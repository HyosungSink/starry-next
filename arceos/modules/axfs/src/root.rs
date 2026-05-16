//! Root directory of the filesystem
//!
//! TODO: it doesn't work very well if the mount points have containment relationships.

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use axerrno::{ax_err, ax_err_type, AxError, AxResult};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsOps, VfsResult};
use axns::{def_resource, ResArc};
use axsync::Mutex;
use cap_access::Cap;
use lazyinit::LazyInit;
use spin::RwLock;

use crate::{
    api::FileType,
    fs::{self},
    mounts,
};

def_resource! {
    pub static CURRENT_DIR_PATH: ResArc<Mutex<String>> = ResArc::new();
    pub static CURRENT_DIR: ResArc<Mutex<VfsNodeRef>> = ResArc::new();
    pub static CURRENT_ROOT_PATH: ResArc<Mutex<String>> = ResArc::new();
    pub static CURRENT_FS_CRED: ResArc<Mutex<FsCred>> = ResArc::new();
}

pub const MAX_SUPPLEMENTARY_GROUPS: usize = 32;

#[derive(Clone, Copy, Debug, Default)]
pub struct FsCred {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub supplementary_len: usize,
    pub supplementary: [u32; MAX_SUPPLEMENTARY_GROUPS],
}

impl CURRENT_DIR_PATH {
    /// Return a copy of the inner path.
    pub fn copy_inner(&self) -> Mutex<String> {
        Mutex::new(self.lock().clone())
    }
}

impl CURRENT_DIR {
    /// Return a copy of the CURRENT_DIR_NODE.
    pub fn copy_inner(&self) -> Mutex<VfsNodeRef> {
        Mutex::new(self.lock().clone())
    }
}

impl CURRENT_ROOT_PATH {
    /// Return a copy of the inner root path.
    pub fn copy_inner(&self) -> Mutex<String> {
        Mutex::new(self.lock().clone())
    }
}

impl CURRENT_FS_CRED {
    pub fn copy_inner(&self) -> Mutex<FsCred> {
        Mutex::new(*self.lock())
    }
}

struct MountPoint {
    path: String,
    fs: Arc<dyn VfsOps>,
    readonly: bool,
    kind: MountedFsKind,
    auto_umount: bool,
    access_seq: u64,
    expire_seq: Option<u64>,
}

struct RootDirectory {
    main_fs: Arc<dyn VfsOps>,
    main_fs_kind: MountedFsKind,
    mounts: RwLock<Vec<MountPoint>>,
}

static ROOT_DIR: LazyInit<Arc<RootDirectory>> = LazyInit::new();
static PATH_METADATA: LazyInit<Mutex<BTreeMap<String, PathMetadata>>> = LazyInit::new();

#[cfg(feature = "ramfs")]
const MIB: usize = 1024 * 1024;

#[cfg(feature = "ramfs")]
fn root_tmp_ramfs_limit() -> Option<usize> {
    Some((axconfig::plat::PHYS_MEMORY_SIZE / 2).clamp(256 * MIB, 768 * MIB))
}

#[cfg(feature = "ramfs")]
fn root_dev_shm_ramfs_limit() -> Option<usize> {
    Some((axconfig::plat::PHYS_MEMORY_SIZE / 4).clamp(64 * MIB, 256 * MIB))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PathMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub ino: u64,
    pub rdev: u64,
    pub special_type: Option<VfsNodeType>,
    pub fs_flags: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountedFsKind {
    Ext4,
    Fat,
    Ramfs,
    Devfs,
    Procfs,
    Sysfs,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct MountTableEntry {
    pub path: String,
    pub readonly: bool,
    pub kind: MountedFsKind,
}

fn default_inode_for_path(path: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in path.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    if hash == 0 { 1 } else { hash }
}

fn default_path_metadata(path: &str, attr: VfsNodeAttr) -> PathMetadata {
    PathMetadata {
        uid: 0,
        gid: 0,
        mode: attr.perm().bits(),
        ino: default_inode_for_path(path),
        rdev: 0,
        special_type: None,
        fs_flags: 0,
    }
}

fn inherited_gid_from_parent(path: &str, parent_attr: VfsNodeAttr) -> u32 {
    let parent_meta = path_metadata(parent_path(path), parent_attr);
    if parent_meta.mode & 0o2000 != 0 {
        parent_meta.gid
    } else {
        current_fs_cred().fsgid
    }
}

fn ensure_current_root_path() {
    if !CURRENT_ROOT_PATH.is_inited() {
        CURRENT_ROOT_PATH.init_new(Mutex::new("/".into()));
    }
}

fn current_root_path() -> String {
    ensure_current_root_path();
    CURRENT_ROOT_PATH.lock().clone()
}

impl MountPoint {
    pub fn new(path: String, fs: Arc<dyn VfsOps>, readonly: bool, kind: MountedFsKind) -> Self {
        Self {
            path,
            fs,
            readonly,
            kind,
            auto_umount: true,
            access_seq: 0,
            expire_seq: None,
        }
    }

    pub fn bind_alias(path: String, fs: Arc<dyn VfsOps>, readonly: bool, kind: MountedFsKind) -> Self {
        Self {
            path,
            fs,
            readonly,
            kind,
            auto_umount: false,
            access_seq: 0,
            expire_seq: None,
        }
    }
}

impl Drop for MountPoint {
    fn drop(&mut self) {
        if self.auto_umount {
            self.fs.umount().ok();
        }
    }
}

impl RootDirectory {
    pub const fn new(main_fs: Arc<dyn VfsOps>, main_fs_kind: MountedFsKind) -> Self {
        Self {
            main_fs,
            main_fs_kind,
            mounts: RwLock::new(Vec::new()),
        }
    }

    pub fn mount(
        &self,
        path: &str,
        fs: Arc<dyn VfsOps>,
        readonly: bool,
        remount: bool,
        kind: MountedFsKind,
    ) -> AxResult {
        if path == "/" {
            return ax_err!(InvalidInput, "cannot mount root filesystem");
        }
        if !path.starts_with('/') {
            return ax_err!(InvalidInput, "mount path must start with '/'");
        }
        if remount {
            let mut mounts = self.mounts.write();
            if let Some(mp) = mounts.iter_mut().find(|mp| mp.path == path) {
                mp.readonly = readonly;
                mp.kind = kind;
                return Ok(());
            }
            return ax_err!(NotFound, "mount point not found");
        }
        if self.mounts.read().iter().any(|mp| mp.path == path) {
            return ax_err!(ResourceBusy, "mount point already exists");
        }
        let mount_node_in_fs = |current_fs: Arc<dyn VfsOps>, rest_path: &str| {
            let root = current_fs.root_dir();
            match root.clone().lookup(rest_path) {
                Ok(node) => {
                    if !node.get_attr()?.is_dir() {
                        return ax_err!(NotADirectory);
                    }
                    Ok(node)
                }
                Err(AxError::NotFound) => {
                    root.create(rest_path, FileType::Dir)?;
                    root.clone().lookup(rest_path)
                }
                Err(err) => Err(err),
            }
        };
        let mount_node = match self.lookup_mounted_fs(path, |current_fs, rest_path| {
            mount_node_in_fs(current_fs, rest_path)
        }) {
            Ok(node) => node,
            Err(AxError::PermissionDenied | AxError::Unsupported | AxError::NotFound) => {
                mount_node_in_fs(self.main_fs.clone(), path)?
            }
            Err(err) => return Err(err),
        };
        fs.mount(path, mount_node)?;
        self.mounts
            .write()
            .push(MountPoint::new(path.into(), fs, readonly, kind));
        Ok(())
    }

    pub fn remount(&self, path: &str, readonly: bool, kind: MountedFsKind) -> AxResult {
        let mut mounts = self.mounts.write();
        let Some(mp) = mounts.iter_mut().find(|mp| mp.path == path) else {
            return ax_err!(NotFound, "mount point not found");
        };
        mp.readonly = readonly;
        mp.kind = kind;
        Ok(())
    }

    pub fn move_mount(&self, from: &str, to: &str) -> AxResult {
        if from == "/" || to == "/" {
            return ax_err!(InvalidInput, "cannot move root filesystem");
        }
        let mut mounts = self.mounts.write();
        let Some(index) = mounts.iter().position(|mp| mp.path == from) else {
            return ax_err!(NotFound, "mount point not found");
        };
        if mounts.iter().any(|mp| mp.path == to) {
            return ax_err!(ResourceBusy, "destination mount point already exists");
        }
        mounts[index].path = to.into();
        mounts[index].access_seq = 0;
        mounts[index].expire_seq = None;
        Ok(())
    }

    pub fn bind_mount(&self, from: &str, to: &str) -> AxResult {
        if from == "/" || to == "/" {
            return ax_err!(InvalidInput, "cannot bind root filesystem");
        }
        let mut mounts = self.mounts.write();
        let Some(index) = mounts.iter().position(|mp| mp.path == from) else {
            return ax_err!(NotFound, "bind source mount point not found");
        };
        if mounts.iter().any(|mp| mp.path == to) {
            return ax_err!(ResourceBusy, "destination mount point already exists");
        }
        let (fs, readonly, kind) = {
            let source = &mounts[index];
            (source.fs.clone(), source.readonly, source.kind)
        };
        mounts.push(MountPoint::bind_alias(
            to.into(),
            fs,
            readonly,
            kind,
        ));
        Ok(())
    }

    pub fn umount(&self, path: &str) -> AxResult {
        let mut mounts = self.mounts.write();
        let Some(index) = mounts.iter().position(|mp| mp.path == path) else {
            return ax_err!(NotFound, "mount point not found");
        };
        let mut mount = mounts.remove(index);
        if !mount.auto_umount {
            return Ok(());
        }
        mount.auto_umount = false;
        match mount.fs.umount() {
            Ok(()) => Ok(()),
            Err(err) => {
                mounts.insert(index, mount);
                Err(err)
            }
        }
    }

    pub fn contains(&self, path: &str) -> bool {
        self.mounts.read().iter().any(|mp| mp.path == path)
    }

    fn matching_mount_index(mounts: &[MountPoint], path: &str) -> Option<usize> {
        let path = path.trim_matches('/');
        let mut max_len = 0usize;
        let mut index = None;
        for (i, mp) in mounts.iter().enumerate() {
            let mount_path = &mp.path[1..];
            if path == mount_path
                || (path.starts_with(mount_path)
                    && path.as_bytes().get(mount_path.len()) == Some(&b'/'))
            {
                if mp.path.len() - 1 > max_len {
                    max_len = mp.path.len() - 1;
                    index = Some(i);
                }
            }
        }
        index
    }

    pub fn note_mount_access(&self, path: &str) {
        let mut mounts = self.mounts.write();
        if let Some(index) = Self::matching_mount_index(&mounts, path) {
            let mount = &mut mounts[index];
            mount.access_seq = mount.access_seq.saturating_add(1);
        }
    }

    pub fn prepare_expire_umount(&self, path: &str) -> AxResult<bool> {
        let mut mounts = self.mounts.write();
        let Some(index) = mounts.iter().position(|mp| mp.path == path) else {
            return ax_err!(NotFound, "mount point not found");
        };
        let mount = &mut mounts[index];
        if mount.expire_seq == Some(mount.access_seq) {
            mount.expire_seq = None;
            Ok(true)
        } else {
            mount.expire_seq = Some(mount.access_seq);
            Ok(false)
        }
    }

    pub fn is_readonly(&self, path: &str) -> bool {
        let path = path.trim_matches('/');
        let mut readonly = false;
        let mut max_len = 0usize;
        for mp in self.mounts.read().iter() {
            let mount_path = &mp.path[1..];
            if path == mount_path
                || (path.starts_with(mount_path)
                    && path.as_bytes().get(mount_path.len()) == Some(&b'/'))
            {
                if mount_path.len() > max_len {
                    max_len = mount_path.len();
                    readonly = mp.readonly;
                }
            }
        }
        readonly
    }

    pub fn mounted_fs_kind(&self, path: &str) -> MountedFsKind {
        let path = path.trim_matches('/');
        let mut kind = self.main_fs_kind;
        let mut max_len = 0usize;
        for mp in self.mounts.read().iter() {
            let mount_path = &mp.path[1..];
            if path == mount_path
                || (path.starts_with(mount_path)
                    && path.as_bytes().get(mount_path.len()) == Some(&b'/'))
            {
                if mount_path.len() > max_len {
                    max_len = mount_path.len();
                    kind = mp.kind;
                }
            }
        }
        kind
    }

    pub fn mount_table_entries(&self) -> Vec<MountTableEntry> {
        self.mounts
            .read()
            .iter()
            .map(|mp| MountTableEntry {
                path: mp.path.clone(),
                readonly: mp.readonly,
                kind: mp.kind,
            })
            .collect()
    }

    fn lookup_mounted_fs<F, T>(&self, path: &str, f: F) -> AxResult<T>
    where
        F: FnOnce(Arc<dyn VfsOps>, &str) -> AxResult<T>,
    {
        debug!("lookup at root: {}", path);
        let path = path.trim_matches('/');
        if let Some(rest) = path.strip_prefix("./") {
            return self.lookup_mounted_fs(rest, f);
        }

        let mut idx = 0;
        let mut max_len = 0;

        // Find the filesystem that has the longest mounted path match
        // TODO: more efficient, e.g. trie
        for (i, mp) in self.mounts.read().iter().enumerate() {
            let mount_path = &mp.path[1..];
            // skip the first '/'
            if path == mount_path
                || (path.starts_with(mount_path)
                    && path.as_bytes().get(mount_path.len()) == Some(&b'/'))
            {
                if mp.path.len() - 1 > max_len {
                    max_len = mp.path.len() - 1;
                    idx = i;
                }
            }
        }

        if max_len == 0 {
            f(self.main_fs.clone(), path) // not matched any mount point
        } else {
            f(
                self.mounts.read()[idx].fs.clone(),
                path[max_len..].trim_start_matches('/'),
            ) // matched at `idx`
        }
    }

    fn mount_route_for_path<'a>(
        &'a self,
        mounts: &'a [MountPoint],
        path: &'a str,
    ) -> (Arc<dyn VfsOps>, &'a str, Option<usize>) {
        let trimmed = path.trim_matches('/');
        if let Some(index) = Self::matching_mount_index(mounts, path) {
            let mount_path_len = mounts[index].path.len() - 1;
            (
                mounts[index].fs.clone(),
                trimmed[mount_path_len..].trim_start_matches('/'),
                Some(index),
            )
        } else {
            (self.main_fs.clone(), trimmed, None)
        }
    }
}

impl VfsNodeOps for RootDirectory {
    axfs_vfs::impl_vfs_dir_default! {}

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        self.main_fs.root_dir().get_attr()
    }

    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        self.lookup_mounted_fs(path, |fs, rest_path| fs.root_dir().lookup(rest_path))
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                Ok(()) // already exists
            } else {
                fs.root_dir().create(rest_path, ty)
            }
        })
    }

    fn remove(&self, path: &str) -> VfsResult {
        self.lookup_mounted_fs(path, |fs, rest_path| {
            if rest_path.is_empty() {
                ax_err!(PermissionDenied) // cannot remove mount points
            } else {
                fs.root_dir().remove(rest_path)
            }
        })
    }

    fn rename(&self, src_path: &str, dst_path: &str) -> VfsResult {
        let mounts = self.mounts.read();
        let (src_fs, src_rel, src_mount) = self.mount_route_for_path(&mounts, src_path);
        let (dst_fs, dst_rel, dst_mount) = self.mount_route_for_path(&mounts, dst_path);
        if src_mount != dst_mount {
            return ax_err!(InvalidInput);
        }
        if src_rel.is_empty() || dst_rel.is_empty() {
            return ax_err!(PermissionDenied);
        }
        let src_rel = src_rel.to_string();
        let dst_rel = dst_rel.to_string();
        drop(mounts);
        if !Arc::ptr_eq(&src_fs, &dst_fs) {
            return ax_err!(InvalidInput);
        }
        src_fs.root_dir().rename(src_rel.as_str(), dst_rel.as_str())
    }
}

pub(crate) fn init_rootfs(disk: crate::dev::Disk) {
    cfg_if::cfg_if! {
        if #[cfg(feature = "myfs")] { // override the default filesystem
            let main_fs = fs::myfs::new_myfs(disk);
            let main_fs_kind = MountedFsKind::Unknown;
        } else if #[cfg(feature = "lwext4_rs")] {
            static EXT4_FS: LazyInit<Arc<fs::lwext4_rust::DiskExt4FileSystem>> = LazyInit::new();
            EXT4_FS.init_once(Arc::new(fs::lwext4_rust::DiskExt4FileSystem::new_root(disk)));
            let main_fs = EXT4_FS.clone();
            let main_fs_kind = MountedFsKind::Ext4;
        } else if #[cfg(feature = "fatfs")] {
            static FAT_FS: LazyInit<Arc<fs::fatfs::FatFileSystem>> = LazyInit::new();
            FAT_FS.init_once(Arc::new(fs::fatfs::FatFileSystem::new(disk)));
            FAT_FS.init();
            let main_fs = FAT_FS.clone();
            let main_fs_kind = MountedFsKind::Fat;
        }
    }

    let root_dir = RootDirectory::new(main_fs, main_fs_kind);

    #[cfg(feature = "devfs")]
    root_dir
        .mount("/dev", mounts::devfs(), false, false, MountedFsKind::Devfs)
        .expect("failed to mount devfs at /dev");

    #[cfg(feature = "ramfs")]
    root_dir
        .mount(
            "/dev/shm",
            mounts::ramfs_with_max_bytes(root_dev_shm_ramfs_limit()),
            false,
            false,
            MountedFsKind::Ramfs,
        )
        .expect("failed to mount ramfs at /dev/shm");

    #[cfg(feature = "ramfs")]
    root_dir
        .mount(
            "/tmp",
            mounts::ramfs_with_max_bytes(root_tmp_ramfs_limit()),
            false,
            false,
            MountedFsKind::Ramfs,
        )
        .expect("failed to mount ramfs at /tmp");

    // Mount another ramfs as procfs
    #[cfg(feature = "procfs")]
    root_dir // should not fail
        .mount(
            "/proc",
            mounts::procfs().unwrap(),
            false,
            false,
            MountedFsKind::Procfs,
        )
        .expect("fail to mount procfs at /proc");

    // Mount another ramfs as sysfs
    #[cfg(feature = "sysfs")]
    root_dir // should not fail
        .mount(
            "/sys",
            mounts::sysfs().unwrap(),
            false,
            false,
            MountedFsKind::Sysfs,
        )
        .expect("fail to mount sysfs at /sys");

    ROOT_DIR.init_once(Arc::new(root_dir));
    info!("rootfs initialized");
    CURRENT_DIR.init_new(Mutex::new(ROOT_DIR.clone()));
    CURRENT_DIR_PATH.init_new(Mutex::new("/".into()));
    CURRENT_ROOT_PATH.init_new(Mutex::new("/".into()));
    CURRENT_FS_CRED.init_new(Mutex::new(FsCred::default()));
    if lookup(None, "/tmp").is_err() {
        create_dir(None, "/tmp").expect("failed to create /tmp");
    }
    set_path_mode("/tmp", 0o777);
}

fn parent_node_of(dir: Option<&VfsNodeRef>, path: &str) -> VfsNodeRef {
    if path.starts_with('/') {
        ROOT_DIR.clone()
    } else {
        dir.cloned().unwrap_or_else(|| CURRENT_DIR.lock().clone())
    }
}

fn lookup_parent_dir(
    dir: Option<&VfsNodeRef>,
    resolved_path: &str,
) -> AxResult<(VfsNodeRef, VfsNodeAttr, String)> {
    let name = resolved_path
        .trim_end_matches('/')
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(resolved_path)
        .to_string();
    let parent_resolved = parent_path(resolved_path);
    let parent = if parent_resolved == "/" {
        ROOT_DIR.clone()
    } else {
        lookup(dir, parent_resolved)?
    };
    let parent_attr = parent.get_attr()?;
    if !parent_attr.is_dir() {
        return ax_err!(NotADirectory);
    }
    Ok((parent, parent_attr, name))
}

fn resolve_path(dir: Option<&VfsNodeRef>, path: &str) -> AxResult<String> {
    if dir.is_none() && !path.starts_with('/') {
        absolute_path(path)
    } else {
        Ok(path.into())
    }
}

pub(crate) fn absolute_path(path: &str) -> AxResult<String> {
    if path.starts_with('/') {
        let canonical = axfs_vfs::path::canonicalize(path);
        let root = current_root_path();
        if root == "/" {
            return Ok(canonical);
        }

        let root_prefix = root.trim_end_matches('/');
        if canonical == root_prefix || canonical.starts_with(&format!("{root_prefix}/")) {
            return Ok(canonical);
        }
        if canonical == "/" {
            return Ok(root_prefix.to_string());
        }
        Ok(format!("{root_prefix}{canonical}"))
    } else {
        let mut abs = CURRENT_DIR_PATH.lock().clone();
        if !abs.ends_with('/') {
            abs.push('/');
        }
        abs.push_str(path);
        Ok(axfs_vfs::path::canonicalize(&abs))
    }
}

pub(crate) fn lookup(dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
    if path.is_empty() {
        return ax_err!(NotFound);
    }
    let resolved_path = resolve_path(dir, path)?;
    let parent = parent_node_of(dir, resolved_path.as_str());
    let parent_attr = parent.get_attr()?;
    if !has_dir_perm(
        parent_path(resolved_path.as_str()),
        parent_attr,
        false,
        true,
        true,
    ) {
        return ax_err!(PermissionDenied);
    }
    let node = match parent.lookup(resolved_path.as_str()) {
        Ok(node) => node,
        Err(err) => {
            if path == "./sort.src" || resolved_path.ends_with("/sort.src") {
                warn!(
                    "lookup sort.src failed: path={} resolved={} cwd={}",
                    path,
                    resolved_path,
                    CURRENT_DIR_PATH.lock().as_str()
                );
            }
            return Err(err);
        }
    };
    if resolved_path.ends_with('/') && !node.get_attr()?.is_dir() {
        ax_err!(NotADirectory)
    } else {
        Ok(node)
    }
}

pub(crate) fn create_file(dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
    if path.is_empty() {
        return ax_err!(NotFound);
    } else if path.ends_with('/') {
        return ax_err!(NotADirectory);
    }
    let resolved_path = resolve_path(dir, path)?;
    let (parent, parent_attr, name) = lookup_parent_dir(dir, resolved_path.as_str())?;
    if !has_dir_perm(
        parent_path(resolved_path.as_str()),
        parent_attr,
        true,
        true,
        true,
    ) {
        return ax_err!(PermissionDenied);
    }
    parent.create(&name, VfsNodeType::File)?;
    let node = parent.lookup(&name)?;
    let attr = node.get_attr()?;
    ensure_path_metadata(
        resolved_path.as_str(),
        attr,
        Some(current_fs_cred().fsuid),
        Some(inherited_gid_from_parent(
            resolved_path.as_str(),
            parent_attr,
        )),
        None,
    );
    Ok(node)
}

pub(crate) fn create_fifo(dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
    if path.is_empty() {
        return ax_err!(NotFound);
    } else if path.ends_with('/') {
        return ax_err!(NotADirectory);
    }
    let resolved_path = resolve_path(dir, path)?;
    let (parent, parent_attr, name) = lookup_parent_dir(dir, resolved_path.as_str())?;
    if !has_dir_perm(
        parent_path(resolved_path.as_str()),
        parent_attr,
        true,
        true,
        true,
    ) {
        return ax_err!(PermissionDenied);
    }
    parent.create(&name, VfsNodeType::Fifo)?;
    let node = parent.lookup(&name)?;
    let attr = node.get_attr()?;
    ensure_path_metadata(
        resolved_path.as_str(),
        attr,
        Some(current_fs_cred().fsuid),
        Some(inherited_gid_from_parent(
            resolved_path.as_str(),
            parent_attr,
        )),
        None,
    );
    Ok(node)
}

pub(crate) fn create_socket(dir: Option<&VfsNodeRef>, path: &str) -> AxResult<VfsNodeRef> {
    if path.is_empty() {
        return ax_err!(NotFound);
    } else if path.ends_with('/') {
        return ax_err!(NotADirectory);
    }
    let resolved_path = resolve_path(dir, path)?;
    let (parent, parent_attr, name) = lookup_parent_dir(dir, resolved_path.as_str())?;
    if !has_dir_perm(
        parent_path(resolved_path.as_str()),
        parent_attr,
        true,
        true,
        true,
    ) {
        return ax_err!(PermissionDenied);
    }
    parent.create(&name, VfsNodeType::Socket)?;
    let node = parent.lookup(&name)?;
    let attr = node.get_attr()?;
    ensure_path_metadata(
        resolved_path.as_str(),
        attr,
        Some(current_fs_cred().fsuid),
        Some(inherited_gid_from_parent(
            resolved_path.as_str(),
            parent_attr,
        )),
        None,
    );
    Ok(node)
}

pub(crate) fn create_dir(dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
    let resolved_path = resolve_path(dir, path)?;
    let (parent, parent_attr, name) = lookup_parent_dir(dir, resolved_path.as_str())?;
    if !has_dir_perm(
        parent_path(resolved_path.as_str()),
        parent_attr,
        true,
        true,
        true,
    ) {
        return ax_err!(PermissionDenied);
    }
    match lookup(dir, resolved_path.as_str()) {
        Ok(_) => Err(AxError::AlreadyExists),
        Err(AxError::NotFound) => {
            parent.create(&name, VfsNodeType::Dir)?;
            let node = parent.lookup(&name)?;
            let attr = node.get_attr()?;
            let parent_meta = path_metadata(parent_path(resolved_path.as_str()), parent_attr);
            ensure_path_metadata(
                resolved_path.as_str(),
                attr,
                Some(current_fs_cred().fsuid),
                Some(inherited_gid_from_parent(
                    resolved_path.as_str(),
                    parent_attr,
                )),
                (parent_meta.mode & 0o2000 != 0).then_some(attr.perm().bits() | 0o2000),
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) fn remove_file(dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
    let resolved_path = resolve_path(dir, path)?;
    let node = lookup(dir, resolved_path.as_str())?;
    let attr = node.get_attr()?;
    let resolved_parent_path = resolved_path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/");
    let parent = lookup(dir, resolved_parent_path)?;
    let parent_attr = parent.get_attr()?;
    if attr.is_dir() {
        ax_err!(IsADirectory)
    } else if !has_dir_perm(resolved_parent_path, parent_attr, true, true, true) {
        ax_err!(PermissionDenied)
    } else {
        parent_node_of(dir, resolved_path.as_str()).remove(resolved_path.as_str())?;
        remove_path_metadata(resolved_path.as_str());
        Ok(())
    }
}

pub(crate) fn remove_dir(dir: Option<&VfsNodeRef>, path: &str) -> AxResult {
    if path.is_empty() {
        return ax_err!(NotFound);
    }
    let path_check = path.trim_matches('/');
    if path_check.is_empty() {
        return ax_err!(DirectoryNotEmpty); // rm -d '/'
    } else if path_check == "."
        || path_check == ".."
        || path_check.ends_with("/.")
        || path_check.ends_with("/..")
    {
        return ax_err!(InvalidInput);
    }
    if ROOT_DIR.contains(&absolute_path(path)?) {
        return ax_err!(PermissionDenied);
    }

    let resolved_path = resolve_path(dir, path)?;
    let node = lookup(dir, resolved_path.as_str())?;
    let attr = node.get_attr()?;
    let resolved_parent_path = resolved_path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/");
    let parent = lookup(dir, resolved_parent_path)?;
    let parent_attr = parent.get_attr()?;
    if !attr.is_dir() {
        ax_err!(NotADirectory)
    } else if !has_dir_perm(resolved_parent_path, parent_attr, true, true, true) {
        ax_err!(PermissionDenied)
    } else {
        let current_path = CURRENT_DIR_PATH.lock().clone();
        let current_trimmed = if current_path == "/" {
            current_path
        } else {
            current_path.trim_end_matches('/').to_string()
        };
        let target_trimmed = if resolved_path == "/" {
            resolved_path.clone()
        } else {
            resolved_path.trim_end_matches('/').to_string()
        };
        if current_trimmed == target_trimmed
            || current_trimmed
                .strip_prefix(target_trimmed.as_str())
                .is_some_and(|rest| rest.starts_with('/'))
        {
            *CURRENT_DIR.lock() = parent.clone();
            *CURRENT_DIR_PATH.lock() = if resolved_parent_path == "/" {
                "/".into()
            } else {
                format!("{}/", resolved_parent_path.trim_end_matches('/'))
            };
        }
        parent_node_of(dir, resolved_path.as_str()).remove(resolved_path.as_str())?;
        remove_path_metadata(resolved_path.as_str());
        Ok(())
    }
}

pub(crate) fn current_dir() -> AxResult<String> {
    let current = CURRENT_DIR_PATH.lock().clone();
    let root = current_root_path();
    if root == "/" {
        if current == "/" {
            return Ok(current);
        }
        return Ok(current.trim_end_matches('/').to_string());
    }

    let root_prefix = root.trim_end_matches('/');
    if current == root_prefix || current == format!("{root_prefix}/") {
        return Ok("/".into());
    }
    if let Some(rest) = current.strip_prefix(root_prefix) {
        return Ok(if rest.is_empty() {
            "/".into()
        } else {
            rest.trim_end_matches('/').into()
        });
    }
    Ok(if current == "/" {
        current
    } else {
        current.trim_end_matches('/').to_string()
    })
}

pub(crate) fn current_fs_cred() -> FsCred {
    *CURRENT_FS_CRED.lock()
}

pub(crate) fn set_uid_triplet(ruid: u32, euid: u32, suid: u32) {
    let mut cred = CURRENT_FS_CRED.lock();
    cred.ruid = ruid;
    cred.euid = euid;
    cred.suid = suid;
    cred.fsuid = euid;
}

pub(crate) fn set_gid_triplet(rgid: u32, egid: u32, sgid: u32) {
    let mut cred = CURRENT_FS_CRED.lock();
    cred.rgid = rgid;
    cred.egid = egid;
    cred.sgid = sgid;
    cred.fsgid = egid;
}

pub(crate) fn set_fsuid(uid: u32) -> u32 {
    let mut cred = CURRENT_FS_CRED.lock();
    let old = cred.fsuid;
    cred.fsuid = uid;
    old
}

pub(crate) fn set_fsgid(gid: u32) -> u32 {
    let mut cred = CURRENT_FS_CRED.lock();
    let old = cred.fsgid;
    cred.fsgid = gid;
    old
}

pub(crate) fn supplementary_groups() -> ([u32; MAX_SUPPLEMENTARY_GROUPS], usize) {
    let cred = CURRENT_FS_CRED.lock();
    (cred.supplementary, cred.supplementary_len)
}

pub(crate) fn set_supplementary_groups(groups: &[u32]) -> AxResult {
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return ax_err!(InvalidInput);
    }
    let mut cred = CURRENT_FS_CRED.lock();
    cred.supplementary[..groups.len()].copy_from_slice(groups);
    cred.supplementary[groups.len()..].fill(0);
    cred.supplementary_len = groups.len();
    Ok(())
}

pub(crate) fn set_current_dir(path: &str) -> AxResult {
    let mut abs_path = absolute_path(path)?;
    if !abs_path.ends_with('/') {
        abs_path += "/";
    }
    if abs_path == "/" {
        *CURRENT_DIR.lock() = ROOT_DIR.clone();
        *CURRENT_DIR_PATH.lock() = "/".into();
        return Ok(());
    }

    let node = lookup(None, &abs_path)?;
    let attr = node.get_attr()?;
    if !attr.is_dir() {
        ax_err!(NotADirectory)
    } else if !has_dir_perm(abs_path.as_str(), attr, false, true, true) {
        ax_err!(PermissionDenied)
    } else {
        *CURRENT_DIR.lock() = node;
        *CURRENT_DIR_PATH.lock() = abs_path;
        Ok(())
    }
}

pub(crate) fn set_current_root(path: &str) -> AxResult {
    let mut abs_path = absolute_path(path)?;
    if abs_path != "/" {
        abs_path.truncate(abs_path.trim_end_matches('/').len());
    }

    let node = lookup(None, abs_path.as_str())?;
    let attr = node.get_attr()?;
    if !attr.is_dir() {
        return ax_err!(NotADirectory);
    }
    if !has_dir_perm(abs_path.as_str(), attr, false, true, true) {
        return ax_err!(PermissionDenied);
    }

    ensure_current_root_path();
    *CURRENT_ROOT_PATH.lock() = abs_path.clone();
    *CURRENT_DIR.lock() = node;
    *CURRENT_DIR_PATH.lock() = if abs_path == "/" {
        "/".into()
    } else {
        format!("{abs_path}/")
    };
    Ok(())
}

pub(crate) fn rename(old: &str, new: &str) -> AxResult {
    let old_resolved = resolve_path(None, old)?;
    let new_resolved = resolve_path(None, new)?;
    if old_resolved == new_resolved {
        return Ok(());
    }
    if let Ok(node) = parent_node_of(None, new_resolved.as_str()).lookup(new_resolved.as_str()) {
        warn!("dst file already exist, now remove it");
        let attr = node.get_attr()?;
        if attr.is_dir() {
            remove_dir(None, new_resolved.as_str())?;
        } else {
            remove_file(None, new_resolved.as_str())?;
        }
    }
    parent_node_of(None, old_resolved.as_str())
        .rename(old_resolved.as_str(), new_resolved.as_str())?;
    rename_path_metadata(old_resolved.as_str(), new_resolved.as_str());
    Ok(())
}

fn normalize_mount_path(path: &str) -> AxResult<String> {
    let mut path = absolute_path(path)?;
    if path.len() > 1 {
        path.truncate(path.trim_end_matches('/').len());
    }
    Ok(path)
}

pub(crate) fn mount_ramfs_with_max_bytes(
    path: &str,
    readonly: bool,
    remount: bool,
    max_bytes: Option<usize>,
) -> AxResult {
    #[cfg(feature = "ramfs")]
    {
        let path = normalize_mount_path(path)?;
        ROOT_DIR.mount(
            &path,
            mounts::ramfs_with_max_bytes(max_bytes),
            readonly,
            remount,
            MountedFsKind::Ramfs,
        )
    }
    #[cfg(not(feature = "ramfs"))]
    {
        let _ = (path, max_bytes);
        ax_err!(Unsupported, "ramfs support is disabled")
    }
}

pub(crate) fn mount_ramfs(path: &str, readonly: bool, remount: bool) -> AxResult {
    mount_ramfs_with_max_bytes(path, readonly, remount, None)
}

pub(crate) fn remount(path: &str, readonly: bool, kind: MountedFsKind) -> AxResult {
    let path = normalize_mount_path(path)?;
    ROOT_DIR.remount(path.as_str(), readonly, kind)
}

pub(crate) fn move_mount(from: &str, to: &str) -> AxResult {
    let from = normalize_mount_path(from)?;
    let to = normalize_mount_path(to)?;
    ROOT_DIR.move_mount(from.as_str(), to.as_str())
}

pub(crate) fn bind_mount(from: &str, to: &str) -> AxResult {
    let from = normalize_mount_path(from)?;
    let to = normalize_mount_path(to)?;
    ROOT_DIR.bind_mount(from.as_str(), to.as_str())
}

pub(crate) fn mount_fatfs(path: &str, source: &str, readonly: bool, remount: bool) -> AxResult {
    #[cfg(feature = "fatfs")]
    {
        let path = normalize_mount_path(path)?;
        let source = normalize_mount_path(source)?;
        let fs = mounts::mountable_fat_fs(source.as_str())
            .ok_or_else(|| ax_err_type!(NotFound, "mount source not found"))?;
        ROOT_DIR.mount(&path, fs, readonly, remount, MountedFsKind::Fat)
    }
    #[cfg(not(feature = "fatfs"))]
    {
        let _ = (path, source, readonly, remount);
        ax_err!(Unsupported, "fatfs support is disabled")
    }
}

#[cfg(feature = "fatfs")]
pub(crate) fn mount_fatfs_fs(
    path: &str,
    fs: Arc<dyn VfsOps>,
    readonly: bool,
    remount: bool,
) -> AxResult {
    let path = normalize_mount_path(path)?;
    ROOT_DIR.mount(&path, fs, readonly, remount, MountedFsKind::Fat)
}

pub(crate) fn mount_ext4_image(
    path: &str,
    image: &[u8],
    readonly: bool,
    remount: bool,
) -> AxResult {
    #[cfg(feature = "lwext4_rs")]
    {
        let path = normalize_mount_path(path)?;
        let fs = mounts::mountable_ext4_fs(path.as_str(), image)?;
        ROOT_DIR.mount(&path, fs, readonly, remount, MountedFsKind::Ext4)
    }
    #[cfg(not(feature = "lwext4_rs"))]
    {
        let _ = (path, image, readonly, remount);
        ax_err!(Unsupported, "ext4 support is disabled")
    }
}

#[cfg(feature = "lwext4_rs")]
pub(crate) fn mount_ext4_fs(
    path: &str,
    fs: Arc<dyn VfsOps>,
    readonly: bool,
    remount: bool,
) -> AxResult {
    let path = normalize_mount_path(path)?;
    ROOT_DIR.mount(&path, fs, readonly, remount, MountedFsKind::Ext4)
}

pub(crate) fn umount(path: &str) -> AxResult {
    let path = normalize_mount_path(path)?;
    ROOT_DIR.umount(&path)
}

pub(crate) fn note_mount_access(path: &str) {
    if let Ok(path) = normalize_mount_path(path) {
        ROOT_DIR.note_mount_access(path.as_str());
    }
}

pub(crate) fn prepare_expire_umount(path: &str) -> AxResult<bool> {
    let path = normalize_mount_path(path)?;
    ROOT_DIR.prepare_expire_umount(path.as_str())
}

pub(crate) fn is_readonly_path(path: &str) -> AxResult<bool> {
    let path = normalize_mount_path(path)?;
    Ok(ROOT_DIR.is_readonly(&path))
}

pub(crate) fn mount_point_exists(path: &str) -> AxResult<bool> {
    let path = normalize_mount_path(path)?;
    Ok(ROOT_DIR.contains(&path))
}

pub(crate) fn path_mount_kind(path: &str) -> MountedFsKind {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    ROOT_DIR.mounted_fs_kind(path.as_str())
}

pub(crate) fn root_fs_kind() -> MountedFsKind {
    ROOT_DIR.main_fs_kind
}

pub(crate) fn mount_table_entries() -> Vec<MountTableEntry> {
    ROOT_DIR.mount_table_entries()
}

pub(crate) fn reclaim_filesystem_caches() -> usize {
    mounts::reclaim_mount_caches()
}

fn path_metadata_map() -> &'static Mutex<BTreeMap<String, PathMetadata>> {
    if !PATH_METADATA.is_inited() {
        PATH_METADATA.init_once(Mutex::new(BTreeMap::new()));
    }
    &PATH_METADATA
}

fn parent_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    let normalized = if trimmed.is_empty() { "/" } else { trimmed };
    normalized
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
}

fn effective_mode_bits(path: &str, attr: VfsNodeAttr) -> u16 {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let mut map = path_metadata_map().lock();
    let entry = map
        .entry(path.clone())
        .or_insert_with(|| default_path_metadata(path.as_str(), attr));
    entry.mode
}

pub(crate) fn path_metadata(path: &str, attr: VfsNodeAttr) -> PathMetadata {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let mut map = path_metadata_map().lock();
    *map.entry(path.clone())
        .or_insert_with(|| default_path_metadata(path.as_str(), attr))
}

pub(crate) fn ensure_path_metadata(
    path: &str,
    attr: VfsNodeAttr,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u16>,
) {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let mut map = path_metadata_map().lock();
    let entry = map
        .entry(path.clone())
        .or_insert_with(|| default_path_metadata(path.as_str(), attr));
    if let Some(uid) = uid {
        entry.uid = uid;
    }
    if let Some(gid) = gid {
        entry.gid = gid;
    }
    if let Some(mode) = mode {
        entry.mode = mode;
    }
}

pub(crate) fn set_path_special_node(path: &str, ty: VfsNodeType, rdev: u64) {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let attr = lookup(None, path.as_str())
        .and_then(|node| node.get_attr())
        .unwrap_or_else(|_| VfsNodeAttr::new(axfs_vfs::VfsNodePerm::empty(), ty, 0, 0));
    let mut map = path_metadata_map().lock();
    let entry = map
        .entry(path.clone())
        .or_insert_with(|| default_path_metadata(path.as_str(), attr));
    entry.special_type = Some(ty);
    entry.rdev = rdev;
}

pub(crate) fn clear_path_special_node(path: &str) {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let mut map = path_metadata_map().lock();
    if let Some(entry) = map.get_mut(path.as_str()) {
        entry.special_type = None;
        entry.rdev = 0;
    }
}

pub(crate) fn set_path_fs_flags(path: &str, fs_flags: u32) {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    let attr = lookup(None, path.as_str())
        .and_then(|node| node.get_attr())
        .unwrap_or_else(|_| {
            VfsNodeAttr::new(axfs_vfs::VfsNodePerm::empty(), VfsNodeType::File, 0, 0)
        });
    let mut map = path_metadata_map().lock();
    let entry = map
        .entry(path.clone())
        .or_insert_with(|| default_path_metadata(path.as_str(), attr));
    entry.fs_flags = fs_flags;
}

pub(crate) fn set_path_mode(path: &str, mode: u16) {
    let attr = lookup(None, path)
        .and_then(|node| node.get_attr())
        .unwrap_or_else(|_| {
            VfsNodeAttr::new(axfs_vfs::VfsNodePerm::empty(), VfsNodeType::File, 0, 0)
        });
    ensure_path_metadata(path, attr, None, None, Some(mode));
}

pub(crate) fn set_path_owner(path: &str, uid: Option<u32>, gid: Option<u32>) {
    let attr = lookup(None, path)
        .and_then(|node| node.get_attr())
        .unwrap_or_else(|_| {
            VfsNodeAttr::new(axfs_vfs::VfsNodePerm::empty(), VfsNodeType::File, 0, 0)
        });
    ensure_path_metadata(path, attr, uid, gid, None);
}

pub(crate) fn clear_path_special_bits(path: &str, mask: u16) {
    let attr = match lookup(None, path).and_then(|node| node.get_attr()) {
        Ok(attr) => attr,
        Err(_) => return,
    };
    let meta = path_metadata(path, attr);
    set_path_mode(path, meta.mode & !mask);
}

pub(crate) fn remove_path_metadata(path: &str) {
    let path = absolute_path(path).unwrap_or_else(|_| path.to_string());
    path_metadata_map().lock().remove(path.as_str());
}

pub(crate) fn rename_path_metadata(old: &str, new: &str) {
    let old = absolute_path(old).unwrap_or_else(|_| old.to_string());
    let new = absolute_path(new).unwrap_or_else(|_| new.to_string());
    let mut map = path_metadata_map().lock();
    if let Some(meta) = map.remove(old.as_str()) {
        map.insert(new, meta);
    }
}

fn perm_caps_for(meta: PathMetadata, use_real_ids: bool, perm: axfs_vfs::VfsNodePerm) -> Cap {
    let cred = current_fs_cred();
    let uid = if use_real_ids { cred.ruid } else { cred.fsuid };
    let gid = if use_real_ids { cred.rgid } else { cred.fsgid };
    if uid == 0 {
        let mut cap = Cap::READ | Cap::WRITE;
        if perm.owner_executable()
            || perm.contains(axfs_vfs::VfsNodePerm::GROUP_EXEC)
            || perm.contains(axfs_vfs::VfsNodePerm::OTHER_EXEC)
        {
            cap |= Cap::EXECUTE;
        }
        return cap;
    }
    let (read_ok, write_ok, exec_ok) = if uid == meta.uid {
        (
            perm.owner_readable(),
            perm.owner_writable(),
            perm.owner_executable(),
        )
    } else if gid == meta.gid
        || cred.rgid == meta.gid
        || cred.sgid == meta.gid
        || cred.supplementary[..cred.supplementary_len].contains(&meta.gid)
    {
        (
            perm.contains(axfs_vfs::VfsNodePerm::GROUP_READ),
            perm.contains(axfs_vfs::VfsNodePerm::GROUP_WRITE),
            perm.contains(axfs_vfs::VfsNodePerm::GROUP_EXEC),
        )
    } else {
        (
            perm.contains(axfs_vfs::VfsNodePerm::OTHER_READ),
            perm.contains(axfs_vfs::VfsNodePerm::OTHER_WRITE),
            perm.contains(axfs_vfs::VfsNodePerm::OTHER_EXEC),
        )
    };
    let mut cap = Cap::empty();
    if read_ok {
        cap |= Cap::READ;
    }
    if write_ok {
        cap |= Cap::WRITE;
    }
    if exec_ok {
        cap |= Cap::EXECUTE;
    }
    cap
}

pub(crate) fn access_caps(path: &str, attr: VfsNodeAttr, use_real_ids: bool) -> Cap {
    let meta = path_metadata(path, attr);
    let perm = axfs_vfs::VfsNodePerm::from_bits_truncate(effective_mode_bits(path, attr) & 0o777);
    let mut caps = perm_caps_for(meta, use_real_ids, perm);
    let cred = current_fs_cred();
    let uid = if use_real_ids { cred.ruid } else { cred.fsuid };
    if uid == 0 && attr.is_dir() {
        caps |= Cap::EXECUTE;
    }
    caps
}

fn has_dir_perm(
    path: &str,
    attr: VfsNodeAttr,
    need_write: bool,
    need_exec: bool,
    use_effective_ids: bool,
) -> bool {
    let caps = access_caps(path, attr, !use_effective_ids);
    (!need_write || caps.contains(Cap::WRITE)) && (!need_exec || caps.contains(Cap::EXECUTE))
}
