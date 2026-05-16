//! [`std::fs`]-like high-level filesystem manipulation operations.

mod dir;
mod file;

pub use self::dir::{DirBuilder, DirEntry, ReadDir};
pub use self::file::{File, FileType, Metadata, OpenOptions, Permissions};

use alloc::{boxed::Box, format, string::String, vec, vec::Vec};
use axerrno::{AxError, LinuxError};
use axfs_vfs::{VfsNodePerm, VfsNodeType};
use axio::{self as io, prelude::*};
use cap_access::Cap;

pub use crate::root::MountedFsKind as PathMountKind;
#[cfg(feature = "lwext4_rs")]
pub use lwext4_rust::KernelDevOp;

#[cfg(any(feature = "lwext4_rs", feature = "fatfs"))]
use alloc::sync::Arc;
#[cfg(feature = "lwext4_rs")]
use alloc::ffi::CString;
#[cfg(feature = "lwext4_rs")]
use lwext4_rust::bindings::{
    ext4_fsymlink, ext4_mode_set, ext4_raw_inode_fill, ext4_readlink, ext4_inode, EOK,
};
#[cfg(feature = "fatfs")]
use axio::SeekFrom;
#[cfg(feature = "fatfs")]
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};

#[cfg(feature = "fatfs")]
struct FatFsDeviceAdapter<IO>(IO);

#[cfg(feature = "fatfs")]
struct MountedFatFs<IO: crate::fs::fatfs::IoTrait + 'static> {
    inner: &'static crate::fs::fatfs::FatFileSystem<IO>,
}

#[cfg(feature = "fatfs")]
pub trait FatFsIo: Send + Sync {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, i32>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, i32>;
    fn flush(&mut self) -> Result<(), i32>;
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, i32>;
}

#[cfg(feature = "fatfs")]
impl<IO: FatFsIo> fatfs::IoBase for FatFsDeviceAdapter<IO> {
    type Error = ();
}

#[cfg(feature = "fatfs")]
impl<IO: FatFsIo> crate::fs::fatfs::IoTrait for FatFsDeviceAdapter<IO> {}

#[cfg(feature = "fatfs")]
impl<IO: FatFsIo> fatfs::Read for FatFsDeviceAdapter<IO> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.0
            .read(buf)
            .inspect_err(|status| error!("fatfs device read failed: {status}"))
            .map_err(|_| ())
    }
}

#[cfg(feature = "fatfs")]
impl<IO: FatFsIo> fatfs::Write for FatFsDeviceAdapter<IO> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.0
            .write(buf)
            .inspect_err(|status| error!("fatfs device write failed: {status}"))
            .map_err(|_| ())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.0
            .flush()
            .inspect_err(|status| error!("fatfs device flush failed: {status}"))
            .map_err(|_| ())
    }
}

#[cfg(feature = "fatfs")]
impl<IO: FatFsIo> fatfs::Seek for FatFsDeviceAdapter<IO> {
    fn seek(&mut self, pos: fatfs::SeekFrom) -> Result<u64, Self::Error> {
        let pos = match pos {
            fatfs::SeekFrom::Start(off) => SeekFrom::Start(off),
            fatfs::SeekFrom::Current(off) => SeekFrom::Current(off),
            fatfs::SeekFrom::End(off) => SeekFrom::End(off),
        };
        self.0
            .seek(pos)
            .inspect_err(|status| error!("fatfs device seek failed: {status}"))
            .map_err(|_| ())
    }
}

#[cfg(feature = "fatfs")]
impl<IO: crate::fs::fatfs::IoTrait + 'static> VfsOps for MountedFatFs<IO> {
    fn root_dir(&self) -> VfsNodeRef {
        self.inner.root_dir()
    }

    fn umount(&self) -> VfsResult {
        Ok(())
    }
}

#[cfg(feature = "lwext4_rs")]
fn ext4_status_to_io(status: i32) -> io::Error {
    let linux = LinuxError::try_from(status.abs()).unwrap_or(LinuxError::EIO);
    let ax = match linux {
        LinuxError::EADDRINUSE => AxError::AddrInUse,
        LinuxError::EEXIST => AxError::AlreadyExists,
        LinuxError::EFAULT => AxError::BadAddress,
        LinuxError::ECONNREFUSED => AxError::ConnectionRefused,
        LinuxError::ECONNRESET => AxError::ConnectionReset,
        LinuxError::ENOTEMPTY => AxError::DirectoryNotEmpty,
        LinuxError::EINVAL => AxError::InvalidInput,
        LinuxError::EIO => AxError::Io,
        LinuxError::EISDIR => AxError::IsADirectory,
        LinuxError::ENOMEM => AxError::NoMemory,
        LinuxError::ENOTDIR => AxError::NotADirectory,
        LinuxError::ENOTCONN => AxError::NotConnected,
        LinuxError::ENOENT => AxError::NotFound,
        LinuxError::EACCES | LinuxError::EPERM | LinuxError::EROFS => AxError::PermissionDenied,
        LinuxError::EBUSY => AxError::ResourceBusy,
        LinuxError::ENOSPC => AxError::StorageFull,
        LinuxError::ENOSYS => AxError::Unsupported,
        LinuxError::EAGAIN => AxError::WouldBlock,
        _ => AxError::Io,
    };
    io::Error::from(ax)
}

/// Returns an iterator over the entries within a directory.
pub fn read_dir(path: &str) -> io::Result<ReadDir> {
    ReadDir::new(path)
}

/// Returns the canonical, absolute form of a path with all intermediate
/// components normalized.
pub fn canonicalize(path: &str) -> io::Result<String> {
    crate::root::absolute_path(path)
}

/// Returns the current working directory as a [`String`].
pub fn current_dir() -> io::Result<String> {
    crate::root::current_dir()
}

pub fn current_uid() -> u32 {
    crate::root::current_fs_cred().ruid
}

pub fn current_euid() -> u32 {
    crate::root::current_fs_cred().euid
}

pub fn current_fsuid() -> u32 {
    crate::root::current_fs_cred().fsuid
}

pub fn current_gid() -> u32 {
    crate::root::current_fs_cred().rgid
}

pub fn current_egid() -> u32 {
    crate::root::current_fs_cred().egid
}

pub fn current_fsgid() -> u32 {
    crate::root::current_fs_cred().fsgid
}

pub fn current_res_uid() -> (u32, u32, u32) {
    let cred = crate::root::current_fs_cred();
    (cred.ruid, cred.euid, cred.suid)
}

pub fn current_res_gid() -> (u32, u32, u32) {
    let cred = crate::root::current_fs_cred();
    (cred.rgid, cred.egid, cred.sgid)
}

pub fn current_supplementary_gids() -> ([u32; crate::root::MAX_SUPPLEMENTARY_GROUPS], usize) {
    crate::root::supplementary_groups()
}

pub fn set_res_uid(ruid: u32, euid: u32, suid: u32) {
    crate::root::set_uid_triplet(ruid, euid, suid);
}

pub fn set_res_gid(rgid: u32, egid: u32, sgid: u32) {
    crate::root::set_gid_triplet(rgid, egid, sgid);
}

pub fn set_fsuid(uid: u32) -> u32 {
    crate::root::set_fsuid(uid)
}

pub fn set_fsgid(gid: u32) -> u32 {
    crate::root::set_fsgid(gid)
}

pub fn set_supplementary_gids(groups: &[u32]) -> io::Result<()> {
    crate::root::set_supplementary_groups(groups).map_err(io::Error::from)
}

pub fn access_caps(path: &str, attr: crate::fops::FileAttr, use_real_ids: bool) -> Cap {
    crate::root::access_caps(path, attr, use_real_ids)
}

pub fn can_access(
    path: &str,
    attr: crate::fops::FileAttr,
    use_real_ids: bool,
    need_read: bool,
    need_write: bool,
    need_exec: bool,
) -> bool {
    let caps = crate::root::access_caps(path, attr, use_real_ids);
    (!need_read || caps.contains(Cap::READ))
        && (!need_write || caps.contains(Cap::WRITE))
        && (!need_exec || caps.contains(Cap::EXECUTE))
}

pub fn path_owner_mode(path: &str, attr: crate::fops::FileAttr) -> (u32, u32, u16) {
    let meta = crate::root::path_metadata(path, attr);
    (meta.uid, meta.gid, meta.mode)
}

#[derive(Clone, Copy, Debug)]
pub struct PathStatMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub ino: u64,
    pub rdev: u64,
    pub special_type: Option<VfsNodeType>,
    pub fs_flags: u32,
}

pub fn path_stat_metadata(path: &str, attr: crate::fops::FileAttr) -> PathStatMetadata {
    let meta = crate::root::path_metadata(path, attr);
    PathStatMetadata {
        uid: meta.uid,
        gid: meta.gid,
        mode: meta.mode,
        ino: meta.ino,
        rdev: meta.rdev,
        special_type: meta.special_type,
        fs_flags: meta.fs_flags,
    }
}

pub fn path_mount_kind(path: &str) -> PathMountKind {
    crate::root::path_mount_kind(path)
}

pub fn reclaim_caches() -> usize {
    crate::root::reclaim_filesystem_caches()
}

pub fn proc_mounts_contents() -> String {
    fn mount_kind_name(kind: crate::root::MountedFsKind) -> &'static str {
        match kind {
            crate::root::MountedFsKind::Ext4 => "ext4",
            crate::root::MountedFsKind::Fat => "vfat",
            crate::root::MountedFsKind::Ramfs => "tmpfs",
            crate::root::MountedFsKind::Devfs => "devfs",
            crate::root::MountedFsKind::Procfs => "proc",
            crate::root::MountedFsKind::Sysfs => "sysfs",
            crate::root::MountedFsKind::Unknown => "rootfs",
        }
    }

    let mut mounts = String::new();
    let root_kind = crate::root::root_fs_kind();
    let root_fs = mount_kind_name(root_kind);
    mounts.push_str(format!("{root_fs} / {root_fs} rw 0 0\n").as_str());

    for mount in crate::root::mount_table_entries() {
        let fs_type = mount_kind_name(mount.kind);
        let flags = if mount.readonly { "ro" } else { "rw" };
        mounts.push_str(format!("{fs_type} {} {fs_type} {flags} 0 0\n", mount.path).as_str());
    }

    mounts
}

pub fn set_path_special_node(path: &str, ty: VfsNodeType, rdev: u64) {
    crate::root::set_path_special_node(path, ty, rdev);
}

pub fn clear_path_special_node(path: &str) {
    crate::root::clear_path_special_node(path);
}

pub fn set_path_fs_flags(path: &str, fs_flags: u32) {
    crate::root::set_path_fs_flags(path, fs_flags);
}

pub fn set_path_owner(path: &str, uid: Option<u32>, gid: Option<u32>) {
    crate::root::set_path_owner(path, uid, gid);
}

pub fn clear_path_special_bits(path: &str, mask: u16) {
    crate::root::clear_path_special_bits(path, mask);
}

/// Changes the current working directory to the specified path.
pub fn set_current_dir(path: &str) -> io::Result<()> {
    crate::root::set_current_dir(path)
}

pub fn set_current_root(path: &str) -> io::Result<()> {
    crate::root::set_current_root(path)
}

/// Read the entire contents of a file into a bytes vector.
pub fn read(path: &str) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Read the entire contents of a file into a string.
pub fn read_to_string(path: &str) -> io::Result<String> {
    let mut file = File::open(path)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let mut string = String::with_capacity(size as usize);
    file.read_to_string(&mut string)?;
    Ok(string)
}

/// Write a slice as the entire contents of a file.
pub fn write<C: AsRef<[u8]>>(path: &str, contents: C) -> io::Result<()> {
    File::create(path)?.write_all(contents.as_ref())
}

/// Given a path, query the file system to get information about a file,
/// directory, etc.
pub fn metadata(path: &str) -> io::Result<Metadata> {
    File::open(path)?.metadata()
}

/// Given a path, query the file system and return the underlying raw node
/// attributes without opening a file descriptor.
pub fn metadata_raw(path: &str) -> io::Result<crate::fops::FileAttr> {
    crate::root::lookup(None, path)?.get_attr()
}

pub fn metadata_raw_nofollow(path: &str) -> io::Result<crate::fops::FileAttr> {
    if let Ok(target) = readlink(path) {
        let size = target.len() as u64;
        let blocks = size.div_ceil(512);
        return Ok(crate::fops::FileAttr::new(
            VfsNodePerm::from_bits_truncate(0o777),
            VfsNodeType::SymLink,
            size,
            blocks,
        ));
    }
    metadata_raw(path)
}

pub fn metadata_raw_ax(path: &str) -> Result<crate::fops::FileAttr, AxError> {
    crate::root::lookup(None, path).and_then(|node| node.get_attr())
}

/// Creates a new, empty directory at the provided path.
pub fn create_dir(path: &str) -> io::Result<()> {
    DirBuilder::new().create(path)
}

pub fn create_fifo(path: &str) -> io::Result<()> {
    crate::root::create_fifo(None, path).map(|_| ())
}

pub fn create_socket(path: &str) -> io::Result<()> {
    crate::root::create_socket(None, path).map(|_| ())
}

/// Recursively create a directory and all of its parent components if they
/// are missing.
pub fn create_dir_all(path: &str) -> io::Result<()> {
    DirBuilder::new().recursive(true).create(path)
}

/// Removes an empty directory.
pub fn remove_dir(path: &str) -> io::Result<()> {
    crate::root::remove_dir(None, path)
}

/// Removes a file from the filesystem.
pub fn remove_file(path: &str) -> io::Result<()> {
    crate::root::remove_file(None, path)
}

/// Rename a file or directory to a new name.
/// Delete the original file if `old` already exists.
///
/// This only works then the new path is in the same mounted fs.
pub fn rename(old: &str, new: &str) -> io::Result<()> {
    crate::root::rename(old, new)
}

/// Mount a RAM filesystem at `path`.
pub fn mount_ramfs(path: &str, readonly: bool, remount: bool) -> io::Result<()> {
    crate::root::mount_ramfs(path, readonly, remount)
}

pub fn remount(path: &str, readonly: bool, kind: PathMountKind) -> io::Result<()> {
    crate::root::remount(path, readonly, kind)
}

pub fn move_mount(from: &str, to: &str) -> io::Result<()> {
    crate::root::move_mount(from, to)
}

pub fn bind_mount(from: &str, to: &str) -> io::Result<()> {
    crate::root::bind_mount(from, to)
}

pub fn mount_ramfs_with_max_bytes(
    path: &str,
    readonly: bool,
    remount: bool,
    max_bytes: Option<usize>,
) -> io::Result<()> {
    crate::root::mount_ramfs_with_max_bytes(path, readonly, remount, max_bytes)
}

pub fn mount_fatfs(path: &str, source: &str, readonly: bool, remount: bool) -> io::Result<()> {
    crate::root::mount_fatfs(path, source, readonly, remount)
}

#[cfg(feature = "fatfs")]
pub fn mount_fatfs_device<IO>(
    path: &str,
    device: IO,
    readonly: bool,
    remount: bool,
) -> io::Result<()>
where
    IO: FatFsIo + 'static,
{
    let mut mount_path = crate::root::absolute_path(path).map_err(io::Error::from)?;
    if mount_path != "/" {
        mount_path.truncate(mount_path.trim_end_matches('/').len());
    }
    let fs = Box::leak(Box::new(
        crate::fs::fatfs::FatFileSystem::try_new(FatFsDeviceAdapter(device))
            .map_err(io::Error::from)?,
    ));
    fs.init();
    let fs = Arc::new(MountedFatFs { inner: fs });
    crate::root::mount_fatfs_fs(mount_path.as_str(), fs, readonly, remount)
        .map_err(io::Error::from)
}

pub fn mount_ext4_image(path: &str, image: &[u8], readonly: bool, remount: bool) -> io::Result<()> {
    crate::root::mount_ext4_image(path, image, readonly, remount)
}

#[cfg(feature = "lwext4_rs")]
pub fn mount_ext4_device<K>(
    path: &str,
    block_dev: K::DevType,
    device_name: &str,
    readonly: bool,
    remount: bool,
) -> io::Result<()>
where
    K: KernelDevOp + 'static,
    K::DevType: 'static,
{
    let mut mount_path = crate::root::absolute_path(path).map_err(io::Error::from)?;
    if mount_path != "/" {
        mount_path.truncate(mount_path.trim_end_matches('/').len());
    }
    let fs = Arc::new(
        crate::fs::lwext4_rust::Ext4FileSystem::<K>::new(
            block_dev,
            mount_path.as_str(),
            device_name,
        )
            .map_err(ext4_status_to_io)?,
    );
    crate::root::mount_ext4_fs(mount_path.as_str(), fs, readonly, remount)
        .map_err(io::Error::from)
}

/// Unmount the filesystem mounted at `path`.
pub fn umount(path: &str) -> io::Result<()> {
    crate::root::umount(path)
}

pub fn is_readonly_path(path: &str) -> io::Result<bool> {
    crate::root::is_readonly_path(path)
}

pub fn mount_point_exists(path: &str) -> io::Result<bool> {
    crate::root::mount_point_exists(path)
}

pub fn note_mount_access(path: &str) {
    crate::root::note_mount_access(path);
}

pub fn prepare_expire_umount(path: &str) -> io::Result<bool> {
    crate::root::prepare_expire_umount(path).map_err(io::Error::from)
}

/// check whether absolute path exists.
pub fn absolute_path_exists(path: &str) -> bool {
    crate::root::lookup(None, path).is_ok()
}

#[cfg(feature = "lwext4_rs")]
fn ext4_link_count(path: &str) -> io::Result<u32> {
    let c_path = CString::new(path).map_err(|_| io::Error::from(AxError::InvalidInput))?;
    let mut ino = 0u32;
    let mut inode: ext4_inode = unsafe { core::mem::zeroed() };
    let status = unsafe { ext4_raw_inode_fill(c_path.as_ptr(), &mut ino, &mut inode) };
    if status == EOK as i32 {
        Ok(u16::from_le(inode.links_count) as u32)
    } else {
        Err(ext4_status_to_io(status))
    }
}

pub fn link_count(path: &str, attr: crate::fops::FileAttr) -> io::Result<u32> {
    let resolved = crate::root::absolute_path(path)?;
    if matches!(
        crate::root::path_mount_kind(resolved.as_str()),
        crate::root::MountedFsKind::Ext4
    ) {
        #[cfg(feature = "lwext4_rs")]
        if let Ok(count) = ext4_link_count(resolved.as_str()) {
            if !attr.is_dir() || count >= 2 {
                return Ok(count.max(if attr.is_dir() { 2 } else { 1 }));
            }
        }
    }

    if !attr.is_dir() {
        return Ok(1);
    }

    let mut count = 2u32;
    for entry in read_dir(resolved.as_str())? {
        let entry = entry?;
        if entry.file_type().is_dir() {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

#[cfg(feature = "lwext4_rs")]
pub fn set_mode(path: &str, mode: u32) -> io::Result<()> {
    let resolved = crate::root::absolute_path(path)?;
    let masked = (mode as u16) & 0o7777;
    let mount_kind = crate::root::path_mount_kind(resolved.as_str());
    #[cfg(feature = "ramfs")]
    {
        let node = crate::root::lookup(None, resolved.as_str())?;
        let perm = VfsNodePerm::from_bits_truncate((mode as u16) & 0o777);
        if let Some(file) = node.as_any().downcast_ref::<axfs_ramfs::FileNode>() {
            file.set_perm(perm);
            crate::root::set_path_mode(resolved.as_str(), masked);
            return Ok(());
        }
        if let Some(dir) = node.as_any().downcast_ref::<axfs_ramfs::DirNode>() {
            dir.set_perm(perm);
            crate::root::set_path_mode(resolved.as_str(), masked);
            return Ok(());
        }
    }
    if !matches!(mount_kind, crate::root::MountedFsKind::Ext4) {
        crate::root::set_path_mode(resolved.as_str(), masked);
        return Ok(());
    }
    let c_path =
        CString::new(resolved.as_str()).map_err(|_| io::Error::from(AxError::InvalidInput))?;
    let status = unsafe { ext4_mode_set(c_path.as_ptr(), mode) };
    if status == EOK as i32 {
        crate::root::set_path_mode(resolved.as_str(), masked);
        Ok(())
    } else {
        Err(ext4_status_to_io(status))
    }
}

#[cfg(not(feature = "lwext4_rs"))]
pub fn set_mode(_path: &str, _mode: u32) -> io::Result<()> {
    Err(io::Error::from(AxError::Unsupported))
}

#[cfg(feature = "lwext4_rs")]
pub fn symlink(target: &str, path: &str) -> io::Result<()> {
    let target = CString::new(target).map_err(|_| io::Error::from(AxError::InvalidInput))?;
    let path = CString::new(path).map_err(|_| io::Error::from(AxError::InvalidInput))?;
    let status = unsafe { ext4_fsymlink(target.as_ptr(), path.as_ptr()) };
    if status == EOK as i32 {
        Ok(())
    } else {
        Err(ext4_status_to_io(status))
    }
}

#[cfg(not(feature = "lwext4_rs"))]
pub fn symlink(_target: &str, _path: &str) -> io::Result<()> {
    Err(io::Error::from(AxError::Unsupported))
}

#[cfg(feature = "lwext4_rs")]
pub fn readlink(path: &str) -> io::Result<Vec<u8>> {
    let path = CString::new(path).map_err(|_| io::Error::from(AxError::InvalidInput))?;
    let mut cap = 256usize;
    loop {
        let mut buf = vec![0u8; cap];
        let mut read_len = 0usize;
        let status = unsafe {
            ext4_readlink(
                path.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut read_len as *mut _,
            )
        };
        if status != EOK as i32 {
            return Err(ext4_status_to_io(status));
        }
        buf.truncate(read_len);
        if read_len < cap {
            return Ok(buf);
        }
        cap = cap.saturating_mul(2);
    }
}

#[cfg(not(feature = "lwext4_rs"))]
pub fn readlink(_path: &str) -> io::Result<Vec<u8>> {
    Err(io::Error::from(AxError::Unsupported))
}
