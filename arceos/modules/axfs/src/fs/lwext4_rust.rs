use crate::alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use alloc::ffi::CString;
use alloc::sync::Arc;
use axerrno::{AxError, LinuxError};
use axfs_vfs::{VfsDirEntry, VfsError, VfsNodePerm, VfsResult};
use axfs_vfs::{VfsNodeAttr, VfsNodeOps, VfsNodeRef, VfsNodeType, VfsOps};
use axsync::Mutex;
use core::sync::atomic::{AtomicUsize, Ordering};
use lazyinit::LazyInit;
use lwext4_rust::bindings::{
    O_CREAT, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SEEK_CUR, SEEK_END, SEEK_SET, ext4_mknod,
};
use lwext4_rust::{Ext4BlockWrapper, Ext4File, InodeTypes, KernelDevOp};

use crate::dev::{Disk, SharedRamDisk};
pub const BLOCK_SIZE: usize = 512;
fn linux_err_to_ax(err: LinuxError) -> AxError {
    match err {
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
    }
}

pub(crate) fn ext4_err_to_vfs(err: i32) -> VfsError {
    LinuxError::try_from(err)
        .map(linux_err_to_ax)
        .unwrap_or(AxError::Io)
}

#[allow(dead_code)]
pub struct Ext4FileSystem<K: KernelDevOp> {
    inner: Mutex<Ext4BlockWrapper<K>>,
    root: VfsNodeRef,
}

pub type DiskExt4FileSystem = Ext4FileSystem<Disk>;
pub type RamExt4FileSystem = Ext4FileSystem<SharedRamDisk>;

unsafe impl<K: KernelDevOp> Sync for Ext4FileSystem<K> {}
unsafe impl<K: KernelDevOp> Send for Ext4FileSystem<K> {}

static NEXT_EXT4_INTERNAL_MOUNT_ID: AtomicUsize = AtomicUsize::new(0);

impl<K: KernelDevOp> Ext4FileSystem<K> {
    pub fn new(block_dev: K::DevType, mount_point: &str, device_name: &str) -> Result<Self, i32> {
        let normalized_mount_point = if mount_point == "/" {
            String::from("/")
        } else {
            let _mount_id = NEXT_EXT4_INTERNAL_MOUNT_ID.fetch_add(1, Ordering::Relaxed);
            mount_point.trim_end_matches('/').to_string()
        };
        let lwext4_mount_point = if normalized_mount_point == "/" {
            String::from("/")
        } else {
            format!("{}/", normalized_mount_point)
        };
        let inner = Ext4BlockWrapper::<K>::new(
            block_dev,
            lwext4_mount_point.as_str(),
            device_name,
        )?;
        FileWrapper::invalidate_shared_dir_entries();
        FileWrapper::invalidate_shared_nodes();
        let root = Arc::new(FileWrapper::new(
            lwext4_mount_point.as_str(),
            InodeTypes::EXT4_DE_DIR,
        ));
        Ok(Self {
            inner: Mutex::new(inner),
            root,
        })
    }
}

impl DiskExt4FileSystem {
    pub fn new_root(disk: Disk) -> Self {
        info!(
            "Got Disk size:{}, position:{}",
            disk.size(),
            disk.position()
        );
        Self::new(disk, "/", "ext4_fs").expect("failed to initialize EXT4 filesystem")
    }
}

/// The [`VfsOps`] trait provides operations on a filesystem.
impl<K: KernelDevOp> VfsOps for Ext4FileSystem<K> {
    fn umount(&self) -> VfsResult {
        FileWrapper::invalidate_shared_dir_entries();
        FileWrapper::invalidate_shared_nodes();
        let result = self.inner.lock().lwext4_umount();
        FileWrapper::invalidate_shared_dir_entries();
        FileWrapper::invalidate_shared_nodes();
        result.map(|_| ()).map_err(ext4_err_to_vfs)
    }

    fn root_dir(&self) -> VfsNodeRef {
        debug!("Get root_dir");
        Arc::clone(&self.root)
    }
}

pub struct FileWrapper(
    Mutex<Ext4File>,
    Mutex<Option<Arc<Vec<(Vec<u8>, InodeTypes)>>>>,
);

unsafe impl Send for FileWrapper {}
unsafe impl Sync for FileWrapper {}

const MAX_SHARED_DIR_ENTRY_CACHE: usize = 2048;
const MAX_CACHEABLE_DIR_ENTRIES: usize = 4096;
const MAX_SHARED_NODE_CACHE: usize = 2048;

static DIR_ENTRY_CACHE: LazyInit<Mutex<BTreeMap<String, Arc<Vec<(Vec<u8>, InodeTypes)>>>>> =
    LazyInit::new();
static NODE_CACHE: LazyInit<Mutex<BTreeMap<String, Arc<FileWrapper>>>> = LazyInit::new();

impl FileWrapper {
    fn shared_dir_entry_cache() -> &'static Mutex<BTreeMap<String, Arc<Vec<(Vec<u8>, InodeTypes)>>>>
    {
        if !DIR_ENTRY_CACHE.is_inited() {
            DIR_ENTRY_CACHE.init_once(Mutex::new(BTreeMap::new()));
        }
        &DIR_ENTRY_CACHE
    }

    fn shared_node_cache() -> &'static Mutex<BTreeMap<String, Arc<FileWrapper>>> {
        if !NODE_CACHE.is_inited() {
            NODE_CACHE.init_once(Mutex::new(BTreeMap::new()));
        }
        &NODE_CACHE
    }

    fn new(path: &str, types: InodeTypes) -> Self {
        debug!("FileWrapper new {:?} {}", types, path);
        //file.file_read_test("/test/test.txt", &mut buf);

        Self(Mutex::new(Ext4File::new(path, types)), Mutex::new(None))
    }

    fn path_and_type(&self) -> (String, InodeTypes) {
        let file = self.0.lock();
        (
            file.get_path().to_str().unwrap().to_string(),
            file.get_type(),
        )
    }

    fn path_deal_with(&self, path: &str) -> String {
        if path.starts_with('/') {
            debug!("path_deal_with: {}", path);
        }
        let p = path.trim_matches('/'); // 首尾去除
        if p.is_empty() || p == "." {
            return String::new();
        }

        if let Some(rest) = p.strip_prefix("./") {
            //if starts with "./"
            return self.path_deal_with(rest);
        }
        let rest_p = p.replace("//", "/");
        if p != rest_p {
            return self.path_deal_with(&rest_p);
        }

        //Todo ? ../
        //注：lwext4创建文件必须提供文件path的绝对路径
        let file = self.0.lock();
        let path = file.get_path();
        let fpath = String::from(path.to_str().unwrap().trim_end_matches('/')) + "/" + p;
        debug!("dealt with full path: {}", fpath.as_str());
        fpath
    }

    fn load_dir_entries(&self) -> Option<Arc<Vec<(Vec<u8>, InodeTypes)>>> {
        let mut cache = self.1.lock();
        if let Some(entries) = cache.as_ref() {
            return Some(Arc::clone(entries));
        }

        let file = self.0.lock();
        if file.get_type() != InodeTypes::EXT4_DE_DIR {
            return None;
        }

        let dir_path = file
            .get_path()
            .to_str()
            .unwrap()
            .trim_end_matches('/')
            .to_string();
        let shared_cache = Self::shared_dir_entry_cache();
        if let Some(entries) = shared_cache.lock().get(dir_path.as_str()).cloned() {
            *cache = Some(Arc::clone(&entries));
            return Some(entries);
        }

        let (names, inode_types) = file.lwext4_dir_entries().ok()?;
        let entries = Arc::new(names.into_iter().zip(inode_types).collect::<Vec<_>>());
        if entries.len() <= MAX_CACHEABLE_DIR_ENTRIES {
            let mut shared = shared_cache.lock();
            if shared.len() >= MAX_SHARED_DIR_ENTRY_CACHE {
                shared.clear();
            }
            shared.insert(dir_path, Arc::clone(&entries));
        }
        *cache = Some(Arc::clone(&entries));
        Some(entries)
    }

    fn cached_child_type(&self, path: &str) -> Option<InodeTypes> {
        if path.is_empty() || path.contains('/') {
            return None;
        }

        let child = path.as_bytes();
        self.load_dir_entries().and_then(|entries| {
            entries.iter().find_map(|(name, ty)| {
                let len = name
                    .iter()
                    .position(|&byte| byte == 0)
                    .unwrap_or(name.len());
                (name[..len] == *child).then(|| ty.clone())
            })
        })
    }

    fn invalidate_cached_dir_entries(&self) {
        *self.1.lock() = None;
    }

    fn invalidate_shared_dir_entries() {
        if DIR_ENTRY_CACHE.is_inited() {
            DIR_ENTRY_CACHE.lock().clear();
        }
    }

    fn cache_key(path: &str, types: InodeTypes) -> String {
        alloc::format!("{}#{:?}", path, types)
    }

    fn cached_node(path: &str, types: InodeTypes) -> VfsNodeRef {
        let cache_key = Self::cache_key(path, types.clone());
        let shared_cache = Self::shared_node_cache();
        if let Some(node) = shared_cache.lock().get(cache_key.as_str()).cloned() {
            return node;
        }
        let node = Arc::new(Self::new(path, types));
        let mut shared = shared_cache.lock();
        if shared.len() >= MAX_SHARED_NODE_CACHE {
            shared.clear();
        }
        shared.insert(cache_key, node.clone());
        node
    }

    fn invalidate_shared_nodes() {
        if NODE_CACHE.is_inited() {
            NODE_CACHE.lock().clear();
        }
    }
}

/// The [`VfsNodeOps`] trait provides operations on a file or a directory.
impl VfsNodeOps for FileWrapper {
    fn release(&self) -> VfsResult {
        let mut file = self.0.lock();
        file.file_close().map(|_| ()).map_err(ext4_err_to_vfs)
    }

    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let mut file = self.0.lock();
        let path = file.get_path().to_str().unwrap().to_string();

        let mode = file.file_mode_get().map_err(ext4_err_to_vfs)?;
        let perm = VfsNodePerm::from_bits_truncate((mode as u16) & 0o777);
        let vtype = match mode & InodeTypes::EXT4_INODE_MODE_TYPE_MASK as u32 {
            x if x == InodeTypes::EXT4_INODE_MODE_FIFO as u32 => VfsNodeType::Fifo,
            x if x == InodeTypes::EXT4_INODE_MODE_CHARDEV as u32 => VfsNodeType::CharDevice,
            x if x == InodeTypes::EXT4_INODE_MODE_DIRECTORY as u32 => VfsNodeType::Dir,
            x if x == InodeTypes::EXT4_INODE_MODE_BLOCKDEV as u32 => VfsNodeType::BlockDevice,
            x if x == InodeTypes::EXT4_INODE_MODE_FILE as u32 => VfsNodeType::File,
            x if x == InodeTypes::EXT4_INODE_MODE_SOFTLINK as u32 => VfsNodeType::SymLink,
            x if x == InodeTypes::EXT4_INODE_MODE_SOCKET as u32 => VfsNodeType::Socket,
            _ => {
                warn!("unknown file type mode={:#x} path={}", mode, path);
                VfsNodeType::File
            }
        };

        let size = if vtype == VfsNodeType::File {
            if file.is_open() {
                file.file_close().map_err(ext4_err_to_vfs)?;
            }
            file.ensure_open_for_read(path.as_str())
                .map_err(ext4_err_to_vfs)?;
            file.file_size()
        } else {
            0 // DIR size ?
        };
        let blocks = (size + (BLOCK_SIZE as u64 - 1)) / BLOCK_SIZE as u64;

        info!(
            "get_attr of {:?} {:?}, size: {}, blocks: {}",
            vtype,
            file.get_path(),
            size,
            blocks
        );

        Ok(VfsNodeAttr::new(perm, vtype, size, blocks))
    }

    fn create(&self, path: &str, ty: VfsNodeType) -> VfsResult {
        info!("create {:?} on Ext4fs: {}", ty, path);
        let fpath = self.path_deal_with(path);
        let fpath = fpath.as_str();
        if fpath.is_empty() {
            return Ok(());
        }

        let types = match ty {
            VfsNodeType::Fifo => InodeTypes::EXT4_DE_FIFO,
            VfsNodeType::CharDevice => InodeTypes::EXT4_DE_CHRDEV,
            VfsNodeType::Dir => InodeTypes::EXT4_DE_DIR,
            VfsNodeType::BlockDevice => InodeTypes::EXT4_DE_BLKDEV,
            VfsNodeType::File => InodeTypes::EXT4_DE_REG_FILE,
            VfsNodeType::SymLink => InodeTypes::EXT4_DE_SYMLINK,
            VfsNodeType::Socket => InodeTypes::EXT4_DE_SOCK,
        };

        let result = if types == InodeTypes::EXT4_DE_FIFO {
            let mut file = self.0.lock();
            let exists = file.check_inode_exist(fpath, types.clone());
            drop(file);
            if exists {
                Ok(())
            } else {
                let path = CString::new(fpath).map_err(|_| VfsError::InvalidInput)?;
                let status = unsafe { ext4_mknod(path.as_ptr(), types as i32, 0) };
                if status == 0 {
                    Ok(())
                } else {
                    Err(ext4_err_to_vfs(status))
                }
            }
        } else {
            let mut file = self.0.lock();
            let result = if file.check_inode_exist(fpath, types.clone()) {
                Ok(())
            } else if types == InodeTypes::EXT4_DE_DIR {
                file.dir_mk(fpath).map(|_v| ()).map_err(ext4_err_to_vfs)
            } else {
                file.file_open(fpath, O_WRONLY | O_CREAT | O_TRUNC)
                    .map_err(ext4_err_to_vfs)?;
                file.file_close().map(|_v| ()).map_err(ext4_err_to_vfs)
            };
            drop(file);
            result
        };
        if result.is_ok() {
            self.invalidate_cached_dir_entries();
            Self::invalidate_shared_dir_entries();
            Self::invalidate_shared_nodes();
        }
        result
    }

    fn remove(&self, path: &str) -> VfsResult {
        debug!("remove ext4fs: {}", path);
        let fpath = self.path_deal_with(path);
        let fpath = fpath.as_str();

        assert!(!fpath.is_empty()); // already check at `root.rs`

        let mut file = self.0.lock();
        let result = if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_DIR) {
            // Recursive directory remove
            file.dir_rm(fpath).map(|_v| ()).map_err(ext4_err_to_vfs)
        } else {
            file.file_remove(fpath)
                .map(|_v| ())
                .map_err(ext4_err_to_vfs)
        };
        drop(file);
        if result.is_ok() {
            self.invalidate_cached_dir_entries();
            Self::invalidate_shared_dir_entries();
            Self::invalidate_shared_nodes();
        }
        result
    }

    /// Get the parent directory of this directory.
    /// Return `None` if the node is a file.
    fn parent(&self) -> Option<VfsNodeRef> {
        let file = self.0.lock();
        if file.get_type() == InodeTypes::EXT4_DE_DIR {
            let path = file.get_path();
            let path = path.to_str().unwrap();
            debug!("Get the parent dir of {}", path);
            let path = path.trim_end_matches('/').trim_end_matches(|c| c != '/');
            if !path.is_empty() {
                return Some(Self::cached_node(path, InodeTypes::EXT4_DE_DIR));
            }
        }
        None
    }

    /// Read directory entries into `dirents`, starting from `start_idx`.
    fn read_dir(&self, start_idx: usize, dirents: &mut [VfsDirEntry]) -> VfsResult<usize> {
        let Some(entries) = self.load_dir_entries() else {
            return Ok(0);
        };

        let entries = &entries[start_idx.min(entries.len())..];
        let read = entries.len().min(dirents.len());
        for (out_entry, (name, inode_ty)) in dirents.iter_mut().zip(entries.iter()).take(read) {
            let ty = match *inode_ty {
                InodeTypes::EXT4_DE_DIR => VfsNodeType::Dir,
                InodeTypes::EXT4_DE_REG_FILE => VfsNodeType::File,
                InodeTypes::EXT4_DE_SYMLINK => VfsNodeType::SymLink,
                InodeTypes::EXT4_DE_FIFO => VfsNodeType::Fifo,
                InodeTypes::EXT4_DE_CHRDEV => VfsNodeType::CharDevice,
                InodeTypes::EXT4_DE_BLKDEV => VfsNodeType::BlockDevice,
                InodeTypes::EXT4_DE_SOCK => VfsNodeType::Socket,
                _ => {
                    error!("unknown file type: {:?}", inode_ty);
                    unreachable!()
                }
            };

            *out_entry = VfsDirEntry::new(core::str::from_utf8(name).unwrap(), ty);
        }
        Ok(read)
    }

    /// Lookup the node with given `path` in the directory.
    /// Return the node if found.
    fn lookup(self: Arc<Self>, path: &str) -> VfsResult<VfsNodeRef> {
        debug!("lookup ext4fs: {:?}, {}", self.0.lock().get_path(), path);

        let fpath = self.path_deal_with(path);
        let fpath = fpath.as_str();
        if fpath.is_empty() {
            return Ok(self.clone());
        }

        /////////
        let mut file = self.0.lock();
        if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_DIR) {
            debug!("lookup new DIR FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_DIR))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_REG_FILE) {
            debug!("lookup new FILE FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_REG_FILE))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_SYMLINK) {
            debug!("lookup new SYMLINK FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_SYMLINK))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_FIFO) {
            debug!("lookup new FIFO FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_FIFO))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_CHRDEV) {
            debug!("lookup new CHRDEV FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_CHRDEV))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_BLKDEV) {
            debug!("lookup new BLKDEV FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_BLKDEV))
        } else if file.check_inode_exist(fpath, InodeTypes::EXT4_DE_SOCK) {
            debug!("lookup new SOCK FileWrapper");
            Ok(Self::cached_node(fpath, InodeTypes::EXT4_DE_SOCK))
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let mut file = self.0.lock();
        let path = file.get_path().to_str().unwrap().to_string();
        file.ensure_open_for_read(path.as_str())
            .map_err(ext4_err_to_vfs)?;
        if offset >= file.file_size() {
            return Ok(0);
        }
        file.file_seek_if_needed(offset).map_err(ext4_err_to_vfs)?;
        file.file_read(buf).map_err(ext4_err_to_vfs)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let mut file = self.0.lock();
        let path = file.get_path().to_str().unwrap().to_string();
        file.ensure_open_for_write(path.as_str())
            .map_err(ext4_err_to_vfs)?;
        file.file_seek_if_needed(offset).map_err(ext4_err_to_vfs)?;
        file.file_write(buf).map_err(ext4_err_to_vfs)
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let mut file = self.0.lock();
        let path = file.get_path().to_str().unwrap().to_string();
        file.ensure_open_for_write(path.as_str())
            .map_err(ext4_err_to_vfs)?;
        file.file_truncate(size).map_err(ext4_err_to_vfs)?;
        Ok(())
    }

    fn rename(&self, src_path: &str, dst_path: &str) -> VfsResult {
        let src_path = self.path_deal_with(src_path);
        let dst_path = self.path_deal_with(dst_path);
        let mut file = self.0.lock();
        let result = file
            .file_rename(src_path.as_str(), dst_path.as_str())
            .map(|_v| ())
            .map_err(ext4_err_to_vfs);
        drop(file);
        if result.is_ok() {
            self.invalidate_cached_dir_entries();
            Self::invalidate_shared_dir_entries();
            Self::invalidate_shared_nodes();
        }
        result
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self as &dyn core::any::Any
    }

    fn fsync(&self) -> VfsResult {
        let mut file = self.0.lock();
        file.file_cache_flush().map_err(ext4_err_to_vfs)?;
        Ok(())
    }
}

impl Drop for FileWrapper {
    fn drop(&mut self) {
        let mut file = self.0.lock();
        debug!("Drop struct FileWrapper {:?}", file.get_path());
        file.file_close().expect("failed to close fd");
        drop(file); // todo
    }
}

pub(crate) fn reclaim_shared_caches() -> (usize, usize) {
    let reclaimed_dir_entries = if DIR_ENTRY_CACHE.is_inited() {
        let mut cache = DIR_ENTRY_CACHE.lock();
        let reclaimed = cache.len();
        cache.clear();
        reclaimed
    } else {
        0
    };
    let reclaimed_nodes = if NODE_CACHE.is_inited() {
        let mut cache = NODE_CACHE.lock();
        let reclaimed = cache.len();
        cache.clear();
        reclaimed
    } else {
        0
    };
    (reclaimed_dir_entries, reclaimed_nodes)
}

impl KernelDevOp for Disk {
    //type DevType = Box<Disk>;
    type DevType = Disk;

    fn read(dev: &mut Disk, mut buf: &mut [u8]) -> Result<usize, i32> {
        debug!("READ block device buf={}", buf.len());
        let mut read_len = 0;
        while !buf.is_empty() {
            match dev.read_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_len += n;
                }
                Err(_e) => return Err(-1),
            }
        }
        debug!("READ rt len={}", read_len);
        Ok(read_len)
    }
    fn write(dev: &mut Self::DevType, mut buf: &[u8]) -> Result<usize, i32> {
        debug!("WRITE block device buf={}", buf.len());
        let mut write_len = 0;
        while !buf.is_empty() {
            match dev.write_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &buf[n..];
                    write_len += n;
                }
                Err(_e) => return Err(-1),
            }
        }
        debug!("WRITE rt len={}", write_len);
        Ok(write_len)
    }
    fn flush(_dev: &mut Self::DevType) -> Result<usize, i32> {
        Ok(0)
    }
    fn seek(dev: &mut Disk, off: i64, whence: i32) -> Result<i64, i32> {
        let size = dev.size();
        debug!(
            "SEEK block device size:{}, pos:{}, offset={}, whence={}",
            size,
            &dev.position(),
            off,
            whence
        );
        let new_pos = match whence as u32 {
            SEEK_SET => Some(off),
            SEEK_CUR => dev.position().checked_add_signed(off).map(|v| v as i64),
            SEEK_END => size.checked_add_signed(off).map(|v| v as i64),
            _ => {
                error!("invalid seek() whence: {}", whence);
                Some(off)
            }
        }
        .ok_or(-1)?;

        if new_pos as u64 > size {
            warn!("Seek beyond the end of the block device");
        }
        dev.set_position(new_pos as u64);
        Ok(new_pos)
    }
}

impl KernelDevOp for SharedRamDisk {
    type DevType = SharedRamDisk;

    fn read(dev: &mut SharedRamDisk, mut buf: &mut [u8]) -> Result<usize, i32> {
        let mut read_len = 0;
        while !buf.is_empty() {
            match dev.read_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    let tmp = buf;
                    buf = &mut tmp[n..];
                    read_len += n;
                }
                Err(_) => return Err(-1),
            }
        }
        Ok(read_len)
    }

    fn write(dev: &mut SharedRamDisk, mut buf: &[u8]) -> Result<usize, i32> {
        let mut write_len = 0;
        while !buf.is_empty() {
            match dev.write_one(buf) {
                Ok(0) => break,
                Ok(n) => {
                    buf = &buf[n..];
                    write_len += n;
                }
                Err(_) => return Err(-1),
            }
        }
        Ok(write_len)
    }

    fn flush(_dev: &mut SharedRamDisk) -> Result<usize, i32> {
        Ok(0)
    }

    fn seek(dev: &mut SharedRamDisk, off: i64, whence: i32) -> Result<i64, i32> {
        let size = dev.size();
        let new_pos = match whence as u32 {
            SEEK_SET => Some(off),
            SEEK_CUR => dev.position().checked_add_signed(off).map(|v| v as i64),
            SEEK_END => size.checked_add_signed(off).map(|v| v as i64),
            _ => Some(off),
        }
        .ok_or(-1)?;
        if new_pos < 0 {
            return Err(-1);
        }
        dev.set_position(new_pos as u64);
        Ok(new_pos)
    }
}
