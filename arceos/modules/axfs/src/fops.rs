//! Low-level filesystem operations.

use alloc::{string::String, vec::Vec};
use axerrno::{AxError, AxResult, ax_err, ax_err_type};
use axfs_vfs::{VfsError, VfsNodeRef};
use axio::SeekFrom;
use cap_access::{Cap, WithCap};
use core::cmp::min;
use core::fmt;

#[cfg(feature = "myfs")]
pub use crate::dev::Disk;
#[cfg(feature = "myfs")]
pub use crate::fs::myfs::MyFileSystemIf;

/// Alias of [`axfs_vfs::VfsNodeType`].
pub type FileType = axfs_vfs::VfsNodeType;
/// Alias of [`axfs_vfs::VfsDirEntry`].
pub type DirEntry = axfs_vfs::VfsDirEntry;
/// Alias of [`axfs_vfs::VfsNodeAttr`].
pub type FileAttr = axfs_vfs::VfsNodeAttr;
/// Alias of [`axfs_vfs::VfsNodePerm`].
pub type FilePerm = axfs_vfs::VfsNodePerm;

/// An opened file object, with open permissions and a cursor.
pub struct File {
    node: WithCap<VfsNodeRef>,
    is_append: bool,
    offset: u64,
    path: String,
}

/// An opened directory object, with open permissions and a cursor for
/// [`read_dir`](Directory::read_dir).
pub struct Directory {
    node: WithCap<VfsNodeRef>,
    entry_idx: usize,
    dirents_cache: Option<Vec<DirEntry>>,
    path: String,
}

/// Options and flags which can be used to configure how a file is opened.
#[derive(Clone)]
pub struct OpenOptions {
    // generic
    read: bool,
    write: bool,
    execute: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    directory: bool,
    path_only: bool,
    // system-specific
    _custom_flags: i32,
    _mode: u32,
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    pub const fn new() -> Self {
        Self {
            // generic
            read: false,
            write: false,
            execute: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            directory: false,
            path_only: false,
            // system-specific
            _custom_flags: 0,
            _mode: 0o666,
        }
    }
    /// Sets the option for read access.
    pub fn read(&mut self, read: bool) {
        self.read = read;
    }
    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) {
        self.write = write;
    }
    /// Sets the option for execute access.
    pub fn execute(&mut self, execute: bool) {
        self.execute = execute;
    }
    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) {
        self.append = append;
    }
    /// Sets the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }
    /// Sets the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) {
        self.create = create;
    }
    /// Sets the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }
    /// Sets the option to open a directory.
    pub fn directory(&mut self, directory: bool) {
        self.directory = directory;
    }
    /// Sets the option to open a path-only descriptor.
    pub fn path_only(&mut self, path_only: bool) {
        self.path_only = path_only;
    }
    /// check whether contains directory.
    pub fn has_directory(&self) -> bool {
        self.directory
    }

    /// Sets the create flags.
    pub fn set_create(mut self, create: bool, create_new: bool) -> Self {
        self.create = create;
        self.create_new = create_new;
        self
    }

    /// Sets the read flag.
    pub fn set_read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets the write flag.
    pub fn set_write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    const fn is_valid(&self) -> bool {
        if self.path_only {
            return !(self.write || self.append || self.truncate || self.create || self.create_new);
        }
        if !self.read && !self.write && !self.append && !self.directory {
            return false;
        }
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate {
                    return false;
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return false;
                }
            }
        }
        true
    }
}

impl File {
    fn access_node(&self, cap: Cap) -> AxResult<&VfsNodeRef> {
        self.node.access_or_err(cap, AxError::PermissionDenied)
    }

    fn _open_at(dir: Option<&VfsNodeRef>, path: &str, opts: &OpenOptions) -> AxResult<Self> {
        debug!("open file: {} {:?}", path, opts);
        if !opts.is_valid() {
            return ax_err!(InvalidInput);
        }

        let node_option = crate::root::lookup(dir, path);
        let node = if opts.create || opts.create_new {
            match node_option {
                Ok(node) => {
                    // already exists
                    if opts.create_new {
                        return ax_err!(AlreadyExists);
                    }
                    node
                }
                // not exists, create new
                Err(VfsError::NotFound) => crate::root::create_file(dir, path)?,
                Err(e) => return Err(e),
            }
        } else {
            // just open the existing
            node_option?
        };

        let attr = node.get_attr()?;
        if attr.is_dir()
            && (opts.create || opts.create_new || opts.write || opts.append || opts.truncate)
        {
            return ax_err!(IsADirectory);
        }
        let access_cap = opts.into();
        let resolved_path = crate::root::absolute_path(path).unwrap_or_else(|_| path.into());
        if !opts.path_only && !perm_to_cap(resolved_path.as_str(), attr.perm()).contains(access_cap)
        {
            return ax_err!(PermissionDenied);
        }

        node.open()?;
        if opts.truncate {
            node.truncate(0)?;
        }
        Ok(Self {
            node: WithCap::new(node, access_cap),
            is_append: opts.append,
            offset: 0,
            path: resolved_path,
        })
    }

    /// Opens a file at the path relative to the current directory. Returns a
    /// [`File`] object.
    pub fn open(path: &str, opts: &OpenOptions) -> AxResult<Self> {
        Self::_open_at(None, path, opts)
    }

    /// Truncates the file to the specified size.
    pub fn truncate(&self, size: u64) -> AxResult {
        self.access_node(Cap::WRITE)?.truncate(size)?;
        Ok(())
    }

    pub fn fallocate(&self, mode: u32, offset: u64, len: u64) -> AxResult {
        let node = self.access_node(Cap::WRITE)?;
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ax_err_type!(InvalidInput))?;
        const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
        const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;
        const FALLOC_FL_PUNCH_HOLE_KEEP_SIZE: u32 = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE;

        #[cfg(feature = "ramfs")]
        if let Some(file) = node.as_any().downcast_ref::<axfs_ramfs::FileNode>() {
            return match mode {
                0 => file.allocate_range(offset, len, false),
                FALLOC_FL_KEEP_SIZE => file.allocate_range(offset, len, true),
                FALLOC_FL_PUNCH_HOLE_KEEP_SIZE => file.punch_hole(offset, len),
                _ => ax_err!(Unsupported),
            };
        }

        if mode != 0 && mode != FALLOC_FL_KEEP_SIZE {
            return if mode == FALLOC_FL_PUNCH_HOLE_KEEP_SIZE {
                ax_err!(Unsupported)
            } else {
                ax_err!(Unsupported)
            };
        }

        let original_size = node.get_attr()?.size();
        if mode == 0 && end > original_size {
            const MATERIALIZE_LIMIT: u64 = 16 * 1024 * 1024;
            const MATERIALIZE_STEP: usize = 4096;
            let materialize_len = end - original_size;
            if materialize_len <= MATERIALIZE_LIMIT {
                let zeros = [0u8; MATERIALIZE_STEP];
                let mut pos = original_size;
                while pos < end {
                    let write_len = ((end - pos) as usize).min(MATERIALIZE_STEP);
                    let written = node.write_at(pos, &zeros[..write_len])?;
                    if written == 0 {
                        return ax_err!(StorageFull);
                    }
                    pos = pos
                        .checked_add(written as u64)
                        .ok_or_else(|| ax_err_type!(InvalidInput))?;
                }
            } else {
                let written = node.write_at(end - 1, &[0])?;
                if written == 0 {
                    return ax_err!(StorageFull);
                }
            }
        }
        Ok(())
    }

    /// Reads the file at the current position. Returns the number of bytes
    /// read.
    ///
    /// After the read, the cursor will be advanced by the number of bytes read.
    pub fn read(&mut self, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.access_node(Cap::READ)?;
        let read_len = node.read_at(self.offset, buf)?;
        self.offset += read_len as u64;
        Ok(read_len)
    }

    /// Reads the file at the given position. Returns the number of bytes read.
    ///
    /// It does not update the file cursor.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.access_node(Cap::READ)?;
        let read_len = node.read_at(offset, buf)?;
        Ok(read_len)
    }

    pub fn read_at_for_exec(&self, offset: u64, buf: &mut [u8]) -> AxResult<usize> {
        let node = self.access_node(Cap::empty())?;
        let read_len = node.read_at(offset, buf)?;
        Ok(read_len)
    }

    /// Writes the file at the current position. Returns the number of bytes
    /// written.
    ///
    /// After the write, the cursor will be advanced by the number of bytes
    /// written.
    pub fn write(&mut self, buf: &[u8]) -> AxResult<usize> {
        let offset = if self.is_append {
            self.get_attr()?.size()
        } else {
            self.offset
        };
        let node = self.access_node(Cap::WRITE)?;
        let write_len = node.write_at(offset, buf)?;
        self.offset = offset + write_len as u64;
        Ok(write_len)
    }

    /// Writes the file at the given position. Returns the number of bytes
    /// written.
    ///
    /// It does not update the file cursor.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> AxResult<usize> {
        let node = self.access_node(Cap::WRITE)?;
        let write_len = node.write_at(offset, buf)?;
        Ok(write_len)
    }

    /// Flushes the file, writes all buffered data to the underlying device.
    pub fn flush(&self) -> AxResult {
        self.access_node(Cap::WRITE)?.fsync()?;
        Ok(())
    }

    /// Updates whether writes should append to the end of file.
    pub fn set_append(&mut self, append: bool) {
        self.is_append = append;
    }

    /// Sets the cursor of the file to the specified offset. Returns the new
    /// position after the seek.
    pub fn seek(&mut self, pos: SeekFrom) -> AxResult<u64> {
        let new_offset = match pos {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::Current(off) => self.offset.checked_add_signed(off),
            SeekFrom::End(off) => self.get_attr()?.size().checked_add_signed(off),
        }
        .ok_or_else(|| ax_err_type!(InvalidInput))?;
        self.offset = new_offset;
        Ok(new_offset)
    }

    /// Gets the file attributes.
    pub fn get_attr(&self) -> AxResult<FileAttr> {
        self.access_node(Cap::empty())?.get_attr()
    }
}

impl Directory {
    fn access_node(&self, cap: Cap) -> AxResult<&VfsNodeRef> {
        self.node.access_or_err(cap, AxError::PermissionDenied)
    }

    fn _open_dir_at(dir: Option<&VfsNodeRef>, path: &str, opts: &OpenOptions) -> AxResult<Self> {
        debug!("open dir: {}", path);
        if !opts.read && !opts.path_only {
            return ax_err!(InvalidInput);
        }
        if opts.create || opts.create_new || opts.write || opts.append || opts.truncate {
            return ax_err!(InvalidInput);
        }

        let node = crate::root::lookup(dir, path)?;
        let attr = node.get_attr()?;
        if !attr.is_dir() {
            return ax_err!(NotADirectory);
        }
        let access_cap = opts.into();
        let resolved_path = crate::root::absolute_path(path).unwrap_or_else(|_| path.into());
        if !opts.path_only && !perm_to_cap(resolved_path.as_str(), attr.perm()).contains(access_cap)
        {
            return ax_err!(PermissionDenied);
        }

        node.open()?;
        Ok(Self {
            node: WithCap::new(node, access_cap),
            entry_idx: 0,
            dirents_cache: None,
            path: if resolved_path.ends_with('/') || resolved_path == "/" {
                resolved_path
            } else {
                alloc::format!("{resolved_path}/")
            },
        })
    }

    fn access_at(&self, path: &str) -> AxResult<Option<&VfsNodeRef>> {
        if path.starts_with('/') {
            Ok(None)
        } else {
            Ok(Some(self.access_node(Cap::empty())?))
        }
    }

    /// Opens a directory at the path relative to the current directory.
    /// Returns a [`Directory`] object.
    pub fn open_dir(path: &str, opts: &OpenOptions) -> AxResult<Self> {
        Self::_open_dir_at(None, path, opts)
    }

    /// Opens a directory at the path relative to this directory. Returns a
    /// [`Directory`] object.
    pub fn open_dir_at(&self, path: &str, opts: &OpenOptions) -> AxResult<Self> {
        Self::_open_dir_at(self.access_at(path)?, path, opts)
    }

    /// Opens a file at the path relative to this directory. Returns a [`File`]
    /// object.
    pub fn open_file_at(&self, path: &str, opts: &OpenOptions) -> AxResult<File> {
        let full_path = if path.starts_with('/') {
            path.into()
        } else if self.path == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}{}", self.path, path)
        };
        File::_open_at(self.access_at(path)?, full_path.as_str(), opts)
    }

    /// Creates an empty file at the path relative to this directory.
    pub fn create_file(&self, path: &str) -> AxResult<VfsNodeRef> {
        let full_path = if path.starts_with('/') {
            path.into()
        } else if self.path == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}{}", self.path, path)
        };
        crate::root::create_file(self.access_at(path)?, full_path.as_str())
    }

    /// Creates an empty directory at the path relative to this directory.
    pub fn create_dir(&self, path: &str) -> AxResult {
        let full_path = if path.starts_with('/') {
            path.into()
        } else if self.path == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}{}", self.path, path)
        };
        crate::root::create_dir(self.access_at(path)?, full_path.as_str())
    }

    /// Removes a file at the path relative to this directory.
    pub fn remove_file(&self, path: &str) -> AxResult {
        let full_path = if path.starts_with('/') {
            path.into()
        } else if self.path == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}{}", self.path, path)
        };
        crate::root::remove_file(self.access_at(path)?, full_path.as_str())
    }

    /// Removes a directory at the path relative to this directory.
    pub fn remove_dir(&self, path: &str) -> AxResult {
        let full_path = if path.starts_with('/') {
            path.into()
        } else if self.path == "/" {
            alloc::format!("/{}", path)
        } else {
            alloc::format!("{}{}", self.path, path)
        };
        crate::root::remove_dir(self.access_at(path)?, full_path.as_str())
    }

    /// Reads directory entries starts from the current position into the
    /// given buffer. Returns the number of entries read.
    ///
    /// After the read, the cursor will be advanced by the number of entries
    /// read.
    pub fn read_dir(&mut self, dirents: &mut [DirEntry]) -> AxResult<usize> {
        const DIR_READ_CACHE_BATCH: usize = 64;

        if self.dirents_cache.is_none() {
            let mut cached = Vec::new();
            let mut start_idx = 0usize;
            loop {
                let mut batch: [DirEntry; DIR_READ_CACHE_BATCH] =
                    core::array::from_fn(|_| DirEntry::default());
                let read = self
                    .access_node(Cap::READ)?
                    .read_dir(start_idx, &mut batch)?;
                if read == 0 {
                    break;
                }
                for entry in &batch[..read] {
                    let name = core::str::from_utf8(entry.name_as_bytes())
                        .map_err(|_| AxError::InvalidData)?;
                    cached.push(DirEntry::new(name, entry.entry_type()));
                }
                start_idx += read;
            }
            self.dirents_cache = Some(cached);
        }

        let cached = self.dirents_cache.as_ref().unwrap();
        if self.entry_idx >= cached.len() {
            return Ok(0);
        }

        let read = min(dirents.len(), cached.len() - self.entry_idx);
        for (out, entry) in dirents.iter_mut().zip(&cached[self.entry_idx..]).take(read) {
            let name =
                core::str::from_utf8(entry.name_as_bytes()).map_err(|_| AxError::InvalidData)?;
            *out = DirEntry::new(name, entry.entry_type());
        }
        self.entry_idx += read;
        Ok(read)
    }

    /// Rename a file or directory to a new name.
    /// Delete the original file if `old` already exists.
    ///
    /// This only works then the new path is in the same mounted fs.
    pub fn rename(&self, old: &str, new: &str) -> AxResult {
        crate::root::rename(old, new)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        unsafe { self.node.access_unchecked().release().ok() };
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        unsafe { self.node.access_unchecked().release().ok() };
    }
}

impl fmt::Debug for OpenOptions {
    #[allow(unused_assignments)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut written = false;
        macro_rules! fmt_opt {
            ($field: ident, $label: literal) => {
                if self.$field {
                    if written {
                        write!(f, " | ")?;
                    }
                    write!(f, $label)?;
                    written = true;
                }
            };
        }
        fmt_opt!(read, "READ");
        fmt_opt!(write, "WRITE");
        fmt_opt!(append, "APPEND");
        fmt_opt!(truncate, "TRUNC");
        fmt_opt!(create, "CREATE");
        fmt_opt!(create_new, "CREATE_NEW");
        fmt_opt!(path_only, "PATH");
        Ok(())
    }
}

impl From<&OpenOptions> for Cap {
    fn from(opts: &OpenOptions) -> Cap {
        if opts.path_only {
            return Cap::empty();
        }
        let mut cap = Cap::empty();
        if opts.read {
            cap |= Cap::READ;
        }
        if opts.write | opts.append {
            cap |= Cap::WRITE;
        }
        if opts.execute {
            cap |= Cap::EXECUTE;
        }
        cap
    }
}

fn perm_to_cap(path: &str, perm: FilePerm) -> Cap {
    let attr = axfs_vfs::VfsNodeAttr::new(perm, FileType::File, 0, 0);
    crate::root::access_caps(path, attr, false)
}
