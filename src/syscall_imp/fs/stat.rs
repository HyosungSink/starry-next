use alloc::string::{String, ToString};
use core::ffi::c_void;

use arceos_posix_api as api;
use arceos_posix_api::get_file_like;
use axerrno::LinuxError;
use axfs::fops::FileAttr;

use super::{handle_user_path, read_user_path, resolve_existing_path};
use crate::syscall_body;
use crate::usercopy::write_value_to_user;

const FS_COMPR_FL: u32 = 0x0000_0004;
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;
const FS_NODUMP_FL: u32 = 0x0000_0040;
const STATX_DIOALIGN: u32 = 0x0000_2000;
const STATX_ATTR_COMPRESSED: u64 = FS_COMPR_FL as u64;
const STATX_ATTR_IMMUTABLE: u64 = FS_IMMUTABLE_FL as u64;
const STATX_ATTR_APPEND: u64 = FS_APPEND_FL as u64;
const STATX_ATTR_NODUMP: u64 = FS_NODUMP_FL as u64;

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct LinuxStat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i32; 2],
}

impl From<arceos_posix_api::ctypes::stat> for LinuxStat {
    fn from(stat: arceos_posix_api::ctypes::stat) -> Self {
        Self {
            st_dev: stat.st_dev,
            st_ino: stat.st_ino,
            st_mode: stat.st_mode,
            st_nlink: stat.st_nlink,
            st_uid: stat.st_uid,
            st_gid: stat.st_gid,
            st_rdev: stat.st_rdev,
            __pad1: 0,
            st_size: stat.st_size,
            st_blksize: stat.st_blksize as i32,
            __pad2: 0,
            st_blocks: stat.st_blocks,
            st_atime: stat.st_atime.tv_sec,
            st_atime_nsec: stat.st_atime.tv_nsec,
            st_mtime: stat.st_mtime.tv_sec,
            st_mtime_nsec: stat.st_mtime.tv_nsec,
            st_ctime: stat.st_ctime.tv_sec,
            st_ctime_nsec: stat.st_ctime.tv_nsec,
            __unused: [0; 2],
        }
    }
}

pub(crate) fn sys_fstat(fd: i32, kstatbuf: *mut c_void) -> i32 {
    let mut statbuf = arceos_posix_api::ctypes::stat::default();

    if unsafe {
        arceos_posix_api::sys_fstat(fd, &mut statbuf as *mut arceos_posix_api::ctypes::stat)
    } < 0
    {
        return -1;
    }

    let kstat = LinuxStat::from(statbuf);
    match write_value_to_user(kstatbuf as *mut LinuxStat, kstat) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FsId {
    __val: [i32; 2],
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct StatFs {
    f_type: u64,
    f_bsize: u64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: FsId,
    f_namelen: u64,
    f_frsize: u64,
    f_flags: u64,
    f_spare: [u64; 4],
}

fn build_statfs_for_path(path: Option<&str>) -> StatFs {
    let mut statfs = StatFs {
        f_type: 0xEF53,
        f_bsize: 4096,
        f_blocks: 262_144,
        f_bfree: 196_608,
        f_bavail: 196_608,
        f_files: 65_536,
        f_ffree: 60_000,
        f_fsid: FsId { __val: [1, 0] },
        f_namelen: 255,
        f_frsize: 4096,
        f_flags: 0,
        f_spare: [0; 4],
    };

    let Some(path) = path else {
        return statfs;
    };

    if path == "/dev/loop0" {
        if let Some(loop_stat) = api::virtual_device_stat("/dev/loop0") {
            let blocks = (loop_stat.st_size.max(0) as u64)
                .div_ceil(statfs.f_bsize)
                .max(1);
            statfs.f_blocks = blocks;
            statfs.f_bfree = blocks;
            statfs.f_bavail = blocks;
            statfs.f_files = blocks;
            statfs.f_ffree = blocks;
        }
        return statfs;
    }

    if matches!(api::virtual_device_stat(path), Some(_)) {
        return statfs;
    }

    match axfs::api::path_mount_kind(path) {
        axfs::api::PathMountKind::Ext4 => {
            if let Some(loop_stat) = api::virtual_device_stat("/dev/loop0") {
                let blocks = (loop_stat.st_size.max(0) as u64)
                    .div_ceil(statfs.f_bsize)
                    .max(1);
                let reserved = blocks.min(256);
                let free = blocks.saturating_sub(reserved);
                statfs.f_blocks = blocks;
                statfs.f_bfree = free;
                statfs.f_bavail = free;
                statfs.f_files = blocks.saturating_mul(4);
                statfs.f_ffree = statfs.f_files.saturating_sub(reserved);
            }
        }
        axfs::api::PathMountKind::Ramfs => {
            statfs.f_type = 0x8584_58f6;
        }
        axfs::api::PathMountKind::Fat => {
            statfs.f_type = 0x4d44;
        }
        _ => {}
    }

    statfs
}

fn build_statfs_for_fd(fd: i32) -> StatFs {
    let file_like = match get_file_like(fd) {
        Ok(file_like) => file_like,
        Err(_) => return build_statfs_for_path(None),
    };
    if let Ok(file) = file_like.clone().into_any().downcast::<api::File>() {
        return build_statfs_for_path(Some(file.path()));
    }
    if let Ok(dir) = file_like.clone().into_any().downcast::<api::Directory>() {
        return build_statfs_for_path(Some(dir.path()));
    }
    if file_like
        .into_any()
        .downcast::<api::LoopDeviceFile>()
        .is_ok()
    {
        return build_statfs_for_path(Some("/dev/loop0"));
    }
    build_statfs_for_path(None)
}

pub(crate) fn sys_statfs(pathname: *const u8, buf: *mut c_void) -> i32 {
    syscall_body!(sys_statfs, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let path = handle_user_path(api::AT_FDCWD.into(), pathname, false)?;
        if api::virtual_device_stat(path.as_str()).is_none() {
            let mut options = axfs::fops::OpenOptions::new();
            options.read(true);
            let _ = axfs::fops::File::open(path.as_str(), &options)?;
        }
        write_value_to_user(
            buf as *mut StatFs,
            build_statfs_for_path(Some(path.as_str())),
        )?;
        Ok(0)
    })
}

pub(crate) fn sys_fstatfs(fd: i32, buf: *mut c_void) -> i32 {
    syscall_body!(sys_fstatfs, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let _ = arceos_posix_api::get_file_like(fd)?;
        write_value_to_user(buf as *mut StatFs, build_statfs_for_fd(fd))?;
        Ok(0)
    })
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct FsStatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
}

/// statx - get file status (extended)
/// Standard C library (libc, -lc)
/// <https://man7.org/linux/man-pages/man2/statx.2.html>
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct StatX {
    /// Bitmask of what information to get.
    pub stx_mask: u32,
    /// Block size for filesystem I/O.
    pub stx_blksize: u32,
    /// File attributes.
    pub stx_attributes: u64,
    /// Number of hard links.
    pub stx_nlink: u32,
    /// User ID of owner.
    pub stx_uid: u32,
    /// Group ID of owner.
    pub stx_gid: u32,
    /// File mode (permissions).
    pub stx_mode: u16,
    /// Inode number.
    pub stx_ino: u64,
    /// Total size, in bytes.
    pub stx_size: u64,
    /// Number of 512B blocks allocated.
    pub stx_blocks: u64,
    /// Mask to show what's supported in stx_attributes.
    pub stx_attributes_mask: u64,
    /// Last access timestamp.
    pub stx_atime: FsStatxTimestamp,
    /// Birth (creation) timestamp.
    pub stx_btime: FsStatxTimestamp,
    /// Last status change timestamp.
    pub stx_ctime: FsStatxTimestamp,
    /// Last modification timestamp.
    pub stx_mtime: FsStatxTimestamp,
    /// Major device ID (if special file).
    pub stx_rdev_major: u32,
    /// Minor device ID (if special file).
    pub stx_rdev_minor: u32,
    /// Major device ID of file system.
    pub stx_dev_major: u32,
    /// Minor device ID of file system.
    pub stx_dev_minor: u32,
    /// Mount ID.
    pub stx_mnt_id: u64,
    /// Memory alignment for direct I/O.
    pub stx_dio_mem_align: u32,
    /// Offset alignment for direct I/O.
    pub stx_dio_offset_align: u32,
}

fn statx_supported_attrs_for_path(path: &str) -> u64 {
    match axfs::api::path_mount_kind(path) {
        axfs::api::PathMountKind::Ext4 => {
            STATX_ATTR_COMPRESSED | STATX_ATTR_APPEND | STATX_ATTR_IMMUTABLE | STATX_ATTR_NODUMP
        }
        axfs::api::PathMountKind::Ramfs => {
            STATX_ATTR_APPEND | STATX_ATTR_IMMUTABLE | STATX_ATTR_NODUMP
        }
        _ => 0,
    }
}

fn statx_attrs_for_path(path: &str, attr: FileAttr) -> (u64, u64) {
    let meta = axfs::api::path_stat_metadata(path, attr);
    let supported = statx_supported_attrs_for_path(path);
    (u64::from(meta.fs_flags) & supported, supported)
}

fn statx_attrs_for_fd(fd: i32) -> Option<(u64, u64)> {
    let file_like = get_file_like(fd).ok()?;
    if let Ok(file) = file_like.clone().into_any().downcast::<api::File>() {
        let attr = axfs::api::metadata_raw(file.path()).ok()?;
        return Some(statx_attrs_for_path(file.path(), attr));
    }
    if let Ok(dir) = file_like.into_any().downcast::<api::Directory>() {
        let attr = axfs::api::metadata_raw(dir.path()).ok()?;
        return Some(statx_attrs_for_path(dir.path(), attr));
    }
    None
}

fn statx_dioalign_for_path(path: &str) -> Option<(u32, u32)> {
    if matches!(path, "/dev/loop0") {
        return Some((512, 512));
    }
    match axfs::api::path_mount_kind(path) {
        axfs::api::PathMountKind::Ext4 => Some((512, 512)),
        _ => None,
    }
}

fn statx_dioalign_for_fd(fd: i32) -> Option<(u32, u32)> {
    let file_like = get_file_like(fd).ok()?;
    if let Ok(file) = file_like.clone().into_any().downcast::<api::File>() {
        return statx_dioalign_for_path(file.path());
    }
    if let Ok(dir) = file_like.clone().into_any().downcast::<api::Directory>() {
        return statx_dioalign_for_path(dir.path());
    }
    if file_like
        .into_any()
        .downcast::<api::LoopDeviceFile>()
        .is_ok()
    {
        return Some((512, 512));
    }
    None
}

fn build_statx_from_stat(
    status: api::ctypes::stat,
    attrs: Option<(u64, u64)>,
    dioalign: Option<(u32, u32)>,
) -> StatX {
    let mut statx = StatX::default();
    statx.stx_mask = 0x0fff;
    statx.stx_blksize = status.st_blksize as u32;
    statx.stx_attributes = attrs.map(|value| value.0).unwrap_or(0);
    statx.stx_nlink = status.st_nlink;
    statx.stx_uid = status.st_uid;
    statx.stx_gid = status.st_gid;
    statx.stx_mode = status.st_mode as u16;
    statx.stx_ino = status.st_ino;
    statx.stx_size = status.st_size as u64;
    statx.stx_blocks = status.st_blocks as u64;
    statx.stx_attributes_mask = attrs.map(|value| value.1).unwrap_or(0);
    statx.stx_atime.tv_sec = status.st_atime.tv_sec;
    statx.stx_atime.tv_nsec = status.st_atime.tv_nsec as u32;
    statx.stx_btime.tv_sec = status.st_ctime.tv_sec;
    statx.stx_btime.tv_nsec = status.st_ctime.tv_nsec as u32;
    statx.stx_ctime.tv_sec = status.st_ctime.tv_sec;
    statx.stx_ctime.tv_nsec = status.st_ctime.tv_nsec as u32;
    statx.stx_mtime.tv_sec = status.st_mtime.tv_sec;
    statx.stx_mtime.tv_nsec = status.st_mtime.tv_nsec as u32;
    statx.stx_dev_major = ((status.st_dev >> 8) & 0xfff) as u32;
    statx.stx_dev_minor = (status.st_dev & 0xff) as u32;
    statx.stx_rdev_major = ((status.st_rdev >> 8) & 0xfff) as u32;
    statx.stx_rdev_minor = (status.st_rdev & 0xff) as u32;
    statx.stx_mnt_id = 1;
    if let Some((mem_align, offset_align)) = dioalign {
        statx.stx_mask |= STATX_DIOALIGN;
        statx.stx_dio_mem_align = mem_align;
        statx.stx_dio_offset_align = offset_align;
    }
    statx
}

fn build_stat_from_attr(path: &str, attr: FileAttr) -> api::ctypes::stat {
    let meta = axfs::api::path_stat_metadata(path, attr);
    let ty = meta.special_type.unwrap_or(attr.file_type()) as u8;
    let uid = meta.uid;
    let gid = meta.gid;
    let mode = meta.mode;
    let perm = mode as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    let size = attr.size();
    let st_blocks = match meta.special_type.unwrap_or(attr.file_type()) {
        axfs::fops::FileType::File | axfs::fops::FileType::SymLink => {
            if size == 0 {
                0
            } else {
                size.div_ceil(512)
            }
        }
        _ => attr.blocks(),
    };
    let st_nlink = axfs::api::link_count(path, attr).unwrap_or(if attr.is_dir() { 2 } else { 1 });
    let (atime, mtime, ctime) = api::get_path_times(path, attr.is_dir());
    api::ctypes::stat {
        st_ino: meta.ino,
        st_nlink,
        st_mode,
        st_uid: uid,
        st_gid: gid,
        st_rdev: meta.rdev,
        st_size: size as _,
        st_blocks: st_blocks as _,
        st_blksize: 4096,
        st_atime: atime,
        st_mtime: mtime,
        st_ctime: ctime,
        ..Default::default()
    }
}

fn stat_by_path(
    dirfd: i32,
    pathname: *const u8,
    follow_final_symlink: bool,
) -> Result<(api::ctypes::stat, Option<(String, FileAttr)>), LinuxError> {
    let path = handle_user_path(dirfd as isize, pathname, false)?;
    if path.as_str() == "/proc" || path.as_str().starts_with("/proc/") {
        crate::task::sync_proc_pid_entries_for_path(path.as_str());
    }
    if let Some(stat) = api::virtual_device_stat(path.as_str()) {
        return Ok((stat, None));
    }
    if let Some(stat) = crate::timekeeping::special_proc_file_stat(path.as_str()) {
        return Ok((stat, None));
    }
    let (resolved, attr) = if follow_final_symlink {
        resolve_existing_path(path.as_str(), true)?
    } else {
        (
            path.to_string(),
            axfs::api::metadata_raw_nofollow(path.as_str()).map_err(LinuxError::from)?,
        )
    };
    Ok((
        build_stat_from_attr(resolved.as_str(), attr),
        Some((resolved, attr)),
    ))
}

const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32 = 0x800;
const AT_EMPTY_PATH: u32 = 0x1000;
const AT_STATX_FORCE_SYNC: u32 = 0x2000;
const AT_STATX_DONT_SYNC: u32 = 0x4000;
const AT_STATX_SYNC_TYPE: u32 = 0x6000;
const STATX_ALLOWED_MASK: u32 = 0x0000_7fff;
const STATX__RESERVED: u32 = 0x8000_0000;

fn resolve_stat_path_input(
    dirfd: i32,
    pathname: *const u8,
    empty_path_allowed: bool,
) -> Result<Option<String>, LinuxError> {
    if pathname.is_null() {
        return if empty_path_allowed {
            Ok(None)
        } else {
            Err(LinuxError::EFAULT)
        };
    }

    let raw_path = read_user_path(pathname as *const _)?;
    if raw_path.is_empty() {
        return if empty_path_allowed {
            Ok(Some(raw_path))
        } else {
            Err(LinuxError::ENOENT)
        };
    }

    if !raw_path.starts_with('/') && dirfd != api::AT_FDCWD as i32 {
        if get_file_like(dirfd).is_err() {
            return Err(LinuxError::EBADF);
        }
        if api::Directory::from_fd(dirfd).is_err() {
            return Err(LinuxError::ENOTDIR);
        }
    }

    Ok(Some(raw_path))
}

pub(crate) fn sys_statx(
    dirfd: i32,
    pathname: *const u8,
    flags: u32,
    _mask: u32,
    statxbuf: *mut c_void,
) -> i32 {
    // `statx()` uses pathname, dirfd, and flags to identify the target
    // file in one of the following ways:

    // An absolute pathname(situation 1)
    //        If pathname begins with a slash, then it is an absolute
    //        pathname that identifies the target file.  In this case,
    //        dirfd is ignored.

    // A relative pathname(situation 2)
    //        If pathname is a string that begins with a character other
    //        than a slash and dirfd is AT_FDCWD, then pathname is a
    //        relative pathname that is interpreted relative to the
    //        process's current working directory.

    // A directory-relative pathname(situation 3)
    //        If pathname is a string that begins with a character other
    //        than a slash and dirfd is a file descriptor that refers to
    //        a directory, then pathname is a relative pathname that is
    //        interpreted relative to the directory referred to by dirfd.
    //        (See openat(2) for an explanation of why this is useful.)

    // By file descriptor(situation 4)
    //        If pathname is an empty string (or NULL since Linux 6.11)
    //        and the AT_EMPTY_PATH flag is specified in flags (see
    //        below), then the target file is the one referred to by the
    //        file descriptor dirfd.

    syscall_body!(sys_statx, {
        if statxbuf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let allowed_flags = AT_SYMLINK_NOFOLLOW
            | AT_NO_AUTOMOUNT
            | AT_EMPTY_PATH
            | AT_STATX_FORCE_SYNC
            | AT_STATX_DONT_SYNC;
        if flags & !allowed_flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        if flags & AT_STATX_SYNC_TYPE == AT_STATX_SYNC_TYPE {
            return Err(LinuxError::EINVAL);
        }
        if (_mask & !STATX_ALLOWED_MASK) != 0 || (_mask & STATX__RESERVED) != 0 {
            return Err(LinuxError::EINVAL);
        }
        let mut status = arceos_posix_api::ctypes::stat::default();
        let raw_path = resolve_stat_path_input(dirfd, pathname, (flags & AT_EMPTY_PATH) != 0)?;
        if raw_path.as_ref().is_none() || raw_path.as_ref().is_some_and(|path| path.is_empty()) {
            let res = unsafe { arceos_posix_api::sys_fstat(dirfd, &mut status as *mut _) };
            if res < 0 {
                return Err(LinuxError::try_from(-res).unwrap());
            }
        } else {
            status = stat_by_path(dirfd, pathname, (flags & AT_SYMLINK_NOFOLLOW) == 0)?.0;
        }
        let attrs = if raw_path.as_ref().is_none()
            || raw_path.as_ref().is_some_and(|path| path.is_empty())
        {
            statx_attrs_for_fd(dirfd)
        } else {
            stat_by_path(dirfd, pathname, (flags & AT_SYMLINK_NOFOLLOW) == 0)?
                .1
                .map(|(resolved, attr)| statx_attrs_for_path(resolved.as_str(), attr))
        };
        let dioalign = if raw_path.as_ref().is_none()
            || raw_path.as_ref().is_some_and(|path| path.is_empty())
        {
            statx_dioalign_for_fd(dirfd)
        } else {
            raw_path
                .as_ref()
                .and_then(|path| statx_dioalign_for_path(path.as_str()))
        };
        write_value_to_user(
            statxbuf as *mut StatX,
            build_statx_from_stat(status, attrs, dioalign),
        )?;
        Ok(0)
    })
}

pub(crate) fn sys_newfstatat(
    dirfd: i32,
    pathname: *const u8,
    statbuf: *mut c_void,
    flags: i32,
) -> i32 {
    syscall_body!(sys_newfstatat, {
        if statbuf.is_null() {
            return Err(LinuxError::EFAULT);
        }

        const AT_EMPTY_PATH_I32: i32 = AT_EMPTY_PATH as i32;
        if flags & !(AT_SYMLINK_NOFOLLOW as i32 | AT_EMPTY_PATH_I32) != 0 {
            return Err(LinuxError::EINVAL);
        }
        let raw_path = resolve_stat_path_input(dirfd, pathname, (flags & AT_EMPTY_PATH_I32) != 0)?;
        if raw_path.as_ref().is_none() || raw_path.as_ref().is_some_and(|path| path.is_empty()) {
            let mut local = api::ctypes::stat::default();
            let res = unsafe { api::sys_fstat(dirfd, &mut local as *mut _) };
            if res < 0 {
                return Err(LinuxError::try_from(-res).unwrap_or(LinuxError::EINVAL));
            }
            write_value_to_user(statbuf as *mut LinuxStat, LinuxStat::from(local))?;
            return Ok(0);
        }

        let local = stat_by_path(dirfd, pathname, (flags & AT_SYMLINK_NOFOLLOW as i32) == 0)?.0;
        write_value_to_user(statbuf as *mut LinuxStat, LinuxStat::from(local))?;
        Ok(0)
    })
}
