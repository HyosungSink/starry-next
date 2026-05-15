use core::ffi::{c_char, c_int, c_void};
#[cfg(feature = "lwext4_rs")]
use core::fmt::Debug;
#[cfg(feature = "lwext4_rs")]
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use alloc::{ffi::CString, format, string::String, sync::Arc, vec, vec::Vec};
use arceos_posix_api::{self as api, get_file_like, FileLike, AT_FDCWD};
use axerrno::{AxError, LinuxError};
#[cfg(feature = "lwext4_rs")]
use axfs::api::KernelDevOp;
use axhal::paging::MappingFlags;
use axhal::time::{monotonic_time_nanos, wall_time, NANOS_PER_SEC};
use axstd::io::SeekFrom;
use axtask::{current, TaskExtRef};
use memory_addr::VirtAddr;

use super::{
    clear_xattrs_under_mount, fd_ops::notify_lease_break_for_fd, handle_kernel_path,
    handle_user_path, read_user_path, resolve_existing_path, validate_path_components,
};
use crate::syscall_body;
use crate::usercopy::{copy_to_user, ensure_user_range, read_value_from_user, write_value_to_user};

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const S_ISUID: u16 = 0o4000;
const S_ISGID: u16 = 0o2000;
const S_IXGRP: u16 = 0o0010;
const TCGETS: usize = 0x5401;
const TIOCGPGRP: usize = 0x540F;
const TIOCSPGRP: usize = 0x5410;
const TIOCGWINSZ: usize = 0x5413;
const TIOCNOTTY: usize = 0x5422;
const RTC_RD_TIME: usize = 0x8024_7009;
const RTC_SET_TIME: usize = 0x4024_700a;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

#[cfg(feature = "lwext4_rs")]
static DEV_ZERO_EXT_MOUNT_WARN_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "lwext4_rs")]
const DEV_ZERO_EXT_MOUNT_WARN_BURST: usize = 3;
#[cfg(feature = "lwext4_rs")]
const DEV_ZERO_EXT_MOUNT_WARN_PERIOD: usize = 16;
#[cfg(feature = "lwext4_rs")]
const EXT4_DIR_LINK_MAX: u32 = 65_000;

#[cfg(feature = "lwext4_rs")]
fn log_ext_mount_backend_warning(
    source: &str,
    target: &str,
    backend_err: &impl Debug,
    backend_kind: &str,
    image_err: &LinuxError,
) {
    if source == "/dev/zero" {
        let count = DEV_ZERO_EXT_MOUNT_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        if count <= DEV_ZERO_EXT_MOUNT_WARN_BURST
            || count % DEV_ZERO_EXT_MOUNT_WARN_PERIOD == 0
        {
            warn!(
                "mount ext source={source} target={target}: device backend failed: {backend_err:?}; image {backend_kind} failed: {image_err:?} [sampled count={count}]"
            );
        }
        return;
    }
    warn!(
        "mount ext source={source} target={target}: device backend failed: {backend_err:?}; image {backend_kind} failed: {image_err:?}"
    );
}
const MAX_CHROOT_SYMLINK_DEPTH: usize = 40;
const BLKGETSIZE64: usize = 0x8008_1272;
const BLKSSZGET: usize = 0x1268;
const BLKPBSZGET: usize = 0x127b;
const LOOP_SET_FD: usize = 0x4C00;
const LOOP_CLR_FD: usize = 0x4C01;
const LOOP_SET_STATUS: usize = 0x4C02;
const LOOP_GET_STATUS: usize = 0x4C03;
const LOOP_SET_STATUS64: usize = 0x4C04;
const LOOP_CTL_GET_FREE: usize = 0x4C82;
const FS_IOC_GETFLAGS: usize = 0x8008_6601;
const FS_IOC_SETFLAGS: usize = 0x4008_6602;
const FS_COMPR_FL: u32 = 0x0000_0004;
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;
const FS_NODUMP_FL: u32 = 0x0000_0040;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserUtimbuf {
    actime: i64,
    modtime: i64,
}

struct FileLikeBlockDev {
    file: Arc<dyn FileLike>,
}

#[cfg(feature = "lwext4_rs")]
struct FileLikeExt4Dev;

#[cfg(feature = "lwext4_rs")]
static EXT4_MOUNT_DEVICE_SEQ: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "lwext4_rs")]
impl KernelDevOp for FileLikeExt4Dev {
    type DevType = FileLikeBlockDev;

    fn read(dev: &mut Self::DevType, buf: &mut [u8]) -> Result<usize, i32> {
        dev.file.read(buf).map_err(|_| -1)
    }

    fn write(dev: &mut Self::DevType, buf: &[u8]) -> Result<usize, i32> {
        dev.file.write(buf).map_err(|_| -1)
    }

    fn seek(dev: &mut Self::DevType, off: i64, whence: i32) -> Result<i64, i32> {
        let pos = match whence {
            SEEK_SET => {
                if off < 0 {
                    return Err(-1);
                }
                SeekFrom::Start(off as u64)
            }
            SEEK_CUR => SeekFrom::Current(off),
            SEEK_END => SeekFrom::End(off),
            _ => return Err(-1),
        };
        dev.file.seek(pos).map(|value| value as i64).map_err(|_| -1)
    }

    fn flush(dev: &mut Self::DevType) -> Result<usize, i32> {
        dev.file.sync_all().map(|_| 0).map_err(|_| -1)
    }
}

impl axfs::api::FatFsIo for FileLikeBlockDev {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, i32> {
        self.file.read(buf).map_err(|_| -1)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, i32> {
        self.file.write(buf).map_err(|_| -1)
    }

    fn flush(&mut self) -> Result<(), i32> {
        self.file.sync_all().map_err(|_| -1)
    }

    fn seek(&mut self, pos: SeekFrom) -> Result<u64, i32> {
        self.file.seek(pos).map_err(|_| -1)
    }
}

fn sanitize_chmod_mode(path: &str, attr: axfs::fops::FileAttr, mode: u32) -> u32 {
    let mut mode = mode;
    if (mode as u16 & S_ISGID) == 0 || axfs::api::current_euid() == 0 {
        return mode;
    }
    let (_uid, gid, _cur_mode) = axfs::api::path_owner_mode(path, attr);
    let gids = axfs::api::current_res_gid();
    let (supplementary, supplementary_len) = axfs::api::current_supplementary_gids();
    let in_group = gid == gids.0
        || gid == gids.1
        || gid == gids.2
        || supplementary[..supplementary_len].contains(&gid);
    if !in_group {
        mode &= !(S_ISGID as u32);
    }
    mode
}

fn ensure_can_chmod(path: &str, attr: axfs::fops::FileAttr) -> Result<(), LinuxError> {
    let (owner_uid, _gid, _mode) = axfs::api::path_owner_mode(path, attr);
    let caller_euid = axfs::api::current_euid();
    if caller_euid == 0 || caller_euid == owner_uid {
        Ok(())
    } else {
        Err(LinuxError::EPERM)
    }
}

fn apply_chown_to_path(
    resolved: &str,
    attr: axfs::fops::FileAttr,
    owner: u32,
    group: u32,
) -> Result<(), LinuxError> {
    if api::virtual_device_stat(resolved).is_some() {
        return Ok(());
    }
    if axfs::api::is_readonly_path(resolved).map_err(LinuxError::from)? {
        return Err(LinuxError::EROFS);
    }
    let (cur_uid, _cur_gid, cur_mode) = axfs::api::path_owner_mode(resolved, attr);
    let cred = axfs::api::current_res_uid();
    let gids = axfs::api::current_res_gid();
    let caller_euid = cred.1;

    let owner = if owner == u32::MAX { None } else { Some(owner) };
    let group = if group == u32::MAX { None } else { Some(group) };
    if caller_euid != 0 {
        if owner.is_some() {
            return Err(LinuxError::EPERM);
        }
        if cur_uid != caller_euid {
            return Err(LinuxError::EPERM);
        }
        if let Some(group) = group {
            if group != gids.0 && group != gids.1 && group != gids.2 {
                return Err(LinuxError::EPERM);
            }
        }
    }
    axfs::api::set_path_owner(resolved, owner, group);
    if attr.is_file() {
        let mut cleared = cur_mode;
        cleared &= !S_ISUID;
        if (cleared & S_ISGID) != 0 && (cleared & S_IXGRP) != 0 {
            cleared &= !S_ISGID;
        }
        if cleared != cur_mode {
            axfs::api::clear_path_special_bits(resolved, cur_mode ^ cleared);
        }
    }
    Ok(())
}

fn resolve_requested_times(
    requested: [api::ctypes::timespec; 2],
    current: [api::ctypes::timespec; 2],
    now_ts: api::ctypes::timespec,
) -> Result<[api::ctypes::timespec; 2], LinuxError> {
    const UTIME_OMIT: i64 = 1_073_741_822;
    const UTIME_NOW: i64 = 1_073_741_823;
    let resolve = |requested: api::ctypes::timespec,
                   current: api::ctypes::timespec|
     -> Result<api::ctypes::timespec, LinuxError> {
        if requested.tv_nsec < 0 || requested.tv_nsec >= NANOS_PER_SEC as i64 {
            if requested.tv_nsec != UTIME_NOW && requested.tv_nsec != UTIME_OMIT {
                return Err(LinuxError::EINVAL);
            }
        }
        Ok(match requested.tv_nsec {
            UTIME_NOW => now_ts,
            UTIME_OMIT => current,
            _ => requested,
        })
    };
    Ok([
        resolve(requested[0], current[0])?,
        resolve(requested[1], current[1])?,
    ])
}

fn set_times_on_resolved_path(
    resolved: &str,
    is_dir: bool,
    requested: Option<[api::ctypes::timespec; 2]>,
    now_ts: api::ctypes::timespec,
) -> Result<(), LinuxError> {
    let path_cstr = CString::new(resolved).map_err(|_| LinuxError::EINVAL)?;
    let fd = api::sys_openat(
        AT_FDCWD as i32,
        path_cstr.as_ptr(),
        (api::ctypes::O_RDONLY | api::ctypes::O_CLOEXEC) as i32,
        0,
    );
    if fd < 0 {
        return Err(LinuxError::try_from((-fd) as i32).unwrap_or(LinuxError::EINVAL));
    }
    let fd = fd as i32;
    let result = (|| -> Result<(), LinuxError> {
        let current = api::get_file_times(fd)?
            .map(|value| [value.0, value.1])
            .unwrap_or([api::ctypes::timespec::default(); 2]);
        let requested = requested.unwrap_or([now_ts; 2]);
        let resolved_times = resolve_requested_times(requested, current, now_ts)?;
        api::set_file_times(fd, resolved_times[0], resolved_times[1])?;
        api::set_path_times(
            resolved,
            is_dir,
            resolved_times[0],
            resolved_times[1],
            resolved_times[1],
        );
        Ok(())
    })();
    let _ = api::sys_close(fd);
    result
}

fn update_path_ctime(path: &str, is_dir: bool) {
    let now = wall_time();
    let now_ts = api::ctypes::timespec {
        tv_sec: now.as_secs() as i64,
        tv_nsec: now.subsec_nanos() as i64,
    };
    let (atime, mtime, _ctime) = api::get_path_times(path, is_dir);
    api::set_path_times(path, is_dir, atime, mtime, now_ts);
}

fn is_cgroup_v2_dir(path: &str) -> bool {
    let root = api::proc_cgroup_mount_path();
    let prefix = format!("{root}/");
    path == root || path.starts_with(prefix.as_str())
}

fn normalized_dir_path(path: &str) -> String {
    if path == "/" {
        String::from("/")
    } else {
        String::from(path.trim_end_matches('/'))
    }
}

fn normalized_parent_path(path: &str) -> &str {
    let trimmed = if path == "/" {
        path
    } else {
        path.trim_end_matches('/')
    };
    match trimmed.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((parent, _)) => parent,
    }
}

fn normalized_base_name(path: &str) -> &str {
    let trimmed = if path == "/" {
        path
    } else {
        path.trim_end_matches('/')
    };
    trimmed
        .rsplit_once('/')
        .map(|(_, name)| name)
        .unwrap_or(trimmed)
}

fn resolve_rename_target_path(dirfd: i32, raw_path: &str) -> Result<String, LinuxError> {
    validate_path_components(raw_path)?;
    if raw_path.is_empty() {
        return Err(LinuxError::ENOENT);
    }
    if !raw_path.starts_with('/') && dirfd != AT_FDCWD as i32 {
        if get_file_like(dirfd).is_err() {
            return Err(LinuxError::EBADF);
        }
        if api::Directory::from_fd(dirfd).is_err() {
            return Err(LinuxError::ENOTDIR);
        }
    }
    let resolved = handle_kernel_path(dirfd as isize, raw_path, false)?;
    Ok(normalized_dir_path(resolved.as_str()))
}

fn canonicalize_rename_destination(path: &str) -> Result<String, LinuxError> {
    let parent = normalized_parent_path(path);
    let (resolved_parent, parent_attr) = resolve_existing_path(parent, true)?;
    if !parent_attr.is_dir() {
        return Err(LinuxError::ENOTDIR);
    }
    let name = normalized_base_name(path);
    if name.is_empty() || name == "/" {
        return Err(LinuxError::ENOENT);
    }
    Ok(if resolved_parent == "/" {
        format!("/{name}")
    } else {
        format!("{resolved_parent}/{name}")
    })
}

#[cfg(feature = "lwext4_rs")]
fn parent_dir_path(path: &str) -> &str {
    normalized_parent_path(path)
}

#[cfg(feature = "lwext4_rs")]
fn ext4_parent_link_limit_hit(parent: &str) -> Result<bool, LinuxError> {
    let parent_attr = axfs::api::metadata_raw(parent).map_err(LinuxError::from)?;
    if !parent_attr.is_dir() {
        return Err(LinuxError::ENOTDIR);
    }
    if !matches!(axfs::api::path_mount_kind(parent), axfs::api::PathMountKind::Ext4) {
        return Ok(false);
    }
    Ok(
        axfs::api::link_count(parent, parent_attr).map_err(LinuxError::from)?
            >= EXT4_DIR_LINK_MAX,
    )
}

#[cfg(feature = "lwext4_rs")]
fn ensure_ext4_subdir_link_capacity(path: &str) -> Result<(), LinuxError> {
    if ext4_parent_link_limit_hit(parent_dir_path(path))? {
        return Err(LinuxError::EMLINK);
    }
    Ok(())
}

#[cfg(feature = "lwext4_rs")]
fn ensure_ext4_rename_dir_capacity(old_path: &str, new_path: &str) -> Result<(), LinuxError> {
    let old_attr = axfs::api::metadata_raw(old_path).map_err(LinuxError::from)?;
    if !old_attr.is_dir() {
        return Ok(());
    }
    let old_parent = parent_dir_path(old_path);
    let new_parent = parent_dir_path(new_path);
    if old_parent == new_parent {
        return Ok(());
    }
    if ext4_parent_link_limit_hit(new_parent)? {
        return Err(LinuxError::EMLINK);
    }
    Ok(())
}

fn ensure_dir_parents(path: &str) -> Result<(), LinuxError> {
    let mut current = String::new();
    for component in path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()[..]
        .iter()
        .copied()
    {
        current.push('/');
        current.push_str(component);
        if !axfs::api::absolute_path_exists(current.as_str()) {
            axfs::api::create_dir(current.as_str()).map_err(LinuxError::from)?;
        }
    }
    Ok(())
}

fn seed_cgroup_v2_dir(path: &str) -> Result<(), LinuxError> {
    let base = path.trim_end_matches('/');
    for (name, contents) in [
        ("cgroup.procs", ""),
        ("cgroup.subtree_control", ""),
        ("cgroup.controllers", "memory\n"),
    ] {
        let file_path = format!("{base}/{name}");
        if !axfs::api::absolute_path_exists(file_path.as_str()) {
            axfs::api::write(file_path.as_str(), contents).map_err(LinuxError::from)?;
        }
    }
    Ok(())
}

fn cleanup_cgroup_v2_dir(path: &str) {
    let base = path.trim_end_matches('/');
    for name in [
        "cgroup.procs",
        "cgroup.subtree_control",
        "cgroup.controllers",
    ] {
        let file_path = format!("{base}/{name}");
        let _ = axfs::api::remove_file(file_path.as_str());
    }
}

fn cleanup_cgroup_v2_tree(path: &str) {
    if let Ok(entries) = axfs::api::read_dir(path) {
        for entry in entries.flatten() {
            let child_path = entry.path();
            if entry.file_type().is_dir() {
                cleanup_cgroup_v2_tree(child_path.as_str());
                let _ = axfs::api::remove_dir(child_path.as_str());
            } else {
                let _ = axfs::api::remove_file(child_path.as_str());
            }
        }
    }
    cleanup_cgroup_v2_dir(path);
}

fn absolute_mount_source_path(path: &str) -> Result<String, LinuxError> {
    if path.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    let mut resolved = if path.starts_with('/') {
        String::from(path)
    } else {
        let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
        if cwd == "/" {
            format!("/{path}")
        } else {
            format!("{cwd}/{path}")
        }
    };
    resolved = axfs::api::canonicalize(resolved.as_str()).unwrap_or(resolved);
    Ok(resolved)
}

fn absolute_umount_target_path(path: &str) -> Result<String, LinuxError> {
    if path.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    if path.starts_with('/') {
        Ok(String::from(path))
    } else {
        let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
        if cwd == "/" {
            Ok(format!("/{path}"))
        } else {
            Ok(format!("{cwd}/{path}"))
        }
    }
}

fn read_mount_source_image(source: &str) -> Result<Vec<u8>, LinuxError> {
    const MAX_IMAGE_BYTES: usize = 64 * 1024 * 1024;
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    const S_IFBLK: u32 = 0o060000;
    let source = absolute_mount_source_path(source)?;
    let source_cstr = CString::new(source).map_err(|_| LinuxError::EINVAL)?;
    let fd = api::sys_openat(
        AT_FDCWD as i32,
        source_cstr.as_ptr(),
        (api::ctypes::O_RDONLY | api::ctypes::O_CLOEXEC) as i32,
        0,
    );
    if fd < 0 {
        return Err(LinuxError::try_from((-fd) as i32).unwrap_or(LinuxError::ENOENT));
    }
    let fd = fd as i32;
    let result = (|| -> Result<Vec<u8>, LinuxError> {
        let file = get_file_like(fd)?;
        let stat = file.stat()?;
        let mode = stat.st_mode & S_IFMT;
        let size = usize::try_from(stat.st_size.max(0)).unwrap_or(usize::MAX);
        if !matches!(mode, S_IFREG | S_IFBLK) || size == 0 || size > MAX_IMAGE_BYTES {
            return Err(LinuxError::EINVAL);
        }
        let mut image = Vec::new();
        image
            .try_reserve(size)
            .map_err(|_| LinuxError::ENOMEM)?;
        let mut buf = [0u8; 8192];
        loop {
            let read = file.read(&mut buf)?;
            if read == 0 {
                break;
            }
            if image.len().saturating_add(read) > MAX_IMAGE_BYTES {
                return Err(LinuxError::EFBIG);
            }
            image.extend_from_slice(&buf[..read]);
        }
        if image.len() != size {
            return Err(LinuxError::EINVAL);
        }
        Ok(image)
    })();
    let _ = api::sys_close(fd);
    result
}

fn mount_source_file_type(source: &str) -> Result<u32, LinuxError> {
    let source = absolute_mount_source_path(source)?;
    let source_cstr = CString::new(source).map_err(|_| LinuxError::EINVAL)?;
    let fd = api::sys_openat(
        AT_FDCWD as i32,
        source_cstr.as_ptr(),
        (api::ctypes::O_RDONLY | api::ctypes::O_CLOEXEC) as i32,
        0,
    );
    if fd < 0 {
        return Err(LinuxError::try_from((-fd) as i32).unwrap_or(LinuxError::ENOENT));
    }
    let fd = fd as i32;
    let result = (|| -> Result<u32, LinuxError> {
        let file = get_file_like(fd)?;
        Ok(file.stat()?.st_mode & S_IFMT)
    })();
    let _ = api::sys_close(fd);
    result
}

#[cfg(feature = "lwext4_rs")]
fn should_retry_ext_mount_via_image(err: &axstd::io::Error) -> bool {
    !matches!(
        LinuxError::from(*err),
        LinuxError::EINVAL
            | LinuxError::EEXIST
            | LinuxError::EBUSY
            | LinuxError::EIO
            | LinuxError::ENOMEM
            | LinuxError::ENOSPC
    )
}

fn open_mount_source_blockdev(
    source: &str,
    readonly: bool,
) -> Result<FileLikeBlockDev, LinuxError> {
    let source_cstr = CString::new(source).map_err(|_| LinuxError::EINVAL)?;
    let access = if readonly {
        api::ctypes::O_RDONLY
    } else {
        api::ctypes::O_RDWR
    };
    let fd = api::sys_openat(
        AT_FDCWD as i32,
        source_cstr.as_ptr(),
        (access | api::ctypes::O_CLOEXEC) as i32,
        0,
    );
    if fd < 0 {
        return Err(LinuxError::try_from((-fd) as i32).unwrap_or(LinuxError::ENOENT));
    }
    let fd = fd as i32;
    let result = get_file_like(fd).map(|file| FileLikeBlockDev { file });
    let _ = api::sys_close(fd);
    result
}

fn le_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn le_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn log_ext_superblock(source: &str, dev: &FileLikeBlockDev) {
    let mut sb = [0u8; 1024];
    if dev.file.seek(SeekFrom::Start(1024)).is_err() {
        return;
    }
    let read = match dev.file.read(&mut sb) {
        Ok(value) => value,
        Err(_) => {
            return;
        }
    };
    if read < sb.len() {
        return;
    }

    let magic = le_u16(&sb, 0x38);
    if magic != 0xef53 {
        return;
    }

    debug!(
        "mount ext source={source}: rev={} compat={:#x} incompat={:#x} ro_compat={:#x} inode_size={} log_block_size={}",
        le_u32(&sb, 0x4c),
        le_u32(&sb, 0x5c),
        le_u32(&sb, 0x60),
        le_u32(&sb, 0x64),
        le_u16(&sb, 0x58),
        le_u32(&sb, 0x18),
    );
}

fn log_unlinkat_ax_error(err: &AxError) {
    if !matches!(err, AxError::NotFound | AxError::NotADirectory) {
        warn!("unlinkat error: {:?}", err);
    }
}

fn log_unlinkat_error(err: &LinuxError) {
    if !matches!(err, LinuxError::ENOENT | LinuxError::ENOTDIR) {
        warn!("unlinkat error: {:?}", err);
    }
}

fn validate_fat_boot_sector(source: &str, dev: &FileLikeBlockDev) -> Result<(), LinuxError> {
    let mut sector = [0u8; 512];
    dev.file
        .seek(SeekFrom::Start(0))
        .map_err(|_| LinuxError::EIO)?;
    let read = dev.file.read(&mut sector).map_err(|_| LinuxError::EIO)?;
    dev.file
        .seek(SeekFrom::Start(0))
        .map_err(|_| LinuxError::EIO)?;
    if read < sector.len() {
        warn!("mount fat source={source}: short boot sector read len={read}");
        return Err(LinuxError::EINVAL);
    }
    if sector[510] != 0x55 || sector[511] != 0xAA {
        warn!(
            "mount fat source={source}: bad boot sector signature={:#04x}{:#04x}",
            sector[510],
            sector[511],
        );
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn resolve_chroot_target(path: &str) -> Result<(String, axfs::fops::FileAttr), LinuxError> {
    if path.is_empty() {
        return Err(LinuxError::ENOENT);
    }

    let mut resolved = axfs::api::canonicalize(path)?;
    for _ in 0..MAX_CHROOT_SYMLINK_DEPTH {
        if let Ok(target) = axfs::api::readlink(resolved.as_str()) {
            let target = String::from_utf8(target).map_err(|_| LinuxError::EINVAL)?;
            let next = if target.starts_with('/') {
                target
            } else {
                let parent = resolved
                    .rsplit_once('/')
                    .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
                    .unwrap_or("/");
                if parent == "/" {
                    format!("/{target}")
                } else {
                    format!("{parent}/{target}")
                }
            };
            resolved = axfs::api::canonicalize(next.as_str()).unwrap_or(next);
            continue;
        }

        let attr = axfs::api::metadata_raw_ax(resolved.as_str()).map_err(LinuxError::from)?;
        return Ok((resolved, attr));
    }

    Err(LinuxError::ELOOP)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Termios {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; 19],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct LinuxRtcTime {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
}

fn supported_inode_flags(path: &str) -> u32 {
    match axfs::api::path_mount_kind(path) {
        axfs::api::PathMountKind::Ext4 => {
            FS_COMPR_FL | FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL
        }
        axfs::api::PathMountKind::Ramfs => FS_IMMUTABLE_FL | FS_APPEND_FL | FS_NODUMP_FL,
        _ => 0,
    }
}

fn path_inode_flags(path: &str, attr: axfs::fops::FileAttr) -> u32 {
    let meta = axfs::api::path_stat_metadata(path, attr);
    meta.fs_flags & supported_inode_flags(path)
}

fn ensure_path_inode_mutation_allowed(path: &str) -> Result<(), LinuxError> {
    let attr = axfs::api::metadata_raw(path).map_err(LinuxError::from)?;
    let blocked = path_inode_flags(path, attr) & (FS_IMMUTABLE_FL | FS_APPEND_FL);
    if blocked != 0 {
        Err(LinuxError::EPERM)
    } else {
        Ok(())
    }
}

fn fd_backing_path(fd: i32) -> Option<String> {
    let file_like = get_file_like(fd).ok()?;
    if let Ok(file) = file_like
        .clone()
        .into_any()
        .downcast::<arceos_posix_api::File>()
    {
        return Some(String::from(file.path()));
    }
    if let Ok(dir) = file_like
        .into_any()
        .downcast::<arceos_posix_api::Directory>()
    {
        return Some(String::from(dir.path()));
    }
    None
}

fn handle_inode_flags_ioctl(path: &str, op: usize, argp: *mut c_void) -> Result<i32, LinuxError> {
    let attr = axfs::api::metadata_raw(path).map_err(LinuxError::from)?;
    let supported = supported_inode_flags(path);
    if supported == 0 {
        return Err(LinuxError::ENOTTY);
    }
    match op {
        FS_IOC_GETFLAGS => {
            if argp.is_null() {
                return Err(LinuxError::EFAULT);
            }
            write_value_to_user(argp as *mut u32, path_inode_flags(path, attr))?;
            Ok(0)
        }
        FS_IOC_SETFLAGS => {
            if argp.is_null() {
                return Err(LinuxError::EFAULT);
            }
            if axfs::api::current_euid() != 0 {
                return Err(LinuxError::EPERM);
            }
            if axfs::api::is_readonly_path(path).map_err(LinuxError::from)? {
                return Err(LinuxError::EROFS);
            }
            let requested = read_value_from_user(argp as *const u32)?;
            if requested & !supported != 0 {
                return Err(LinuxError::EINVAL);
            }
            axfs::api::set_path_fs_flags(path, requested & supported);
            Ok(0)
        }
        _ => Err(LinuxError::ENOTTY),
    }
}

/// The ioctl() system call manipulates the underlying device parameters
/// of special files.
///
/// # Arguments
/// * `fd` - The file descriptor
/// * `op` - The request code. It is of type unsigned long in glibc and BSD,
///   and of type int in musl and other UNIX systems.
/// * `argp` - The argument to the request. It is a pointer to a memory location
pub(crate) fn sys_ioctl(fd: i32, op: usize, argp: *mut c_void) -> i32 {
    syscall_body!(sys_ioctl, {
        let op = (op as u32) as usize;
        if matches!(op, RTC_RD_TIME | RTC_SET_TIME) {
            if argp.is_null() {
                return Err(LinuxError::EFAULT);
            }
            if op == RTC_SET_TIME {
                return Ok(0);
            }
            let secs = (monotonic_time_nanos() / 1_000_000_000) as i32;
            let rtc = LinuxRtcTime {
                tm_sec: secs % 60,
                tm_min: (secs / 60) % 60,
                tm_hour: (secs / 3600) % 24,
                tm_mday: 1,
                tm_mon: 0,
                tm_year: 70,
                tm_wday: 4,
                tm_yday: 0,
                tm_isdst: 0,
            };
            write_value_to_user(argp as *mut LinuxRtcTime, rtc)?;
            return Ok(0);
        }

        let file = get_file_like(fd)?;
        if let Ok(loop_ctl) = file
            .clone()
            .into_any()
            .downcast::<arceos_posix_api::LoopControlDevice>()
        {
            return match op {
                LOOP_CTL_GET_FREE => Ok(loop_ctl.free_index()?),
                _ => Err(LinuxError::ENOTTY),
            };
        }
        if let Ok(loop_dev) = file
            .clone()
            .into_any()
            .downcast::<arceos_posix_api::LoopDeviceFile>()
        {
            return match op {
                BLKGETSIZE64 => {
                    if argp.is_null() {
                        return Err(LinuxError::EFAULT);
                    }
                    write_value_to_user(argp as *mut u64, loop_dev.size_bytes()?)?;
                    Ok(0)
                }
                BLKSSZGET | BLKPBSZGET => {
                    if argp.is_null() {
                        return Err(LinuxError::EFAULT);
                    }
                    write_value_to_user(argp as *mut u32, 512u32)?;
                    Ok(0)
                }
                LOOP_SET_FD => {
                    loop_dev.attach_fd(argp as usize as i32)?;
                    Ok(0)
                }
                LOOP_SET_STATUS | LOOP_SET_STATUS64 => {
                    loop_dev.set_status()?;
                    Ok(0)
                }
                LOOP_GET_STATUS => {
                    if loop_dev.has_status() {
                        Ok(0)
                    } else {
                        Err(LinuxError::ENXIO)
                    }
                }
                LOOP_CLR_FD => {
                    loop_dev.clear_fd()?;
                    Ok(0)
                }
                _ => Err(LinuxError::ENOTTY),
            };
        }
        if matches!(op, FS_IOC_GETFLAGS | FS_IOC_SETFLAGS) {
            if let Some(path) = fd_backing_path(fd) {
                return handle_inode_flags_ioctl(path.as_str(), op, argp);
            }
        }
        let stat = file.stat()?;
        if stat.st_mode & S_IFMT != S_IFCHR {
            return Err(LinuxError::ENOTTY);
        }

        match op {
            TCGETS => {
                if argp.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                write_value_to_user(argp as *mut Termios, Termios::default())?;
                Ok(0)
            }
            TIOCGWINSZ => {
                if argp.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                write_value_to_user(
                    argp as *mut WinSize,
                    WinSize {
                        ws_row: 24,
                        ws_col: 80,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    },
                )?;
                Ok(0)
            }
            TIOCGPGRP => {
                if argp.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                write_value_to_user(
                    argp as *mut i32,
                    current().task_ext().process_group() as i32,
                )?;
                Ok(0)
            }
            TIOCSPGRP => {
                if argp.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let pgid = crate::usercopy::read_value_from_user(argp as *const i32)?;
                if pgid <= 0 {
                    return Err(LinuxError::EINVAL);
                }
                current().task_ext().set_process_group(pgid as u64);
                Ok(0)
            }
            TIOCNOTTY => Ok(0),
            _ => Err(LinuxError::ENOTTY),
        }
    })
}

pub(crate) fn sys_chdir(path: *const c_char) -> c_int {
    syscall_body!(sys_chdir, {
        let path = read_user_path(path).map_err(|err| {
            warn!("Failed to convert path: {err:?}");
            LinuxError::EFAULT
        })?;
        if path.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        validate_path_components(path.as_str())?;
        let resolved = axfs::api::canonicalize(path.as_str()).unwrap_or(path);
        let (resolved, attr) = resolve_existing_path(resolved.as_str(), true)?;
        if !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
        axfs::api::set_current_dir(resolved.as_str())?;
        Ok(0)
    })
}

pub(crate) fn sys_chroot(path: *const c_char) -> c_int {
    syscall_body!(sys_chroot, {
        let path = read_user_path(path)?;
        let (resolved, attr) = resolve_chroot_target(path.as_str())?;
        if !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
        if !axfs::api::can_access(resolved.as_str(), attr, false, false, false, true) {
            return Err(LinuxError::EACCES);
        }
        if axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }
        axfs::api::set_current_root(resolved.as_str())?;
        Ok(0)
    })
}

pub(crate) fn sys_mount(
    source: *const c_char,
    target: *const c_char,
    fs_type: *const c_char,
    flags: usize,
    data: *const c_void,
) -> isize {
    fn parse_tmpfs_size_bytes(data: &str) -> Option<usize> {
        for entry in data.split(',') {
            let Some(value) = entry.trim().strip_prefix("size=") else {
                continue;
            };
            let (digits, shift) = match value.as_bytes().last().copied() {
                Some(b'k') | Some(b'K') => (&value[..value.len() - 1], 10u32),
                Some(b'm') | Some(b'M') => (&value[..value.len() - 1], 20u32),
                Some(b'g') | Some(b'G') => (&value[..value.len() - 1], 30u32),
                Some(b't') | Some(b'T') => (&value[..value.len() - 1], 40u32),
                _ => (value, 0u32),
            };
            let units = digits.parse::<usize>().ok()?;
            return units.checked_shl(shift);
        }
        None
    }

    let source = if source.is_null() {
        String::new()
    } else {
        match read_user_path(source) {
            Ok(path) => path,
            Err(err) => return -(err.code() as isize),
        }
    };
    let target = match read_user_path(target) {
        Ok(path) => path,
        Err(err) => return -(err.code() as isize),
    };
    let fs_type = if fs_type.is_null() {
        String::new()
    } else {
        match read_user_path(fs_type) {
            Ok(path) => path,
            Err(err) => return -(err.code() as isize),
        }
    };
    let mount_data = if data.is_null() {
        None
    } else {
        read_user_path(data.cast()).ok()
    };

    syscall_body!(sys_mount, {
        const MS_RDONLY: usize = 0x1;
        const MS_BIND: usize = 0x1000;
        const MS_MOVE: usize = 0x2000;
        const MS_REMOUNT: usize = 0x20;
        const MS_PRIVATE: usize = 1 << 18;
        let readonly = flags & MS_RDONLY != 0;
        let remount = flags & MS_REMOUNT != 0;
        let bind_mount = flags & MS_BIND != 0;
        let move_mount = flags & MS_MOVE != 0;
        let private_mount = flags & MS_PRIVATE != 0;

        validate_path_components(target.as_str())?;
        let absolute_target = absolute_umount_target_path(target.as_str())?;
        let target_attr = axfs::api::metadata_raw_nofollow(absolute_target.as_str())
            .map_err(LinuxError::from)?;
        if !target_attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }

        if bind_mount {
            let source = absolute_mount_source_path(source.as_str())?;
            let source_attr = axfs::api::metadata_raw_nofollow(source.as_str())
                .map_err(LinuxError::from)?;
            if !source_attr.is_dir() {
                return Err(LinuxError::EINVAL);
            }
            if source == absolute_target {
                return Ok(0);
            }
            axfs::api::bind_mount(source.as_str(), absolute_target.as_str())
                .map_err(LinuxError::from)?;
            return Ok(0);
        }

        if private_mount {
            return Ok(0);
        }

        if move_mount {
            let source = absolute_mount_source_path(source.as_str())?;
            axfs::api::move_mount(source.as_str(), absolute_target.as_str())
                .map_err(LinuxError::from)?;
            clear_xattrs_under_mount(source.as_str());
            clear_xattrs_under_mount(absolute_target.as_str());
            return Ok(0);
        }

        if remount {
            if !axfs::api::mount_point_exists(absolute_target.as_str()).map_err(LinuxError::from)? {
                return Err(LinuxError::EINVAL);
            }
            if readonly
                && arceos_posix_api::has_open_writable_file_under(absolute_target.as_str())
            {
                return Err(LinuxError::EBUSY);
            }
            let kind = match fs_type.as_str() {
                "tmpfs" | "ramfs" | "overlay" => axfs::api::PathMountKind::Ramfs,
                "vfat" | "fat" => axfs::api::PathMountKind::Fat,
                "ext2" | "ext3" | "ext4" => axfs::api::PathMountKind::Ext4,
                "cgroup2" => axfs::api::PathMountKind::Ramfs,
                _ => axfs::api::path_mount_kind(absolute_target.as_str()),
            };
            axfs::api::remount(absolute_target.as_str(), readonly, kind)
                .map_err(LinuxError::from)?;
            return Ok(0);
        }
        if flags & MS_REMOUNT == 0
            && fs_type != "cgroup2"
            && axfs::api::mount_point_exists(absolute_target.as_str()).map_err(LinuxError::from)?
        {
            return Err(LinuxError::EBUSY);
        }
        if !matches!(
            fs_type.as_str(),
            "tmpfs"
                | "ramfs"
                | "overlay"
                | "cgroup2"
                | "vfat"
                | "fat"
                | "ext2"
                | "ext3"
                | "ext4"
        ) {
            return if fs_type.is_empty() {
                Err(LinuxError::EINVAL)
            } else {
                Err(LinuxError::ENODEV)
            };
        }
        info!("mount source={source} target={absolute_target} fstype={fs_type}");
        if fs_type == "cgroup2" {
            if !axfs::api::absolute_path_exists(absolute_target.as_str()) {
                axfs::api::create_dir(absolute_target.as_str()).map_err(LinuxError::from)?;
            }
            seed_cgroup_v2_dir(absolute_target.as_str())?;
            api::set_proc_cgroup_mount_path(absolute_target.as_str());
        } else if fs_type == "tmpfs" {
            let max_bytes = mount_data.as_deref().and_then(parse_tmpfs_size_bytes);
            axfs::api::mount_ramfs_with_max_bytes(
                absolute_target.as_str(),
                readonly,
                remount,
                max_bytes,
            )?;
        } else if fs_type == "overlay" {
            axfs::api::mount_ramfs(absolute_target.as_str(), readonly, remount)?;
        } else if matches!(fs_type.as_str(), "vfat" | "fat") {
            let source = absolute_mount_source_path(source.as_str())?;
            let block_dev = open_mount_source_blockdev(source.as_str(), readonly)?;
            validate_fat_boot_sector(source.as_str(), &block_dev)?;
            axfs::api::mount_fatfs_device(absolute_target.as_str(), block_dev, readonly, remount)?;
        } else if matches!(fs_type.as_str(), "ext2" | "ext3" | "ext4") {
            #[cfg(feature = "lwext4_rs")]
            {
                let source = absolute_mount_source_path(source.as_str())?;
                let source_type = mount_source_file_type(source.as_str())?;
                if source_type == S_IFCHR {
                    return Err(LinuxError::ENOTBLK);
                }
                if !matches!(source_type, S_IFREG | S_IFBLK) {
                    return Err(LinuxError::EINVAL);
                }
                let allow_image_fallback = source_type != S_IFBLK;
                let block_dev = open_mount_source_blockdev(source.as_str(), readonly)?;
                log_ext_superblock(source.as_str(), &block_dev);
                let device_id = EXT4_MOUNT_DEVICE_SEQ.fetch_add(1, Ordering::Relaxed);
                let device_name = format!("ext4:{device_id}:{}", source.trim_start_matches('/'));
                if let Err(err) = axfs::api::mount_ext4_device::<FileLikeExt4Dev>(
                    absolute_target.as_str(),
                    block_dev,
                    device_name.as_str(),
                    readonly,
                    remount,
                ) {
                    if !allow_image_fallback || !should_retry_ext_mount_via_image(&err) {
                        return Err(LinuxError::from(err));
                    }
                    let image = match read_mount_source_image(source.as_str()) {
                        Ok(image) => image,
                        Err(image_err) => {
                            log_ext_mount_backend_warning(
                                source.as_str(),
                                absolute_target.as_str(),
                                &err,
                                "fallback read",
                                &image_err,
                            );
                            return Err(image_err);
                        }
                    };
                    if let Err(image_err) = axfs::api::mount_ext4_image(
                        absolute_target.as_str(),
                        image.as_slice(),
                        readonly,
                        remount,
                    )
                    .map_err(LinuxError::from)
                    {
                        log_ext_mount_backend_warning(
                            source.as_str(),
                            absolute_target.as_str(),
                            &err,
                            "backend",
                            &image_err,
                        );
                        return Err(image_err);
                    }
                }
            }
            #[cfg(not(feature = "lwext4_rs"))]
            {
                let _ = source;
                return Err(LinuxError::ENODEV);
            }
        } else {
            axfs::api::mount_ramfs(
                absolute_target.as_str(),
                flags & MS_RDONLY != 0,
                flags & MS_REMOUNT != 0,
            )?;
        }
        clear_xattrs_under_mount(absolute_target.as_str());
        Ok(0)
    })
}

pub(crate) fn sys_umount(target: *const c_char, flags: c_int) -> isize {
    let target = match read_user_path(target) {
        Ok(path) => path,
        Err(_) => return LinuxError::EFAULT.code() as isize,
    };

    syscall_body!(sys_umount, {
        const MNT_FORCE: i32 = 0x1;
        const MNT_DETACH: i32 = 0x2;
        const MNT_EXPIRE: i32 = 0x4;
        const UMOUNT_NOFOLLOW: i32 = 0x8;
        let supported_flags = MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW;
        if flags & !supported_flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        let absolute_target = absolute_umount_target_path(target.as_str())?;
        if flags & UMOUNT_NOFOLLOW != 0 {
            let attr = axfs::api::metadata_raw_nofollow(absolute_target.as_str())
                .map_err(LinuxError::from)?;
            if attr.file_type().is_symlink() {
                return Err(LinuxError::EINVAL);
            }
        }
        let resolved_target =
            axfs::api::canonicalize(absolute_target.as_str()).unwrap_or(absolute_target);
        if flags & MNT_EXPIRE != 0 {
            if flags & (MNT_FORCE | MNT_DETACH) != 0 {
                return Err(LinuxError::EINVAL);
            }
            if !axfs::api::prepare_expire_umount(resolved_target.as_str())
                .map_err(LinuxError::from)?
            {
                return Err(LinuxError::EAGAIN);
            }
        }
        if is_cgroup_v2_dir(resolved_target.as_str()) {
            return Ok(0);
        }
        axfs::api::umount(resolved_target.as_str())?;
        clear_xattrs_under_mount(resolved_target.as_str());
        Ok(0)
    })
}

pub(crate) fn sys_mkdirat(dirfd: i32, path: *const c_char, mode: u32) -> c_int {
    syscall_body!(sys_mkdirat, {
        let raw_path = read_user_path(path).map_err(|err| {
            warn!("Failed to read mkdir path: {err:?}");
            err
        })?;
        let path = handle_user_path(dirfd as isize, path.cast(), true).map_err(|err| {
            warn!("Failed to resolve mkdir path: {err:?}");
            err
        })?;
        let normalized_path = normalized_dir_path(path.as_str());
        if axfs::api::is_readonly_path(normalized_path.as_str()).unwrap_or(false) {
            return Err(LinuxError::EROFS);
        }
        let is_cgroup_path = is_cgroup_v2_dir(normalized_path.as_str());
        #[cfg(feature = "lwext4_rs")]
        if !is_cgroup_path {
            ensure_ext4_subdir_link_capacity(normalized_path.as_str())?;
        }
        let relative_to_dirfd = !raw_path.starts_with('/') && dirfd != AT_FDCWD as i32;
        let create_result = if is_cgroup_path {
            axfs::api::create_dir(normalized_path.as_str()).map_err(LinuxError::from)
        } else if relative_to_dirfd {
            let dir = api::Directory::from_fd(dirfd).map_err(|_| LinuxError::EBADF)?;
            dir.inner()
                .lock()
                .create_dir(raw_path.as_str())
                .map_err(LinuxError::from)
        } else {
            axfs::api::create_dir(path.as_str()).map_err(LinuxError::from)
        };
        if let Err(err) = create_result {
            if is_cgroup_path && matches!(err, LinuxError::ENOENT) {
                ensure_dir_parents(normalized_path.as_str())?;
                if is_cgroup_path {
                    axfs::api::create_dir(normalized_path.as_str()).map_err(|retry_err| {
                        warn!(
                            "Failed to create directory {} after ensuring parents: {retry_err:?}",
                            normalized_path.as_str()
                        );
                        LinuxError::from(retry_err)
                    })?;
                } else if relative_to_dirfd {
                    let dir = api::Directory::from_fd(dirfd).map_err(|_| LinuxError::EBADF)?;
                    dir.inner()
                        .lock()
                        .create_dir(raw_path.as_str())
                        .or_else(|retry_err| {
                            warn!(
                                "Failed to create directory {} after ensuring parents: {retry_err:?}",
                                normalized_path.as_str()
                            );
                            if matches!(LinuxError::from(retry_err), LinuxError::ENOENT) {
                                Ok(())
                            } else {
                                Err(LinuxError::from(retry_err))
                            }
                        })?;
                } else {
                    axfs::api::create_dir(normalized_path.as_str()).map_err(|retry_err| {
                        warn!(
                            "Failed to create directory {} after ensuring parents: {retry_err:?}",
                            normalized_path.as_str()
                        );
                        LinuxError::from(retry_err)
                    })?;
                }
            } else {
                warn!(
                    "Failed to create directory {}: {err:?}",
                    normalized_path.as_str()
                );
                return Err(err);
            }
        }
        let umask = current().task_ext().umask.load(Ordering::Acquire) as u32;
        let masked_mode = mode & !umask & 0o777;
        axfs::api::set_mode(normalized_path.as_str(), masked_mode).map_err(LinuxError::from)?;
        if is_cgroup_v2_dir(normalized_path.as_str()) {
            seed_cgroup_v2_dir(normalized_path.as_str())?;
        }
        Ok(0)
    })
}

pub(crate) fn sys_mknodat(dirfd: i32, path: *const c_char, mode: u32, dev: u64) -> isize {
    syscall_body!(sys_mknodat, {
        let raw_path = read_user_path(path)?;
        if raw_path.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        if !raw_path.starts_with('/') && dirfd != AT_FDCWD as i32 {
            if get_file_like(dirfd).is_err() {
                return Err(LinuxError::EBADF);
            }
            if api::Directory::from_fd(dirfd).is_err() {
                return Err(LinuxError::ENOTDIR);
            }
        }
        let path = handle_user_path(dirfd as isize, path.cast(), false)?;
        let parent = path
            .rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .unwrap_or(".");
        resolve_existing_path(parent, true)?;
        if axfs::api::is_readonly_path(path.as_str()).unwrap_or(false) {
            return Err(LinuxError::EROFS);
        }
        debug!(
            "sys_mknodat dirfd={} path={} mode={:#o} dev={:#x}",
            dirfd,
            path.as_str(),
            mode,
            dev
        );
        let umask = current().task_ext().umask.load(Ordering::Acquire) as u32;
        let masked_mode = (mode & S_IFMT) | ((mode & 0o7777) & !umask);
        match mode & S_IFMT {
            S_IFIFO => {
                axfs::api::create_fifo(path.as_str()).map_err(|err| {
                    warn!("create_fifo failed for {}: {:?}", path.as_str(), err);
                    LinuxError::from(err)
                })?;
                axfs::api::clear_path_special_node(path.as_str());
                let _ = axfs::api::set_mode(path.as_str(), masked_mode);
                Ok(0)
            }
            0 | S_IFREG => {
                axfs::api::File::create(path.as_str()).map_err(|err| {
                    warn!("create file failed for {}: {:?}", path.as_str(), err);
                    LinuxError::from(err)
                })?;
                axfs::api::clear_path_special_node(path.as_str());
                let _ = axfs::api::set_mode(path.as_str(), masked_mode);
                Ok(0)
            }
            S_IFSOCK => {
                axfs::api::create_socket(path.as_str()).map_err(|err| {
                    warn!(
                        "create socket-like node failed for {}: {:?}",
                        path.as_str(),
                        err
                    );
                    LinuxError::from(err)
                })?;
                axfs::api::set_path_special_node(path.as_str(), axfs::fops::FileType::Socket, dev);
                let _ = axfs::api::set_mode(path.as_str(), masked_mode);
                Ok(0)
            }
            S_IFCHR | S_IFBLK => {
                if axfs::api::current_euid() != 0 {
                    return Err(LinuxError::EPERM);
                }
                axfs::api::File::create(path.as_str()).map_err(|err| {
                    warn!(
                        "create special file failed for {}: {:?}",
                        path.as_str(),
                        err
                    );
                    LinuxError::from(err)
                })?;
                let ty = if mode & S_IFMT == S_IFCHR {
                    axfs::fops::FileType::CharDevice
                } else {
                    axfs::fops::FileType::BlockDevice
                };
                axfs::api::set_path_special_node(path.as_str(), ty, dev);
                let _ = axfs::api::set_mode(path.as_str(), masked_mode);
                Ok(0)
            }
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub(crate) fn sys_fchmodat(dirfd: i32, path: *const c_char, _mode: u32, _flags: i32) -> isize {
    syscall_body!(sys_fchmodat, {
        if _flags & !AT_SYMLINK_NOFOLLOW != 0 {
            return Err(LinuxError::EINVAL);
        }
        let raw_path = read_user_path(path)?;
        if raw_path.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        validate_path_components(raw_path.as_str())?;
        let resolved = handle_user_path(dirfd as isize, path as *const u8, false)?;
        let (resolved, attr) =
            resolve_existing_path(resolved.as_str(), (_flags & AT_SYMLINK_NOFOLLOW) == 0)?;
        if api::virtual_device_stat(resolved.as_str()).is_some() {
            return Ok(0);
        }
        if axfs::api::is_readonly_path(resolved.as_str()).map_err(LinuxError::from)? {
            return Err(LinuxError::EROFS);
        }
        ensure_can_chmod(resolved.as_str(), attr)?;
        let mode = sanitize_chmod_mode(resolved.as_str(), attr, _mode);
        axfs::api::set_mode(resolved.as_str(), mode).map_err(LinuxError::from)?;
        update_path_ctime(resolved.as_str(), attr.is_dir());
        Ok(0)
    })
}

pub(crate) fn sys_fchmod(fd: i32, mode: u32) -> isize {
    syscall_body!(sys_fchmod, {
        let file_like = get_file_like(fd)?;
        if let Ok(file) = file_like
            .clone()
            .into_any()
            .downcast::<arceos_posix_api::File>()
        {
            let attr = axfs::api::metadata_raw(file.path()).map_err(LinuxError::from)?;
            ensure_can_chmod(file.path(), attr)?;
            let mode = sanitize_chmod_mode(file.path(), attr, mode);
            axfs::api::set_mode(file.path(), mode).map_err(LinuxError::from)?;
            update_path_ctime(file.path(), attr.is_dir());
            return Ok(0);
        }
        if let Ok(dir) = file_like
            .into_any()
            .downcast::<arceos_posix_api::Directory>()
        {
            let attr = axfs::api::metadata_raw(dir.path()).map_err(LinuxError::from)?;
            ensure_can_chmod(dir.path(), attr)?;
            let mode = sanitize_chmod_mode(dir.path(), attr, mode);
            axfs::api::set_mode(dir.path(), mode).map_err(LinuxError::from)?;
            update_path_ctime(dir.path(), attr.is_dir());
            return Ok(0);
        }
        return Err(LinuxError::EINVAL);
    })
}

pub(crate) fn sys_symlinkat(
    old_path: *const c_char,
    new_dirfd: i32,
    new_path: *const c_char,
) -> isize {
    syscall_body!(sys_symlinkat, {
        let old_path = read_user_path(old_path)?;
        let resolved_new = handle_user_path(new_dirfd as isize, new_path as *const u8, false)?;
        axfs::api::symlink(old_path.as_str(), resolved_new.as_str()).map_err(LinuxError::from)?;
        Ok(0)
    })
}

pub(crate) fn sys_fchownat(
    dirfd: i32,
    path: *const c_char,
    _owner: u32,
    _group: u32,
    _flags: i32,
) -> isize {
    syscall_body!(sys_fchownat, {
        if _flags & !AT_SYMLINK_NOFOLLOW != 0 {
            return Err(LinuxError::EINVAL);
        }
        let raw_path = read_user_path(path)?;
        if raw_path.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        if !raw_path.starts_with('/') && dirfd != AT_FDCWD as i32 {
            if get_file_like(dirfd).is_err() {
                return Err(LinuxError::EBADF);
            }
            if api::Directory::from_fd(dirfd).is_err() {
                return Err(LinuxError::ENOTDIR);
            }
        }
        validate_path_components(raw_path.as_str())?;
        let resolved = handle_user_path(dirfd as isize, path as *const u8, false)?;
        let (resolved, attr) =
            resolve_existing_path(resolved.as_str(), (_flags & AT_SYMLINK_NOFOLLOW) == 0)?;
        apply_chown_to_path(resolved.as_str(), attr, _owner, _group)?;
        Ok(0)
    })
}

pub(crate) fn sys_fchown(fd: i32, owner: u32, group: u32) -> isize {
    syscall_body!(sys_fchown, {
        let file_like = get_file_like(fd)?;
        if let Ok(file) = file_like
            .clone()
            .into_any()
            .downcast::<arceos_posix_api::File>()
        {
            let attr = axfs::api::metadata_raw(file.path()).map_err(LinuxError::from)?;
            apply_chown_to_path(file.path(), attr, owner, group)?;
            return Ok(0);
        }
        if let Ok(dir) = file_like
            .into_any()
            .downcast::<arceos_posix_api::Directory>()
        {
            let attr = axfs::api::metadata_raw(dir.path()).map_err(LinuxError::from)?;
            apply_chown_to_path(dir.path(), attr, owner, group)?;
            return Ok(0);
        }
        Err(LinuxError::EINVAL)
    })
}

pub(crate) fn sys_chown(path: *const c_char, owner: u32, group: u32) -> isize {
    sys_fchownat(AT_FDCWD as i32, path, owner, group, 0)
}

pub(crate) fn sys_lchown(path: *const c_char, owner: u32, group: u32) -> isize {
    sys_fchownat(AT_FDCWD as i32, path, owner, group, AT_SYMLINK_NOFOLLOW)
}

pub(crate) fn sys_umask(mask: u32) -> isize {
    current().task_ext().swap_umask(mask) as isize
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DirEnt {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
    d_name: [u8; 0],
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Unknown = 0,
    Fifo = 1,
    Chr = 2,
    Dir = 4,
    Blk = 6,
    Reg = 8,
    Lnk = 10,
    Socket = 12,
    Wht = 14,
}

impl From<axfs::api::FileType> for FileType {
    fn from(ft: axfs::api::FileType) -> Self {
        match ft {
            ft if ft.is_dir() => FileType::Dir,
            ft if ft.is_file() => FileType::Reg,
            _ => FileType::Unknown,
        }
    }
}

impl DirEnt {
    const FIXED_SIZE: usize = core::mem::size_of::<u64>()
        + core::mem::size_of::<i64>()
        + core::mem::size_of::<u16>()
        + core::mem::size_of::<u8>();

    fn new(ino: u64, off: i64, reclen: usize, file_type: FileType) -> Self {
        Self {
            d_ino: ino,
            d_off: off,
            d_reclen: reclen as u16,
            d_type: file_type as u8,
            d_name: [],
        }
    }

    unsafe fn write_name(&mut self, name: &[u8]) {
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), self.d_name.as_mut_ptr(), name.len());
        }
    }
}

// Directory buffer for getdents64 syscall
struct DirBuffer<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> DirBuffer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn remaining_space(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    fn can_fit_entry(&self, entry_size: usize) -> bool {
        self.remaining_space() >= entry_size
    }

    fn write_entry(&mut self, dirent: DirEnt, name: &[u8]) -> Result<(), ()> {
        if !self.can_fit_entry(dirent.d_reclen as usize) {
            return Err(());
        }
        unsafe {
            let entry_ptr = self.buf.as_mut_ptr().add(self.offset) as *mut DirEnt;
            entry_ptr.write(dirent);
            (*entry_ptr).write_name(name);
        }

        self.offset += dirent.d_reclen as usize;
        Ok(())
    }
}

pub(crate) fn sys_getdents64(fd: i32, buf: *mut c_void, len: usize) -> isize {
    const DIRENT_MAX_NAME_LEN: usize = 255;
    const DIRENT_MAX_RECLEN: usize = (DirEnt::FIXED_SIZE + DIRENT_MAX_NAME_LEN + 1 + 7) & !7;
    const DIRENT_BATCH_CAP: usize = 16;

    if buf.is_null() {
        warn!("Null buffer passed to getdents64");
        return -(LinuxError::EFAULT.code() as isize);
    }
    if len < DirEnt::FIXED_SIZE {
        warn!("Buffer size too small: {len}");
        return -(LinuxError::EINVAL.code() as isize);
    }

    if let Err(e) = ensure_user_range(
        VirtAddr::from(buf as usize),
        len,
        MappingFlags::READ | MappingFlags::WRITE,
    ) {
        warn!("Memory allocation failed: {:?}", e);
        return -(e.code() as isize);
    }

    let dir = match arceos_posix_api::Directory::from_fd(fd) {
        Ok(dir) => dir,
        Err(err) => {
            let mapped = match arceos_posix_api::get_file_like(fd) {
                Ok(_) => LinuxError::ENOTDIR,
                Err(_) => LinuxError::EBADF,
            };
            warn!("Invalid directory descriptor: {:?}", mapped);
            return -(mapped.code() as isize);
        }
    };

    let mut user_buf = vec![0u8; len];
    let mut buffer = DirBuffer::new(&mut user_buf);
    let mut cursor = 0i64;

    loop {
        let mut max_batch = core::cmp::min(
            DIRENT_BATCH_CAP,
            buffer.remaining_space() / DIRENT_MAX_RECLEN,
        );
        if max_batch == 0 {
            if buffer.offset == 0 {
                max_batch = 1;
            } else {
                break;
            }
        }

        let batch_start = buffer.offset;
        let mut wrote_entry = false;
        let mut entries: [axfs::fops::DirEntry; DIRENT_BATCH_CAP] =
            core::array::from_fn(|_| axfs::fops::DirEntry::default());
        let read_count = match dir.read_dir(&mut entries[..max_batch]) {
            Ok(count) => count,
            Err(err) => {
                warn!("Failed to read directory entries: {:?}", err);
                return -(err.code() as isize);
            }
        };
        if read_count == 0 {
            break;
        }

        for entry in &entries[..read_count] {
            let name = entry.name_as_bytes();
            let reclen = (name.len() + 1 + DirEnt::FIXED_SIZE + 7) & !7;
            if !buffer.can_fit_entry(reclen) {
                break;
            }

            cursor += reclen as i64;
            let dirent = DirEnt::new(1, cursor, reclen, FileType::from(entry.entry_type()));
            let mut name_bytes = [0u8; DIRENT_MAX_NAME_LEN + 1];
            name_bytes[..name.len()].copy_from_slice(name);
            name_bytes[name.len()] = 0;
            if buffer
                .write_entry(dirent, &name_bytes[..name.len() + 1])
                .is_err()
            {
                break;
            }
            wrote_entry = true;
        }

        if !wrote_entry {
            if batch_start == 0 {
                warn!(
                    "Buffer too small for first directory entry: remaining={}, fd={}",
                    buffer.remaining_space(),
                    fd
                );
                return -(LinuxError::EINVAL.code() as isize);
            }
            break;
        }
    }

    if buffer.offset == 0 {
        return 0;
    }
    let written = buffer.offset;
    drop(buffer);
    if let Err(err) = copy_to_user(buf, &user_buf[..written]) {
        warn!("Failed to write getdents64 buffer: {:?}", err);
        return -(err.code() as isize);
    }
    written as isize
}

/// create a link from new_path to old_path
/// old_path: old file path
/// new_path: new file path
/// flags: link flags
/// return value: return 0 when success, else return -1.
pub(crate) fn sys_linkat(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
    flags: i32,
) -> i32 {
    if flags != 0 {
        warn!("Unsupported flags: {flags}");
    }

    // handle old path
    handle_user_path(old_dirfd as isize, old_path, false)
        .inspect_err(|err| warn!("Failed to convert new path: {err:?}"))
        .and_then(|old_path| {
            //handle new path
            handle_user_path(new_dirfd as isize, new_path, false)
                .inspect_err(|err| warn!("Failed to convert new path: {err:?}"))
                .map(|new_path| (old_path, new_path))
        })
        .and_then(|(old_path, new_path)| {
            arceos_posix_api::HARDLINK_MANAGER
                .create_link(&new_path, &old_path)
                .inspect_err(|err| warn!("Failed to create link: {err:?}"))
                .map_err(|err| LinuxError::from(AxError::from(err)))
        })
        .map(|_| 0)
        .unwrap_or(-1)
}

/// remove link of specific file (can be used to delete file)
/// dir_fd: the directory of link to be removed
/// path: the name of link to be removed
/// flags: can be 0 or AT_REMOVEDIR
/// return 0 when success, else return -1
pub fn sys_unlinkat(dir_fd: isize, path: *const u8, flags: usize) -> isize {
    const AT_REMOVEDIR: usize = 0x200;
    syscall_body!(sys_unlinkat, {
        let path = handle_user_path(dir_fd, path, false)
            .inspect_err(log_unlinkat_error)?;
        if flags == AT_REMOVEDIR {
            if is_cgroup_v2_dir(path.as_str()) {
                cleanup_cgroup_v2_tree(path.as_str());
                if let Err(err) = axfs::api::remove_dir(path.as_str()) {
                    let _ = seed_cgroup_v2_dir(path.as_str());
                    log_unlinkat_ax_error(&err);
                    return Err(LinuxError::from(err));
                }
                let cgroup_root = api::proc_cgroup_mount_path();
                if path.as_str().trim_end_matches('/') == cgroup_root.trim_end_matches('/') {
                    api::clear_proc_cgroup_mount_path();
                }
                return Ok(0);
            }
            axfs::api::remove_dir(path.as_str())
                .inspect_err(log_unlinkat_ax_error)?;
            api::note_removed_directory(path.as_str());
            crate::mm::invalidate_exec_cache_path(path.as_str());
            return Ok(0);
        }
        let metadata = axfs::api::metadata(path.as_str()).inspect_err(log_unlinkat_ax_error)?;
        if metadata.is_dir() {
            return Err(LinuxError::EISDIR);
        }
        ensure_path_inode_mutation_allowed(path.as_str())?;
        debug!("unlink file: {:?}", path);
        if arceos_posix_api::HARDLINK_MANAGER
            .remove_link(&path)
            .is_none()
        {
            axfs::api::remove_file(path.as_str())
                .inspect_err(log_unlinkat_ax_error)?;
        }
        api::remove_named_tmpfile_path(path.as_str());
        crate::mm::invalidate_exec_cache_path(path.as_str());
        Ok(0)
    })
}

pub(crate) fn sys_utimensat(
    dirfd: i32,
    pathname: *const u8,
    times: *const c_void,
    _flags: i32,
) -> isize {
    syscall_body!(sys_utimensat, {
        let now = wall_time();
        let now_ts = api::ctypes::timespec {
            tv_sec: now.as_secs() as i64,
            tv_nsec: now.subsec_nanos() as i64,
        };

        let empty_path = if pathname.is_null() {
            false
        } else {
            read_user_path(pathname.cast())?.is_empty()
        };

        if pathname.is_null() || (empty_path && (_flags & 0x1000) != 0) {
            if pathname.is_null() && dirfd == AT_FDCWD as i32 {
                return Err(LinuxError::EFAULT);
            }
            get_file_like(dirfd)?;
            if let Some(path) = fd_backing_path(dirfd) {
                ensure_path_inode_mutation_allowed(path.as_str())?;
            }
            let existing = api::get_file_times(dirfd)?;
            let requested = if times.is_null() {
                [now_ts; 2]
            } else {
                [
                    read_value_from_user(times as *const api::ctypes::timespec)?,
                    read_value_from_user(unsafe {
                        (times as *const api::ctypes::timespec).add(1)
                    })?,
                ]
            };
            let current = existing
                .map(|value| value.0)
                .zip(existing.map(|value| value.1))
                .map(|(atime, mtime)| [atime, mtime])
                .unwrap_or([api::ctypes::timespec::default(); 2]);
            let resolved = resolve_requested_times(requested, current, now_ts)?;
            api::set_file_times(dirfd, resolved[0], resolved[1])?;
            let file_like = get_file_like(dirfd)?;
            if let Ok(file) = file_like
                .clone()
                .into_any()
                .downcast::<arceos_posix_api::File>()
            {
                api::set_path_times(file.path(), false, resolved[0], resolved[1], resolved[1]);
            } else if let Ok(dir) = file_like
                .into_any()
                .downcast::<arceos_posix_api::Directory>()
            {
                api::set_path_times(dir.path(), true, resolved[0], resolved[1], resolved[1]);
            }
            return Ok(0);
        }
        if empty_path {
            return Err(LinuxError::ENOENT);
        }

        let path =
            handle_user_path(dirfd as isize, pathname, false).map_err(|_| LinuxError::ENOENT)?;
        if !path.exists() {
            if let Some((parent, _)) = path.as_str().rsplit_once('/') {
                if !parent.is_empty()
                    && axfs::api::metadata(parent)
                        .map(|meta| !meta.is_dir())
                        .unwrap_or(false)
                {
                    return Err(LinuxError::ENOTDIR);
                }
            }
            return Err(LinuxError::ENOENT);
        }
        if _flags & !AT_SYMLINK_NOFOLLOW != 0 {
            return Err(LinuxError::EINVAL);
        }
        let (resolved, attr) =
            resolve_existing_path(path.as_str(), (_flags & AT_SYMLINK_NOFOLLOW) == 0)?;
        let requested = if times.is_null() {
            None
        } else {
            Some([
                read_value_from_user(times as *const api::ctypes::timespec)?,
                read_value_from_user(unsafe { (times as *const api::ctypes::timespec).add(1) })?,
            ])
        };
        if axfs::api::is_readonly_path(resolved.as_str()).map_err(LinuxError::from)? {
            return Err(LinuxError::EROFS);
        }
        ensure_path_inode_mutation_allowed(resolved.as_str())?;
        let (owner_uid, _owner_gid, _owner_mode) =
            axfs::api::path_owner_mode(resolved.as_str(), attr);
        let caller_euid = axfs::api::current_euid();
        if let Some(_) = requested {
            if caller_euid != 0 && caller_euid != owner_uid {
                return Err(LinuxError::EPERM);
            }
        } else if caller_euid != 0
            && caller_euid != owner_uid
            && !axfs::api::can_access(resolved.as_str(), attr, false, false, true, false)
        {
            return Err(LinuxError::EACCES);
        }
        set_times_on_resolved_path(resolved.as_str(), attr.is_dir(), requested, now_ts)?;
        Ok(0)
    })
}

pub(crate) fn sys_utime(pathname: *const c_char, times: *const UserUtimbuf) -> isize {
    syscall_body!(sys_utime, {
        let requested = if times.is_null() {
            None
        } else {
            let times = read_value_from_user(times)?;
            Some([
                api::ctypes::timespec {
                    tv_sec: times.actime,
                    tv_nsec: 0,
                },
                api::ctypes::timespec {
                    tv_sec: times.modtime,
                    tv_nsec: 0,
                },
            ])
        };
        let now = wall_time();
        let now_ts = api::ctypes::timespec {
            tv_sec: now.as_secs() as i64,
            tv_nsec: now.subsec_nanos() as i64,
        };
        let resolved = handle_user_path(AT_FDCWD as isize, pathname.cast(), false)
            .map_err(|_| LinuxError::ENOENT)?;
        let (resolved, _attr) = resolve_existing_path(resolved.as_str(), true)?;
        let attr = axfs::api::metadata_raw(resolved.as_str()).map_err(LinuxError::from)?;
        ensure_path_inode_mutation_allowed(resolved.as_str())?;
        set_times_on_resolved_path(resolved.as_str(), attr.is_dir(), requested, now_ts)?;
        Ok(0)
    })
}

pub(crate) fn sys_utimes(pathname: *const c_char, times: *const api::ctypes::timeval) -> isize {
    syscall_body!(sys_utimes, {
        let requested = if times.is_null() {
            None
        } else {
            let atime = read_value_from_user(times)?;
            let mtime = read_value_from_user(unsafe { times.add(1) })?;
            Some([
                api::ctypes::timespec {
                    tv_sec: atime.tv_sec,
                    tv_nsec: atime.tv_usec * 1_000,
                },
                api::ctypes::timespec {
                    tv_sec: mtime.tv_sec,
                    tv_nsec: mtime.tv_usec * 1_000,
                },
            ])
        };
        let now = wall_time();
        let now_ts = api::ctypes::timespec {
            tv_sec: now.as_secs() as i64,
            tv_nsec: now.subsec_nanos() as i64,
        };
        let resolved = handle_user_path(AT_FDCWD as isize, pathname.cast(), false)
            .map_err(|_| LinuxError::ENOENT)?;
        let (resolved, _attr) = resolve_existing_path(resolved.as_str(), true)?;
        let attr = axfs::api::metadata_raw(resolved.as_str()).map_err(LinuxError::from)?;
        ensure_path_inode_mutation_allowed(resolved.as_str())?;
        set_times_on_resolved_path(resolved.as_str(), attr.is_dir(), requested, now_ts)?;
        Ok(0)
    })
}

pub(crate) fn sys_renameat2(
    old_dirfd: i32,
    old_path: *const u8,
    new_dirfd: i32,
    new_path: *const u8,
    flags: u32,
) -> isize {
    syscall_body!(sys_renameat2, {
        if flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        let old_raw = read_user_path(old_path.cast())?;
        let new_raw = read_user_path(new_path.cast())?;
        let old_path = resolve_rename_target_path(old_dirfd, old_raw.as_str())?;
        let new_path = resolve_rename_target_path(new_dirfd, new_raw.as_str())?;
        let (old_resolved, _old_attr) = resolve_existing_path(old_path.as_str(), false)?;
        let new_resolved = canonicalize_rename_destination(new_path.as_str())?;
        if axfs::api::is_readonly_path(old_resolved.as_str()).unwrap_or(false)
            || axfs::api::is_readonly_path(normalized_parent_path(new_resolved.as_str()))
                .unwrap_or(false)
        {
            return Err(LinuxError::EROFS);
        }
        #[cfg(feature = "lwext4_rs")]
        ensure_ext4_rename_dir_capacity(old_resolved.as_str(), new_resolved.as_str())?;
        ensure_path_inode_mutation_allowed(old_resolved.as_str())?;
        if axfs::api::absolute_path_exists(new_resolved.as_str()) {
            ensure_path_inode_mutation_allowed(new_resolved.as_str())?;
        }
        if axfs::api::absolute_path_exists(new_resolved.as_str()) {
            if axfs::api::metadata_raw_nofollow(new_resolved.as_str())
                .map_err(LinuxError::from)?
                .is_dir()
            {
                let _ = axfs::api::remove_dir(new_resolved.as_str());
            } else {
                let _ = axfs::api::remove_file(new_resolved.as_str());
            }
        }
        axfs::api::rename(old_resolved.as_str(), new_resolved.as_str())?;
        crate::mm::invalidate_exec_cache_path(old_resolved.as_str());
        crate::mm::invalidate_exec_cache_path(new_resolved.as_str());
        Ok(0)
    })
}

pub(crate) fn sys_getcwd(buf: *mut c_char, size: usize) -> isize {
    syscall_body!(sys_getcwd, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let cwd = axfs::api::current_dir()?;
        let bytes = cwd.as_bytes();
        if bytes.len() + 1 > size {
            return Err(LinuxError::ERANGE);
        }
        copy_to_user(buf.cast::<c_void>(), bytes)?;
        copy_to_user(unsafe { buf.add(bytes.len()) }.cast::<c_void>(), &[0])?;
        Ok((bytes.len() + 1) as isize)
    })
}

pub(crate) fn sys_ftruncate(fd: i32, length: api::ctypes::off_t) -> isize {
    syscall_body!(sys_ftruncate, {
        if length < 0 {
            return Err(LinuxError::EINVAL);
        }
        let mut rlimit = api::ctypes::rlimit::default();
        if unsafe { api::sys_getrlimit(api::ctypes::RLIMIT_FSIZE as i32, &mut rlimit as *mut _) }
            == 0
            && rlimit.rlim_cur != u64::MAX
            && (length as u64) > rlimit.rlim_cur
        {
            return Err(LinuxError::EFBIG);
        }
        let file = get_file_like(fd)?;
        if (file.status_flags() as u32 & api::ctypes::O_ACCMODE) == api::ctypes::O_RDONLY {
            return Err(LinuxError::EINVAL);
        }
        if let Some(path) = fd_backing_path(fd) {
            ensure_path_inode_mutation_allowed(path.as_str())?;
        }
        let old_size = file.stat()?.st_size.max(0) as u64;
        if let Ok(file) = file.clone().into_any().downcast::<arceos_posix_api::File>() {
            crate::mm::invalidate_exec_cache_path(file.path());
        }
        notify_lease_break_for_fd(fd, true, true);
        if (length as u64) <= old_size {
            file.truncate(length as u64)?;
        } else if length > 0 {
            let saved = api::sys_lseek(fd, 0, 1);
            if api::sys_lseek(fd, old_size as i64, 0) < 0 {
                return Err(LinuxError::EINVAL);
            }
            let zeros = [0u8; 4096];
            let mut remaining = (length as u64) - old_size;
            while remaining > 0 {
                let chunk = remaining.min(zeros.len() as u64) as usize;
                let written = file.write(&zeros[..chunk])?;
                if written == 0 {
                    return Err(LinuxError::EIO);
                }
                remaining -= written as u64;
            }
            if saved >= 0 {
                let _ = api::sys_lseek(fd, saved, 0);
            }
        }
        Ok(0)
    })
}

pub(crate) fn sys_truncate(path: *const c_char, length: api::ctypes::off_t) -> isize {
    syscall_body!(sys_truncate, {
        if length < 0 {
            return Err(LinuxError::EINVAL);
        }
        let mut rlimit = api::ctypes::rlimit::default();
        if unsafe { api::sys_getrlimit(api::ctypes::RLIMIT_FSIZE as i32, &mut rlimit as *mut _) }
            == 0
            && rlimit.rlim_cur != u64::MAX
            && (length as u64) > rlimit.rlim_cur
        {
            return Err(LinuxError::EFBIG);
        }
        let raw_path = read_user_path(path)?;
        if raw_path.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        validate_path_components(raw_path.as_str())?;
        let resolved = handle_user_path(AT_FDCWD as isize, path.cast(), false)?;
        let (resolved, attr) = resolve_existing_path(resolved.as_str(), true)?;
        if attr.is_dir() {
            return Err(LinuxError::EISDIR);
        }
        if axfs::api::is_readonly_path(resolved.as_str()).map_err(LinuxError::from)? {
            return Err(LinuxError::EROFS);
        }
        ensure_path_inode_mutation_allowed(resolved.as_str())?;
        let path_cstr = CString::new(resolved.as_str()).map_err(|_| LinuxError::EINVAL)?;
        let fd = api::sys_openat(
            AT_FDCWD as i32,
            path_cstr.as_ptr(),
            (api::ctypes::O_WRONLY | api::ctypes::O_CLOEXEC) as i32,
            0,
        );
        if fd < 0 {
            return Err(LinuxError::try_from((-fd) as i32).unwrap_or(LinuxError::EINVAL));
        }
        let fd = fd as i32;
        let result = (|| -> Result<(), LinuxError> {
            let file = get_file_like(fd)?;
            let old_size = file.stat()?.st_size.max(0) as u64;
            if let Ok(file) = file.clone().into_any().downcast::<arceos_posix_api::File>() {
                crate::mm::invalidate_exec_cache_path(file.path());
            }
            notify_lease_break_for_fd(fd, true, true);
            if (length as u64) <= old_size {
                file.truncate(length as u64)?;
            } else if length > 0 {
                if api::sys_lseek(fd, old_size as i64, 0) < 0 {
                    return Err(LinuxError::EINVAL);
                }
                let zeros = [0u8; 4096];
                let mut remaining = (length as u64) - old_size;
                while remaining > 0 {
                    let chunk = remaining.min(zeros.len() as u64) as usize;
                    let written = file.write(&zeros[..chunk])?;
                    if written == 0 {
                        return Err(LinuxError::EIO);
                    }
                    remaining -= written as u64;
                }
            }
            Ok(())
        })();
        let _ = api::sys_close(fd);
        result?;
        Ok(0)
    })
}

pub(crate) fn sys_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> isize {
    syscall_body!(sys_fallocate, {
        if offset < 0 || len < 0 || len == 0 {
            return Err(LinuxError::EINVAL);
        }
        let end = offset.checked_add(len).ok_or(LinuxError::EFBIG)?;
        if end < 0 || end > i64::MAX {
            return Err(LinuxError::EFBIG);
        }
        let mut rlimit = api::ctypes::rlimit::default();
        if unsafe { api::sys_getrlimit(api::ctypes::RLIMIT_FSIZE as i32, &mut rlimit as *mut _) }
            == 0
            && rlimit.rlim_cur != u64::MAX
            && (end as u64) > rlimit.rlim_cur
        {
            return Err(LinuxError::EFBIG);
        }
        let file = get_file_like(fd)?;
        if (file.status_flags() as u32 & api::ctypes::O_ACCMODE) == api::ctypes::O_RDONLY {
            return Err(LinuxError::EBADF);
        }
        let file = file
            .into_any()
            .downcast::<arceos_posix_api::File>()
            .map_err(|_| LinuxError::EBADF)?;
        if axfs::api::is_readonly_path(file.path()).map_err(LinuxError::from)? {
            return Err(LinuxError::EROFS);
        }
        file.inner()
            .lock()
            .fallocate(mode as u32, offset as u64, len as u64)
            .map_err(|err| match LinuxError::from(err) {
                LinuxError::ENOSYS => LinuxError::EOPNOTSUPP,
                other => other,
            })?;
        crate::mm::invalidate_exec_cache_path(file.path());
        Ok(0)
    })
}
