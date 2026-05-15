use alloc::{
    ffi::CString,
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    ffi::{c_char, c_int, c_void},
    mem::zeroed,
    time::Duration,
};

use arceos_posix_api::{self as api, ctypes::mode_t, get_file_like};
use axerrno::LinuxError;
use axhal::{mem::VirtAddr, paging::MappingFlags};
use axtask::{current, TaskExtRef};
use axstd::io::SeekFrom;
use core::sync::atomic::{AtomicBool, Ordering};
use memory_addr::PAGE_SIZE_4K;

use super::{
    fd_ops::{notify_fd_write_event, notify_lease_break_for_fd},
    handle_kernel_path, handle_user_path, read_user_path, resolve_existing_path,
};

use crate::signal::{current_blocked_mask, read_user_sigset_mask, set_current_blocked_mask};
use crate::syscall_body;
use crate::timekeeping::open_special_proc_file;
use crate::usercopy::{
    copy_from_user, copy_to_user, ensure_user_range, read_value_from_user, write_value_to_user,
};

static LIBCBENCH_TMP_OPEN_LOGGED: AtomicBool = AtomicBool::new(false);
const O_PATH: i32 = 0o10000000;
const AT_EACCESS: i32 = 0x200;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_EMPTY_PATH: i32 = 0x1000;
const SEEK_CUR: i32 = 1;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFBLK: u32 = 0o060000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFIFO: u32 = 0o010000;
const S_IFSOCK: u32 = 0o140000;
const SPLICE_F_MOVE: u32 = 0x01;
const SPLICE_F_NONBLOCK: u32 = 0x02;
const SPLICE_F_MORE: u32 = 0x04;
const SPLICE_F_GIFT: u32 = 0x08;
const POSIX_FADV_NORMAL: i32 = 0;
const POSIX_FADV_RANDOM: i32 = 1;
const POSIX_FADV_SEQUENTIAL: i32 = 2;
const POSIX_FADV_WILLNEED: i32 = 3;
const POSIX_FADV_DONTNEED: i32 = 4;
const POSIX_FADV_NOREUSE: i32 = 5;
const FS_IMMUTABLE_FL: u32 = 0x0000_0010;
const FS_APPEND_FL: u32 = 0x0000_0020;

fn validate_vectored_io(iov: *const api::ctypes::iovec, iocnt: i32) -> Result<(), LinuxError> {
    if iocnt < 0 {
        return Err(LinuxError::EINVAL);
    }
    if iocnt > 0 && iov.is_null() {
        return Err(LinuxError::EFAULT);
    }

    let mut total = 0usize;
    for index in 0..iocnt as usize {
        let iov_ref = read_value_from_user(unsafe { iov.add(index) })?;
        if iov_ref.iov_len > isize::MAX as usize {
            return Err(LinuxError::EINVAL);
        }
        total = total
            .checked_add(iov_ref.iov_len)
            .filter(|sum| *sum <= isize::MAX as usize)
            .ok_or(LinuxError::EINVAL)?;
    }
    Ok(())
}

fn validate_positional_fd(
    fd: i32,
    wants_write: bool,
) -> Result<alloc::sync::Arc<dyn api::FileLike>, LinuxError> {
    let file = get_file_like(fd)?;
    let flags = file.status_flags();
    if flags & (O_PATH as usize) != 0 {
        return Err(LinuxError::EBADF);
    }
    let mode = file.stat()?.st_mode & S_IFMT;
    if matches!(mode, S_IFIFO | S_IFSOCK) {
        return Err(LinuxError::ESPIPE);
    }
    let access = (flags as u32) & api::ctypes::O_ACCMODE;
    if wants_write {
        if access == api::ctypes::O_RDONLY {
            return Err(LinuxError::EBADF);
        }
    } else if access == api::ctypes::O_WRONLY {
        return Err(LinuxError::EBADF);
    }

    if !wants_write && mode == S_IFDIR {
        return Err(LinuxError::EISDIR);
    }

    Ok(file)
}

fn splice_nonpipe_supported(mode: u32) -> bool {
    matches!(mode, S_IFREG | S_IFBLK | S_IFCHR | S_IFSOCK)
}

fn splice_seekable(mode: u32) -> bool {
    matches!(mode, S_IFREG | S_IFBLK)
}

fn update_current_proc_stat(state: char) {
    let pid = current().id().as_u64();
    let dir = format!("/proc/{pid}");
    let path = format!("{dir}/stat");
    let utime = (axhal::time::monotonic_time_nanos() as u64 / 10_000_000).max(1);
    let contents = format!(
        "{pid} (busybox) {state} 0 0 0 0 0 0 0 0 0 0 {utime} 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    );
    if !axfs::api::absolute_path_exists(dir.as_str()) {
        let _ = axfs::api::create_dir(dir.as_str());
    }
    let _ = axfs::api::write(path.as_str(), contents.as_bytes());
}

fn is_cgroup_v2_path(path: &str) -> bool {
    let root = api::proc_cgroup_mount_path();
    let prefix = format!("{root}/");
    path == root || path.starts_with(prefix.as_str())
}

fn normalized_dir_path(path: &str) -> String {
    if path == "/" {
        "/".to_string()
    } else {
        path.trim_end_matches('/').to_string()
    }
}

fn join_dir_entry_path(dir_path: &str, entry: &str) -> String {
    let dir_path = normalized_dir_path(dir_path);
    if entry.starts_with('/') {
        return entry.to_string();
    }
    if dir_path == "/" {
        format!("/{entry}")
    } else {
        format!("{dir_path}/{entry}")
    }
}

fn ensure_dir_parents(path: &str) -> Result<(), LinuxError> {
    let mut current = String::new();
    for component in path.split('/').filter(|part| !part.is_empty()) {
        current.push('/');
        current.push_str(component);
        if !axfs::api::absolute_path_exists(current.as_str()) {
            axfs::api::create_dir(current.as_str()).map_err(LinuxError::from)?;
        }
    }
    Ok(())
}

fn ensure_open_inode_flags_allow(path: &str, flags: i32) -> Result<(), LinuxError> {
    let attr = axfs::api::metadata_raw(path).map_err(LinuxError::from)?;
    let fs_flags = axfs::api::path_stat_metadata(path, attr).fs_flags;
    let access = (flags as u32) & api::ctypes::O_ACCMODE;
    let write_intent = access != api::ctypes::O_RDONLY
        || (flags as u32 & (api::ctypes::O_TRUNC | api::ctypes::O_APPEND)) != 0;

    if (fs_flags & FS_IMMUTABLE_FL) != 0 && write_intent {
        return Err(LinuxError::EPERM);
    }
    if (fs_flags & FS_APPEND_FL) != 0 {
        if (flags as u32 & api::ctypes::O_TRUNC) != 0 {
            return Err(LinuxError::EPERM);
        }
        if access != api::ctypes::O_RDONLY && (flags as u32 & api::ctypes::O_APPEND) == 0 {
            return Err(LinuxError::EPERM);
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

fn ensure_cgroup_open_target(path: &str, flags: i32) -> Result<(), LinuxError> {
    if !is_cgroup_v2_path(path) {
        return Ok(());
    }
    let dir_flags = api::ctypes::O_DIRECTORY as i32 | O_PATH;
    if flags & dir_flags != 0 {
        ensure_dir_parents(path)?;
        seed_cgroup_v2_dir(path)?;
        return Ok(());
    }
    let parent = path
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/");
    ensure_dir_parents(parent)?;
    seed_cgroup_v2_dir(parent)?;
    Ok(())
}

fn resolve_faccessat_path(
    dirfd: i32,
    path: *const c_char,
    flags: i32,
) -> Result<(String, axfs::fops::FileAttr), LinuxError> {
    if path.is_null() {
        return Err(LinuxError::EFAULT);
    }
    let raw_path = read_user_path(path)?;
    if raw_path.is_empty() && flags & AT_EMPTY_PATH == 0 {
        return Err(LinuxError::ENOENT);
    }
    if flags & !(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH) != 0 {
        return Err(LinuxError::EINVAL);
    }
    if raw_path.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    if !raw_path.starts_with('/') && dirfd != api::AT_FDCWD as i32 {
        if get_file_like(dirfd).is_err() {
            return Err(LinuxError::EBADF);
        }
        if api::Directory::from_fd(dirfd).is_err() {
            return Err(LinuxError::ENOTDIR);
        }
    }

    let resolved = handle_user_path(dirfd as isize, path as *const u8, false)?;
    resolve_existing_path(resolved.as_str(), flags & AT_SYMLINK_NOFOLLOW == 0)
}

fn runtime_prefixes_for_exec(exec_path: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut dir = crate::mm::absolute_exec_path(exec_path);
    if !dir.ends_with('/') {
        dir = dir
            .rsplit_once('/')
            .map(|(parent, _)| {
                if parent.is_empty() {
                    "/".to_string()
                } else {
                    parent.to_string()
                }
            })
            .unwrap_or_else(|| "/".to_string());
    }
    loop {
        if !prefixes.iter().any(|existing| existing == &dir) {
            prefixes.push(dir.clone());
        }
        if dir == "/" {
            break;
        }
        dir = dir
            .rsplit_once('/')
            .map(|(parent, _)| {
                if parent.is_empty() {
                    "/".to_string()
                } else {
                    parent.to_string()
                }
            })
            .unwrap_or_else(|| "/".to_string());
    }
    prefixes
}

fn runtime_scoped_absolute_path(exec_path: &str, path: &str) -> Option<String> {
    if !matches!(
        path,
        p if p.starts_with("/lib/")
            || p.starts_with("/lib64/")
            || p.starts_with("/usr/lib/")
            || p.starts_with("/usr/lib64/")
    ) {
        return None;
    }
    runtime_prefixes_for_exec(exec_path)
        .into_iter()
        .filter(|prefix| prefix != "/")
        .map(|prefix| format!("{prefix}{path}"))
        .find(|candidate| axfs::api::absolute_path_exists(candidate.as_str()))
}

pub(crate) fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    syscall_body!(sys_read, {
        if count == 0 {
            return Ok(0);
        }
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            let read_len = file.read(&mut kbuf[..chunk])?;
            if read_len == 0 {
                break;
            }
            copy_to_user(
                unsafe { (buf as *mut u8).add(total) as *mut c_void },
                &kbuf[..read_len],
            )?;
            total += read_len;
            if read_len < chunk {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_pread64(
    fd: i32,
    buf: *mut c_void,
    count: usize,
    offset: api::ctypes::off_t,
) -> isize {
    syscall_body!(sys_pread64, {
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        if count == 0 {
            return Ok(0);
        }
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            let read_len = file.read_at(offset as u64 + total as u64, &mut kbuf[..chunk])?;
            if read_len == 0 {
                break;
            }
            copy_to_user(
                unsafe { (buf as *mut u8).add(total) as *mut c_void },
                &kbuf[..read_len],
            )?;
            total += read_len;
            if read_len < chunk {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_pwrite64(
    fd: i32,
    buf: *const c_void,
    count: usize,
    offset: api::ctypes::off_t,
) -> isize {
    syscall_body!(sys_pwrite64, {
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        if count == 0 {
            return Ok(0);
        }
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            let user_ptr = unsafe { (buf as *const u8).add(total) as *const c_void };
            copy_from_user(&mut kbuf[..chunk], user_ptr)?;
            let written = file.write_at(offset as u64 + total as u64, &kbuf[..chunk])?;
            total += written;
            if written < chunk {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_readv(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    syscall_body!(sys_readv, {
        validate_vectored_io(iov, iocnt)?;

        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        for index in 0..iocnt as usize {
            let iov_ref = read_value_from_user(unsafe { iov.add(index) })?;
            if iov_ref.iov_len == 0 {
                continue;
            }

            let mut iov_total = 0usize;
            while iov_total < iov_ref.iov_len {
                let chunk = (iov_ref.iov_len - iov_total).min(kbuf.len());
                let read_len = file.read(&mut kbuf[..chunk])?;
                if read_len == 0 {
                    break;
                }
                copy_to_user(
                    unsafe { (iov_ref.iov_base as *mut u8).add(iov_total) as *mut c_void },
                    &kbuf[..read_len],
                )?;
                iov_total += read_len;
                total += read_len;
                if read_len < chunk {
                    return Ok(total);
                }
            }
            if iov_total < iov_ref.iov_len {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_preadv(
    fd: i32,
    iov: *const api::ctypes::iovec,
    iocnt: i32,
    offset: api::ctypes::off_t,
) -> isize {
    syscall_body!(sys_preadv, {
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        validate_vectored_io(iov, iocnt)?;

        let file = validate_positional_fd(fd, false)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        let base_offset = offset as u64;
        for index in 0..iocnt as usize {
            let iov_ref = read_value_from_user(unsafe { iov.add(index) })?;
            if iov_ref.iov_len == 0 {
                continue;
            }

            let mut iov_total = 0usize;
            while iov_total < iov_ref.iov_len {
                let chunk = (iov_ref.iov_len - iov_total).min(kbuf.len());
                let read_len = file.read_at(base_offset + total as u64, &mut kbuf[..chunk])?;
                if read_len == 0 {
                    break;
                }
                copy_to_user(
                    unsafe { (iov_ref.iov_base as *mut u8).add(iov_total) as *mut c_void },
                    &kbuf[..read_len],
                )?;
                iov_total += read_len;
                total += read_len;
                if read_len < chunk {
                    return Ok(total);
                }
            }
            if iov_total < iov_ref.iov_len {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    let mut progress_chunks = Vec::new();
    let ret = syscall_body!(sys_write, {
        if count == 0 {
            return Ok(0);
        }
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            let user_ptr = unsafe { (buf as *const u8).add(total) as *const c_void };
            copy_from_user(&mut kbuf[..chunk], user_ptr)?;
            let written = file.write(&kbuf[..chunk])?;
            if written > 0 && (fd == 1 || fd == 2) {
                progress_chunks.push(kbuf[..written].to_vec());
            }
            total += written;
            if written < chunk {
                break;
            }
        }
        Ok(total)
    });
    if ret == -(LinuxError::EPIPE.code() as isize) {
        crate::signal::send_current_signal(13);
    } else if ret > 0 {
        notify_fd_write_event(fd);
        for chunk in &progress_chunks {
            crate::note_competition_output_activity(fd, chunk);
        }
    }
    ret
}

pub(crate) fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    syscall_body!(sys_writev, {
        validate_vectored_io(iov, iocnt)?;

        let file = get_file_like(fd)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        for index in 0..iocnt as usize {
            let iov_ref = read_value_from_user(unsafe { iov.add(index) })?;
            if iov_ref.iov_len == 0 {
                continue;
            }

            let mut iov_total = 0usize;
            while iov_total < iov_ref.iov_len {
                let chunk = (iov_ref.iov_len - iov_total).min(kbuf.len());
                let user_ptr =
                    unsafe { (iov_ref.iov_base as *const u8).add(iov_total) as *const c_void };
                copy_from_user(&mut kbuf[..chunk], user_ptr)?;
                let written = file.write(&kbuf[..chunk])?;
                if written > 0 && (fd == 1 || fd == 2) {
                    crate::note_competition_output_activity(fd, &kbuf[..written]);
                }
                iov_total += written;
                total += written;
                if written < chunk {
                    break;
                }
            }
            if iov_total < iov_ref.iov_len {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_pwritev(
    fd: i32,
    iov: *const api::ctypes::iovec,
    iocnt: i32,
    offset: api::ctypes::off_t,
) -> isize {
    syscall_body!(sys_pwritev, {
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        validate_vectored_io(iov, iocnt)?;

        let file = validate_positional_fd(fd, true)?;
        let mut total = 0usize;
        let mut kbuf = [0u8; PAGE_SIZE_4K];
        let base_offset = offset as u64;
        for index in 0..iocnt as usize {
            let iov_ref = read_value_from_user(unsafe { iov.add(index) })?;
            if iov_ref.iov_len == 0 {
                continue;
            }

            let mut iov_total = 0usize;
            while iov_total < iov_ref.iov_len {
                let chunk = (iov_ref.iov_len - iov_total).min(kbuf.len());
                let user_ptr =
                    unsafe { (iov_ref.iov_base as *const u8).add(iov_total) as *const c_void };
                copy_from_user(&mut kbuf[..chunk], user_ptr)?;
                let written = file.write_at(base_offset + total as u64, &kbuf[..chunk])?;
                if written > 0 && (fd == 1 || fd == 2) {
                    crate::note_competition_output_activity(fd, &kbuf[..written]);
                }
                iov_total += written;
                total += written;
                if written < chunk {
                    break;
                }
            }
            if iov_total < iov_ref.iov_len {
                break;
            }
        }
        Ok(total)
    })
}

pub(crate) fn sys_preadv2(
    fd: i32,
    iov: *const api::ctypes::iovec,
    iocnt: i32,
    offset: api::ctypes::off_t,
    flags: i32,
) -> isize {
    syscall_body!(sys_preadv2, {
        if flags != 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        let ret = sys_preadv(fd, iov, iocnt, offset);
        if ret < 0 {
            return Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL));
        }
        Ok(ret as usize)
    })
}

pub(crate) fn sys_pwritev2(
    fd: i32,
    iov: *const api::ctypes::iovec,
    iocnt: i32,
    offset: api::ctypes::off_t,
    flags: i32,
) -> isize {
    syscall_body!(sys_pwritev2, {
        if flags != 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }
        let ret = sys_pwritev(fd, iov, iocnt, offset);
        if ret < 0 {
            return Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL));
        }
        Ok(ret as usize)
    })
}

pub(crate) fn sys_copy_file_range(
    fd_in: i32,
    off_in: *mut api::ctypes::off_t,
    fd_out: i32,
    off_out: *mut api::ctypes::off_t,
    len: usize,
    flags: u32,
) -> isize {
    syscall_body!(sys_copy_file_range, {
        const MAX_COPY_FILE_OFFSET: u64 = i64::MAX as u64;
        if flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        if len == 0 {
            return Ok(0);
        }
        let input = get_file_like(fd_in)?;
        let output = get_file_like(fd_out)?;
        if input.status_flags() & (O_PATH as usize) != 0
            || output.status_flags() & (O_PATH as usize) != 0
        {
            return Err(LinuxError::EBADF);
        }
        let input_stat = input.stat()?;
        let output_stat = output.stat()?;
        let input_mode = input_stat.st_mode & S_IFMT;
        let output_mode = output_stat.st_mode & S_IFMT;
        if input_mode == S_IFDIR || output_mode == S_IFDIR {
            return Err(LinuxError::EISDIR);
        }
        if input_mode != S_IFREG || output_mode != S_IFREG {
            return Err(LinuxError::EINVAL);
        }
        let input_access = (input.status_flags() as u32) & api::ctypes::O_ACCMODE;
        let output_access = (output.status_flags() as u32) & api::ctypes::O_ACCMODE;
        if input_access == api::ctypes::O_WRONLY || output_access == api::ctypes::O_RDONLY {
            return Err(LinuxError::EBADF);
        }
        if output.status_flags() & (api::ctypes::O_APPEND as usize) != 0 {
            return Err(LinuxError::EBADF);
        }

        let in_pos = if off_in.is_null() {
            input.seek(SeekFrom::Current(0))?
        } else {
            let offset = read_value_from_user(off_in as *const api::ctypes::off_t)?;
            u64::try_from(offset).map_err(|_| LinuxError::EINVAL)?
        };
        let out_pos = if off_out.is_null() {
            output.seek(SeekFrom::Current(0))?
        } else {
            let offset = read_value_from_user(off_out as *const api::ctypes::off_t)?;
            u64::try_from(offset).map_err(|_| LinuxError::EINVAL)?
        };

        if in_pos > MAX_COPY_FILE_OFFSET || out_pos > MAX_COPY_FILE_OFFSET {
            return Err(LinuxError::EINVAL);
        }
        if len > i64::MAX as usize {
            return Err(LinuxError::EOVERFLOW);
        }
        let len_u64 = len as u64;
        if in_pos
            .checked_add(len_u64)
            .is_none_or(|end| end > MAX_COPY_FILE_OFFSET)
        {
            return Err(LinuxError::EOVERFLOW);
        }
        if out_pos.checked_add(len_u64).is_none() {
            return Err(LinuxError::EOVERFLOW);
        }
        if out_pos + len_u64 > MAX_COPY_FILE_OFFSET {
            return Err(LinuxError::EFBIG);
        }

        if let Ok(output_file) = output.clone().into_any().downcast::<api::File>() {
            if let Ok(attr) = axfs::api::metadata_raw(output_file.path()) {
                let fs_flags = axfs::api::path_stat_metadata(output_file.path(), attr).fs_flags;
                if (fs_flags & FS_IMMUTABLE_FL) != 0 {
                    return Err(LinuxError::EPERM);
                }
            }
        }

        if let (Some(input_key), Some(output_key)) = (input.lock_key(), output.lock_key()) {
            if input_key == output_key {
                let in_end = in_pos + len_u64;
                let out_end = out_pos + len_u64;
                if in_pos < out_end && out_pos < in_end {
                    return Err(LinuxError::EINVAL);
                }
            }
        }

        let mut input_offset = in_pos;
        let mut output_offset = out_pos;
        let mut copied = 0usize;
        let mut remaining = len;
        let mut buf = vec![0u8; len.min(PAGE_SIZE_4K).max(1)];

        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            let read_len = input.read_at(input_offset, &mut buf[..chunk])?;
            if read_len == 0 {
                break;
            }

            let mut written_total = 0usize;
            while written_total < read_len {
                let written = output.write_at(
                    output_offset + written_total as u64,
                    &buf[written_total..read_len],
                )?;
                if written == 0 {
                    if copied == 0 {
                        return Err(LinuxError::EIO);
                    }
                    break;
                }
                written_total += written;
            }

            if written_total == 0 {
                break;
            }

            copied += written_total;
            remaining -= written_total;
            input_offset += written_total as u64;
            output_offset += written_total as u64;
            if written_total < read_len {
                break;
            }
        }

        if off_in.is_null() {
            input.seek(SeekFrom::Start(input_offset))?;
        } else {
            write_value_to_user(off_in, input_offset as api::ctypes::off_t)?;
        }
        if off_out.is_null() {
            output.seek(SeekFrom::Start(output_offset))?;
        } else {
            write_value_to_user(off_out, output_offset as api::ctypes::off_t)?;
        }

        let now_ns = axhal::time::wall_time().as_nanos() as i64;
        let now = api::ctypes::timespec {
            tv_sec: now_ns / 1_000_000_000,
            tv_nsec: now_ns % 1_000_000_000,
        };
        if copied > 0 {
            api::set_file_times(fd_out, now, now)?;
        }
        Ok(copied)
    })
}

pub(crate) fn sys_openat(dirfd: i32, path: *const c_char, flags: i32, modes: mode_t) -> isize {
    let raw_path = match read_user_path(path) {
        Ok(path_str) => path_str,
        Err(err) => return -(err.code() as isize),
    };
    if !raw_path.starts_with('/') && dirfd != api::AT_FDCWD as i32 {
        if get_file_like(dirfd).is_err() {
            return -(LinuxError::EBADF.code() as isize);
        }
        if api::Directory::from_fd(dirfd).is_err() {
            return -(LinuxError::ENOTDIR.code() as isize);
        }
    }
    let write_like = (flags as u32 & 0b11) != api::ctypes::O_RDONLY
        || (flags as u32 & (api::ctypes::O_CREAT | api::ctypes::O_TRUNC | api::ctypes::O_APPEND))
            != 0;
    let resolved_for_trace = if write_like {
        handle_kernel_path(dirfd as isize, raw_path.as_str(), false)
            .ok()
            .map(|path| path.as_str().to_string())
    } else {
        None
    };
    let curr = current();
    if curr.task_ext().exec_path().contains("libc-bench")
        && raw_path.contains("/tmp/")
        && !LIBCBENCH_TMP_OPEN_LOGGED.swap(true, Ordering::Relaxed)
    {
        debug!(
            "[libcbench-openat-tmp] task={} dirfd={} path={} flags={:#x}",
            curr.id_name(),
            dirfd,
            raw_path,
            flags
        );
    }
    let Ok(path_cstr) = CString::new(raw_path.as_str()) else {
        return -(LinuxError::EINVAL.code() as isize);
    };
    if write_like {
        match handle_kernel_path(dirfd as isize, raw_path.as_str(), false) {
            Ok(resolved) => {
                if let Ok((resolved_path, _attr)) = resolve_existing_path(resolved.as_str(), true) {
                    if let Err(err) = ensure_open_inode_flags_allow(resolved_path.as_str(), flags) {
                        return -(err.code() as isize);
                    }
                }
                let exec_target = resolve_existing_path(resolved.as_str(), true)
                    .map(|(path, _)| path)
                    .unwrap_or_else(|_| resolved.as_str().to_string());
                if crate::task::is_exec_path_in_use(exec_target.as_str()) {
                    return -(LinuxError::ETXTBSY.code() as isize);
                }
            }
            Err(_) => {}
        }
    }
    let special_resolved = if raw_path == "/proc" || raw_path.starts_with("/proc/") {
        Some(raw_path.clone())
    } else if raw_path.starts_with("proc/")
        || raw_path == "timens_offsets"
        || raw_path == "time_for_children"
    {
        handle_kernel_path(dirfd as isize, raw_path.as_str(), false)
            .ok()
            .map(|path| path.as_str().to_string())
    } else {
        None
    };
    if let Some(resolved) = special_resolved {
        crate::task::sync_proc_pid_entries_for_path(resolved.as_str());
        if let Some(fd) = open_special_proc_file(resolved.as_str(), flags) {
            return fd;
        }
    }
    let ret = api::sys_openat(dirfd, path_cstr.as_ptr(), flags, modes) as isize;
    if write_like && ret >= 0 {
        if let Some(path) = resolved_for_trace.as_deref() {
            crate::mm::invalidate_exec_cache_path(path);
        }
        notify_lease_break_for_fd(ret as c_int, true, false);
    } else if ret >= 0 {
        notify_lease_break_for_fd(ret as c_int, false, false);
    }
    if ret != -(LinuxError::ENOENT.code() as isize) {
        return ret;
    }
    if raw_path.starts_with('/') {
        if let Some(alias) =
            runtime_scoped_absolute_path(curr.task_ext().exec_path().as_str(), raw_path.as_str())
        {
            if let Ok(alias_cstr) = CString::new(alias.as_str()) {
                let alias_ret =
                    api::sys_openat(api::AT_FDCWD as i32, alias_cstr.as_ptr(), flags, modes)
                        as isize;
                if write_like && alias_ret >= 0 {
                    crate::mm::invalidate_exec_cache_path(alias.as_str());
                    notify_lease_break_for_fd(alias_ret as c_int, true, false);
                } else if alias_ret >= 0 {
                    notify_lease_break_for_fd(alias_ret as c_int, false, false);
                }
                if alias_ret != -(LinuxError::ENOENT.code() as isize) {
                    return alias_ret;
                }
            }
        }
    }
    if raw_path.starts_with('/') || dirfd == api::AT_FDCWD as i32 {
        return ret;
    }
    let resolved = if let Ok(dir) = api::Directory::from_fd(dirfd) {
        join_dir_entry_path(dir.path(), raw_path.as_str())
    } else {
        let Ok(resolved) = handle_kernel_path(dirfd as isize, raw_path.as_str(), false) else {
            return ret;
        };
        resolved.as_str().to_string()
    };
    if !is_cgroup_v2_path(resolved.as_str()) {
        return ret;
    }
    let _ = ensure_cgroup_open_target(resolved.as_str(), flags);
    let Ok(path_cstr) = CString::new(resolved.as_str()) else {
        return ret;
    };
    let cgroup_ret =
        api::sys_openat(api::AT_FDCWD as i32, path_cstr.as_ptr(), flags, modes) as isize;
    if cgroup_ret >= 0 {
        notify_lease_break_for_fd(cgroup_ret as c_int, write_like, false);
    }
    cgroup_ret
}

pub(crate) fn sys_lseek(fd: i32, offset: api::ctypes::off_t, whence: i32) -> isize {
    api::sys_lseek(fd, offset, whence) as isize
}

pub(crate) fn sys_fadvise64(fd: i32, _offset: i64, _len: i64, advice: i32) -> isize {
    syscall_body!(sys_fadvise64, {
        let file = get_file_like(fd)?;
        if file.status_flags() & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        if file.clone().into_any().downcast::<api::Directory>().is_ok() {
            return Err(LinuxError::EINVAL);
        }
        let access = (file.status_flags() as u32) & api::ctypes::O_ACCMODE;
        if access == api::ctypes::O_WRONLY {
            return Err(LinuxError::EBADF);
        }

        if !matches!(
            advice,
            POSIX_FADV_NORMAL
                | POSIX_FADV_RANDOM
                | POSIX_FADV_SEQUENTIAL
                | POSIX_FADV_WILLNEED
                | POSIX_FADV_DONTNEED
                | POSIX_FADV_NOREUSE
        ) {
            return Err(LinuxError::EINVAL);
        }

        let stat = file.stat()?;
        match stat.st_mode & S_IFMT {
            S_IFDIR => return Err(LinuxError::EINVAL),
            S_IFIFO => return Err(LinuxError::ESPIPE),
            S_IFSOCK => return Err(LinuxError::EINVAL),
            _ => {}
        }

        let current = api::sys_lseek(fd, 0, SEEK_CUR);
        if current < 0 {
            return Err(LinuxError::try_from((-current) as i32).unwrap_or(LinuxError::EINVAL));
        }

        Ok(0)
    })
}

pub(crate) fn sys_readahead(fd: i32, offset: i64, count: usize) -> isize {
    syscall_body!(sys_readahead, {
        let file = get_file_like(fd)?;
        if file.status_flags() & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        if file.clone().into_any().downcast::<api::Directory>().is_ok() {
            return Err(LinuxError::EINVAL);
        }
        let access = (file.status_flags() as u32) & api::ctypes::O_ACCMODE;
        if access == api::ctypes::O_WRONLY {
            return Err(LinuxError::EBADF);
        }
        if offset < 0 {
            return Err(LinuxError::EINVAL);
        }

        let stat = file.stat()?;
        match stat.st_mode & S_IFMT {
            S_IFDIR => return Err(LinuxError::EINVAL),
            S_IFIFO => return Err(LinuxError::ESPIPE),
            S_IFSOCK => return Err(LinuxError::EINVAL),
            _ => {}
        }

        let current = api::sys_lseek(fd, 0, SEEK_CUR);
        if current < 0 {
            return Err(LinuxError::try_from((-current) as i32).unwrap_or(LinuxError::EINVAL));
        }

        if count != 0 {
            let mut byte = [0u8; 1];
            let _ = file.read_at(offset as u64, &mut byte);
        }

        Ok(0)
    })
}

pub(crate) fn sys_sendfile(
    out_fd: i32,
    in_fd: i32,
    offset: *mut api::ctypes::off_t,
    count: usize,
) -> isize {
    syscall_body!(sys_sendfile, {
        const SEEK_SET: i32 = 0;
        const SEEK_CUR: i32 = 1;
        let mut saved_offset = 0;
        let mut working_offset = 0;
        let use_explicit_offset = !offset.is_null();
        if use_explicit_offset {
            saved_offset = api::sys_lseek(in_fd, 0, SEEK_CUR);
            if saved_offset < 0 {
                return Err(
                    LinuxError::try_from((-saved_offset) as i32).unwrap_or(LinuxError::EINVAL)
                );
            }
            working_offset = read_value_from_user(offset)?;
            let seek_ret = api::sys_lseek(in_fd, working_offset, SEEK_SET);
            if seek_ret < 0 {
                return Err(LinuxError::try_from((-seek_ret) as i32).unwrap_or(LinuxError::EINVAL));
            }
        }

        let mut buf = [0u8; 4096];
        let mut copied = 0usize;
        let mut remaining = count;
        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            let read_ret = api::sys_read(in_fd, buf.as_mut_ptr() as *mut _, chunk);
            if read_ret < 0 {
                if use_explicit_offset {
                    let _ = api::sys_lseek(in_fd, saved_offset, SEEK_SET);
                }
                return Err(LinuxError::try_from((-read_ret) as i32).unwrap_or(LinuxError::EIO));
            }
            if read_ret == 0 {
                break;
            }
            let write_ret = api::sys_write(out_fd, buf.as_ptr() as *const _, read_ret as usize);
            if write_ret < 0 {
                if use_explicit_offset {
                    let _ = api::sys_lseek(in_fd, saved_offset, SEEK_SET);
                }
                return Err(LinuxError::try_from((-write_ret) as i32).unwrap_or(LinuxError::EIO));
            }
            let written = write_ret as usize;
            copied += written;
            remaining -= written;
            if written < read_ret as usize {
                break;
            }
        }

        if use_explicit_offset {
            let new_offset = working_offset + copied as api::ctypes::off_t;
            write_value_to_user(offset, new_offset)?;
            let _ = api::sys_lseek(in_fd, saved_offset, SEEK_SET);
        }
        Ok(copied)
    })
}

pub(crate) fn sys_splice(
    fd_in: i32,
    off_in: *mut api::ctypes::off_t,
    fd_out: i32,
    off_out: *mut api::ctypes::off_t,
    len: usize,
    flags: u32,
) -> isize {
    syscall_body!(sys_splice, {
        let supported_flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
        if flags & !supported_flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        if len == 0 {
            return Ok(0);
        }

        let input = get_file_like(fd_in)?;
        let output = get_file_like(fd_out)?;
        if input.status_flags() & (O_PATH as usize) != 0
            || output.status_flags() & (O_PATH as usize) != 0
        {
            return Err(LinuxError::EBADF);
        }
        let input_access = (input.status_flags() as u32) & api::ctypes::O_ACCMODE;
        let output_access = (output.status_flags() as u32) & api::ctypes::O_ACCMODE;
        if input_access == api::ctypes::O_WRONLY || output_access == api::ctypes::O_RDONLY {
            return Err(LinuxError::EBADF);
        }
        if output.status_flags() & (api::ctypes::O_APPEND as usize) != 0 {
            return Err(LinuxError::EINVAL);
        }

        let input_mode = input.stat()?.st_mode & S_IFMT;
        let output_mode = output.stat()?.st_mode & S_IFMT;
        if matches!(input_mode, S_IFDIR) || matches!(output_mode, S_IFDIR) {
            return Err(LinuxError::EINVAL);
        }

        let input_is_pipe = input_mode == S_IFIFO;
        let output_is_pipe = output_mode == S_IFIFO;
        if !input_is_pipe && !output_is_pipe {
            return Err(LinuxError::EINVAL);
        }
        if !input_is_pipe && !splice_nonpipe_supported(input_mode) {
            return Err(LinuxError::EINVAL);
        }
        if !output_is_pipe && !splice_nonpipe_supported(output_mode) {
            return Err(LinuxError::EINVAL);
        }
        if !off_in.is_null() && !splice_seekable(input_mode) {
            return Err(LinuxError::ESPIPE);
        }
        if !off_out.is_null() && !splice_seekable(output_mode) {
            return Err(LinuxError::ESPIPE);
        }

        let mut input_offset = if off_in.is_null() {
            None
        } else {
            Some(read_value_from_user(off_in as *const api::ctypes::off_t)? as u64)
        };
        let mut output_offset = if off_out.is_null() {
            None
        } else {
            Some(read_value_from_user(off_out as *const api::ctypes::off_t)? as u64)
        };

        let mut buf = vec![0u8; len.min(PAGE_SIZE_4K).max(1)];
        let mut copied = 0usize;
        let mut remaining = len;

        while remaining > 0 {
            let chunk = remaining.min(buf.len());
            let read_len = match input_offset {
                Some(offset) => input.read_at(offset, &mut buf[..chunk])?,
                None => input.read(&mut buf[..chunk])?,
            };
            if read_len == 0 {
                break;
            }

            let mut written_total = 0usize;
            while written_total < read_len {
                let written = match output_offset {
                    Some(offset) => output
                        .write_at(offset + written_total as u64, &buf[written_total..read_len])?,
                    None => output.write(&buf[written_total..read_len])?,
                };
                if written == 0 {
                    if copied == 0 {
                        return Err(LinuxError::EIO);
                    }
                    break;
                }
                written_total += written;
            }

            if written_total == 0 {
                break;
            }

            copied += written_total;
            remaining -= written_total;
            if let Some(offset) = input_offset.as_mut() {
                *offset += written_total as u64;
            }
            if let Some(offset) = output_offset.as_mut() {
                *offset += written_total as u64;
            }
            if written_total < read_len {
                break;
            }
        }

        if let Some(offset) = input_offset {
            write_value_to_user(off_in, offset as api::ctypes::off_t)?;
        }
        if let Some(offset) = output_offset {
            write_value_to_user(off_out, offset as api::ctypes::off_t)?;
        }
        Ok(copied)
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

const FD_SETSIZE: usize = 1024;
const BITS_PER_ULONG: usize = core::mem::size_of::<core::ffi::c_ulong>() * 8;
const POLLIN: i16 = 0x001;
const POLLPRI: i16 = 0x002;
const POLLOUT: i16 = 0x004;
const POLLERR: i16 = 0x008;
const POLLNVAL: i16 = 0x020;
fn fd_set_insert(set: &mut api::ctypes::fd_set, fd: usize) {
    set.fds_bits[fd / BITS_PER_ULONG] |= 1 << (fd % BITS_PER_ULONG);
}

fn fd_set_contains(set: &api::ctypes::fd_set, fd: usize) -> bool {
    set.fds_bits[fd / BITS_PER_ULONG] & (1 << (fd % BITS_PER_ULONG)) != 0
}

fn timespec_to_duration(ts: api::ctypes::timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn timeval_from_duration(duration: Duration) -> api::ctypes::timeval {
    api::ctypes::timeval {
        tv_sec: duration.as_secs() as _,
        tv_usec: duration.subsec_micros() as _,
    }
}

pub(crate) fn sys_ppoll(
    fds: *mut PollFd,
    nfds: usize,
    timeout: *const api::ctypes::timespec,
    _sigmask: *const c_void,
    _sigsetsize: usize,
) -> isize {
    syscall_body!(sys_ppoll, {
        if nfds > FD_SETSIZE {
            return Err(LinuxError::EINVAL);
        }
        if nfds > 0 && fds.is_null() {
            return Err(LinuxError::EFAULT);
        }

        let mut pollfds = Vec::with_capacity(nfds);
        for index in 0..nfds {
            pollfds.push(read_value_from_user(unsafe { fds.add(index) })?);
        }

        let mut readfds = unsafe { zeroed::<api::ctypes::fd_set>() };
        let mut writefds = unsafe { zeroed::<api::ctypes::fd_set>() };
        let mut exceptfds = unsafe { zeroed::<api::ctypes::fd_set>() };
        let mut ready = 0usize;
        let mut max_fd = 0usize;

        for pollfd in &mut pollfds {
            pollfd.revents = 0;
            if pollfd.fd < 0 {
                continue;
            }
            let fd = pollfd.fd as usize;
            if fd >= FD_SETSIZE {
                pollfd.revents = POLLNVAL;
                ready += 1;
                continue;
            }
            pollfd.revents |= api::poll_extra_revents(pollfd.fd)?;
            if pollfd.revents & (POLLERR | POLLNVAL) != 0 {
                ready += 1;
                continue;
            }
            if pollfd.events & POLLIN != 0 {
                fd_set_insert(&mut readfds, fd);
            }
            if pollfd.events & POLLOUT != 0 {
                fd_set_insert(&mut writefds, fd);
            }
            if pollfd.events & POLLPRI != 0 {
                fd_set_insert(&mut exceptfds, fd);
            }
            max_fd = max_fd.max(fd + 1);
        }

        if ready == 0 {
            let mut timeout_storage = if timeout.is_null() {
                None
            } else {
                Some(timeval_from_duration(timespec_to_duration(
                    read_value_from_user(timeout)?,
                )?))
            };
            let select_ret = unsafe {
                api::sys_select(
                    max_fd as i32,
                    &mut readfds,
                    &mut writefds,
                    &mut exceptfds,
                    timeout_storage
                        .as_mut()
                        .map(|timeout| timeout as *mut _)
                        .unwrap_or(core::ptr::null_mut()),
                )
            };
            if select_ret < 0 {
                return Err(LinuxError::try_from(-select_ret).unwrap_or(LinuxError::EIO));
            }
        }

        for pollfd in &mut pollfds {
            if pollfd.fd < 0 || pollfd.revents != 0 {
                continue;
            }
            let fd = pollfd.fd as usize;
            if fd_set_contains(&readfds, fd) {
                pollfd.revents |= POLLIN;
            }
            if fd_set_contains(&writefds, fd) {
                pollfd.revents |= POLLOUT;
            }
            if fd_set_contains(&exceptfds, fd) {
                pollfd.revents |= POLLPRI;
            }
            pollfd.revents |= api::poll_extra_revents(pollfd.fd)?;
            if pollfd.revents != 0 {
                ready += 1;
            }
        }

        if nfds > 0 {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    pollfds.as_ptr().cast::<u8>(),
                    pollfds.len() * core::mem::size_of::<PollFd>(),
                )
            };
            copy_to_user(fds.cast::<c_void>(), bytes)?;
        }

        Ok(ready)
    })
}

pub(crate) fn sys_poll(fds: *mut PollFd, nfds: usize, timeout_ms: i32) -> isize {
    syscall_body!(sys_poll, {
        let timeout_storage = api::ctypes::timespec {
            tv_sec: (timeout_ms / 1000) as _,
            tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
        };
        let timeout_ptr = if timeout_ms < 0 {
            core::ptr::null()
        } else {
            &timeout_storage as *const _
        };
        let ret = sys_ppoll(fds, nfds, timeout_ptr, core::ptr::null(), 0);
        if ret < 0 {
            return Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EIO));
        }
        Ok(ret)
    })
}

pub(crate) fn sys_pselect6(
    nfds: i32,
    readfds: *mut api::ctypes::fd_set,
    writefds: *mut api::ctypes::fd_set,
    exceptfds: *mut api::ctypes::fd_set,
    timeout: *const api::ctypes::timespec,
    _sigmask: *const c_void,
) -> isize {
    syscall_body!(sys_pselect6, {
        if nfds < 0 {
            return Err(LinuxError::EINVAL);
        }

        let mut readfds_local = if readfds.is_null() {
            unsafe { zeroed::<api::ctypes::fd_set>() }
        } else {
            read_value_from_user(readfds)?
        };
        let mut writefds_local = if writefds.is_null() {
            unsafe { zeroed::<api::ctypes::fd_set>() }
        } else {
            read_value_from_user(writefds)?
        };
        let mut exceptfds_local = if exceptfds.is_null() {
            unsafe { zeroed::<api::ctypes::fd_set>() }
        } else {
            read_value_from_user(exceptfds)?
        };

        let mut timeout_storage = if timeout.is_null() {
            None
        } else {
            Some(timeval_from_duration(timespec_to_duration(
                read_value_from_user(timeout)?,
            )?))
        };

        let ret = unsafe {
            api::sys_select(
                nfds,
                if readfds.is_null() {
                    core::ptr::null_mut()
                } else {
                    &mut readfds_local
                },
                if writefds.is_null() {
                    core::ptr::null_mut()
                } else {
                    &mut writefds_local
                },
                if exceptfds.is_null() {
                    core::ptr::null_mut()
                } else {
                    &mut exceptfds_local
                },
                timeout_storage
                    .as_mut()
                    .map(|timeout| timeout as *mut _)
                    .unwrap_or(core::ptr::null_mut()),
            )
        };
        if ret < 0 {
            return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EIO));
        }

        if !readfds.is_null() {
            write_value_to_user(readfds, readfds_local)?;
        }
        if !writefds.is_null() {
            write_value_to_user(writefds, writefds_local)?;
        }
        if !exceptfds.is_null() {
            write_value_to_user(exceptfds, exceptfds_local)?;
        }

        Ok(ret)
    })
}

pub(crate) fn sys_epoll_create1(flags: i32) -> isize {
    let cloexec = api::ctypes::EPOLL_CLOEXEC as i32;
    if flags & !cloexec != 0 {
        return -(LinuxError::EINVAL.code() as isize);
    }
    let fd = arceos_posix_api::sys_epoll_create(1);
    if fd < 0 {
        return fd as isize;
    }
    if flags & cloexec != 0 {
        let ret = api::sys_fcntl(
            fd,
            api::ctypes::F_SETFD as _,
            api::ctypes::FD_CLOEXEC as usize,
        );
        if ret < 0 {
            let _ = api::sys_close(fd);
            return ret as isize;
        }
    }
    fd as isize
}

pub(crate) fn sys_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *mut api::ctypes::epoll_event,
) -> isize {
    match op as u32 {
        api::ctypes::EPOLL_CTL_ADD | api::ctypes::EPOLL_CTL_MOD | api::ctypes::EPOLL_CTL_DEL => {}
        _ => return -(LinuxError::EINVAL.code() as isize),
    }
    if epfd < 0 || fd < 0 {
        return -(LinuxError::EBADF.code() as isize);
    }
    if epfd == fd {
        return -(LinuxError::EINVAL.code() as isize);
    }
    let mut event_copy = api::ctypes::epoll_event::default();
    let event_ptr = if op as u32 == api::ctypes::EPOLL_CTL_DEL {
        core::ptr::null_mut()
    } else {
        if event.is_null() {
            return -(LinuxError::EFAULT.code() as isize);
        }
        match read_value_from_user(event) {
            Ok(value) => {
                event_copy = value;
                &mut event_copy as *mut _
            }
            Err(err) => return -(err.code() as isize),
        }
    };
    unsafe { arceos_posix_api::sys_epoll_ctl(epfd, op, fd, event_ptr) as isize }
}

pub(crate) fn sys_epoll_pwait(
    epfd: i32,
    events: *mut api::ctypes::epoll_event,
    maxevents: i32,
    timeout: i32,
    sigmask: *const c_void,
    sigsetsize: usize,
) -> isize {
    if maxevents <= 0 {
        return -(LinuxError::EINVAL.code() as isize);
    }
    if events.is_null() {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let user_len =
        (maxevents as usize).saturating_mul(core::mem::size_of::<api::ctypes::epoll_event>());
    if let Err(err) = ensure_user_range(
        VirtAddr::from(events as usize),
        user_len,
        MappingFlags::WRITE,
    ) {
        return -(err.code() as isize);
    }
    let old_mask = if sigmask.is_null() {
        None
    } else {
        if sigsetsize < core::mem::size_of::<u64>() {
            return -(LinuxError::EINVAL.code() as isize);
        }
        match read_user_sigset_mask(sigmask) {
            Ok(new_mask) => {
                let old_mask = current_blocked_mask();
                set_current_blocked_mask(new_mask);
                Some(old_mask)
            }
            Err(err) => return -(err.code() as isize),
        }
    };
    let mut event_buf = alloc::vec![api::ctypes::epoll_event::default(); maxevents as usize];
    update_current_proc_stat('S');
    let ret = unsafe {
        arceos_posix_api::sys_epoll_wait(epfd, event_buf.as_mut_ptr(), maxevents, timeout) as isize
    };
    update_current_proc_stat('R');
    if let Some(mask) = old_mask {
        set_current_blocked_mask(mask);
    }
    if ret > 0 {
        let count = ret as usize;
        let bytes = unsafe {
            core::slice::from_raw_parts(
                event_buf.as_ptr().cast::<u8>(),
                count.saturating_mul(core::mem::size_of::<api::ctypes::epoll_event>()),
            )
        };
        if let Err(err) = copy_to_user(events.cast::<c_void>(), bytes) {
            return -(err.code() as isize);
        }
    }
    ret
}

pub(crate) fn sys_epoll_pwait2(
    epfd: i32,
    events: *mut api::ctypes::epoll_event,
    maxevents: i32,
    timeout: *const api::ctypes::timespec,
    sigmask: *const c_void,
    sigsetsize: usize,
) -> isize {
    let timeout_ms = if timeout.is_null() {
        -1
    } else {
        match read_value_from_user(timeout) {
            Ok(ts) => {
                if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let millis = (ts.tv_sec as i128)
                    .saturating_mul(1000)
                    .saturating_add((ts.tv_nsec as i128) / 1_000_000);
                millis.clamp(i32::MIN as i128, i32::MAX as i128) as i32
            }
            Err(err) => return -(err.code() as isize),
        }
    };
    sys_epoll_pwait(epfd, events, maxevents, timeout_ms, sigmask, sigsetsize)
}

pub(crate) fn sys_readlinkat(
    dirfd: i32,
    path: *const c_char,
    buf: *mut c_char,
    bufsiz: usize,
) -> isize {
    syscall_body!(sys_readlinkat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if bufsiz == 0 {
            return Ok(0);
        }
        let resolved = handle_user_path(dirfd as isize, path as *const u8, false)?;
        let curr = current();
        let target = match resolved.as_str() {
            "/proc/self/exe" => curr.task_ext().exec_path(),
            _ => {
                let tmp = axfs::api::readlink(resolved.as_str()).map_err(LinuxError::from)?;
                let read_len = tmp.len().min(bufsiz);
                copy_to_user(buf.cast::<c_void>(), &tmp[..read_len])?;
                return Ok(read_len);
            }
        };
        let bytes = target.as_bytes();
        let len = bytes.len().min(bufsiz);
        copy_to_user(buf.cast::<c_void>(), &bytes[..len])?;
        Ok(len)
    })
}

fn faccessat_impl(
    dirfd: i32,
    path: *const c_char,
    mode: i32,
    flags: i32,
) -> Result<isize, LinuxError> {
    let (resolved, attr) = match resolve_faccessat_path(dirfd, path, flags) {
        Ok(result) => result,
        Err(err) => return Err(err),
    };
    if api::virtual_device_stat(resolved.as_str()).is_some() {
        return Ok(0);
    }
    const R_OK: i32 = 4;
    const W_OK: i32 = 2;
    const X_OK: i32 = 1;
    if mode & !(R_OK | W_OK | X_OK) != 0 {
        return Err(LinuxError::EINVAL);
    }
    if mode & W_OK != 0 && axfs::api::is_readonly_path(resolved.as_str())? {
        return Err(LinuxError::EROFS);
    }
    let use_real_ids = flags & AT_EACCESS == 0;
    let cred_uid = if use_real_ids {
        axfs::api::current_uid()
    } else {
        axfs::api::current_euid()
    };
    let perm = attr.perm();
    let root = cred_uid == 0;
    if mode & R_OK != 0
        && !axfs::api::can_access(resolved.as_str(), attr, use_real_ids, true, false, false)
    {
        return Err(LinuxError::EACCES);
    }
    if mode & W_OK != 0
        && !axfs::api::can_access(resolved.as_str(), attr, use_real_ids, false, true, false)
    {
        return Err(LinuxError::EACCES);
    }
    if mode & X_OK != 0 {
        let any_exec = perm.owner_executable()
            || perm.contains(axfs::fops::FilePerm::GROUP_EXEC)
            || perm.contains(axfs::fops::FilePerm::OTHER_EXEC);
        if (!axfs::api::can_access(resolved.as_str(), attr, use_real_ids, false, false, true))
            || (root && !attr.is_dir() && !any_exec)
        {
            return Err(LinuxError::EACCES);
        }
    }
    Ok(0)
}

pub(crate) fn sys_faccessat(dirfd: i32, path: *const c_char, mode: i32, _flags: i32) -> isize {
    syscall_body!(sys_faccessat, { faccessat_impl(dirfd, path, mode, 0) })
}

pub(crate) fn sys_faccessat2(dirfd: i32, path: *const c_char, mode: i32, flags: i32) -> isize {
    syscall_body!(sys_faccessat2, { faccessat_impl(dirfd, path, mode, flags) })
}
