use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_int;

use axerrno::{LinuxError, LinuxResult};
use axio::{PollState, SeekFrom};
use axns::{ResArc, def_resource};
use flatten_objects::FlattenObjects;
use spin::{Mutex, RwLock};

#[cfg(feature = "pipe")]
use super::pipe::{Pipe, pipe_max_size};
use crate::ctypes;
use crate::imp::stdio::{stdin, stdout};

fn current_fd_limit() -> usize {
    super::resources::current_nofile_limit().max(3)
}

pub const AX_FILE_LIMIT: usize = 1024;
pub(crate) const FD_CLOEXEC_FLAG: usize = 1;
const F_SETPIPE_SZ: u32 = 1031;
const F_GETPIPE_SZ: u32 = 1032;
const F_SETLEASE: u32 = 1024;
const F_GETLEASE: u32 = 1025;
const F_SETOWN_EX: u32 = 15;
const F_GETOWN_EX: u32 = 16;

#[repr(C)]
#[derive(Clone, Copy)]
struct UserFlock {
    l_type: i16,
    l_whence: i16,
    l_start: i64,
    l_len: i64,
    l_pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserFOwnerEx {
    type_: i32,
    pid: i32,
}

#[derive(Clone, Copy)]
struct FileLock {
    key: u64,
    owner: u64,
    typ: i16,
    start: i64,
    len: i64,
}

#[derive(Clone, Copy)]
struct FileLease {
    key: u64,
    owner: u64,
    typ: i32,
}

#[derive(Clone, Copy, Default)]
struct FdControl {
    fd: c_int,
    owner: i32,
    owner_ex: UserFOwnerEx,
    signal: i32,
}

static FILE_LOCKS: Mutex<Vec<FileLock>> = Mutex::new(Vec::new());
static FILE_LEASES: Mutex<Vec<FileLease>> = Mutex::new(Vec::new());
static FD_CONTROLS: Mutex<Vec<FdControl>> = Mutex::new(Vec::new());

#[allow(dead_code)]
pub trait FileLike: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize>;
    fn write(&self, buf: &[u8]) -> LinuxResult<usize>;
    fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::ESPIPE)
    }
    fn write_at(&self, _offset: u64, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::ESPIPE)
    }
    fn stat(&self) -> LinuxResult<ctypes::stat>;
    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync>;
    fn poll(&self) -> LinuxResult<PollState>;
    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult;
    fn seek(&self, _pos: SeekFrom) -> LinuxResult<u64> {
        Err(LinuxError::ESPIPE)
    }
    fn truncate(&self, _length: u64) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }
    fn sync_all(&self) -> LinuxResult {
        Ok(())
    }
    fn set_append(&self, _append: bool) -> LinuxResult {
        Ok(())
    }
    fn status_flags(&self) -> usize {
        0
    }
    fn lock_key(&self) -> Option<(u64, u64)> {
        None
    }
    fn fcntl_identity(&self) -> usize {
        core::ptr::from_ref(self).cast::<()>() as usize
    }
}

def_resource! {
    pub static FD_TABLE: ResArc<RwLock<FlattenObjects<Arc<dyn FileLike>, AX_FILE_LIMIT>>> = ResArc::new();
    pub static FD_FLAGS: ResArc<RwLock<FlattenObjects<usize, AX_FILE_LIMIT>>> = ResArc::new();
}

fn current_lock_owner() -> u64 {
    axtask::current().id().as_u64()
}

fn validate_user_ptr<T>(addr: usize) -> LinuxResult<*mut T> {
    if addr < core::mem::size_of::<T>() || addr == usize::MAX {
        return Err(LinuxError::EFAULT);
    }
    Ok(addr as *mut T)
}

fn read_user_value<T: Copy>(addr: usize) -> LinuxResult<T> {
    let ptr = validate_user_ptr::<T>(addr)?;
    Ok(unsafe { core::ptr::read(ptr) })
}

fn write_user_value<T: Copy>(addr: usize, value: T) -> LinuxResult<()> {
    let ptr = validate_user_ptr::<T>(addr)?;
    unsafe { core::ptr::write(ptr, value) };
    Ok(())
}

fn fd_file_key(fd: c_int) -> LinuxResult<u64> {
    Ok(get_file_like(fd)?.stat()?.st_ino as u64)
}

fn lock_end(start: i64, len: i64) -> i64 {
    if len == 0 {
        i64::MAX
    } else if len > 0 {
        start.saturating_add(len)
    } else {
        start
    }
}

fn lock_start(start: i64, len: i64) -> i64 {
    if len < 0 {
        start.saturating_add(len)
    } else {
        start
    }
}

fn locks_overlap(left: FileLock, right: FileLock) -> bool {
    lock_start(left.start, left.len) < lock_end(right.start, right.len)
        && lock_start(right.start, right.len) < lock_end(left.start, left.len)
}

fn locks_conflict(left: FileLock, right: FileLock) -> bool {
    left.key == right.key
        && left.owner != right.owner
        && locks_overlap(left, right)
        && (left.typ == ctypes::F_WRLCK as i16 || right.typ == ctypes::F_WRLCK as i16)
}

fn validate_flock(lock: UserFlock) -> LinuxResult<()> {
    if !matches!(
        lock.l_type as u32,
        ctypes::F_RDLCK | ctypes::F_WRLCK | ctypes::F_UNLCK
    ) {
        return Err(LinuxError::EINVAL);
    }
    if !matches!(lock.l_whence as i32, 0..=2) {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn fcntl_getlk(fd: c_int, arg: usize) -> LinuxResult<c_int> {
    let key = fd_file_key(fd)?;
    let mut lock = read_user_value::<UserFlock>(arg)?;
    validate_flock(lock)?;
    let query = FileLock {
        key,
        owner: current_lock_owner(),
        typ: lock.l_type,
        start: lock.l_start,
        len: lock.l_len,
    };
    if let Some(conflict) = FILE_LOCKS
        .lock()
        .iter()
        .copied()
        .find(|existing| locks_conflict(*existing, query))
    {
        lock.l_type = conflict.typ;
        lock.l_whence = 0;
        lock.l_start = conflict.start;
        lock.l_len = conflict.len;
        lock.l_pid = conflict.owner as i32;
    } else {
        lock.l_type = ctypes::F_UNLCK as i16;
    }
    write_user_value(arg, lock)?;
    Ok(0)
}

fn fcntl_setlk(fd: c_int, arg: usize, wait: bool) -> LinuxResult<c_int> {
    let key = fd_file_key(fd)?;
    let lock = read_user_value::<UserFlock>(arg)?;
    validate_flock(lock)?;
    let owner = current_lock_owner();
    let requested = FileLock {
        key,
        owner,
        typ: lock.l_type,
        start: lock.l_start,
        len: lock.l_len,
    };
    loop {
        let mut locks = FILE_LOCKS.lock();
        if requested.typ == ctypes::F_UNLCK as i16 {
            locks.retain(|existing| !(existing.key == key && existing.owner == owner));
            return Ok(0);
        }
        if locks
            .iter()
            .copied()
            .any(|existing| locks_conflict(existing, requested))
        {
            drop(locks);
            if !wait {
                return Err(LinuxError::EAGAIN);
            }
            axtask::sleep(core::time::Duration::from_millis(10));
            continue;
        }
        locks.retain(|existing| !(existing.key == key && existing.owner == owner));
        locks.push(requested);
        return Ok(0);
    }
}

fn remove_locks_for_fd(fd: c_int) {
    if let Ok(key) = fd_file_key(fd) {
        let owner = current_lock_owner();
        FILE_LOCKS
            .lock()
            .retain(|existing| !(existing.key == key && existing.owner == owner));
    }
}

fn fd_open_count_for_key(key: u64) -> usize {
    FD_TABLE
        .read()
        .iter()
        .filter(|(_, file)| file.stat().is_ok_and(|stat| stat.st_ino as u64 == key))
        .count()
}

fn fcntl_setlease(fd: c_int, arg: usize) -> LinuxResult<c_int> {
    let key = fd_file_key(fd)?;
    let owner = current_lock_owner();
    let typ = arg as i32;
    match typ as u32 {
        ctypes::F_UNLCK => {
            FILE_LEASES
                .lock()
                .retain(|lease| !(lease.key == key && lease.owner == owner));
            Ok(0)
        }
        ctypes::F_WRLCK => {
            if fd_open_count_for_key(key) > 1 {
                return Err(LinuxError::EAGAIN);
            }
            let mut leases = FILE_LEASES.lock();
            leases.retain(|lease| !(lease.key == key && lease.owner == owner));
            leases.push(FileLease { key, owner, typ });
            Ok(0)
        }
        ctypes::F_RDLCK => Err(LinuxError::EAGAIN),
        _ => Err(LinuxError::EINVAL),
    }
}

fn fcntl_getlease(fd: c_int) -> LinuxResult<c_int> {
    let key = fd_file_key(fd)?;
    let owner = current_lock_owner();
    Ok(FILE_LEASES
        .lock()
        .iter()
        .find(|lease| lease.key == key && lease.owner == owner)
        .map(|lease| lease.typ)
        .unwrap_or(ctypes::F_UNLCK as i32))
}

fn fd_control_mut(fd: c_int) -> FdControl {
    let controls = FD_CONTROLS.lock();
    controls
        .iter()
        .copied()
        .find(|control| control.fd == fd)
        .unwrap_or(FdControl {
            fd,
            owner_ex: UserFOwnerEx { type_: 1, pid: 0 },
            ..Default::default()
        })
}

fn store_fd_control(control: FdControl) {
    let mut controls = FD_CONTROLS.lock();
    if let Some(slot) = controls.iter_mut().find(|slot| slot.fd == control.fd) {
        *slot = control;
    } else {
        controls.push(control);
    }
}

impl FD_TABLE {
    /// Return a copy of the inner table.
    pub fn copy_inner(&self) -> RwLock<FlattenObjects<Arc<dyn FileLike>, AX_FILE_LIMIT>> {
        let table = self.read();
        let mut new_table = FlattenObjects::new();
        for (i, file) in table.iter() {
            let _ = new_table.add_at(i, file.clone());
        }
        RwLock::new(new_table)
    }
}

impl FD_FLAGS {
    /// Return a copy of the inner flags table.
    pub fn copy_inner(&self) -> RwLock<FlattenObjects<usize, AX_FILE_LIMIT>> {
        let table = self.read();
        let mut new_table = FlattenObjects::new();
        for (i, flags) in table.iter() {
            let _ = new_table.add_at(i, *flags);
        }
        RwLock::new(new_table)
    }
}

/// Get a file by `fd`.
pub fn get_file_like(fd: c_int) -> LinuxResult<Arc<dyn FileLike>> {
    FD_TABLE
        .read()
        .get(fd as usize)
        .cloned()
        .ok_or(LinuxError::EBADF)
}

/// Add a file to the file descriptor table.
pub fn add_file_like(f: Arc<dyn FileLike>) -> LinuxResult<c_int> {
    add_file_like_with_flags(f, 0)
}

fn add_file_like_with_flags(f: Arc<dyn FileLike>, flags: usize) -> LinuxResult<c_int> {
    let fd_limit = current_fd_limit().min(AX_FILE_LIMIT);
    let fd = {
        let mut table = FD_TABLE.write();
        let mut chosen = None;
        for fd in 0..fd_limit {
            if table.get(fd).is_none() {
                table
                    .add_at(fd, f.clone())
                    .map_err(|_| LinuxError::EMFILE)?;
                chosen = Some(fd);
                break;
            }
        }
        chosen.ok_or(LinuxError::EMFILE)?
    };
    if FD_FLAGS
        .write()
        .add_at(fd, flags & FD_CLOEXEC_FLAG)
        .is_err()
    {
        let _ = FD_TABLE.write().remove(fd);
        return Err(LinuxError::EMFILE);
    }
    Ok(fd as c_int)
}

fn add_file_like_from_with_flags(
    f: Arc<dyn FileLike>,
    min_fd: usize,
    flags: usize,
) -> LinuxResult<c_int> {
    let fd_limit = current_fd_limit().min(AX_FILE_LIMIT);
    if min_fd >= AX_FILE_LIMIT {
        return Err(LinuxError::EINVAL);
    }
    if min_fd >= fd_limit {
        return Err(LinuxError::EMFILE);
    }

    let fd = {
        let mut table = FD_TABLE.write();
        let mut chosen = None;
        for fd in min_fd..fd_limit {
            if table.get(fd).is_none() {
                table
                    .add_at(fd, f.clone())
                    .map_err(|_| LinuxError::EMFILE)?;
                chosen = Some(fd);
                break;
            }
        }
        chosen.ok_or(LinuxError::EMFILE)?
    };

    if FD_FLAGS
        .write()
        .add_at(fd, flags & FD_CLOEXEC_FLAG)
        .is_err()
    {
        let _ = FD_TABLE.write().remove(fd);
        return Err(LinuxError::EMFILE);
    }
    Ok(fd as c_int)
}

pub(crate) fn add_file_like_with_fd_flags(
    f: Arc<dyn FileLike>,
    flags: usize,
) -> LinuxResult<c_int> {
    add_file_like_with_flags(f, flags)
}

/// Close a file by `fd`.
pub fn close_file_like(fd: c_int) -> LinuxResult {
    remove_locks_for_fd(fd);
    let _f = FD_TABLE
        .write()
        .remove(fd as usize)
        .ok_or(LinuxError::EBADF)?;
    let _ = FD_FLAGS.write().remove(fd as usize);
    FD_CONTROLS.lock().retain(|control| control.fd != fd);
    Ok(())
}

/// Close a file by `fd`.
pub fn sys_close(fd: c_int) -> c_int {
    debug!("sys_close <= {}", fd);
    syscall_body!(sys_close, close_file_like(fd).map(|_| 0))
}

fn dup_fd(old_fd: c_int) -> LinuxResult<c_int> {
    dup_fd_with_flags(old_fd, 0, 0)
}

fn dup_fd_with_flags(old_fd: c_int, min_fd: usize, flags: usize) -> LinuxResult<c_int> {
    let f = get_file_like(old_fd)?;
    let new_fd = add_file_like_from_with_flags(f, min_fd, flags)?;
    Ok(new_fd)
}

/// Duplicate a file descriptor.
pub fn sys_dup(old_fd: c_int) -> c_int {
    debug!("sys_dup <= {}", old_fd);
    syscall_body!(sys_dup, dup_fd(old_fd))
}

/// Duplicate a file descriptor, but it uses the file descriptor number specified in `new_fd`.
///
/// TODO: `dup2` should forcibly close new_fd if it is already opened.
pub fn sys_dup2(old_fd: c_int, new_fd: c_int) -> c_int {
    debug!("sys_dup2 <= old_fd: {}, new_fd: {}", old_fd, new_fd);
    syscall_body!(sys_dup2, {
        if old_fd == new_fd {
            let r = sys_fcntl(old_fd, ctypes::F_GETFD as _, 0);
            if r >= 0 {
                return Ok(old_fd);
            } else {
                return Ok(r);
            }
        }
        let fd_limit = current_fd_limit().min(AX_FILE_LIMIT);
        if new_fd as usize >= AX_FILE_LIMIT || new_fd as usize >= fd_limit {
            return Err(LinuxError::EBADF);
        }

        let f = get_file_like(old_fd)?;
        let mut table = FD_TABLE.write();
        if table.get(new_fd as usize).is_some() {
            let _ = table.remove(new_fd as usize);
        }
        drop(table);
        let mut flags_table = FD_FLAGS.write();
        if flags_table.get(new_fd as usize).is_some() {
            let _ = flags_table.remove(new_fd as usize);
        }
        drop(flags_table);
        let mut table = FD_TABLE.write();
        table
            .add_at(new_fd as usize, f.clone())
            .map_err(|_| LinuxError::EMFILE)?;
        FD_FLAGS
            .write()
            .add_at(new_fd as usize, 0)
            .map_err(|_| LinuxError::EMFILE)?;

        Ok(new_fd)
    })
}

/// Manipulate file descriptor.
///
/// TODO: `SET/GET` command is ignored, hard-code stdin/stdout
pub fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    debug!("sys_fcntl <= fd: {} cmd: {} arg: {}", fd, cmd, arg);
    syscall_body!(sys_fcntl, {
        match cmd as u32 {
            ctypes::F_GETFD => {
                if FD_TABLE.read().get(fd as usize).is_none() {
                    return Err(LinuxError::EBADF);
                }
                Ok(FD_FLAGS.read().get(fd as usize).copied().unwrap_or(0) as c_int)
            }
            ctypes::F_SETFD => {
                if FD_TABLE.read().get(fd as usize).is_none() {
                    return Err(LinuxError::EBADF);
                }
                let mut flags = FD_FLAGS.write();
                if flags.get(fd as usize).is_some() {
                    let _ = flags.remove(fd as usize);
                }
                flags
                    .add_at(fd as usize, arg & FD_CLOEXEC_FLAG)
                    .map_err(|_| LinuxError::EMFILE)?;
                Ok(0)
            }
            ctypes::F_GETFL => Ok(get_file_like(fd)?.status_flags() as c_int),
            ctypes::F_DUPFD => dup_fd_with_flags(fd, arg, 0),
            ctypes::F_DUPFD_CLOEXEC => dup_fd_with_flags(fd, arg, FD_CLOEXEC_FLAG),
            ctypes::F_GETLK => fcntl_getlk(fd, arg),
            ctypes::F_SETLK => fcntl_setlk(fd, arg, false),
            ctypes::F_SETLKW => fcntl_setlk(fd, arg, true),
            ctypes::F_SETFL => {
                if fd == 0 || fd == 1 || fd == 2 {
                    return Ok(0);
                }
                let file = get_file_like(fd)?;
                file.set_nonblocking(arg & (ctypes::O_NONBLOCK as usize) > 0)?;
                file.set_append(arg & (ctypes::O_APPEND as usize) > 0)?;
                Ok(0)
            }
            F_SETPIPE_SZ => {
                #[cfg(feature = "pipe")]
                if let Ok(pipe) = get_file_like(fd)?.clone().into_any().downcast::<Pipe>() {
                    let requested = arg;
                    if requested > i32::MAX as usize {
                        return Err(LinuxError::EINVAL);
                    }
                    if requested > pipe_max_size() {
                        return Err(LinuxError::EPERM);
                    }
                    return pipe.resize_capacity(requested).map(|size| size as c_int);
                }
                Err(LinuxError::EINVAL)
            }
            F_GETPIPE_SZ => {
                #[cfg(feature = "pipe")]
                if let Ok(pipe) = get_file_like(fd)?.clone().into_any().downcast::<Pipe>() {
                    return Ok(pipe.capacity() as c_int);
                }
                Err(LinuxError::EINVAL)
            }
            F_SETLEASE => fcntl_setlease(fd, arg),
            F_GETLEASE => fcntl_getlease(fd),
            ctypes::F_SETOWN => {
                get_file_like(fd)?;
                let mut control = fd_control_mut(fd);
                control.owner = arg as i32;
                control.owner_ex = UserFOwnerEx {
                    type_: 1,
                    pid: arg as i32,
                };
                store_fd_control(control);
                Ok(0)
            }
            ctypes::F_GETOWN => {
                get_file_like(fd)?;
                Ok(fd_control_mut(fd).owner)
            }
            ctypes::F_SETSIG => {
                get_file_like(fd)?;
                let mut control = fd_control_mut(fd);
                control.signal = arg as i32;
                store_fd_control(control);
                Ok(0)
            }
            ctypes::F_GETSIG => {
                get_file_like(fd)?;
                Ok(fd_control_mut(fd).signal)
            }
            F_SETOWN_EX => {
                get_file_like(fd)?;
                let owner_ex = read_user_value::<UserFOwnerEx>(arg)?;
                let mut control = fd_control_mut(fd);
                control.owner = owner_ex.pid;
                control.owner_ex = owner_ex;
                store_fd_control(control);
                Ok(0)
            }
            F_GETOWN_EX => {
                get_file_like(fd)?;
                write_user_value(arg, fd_control_mut(fd).owner_ex)?;
                Ok(0)
            }
            _ => {
                warn!("unsupported fcntl parameters: cmd {}", cmd);
                Err(LinuxError::EINVAL)
            }
        }
    })
}

pub fn close_on_exec_fds() {
    let cloexec_fds = {
        let flags = FD_FLAGS.read();
        flags
            .iter()
            .filter_map(|(fd, bits)| (bits & FD_CLOEXEC_FLAG != 0).then_some(fd as c_int))
            .collect::<Vec<_>>()
    };
    for fd in cloexec_fds {
        let _ = close_file_like(fd);
    }
}

pub fn close_all_fds() {
    let all_fds = {
        let table = FD_TABLE.read();
        table.iter().map(|(fd, _)| fd as c_int).collect::<Vec<_>>()
    };
    for fd in all_fds {
        let _ = close_file_like(fd);
    }
}

pub fn close_all_fds_fast() {
    {
        let mut table = FD_TABLE.write();
        *table = FlattenObjects::new();
    }
    {
        let mut flags = FD_FLAGS.write();
        *flags = FlattenObjects::new();
    }
    FD_CONTROLS.lock().clear();
}

#[ctor_bare::register_ctor]
fn init_stdio() {
    let mut fd_table = flatten_objects::FlattenObjects::new();
    let mut fd_flags = flatten_objects::FlattenObjects::new();
    fd_table
        .add_at(0, Arc::new(stdin()) as _)
        .unwrap_or_else(|_| panic!()); // stdin
    fd_flags.add_at(0, 0).unwrap_or_else(|_| panic!());
    fd_table
        .add_at(1, Arc::new(stdout()) as _)
        .unwrap_or_else(|_| panic!()); // stdout
    fd_flags.add_at(1, 0).unwrap_or_else(|_| panic!());
    fd_table
        .add_at(2, Arc::new(stdout()) as _)
        .unwrap_or_else(|_| panic!()); // stderr
    fd_flags.add_at(2, 0).unwrap_or_else(|_| panic!());
    FD_TABLE.init_new(spin::RwLock::new(fd_table));
    FD_FLAGS.init_new(spin::RwLock::new(fd_flags));
}
