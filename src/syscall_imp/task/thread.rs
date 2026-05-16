use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    ffi::{c_char, c_int, c_void},
    sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

use arceos_posix_api::{
    self as api, add_file_like, get_file_like, Directory, FileLike, PollState, FD_TABLE,
};
use axerrno::LinuxError;
use axfs::{CURRENT_DIR_PATH, CURRENT_FS_CRED};
use axhal::arch::TrapFrame;
use axhal::paging::MappingFlags;
#[cfg(target_arch = "loongarch64")]
use axhal::time::monotonic_time_nanos;
#[cfg(target_arch = "riscv64")]
use axhal::time::monotonic_time_nanos;
use axtask::{current, AxTaskRef, TaskExtRef};
use memory_addr::VirtAddr;
use num_enum::TryFromPrimitive;
use spin::Mutex;

#[cfg(feature = "contest_diag_logs")]
use axhal::time::monotonic_time_nanos;

use crate::{
    ctypes::{CloneFlags, WaitFlags, WaitStatus},
    signal::{
        send_signal_to_task_with_siginfo, send_tkill_signal_to_task, send_user_signal_to_task,
        UserSigInfo,
    },
    syscall_body,
    task::{
        find_live_task_by_tid, find_process_leader_by_pid, find_zombie_process_by_pid,
        process_leader_tasks, unregister_zombie_process, wait_child,
        wait_child_selector_from_waitpid, wait_child_status, wait_selector_matches_live,
        wait_status_continued, wait_status_stopped, WaitChildSelector, ZombieProcess,
    },
    timekeeping::setns_time_namespace_from_fd,
    usercopy::{copy_from_user, ensure_user_range, read_value_from_user, write_value_to_user},
};

const CAP_VERSION_1: u32 = 0x1998_0330;
const CAP_VERSION_2: u32 = 0x2007_1026;
const CAP_VERSION_3: u32 = 0x2008_0522;
const CAP_SETPCAP: u32 = 8;
const PR_CAPBSET_READ: i32 = 23;
const PR_CAPBSET_DROP: i32 = 24;
const PR_GET_TIMERSLACK: i32 = 30;
const DEFAULT_TIMERSLACK_NS: isize = 50_000;
const CLONE_INTO_CGROUP_FLAG: u64 = 1 << 33;
const P_ALL: i32 = 0;
const P_PID: i32 = 1;
const P_PGID: i32 = 2;
const P_PIDFD: i32 = 3;
const KCMP_FILE: i32 = 0;
const KCMP_VM: i32 = 1;
const KCMP_FILES: i32 = 2;
const KCMP_FS: i32 = 3;
const KCMP_SIGHAND: i32 = 4;
const KCMP_IO: i32 = 5;
const KCMP_SYSVSEM: i32 = 6;
const WSTOPPED: u32 = 0x0000_0002;
const WEXITED: u32 = 0x0000_0004;
const WNOWAIT: u32 = 0x0100_0000;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const CLD_DUMPED: i32 = 3;
const CLD_STOPPED: i32 = 5;
const CLD_CONTINUED: i32 = 6;
const SIGCONT_STATUS: i32 = 18;
const AT_EMPTY_PATH: i32 = 0x1000;
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

fn should_report_epoll_ltp_progress(exec_path: &str) -> bool {
    let _ = exec_path;
    false
}

fn should_trace_fork13() -> bool {
    false
}

struct PidFd {
    pid: usize,
    nonblocking: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct WaitSigInfoSigChld {
    si_pid: i32,
    si_uid: u32,
    si_status: i32,
    si_utime: isize,
    si_stime: isize,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct WaitSigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    _pad0: i32,
    sigchld: WaitSigInfoSigChld,
    _pad1: [u8; 80],
}

impl PidFd {
    fn new(pid: usize, nonblocking: bool) -> Self {
        Self { pid, nonblocking }
    }
}

impl FileLike for PidFd {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EINVAL)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> Result<arceos_posix_api::ctypes::stat, LinuxError> {
        Ok(arceos_posix_api::ctypes::stat {
            st_ino: self.pid as u64,
            st_nlink: 1,
            st_mode: 0o600,
            st_uid: axfs::api::current_uid(),
            st_gid: axfs::api::current_gid(),
            st_blksize: 4096,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: find_process_leader_by_pid(self.pid).is_none(),
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }

    fn status_flags(&self) -> usize {
        let mut flags = arceos_posix_api::ctypes::O_RDONLY as usize;
        if self.nonblocking {
            flags |= arceos_posix_api::ctypes::O_NONBLOCK as usize;
        }
        flags
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserCapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Clone, Copy)]
struct ProcessSecurityState {
    caps: [UserCapData; 2],
    bounding: u64,
}

static CAPABILITY_STATE: Mutex<BTreeMap<u32, ProcessSecurityState>> = Mutex::new(BTreeMap::new());

fn cap_slots(version: u32) -> Option<usize> {
    match version {
        CAP_VERSION_1 => Some(1),
        CAP_VERSION_2 | CAP_VERSION_3 => Some(2),
        _ => None,
    }
}

fn current_proc_identity() -> (u32, u32) {
    let task = current();
    let tid = if task.id().as_u64() == task.task_ext().leader_tid() {
        task.task_ext().proc_id as u32
    } else {
        task.id().as_u64() as u32
    };
    (task.task_ext().proc_id as u32, tid)
}

fn resolve_capget_target(pid: i32) -> Result<u32, LinuxError> {
    if pid < 0 {
        return Err(LinuxError::EINVAL);
    }
    let (proc_id, tid) = current_proc_identity();
    if pid == 0 || pid as u32 == proc_id || pid as u32 == tid {
        Ok(proc_id)
    } else {
        Err(LinuxError::ESRCH)
    }
}

fn resolve_capset_target(pid: i32) -> Result<u32, LinuxError> {
    if pid < 0 {
        return Err(LinuxError::EPERM);
    }
    let (proc_id, tid) = current_proc_identity();
    if pid == 0 || pid as u32 == proc_id || pid as u32 == tid {
        Ok(proc_id)
    } else {
        Err(LinuxError::EPERM)
    }
}

fn default_security_state() -> ProcessSecurityState {
    if axfs::api::current_euid() == 0 {
        ProcessSecurityState {
            caps: [UserCapData {
                effective: u32::MAX,
                permitted: u32::MAX,
                inheritable: u32::MAX,
            }; 2],
            bounding: u64::MAX,
        }
    } else {
        ProcessSecurityState {
            caps: [UserCapData::default(); 2],
            bounding: u64::MAX,
        }
    }
}

fn current_security_state(target: u32) -> ProcessSecurityState {
    CAPABILITY_STATE
        .lock()
        .get(&target)
        .copied()
        .unwrap_or_else(default_security_state)
}

fn cap_word_mask(cap: u32) -> (usize, u32) {
    let word = (cap / 32) as usize;
    let bit = 1u32 << (cap % 32);
    (word, bit)
}

fn has_cap_setpcap(state: &ProcessSecurityState) -> bool {
    let (word, bit) = cap_word_mask(CAP_SETPCAP);
    state.caps[word].effective & bit != 0
}

fn caps_subset(lhs: [u32; 2], rhs: [u32; 2]) -> bool {
    (lhs[0] & !rhs[0]) == 0 && (lhs[1] & !rhs[1]) == 0
}

fn capdata_mask(data: &[UserCapData; 2], field: fn(&UserCapData) -> u32) -> [u32; 2] {
    [field(&data[0]), field(&data[1])]
}

fn validate_capset(old: &ProcessSecurityState, new: &[UserCapData; 2]) -> Result<(), LinuxError> {
    let new_effective = capdata_mask(new, |data| data.effective);
    let new_permitted = capdata_mask(new, |data| data.permitted);
    let new_inheritable = capdata_mask(new, |data| data.inheritable);
    let old_permitted = capdata_mask(&old.caps, |data| data.permitted);
    let old_inheritable = capdata_mask(&old.caps, |data| data.inheritable);

    if !caps_subset(new_effective, new_permitted) {
        return Err(LinuxError::EPERM);
    }
    if !caps_subset(new_permitted, old_permitted) {
        return Err(LinuxError::EPERM);
    }
    let inheritable_limit = [
        old_inheritable[0] | old_permitted[0],
        old_inheritable[1] | old_permitted[1],
    ];
    if !caps_subset(new_inheritable, inheritable_limit) {
        return Err(LinuxError::EPERM);
    }
    if !has_cap_setpcap(old) && !caps_subset(new_inheritable, old_inheritable) {
        return Err(LinuxError::EPERM);
    }
    let bounding = [old.bounding as u32, (old.bounding >> 32) as u32];
    if !caps_subset(new_inheritable, bounding) {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

pub(crate) fn sys_capget(header: *mut c_void, data: *mut c_void) -> isize {
    syscall_body!(sys_capget, {
        if header.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let mut user_header = read_value_from_user(header as *const UserCapHeader)?;
        let slots = match cap_slots(user_header.version) {
            Some(slots) => slots,
            None => {
                user_header.version = CAP_VERSION_3;
                write_value_to_user(header as *mut UserCapHeader, user_header)?;
                return Err(LinuxError::EINVAL);
            }
        };
        let target = resolve_capget_target(user_header.pid)?;
        if data.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let state = current_security_state(target);
        let data = data as *mut UserCapData;
        for (index, cap) in state.caps.iter().take(slots).enumerate() {
            write_value_to_user(unsafe { data.add(index) }, *cap)?;
        }
        Ok(0)
    })
}

pub(crate) fn sys_capset(header: *const c_void, data: *const c_void) -> isize {
    syscall_body!(sys_capset, {
        if header.is_null() || data.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let mut user_header = read_value_from_user(header as *const UserCapHeader)?;
        let slots = match cap_slots(user_header.version) {
            Some(slots) => slots,
            None => {
                user_header.version = CAP_VERSION_3;
                write_value_to_user(header as *mut UserCapHeader, user_header)?;
                return Err(LinuxError::EINVAL);
            }
        };
        let target = resolve_capset_target(user_header.pid)?;
        let data = data as *const UserCapData;
        let mut caps = [UserCapData::default(); 2];
        for (index, slot) in caps.iter_mut().take(slots).enumerate() {
            *slot = read_value_from_user(unsafe { data.add(index) })?;
        }
        let old_state = current_security_state(target);
        validate_capset(&old_state, &caps)?;
        CAPABILITY_STATE.lock().insert(
            target,
            ProcessSecurityState {
                caps,
                bounding: old_state.bounding,
            },
        );
        Ok(0)
    })
}

pub(crate) fn sys_prctl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> isize {
    let _ = (arg3, arg4, arg5);
    syscall_body!(sys_prctl, {
        let (proc_id, _) = current_proc_identity();
        match option {
            PR_CAPBSET_READ => {
                if arg2 >= 64 {
                    return Err(LinuxError::EINVAL);
                }
                let state = current_security_state(proc_id);
                Ok(((state.bounding >> arg2) & 1) as isize)
            }
            PR_CAPBSET_DROP => {
                if arg2 >= 64 {
                    return Err(LinuxError::EINVAL);
                }
                let mut table = CAPABILITY_STATE.lock();
                let mut state = table
                    .get(&proc_id)
                    .copied()
                    .unwrap_or_else(default_security_state);
                state.bounding &= !(1u64 << arg2);
                table.insert(proc_id, state);
                Ok(0)
            }
            PR_GET_TIMERSLACK => Ok(DEFAULT_TIMERSLACK_NS),
            _ => Err(LinuxError::EINVAL),
        }
    })
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

const CLONE_ARGS_MIN_SIZE: usize = 8 * core::mem::size_of::<u64>();
const MAX_SIGNAL_NUMBER: u64 = 64;

fn read_clone3_args_from_user(
    cl_args: *const CloneArgs,
    size: usize,
) -> Result<CloneArgs, LinuxError> {
    if size < CLONE_ARGS_MIN_SIZE {
        return Err(LinuxError::EINVAL);
    }

    let mut args = CloneArgs {
        flags: 0,
        pidfd: 0,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: 0,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let known_size = core::mem::size_of::<CloneArgs>();
    let copy_len = size.min(known_size);
    let args_bytes = unsafe {
        core::slice::from_raw_parts_mut((&mut args as *mut CloneArgs).cast::<u8>(), known_size)
    };
    copy_from_user(&mut args_bytes[..copy_len], cl_args.cast())?;

    if size > known_size {
        let extra_len = size - known_size;
        let mut offset = 0usize;
        let mut extra = [0u8; 64];
        while offset < extra_len {
            let chunk = (extra_len - offset).min(extra.len());
            copy_from_user(&mut extra[..chunk], unsafe {
                (cl_args as *const u8).add(known_size + offset).cast()
            })?;
            if extra[..chunk].iter().any(|byte| *byte != 0) {
                return Err(LinuxError::E2BIG);
            }
            offset += chunk;
        }
    }

    Ok(args)
}

fn validate_clone3_args(args: &CloneArgs) -> Result<(), LinuxError> {
    let clone_flags = CloneFlags::from_bits_truncate(args.flags as u32);
    let clone_into_cgroup = (args.flags & CLONE_INTO_CGROUP_FLAG) != 0;

    if args.exit_signal > MAX_SIGNAL_NUMBER {
        return Err(LinuxError::EINVAL);
    }
    if (args.stack == 0) != (args.stack_size == 0) {
        return Err(LinuxError::EINVAL);
    }
    if clone_flags.contains(CloneFlags::CLONE_SIGHAND)
        && !clone_flags.contains(CloneFlags::CLONE_VM)
    {
        return Err(LinuxError::EINVAL);
    }
    if clone_flags.contains(CloneFlags::CLONE_THREAD)
        && !clone_flags.contains(CloneFlags::CLONE_SIGHAND)
    {
        return Err(LinuxError::EINVAL);
    }
    if clone_flags.contains(CloneFlags::CLONE_FS) && clone_flags.contains(CloneFlags::CLONE_NEWNS) {
        return Err(LinuxError::EINVAL);
    }
    if clone_flags.contains(CloneFlags::CLONE_THREAD)
        && clone_flags.contains(CloneFlags::CLONE_PIDFD)
    {
        return Err(LinuxError::EINVAL);
    }

    if clone_flags.contains(CloneFlags::CLONE_PIDFD) {
        if args.pidfd == 0 {
            return Err(LinuxError::EINVAL);
        }
        ensure_user_range(
            VirtAddr::from_usize(args.pidfd as usize),
            core::mem::size_of::<i32>(),
            MappingFlags::WRITE,
        )?;
    }

    if args.set_tid != 0 || args.set_tid_size != 0 {
        return Err(LinuxError::ENOSYS);
    }
    if clone_into_cgroup {
        if args.cgroup == 0 {
            return Err(LinuxError::EINVAL);
        }
        let dir = Directory::from_fd(args.cgroup as c_int).map_err(|_| LinuxError::EBADF)?;
        let cgroup_root = arceos_posix_api::proc_cgroup_mount_path();
        let cgroup_prefix = alloc::format!("{cgroup_root}/");
        if dir.path() != cgroup_root && !dir.path().starts_with(cgroup_prefix.as_str()) {
            return Err(LinuxError::EINVAL);
        }
    } else if args.cgroup != 0 {
        return Err(LinuxError::EINVAL);
    }

    Ok(())
}

fn add_pidfd_for_pid(pid: usize, flags: u32) -> Result<c_int, LinuxError> {
    let nonblocking = (flags & arceos_posix_api::ctypes::O_NONBLOCK) != 0;
    let fd = add_file_like(Arc::new(PidFd::new(pid, nonblocking)))?;
    let ret = api::sys_fcntl(
        fd,
        api::ctypes::F_SETFD as _,
        api::ctypes::FD_CLOEXEC as usize,
    );
    if ret < 0 {
        let _ = api::sys_close(fd);
        return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EINVAL));
    }
    Ok(fd)
}

fn pid_from_proc_dir_path(path: &str) -> Result<usize, LinuxError> {
    let path = path.trim_end_matches('/');
    if path == "/proc/self" {
        return Ok(current().task_ext().proc_id);
    }
    let Some(pid) = path.strip_prefix("/proc/") else {
        return Err(LinuxError::EBADF);
    };
    if pid.is_empty() || !pid.bytes().all(|ch| ch.is_ascii_digit()) {
        return Err(LinuxError::EBADF);
    }
    pid.parse::<usize>().map_err(|_| LinuxError::EBADF)
}

fn pidfd_target(fd: c_int) -> Result<(usize, bool), LinuxError> {
    let file = get_file_like(fd)?;
    if let Ok(pidfd) = file.clone().into_any().downcast::<PidFd>() {
        return Ok((pidfd.pid, pidfd.nonblocking));
    }
    if let Ok(dir) = file.into_any().downcast::<Directory>() {
        return Ok((pid_from_proc_dir_path(dir.path())?, false));
    }
    Err(LinuxError::EBADF)
}

fn pid_from_pidfd(fd: c_int) -> Result<usize, LinuxError> {
    pidfd_target(fd).map(|(pid, _)| pid)
}

struct WaitIdTarget {
    selector: WaitChildSelector,
    pidfd_nonblocking: bool,
}

fn waitid_target_pid(idtype: i32, id: usize) -> Result<WaitIdTarget, LinuxError> {
    match idtype {
        P_ALL => Ok(WaitIdTarget {
            selector: WaitChildSelector::Any,
            pidfd_nonblocking: false,
        }),
        P_PID => {
            if id == 0 {
                Err(LinuxError::ECHILD)
            } else {
                Ok(WaitIdTarget {
                    selector: WaitChildSelector::Pid(id as u64),
                    pidfd_nonblocking: false,
                })
            }
        }
        P_PGID => {
            let pgid = if id == 0 {
                current().task_ext().process_group()
            } else {
                id as u64
            };
            Ok(WaitIdTarget {
                selector: WaitChildSelector::ProcessGroup(pgid),
                pidfd_nonblocking: false,
            })
        }
        P_PIDFD => {
            let (pid, nonblocking) = pidfd_target(id as c_int)?;
            Ok(WaitIdTarget {
                selector: WaitChildSelector::Pid(pid as u64),
                pidfd_nonblocking: nonblocking,
            })
        }
        _ => Err(LinuxError::EINVAL),
    }
}

fn waitid_zero_info(infop: *mut WaitSigInfo) -> Result<(), LinuxError> {
    if infop.is_null() {
        return Ok(());
    }
    write_value_to_user(
        infop,
        WaitSigInfo {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            _pad0: 0,
            sigchld: WaitSigInfoSigChld {
                si_pid: 0,
                si_uid: 0,
                si_status: 0,
                si_utime: 0,
                si_stime: 0,
            },
            _pad1: [0; 80],
        },
    )
}

fn write_waitid_siginfo_fields(
    infop: *mut WaitSigInfo,
    child_pid: u64,
    si_code: i32,
    si_status: i32,
) -> Result<(), LinuxError> {
    if infop.is_null() {
        return Ok(());
    }
    write_value_to_user(
        infop,
        WaitSigInfo {
            si_signo: 17,
            si_errno: 0,
            si_code,
            _pad0: 0,
            sigchld: WaitSigInfoSigChld {
                si_pid: child_pid as i32,
                si_uid: 0,
                si_status,
                si_utime: 0,
                si_stime: 0,
            },
            _pad1: [0; 80],
        },
    )
}

fn write_waitid_siginfo(
    infop: *mut WaitSigInfo,
    child_pid: u64,
    wait_status: i32,
) -> Result<(), LinuxError> {
    let (si_code, si_status) = if (wait_status & 0x7f) == 0 {
        (CLD_EXITED, (wait_status >> 8) & 0xff)
    } else if (wait_status & 0x80) != 0 {
        (CLD_DUMPED, wait_status & 0x7f)
    } else {
        (CLD_KILLED, wait_status & 0x7f)
    };
    write_waitid_siginfo_fields(infop, child_pid, si_code, si_status)
}

fn waitid_child_state_event(
    selector: WaitChildSelector,
    options: u32,
    consume: bool,
) -> Option<(u64, i32, i32)> {
    let curr = current();
    let curr_proc_id = curr.task_ext().proc_id;
    let children = curr.task_ext().children.lock();

    for child in children.iter() {
        if !wait_selector_matches_live(curr_proc_id, selector, child) {
            continue;
        }
        if (options & WSTOPPED) != 0 && child.task_ext().wait_stop_pending() {
            let sig = child.task_ext().wait_stop_signal();
            if consume {
                let _ = child.task_ext().consume_wait_stop_pending();
            }
            return Some((child.task_ext().proc_id as u64, CLD_STOPPED, sig));
        }
        if (options & WaitFlags::WCONTINUED.bits()) != 0 && child.task_ext().wait_continue_pending()
        {
            if consume {
                let _ = child.task_ext().consume_wait_continue_pending();
            }
            return Some((
                child.task_ext().proc_id as u64,
                CLD_CONTINUED,
                SIGCONT_STATUS,
            ));
        }
    }

    None
}

fn waitid_exited_event(
    selector: WaitChildSelector,
    consume: bool,
) -> Result<Option<(u64, i32)>, WaitStatus> {
    let curr = current();
    {
        let mut zombies = curr.task_ext().zombie_children.lock();
        let zombie_index = zombies.iter().position(|zombie| {
            crate::task::wait_selector_matches_zombie(selector, zombie.pid, zombie.process_group)
        });
        if let Some(index) = zombie_index {
            let zombie = if consume {
                let zombie = zombies.remove(index);
                unregister_zombie_process(zombie.pid);
                zombie
            } else {
                zombies[index]
            };
            return Ok(Some((zombie.pid, zombie.wait_status)));
        }
    }

    Err(wait_child_status(curr.as_task_ref(), selector))
}

fn wait4_child_state_event(
    selector: WaitChildSelector,
    option_flag: WaitFlags,
    consume: bool,
) -> Option<(u64, i32)> {
    let curr = current();
    let curr_proc_id = curr.task_ext().proc_id;
    let children = curr.task_ext().children.lock();

    for child in children.iter() {
        if !wait_selector_matches_live(curr_proc_id, selector, child) {
            continue;
        }
        if option_flag.contains(WaitFlags::WIMTRACED) && child.task_ext().wait_stop_pending() {
            let sig = child.task_ext().wait_stop_signal() as usize;
            if consume {
                let _ = child.task_ext().consume_wait_stop_pending();
            }
            return Some((child.task_ext().proc_id as u64, wait_status_stopped(sig)));
        }
        if option_flag.contains(WaitFlags::WCONTINUED) && child.task_ext().wait_continue_pending() {
            if consume {
                let _ = child.task_ext().consume_wait_continue_pending();
            }
            return Some((child.task_ext().proc_id as u64, wait_status_continued()));
        }
    }

    None
}

fn wait_for_child_wait_event(curr_task: &AxTaskRef, observed_seq: u64) {
    curr_task.task_ext().child_exit_wq.wait_until(|| {
        curr_task.task_ext().child_wait_event_seq() != observed_seq
            || crate::signal::current_has_interrupting_signal(true)
    });
}

fn attach_pid_to_cgroup(dirfd: c_int, pid: usize) -> Result<(), LinuxError> {
    let dir = Directory::from_fd(dirfd).map_err(|_| LinuxError::EBADF)?;
    let path = alloc::format!("{}/cgroup.procs", dir.path().trim_end_matches('/'));
    axfs::api::write(path.as_str(), alloc::format!("{pid}\n")).map_err(LinuxError::from)
}

const BUSYBOX_TRACE_LOG_LIMIT: usize = 96;
const BUSYBOX_KILL_TRACE_LOG_LIMIT: usize = 64;
static BUSYBOX_TRACE_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static BUSYBOX_KILL_TRACE_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn busybox_trace_arch_tag() -> &'static str {
    #[cfg(target_arch = "loongarch64")]
    {
        "la"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "rv"
    }
    #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
    {
        "unknown"
    }
}

fn is_busybox_trace_task(name: &str) -> bool {
    name.contains("busybox")
        || name == "sh"
        || name == "ash"
        || name == "sleep"
        || name.ends_with("/busybox")
        || name.ends_with("/sh")
        || name.ends_with("/ash")
        || name.ends_with("/sleep")
}

fn is_busybox_trace_exec_path(path: &str) -> bool {
    path.contains("busybox")
        || path.ends_with("busybox_testcode.sh")
        || path.ends_with("/sh")
        || path.ends_with("/ash")
        || path.ends_with("/sleep")
}

fn should_trace_busybox() -> bool {
    let curr = current();
    is_busybox_trace_task(curr.name())
        || is_busybox_trace_exec_path(curr.task_ext().exec_path().as_str())
}

fn should_trace_busybox_exec_target(path: &str) -> bool {
    is_busybox_trace_exec_path(path)
}

fn take_busybox_trace_slot() -> Option<usize> {
    let _ = BUSYBOX_TRACE_LOG_COUNT.load(AtomicOrdering::Relaxed);
    None
}

fn take_busybox_exec_trace_slot(path: &str) -> Option<usize> {
    let _ = path;
    None
}

fn take_busybox_kill_trace_slot(pid: i32, signum: usize) -> Option<usize> {
    let _ = pid;
    let _ = signum;
    None
}

fn summarize_kill_targets(targets: &[KillTarget]) -> String {
    let mut summary = String::new();
    for (index, target) in targets.iter().take(4).enumerate() {
        if index > 0 {
            summary.push('|');
        }
        match target {
            KillTarget::Live(task) => summary.push_str(&alloc::format!(
                "live:tid={},pid={},pgid={},exec={}",
                task.id().as_u64(),
                task.task_ext().proc_id,
                task.task_ext().process_group(),
                task.task_ext().exec_path()
            )),
            KillTarget::Zombie(zombie) => summary.push_str(&alloc::format!(
                "zombie:pid={},pgid={}",
                zombie.pid,
                zombie.process_group
            )),
        }
    }
    if targets.len() > 4 {
        summary.push_str(&alloc::format!("|more={}", targets.len() - 4));
    }
    if summary.is_empty() {
        summary.push_str("none");
    }
    summary
}

#[cfg(target_arch = "riscv64")]
fn should_trace_riscv_libcbench() -> bool {
    false
}

#[cfg(target_arch = "riscv64")]
fn take_riscv_libcbench_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, AtomicOrdering::Relaxed) < limit
}

/// ARCH_PRCTL codes
///
/// It is only avaliable on x86_64, and is not convenient
/// to generate automatically via c_to_rust binding.
#[derive(Debug, Eq, PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum ArchPrctlCode {
    /// Set the GS segment base
    SetGs = 0x1001,
    /// Set the FS segment base
    SetFs = 0x1002,
    /// Get the FS segment base
    GetFs = 0x1003,
    /// Get the GS segment base
    GetGs = 0x1004,
    /// The setting of the flag manipulated by ARCH_SET_CPUID
    GetCpuid = 0x1011,
    /// Enable (addr != 0) or disable (addr == 0) the cpuid instruction for the calling thread.
    SetCpuid = 0x1012,
}

pub(crate) fn sys_getpid() -> i32 {
    syscall_body!(sys_getpid, {
        Ok(axtask::current().task_ext().proc_id as c_int)
    })
}

pub(crate) fn sys_getppid() -> i32 {
    syscall_body!(sys_getppid, {
        let curr = axtask::current();
        let ppid = curr.task_ext().get_parent() as c_int;
        Ok(ppid)
    })
}

pub(crate) fn sys_getuid() -> i32 {
    syscall_body!(sys_getuid, Ok(axfs::api::current_uid() as i32))
}

pub(crate) fn sys_geteuid() -> i32 {
    syscall_body!(sys_geteuid, Ok(axfs::api::current_euid() as i32))
}

pub(crate) fn sys_getgid() -> i32 {
    syscall_body!(sys_getgid, Ok(axfs::api::current_gid() as i32))
}

pub(crate) fn sys_getegid() -> i32 {
    syscall_body!(sys_getegid, Ok(axfs::api::current_egid() as i32))
}

pub(crate) fn sys_setfsuid(uid: u32) -> isize {
    syscall_body!(sys_setfsuid, {
        let old = axfs::api::current_fsuid();
        let (ruid, euid, suid) = axfs::api::current_res_uid();
        let allowed = axfs::api::current_euid() == 0
            || uid == ruid
            || uid == euid
            || uid == suid
            || uid == old;
        if allowed && uid != u32::MAX {
            axfs::api::set_fsuid(uid);
        }
        Ok(old as isize)
    })
}

pub(crate) fn sys_setfsgid(gid: u32) -> isize {
    syscall_body!(sys_setfsgid, {
        let old = axfs::api::current_fsgid();
        let (rgid, egid, sgid) = axfs::api::current_res_gid();
        let allowed = axfs::api::current_euid() == 0
            || gid == rgid
            || gid == egid
            || gid == sgid
            || gid == old;
        if allowed && gid != u32::MAX {
            axfs::api::set_fsgid(gid);
        }
        Ok(old as isize)
    })
}

pub(crate) fn sys_setuid(uid: u32) -> isize {
    syscall_body!(sys_setuid, {
        let (ruid, euid, suid) = axfs::api::current_res_uid();
        if euid != 0 && uid != ruid && uid != euid && uid != suid {
            return Err(LinuxError::EPERM);
        }
        if euid == 0 {
            axfs::api::set_res_uid(uid, uid, uid);
        } else {
            axfs::api::set_res_uid(ruid, uid, suid);
        }
        Ok(0)
    })
}

pub(crate) fn sys_setgid(gid: u32) -> isize {
    syscall_body!(sys_setgid, {
        let (rgid, egid, sgid) = axfs::api::current_res_gid();
        if axfs::api::current_euid() != 0 && gid != rgid && gid != egid && gid != sgid {
            return Err(LinuxError::EPERM);
        }
        if axfs::api::current_euid() == 0 {
            axfs::api::set_res_gid(gid, gid, gid);
        } else {
            axfs::api::set_res_gid(rgid, gid, sgid);
        }
        Ok(0)
    })
}

pub(crate) fn sys_setreuid(ruid: u32, euid: u32) -> isize {
    syscall_body!(sys_setreuid, {
        let (old_ruid, old_euid, old_suid) = axfs::api::current_res_uid();
        let new_ruid = if ruid == u32::MAX { old_ruid } else { ruid };
        let new_euid = if euid == u32::MAX { old_euid } else { euid };
        if old_euid != 0 {
            if ruid != u32::MAX && new_ruid != old_ruid && new_ruid != old_euid {
                return Err(LinuxError::EPERM);
            }
            if euid != u32::MAX
                && new_euid != old_ruid
                && new_euid != old_euid
                && new_euid != old_suid
            {
                return Err(LinuxError::EPERM);
            }
        }
        let new_suid =
            if old_euid == 0 || (ruid != u32::MAX) || (euid != u32::MAX && new_euid != old_ruid) {
                new_euid
            } else {
                old_suid
            };
        axfs::api::set_res_uid(new_ruid, new_euid, new_suid);
        Ok(0)
    })
}

pub(crate) fn sys_setregid(rgid: u32, egid: u32) -> isize {
    syscall_body!(sys_setregid, {
        let (old_rgid, old_egid, old_sgid) = axfs::api::current_res_gid();
        let new_rgid = if rgid == u32::MAX { old_rgid } else { rgid };
        let new_egid = if egid == u32::MAX { old_egid } else { egid };
        let privileged = axfs::api::current_euid() == 0;
        if !privileged {
            if rgid != u32::MAX && new_rgid != old_rgid && new_rgid != old_egid {
                return Err(LinuxError::EPERM);
            }
            if egid != u32::MAX
                && new_egid != old_rgid
                && new_egid != old_egid
                && new_egid != old_sgid
            {
                return Err(LinuxError::EPERM);
            }
        }
        let new_sgid =
            if privileged || (rgid != u32::MAX) || (egid != u32::MAX && new_egid != old_rgid) {
                new_egid
            } else {
                old_sgid
            };
        axfs::api::set_res_gid(new_rgid, new_egid, new_sgid);
        Ok(0)
    })
}

pub(crate) fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> isize {
    syscall_body!(sys_setresuid, {
        let (old_ruid, old_euid, old_suid) = axfs::api::current_res_uid();
        let new_ruid = if ruid == u32::MAX { old_ruid } else { ruid };
        let new_euid = if euid == u32::MAX { old_euid } else { euid };
        let new_suid = if suid == u32::MAX { old_suid } else { suid };
        if old_euid != 0 {
            for uid in [new_ruid, new_euid, new_suid] {
                if uid != old_ruid && uid != old_euid && uid != old_suid {
                    return Err(LinuxError::EPERM);
                }
            }
        }
        axfs::api::set_res_uid(new_ruid, new_euid, new_suid);
        Ok(0)
    })
}

pub(crate) fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> isize {
    syscall_body!(sys_setresgid, {
        let (old_rgid, old_egid, old_sgid) = axfs::api::current_res_gid();
        let new_rgid = if rgid == u32::MAX { old_rgid } else { rgid };
        let new_egid = if egid == u32::MAX { old_egid } else { egid };
        let new_sgid = if sgid == u32::MAX { old_sgid } else { sgid };
        if axfs::api::current_euid() != 0 {
            for gid in [new_rgid, new_egid, new_sgid] {
                if gid != old_rgid && gid != old_egid && gid != old_sgid {
                    return Err(LinuxError::EPERM);
                }
            }
        }
        axfs::api::set_res_gid(new_rgid, new_egid, new_sgid);
        Ok(0)
    })
}

pub(crate) fn sys_getresuid(ruid: *mut u32, euid: *mut u32, suid: *mut u32) -> isize {
    syscall_body!(sys_getresuid, {
        if ruid.is_null() || euid.is_null() || suid.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let (cur_ruid, cur_euid, cur_suid) = axfs::api::current_res_uid();
        write_value_to_user(ruid, cur_ruid)?;
        write_value_to_user(euid, cur_euid)?;
        write_value_to_user(suid, cur_suid)?;
        Ok(0)
    })
}

pub(crate) fn sys_getresgid(rgid: *mut u32, egid: *mut u32, sgid: *mut u32) -> isize {
    syscall_body!(sys_getresgid, {
        if rgid.is_null() || egid.is_null() || sgid.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let (cur_rgid, cur_egid, cur_sgid) = axfs::api::current_res_gid();
        write_value_to_user(rgid, cur_rgid)?;
        write_value_to_user(egid, cur_egid)?;
        write_value_to_user(sgid, cur_sgid)?;
        Ok(0)
    })
}

pub(crate) fn sys_setgroups(size: usize, list: *const u32) -> isize {
    syscall_body!(sys_setgroups, {
        if axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }
        let groups = if size == 0 {
            Vec::new()
        } else {
            if list.is_null() {
                return Err(LinuxError::EFAULT);
            }
            let mut groups = vec![0u32; size];
            copy_from_user(
                unsafe {
                    core::slice::from_raw_parts_mut(
                        groups.as_mut_ptr().cast::<u8>(),
                        size * core::mem::size_of::<u32>(),
                    )
                },
                list.cast(),
            )?;
            groups
        };
        axfs::api::set_supplementary_gids(&groups).map_err(LinuxError::from)?;
        Ok(0)
    })
}

pub(crate) fn sys_getgroups(size: usize, list: *mut u32) -> isize {
    syscall_body!(sys_getgroups, {
        let (groups, count) = axfs::api::current_supplementary_gids();
        if size > i32::MAX as usize {
            return Err(LinuxError::EINVAL);
        }
        if size == 0 {
            return Ok(count as isize);
        }
        if size < count {
            return Err(LinuxError::EINVAL);
        }
        if count != 0 {
            if list.is_null() {
                return Err(LinuxError::EFAULT);
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    groups.as_ptr().cast::<u8>(),
                    count * core::mem::size_of::<u32>(),
                )
            };
            crate::usercopy::copy_to_user(list.cast(), bytes)?;
        }
        Ok(count as isize)
    })
}

pub(crate) fn sys_gettid() -> i32 {
    syscall_body!(sys_gettid, {
        let curr = current();
        Ok(if curr.id().as_u64() == curr.task_ext().leader_tid() {
            curr.task_ext().proc_id as c_int
        } else {
            curr.id().as_u64() as c_int
        })
    })
}

pub(crate) fn sys_setsid() -> isize {
    syscall_body!(sys_setsid, {
        let curr = current();
        let proc_id = curr.task_ext().proc_id as u64;
        if curr.task_ext().process_group() == proc_id {
            return Err(LinuxError::EPERM);
        }
        curr.task_ext().set_process_group(proc_id);
        curr.task_ext().set_session(proc_id);
        if let Some(slot) = take_busybox_trace_slot() {
            warn!(
                "[online-busybox-proc:{}:{}] setsid task={} exec_path={} now_ms={}",
                busybox_trace_arch_tag(),
                slot,
                curr.id_name(),
                curr.task_ext().exec_path(),
                monotonic_time_nanos() / 1_000_000
            );
        }
        Ok(proc_id as isize)
    })
}

pub(crate) fn task_by_pid(pid: i32) -> Result<axtask::AxTaskRef, LinuxError> {
    let curr = current();
    if pid == 0 || pid as usize == curr.task_ext().proc_id {
        return Ok(curr.as_task_ref().clone());
    }
    find_process_leader_by_pid(pid as usize).ok_or(LinuxError::ESRCH)
}

pub(crate) fn sys_getpgid(pid: i32) -> isize {
    syscall_body!(sys_getpgid, {
        if pid < 0 {
            return Err(LinuxError::ESRCH);
        }
        let task = match task_by_pid(pid) {
            Ok(task) => task,
            Err(LinuxError::ESRCH) if pid == 1 => return Ok(0),
            Err(err) => return Err(err),
        };
        Ok(task.task_ext().process_group() as isize)
    })
}

pub(crate) fn sys_getsid(pid: i32) -> isize {
    syscall_body!(sys_getsid, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        let task = task_by_pid(pid)?;
        Ok(task.task_ext().session() as isize)
    })
}

pub(crate) fn sys_setpgid(pid: i32, pgid: i32) -> isize {
    syscall_body!(sys_setpgid, {
        if pid < 0 || pgid < 0 {
            return Err(LinuxError::EINVAL);
        }
        let task = task_by_pid(pid)?;
        let curr = current();
        let curr_pid = curr.task_ext().proc_id as i32;
        let target_pid = task.task_ext().proc_id as i32;
        if target_pid != curr_pid {
            let is_child = curr
                .task_ext()
                .children
                .lock()
                .iter()
                .any(|child| child.task_ext().proc_id as i32 == target_pid);
            if !is_child {
                return Err(LinuxError::ESRCH);
            }
            if task.task_ext().session() != curr.task_ext().session() {
                return Err(LinuxError::EPERM);
            }
            if task.task_ext().exec_path() != curr.task_ext().exec_path() {
                return Err(LinuxError::EACCES);
            }
        }
        if task.task_ext().session() == target_pid as u64 {
            return Err(LinuxError::EPERM);
        }
        let new_pgid = if pgid == 0 { target_pid } else { pgid };
        if new_pgid <= 0 {
            return Err(LinuxError::EINVAL);
        }
        if new_pgid != target_pid {
            let target_session = task.task_ext().session();
            let group_exists_in_session = process_leader_tasks().into_iter().any(|leader| {
                leader.task_ext().process_group() == new_pgid as u64
                    && leader.task_ext().session() == target_session
            });
            if !group_exists_in_session {
                return Err(LinuxError::EPERM);
            }
        }
        task.task_ext().set_process_group(new_pgid as u64);
        Ok(0)
    })
}

fn validate_kill_signum(signum: i32) -> Result<usize, LinuxError> {
    match signum {
        0..=64 => Ok(signum as usize),
        _ => Err(LinuxError::EINVAL),
    }
}

fn may_signal_task(task: &AxTaskRef) -> bool {
    let (sender_ruid, sender_euid, _) = axfs::api::current_res_uid();
    if sender_euid == 0 {
        return true;
    }

    let target_cred = *CURRENT_FS_CRED.deref_from(&task.task_ext().ns).lock();
    [sender_ruid, sender_euid]
        .into_iter()
        .any(|uid| uid == target_cred.ruid || uid == target_cred.euid || uid == target_cred.suid)
}

fn may_signal_zombie(zombie: &ZombieProcess) -> bool {
    let (sender_ruid, sender_euid, _) = axfs::api::current_res_uid();
    if sender_euid == 0 {
        return true;
    }
    [sender_ruid, sender_euid]
        .into_iter()
        .any(|uid| uid == zombie.ruid || uid == zombie.euid || uid == zombie.suid)
}

enum KillTarget {
    Live(AxTaskRef),
    Zombie(ZombieProcess),
}

fn kill_targets(
    pid: i32,
    caller_pid: usize,
    caller_pgid: u64,
) -> Result<Vec<KillTarget>, LinuxError> {
    if pid > 0 {
        if let Some(task) = find_process_leader_by_pid(pid as usize) {
            return Ok(vec![KillTarget::Live(task)]);
        }
        if let Some(zombie) = find_zombie_process_by_pid(pid as usize) {
            return Ok(vec![KillTarget::Zombie(zombie)]);
        }
        return Err(LinuxError::ESRCH);
    }

    if pid == 0 {
        let targets: Vec<_> = process_leader_tasks()
            .into_iter()
            .filter(|task| task.task_ext().process_group() == caller_pgid)
            .map(KillTarget::Live)
            .collect();
        return if targets.is_empty() {
            Err(LinuxError::ESRCH)
        } else {
            Ok(targets)
        };
    }

    if pid == -1 {
        let targets: Vec<_> = process_leader_tasks()
            .into_iter()
            .filter(|task| {
                let task_pid = task.task_ext().proc_id;
                task_pid != 1 && task_pid != caller_pid
            })
            .map(KillTarget::Live)
            .collect();
        return if targets.is_empty() {
            Err(LinuxError::ESRCH)
        } else {
            Ok(targets)
        };
    }

    let Some(target_pgid) = pid.checked_neg() else {
        return Err(LinuxError::ESRCH);
    };
    let targets: Vec<_> = process_leader_tasks()
        .into_iter()
        .filter(|task| task.task_ext().process_group() == target_pgid as u64)
        .map(KillTarget::Live)
        .collect();
    if targets.is_empty() {
        Err(LinuxError::ESRCH)
    } else {
        Ok(targets)
    }
}

pub(crate) fn sys_kill(pid: i32, signum: i32) -> isize {
    syscall_body!(sys_kill, {
        let signum = validate_kill_signum(signum)?;
        let curr = current();
        let diag_slot = take_busybox_kill_trace_slot(pid, signum);
        if let Some(slot) = diag_slot {
            warn!(
                "[online-busybox-kill:{}:{}] enter curr_tid={} curr_pid={} curr_pgid={} name={} exec_path={} pid_arg={} signum={}",
                busybox_trace_arch_tag(),
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                curr.task_ext().process_group(),
                curr.name(),
                curr.task_ext().exec_path(),
                pid,
                signum,
            );
        }
        let targets = match kill_targets(
            pid,
            curr.task_ext().proc_id,
            curr.task_ext().process_group(),
        ) {
            Ok(targets) => {
                if let Some(slot) = diag_slot {
                    warn!(
                        "[online-busybox-kill:{}:{}] resolve pid_arg={} signum={} target_count={} targets={}",
                        busybox_trace_arch_tag(),
                        slot,
                        pid,
                        signum,
                        targets.len(),
                        summarize_kill_targets(&targets),
                    );
                }
                targets
            }
            Err(err) => {
                if let Some(slot) = diag_slot {
                    warn!(
                        "[online-busybox-kill:{}:{}] resolve pid_arg={} signum={} result={:?}",
                        busybox_trace_arch_tag(),
                        slot,
                        pid,
                        signum,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let sender_pid = curr.task_ext().proc_id as i32;
        let sender_uid = axfs::api::current_uid();
        let mut permitted = false;
        let mut denied = false;

        for target in targets {
            match target {
                KillTarget::Live(task) => {
                    if !may_signal_task(&task) {
                        denied = true;
                        if let Some(slot) = diag_slot {
                            warn!(
                                "[online-busybox-kill:{}:{}] deny-live target_tid={} target_pid={} target_pgid={} exec_path={}",
                                busybox_trace_arch_tag(),
                                slot,
                                task.id().as_u64(),
                                task.task_ext().proc_id,
                                task.task_ext().process_group(),
                                task.task_ext().exec_path(),
                            );
                        }
                        continue;
                    }
                    permitted = true;
                    if signum == 0 {
                        if let Some(slot) = diag_slot {
                            warn!(
                                "[online-busybox-kill:{}:{}] probe-live target_tid={} target_pid={} target_pgid={} exec_path={}",
                                busybox_trace_arch_tag(),
                                slot,
                                task.id().as_u64(),
                                task.task_ext().proc_id,
                                task.task_ext().process_group(),
                                task.task_ext().exec_path(),
                            );
                        }
                        continue;
                    }
                    let delivery = if task.id().as_u64() == curr.id().as_u64() {
                        "self"
                    } else {
                        "task"
                    };
                    if let Some(slot) = diag_slot {
                        warn!(
                            "[online-busybox-kill:{}:{}] send-live delivery={} target_tid={} target_pid={} target_pgid={} exec_path={} signum={}",
                            busybox_trace_arch_tag(),
                            slot,
                            delivery,
                            task.id().as_u64(),
                            task.task_ext().proc_id,
                            task.task_ext().process_group(),
                            task.task_ext().exec_path(),
                            signum,
                        );
                    }
                    if task.id().as_u64() == curr.id().as_u64() {
                        crate::signal::send_current_signal(signum);
                    } else {
                        send_user_signal_to_task(&task, signum, sender_pid, sender_uid);
                    }
                }
                KillTarget::Zombie(zombie) => {
                    if !may_signal_zombie(&zombie) {
                        denied = true;
                        if let Some(slot) = diag_slot {
                            warn!(
                                "[online-busybox-kill:{}:{}] deny-zombie target_pid={} target_pgid={}",
                                busybox_trace_arch_tag(),
                                slot,
                                zombie.pid,
                                zombie.process_group,
                            );
                        }
                        continue;
                    }
                    permitted = true;
                    if let Some(slot) = diag_slot {
                        warn!(
                            "[online-busybox-kill:{}:{}] match-zombie target_pid={} target_pgid={} signum={}",
                            busybox_trace_arch_tag(),
                            slot,
                            zombie.pid,
                            zombie.process_group,
                            signum,
                        );
                    }
                }
            }
        }

        let result = if permitted {
            Ok(0)
        } else if denied {
            Err(LinuxError::EPERM)
        } else {
            Err(LinuxError::ESRCH)
        };
        if let Some(slot) = diag_slot {
            warn!(
                "[online-busybox-kill:{}:{}] exit pid_arg={} signum={} permitted={} denied={} result={:?}",
                busybox_trace_arch_tag(),
                slot,
                pid,
                signum,
                permitted,
                denied,
                result,
            );
        }
        result
    })
}

pub(crate) fn sys_tgkill(tgid: i32, tid: i32, signum: i32) -> isize {
    syscall_body!(sys_tgkill, {
        if tid <= 0 || signum < 0 {
            return Err(LinuxError::EINVAL);
        }

        let curr = current();
        let current_tgid = curr.task_ext().proc_id as i32;
        if tgid != 0 && tgid != current_tgid {
            return Err(LinuxError::ESRCH);
        }

        if tid == curr.id().as_u64() as i32 {
            crate::signal::send_current_signal(signum as usize);
            return Ok(0);
        }

        let Some(task) = find_live_task_by_tid(tid as u64) else {
            return Err(LinuxError::ESRCH);
        };
        if tgid != 0 && task.task_ext().proc_id as i32 != tgid {
            return Err(LinuxError::ESRCH);
        }
        send_tkill_signal_to_task(
            &task,
            signum as usize,
            curr.task_ext().proc_id as i32,
            axfs::api::current_uid(),
        );
        Ok(0)
    })
}

pub(crate) fn sys_tkill(tid: i32, signum: i32) -> isize {
    syscall_body!(sys_tkill, {
        if tid <= 0 || signum < 0 {
            return Err(LinuxError::EINVAL);
        }
        if tid == current().id().as_u64() as i32 {
            crate::signal::send_current_signal(signum as usize);
            return Ok(0);
        }
        let curr = current();
        let Some(task) = find_live_task_by_tid(tid as u64) else {
            return Err(LinuxError::ESRCH);
        };
        send_tkill_signal_to_task(
            &task,
            signum as usize,
            curr.task_ext().proc_id as i32,
            axfs::api::current_uid(),
        );
        Ok(0)
    })
}

pub(crate) fn sys_prlimit64(
    pid: i32,
    resource: i32,
    new_limit: *const arceos_posix_api::ctypes::rlimit,
    old_limit: *mut arceos_posix_api::ctypes::rlimit,
) -> isize {
    syscall_body!(sys_prlimit64, {
        let current_pid = current().task_ext().proc_id as i32;
        if pid != 0 && pid != current_pid {
            return Err(LinuxError::ESRCH);
        }

        if !old_limit.is_null() {
            let mut local = arceos_posix_api::ctypes::rlimit::default();
            let res = unsafe { arceos_posix_api::sys_getrlimit(resource, &mut local as *mut _) };
            if res < 0 {
                return Err(LinuxError::try_from(-res).unwrap_or(LinuxError::EINVAL));
            }
            write_value_to_user(old_limit, local)?;
        }

        if !new_limit.is_null() {
            let mut local = read_value_from_user(new_limit)?;
            let res = unsafe { arceos_posix_api::sys_setrlimit(resource, &mut local as *mut _) };
            if res < 0 {
                return Err(LinuxError::try_from(-res).unwrap_or(LinuxError::EINVAL));
            }
        }

        Ok(0)
    })
}

pub(crate) fn sys_rt_sigaction(
    signum: i32,
    act: *const c_void,
    oldact: *mut c_void,
    sigsetsize: usize,
) -> isize {
    crate::signal::sys_rt_sigaction(signum, act, oldact, sigsetsize)
}

pub(crate) fn sys_rt_sigprocmask(
    how: i32,
    set: *const c_void,
    oldset: *mut c_void,
    sigsetsize: usize,
) -> isize {
    crate::signal::sys_rt_sigprocmask(how, set, oldset, sigsetsize)
}

pub(crate) fn sys_rt_sigsuspend(set: *const c_void, sigsetsize: usize) -> isize {
    crate::signal::sys_rt_sigsuspend(set, sigsetsize)
}

pub(crate) fn sys_rt_sigtimedwait(
    set: *const c_void,
    info: *mut c_void,
    timeout: *const c_void,
    sigsetsize: usize,
) -> isize {
    crate::signal::sys_rt_sigtimedwait(set, info, timeout, sigsetsize)
}

pub(crate) fn sys_rt_sigreturn() -> isize {
    crate::signal::sys_rt_sigreturn()
}

pub(crate) fn sys_getitimer(which: i32, curr_value: *mut c_void) -> isize {
    crate::signal::sys_getitimer(which, curr_value)
}

pub(crate) fn sys_setitimer(which: i32, new_value: *const c_void, old_value: *mut c_void) -> isize {
    crate::signal::sys_setitimer(which, new_value, old_value)
}

pub(crate) fn sys_set_robust_list(head: usize, len: usize) -> isize {
    syscall_body!(sys_set_robust_list, {
        if len != core::mem::size_of::<usize>() * 3 {
            return Err(LinuxError::EINVAL);
        }
        if head == 0 {
            return Err(LinuxError::EINVAL);
        }
        current()
            .task_ext()
            .set_robust_list(head as u64, len as u64);
        Ok(0)
    })
}

pub(crate) fn sys_get_robust_list(pid: i32, head_ptr: *mut usize, len_ptr: *mut usize) -> isize {
    syscall_body!(sys_get_robust_list, {
        if head_ptr.is_null() || len_ptr.is_null() {
            return Err(LinuxError::EFAULT);
        }

        let task = if pid == 0 {
            current().as_task_ref().clone()
        } else if pid > 0 {
            find_live_task_by_tid(pid as u64).ok_or(LinuxError::ESRCH)?
        } else {
            return Err(LinuxError::ESRCH);
        };

        write_value_to_user(head_ptr, task.task_ext().robust_list_head() as usize)?;
        write_value_to_user(len_ptr, task.task_ext().robust_list_len() as usize)?;
        Ok(0)
    })
}

pub(crate) fn sys_exit(status: i32) -> ! {
    if current().task_ext().exec_path().ends_with("/mprotect02") {
        warn!(
            "[mprotect02-exit] task={} pid={} syscall=exit status={}",
            current().id_name(),
            current().task_ext().proc_id,
            status
        );
    }
    #[cfg(target_arch = "riscv64")]
    if should_trace_riscv_libcbench() && take_riscv_libcbench_trace_slot(64) {
        let curr = current();
        warn!(
            "[rv-libcbench-thread] exit task={} proc_id={} status={} clear_child_tid={:#x} now_ms={}",
            curr.id_name(),
            curr.task_ext().proc_id,
            status,
            curr.task_ext().clear_child_tid(),
            monotonic_time_nanos() / 1_000_000
        );
    }
    if let Some(slot) = take_busybox_trace_slot() {
        warn!(
            "[online-busybox-proc:{}:{}] exit task={} exec_path={} status={} now_ms={}",
            busybox_trace_arch_tag(),
            slot,
            current().id_name(),
            current().task_ext().exec_path(),
            status,
            monotonic_time_nanos() / 1_000_000
        );
    }
    crate::task::exit_current_task(crate::task::wait_status_exited(status), true, true);
}

pub(crate) fn sys_exit_group(status: i32) -> ! {
    if current().task_ext().exec_path().ends_with("/mprotect02") {
        warn!(
            "[mprotect02-exit] task={} pid={} syscall=exit_group status={}",
            current().id_name(),
            current().task_ext().proc_id,
            status
        );
    }
    #[cfg(target_arch = "riscv64")]
    if should_trace_riscv_libcbench() && take_riscv_libcbench_trace_slot(64) {
        let curr = current();
        warn!(
            "[rv-libcbench-thread] exit_group task={} proc_id={} status={} clear_child_tid={:#x} now_ms={}",
            curr.id_name(),
            curr.task_ext().proc_id,
            status,
            curr.task_ext().clear_child_tid(),
            monotonic_time_nanos() / 1_000_000
        );
    }
    if let Some(slot) = take_busybox_trace_slot() {
        warn!(
            "[online-busybox-proc:{}:{}] exit_group task={} exec_path={} status={} now_ms={}",
            busybox_trace_arch_tag(),
            slot,
            current().id_name(),
            current().task_ext().exec_path(),
            status,
            monotonic_time_nanos() / 1_000_000
        );
    }
    let curr = current();
    let tid = curr.id().as_u64();
    let proc_id = curr.task_ext().proc_id;
    if tid == curr.task_ext().leader_tid() {
        crate::task::terminate_other_threads_in_group(proc_id, tid, 9);
        crate::task::wait_for_other_threads_in_group_to_exit(proc_id, tid);
    }
    crate::task::exit_current_task(crate::task::wait_status_exited(status), true, true);
}

/// To set the clear_child_tid field in the task extended data.
///
/// The set_tid_address() always succeeds
pub(crate) fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    syscall_body!(sys_set_tid_address, {
        let curr = current();
        #[cfg(target_arch = "riscv64")]
        if should_trace_riscv_libcbench() && take_riscv_libcbench_trace_slot(64) {
            warn!(
                "[rv-libcbench-thread] set_tid_address task={} proc_id={} tid_ptr={:#x} now_ms={}",
                curr.id_name(),
                curr.task_ext().proc_id,
                tid_ptd as usize,
                monotonic_time_nanos() / 1_000_000
            );
        }
        curr.task_ext().set_clear_child_tid(tid_ptd as _);
        Ok(if curr.id().as_u64() == curr.task_ext().leader_tid() {
            curr.task_ext().proc_id as isize
        } else {
            curr.id().as_u64() as isize
        })
    })
}

#[cfg(target_arch = "x86_64")]
pub(crate) fn sys_arch_prctl(code: i32, addr: u64) -> isize {
    use axerrno::LinuxError;
    syscall_body!(sys_arch_prctl, {
        match ArchPrctlCode::try_from(code) {
            // TODO: check the legality of the address
            Ok(ArchPrctlCode::SetFs) => {
                unsafe {
                    axhal::arch::write_thread_pointer(addr as usize);
                }
                Ok(0)
            }
            Ok(ArchPrctlCode::GetFs) => {
                write_value_to_user(addr as *mut u64, axhal::arch::read_thread_pointer() as u64)?;
                Ok(0)
            }
            Ok(ArchPrctlCode::SetGs) => {
                unsafe {
                    x86::msr::wrmsr(x86::msr::IA32_KERNEL_GSBASE, addr);
                }
                Ok(0)
            }
            Ok(ArchPrctlCode::GetGs) => {
                write_value_to_user(
                    addr as *mut u64,
                    x86::msr::rdmsr(x86::msr::IA32_KERNEL_GSBASE),
                )?;
                Ok(0)
            }
            _ => Err(LinuxError::ENOSYS),
        }
    })
}

pub(crate) fn sys_clone(
    tf: &TrapFrame,
    flags: usize,
    user_stack: usize,
    ptid: usize,
    arg3: usize,
    arg4: usize,
) -> isize {
    syscall_body!(sys_clone, {
        let curr_task = current();
        let trace_fork13 = should_trace_fork13();
        let report_epoll_progress = should_report_epoll_ltp_progress(curr_task.name());
        #[cfg(target_arch = "riscv64")]
        if trace_fork13 {
            warn!(
                "[fork13-clone] task={} pid={} flags={:#x} user_stack={:#x} ptid={:#x} arg3={:#x} arg4={:#x} sp={:#x} ra={:#x} s0={:#x}",
                curr_task.id_name(),
                curr_task.task_ext().proc_id,
                flags,
                user_stack,
                ptid,
                arg3,
                arg4,
                tf.get_sp(),
                tf.regs.ra,
                tf.regs.s0,
            );
        }
        #[cfg(target_arch = "riscv64")]
        if should_trace_riscv_libcbench() && take_riscv_libcbench_trace_slot(64) {
            warn!(
                "[rv-libcbench-thread] clone-enter task={} proc_id={} flags={:#x} user_stack={:#x} ptid={:#x} arg3={:#x} arg4={:#x} now_ms={}",
                curr_task.id_name(),
                curr_task.task_ext().proc_id,
                flags,
                user_stack,
                ptid,
                arg3,
                arg4,
                monotonic_time_nanos() / 1_000_000
            );
        }
        if let Some(slot) = take_busybox_trace_slot() {
            warn!(
                "[online-busybox-proc:{}:{}] clone-enter task={} exec_path={} flags={:#x} user_stack={:#x} ptid={:#x} tls={:#x} ctid={:#x} now_ms={}",
                busybox_trace_arch_tag(),
                slot,
                curr_task.id_name(),
                curr_task.task_ext().exec_path(),
                flags,
                user_stack,
                ptid,
                arg3,
                arg4,
                monotonic_time_nanos() / 1_000_000
            );
        }
        #[cfg(feature = "contest_diag_logs")]
        if curr_task.name().contains("userboot") {
            let mut eval_localvar_stop = 0usize;
            let localvar_stop_ok = curr_task
                .task_ext()
                .aspace
                .lock()
                .read(memory_addr::VirtAddr::from_usize(0x3fffff740), unsafe {
                    core::slice::from_raw_parts_mut(
                        (&mut eval_localvar_stop as *mut usize).cast::<u8>(),
                        core::mem::size_of::<usize>(),
                    )
                })
                .is_ok();
            crate::diag_warn!(
                "clone task={} flags={:#x} user_stack={:#x} ptid={:#x} tls={:#x} ctid={:#x} localvar_stop@0x3fffff740={:#x} localvar_stop_ok={} now_ms={}",
                curr_task.id_name(),
                flags,
                user_stack,
                ptid,
                arg3,
                arg4,
                eval_localvar_stop,
                localvar_stop_ok,
                monotonic_time_nanos() / 1_000_000
            );
        }
        if flags != 0x11 {
            crate::diag_warn!(
                "sys_clone special flags={:#x} user_stack={:#x} ptid={:#x} tls/arg3={:#x} ctid/arg4={:#x}",
                flags,
                user_stack,
                ptid,
                arg3,
                arg4
            );
        }
        #[cfg(target_arch = "loongarch64")]
        let (ctid, tls) = (arg3, arg4);
        #[cfg(not(target_arch = "loongarch64"))]
        let (tls, ctid) = (arg3, arg4);

        let clone_flags = CloneFlags::from_bits_truncate((flags & !0x3f) as u32);
        let stack = if user_stack == 0 {
            None
        } else {
            Some(user_stack)
        };
        let new_task_id = curr_task
            .task_ext()
            .clone_task(tf, flags, stack, ptid, tls, ctid)
            .map_err(|err| {
                if clone_flags.contains(CloneFlags::CLONE_THREAD) {
                    warn!(
                        "clone thread failed: task={} flags={:#x} ptid={:#x} tls={:#x} ctid={:#x} err={:?}",
                        curr_task.id_name(),
                        flags,
                        ptid,
                        tls,
                        ctid,
                        err
                    );
                }
                LinuxError::from(err)
            })?;
        #[cfg(target_arch = "riscv64")]
        if trace_fork13 {
            warn!(
                "[fork13-clone] ok parent_task={} parent_pid={} child_tid={} ret_sp={:#x} ret_ra={:#x} ret_s0={:#x}",
                curr_task.id_name(),
                curr_task.task_ext().proc_id,
                new_task_id,
                tf.get_sp(),
                tf.regs.ra,
                tf.regs.s0,
            );
        }
        #[cfg(target_arch = "riscv64")]
        if should_trace_riscv_libcbench() && take_riscv_libcbench_trace_slot(64) {
            warn!(
                "[rv-libcbench-thread] clone-ok parent_task={} parent_proc_id={} child_tid={} tls={:#x} ctid={:#x} now_ms={}",
                curr_task.id_name(),
                curr_task.task_ext().proc_id,
                new_task_id,
                tls,
                ctid,
                monotonic_time_nanos() / 1_000_000
            );
        }
        if let Some(slot) = take_busybox_trace_slot() {
            warn!(
                "[online-busybox-proc:{}:{}] clone-ok parent_task={} parent_pid={} child_tid={} flags={:#x} tls={:#x} ctid={:#x} now_ms={}",
                busybox_trace_arch_tag(),
                slot,
                curr_task.id_name(),
                curr_task.task_ext().proc_id,
                new_task_id,
                flags,
                tls,
                ctid,
                monotonic_time_nanos() / 1_000_000
            );
        }
        if report_epoll_progress {
            crate::note_competition_pass_point();
        }
        Ok(new_task_id as isize)
    })
}

pub(crate) fn sys_clone3(tf: &TrapFrame, cl_args: *const CloneArgs, size: usize) -> isize {
    syscall_body!(sys_clone3, {
        let args = read_clone3_args_from_user(cl_args, size)?;
        validate_clone3_args(&args)?;
        let curr_task = current();
        let clone_flags = CloneFlags::from_bits_truncate(args.flags as u32);
        let clone_into_cgroup = (args.flags & CLONE_INTO_CGROUP_FLAG) != 0;
        let flags = args.flags as usize | (args.exit_signal as usize & 0x3f);
        let stack = if args.stack == 0 {
            None
        } else {
            let top = args
                .stack
                .checked_add(args.stack_size)
                .ok_or(LinuxError::EINVAL)?;
            Some(top as usize)
        };
        let tid = curr_task
            .task_ext()
            .clone_task(
                tf,
                flags,
                stack,
                args.parent_tid as usize,
                args.tls as usize,
                args.child_tid as usize,
            )
            .map_err(|err| LinuxError::from(err))?;
        if clone_flags.contains(CloneFlags::CLONE_PIDFD) {
            let pidfd = add_pidfd_for_pid(tid as usize, 0)?;
            write_value_to_user(args.pidfd as *mut i32, pidfd)?;
        }
        if clone_into_cgroup {
            attach_pid_to_cgroup(args.cgroup as c_int, tid as usize)?;
        }
        Ok(tid as isize)
    })
}

pub(crate) fn sys_unshare(flags: usize) -> isize {
    syscall_body!(sys_unshare, {
        let supported = CloneFlags::CLONE_FILES
            | CloneFlags::CLONE_FS
            | CloneFlags::CLONE_NEWNS
            | CloneFlags::CLONE_NEWTIME;
        if flags & !(supported.bits() as usize) != 0 {
            return Err(LinuxError::EINVAL);
        }
        let flags = CloneFlags::from_bits_truncate(flags as u32);
        if flags.contains(CloneFlags::CLONE_NEWNS) && axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }
        if flags.contains(CloneFlags::CLONE_NEWTIME) {
            current().task_ext().unshare_time_namespace();
        }
        Ok(0)
    })
}

pub(crate) fn sys_setns(fd: c_int, nstype: c_int) -> isize {
    syscall_body!(sys_setns, {
        if nstype != 0 && nstype != CloneFlags::CLONE_NEWTIME.bits() as c_int {
            return Err(LinuxError::EINVAL);
        }
        setns_time_namespace_from_fd(fd)?;
        Ok(0)
    })
}

pub(crate) fn sys_pidfd_open(pid: i32, flags: u32) -> isize {
    syscall_body!(sys_pidfd_open, {
        if pid <= 0 {
            return Err(LinuxError::EINVAL);
        }
        let supported = arceos_posix_api::ctypes::O_NONBLOCK as u32;
        if flags & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }
        if find_process_leader_by_pid(pid as usize).is_none() {
            return Err(LinuxError::ESRCH);
        }
        add_pidfd_for_pid(pid as usize, flags).map(|fd| fd as isize)
    })
}

pub(crate) fn sys_pidfd_send_signal(
    pidfd: c_int,
    signum: c_int,
    info: *const c_void,
    flags: u32,
) -> isize {
    syscall_body!(sys_pidfd_send_signal, {
        if flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        if signum < 0 || signum as u64 > MAX_SIGNAL_NUMBER {
            return Err(LinuxError::EINVAL);
        }
        let pid = pid_from_pidfd(pidfd)?;
        if axfs::api::current_euid() != 0 && pid != current().task_ext().proc_id {
            return Err(LinuxError::EPERM);
        }
        let task = find_process_leader_by_pid(pid).ok_or(LinuxError::ESRCH)?;
        if signum == 0 {
            return Ok(0);
        }

        if info.is_null() {
            crate::signal::send_signal_to_task(&task, signum as usize);
        } else {
            let user_info = read_value_from_user(info as *const UserSigInfo)?;
            if user_info.signo() != signum {
                return Err(LinuxError::EINVAL);
            }
            send_signal_to_task_with_siginfo(
                &task,
                signum as usize,
                current().task_ext().proc_id as i32,
                axfs::api::current_uid(),
                user_info.signal_value(),
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_pidfd_getfd(pidfd: c_int, targetfd: c_int, flags: u32) -> isize {
    syscall_body!(sys_pidfd_getfd, {
        if flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        if targetfd < 0 {
            return Err(LinuxError::EBADF);
        }

        let pid = pid_from_pidfd(pidfd)?;
        if axfs::api::current_euid() != 0 && pid != current().task_ext().proc_id {
            return Err(LinuxError::EPERM);
        }

        let task = find_process_leader_by_pid(pid).ok_or(LinuxError::ESRCH)?;
        let file = FD_TABLE
            .deref_from(&task.task_ext().ns)
            .read()
            .get(targetfd as usize)
            .cloned()
            .ok_or(LinuxError::EBADF)?;
        let new_fd = add_file_like(file)?;
        let ret = api::sys_fcntl(
            new_fd,
            api::ctypes::F_SETFD as _,
            api::ctypes::FD_CLOEXEC as usize,
        );
        if ret < 0 {
            let _ = api::sys_close(new_fd);
            return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EINVAL));
        }
        Ok(new_fd as isize)
    })
}

pub(crate) fn sys_kcmp(pid1: i32, pid2: i32, kcmp_type: i32, idx1: usize, idx2: usize) -> isize {
    syscall_body!(sys_kcmp, {
        if pid1 < 0 || pid2 < 0 {
            return Err(LinuxError::EINVAL);
        }
        let task1 = task_by_pid(pid1)?;
        let task2 = task_by_pid(pid2)?;
        let different = match kcmp_type {
            KCMP_FILE => {
                let file1 = FD_TABLE
                    .deref_from(&task1.task_ext().ns)
                    .read()
                    .get(idx1)
                    .cloned()
                    .ok_or(LinuxError::EBADF)?;
                let file2 = FD_TABLE
                    .deref_from(&task2.task_ext().ns)
                    .read()
                    .get(idx2)
                    .cloned()
                    .ok_or(LinuxError::EBADF)?;
                !Arc::ptr_eq(&file1, &file2)
            }
            KCMP_VM => !Arc::ptr_eq(&task1.task_ext().aspace, &task2.task_ext().aspace),
            KCMP_FILES => !Arc::ptr_eq(
                &FD_TABLE.deref_from(&task1.task_ext().ns).share(),
                &FD_TABLE.deref_from(&task2.task_ext().ns).share(),
            ),
            KCMP_FS => {
                let cwd1 = CURRENT_DIR_PATH.deref_from(&task1.task_ext().ns).share();
                let cwd2 = CURRENT_DIR_PATH.deref_from(&task2.task_ext().ns).share();
                let cred1 = CURRENT_FS_CRED.deref_from(&task1.task_ext().ns).share();
                let cred2 = CURRENT_FS_CRED.deref_from(&task2.task_ext().ns).share();
                !Arc::ptr_eq(&cwd1, &cwd2) || !Arc::ptr_eq(&cred1, &cred2)
            }
            KCMP_SIGHAND => {
                task1.task_ext().signals.lock().actions_identity()
                    != task2.task_ext().signals.lock().actions_identity()
            }
            KCMP_IO => task1.task_ext().io_context_id() != task2.task_ext().io_context_id(),
            KCMP_SYSVSEM => task1.task_ext().sysvsem_id() != task2.task_ext().sysvsem_id(),
            _ => return Err(LinuxError::EINVAL),
        };
        Ok(different as isize)
    })
}

pub(crate) fn sys_waitid(idtype: i32, id: usize, infop: *mut WaitSigInfo, options: u32) -> isize {
    syscall_body!(sys_waitid, {
        let supported =
            WSTOPPED | WEXITED | WaitFlags::WCONTINUED.bits() | WaitFlags::WNOHANG.bits() | WNOWAIT;
        let wanted = WSTOPPED | WEXITED | WaitFlags::WCONTINUED.bits();
        if options & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }
        if options & wanted == 0 {
            return Err(LinuxError::EINVAL);
        }

        let target = waitid_target_pid(idtype, id)?;
        let option_flag = WaitFlags::from_bits(options & WaitFlags::WNOHANG.bits()).unwrap();
        let consume = (options & WNOWAIT) == 0;
        loop {
            if let Some((child_pid, si_code, si_status)) =
                waitid_child_state_event(target.selector, options, consume)
            {
                write_waitid_siginfo_fields(infop, child_pid, si_code, si_status)?;
                return Ok(0);
            }

            if (options & WEXITED) != 0 {
                match waitid_exited_event(target.selector, consume) {
                    Ok(Some((child_pid, exit_code))) => {
                        write_waitid_siginfo(infop, child_pid, exit_code)?;
                        return Ok(0);
                    }
                    Ok(None) => {}
                    Err(WaitStatus::NotExist) => return Err(LinuxError::ECHILD),
                    Err(WaitStatus::Running) => {}
                    Err(_) => return Err(LinuxError::ECHILD),
                }
            }

            match wait_child_status(current().as_task_ref(), target.selector) {
                WaitStatus::NotExist => return Err(LinuxError::ECHILD),
                WaitStatus::Running => {
                    if target.pidfd_nonblocking {
                        return Err(LinuxError::EAGAIN);
                    }
                    if option_flag.contains(WaitFlags::WNOHANG) {
                        waitid_zero_info(infop)?;
                        return Ok(0);
                    }
                    let curr_task = current();
                    loop {
                        let observed_seq = curr_task.task_ext().child_wait_event_seq();
                        let child_status =
                            wait_child_status(curr_task.as_task_ref(), target.selector);
                        if child_status != WaitStatus::Running
                            || waitid_child_state_event(target.selector, options, false).is_some()
                        {
                            break;
                        }
                        if crate::signal::current_has_interrupting_signal(true) {
                            return Err(LinuxError::EINTR);
                        }
                        wait_for_child_wait_event(curr_task.as_task_ref(), observed_seq);
                    }
                }
                _ => {}
            }
        }
    })
}

pub(crate) fn sys_wait4(pid: i32, exit_code_ptr: *mut i32, option: u32) -> isize {
    syscall_body!(sys_wait4, {
        let option_flag = WaitFlags::from_bits(option).ok_or(LinuxError::EINVAL)?;
        let curr = current();
        let trace_fork13 = should_trace_fork13();
        let selector = wait_child_selector_from_waitpid(curr.as_task_ref(), pid)?;
        let report_epoll_progress = should_report_epoll_ltp_progress(curr.name());
        if let Some(slot) = take_busybox_trace_slot() {
            warn!(
                "[online-busybox-proc:{}:{}] wait4-enter task={} exec_path={} pid={} option={:#x} now_ms={}",
                busybox_trace_arch_tag(),
                slot,
                current().id_name(),
                current().task_ext().exec_path(),
                pid,
                option,
                monotonic_time_nanos() / 1_000_000
            );
        }
        #[cfg(feature = "contest_diag_logs")]
        let curr_task = current();
        #[cfg(feature = "contest_diag_logs")]
        if curr_task.name().contains("userboot") {
            let trap =
                crate::task::read_trapframe_from_kstack(curr_task.get_kernel_stack_top().unwrap());
            let mut caller_ra = 0usize;
            let mut eval_localvar_stop = 0usize;
            let caller_ra_ok = curr_task
                .task_ext()
                .aspace
                .lock()
                .read(
                    memory_addr::VirtAddr::from_usize(
                        trap.get_sp() + core::mem::size_of::<usize>(),
                    ),
                    unsafe {
                        core::slice::from_raw_parts_mut(
                            (&mut caller_ra as *mut usize).cast::<u8>(),
                            core::mem::size_of::<usize>(),
                        )
                    },
                )
                .is_ok();
            let localvar_stop_ok = curr_task
                .task_ext()
                .aspace
                .lock()
                .read(memory_addr::VirtAddr::from_usize(0x3fffff740), unsafe {
                    core::slice::from_raw_parts_mut(
                        (&mut eval_localvar_stop as *mut usize).cast::<u8>(),
                        core::mem::size_of::<usize>(),
                    )
                })
                .is_ok();
            crate::diag_warn!(
                "wait4 task={} pid={} status_ptr={:#x} option={:#x} s2={:#x} ra={:#x} caller_ra={:#x} caller_ra_ok={} localvar_stop@0x3fffff740={:#x} localvar_stop_ok={} sp={:#x} now_ms={}",
                curr_task.id_name(),
                pid,
                exit_code_ptr as usize,
                option,
                trap.regs.s2,
                trap.regs.ra,
                caller_ra,
                caller_ra_ok,
                eval_localvar_stop,
                localvar_stop_ok,
                trap.get_sp(),
                monotonic_time_nanos() / 1_000_000
            );
        }
        loop {
            #[cfg(target_arch = "riscv64")]
            if trace_fork13 {
                let trap =
                    crate::task::read_trapframe_from_kstack(curr.get_kernel_stack_top().unwrap());
                warn!(
                    "[fork13-wait4] task={} pid={} status_ptr={:#x} option={:#x} sp={:#x} ra={:#x} s0={:#x}",
                    curr.id_name(),
                    pid,
                    exit_code_ptr as usize,
                    option,
                    trap.get_sp(),
                    trap.regs.ra,
                    trap.regs.s0,
                );
            }
            if let Some((child_pid, wait_status)) =
                wait4_child_state_event(selector, option_flag, true)
            {
                if report_epoll_progress {
                    crate::note_competition_pass_point();
                }
                if !exit_code_ptr.is_null() {
                    crate::usercopy::write_value_to_user(exit_code_ptr, wait_status)?;
                }
                return Ok(child_pid as isize);
            }

            let answer = wait_child(selector);
            match answer {
                Ok((pid, exit_code)) => {
                    if report_epoll_progress {
                        crate::note_competition_pass_point();
                    }
                    if let Some(slot) = take_busybox_trace_slot() {
                        warn!(
                            "[online-busybox-proc:{}:{}] wait4-return task={} exec_path={} child_pid={} exit_code={} now_ms={}",
                            busybox_trace_arch_tag(),
                            slot,
                            current().id_name(),
                            current().task_ext().exec_path(),
                            pid,
                            exit_code,
                            monotonic_time_nanos() / 1_000_000
                        );
                    }
                    #[cfg(feature = "contest_diag_logs")]
                    if curr_task.name().contains("userboot") {
                        let trap = crate::task::read_trapframe_from_kstack(
                            curr_task.get_kernel_stack_top().unwrap(),
                        );
                        crate::diag_warn!(
                            "wait4 return task={} child_pid={} exit_code={} option={:#x} s2={:#x} ra={:#x} sp={:#x}",
                            curr_task.id_name(),
                            pid,
                            exit_code,
                            option,
                            trap.regs.s2,
                            trap.regs.ra,
                            trap.get_sp()
                        );
                    }
                    if !exit_code_ptr.is_null() {
                        crate::usercopy::write_value_to_user(exit_code_ptr, exit_code)?;
                    }
                    return Ok(pid as isize);
                }
                Err(status) => match status {
                    WaitStatus::NotExist => {
                        #[cfg(feature = "contest_diag_logs")]
                        if curr_task.name().contains("userboot") {
                            let trap = crate::task::read_trapframe_from_kstack(
                                curr_task.get_kernel_stack_top().unwrap(),
                            );
                            crate::diag_warn!(
                                "wait4 nochild task={} pid={} option={:#x} s2={:#x} ra={:#x} sp={:#x}",
                                curr_task.id_name(),
                                pid,
                                option,
                                trap.regs.s2,
                                trap.regs.ra,
                                trap.get_sp()
                            );
                        }
                        return Err(LinuxError::ECHILD);
                    }
                    WaitStatus::Running => {
                        if let Some(slot) = take_busybox_trace_slot() {
                            warn!(
                                "[online-busybox-proc:{}:{}] wait4-block task={} exec_path={} pid={} option={:#x} now_ms={}",
                                busybox_trace_arch_tag(),
                                slot,
                                current().id_name(),
                                current().task_ext().exec_path(),
                                pid,
                                option,
                                monotonic_time_nanos() / 1_000_000
                            );
                        }
                        #[cfg(feature = "contest_diag_logs")]
                        if curr_task.name().contains("userboot") {
                            crate::diag_warn!(
                                "wait4 running task={} pid={} option={:#x}",
                                curr_task.id_name(),
                                pid,
                                option
                            );
                        }
                        if option_flag.contains(WaitFlags::WNOHANG) {
                            return Ok(0);
                        } else {
                            let curr_task = current();
                            loop {
                                let observed_seq = curr_task.task_ext().child_wait_event_seq();
                                let status = crate::task::wait_child_status(
                                    curr_task.as_task_ref(),
                                    selector,
                                );
                                if status != WaitStatus::Running
                                    || wait4_child_state_event(selector, option_flag, false)
                                        .is_some()
                                {
                                    break;
                                }
                                if crate::signal::current_has_interrupting_signal(true) {
                                    return Err(LinuxError::EINTR);
                                }
                                wait_for_child_wait_event(curr_task.as_task_ref(), observed_seq);
                            }
                        }
                    }
                    _ => {
                        panic!("Shouldn't reach here!");
                    }
                },
            }
        }
    })
}

fn read_exec_user_c_string(ptr: *const c_char, max_len: usize) -> Result<String, LinuxError> {
    if ptr.is_null() {
        return Err(LinuxError::EFAULT);
    }

    let mut bytes = Vec::new();
    for index in 0..max_len {
        let byte = read_value_from_user(unsafe { ptr.add(index) as *const u8 })?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| LinuxError::EINVAL);
        }
        bytes.push(byte);
    }

    Err(LinuxError::E2BIG)
}

fn read_exec_c_string_array(values: *const usize, name: &str) -> Result<Vec<String>, LinuxError> {
    const MAX_EXEC_ARGS: usize = 256;
    const MAX_EXEC_ARG_LEN: usize = 4096;

    #[cfg(not(feature = "contest_diag_logs"))]
    let _ = name;

    if values.is_null() {
        return Ok(Vec::new());
    }

    let mut args = Vec::new();
    for index in 0..MAX_EXEC_ARGS {
        let arg_ptr = read_value_from_user(unsafe { values.add(index) })? as *const c_char;
        if arg_ptr.is_null() {
            return Ok(args);
        }
        match read_exec_user_c_string(arg_ptr, MAX_EXEC_ARG_LEN) {
            Ok(arg) => args.push(arg),
            Err(err) => {
                crate::diag_warn!(
                    "execve read {}[{}] failed: ptr={:#x} err={:?}",
                    name,
                    index,
                    arg_ptr as usize,
                    err
                );
                return Err(err);
            }
        }
    }
    Err(LinuxError::E2BIG)
}

pub fn sys_execve(path: *const c_char, argv: *const usize, envp: *const usize) -> isize {
    syscall_body!(sys_execve, {
        let path_str = match read_exec_user_c_string(path, 4096) {
            Ok(path_str) => path_str,
            Err(err) => {
                crate::diag_warn!(
                    "execve read path failed: ptr={:#x} err={:?}",
                    path as usize,
                    err
                );
                return Err(err);
            }
        };
        let path_owned = path_str;
        crate::syscall_imp::validate_path_components(path_owned.as_str())?;
        let absolute_path = crate::mm::absolute_exec_path(path_owned.as_str());
        crate::syscall_imp::verify_searchable_prefixes(absolute_path.as_str())?;
        if crate::task::is_path_open_for_write(absolute_path.as_str()) {
            return Err(LinuxError::ETXTBSY);
        }

        let mut args = read_exec_c_string_array(argv, "argv")?;
        if args.is_empty() {
            args.push(path_owned.clone());
        }
        let env = read_exec_c_string_array(envp, "envp")?;
        if let Some(slot) = take_busybox_exec_trace_slot(&path_owned) {
            warn!(
                "[online-busybox-proc:{}:{}] execve task={} exec_path={} path={} argc={} argv0={} now_ms={}",
                busybox_trace_arch_tag(),
                slot,
                current().id_name(),
                current().task_ext().exec_path(),
                path_owned,
                args.len(),
                args.first().map(String::as_str).unwrap_or("<none>"),
                monotonic_time_nanos() / 1_000_000
            );
        }
        #[cfg(feature = "contest_diag_logs")]
        if current().name().contains("userboot") {
            crate::diag_warn!(
                "execve task={} path={} argc={} argv0={} now_ms={}",
                current().id_name(),
                path_owned,
                args.len(),
                args.first().map(String::as_str).unwrap_or("<none>"),
                monotonic_time_nanos() / 1_000_000
            );
        }

        if let Err(e) = crate::task::exec_with_args_env(&path_owned, args, env) {
            if !crate::mm::is_expected_exec_lookup_error(&e) {
                crate::task::log_exec_failure(&path_owned, &e);
            }
            crate::task::maybe_terminate_on_exec_failure(&path_owned, &e);
            return Err::<isize, _>(e.into());
        }

        unreachable!("execve should never return");
    })
}

fn read_exec_image_from_fd(fd: i32) -> Result<(String, Vec<u8>), LinuxError> {
    let file = get_file_like(fd)?;
    let file = file
        .into_any()
        .downcast::<api::File>()
        .map_err(|_| LinuxError::EACCES)?;
    let size = file.inner().lock().get_attr().map_err(LinuxError::from)?.size() as usize;
    if size > 64 * 1024 * 1024 {
        return Err(LinuxError::E2BIG);
    }
    let mut image = vec![0u8; size];
    let mut read = 0usize;
    while read < size {
        let n = file
            .inner()
            .lock()
            .read_at_for_exec(read as u64, &mut image[read..])
            .map_err(LinuxError::from)?;
        if n == 0 {
            break;
        }
        read += n;
    }
    image.truncate(read);
    Ok((file.path().to_string(), image))
}

pub fn sys_execveat(
    dirfd: i32,
    path: *const c_char,
    argv: *const usize,
    envp: *const usize,
    flags: i32,
) -> isize {
    syscall_body!(sys_execveat, {
        if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0 {
            return Err(LinuxError::EINVAL);
        }
        let path_str = read_exec_user_c_string(path, 4096)?;
        let (path_owned, image) = if path_str.is_empty() {
            if flags & AT_EMPTY_PATH == 0 {
                return Err(LinuxError::ENOENT);
            }
            let (fd_path, image) = read_exec_image_from_fd(dirfd)?;
            (fd_path, Some(image))
        } else {
            if !path_str.starts_with('/') && dirfd != api::AT_FDCWD as i32 {
                if get_file_like(dirfd).is_err() {
                    return Err(LinuxError::EBADF);
                }
                if Directory::from_fd(dirfd).is_err() {
                    return Err(LinuxError::ENOTDIR);
                }
            }
            let resolved = crate::syscall_imp::handle_kernel_path(
                dirfd as isize,
                path_str.as_str(),
                false,
            )?;
            (resolved.to_string(), None)
        };
        crate::syscall_imp::validate_path_components(path_owned.as_str())?;
        if flags & AT_SYMLINK_NOFOLLOW != 0 {
            let attr = axfs::api::metadata_raw_nofollow(path_owned.as_str()).map_err(LinuxError::from)?;
            if attr.file_type().is_symlink() {
                return Err(LinuxError::ELOOP);
            }
        }
        if image.is_none() {
            let absolute_path = crate::mm::absolute_exec_path(path_owned.as_str());
            crate::syscall_imp::verify_searchable_prefixes(absolute_path.as_str())?;
            if crate::task::is_path_open_for_write(absolute_path.as_str()) {
                return Err(LinuxError::ETXTBSY);
            }
        }

        let mut args = read_exec_c_string_array(argv, "argv")?;
        if args.is_empty() {
            args.push(path_owned.clone());
        }
        let env = read_exec_c_string_array(envp, "envp")?;
        let result = if let Some(image) = image {
            crate::task::exec_with_args_env_from_bytes(&path_owned, image, args, env)
        } else {
            crate::task::exec_with_args_env(&path_owned, args, env)
        };
        if let Err(e) = result {
            if !crate::mm::is_expected_exec_lookup_error(&e) {
                crate::task::log_exec_failure(&path_owned, &e);
            }
            crate::task::maybe_terminate_on_exec_failure(&path_owned, &e);
            return Err::<isize, _>(e.into());
        }

        unreachable!("execveat should never return");
    })
}
