use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
};
use core::{
    ffi::c_char,
    ffi::c_long,
    ffi::c_void,
    mem::size_of,
    ptr::NonNull,
    sync::atomic::{fence, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use arceos_posix_api::ctypes::{sockaddr, sockaddr_in, socklen_t, timespec, timeval};
use arceos_posix_api::{get_file_like, FD_FLAGS};
use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use axhal::time::{monotonic_time_nanos, NANOS_PER_MICROS, NANOS_PER_SEC};
use axsync::Mutex;
use axtask::{current, TaskExtRef, WaitQueue};
use memory_addr::VirtAddr;
use spin::Once;

use crate::{
    syscall_body,
    syscall_imp::fs::resolve_existing_path,
    timekeeping::{monotonic_deadline_from_clock, timespec_to_nanos},
    usercopy::{
        copy_from_user, copy_to_user, ensure_user_range, read_value_from_user, write_value_to_user,
    },
};

#[cfg(target_arch = "riscv64")]
fn should_trace_riscv_libcbench_futex() -> bool {
    false
}

fn should_trace_nice05_futex() -> bool {
    let curr = current();
    let exec_path = curr.task_ext().exec_path();
    exec_path.contains("nice05")
}

#[cfg(target_arch = "riscv64")]
fn take_riscv_libcbench_futex_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < limit
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub(crate) struct Rusage {
    ru_utime: timeval,
    ru_stime: timeval,
    ru_maxrss: c_long,
    ru_ixrss: c_long,
    ru_idrss: c_long,
    ru_isrss: c_long,
    ru_minflt: c_long,
    ru_majflt: c_long,
    ru_nswap: c_long,
    ru_inblock: c_long,
    ru_oublock: c_long,
    ru_msgsnd: c_long,
    ru_msgrcv: c_long,
    ru_nsignals: c_long,
    ru_nvcsw: c_long,
    ru_nivcsw: c_long,
}

const RUSAGE_SELF: i32 = 0;
const RUSAGE_CHILDREN: i32 = -1;
const RUSAGE_THREAD: i32 = 1;
const SOCK_NONBLOCK: i32 = 0o0004000;
const SOCK_CLOEXEC: i32 = 0o2000000;
const FD_CLOEXEC_FLAG: usize = 1;
const ACCT_COMM_LEN: usize = 16;
const ACCT_HZ: u64 = 100;
const MEMBARRIER_CMD_QUERY: i32 = 0;
const MEMBARRIER_CMD_GLOBAL: i32 = 1;
const MEMBARRIER_CMD_GLOBAL_EXPEDITED: i32 = 1 << 1;
const MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
const MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
const MEMBARRIER_CMD_GET_REGISTRATIONS: i32 = 1 << 9;
const MPOL_DEFAULT: i32 = 0;
const MPOL_PREFERRED: i32 = 1;
const MPOL_BIND: i32 = 2;
const MPOL_INTERLEAVE: i32 = 3;
const MPOL_LOCAL: i32 = 4;
const MPOL_PREFERRED_MANY: i32 = 5;
const MPOL_F_NODE: u32 = 1;
const MPOL_F_ADDR: u32 = 1 << 1;
const MPOL_F_MEMS_ALLOWED: u32 = 1 << 2;
const MPOL_MODE_FLAGS: u32 = 1 << 15 | 1 << 14;

const SUPPORTED_MEMBARRIER_COMMANDS: i32 = MEMBARRIER_CMD_GLOBAL
    | MEMBARRIER_CMD_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
    | MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | MEMBARRIER_CMD_GET_REGISTRATIONS;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AcctRecordV0 {
    ac_flag: u8,
    ac_uid: u16,
    ac_gid: u16,
    ac_tty: u16,
    ac_btime: u32,
    ac_utime: u16,
    ac_stime: u16,
    ac_etime: u16,
    ac_mem: u16,
    ac_io: u16,
    ac_rw: u16,
    ac_minflt: u16,
    ac_majflt: u16,
    ac_swaps: u16,
    ac_exitcode: u32,
    ac_comm: [u8; ACCT_COMM_LEN + 1],
    ac_pad: [u8; 10],
}

fn process_accounting_path() -> &'static Mutex<Option<String>> {
    static PROCESS_ACCOUNTING_PATH: Once<Mutex<Option<String>>> = Once::new();
    PROCESS_ACCOUNTING_PATH.call_once(|| Mutex::new(None))
}

fn membarrier_registrations() -> &'static Mutex<BTreeMap<usize, i32>> {
    static MEMBARRIER_REGISTRATIONS: Once<Mutex<BTreeMap<usize, i32>>> = Once::new();
    MEMBARRIER_REGISTRATIONS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn current_membarrier_proc_id() -> usize {
    current().task_ext().proc_id
}

fn current_membarrier_registration_bits() -> i32 {
    membarrier_registrations()
        .lock()
        .get(&current_membarrier_proc_id())
        .copied()
        .unwrap_or(0)
}

fn register_current_membarrier(bits: i32) {
    let proc_id = current_membarrier_proc_id();
    let mut registrations = membarrier_registrations().lock();
    let entry = registrations.entry(proc_id).or_insert(0);
    *entry |= bits;
}

fn validate_cstring_path(path: &str) -> Result<(), LinuxError> {
    if path.len() >= 4096 {
        return Err(LinuxError::ENAMETOOLONG);
    }
    for component in path.split('/').filter(|part| !part.is_empty()) {
        if component.len() > 255 {
            return Err(LinuxError::ENAMETOOLONG);
        }
    }
    Ok(())
}

fn encode_acct_comp_t(value: u64) -> u16 {
    let mut exp = 0u16;
    let mut mant = value;
    while mant > 0x1fff {
        mant = (mant + 0x7) >> 3;
        exp += 1;
        if exp >= 7 {
            mant = 0x1fff;
            exp = 7;
            break;
        }
    }
    ((exp & 0x7) << 13) | (mant as u16 & 0x1fff)
}

fn basename_bytes(path: &str) -> &[u8] {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .map(str::as_bytes)
        .unwrap_or(path.as_bytes())
}

fn build_acct_record(exit_code: i32) -> AcctRecordV0 {
    let curr = current();
    let task_ext = curr.task_ext();
    let (utime_ns, stime_ns) = task_ext.time_stat_output();
    let elapsed_ns = monotonic_time_nanos().saturating_sub(task_ext.start_monotonic_ns());
    let utime_ticks = ((utime_ns as u64) * ACCT_HZ).div_ceil(NANOS_PER_SEC as u64);
    let stime_ticks = ((stime_ns as u64) * ACCT_HZ).div_ceil(NANOS_PER_SEC as u64);
    let elapsed_ticks = ((elapsed_ns as u64) * ACCT_HZ).div_ceil(NANOS_PER_SEC as u64);

    let mut record = AcctRecordV0 {
        ac_uid: axfs::api::current_uid() as u16,
        ac_gid: axfs::api::current_gid() as u16,
        ac_btime: task_ext.start_wall_time_sec() as u32,
        ac_utime: encode_acct_comp_t(utime_ticks),
        ac_stime: encode_acct_comp_t(stime_ticks),
        ac_etime: encode_acct_comp_t(elapsed_ticks),
        ac_exitcode: exit_code as u32,
        ..Default::default()
    };
    let exec_path = task_ext.exec_path();
    let comm = basename_bytes(exec_path.as_str());
    let copy_len = comm.len().min(ACCT_COMM_LEN);
    record.ac_comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    record
}

pub(crate) fn record_process_accounting(exit_code: i32) {
    let curr = current();
    if curr.id().as_u64() as usize != curr.task_ext().proc_id {
        return;
    }
    let path = process_accounting_path().lock().clone();
    let Some(path) = path else {
        return;
    };

    let record = build_acct_record(exit_code);
    let mut options = axfs::fops::OpenOptions::new();
    options.write(true);
    options.append(true);
    options.create(true);
    let Ok(mut file) = axfs::fops::File::open(path.as_str(), &options) else {
        warn!("acct: failed to open accounting file {}", path);
        return;
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&record as *const AcctRecordV0).cast::<u8>(),
            core::mem::size_of::<AcctRecordV0>(),
        )
    };
    let mut written = 0;
    while written < bytes.len() {
        match file.write(&bytes[written..]) {
            Ok(0) => {
                warn!(
                    "acct: short write while appending accounting record to {}",
                    path
                );
                return;
            }
            Ok(size) => written += size,
            Err(err) => {
                warn!(
                    "acct: failed to append accounting record to {}: {:?}",
                    path, err
                );
                return;
            }
        }
    }
}

pub(crate) fn sys_acct(filename: *const c_char) -> isize {
    syscall_body!(sys_acct, {
        if axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }

        if filename.is_null() {
            *process_accounting_path().lock() = None;
            return Ok(0);
        }

        let path = crate::usercopy::read_cstring_from_user(filename.cast(), 4096)?;
        validate_cstring_path(path.as_str())?;

        let trimmed = if path.len() > 1 {
            path.trim_end_matches('/').to_string()
        } else {
            path.clone()
        };
        let (resolved, attr) = resolve_existing_path(trimmed.as_str(), true)?;

        if path.ends_with('/') && !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
        if attr.is_dir() {
            return Err(LinuxError::EISDIR);
        }
        if !attr.is_file() {
            return Err(LinuxError::EACCES);
        }
        if axfs::api::is_readonly_path(resolved.as_str()).unwrap_or(false) {
            return Err(LinuxError::EROFS);
        }
        if !axfs::api::can_access(resolved.as_str(), attr, false, false, true, false) {
            return Err(LinuxError::EACCES);
        }

        *process_accounting_path().lock() = Some(resolved);
        Ok(0)
    })
}

pub(crate) fn sys_delete_module(name: *const c_char, _flags: i32) -> isize {
    syscall_body!(sys_delete_module, {
        if name.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }

        let module_name = crate::usercopy::read_cstring_from_user(name.cast(), 256)?;
        if module_name.is_empty() {
            return Err(LinuxError::ENOENT);
        }
        Err::<usize, LinuxError>(LinuxError::ENOENT)
    })
}

fn validate_user_read(ptr: *const c_void, len: usize) -> Result<(), LinuxError> {
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(LinuxError::EFAULT);
    }
    ensure_user_range(VirtAddr::from(ptr as usize), len, MappingFlags::READ)
}

fn validate_user_write(ptr: *mut c_void, len: usize) -> Result<(), LinuxError> {
    if len == 0 {
        return Ok(());
    }
    if ptr.is_null() {
        return Err(LinuxError::EFAULT);
    }
    ensure_user_range(VirtAddr::from(ptr as usize), len, MappingFlags::WRITE)
}

fn validate_user_read_write(ptr: *mut c_void, len: usize) -> Result<(), LinuxError> {
    validate_user_read(ptr.cast::<c_void>(), len)?;
    validate_user_write(ptr, len)
}

fn nodemask_len_bytes(maxnode: usize) -> usize {
    maxnode.div_ceil(8)
}

fn read_nodemask_allows_single_node(
    nodemask: *const usize,
    maxnode: usize,
) -> Result<bool, LinuxError> {
    let byte_len = nodemask_len_bytes(maxnode);
    if byte_len == 0 || nodemask.is_null() {
        return Ok(true);
    }
    validate_user_read(nodemask.cast(), byte_len)?;
    let mut bytes = alloc::vec![0u8; byte_len];
    copy_from_user(bytes.as_mut_slice(), nodemask.cast())?;
    let first = bytes.first().copied().unwrap_or(0);
    let other_bits = first & !1;
    Ok(first & 1 != 0 && other_bits == 0 && bytes[1..].iter().all(|byte| *byte == 0))
}

fn write_single_node_nodemask(nodemask: *mut usize, maxnode: usize) -> Result<(), LinuxError> {
    let byte_len = nodemask_len_bytes(maxnode);
    if byte_len == 0 || nodemask.is_null() {
        return Ok(());
    }
    validate_user_write(nodemask.cast(), byte_len)?;
    let mut bytes = alloc::vec![0u8; byte_len];
    bytes[0] = 1;
    copy_to_user(nodemask.cast(), bytes.as_slice())
}

fn validate_single_node_mempolicy(
    mode: i32,
    nodemask: *const usize,
    maxnode: usize,
) -> Result<(), LinuxError> {
    let base_mode = mode & !(MPOL_MODE_FLAGS as i32);
    match base_mode {
        MPOL_DEFAULT | MPOL_LOCAL => Ok(()),
        MPOL_PREFERRED | MPOL_BIND | MPOL_INTERLEAVE | MPOL_PREFERRED_MANY => {
            if read_nodemask_allows_single_node(nodemask, maxnode)? {
                Ok(())
            } else {
                Err(LinuxError::EINVAL)
            }
        }
        _ => Err(LinuxError::EINVAL),
    }
}

fn safe_zero_len_const_ptr(ptr: *const c_void, len: usize) -> *const c_void {
    if len == 0 {
        NonNull::<u8>::dangling().as_ptr().cast::<c_void>()
    } else {
        ptr
    }
}

fn safe_zero_len_mut_ptr(ptr: *mut c_void, len: usize) -> *mut c_void {
    if len == 0 {
        NonNull::<u8>::dangling().as_ptr().cast::<c_void>()
    } else {
        ptr
    }
}

fn timeval_from_ns(total_ns: usize) -> timeval {
    let secs = total_ns / NANOS_PER_SEC as usize;
    let micros = (total_ns % NANOS_PER_SEC as usize) / NANOS_PER_MICROS as usize;
    timeval {
        tv_sec: secs as _,
        tv_usec: micros as c_long,
    }
}

fn current_rusage() -> Rusage {
    let (utime_ns, stime_ns) = current().task_ext().time_stat_output();
    Rusage {
        ru_utime: timeval_from_ns(utime_ns),
        ru_stime: timeval_from_ns(stime_ns),
        ..Default::default()
    }
}

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_CMP_REQUEUE: u32 = 4;
const FUTEX_WAKE_OP: u32 = 5;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const FUTEX_OP_SET: u32 = 0;
const FUTEX_OP_ADD: u32 = 1;
const FUTEX_OP_OR: u32 = 2;
const FUTEX_OP_ANDN: u32 = 3;
const FUTEX_OP_XOR: u32 = 4;
const FUTEX_OP_OPARG_SHIFT: u32 = 8;
const FUTEX_OP_CMP_EQ: u32 = 0;
const FUTEX_OP_CMP_NE: u32 = 1;
const FUTEX_OP_CMP_LT: u32 = 2;
const FUTEX_OP_CMP_LE: u32 = 3;
const FUTEX_OP_CMP_GT: u32 = 4;
const FUTEX_OP_CMP_GE: u32 = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FutexKey {
    scope: u64,
    addr: usize,
}

struct FutexState {
    waiters: AtomicUsize,
    wake_seq: AtomicU64,
    wait_queue: WaitQueue,
}

impl FutexState {
    fn new() -> Self {
        Self {
            waiters: AtomicUsize::new(0),
            wake_seq: AtomicU64::new(0),
            wait_queue: WaitQueue::new(),
        }
    }
}

fn futex_table() -> &'static Mutex<BTreeMap<FutexKey, Arc<FutexState>>> {
    static FUTEX_TABLE: Once<Mutex<BTreeMap<FutexKey, Arc<FutexState>>>> = Once::new();
    FUTEX_TABLE.call_once(|| Mutex::new(BTreeMap::new()))
}

fn private_futex_scope() -> u64 {
    let aspace = Arc::as_ptr(&current().task_ext().aspace);
    aspace as usize as u64
}

fn shared_futex_addr(uaddr: *const u32) -> Option<usize> {
    if uaddr.is_null() {
        return None;
    }
    current()
        .task_ext()
        .aspace
        .lock()
        .shared_futex_key_addr(VirtAddr::from(uaddr as usize))
}

fn futex_key(uaddr: *const u32, futex_op: u32) -> FutexKey {
    let is_private = futex_op & FUTEX_PRIVATE_FLAG != 0;
    let scope = if is_private { private_futex_scope() } else { 0 };
    let addr = if is_private {
        uaddr as usize
    } else {
        shared_futex_addr(uaddr).unwrap_or(uaddr as usize)
    };
    FutexKey { scope, addr }
}

fn futex_state(key: FutexKey) -> Arc<FutexState> {
    let mut table = futex_table().lock();
    table
        .entry(key)
        .or_insert_with(|| Arc::new(FutexState::new()))
        .clone()
}

fn maybe_remove_futex_state(key: FutexKey, state: &Arc<FutexState>) {
    if state.waiters.load(Ordering::Acquire) != 0 {
        return;
    }
    let mut table = futex_table().lock();
    if table
        .get(&key)
        .is_some_and(|existing| Arc::ptr_eq(existing, state))
        && state.waiters.load(Ordering::Acquire) == 0
    {
        table.remove(&key);
    }
}

fn futex_deadline_ns(futex_op: u32, timeout: *const timespec) -> Result<Option<u64>, LinuxError> {
    if timeout.is_null() {
        return Ok(None);
    }
    let req = read_value_from_user(timeout)?;
    let timeout_ns = timespec_to_nanos(req)?;
    let op = futex_op & FUTEX_CMD_MASK;
    let absolute = matches!(op, FUTEX_WAIT_BITSET);
    let clock_id = if absolute && (futex_op & FUTEX_CLOCK_REALTIME != 0) {
        CLOCK_REALTIME
    } else {
        CLOCK_MONOTONIC
    };
    monotonic_deadline_from_clock(clock_id, timeout_ns, absolute).map(Some)
}

fn futex_wait(
    uaddr: *const u32,
    futex_op: u32,
    val: u32,
    timeout: *const timespec,
) -> Result<isize, LinuxError> {
    let key = futex_key(uaddr, futex_op);
    let state = futex_state(key);
    let expected_seq = state.wake_seq.load(Ordering::Acquire);
    let deadline_ns = futex_deadline_ns(futex_op, timeout)?;
    let current_value = read_value_from_user(uaddr)?;
    if current_value != val {
        maybe_remove_futex_state(key, &state);
        return Err(LinuxError::EAGAIN);
    }

    state.waiters.fetch_add(1, Ordering::AcqRel);
    let mut timed_out = false;
    let wait_done = || {
        crate::signal::current_has_pending_signal()
            || state.wake_seq.load(Ordering::Acquire) != expected_seq
    };
    match deadline_ns {
        Some(deadline_ns) => loop {
            if wait_done() {
                break;
            }
            let now_ns = monotonic_time_nanos();
            if now_ns >= deadline_ns {
                timed_out = true;
                break;
            }
            let remaining = Duration::from_nanos(deadline_ns.saturating_sub(now_ns));
            let woke_by_timeout = state.wait_queue.wait_timeout_until(remaining, wait_done);
            if woke_by_timeout && !wait_done() && monotonic_time_nanos() >= deadline_ns {
                timed_out = true;
                break;
            }
        },
        None => state.wait_queue.wait_until(wait_done),
    }
    state.waiters.fetch_sub(1, Ordering::AcqRel);
    let awakened = state.wake_seq.load(Ordering::Acquire) != expected_seq;
    maybe_remove_futex_state(key, &state);
    if crate::signal::current_has_pending_signal() && !awakened {
        Err(LinuxError::EINTR)
    } else if timed_out && !awakened {
        Err(LinuxError::ETIMEDOUT)
    } else {
        Ok(0)
    }
}

fn futex_wake_by_key(key: FutexKey, max_wake: u32) -> isize {
    if max_wake == 0 {
        return 0;
    }
    let state = {
        let table = futex_table().lock();
        table.get(&key).cloned()
    };
    let Some(state) = state else {
        return 0;
    };

    state.wake_seq.fetch_add(1, Ordering::AcqRel);
    let mut woken = 0usize;
    for _ in 0..max_wake {
        if state.wait_queue.notify_one(false) {
            woken += 1;
        } else {
            break;
        }
    }
    maybe_remove_futex_state(key, &state);
    woken as isize
}

fn futex_wake(uaddr: *const u32, futex_op: u32, max_wake: u32) -> isize {
    futex_wake_by_key(futex_key(uaddr, futex_op), max_wake)
}

pub(crate) fn wake_futex_word(uaddr: *mut u32) {
    if uaddr.is_null() {
        return;
    }
    let addr = uaddr as usize;
    let shared_key = FutexKey { scope: 0, addr };
    let private_key = FutexKey {
        scope: private_futex_scope(),
        addr,
    };
    let _ = futex_wake_by_key(shared_key, 1);
    let _ = futex_wake_by_key(private_key, 1);
}

fn futex_requeue(
    uaddr: *const u32,
    futex_op: u32,
    max_wake: u32,
    uaddr2: *const u32,
    max_requeue: u32,
    compare: Option<u32>,
) -> Result<isize, LinuxError> {
    if uaddr2.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if let Some(expected) = compare {
        let current_value = read_value_from_user(uaddr)?;
        if current_value != expected {
            return Err(LinuxError::EAGAIN);
        }
    }
    let total = max_wake.saturating_add(max_requeue);
    Ok(futex_wake(uaddr, futex_op, total))
}

fn futex_wake_op(
    uaddr: *const u32,
    futex_op: u32,
    max_wake: u32,
    uaddr2: *const u32,
    max_wake2: u32,
    encoded_op: u32,
) -> Result<isize, LinuxError> {
    if uaddr2.is_null() {
        return Err(LinuxError::EFAULT);
    }

    let raw_op = (encoded_op >> 28) & 0xf;
    let cmp = (encoded_op >> 24) & 0xf;
    let mut oparg = (encoded_op >> 12) & 0xfff;
    let cmparg = encoded_op & 0xfff;
    let use_shift = raw_op & FUTEX_OP_OPARG_SHIFT != 0;
    let op = raw_op & !FUTEX_OP_OPARG_SHIFT;
    if use_shift {
        oparg = 1u32.checked_shl(oparg).unwrap_or(0);
    }

    let oldval = read_value_from_user(uaddr2)?;
    let newval = match op {
        FUTEX_OP_SET => oparg,
        FUTEX_OP_ADD => oldval.wrapping_add(oparg),
        FUTEX_OP_OR => oldval | oparg,
        FUTEX_OP_ANDN => oldval & !oparg,
        FUTEX_OP_XOR => oldval ^ oparg,
        _ => return Err(LinuxError::ENOSYS),
    };
    write_value_to_user(uaddr2 as *mut u32, newval)?;

    let wake_primary = futex_wake(uaddr, futex_op, max_wake);
    let should_wake_secondary = match cmp {
        FUTEX_OP_CMP_EQ => oldval == cmparg,
        FUTEX_OP_CMP_NE => oldval != cmparg,
        FUTEX_OP_CMP_LT => oldval < cmparg,
        FUTEX_OP_CMP_LE => oldval <= cmparg,
        FUTEX_OP_CMP_GT => oldval > cmparg,
        FUTEX_OP_CMP_GE => oldval >= cmparg,
        _ => return Err(LinuxError::ENOSYS),
    };
    let wake_secondary = if should_wake_secondary {
        futex_wake(uaddr2, futex_op, max_wake2)
    } else {
        0
    };
    Ok(wake_primary + wake_secondary)
}

pub(crate) fn clear_child_tid_and_wake(clear_child_tid: *mut i32) {
    if clear_child_tid.is_null() {
        return;
    }
    #[cfg(target_arch = "riscv64")]
    if should_trace_riscv_libcbench_futex() && take_riscv_libcbench_futex_trace_slot(128) {
        let curr = current();
        warn!(
            "[rv-libcbench-futex] clear_child_tid task={} proc_id={} addr={:#x} now_ms={}",
            curr.id_name(),
            curr.task_ext().proc_id,
            clear_child_tid as usize,
            monotonic_time_nanos() / 1_000_000
        );
    }
    let _ = write_value_to_user(clear_child_tid, 0);
    wake_futex_word(clear_child_tid.cast());
}

fn next_pseudo_random_u64(seed: &mut u64) -> u64 {
    *seed ^= *seed << 7;
    *seed ^= *seed >> 9;
    *seed ^= *seed << 8;
    *seed
}

pub(crate) fn sys_madvise(_addr: usize, _len: usize, _advice: i32) -> isize {
    syscall_body!(sys_madvise, Ok(0))
}

pub(crate) fn sys_mbind(
    _start: usize,
    _len: usize,
    mode: i32,
    nodemask: *const usize,
    maxnode: usize,
    _flags: u32,
) -> isize {
    syscall_body!(sys_mbind, {
        validate_single_node_mempolicy(mode, nodemask, maxnode)?;
        Ok(0)
    })
}

pub(crate) fn sys_get_mempolicy(
    mode: *mut i32,
    nodemask: *mut usize,
    maxnode: usize,
    _addr: usize,
    flags: u32,
) -> isize {
    syscall_body!(sys_get_mempolicy, {
        if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
            return Err(LinuxError::EINVAL);
        }
        if !mode.is_null() {
            let value = if flags & MPOL_F_NODE != 0 {
                0
            } else {
                MPOL_DEFAULT
            };
            write_value_to_user(mode, value)?;
        }
        write_single_node_nodemask(nodemask, maxnode)?;
        Ok(0)
    })
}

pub(crate) fn sys_set_mempolicy(mode: i32, nodemask: *const usize, maxnode: usize) -> isize {
    syscall_body!(sys_set_mempolicy, {
        validate_single_node_mempolicy(mode, nodemask, maxnode)?;
        Ok(0)
    })
}

pub(crate) fn sys_mlock(addr: usize, len: usize) -> isize {
    syscall_body!(sys_mlock, {
        if len != 0 && addr == 0 {
            return Err(LinuxError::EINVAL);
        }
        Ok(0)
    })
}

pub(crate) fn sys_munlock(addr: usize, len: usize) -> isize {
    syscall_body!(sys_munlock, {
        if len != 0 && addr == 0 {
            return Err(LinuxError::EINVAL);
        }
        Ok(0)
    })
}

pub(crate) fn sys_mlockall(_flags: i32) -> isize {
    syscall_body!(sys_mlockall, Ok(0))
}

pub(crate) fn sys_munlockall() -> isize {
    syscall_body!(sys_munlockall, Ok(0))
}

pub(crate) fn sys_getrandom(buf: *mut u8, len: usize, _flags: u32) -> isize {
    syscall_body!(sys_getrandom, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let mut seed = monotonic_time_nanos() as u64 ^ 0x9e37_79b9_7f4a_7c15;
        let mut bytes = [0u8; 256];
        let mut written = 0usize;
        while written < len {
            for chunk in bytes.chunks_exact_mut(8) {
                chunk.copy_from_slice(&next_pseudo_random_u64(&mut seed).to_ne_bytes());
            }
            let chunk_len = (len - written).min(bytes.len());
            copy_to_user(
                unsafe { buf.add(written) }.cast::<c_void>(),
                &bytes[..chunk_len],
            )?;
            written += chunk_len;
        }
        Ok(written as isize)
    })
}

pub(crate) fn sys_membarrier(cmd: i32, flags: u32, _cpu_id: i32) -> isize {
    syscall_body!(sys_membarrier, {
        if flags != 0 {
            return Err(LinuxError::EINVAL);
        }

        match cmd {
            MEMBARRIER_CMD_QUERY => Ok(SUPPORTED_MEMBARRIER_COMMANDS as isize),
            MEMBARRIER_CMD_GLOBAL | MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
                fence(Ordering::SeqCst);
                Ok(0)
            }
            MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
                register_current_membarrier(MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED);
                Ok(0)
            }
            MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
                if current_membarrier_registration_bits()
                    & MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED
                    == 0
                {
                    return Err(LinuxError::EPERM);
                }
                fence(Ordering::SeqCst);
                Ok(0)
            }
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
                register_current_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED);
                Ok(0)
            }
            MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
                if current_membarrier_registration_bits()
                    & MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
                    == 0
                {
                    return Err(LinuxError::EPERM);
                }
                fence(Ordering::SeqCst);
                Ok(0)
            }
            MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
                register_current_membarrier(MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE);
                Ok(0)
            }
            MEMBARRIER_CMD_GET_REGISTRATIONS => Ok(current_membarrier_registration_bits() as isize),
            MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ
            | MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => Err(LinuxError::EINVAL),
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub(crate) fn sys_futex(
    uaddr: *const u32,
    futex_op: u32,
    val: u32,
    timeout: *const timespec,
    uaddr2: *const u32,
    val3: u32,
) -> isize {
    syscall_body!(sys_futex, {
        if uaddr.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let op = futex_op & FUTEX_CMD_MASK;
        #[cfg(target_arch = "riscv64")]
        if should_trace_riscv_libcbench_futex()
            && take_riscv_libcbench_futex_trace_slot(128)
            && matches!(
                op,
                FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAKE | FUTEX_WAKE_BITSET
            )
        {
            let curr = current();
            let current_value = read_value_from_user(uaddr).ok();
            warn!(
                "[rv-libcbench-futex] task={} proc_id={} op={:#x} raw_op={:#x} uaddr={:#x} val={} cur={:?} now_ms={}",
                curr.id_name(),
                curr.task_ext().proc_id,
                op,
                futex_op,
                uaddr as usize,
                val,
                current_value,
                monotonic_time_nanos() / 1_000_000
            );
        }
        if should_trace_nice05_futex()
            && matches!(
                op,
                FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAKE | FUTEX_WAKE_BITSET
            )
        {
            let curr = current();
            let current_value = read_value_from_user(uaddr).ok();
            warn!(
                "[nice05-diag] syscall=futex enter tid={} pid={} op={:#x} raw_op={:#x} uaddr={:#x} val={} cur={:?}",
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                op,
                futex_op,
                uaddr as usize,
                val,
                current_value,
            );
        }
        let ret = match op {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => futex_wait(uaddr, futex_op, val, timeout),
            FUTEX_WAKE | FUTEX_WAKE_BITSET => Ok(futex_wake(uaddr, futex_op, val)),
            FUTEX_REQUEUE => {
                futex_requeue(uaddr, futex_op, val, uaddr2, timeout as usize as u32, None)
            }
            FUTEX_CMP_REQUEUE => futex_requeue(
                uaddr,
                futex_op,
                val,
                uaddr2,
                timeout as usize as u32,
                Some(val3),
            ),
            FUTEX_WAKE_OP => {
                futex_wake_op(uaddr, futex_op, val, uaddr2, timeout as usize as u32, val3)
            }
            _ => Err(LinuxError::ENOSYS),
        }?;
        if should_trace_nice05_futex()
            && matches!(
                op,
                FUTEX_WAIT | FUTEX_WAIT_BITSET | FUTEX_WAKE | FUTEX_WAKE_BITSET
            )
        {
            let curr = current();
            warn!(
                "[nice05-diag] syscall=futex exit tid={} pid={} op={:#x} ret={}",
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                op,
                ret,
            );
        }
        Ok(ret)
    })
}

pub(crate) fn sys_socket(domain: i32, socktype: i32, protocol: i32) -> isize {
    arceos_posix_api::sys_socket(domain, socktype, protocol) as isize
}

pub(crate) fn sys_socketpair(domain: i32, socktype: i32, protocol: i32, sv: *mut i32) -> isize {
    if sv.is_null() {
        return -LinuxError::EFAULT.code() as isize;
    }
    let mut local_fds = [0i32; 2];
    let ret = arceos_posix_api::sys_socketpair(domain, socktype, protocol, &mut local_fds);
    if ret == 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                local_fds.as_ptr().cast::<u8>(),
                core::mem::size_of_val(&local_fds),
            )
        };
        if crate::usercopy::copy_to_user(sv.cast::<c_void>(), bytes).is_err() {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    ret as isize
}

pub(crate) fn sys_bind(fd: i32, addr: *const sockaddr, addrlen: socklen_t) -> isize {
    if addrlen as usize >= size_of::<sockaddr_in>() {
        if let Err(err) = validate_user_read(addr.cast::<c_void>(), size_of::<sockaddr_in>()) {
            return -err.code() as isize;
        }
    }
    arceos_posix_api::sys_bind(fd, addr, addrlen) as isize
}

pub(crate) fn sys_connect(fd: i32, addr: *const sockaddr, addrlen: socklen_t) -> isize {
    if addrlen as usize >= size_of::<sockaddr_in>() {
        if let Err(err) = validate_user_read(addr.cast::<c_void>(), size_of::<sockaddr_in>()) {
            return -err.code() as isize;
        }
    }
    arceos_posix_api::sys_connect(fd, addr, addrlen) as isize
}

pub(crate) fn sys_listen(fd: i32, backlog: i32) -> isize {
    arceos_posix_api::sys_listen(fd, backlog) as isize
}

pub(crate) fn sys_accept(fd: i32, addr: *mut sockaddr, addrlen: *mut socklen_t) -> isize {
    if !addrlen.is_null() {
        let user_len = match read_value_from_user(addrlen.cast_const()) {
            Ok(len) => len as usize,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = validate_user_read_write(addrlen.cast::<c_void>(), size_of::<socklen_t>())
        {
            return -err.code() as isize;
        }
        if !addr.is_null() {
            if let Err(err) = validate_user_write(
                addr.cast::<c_void>(),
                user_len.min(size_of::<sockaddr_in>()),
            ) {
                if get_file_like(fd).is_ok() {
                    return unsafe {
                        arceos_posix_api::sys_accept(
                            fd,
                            core::ptr::null_mut(),
                            core::ptr::null_mut(),
                        ) as isize
                    };
                }
                return -err.code() as isize;
            }
        }
    }
    unsafe { arceos_posix_api::sys_accept(fd, addr, addrlen) as isize }
}

pub(crate) fn sys_accept4(
    fd: i32,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
    flags: i32,
) -> isize {
    let new_fd = sys_accept(fd, addr, addrlen);
    if new_fd < 0 {
        return new_fd;
    }
    if flags & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
        let _ = arceos_posix_api::sys_close(new_fd as i32);
        return -(LinuxError::EINVAL.code() as isize);
    }
    if flags & SOCK_NONBLOCK != 0 {
        if let Err(err) = get_file_like(new_fd as i32).and_then(|file| file.set_nonblocking(true)) {
            let _ = arceos_posix_api::sys_close(new_fd as i32);
            return -(err.code() as isize);
        }
    }
    if flags & SOCK_CLOEXEC != 0 {
        let mut flags_table = FD_FLAGS.write();
        if let Some(bits) = flags_table.get_mut(new_fd as usize) {
            *bits |= FD_CLOEXEC_FLAG;
        }
    }
    new_fd
}

pub(crate) fn sys_sendto(
    fd: i32,
    buf: *const c_void,
    len: usize,
    flags: i32,
    addr: *const sockaddr,
    addrlen: socklen_t,
) -> isize {
    if let Err(err) = validate_user_read(buf, len) {
        return -err.code() as isize;
    }
    if !addr.is_null() && addrlen as usize >= size_of::<sockaddr_in>() {
        if let Err(err) = validate_user_read(addr.cast::<c_void>(), size_of::<sockaddr_in>()) {
            return -err.code() as isize;
        }
    }
    arceos_posix_api::sys_sendto(
        fd,
        safe_zero_len_const_ptr(buf, len),
        len,
        flags,
        addr,
        addrlen,
    ) as isize
}

pub(crate) fn sys_recvfrom(
    fd: i32,
    buf: *mut c_void,
    len: usize,
    flags: i32,
    addr: *mut sockaddr,
    addrlen: *mut socklen_t,
) -> isize {
    if let Err(err) = validate_user_write(buf, len) {
        return -err.code() as isize;
    }
    if !addr.is_null() && !addrlen.is_null() {
        let user_len = match read_value_from_user(addrlen.cast_const()) {
            Ok(len) => len as usize,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = validate_user_read_write(addrlen.cast::<c_void>(), size_of::<socklen_t>())
        {
            return -err.code() as isize;
        }
        if let Err(err) = validate_user_write(
            addr.cast::<c_void>(),
            user_len.min(size_of::<sockaddr_in>()),
        ) {
            return -err.code() as isize;
        }
    }
    unsafe {
        arceos_posix_api::sys_recvfrom(
            fd,
            safe_zero_len_mut_ptr(buf, len),
            len,
            flags,
            addr,
            addrlen,
        ) as isize
    }
}

#[allow(dead_code)]
pub(crate) fn sys_send(fd: i32, buf: *const c_void, len: usize, flags: i32) -> isize {
    if let Err(err) = validate_user_read(buf, len) {
        return -err.code() as isize;
    }
    arceos_posix_api::sys_send(fd, safe_zero_len_const_ptr(buf, len), len, flags) as isize
}

#[allow(dead_code)]
pub(crate) fn sys_recv(fd: i32, buf: *mut c_void, len: usize, flags: i32) -> isize {
    if let Err(err) = validate_user_write(buf, len) {
        return -err.code() as isize;
    }
    arceos_posix_api::sys_recv(fd, safe_zero_len_mut_ptr(buf, len), len, flags) as isize
}

pub(crate) fn sys_shutdown(fd: i32, how: i32) -> isize {
    arceos_posix_api::sys_shutdown(fd, how) as isize
}

pub(crate) fn sys_getsockname(fd: i32, addr: *mut sockaddr, addrlen: *mut socklen_t) -> isize {
    if !addr.is_null() && !addrlen.is_null() {
        let user_len = match read_value_from_user(addrlen.cast_const()) {
            Ok(len) => len as usize,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = validate_user_read_write(addrlen.cast::<c_void>(), size_of::<socklen_t>())
        {
            return -err.code() as isize;
        }
        if let Err(err) = validate_user_write(
            addr.cast::<c_void>(),
            user_len.min(size_of::<sockaddr_in>()),
        ) {
            return -err.code() as isize;
        }
    }
    unsafe { arceos_posix_api::sys_getsockname(fd, addr, addrlen) as isize }
}

pub(crate) fn sys_getpeername(fd: i32, addr: *mut sockaddr, addrlen: *mut socklen_t) -> isize {
    if !addr.is_null() && !addrlen.is_null() {
        let user_len = match read_value_from_user(addrlen.cast_const()) {
            Ok(len) => len as usize,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = validate_user_read_write(addrlen.cast::<c_void>(), size_of::<socklen_t>())
        {
            return -err.code() as isize;
        }
        if let Err(err) = validate_user_write(
            addr.cast::<c_void>(),
            user_len.min(size_of::<sockaddr_in>()),
        ) {
            return -err.code() as isize;
        }
    }
    unsafe { arceos_posix_api::sys_getpeername(fd, addr, addrlen) as isize }
}

pub(crate) fn sys_setsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *const c_void,
    optlen: socklen_t,
) -> isize {
    let needs_timeval = matches!((level, optname), (1, 20) | (1, 21));
    if needs_timeval && optlen as usize >= size_of::<timeval>() {
        if let Err(err) = validate_user_read(optval, size_of::<timeval>()) {
            return -err.code() as isize;
        }
    }
    unsafe { arceos_posix_api::sys_setsockopt(fd, level, optname, optval, optlen) as isize }
}

pub(crate) fn sys_getsockopt(
    fd: i32,
    level: i32,
    optname: i32,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> isize {
    if !optlen.is_null() {
        let user_len = match read_value_from_user(optlen.cast_const()) {
            Ok(len) => len as usize,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = validate_user_read_write(optlen.cast::<c_void>(), size_of::<socklen_t>())
        {
            return -err.code() as isize;
        }
        if let Err(err) = validate_user_write(optval, user_len.min(size_of::<i32>())) {
            return -err.code() as isize;
        }
    }
    unsafe { arceos_posix_api::sys_getsockopt(fd, level, optname, optval, optlen) as isize }
}

pub(crate) fn sys_getrusage(who: i32, usage: *mut Rusage) -> isize {
    syscall_body!(sys_getrusage, {
        if usage.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let rusage = match who {
            RUSAGE_SELF | RUSAGE_THREAD => current_rusage(),
            RUSAGE_CHILDREN => Rusage::default(),
            _ => return Err(LinuxError::EINVAL),
        };
        write_value_to_user(usage, rusage)?;
        Ok(0)
    })
}

pub(crate) fn sys_getcpu(cpu: *mut u32, node: *mut u32, _cache: *mut c_void) -> isize {
    syscall_body!(sys_getcpu, {
        if !cpu.is_null() {
            write_value_to_user(cpu, 0u32)?;
        }
        if !node.is_null() {
            write_value_to_user(node, 0u32)?;
        }
        Ok(0)
    })
}
