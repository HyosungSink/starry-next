use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{
    ffi::c_void,
    mem::size_of,
    sync::atomic::{AtomicUsize, Ordering},
};

use axerrno::{LinuxError, LinuxResult};
use axhal::trap;
use axhal::{
    arch::TrapFrame,
    paging::MappingFlags,
    time::{monotonic_time_nanos, NANOS_PER_MICROS, NANOS_PER_SEC},
};
use axmm::AddrSpace;
use axsync::Mutex;
use axtask::{current, AxTaskRef, TaskExtRef};
use memory_addr::{VirtAddr, PAGE_SIZE_4K};

#[cfg(target_arch = "riscv64")]
use axhal::mem::phys_to_virt;
#[cfg(target_arch = "riscv64")]
use memory_addr::MemoryAddr;

use crate::{
    syscall_body,
    task::{find_live_task_by_tid, thread_group_tasks},
    task::{read_trapframe_from_kstack, write_trapframe_to_kstack},
    timekeeping::{current_clock_nanos, monotonic_deadline_from_clock},
    usercopy::{read_value_from_user, write_value_to_user},
};

const SIGNAL_WORKER_STACK_SIZE: usize = 16 * 1024;

const MAX_SIGNALS: usize = 64;
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;
const SIGHUP: usize = 1;
const SIGINT: usize = 2;
const SIGQUIT: usize = 3;
const SIGILL: usize = 4;
const SIGTRAP: usize = 5;
const SIGABRT: usize = 6;
const SIGBUS: usize = 7;
const SIGFPE: usize = 8;
const SIGCANCEL: usize = 33;
const SIGCANCEL_LEGACY: usize = 32;
const SIGKILL: usize = 9;
const SIGUSR1: usize = 10;
const SIGSEGV: usize = 11;
const SIGUSR2: usize = 12;
const SIGPIPE: usize = 13;
const SIGALRM: usize = 14;
const SIGTERM: usize = 15;
const SIGSTKFLT: usize = 16;
const SIGCHLD: usize = 17;
const SIGCONT: usize = 18;
const SIGSTOP: usize = 19;
const SIGTSTP: usize = 20;
const SIGTTIN: usize = 21;
const SIGTTOU: usize = 22;
const SIGURG: usize = 23;
const SIGXCPU: usize = 24;
const SIGXFSZ: usize = 25;
const SIGVTALRM: usize = 26;
const SIGPROF: usize = 27;
const SIGWINCH: usize = 28;
const SIGIO: usize = 29;
const SIGPWR: usize = 30;
const SIGSYS: usize = 31;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const SA_SIGINFO: usize = 0x0000_0004;
const SA_RESTORER: usize = 0x0400_0000;
const SA_RESTART: usize = 0x1000_0000;
const SA_NODEFER: usize = 0x4000_0000;
const SA_RESETHAND: usize = 0x8000_0000;
const ITIMER_REAL: i32 = 0;
const ITIMER_VIRTUAL: i32 = 1;
const ITIMER_PROF: i32 = 2;
const TIMER_ABSTIME: i32 = 1;
const SIGEV_SIGNAL: i32 = 0;
const SIGEV_NONE: i32 = 1;
const MPROTECT02_SIGNAL_LOG_LIMIT: usize = 64;
const SETITIMER_DIAG_LOG_LIMIT: usize = 128;

static MPROTECT02_SIGNAL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static SETITIMER_DIAG_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn trace_mprotect02_signal() -> bool {
    current().task_ext().exec_path().ends_with("/mprotect02")
        || current().task_ext().exec_path() == "mprotect02"
}

fn take_mprotect02_signal_log_slot() -> Option<usize> {
    let slot = MPROTECT02_SIGNAL_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    (slot < MPROTECT02_SIGNAL_LOG_LIMIT).then_some(slot + 1)
}

fn trace_setitimer01_task(task: &AxTaskRef) -> bool {
    let exec_path = task.task_ext().exec_path();
    exec_path.ends_with("/setitimer01") || exec_path == "setitimer01"
}

fn trace_setitimer01() -> bool {
    let curr = current();
    if unsafe { curr.task_ext_ptr() }.is_null() {
        return false;
    }
    trace_setitimer01_task(curr.as_task_ref())
}

fn take_setitimer_diag_slot() -> Option<usize> {
    if !trace_setitimer01() {
        return None;
    }
    let slot = SETITIMER_DIAG_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    (slot < SETITIMER_DIAG_LOG_LIMIT).then_some(slot + 1)
}

const SIGEV_THREAD: i32 = 2;
const SIGEV_THREAD_ID: i32 = 4;
const SI_QUEUE: i32 = -1;
const SI_TKILL: i32 = -6;
const SI_USER: i32 = 0;
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
const CLOCK_BOOTTIME: i32 = 7;
const CLOCK_BOOTTIME_ALARM: i32 = 9;
const CLOCK_REALTIME_ALARM: i32 = 8;
const CLOCK_TAI: i32 = 11;
const SIGNAL_FRAME_MAGIC: u64 = 0x5349_4746_524d_3031;

#[cfg(target_arch = "riscv64")]
const SIGNAL_TRAMPOLINE_BYTES: &[u8] = &[
    0x93, 0x08, 0xb0, 0x08, // li a7, 139
    0x73, 0x00, 0x00, 0x00, // ecall
    0x73, 0x00, 0x10, 0x00, // ebreak
];

#[cfg(target_arch = "loongarch64")]
const SIGNAL_TRAMPOLINE_BYTES: &[u8] = &[
    0x0b, 0x2c, 0x82, 0x03, // li.w $a7, 139
    0x00, 0x00, 0x2b, 0x00, // syscall 0
    0x00, 0x00, 0x2a, 0x00, // break 0
];

#[cfg(target_arch = "riscv64")]
fn read_user_insn_bytes_for_diag(
    aspace: &mut AddrSpace,
    pc: VirtAddr,
) -> (
    Option<(usize, memory_addr::PhysAddr, MappingFlags, usize)>,
    usize,
    [u8; 8],
    &'static str,
) {
    let mut bytes = [0u8; 8];
    let query = aspace.page_table().query(pc).ok();
    let page_offset = pc.as_usize() & (PAGE_SIZE_4K - 1);
    let max_len = (PAGE_SIZE_4K - page_offset).min(bytes.len());

    if max_len == 0 {
        return (
            query.map(|(paddr, flags, page_size)| (pc.as_usize(), paddr, flags, page_size.into())),
            0,
            bytes,
            "empty",
        );
    }

    if aspace.read(pc, &mut bytes[..max_len]).is_ok() {
        return (
            query.map(|(paddr, flags, page_size)| (pc.as_usize(), paddr, flags, page_size.into())),
            max_len,
            bytes,
            "user-read",
        );
    }

    if let Some((paddr, flags, page_size)) = query {
        let base = phys_to_virt(paddr.align_down_4k());
        unsafe {
            core::ptr::copy_nonoverlapping(
                base.as_ptr().add(page_offset),
                bytes.as_mut_ptr(),
                max_len,
            );
        }
        return (
            Some((pc.as_usize(), paddr, flags, page_size.into())),
            max_len,
            bytes,
            "phys-read",
        );
    }

    (None, 0, bytes, "unreadable")
}

#[cfg(target_arch = "riscv64")]
fn handle_user_trap_diagnostic(
    tf: &TrapFrame,
    trap_bits: usize,
    trap_value: usize,
    from_user: bool,
) {
    let curr = current();
    let exec_path = curr.task_ext().exec_path();
    let pc = VirtAddr::from_usize(tf.sepc);
    let mut aspace = curr.task_ext().aspace.lock();
    let (pte, insn_len, insn_bytes, read_mode) = read_user_insn_bytes_for_diag(&mut aspace, pc);
    drop(aspace);

    let insn16 = if insn_len >= 2 {
        Some(u16::from_le_bytes([insn_bytes[0], insn_bytes[1]]))
    } else {
        None
    };
    let insn32 = if insn_len >= 4 {
        Some(u32::from_le_bytes([
            insn_bytes[0],
            insn_bytes[1],
            insn_bytes[2],
            insn_bytes[3],
        ]))
    } else {
        None
    };
    let decoded_len = insn16
        .map(|value| if value & 0b11 != 0b11 { 2 } else { 4 })
        .unwrap_or(0);

    warn!(
        "[rv-user-trap] task={} tid={} pid={} exec_path={} from_user={} scause_bits={:#x} stval={:#x} sepc={:#x} ra={:#x} sp={:#x} gp={:#x} tp={:#x} sstatus={:#x}",
        curr.name(),
        curr.id().as_u64(),
        curr.task_ext().proc_id,
        exec_path,
        from_user,
        trap_bits,
        trap_value,
        tf.sepc,
        tf.regs.ra,
        tf.regs.sp,
        tf.regs.gp,
        tf.regs.tp,
        tf.sstatus,
    );

    match pte {
        Some((pc_addr, paddr, flags, page_size)) => warn!(
            "[rv-user-trap] pc_va={:#x} paddr={:#x} flags={:?} page_size={:?} insn_read={} decoded_len={} insn16={:?} insn32={:?} bytes={:02x?}",
            pc_addr,
            paddr.as_usize(),
            flags,
            page_size,
            read_mode,
            decoded_len,
            insn16,
            insn32,
            &insn_bytes[..insn_len],
        ),
        None => warn!(
            "[rv-user-trap] pc_va={:#x} page_table_query=miss insn_read={} decoded_len={} insn16={:?} insn32={:?} bytes={:02x?}",
            tf.sepc,
            read_mode,
            decoded_len,
            insn16,
            insn32,
            &insn_bytes[..insn_len],
        ),
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserSigSet {
    bits: u64,
}

impl UserSigSet {
    const fn from_mask(mask: u64) -> Self {
        Self { bits: mask }
    }

    const fn as_mask(self) -> u64 {
        self.bits
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserContextSigSet {
    bits: [u64; 16],
}

impl UserContextSigSet {
    const fn from_mask(mask: u64) -> Self {
        let mut bits = [0; 16];
        bits[0] = mask;
        Self { bits }
    }

    const fn as_mask(self) -> u64 {
        self.bits[0]
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserSigAction {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: UserSigSet,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserTimeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserItimerval {
    it_interval: UserTimeval,
    it_value: UserTimeval,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserItimerspec {
    it_interval: UserTimespec,
    it_value: UserTimespec,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserSigVal {
    sival_ptr: *mut c_void,
}

impl Default for UserSigVal {
    fn default() -> Self {
        Self {
            sival_ptr: core::ptr::null_mut(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserSigevent {
    sigev_value: UserSigVal,
    sigev_signo: i32,
    sigev_notify: i32,
    sigev_notify_thread_id: i32,
    unused: [i32; 11],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct UserSigInfo {
    si_signo: i32,
    si_errno: i32,
    si_code: i32,
    pad0: i32,
    fields: [u8; 128 - 4 * size_of::<i32>()],
}

impl Default for UserSigInfo {
    fn default() -> Self {
        Self {
            si_signo: 0,
            si_errno: 0,
            si_code: 0,
            pad0: 0,
            fields: [0; 128 - 4 * size_of::<i32>()],
        }
    }
}

impl UserSigInfo {
    pub(crate) fn simple(signum: usize) -> Self {
        Self {
            si_signo: signum as i32,
            ..Default::default()
        }
    }

    fn from_sender(signum: usize, si_code: i32, sender_pid: i32, sender_uid: u32) -> Self {
        let mut info = Self {
            si_signo: signum as i32,
            si_code,
            ..Default::default()
        };
        info.fields[..4].copy_from_slice(&sender_pid.to_ne_bytes());
        info.fields[4..8].copy_from_slice(&sender_uid.to_ne_bytes());
        info
    }

    pub(crate) fn queued(signum: usize, sender_pid: i32, sender_uid: u32, value: usize) -> Self {
        let mut info = Self::from_sender(signum, SI_QUEUE, sender_pid, sender_uid);
        info.fields[8..16].copy_from_slice(&(value as u64).to_ne_bytes());
        info
    }

    pub(crate) fn tkill(signum: usize, sender_pid: i32, sender_uid: u32) -> Self {
        Self::from_sender(signum, SI_TKILL, sender_pid, sender_uid)
    }

    pub(crate) fn user(signum: usize, sender_pid: i32, sender_uid: u32) -> Self {
        Self::from_sender(signum, SI_USER, sender_pid, sender_uid)
    }

    pub(crate) fn signal_value(&self) -> usize {
        u64::from_ne_bytes(self.fields[8..16].try_into().unwrap()) as usize
    }

    pub(crate) fn signo(&self) -> i32 {
        self.si_signo
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserStack {
    ss_sp: usize,
    ss_flags: i32,
    _pad: i32,
    ss_size: usize,
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy)]
struct UserMContext {
    gregs: [u64; 32],
    fpregs: [u8; 528],
}

#[cfg(target_arch = "riscv64")]
impl Default for UserMContext {
    fn default() -> Self {
        Self {
            gregs: [0; 32],
            fpregs: [0; 528],
        }
    }
}

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserUContext {
    uc_flags: usize,
    uc_link: usize,
    uc_stack: UserStack,
    uc_sigmask: UserContextSigSet,
    // Linux RISC-V keeps `uc_mcontext` 16-byte aligned, so user-space
    // handlers such as musl's cancel handler expect it at offset 176.
    _pad: u64,
    uc_mcontext: UserMContext,
}

#[cfg(target_arch = "loongarch64")]
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct UserMContext {
    pc: u64,
    gregs: [u64; 32],
    flags: u32,
    _pad: u32,
}

#[cfg(target_arch = "loongarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UserUContext {
    uc_flags: usize,
    uc_link: usize,
    uc_stack: UserStack,
    uc_sigmask: UserContextSigSet,
    uc_mcontext: UserMContext,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SignalFrame {
    siginfo: UserSigInfo,
    ucontext: UserUContext,
    magic: u64,
}

impl Default for SignalFrame {
    fn default() -> Self {
        Self {
            siginfo: UserSigInfo::default(),
            ucontext: UserUContext::default(),
            magic: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct SignalAction {
    handler: usize,
    mask: u64,
    flags: usize,
    restorer: usize,
}

#[derive(Clone, Copy, Default)]
struct PosixTimer {
    clock_id: i32,
    notify: i32,
    notify_signum: usize,
    notify_tid: u64,
    interval_ns: u64,
    deadline_ns: u64,
    overrun: u32,
    armed_seq: u64,
}

#[derive(Clone)]
pub struct SignalState {
    actions: Arc<Mutex<[SignalAction; MAX_SIGNALS]>>,
    blocked_mask: u64,
    sigsuspend_restore_mask: Option<u64>,
    pending_mask: u64,
    pending_info: [Option<UserSigInfo>; MAX_SIGNALS],
    in_handler: bool,
    real_timer_interval_ns: usize,
    real_timer_deadline_ns: usize,
    real_timer_armed_seq: u64,
    virtual_timer_interval_ns: usize,
    virtual_timer_deadline_ns: usize,
    virtual_timer_armed_seq: u64,
    prof_timer_interval_ns: usize,
    prof_timer_deadline_ns: usize,
    prof_timer_armed_seq: u64,
    next_posix_timer_id: i32,
    posix_timers: BTreeMap<i32, PosixTimer>,
}

impl Default for SignalState {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalState {
    pub fn new() -> Self {
        Self {
            actions: Arc::new(Mutex::new([SignalAction::default(); MAX_SIGNALS])),
            blocked_mask: 0,
            sigsuspend_restore_mask: None,
            pending_mask: 0,
            pending_info: [None; MAX_SIGNALS],
            in_handler: false,
            real_timer_interval_ns: 0,
            real_timer_deadline_ns: 0,
            real_timer_armed_seq: 0,
            virtual_timer_interval_ns: 0,
            virtual_timer_deadline_ns: 0,
            virtual_timer_armed_seq: 0,
            prof_timer_interval_ns: 0,
            prof_timer_deadline_ns: 0,
            prof_timer_armed_seq: 0,
            next_posix_timer_id: 1,
            posix_timers: BTreeMap::new(),
        }
    }

    pub fn fork_from_parent(parent: &Self, share_actions: bool) -> Self {
        Self {
            actions: if share_actions {
                Arc::clone(&parent.actions)
            } else {
                Arc::new(Mutex::new(*parent.actions.lock()))
            },
            blocked_mask: parent.blocked_mask,
            sigsuspend_restore_mask: None,
            pending_mask: 0,
            pending_info: [None; MAX_SIGNALS],
            in_handler: false,
            real_timer_interval_ns: 0,
            real_timer_deadline_ns: 0,
            real_timer_armed_seq: 0,
            virtual_timer_interval_ns: 0,
            virtual_timer_deadline_ns: 0,
            virtual_timer_armed_seq: 0,
            prof_timer_interval_ns: 0,
            prof_timer_deadline_ns: 0,
            prof_timer_armed_seq: 0,
            next_posix_timer_id: 1,
            posix_timers: BTreeMap::new(),
        }
    }

    pub fn reset_for_exec(&mut self) {
        let mut actions = *self.actions.lock();
        for action in &mut actions {
            if action.handler != SIG_IGN {
                *action = SignalAction::default();
            }
        }
        if let Ok(sigquit_index) = Self::signal_index(SIGQUIT) {
            // Shell-launched test binaries must not keep an ignored SIGQUIT
            // across exec, otherwise default-terminate probes such as LTP kill11
            // inherit a permanently ignored SIGQUIT and hang.
            if actions[sigquit_index].handler == SIG_IGN {
                actions[sigquit_index] = SignalAction::default();
            }
        }
        self.actions = Arc::new(Mutex::new(actions));
        self.blocked_mask = 0;
        self.sigsuspend_restore_mask = None;
        self.pending_mask = 0;
        self.pending_info = [None; MAX_SIGNALS];
        self.in_handler = false;
        self.real_timer_interval_ns = 0;
        self.real_timer_deadline_ns = 0;
        self.real_timer_armed_seq = 0;
        self.virtual_timer_interval_ns = 0;
        self.virtual_timer_deadline_ns = 0;
        self.virtual_timer_armed_seq = 0;
        self.prof_timer_interval_ns = 0;
        self.prof_timer_deadline_ns = 0;
        self.prof_timer_armed_seq = 0;
        self.next_posix_timer_id = 1;
        self.posix_timers.clear();
    }

    pub(crate) fn actions_identity(&self) -> usize {
        Arc::as_ptr(&self.actions) as usize
    }

    fn signal_bit(signum: usize) -> u64 {
        1u64 << (signum - 1)
    }

    fn signal_index(signum: usize) -> Result<usize, LinuxError> {
        if !(1..=MAX_SIGNALS).contains(&signum) {
            return Err(LinuxError::EINVAL);
        }
        Ok(signum - 1)
    }

    fn update_real_timer(&mut self, now_ns: usize) {
        if self.real_timer_deadline_ns == 0 || now_ns < self.real_timer_deadline_ns {
            return;
        }

        self.queue_signal(SIGALRM, None);
        if self.real_timer_interval_ns == 0 {
            self.real_timer_deadline_ns = 0;
            return;
        }

        let overdue = now_ns - self.real_timer_deadline_ns;
        let steps = overdue / self.real_timer_interval_ns + 1;
        self.real_timer_deadline_ns += steps * self.real_timer_interval_ns;
    }

    fn real_timer_value(&self, now_ns: usize) -> (usize, usize) {
        let value_ns = if self.real_timer_deadline_ns == 0 {
            0
        } else {
            self.real_timer_deadline_ns.saturating_sub(now_ns)
        };
        (self.real_timer_interval_ns, value_ns)
    }

    fn set_real_timer(&mut self, interval_ns: usize, value_ns: usize, now_ns: usize) -> u64 {
        self.real_timer_armed_seq = self.real_timer_armed_seq.wrapping_add(1);
        self.real_timer_interval_ns = interval_ns;
        self.real_timer_deadline_ns = if value_ns == 0 { 0 } else { now_ns + value_ns };
        if value_ns == 0 {
            self.clear_pending(SIGALRM);
        }
        self.real_timer_armed_seq
    }

    fn virtual_timer_value(&self, now_ns: usize) -> (usize, usize) {
        let value_ns = if self.virtual_timer_deadline_ns == 0 {
            0
        } else {
            self.virtual_timer_deadline_ns.saturating_sub(now_ns)
        };
        (self.virtual_timer_interval_ns, value_ns)
    }

    fn set_virtual_timer(&mut self, interval_ns: usize, value_ns: usize, now_ns: usize) -> u64 {
        self.virtual_timer_armed_seq = self.virtual_timer_armed_seq.wrapping_add(1);
        self.virtual_timer_interval_ns = interval_ns;
        self.virtual_timer_deadline_ns = if value_ns == 0 { 0 } else { now_ns + value_ns };
        if value_ns == 0 {
            self.clear_pending(SIGVTALRM);
        }
        self.virtual_timer_armed_seq
    }

    fn prof_timer_value(&self, now_ns: usize) -> (usize, usize) {
        let value_ns = if self.prof_timer_deadline_ns == 0 {
            0
        } else {
            self.prof_timer_deadline_ns.saturating_sub(now_ns)
        };
        (self.prof_timer_interval_ns, value_ns)
    }

    fn set_prof_timer(&mut self, interval_ns: usize, value_ns: usize, now_ns: usize) -> u64 {
        self.prof_timer_armed_seq = self.prof_timer_armed_seq.wrapping_add(1);
        self.prof_timer_interval_ns = interval_ns;
        self.prof_timer_deadline_ns = if value_ns == 0 { 0 } else { now_ns + value_ns };
        if value_ns == 0 {
            self.clear_pending(SIGPROF);
        }
        self.prof_timer_armed_seq
    }

    fn update_posix_timers(&mut self, now_ns: usize) {
        let mut pending_signals = Vec::new();
        for timer in self.posix_timers.values_mut() {
            if timer.deadline_ns == 0 || now_ns < timer.deadline_ns as usize {
                continue;
            }

            if trace_clock_settime03() {
                warn!(
                    "[clock_settime03-timer_expire] tid={} proc_id={} clock_id={} notify={} signum={} now_ns={} deadline_ns={}",
                    current().id().as_u64(),
                    current().task_ext().proc_id,
                    timer.clock_id,
                    timer.notify,
                    timer.notify_signum,
                    now_ns,
                    timer.deadline_ns
                );
            }
            if timer.notify == SIGEV_SIGNAL || timer.notify == SIGEV_THREAD_ID {
                pending_signals.push(timer.notify_signum);
            }

            if timer.interval_ns == 0 {
                timer.deadline_ns = 0;
                timer.overrun = 0;
                continue;
            }

            let overdue = now_ns as u64 - timer.deadline_ns;
            let steps = overdue / timer.interval_ns + 1;
            timer.deadline_ns = timer
                .deadline_ns
                .saturating_add(steps.saturating_mul(timer.interval_ns));
            timer.overrun = steps.saturating_sub(1).min(u32::MAX as u64) as u32;
        }
        for signum in pending_signals {
            self.queue_signal(signum, None);
        }
    }

    fn create_posix_timer(
        &mut self,
        clock_id: i32,
        notify: i32,
        notify_signum: usize,
        notify_tid: u64,
    ) -> i32 {
        let mut timer_id = self.next_posix_timer_id.max(1);
        while self.posix_timers.contains_key(&timer_id) {
            timer_id = timer_id.saturating_add(1);
        }
        self.next_posix_timer_id = timer_id.saturating_add(1);
        self.posix_timers.insert(
            timer_id,
            PosixTimer {
                clock_id,
                notify,
                notify_signum,
                notify_tid,
                ..Default::default()
            },
        );
        timer_id
    }

    fn posix_timer_value(&self, timer_id: i32, now_ns: usize) -> Result<(u64, u64), LinuxError> {
        let timer = self.posix_timers.get(&timer_id).ok_or(LinuxError::EINVAL)?;
        let value_ns = if timer.deadline_ns == 0 {
            0
        } else {
            timer.deadline_ns.saturating_sub(now_ns as u64)
        };
        Ok((timer.interval_ns, value_ns))
    }

    fn set_posix_timer(
        &mut self,
        timer_id: i32,
        interval_ns: u64,
        deadline_ns: u64,
    ) -> Result<(u64, u64, u64), LinuxError> {
        let timer = self
            .posix_timers
            .get_mut(&timer_id)
            .ok_or(LinuxError::EINVAL)?;
        let old = (
            timer.interval_ns,
            if timer.deadline_ns == 0 {
                0
            } else {
                timer.deadline_ns
            },
        );
        timer.interval_ns = interval_ns;
        timer.deadline_ns = deadline_ns;
        timer.overrun = 0;
        timer.armed_seq = timer.armed_seq.wrapping_add(1).max(1);
        Ok((old.0, old.1, timer.armed_seq))
    }

    fn delete_posix_timer(&mut self, timer_id: i32) -> Result<(), LinuxError> {
        self.posix_timers
            .remove(&timer_id)
            .map(|_| ())
            .ok_or(LinuxError::EINVAL)
    }

    fn posix_timer_overrun(&self, timer_id: i32) -> Result<i32, LinuxError> {
        self.posix_timers
            .get(&timer_id)
            .map(|timer| timer.overrun as i32)
            .ok_or(LinuxError::EINVAL)
    }

    fn finish_handler(&mut self, old_mask: u64) {
        self.blocked_mask = old_mask & !(Self::signal_bit(SIGKILL) | Self::signal_bit(SIGSTOP));
        self.sigsuspend_restore_mask = None;
        self.in_handler = false;
    }

    fn set_action(&mut self, signum: usize, action: SignalAction) {
        self.actions.lock()[signum - 1] = action;
    }

    fn action(&self, signum: usize) -> SignalAction {
        self.actions.lock()[signum - 1]
    }

    fn queue_signal(&mut self, signum: usize, siginfo: Option<UserSigInfo>) {
        let index = signum - 1;
        self.pending_mask |= Self::signal_bit(signum);
        if let Some(siginfo) = siginfo {
            self.pending_info[index] = Some(siginfo);
        } else if self.pending_info[index].is_none() {
            self.pending_info[index] = Some(UserSigInfo::simple(signum));
        }
    }

    fn clear_pending(&mut self, signum: usize) {
        self.pending_mask &= !Self::signal_bit(signum);
        self.pending_info[signum - 1] = None;
    }

    fn take_pending_info(&mut self, signum: usize) -> UserSigInfo {
        self.pending_info[signum - 1]
            .take()
            .unwrap_or_else(|| UserSigInfo::simple(signum))
    }
}

enum PreparedSignal {
    Terminate(usize),
    Stop(usize),
    Handler {
        signum: usize,
        handler: usize,
        flags: usize,
        restorer: usize,
        old_mask: u64,
        siginfo: UserSigInfo,
    },
}

fn signal_trampoline_addr() -> VirtAddr {
    VirtAddr::from_usize(
        axconfig::plat::USER_STACK_TOP - axconfig::plat::USER_STACK_SIZE - PAGE_SIZE_4K,
    )
}

fn signal_default_ignored(signum: usize) -> bool {
    matches!(signum, SIGCHLD | SIGCONT | SIGURG | SIGWINCH)
}

fn signal_default_stops(signum: usize) -> bool {
    matches!(signum, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

fn signal_is_cancel(signum: usize) -> bool {
    matches!(signum, SIGCANCEL | SIGCANCEL_LEGACY)
}

fn signal_default_terminates(signum: usize) -> bool {
    matches!(
        signum,
        SIGHUP
            | SIGABRT
            | SIGALRM
            | SIGBUS
            | SIGFPE
            | SIGILL
            | SIGINT
            | SIGIO
            | SIGKILL
            | SIGQUIT
            | SIGSEGV
            | SIGPIPE
            | SIGPROF
            | SIGPWR
            | SIGSTKFLT
            | SIGSYS
            | SIGTERM
            | SIGTRAP
            | SIGUSR1
            | SIGUSR2
            | SIGVTALRM
            | SIGXCPU
            | SIGXFSZ
    )
}

fn has_interrupting_pending_signal_with_ignored_mask(
    signals: &SignalState,
    restartable: bool,
    ignored_mask: u64,
) -> bool {
    let mut ready = signals.pending_mask & !signals.blocked_mask & !ignored_mask;
    while ready != 0 {
        let signum = ready.trailing_zeros() as usize + 1;
        ready &= !SignalState::signal_bit(signum);

        if matches!(signum, SIGKILL | SIGSTOP) {
            return true;
        }

        let action = signals.action(signum);
        if action.handler == SIG_IGN {
            continue;
        }
        if action.handler == SIG_DFL && signal_default_ignored(signum) {
            continue;
        }
        if restartable && action.handler != SIG_DFL && action.flags & SA_RESTART != 0 {
            continue;
        }
        return true;
    }
    false
}

fn has_interrupting_pending_signal(signals: &SignalState, restartable: bool) -> bool {
    has_interrupting_pending_signal_with_ignored_mask(signals, restartable, 0)
}

fn current_now_ns() -> usize {
    monotonic_time_nanos() as usize
}

fn timeval_to_ns(tv: UserTimeval) -> LinuxResult<usize> {
    if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
        return Err(LinuxError::EINVAL);
    }
    let secs = tv.tv_sec as usize;
    let usecs = tv.tv_usec as usize;
    secs.checked_mul(NANOS_PER_SEC as usize)
        .and_then(|base| {
            usecs
                .checked_mul(NANOS_PER_MICROS as usize)
                .map(|delta| base + delta)
        })
        .ok_or(LinuxError::EINVAL)
}

fn ns_to_timeval(ns: usize) -> UserTimeval {
    UserTimeval {
        tv_sec: (ns / NANOS_PER_SEC as usize) as i64,
        tv_usec: ((ns % NANOS_PER_SEC as usize) / NANOS_PER_MICROS as usize) as i64,
    }
}

fn ns_to_timespec(ns: u64) -> UserTimespec {
    UserTimespec {
        tv_sec: (ns / NANOS_PER_SEC) as i64,
        tv_nsec: (ns % NANOS_PER_SEC) as i64,
    }
}

fn timespec_to_ns(ts: UserTimespec) -> LinuxResult<usize> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= NANOS_PER_SEC as i64 {
        return Err(LinuxError::EINVAL);
    }
    let secs = ts.tv_sec as usize;
    let nanos = ts.tv_nsec as usize;
    secs.checked_mul(NANOS_PER_SEC as usize)
        .and_then(|base| base.checked_add(nanos))
        .ok_or(LinuxError::EINVAL)
}

fn write_itimerspec(dst: *mut c_void, interval_ns: u64, value_ns: u64) -> Result<(), LinuxError> {
    if dst.is_null() {
        return Ok(());
    }
    write_value_to_user(
        dst as *mut UserItimerspec,
        UserItimerspec {
            it_interval: ns_to_timespec(interval_ns),
            it_value: ns_to_timespec(value_ns),
        },
    )
}

fn fill_itimerval(dst: *mut c_void, interval_ns: usize, value_ns: usize) -> Result<(), LinuxError> {
    if dst.is_null() {
        return Ok(());
    }
    write_value_to_user(
        dst as *mut UserItimerval,
        UserItimerval {
            it_interval: ns_to_timeval(interval_ns),
            it_value: ns_to_timeval(value_ns),
        },
    )
}

fn sanitize_mask(mask: u64) -> u64 {
    mask & !(SignalState::signal_bit(SIGKILL) | SignalState::signal_bit(SIGSTOP))
}

pub(crate) fn read_user_sigset_mask(set: *const c_void) -> LinuxResult<u64> {
    if set.is_null() {
        return Err(LinuxError::EFAULT);
    }
    Ok(sanitize_mask(
        read_value_from_user(set as *const UserSigSet)?.as_mask(),
    ))
}

pub(crate) fn current_blocked_mask() -> u64 {
    current().task_ext().signals.lock().blocked_mask
}

pub(crate) fn set_current_blocked_mask(mask: u64) {
    current().task_ext().signals.lock().blocked_mask = sanitize_mask(mask);
}

fn refresh_timers(signals: &mut SignalState, now_ns: usize) {
    signals.update_real_timer(now_ns);
    signals.update_posix_timers(now_ns);
}

fn process_user_cpu_time_ns(proc_id: usize) -> usize {
    thread_group_tasks(proc_id)
        .into_iter()
        .fold(0usize, |acc, task| {
            let (utime_ns, _) = task.task_ext().time_stat_output();
            acc.saturating_add(utime_ns)
        })
}

fn process_prof_cpu_time_ns(proc_id: usize) -> usize {
    thread_group_tasks(proc_id)
        .into_iter()
        .fold(0usize, |acc, task| {
            let (utime_ns, stime_ns) = task.task_ext().time_stat_output();
            acc.saturating_add(utime_ns.saturating_add(stime_ns))
        })
}

fn process_itimer_clock_ns(proc_id: usize, which: i32) -> usize {
    match which {
        ITIMER_VIRTUAL => process_user_cpu_time_ns(proc_id),
        ITIMER_PROF => process_prof_cpu_time_ns(proc_id),
        _ => 0,
    }
}

fn itimer_signal(which: i32) -> usize {
    match which {
        ITIMER_REAL => SIGALRM,
        ITIMER_VIRTUAL => SIGVTALRM,
        ITIMER_PROF => SIGPROF,
        _ => SIGALRM,
    }
}

fn wake_thread_group_for_signal(proc_id: usize, signum: usize) {
    for task in thread_group_tasks(proc_id) {
        wake_task_for_signal(&task, signum);
    }
}

fn queue_posix_timer_signal(owner: &AxTaskRef, notify: i32, signum: usize, notify_tid: u64) {
    match notify {
        SIGEV_SIGNAL => {
            let mut signals = owner.task_ext().signals.lock();
            signals.queue_signal(signum, None);
            drop(signals);
            wake_thread_group_for_signal(owner.task_ext().proc_id, signum);
        }
        SIGEV_THREAD_ID => {
            if let Some(target) = find_live_task_by_tid(notify_tid) {
                queue_signal_and_wake(&target, signum, None);
            } else {
                let mut signals = owner.task_ext().signals.lock();
                signals.queue_signal(signum, None);
                drop(signals);
                wake_thread_group_for_signal(owner.task_ext().proc_id, signum);
            }
        }
        _ => {}
    }
}

fn spawn_real_timer_worker(owner: &AxTaskRef, armed_seq: u64) {
    let owner = Arc::downgrade(owner);
    axtask::spawn_raw(move || loop {
        let Some(owner) = owner.upgrade() else {
            return;
        };

        let (deadline_ns, interval_ns) = {
            let signals = owner.task_ext().signals.lock();
            if signals.real_timer_armed_seq != armed_seq || signals.real_timer_deadline_ns == 0 {
                return;
            }
            (
                signals.real_timer_deadline_ns as u64,
                signals.real_timer_interval_ns as u64,
            )
        };

        let now_ns = monotonic_time_nanos();
        if now_ns < deadline_ns {
            axtask::sleep(core::time::Duration::from_nanos(
                deadline_ns.saturating_sub(now_ns),
            ));
        }

        let periodic = {
            let now_ns = monotonic_time_nanos() as usize;
            let mut signals = owner.task_ext().signals.lock();
            if signals.real_timer_armed_seq != armed_seq || signals.real_timer_deadline_ns == 0 {
                return;
            }
            if now_ns < signals.real_timer_deadline_ns {
                true
            } else {
                signals.queue_signal(SIGALRM, None);
                if signals.real_timer_interval_ns == 0 {
                    signals.real_timer_deadline_ns = 0;
                    false
                } else {
                    let overdue = now_ns - signals.real_timer_deadline_ns;
                    let steps = overdue / signals.real_timer_interval_ns + 1;
                    signals.real_timer_deadline_ns += steps * signals.real_timer_interval_ns;
                    true
                }
            }
        };
        wake_task_for_signal(&owner, SIGALRM);
        if trace_setitimer01_task(&owner) {
            if let Some(slot) = take_setitimer_diag_slot() {
                warn!(
                        "[setitimer-diag:{}] fire kind=real owner_tid={} owner_pid={} seq={} periodic={}",
                        slot,
                        owner.id().as_u64(),
                        owner.task_ext().proc_id,
                        armed_seq,
                        periodic,
                    );
            }
        }
        if !periodic {
            return;
        }
    }, "signal-real-timer".into(), SIGNAL_WORKER_STACK_SIZE);
}

fn spawn_cpu_itimer_worker(owner: &AxTaskRef, which: i32, armed_seq: u64) {
    let owner = Arc::downgrade(owner);
    axtask::spawn_raw(move || loop {
        let Some(owner) = owner.upgrade() else {
            return;
        };
        let proc_id = owner.task_ext().proc_id;
        let (deadline_ns, interval_ns) = {
            let signals = owner.task_ext().signals.lock();
            match which {
                ITIMER_VIRTUAL => {
                    if signals.virtual_timer_armed_seq != armed_seq
                        || signals.virtual_timer_deadline_ns == 0
                    {
                        return;
                    }
                    (
                        signals.virtual_timer_deadline_ns as u64,
                        signals.virtual_timer_interval_ns as u64,
                    )
                }
                ITIMER_PROF => {
                    if signals.prof_timer_armed_seq != armed_seq
                        || signals.prof_timer_deadline_ns == 0
                    {
                        return;
                    }
                    (
                        signals.prof_timer_deadline_ns as u64,
                        signals.prof_timer_interval_ns as u64,
                    )
                }
                _ => return,
            }
        };

        let now_cpu_ns = process_itimer_clock_ns(proc_id, which) as u64;
        if now_cpu_ns < deadline_ns {
            let sleep_ns = deadline_ns.saturating_sub(now_cpu_ns).min(1_000_000);
            axtask::sleep(core::time::Duration::from_nanos(sleep_ns.max(1)));
            continue;
        }

        let periodic = {
            let now_cpu_ns = process_itimer_clock_ns(proc_id, which);
            let mut signals = owner.task_ext().signals.lock();
            match which {
                ITIMER_VIRTUAL => {
                    if signals.virtual_timer_armed_seq != armed_seq
                        || signals.virtual_timer_deadline_ns == 0
                    {
                        return;
                    }
                    if now_cpu_ns < signals.virtual_timer_deadline_ns {
                        true
                    } else if signals.virtual_timer_interval_ns == 0 {
                        signals.virtual_timer_deadline_ns = 0;
                        false
                    } else {
                        let overdue = now_cpu_ns - signals.virtual_timer_deadline_ns;
                        let steps = overdue / signals.virtual_timer_interval_ns + 1;
                        signals.virtual_timer_deadline_ns +=
                            steps * signals.virtual_timer_interval_ns;
                        true
                    }
                }
                ITIMER_PROF => {
                    if signals.prof_timer_armed_seq != armed_seq
                        || signals.prof_timer_deadline_ns == 0
                    {
                        return;
                    }
                    if now_cpu_ns < signals.prof_timer_deadline_ns {
                        true
                    } else if signals.prof_timer_interval_ns == 0 {
                        signals.prof_timer_deadline_ns = 0;
                        false
                    } else {
                        let overdue = now_cpu_ns - signals.prof_timer_deadline_ns;
                        let steps = overdue / signals.prof_timer_interval_ns + 1;
                        signals.prof_timer_deadline_ns += steps * signals.prof_timer_interval_ns;
                        true
                    }
                }
                _ => return,
            }
        };

        queue_signal_and_wake(&owner, itimer_signal(which), None);
        if trace_setitimer01_task(&owner) {
            if let Some(slot) = take_setitimer_diag_slot() {
                warn!(
                    "[setitimer-diag:{}] fire kind={} owner_tid={} owner_pid={} seq={} periodic={}",
                    slot,
                    which,
                    owner.id().as_u64(),
                    owner.task_ext().proc_id,
                    armed_seq,
                    periodic,
                );
            }
        }
        if !periodic {
            return;
        }
    }, "signal-cpu-itimer".into(), SIGNAL_WORKER_STACK_SIZE);
}

fn spawn_posix_timer_worker(owner: &AxTaskRef, timer_id: i32, armed_seq: u64) {
    let owner = Arc::downgrade(owner);
    axtask::spawn_raw(move || loop {
        let Some(owner) = owner.upgrade() else {
            return;
        };
        if trace_clock_settime03_task(&owner) {
            warn!(
                "[clock_settime03-worker] state=start owner_tid={} owner_pid={} timerid={} seq={}",
                owner.id().as_u64(),
                owner.task_ext().proc_id,
                timer_id,
                armed_seq
            );
        }

        let deadline_ns = {
            let signals = owner.task_ext().signals.lock();
            let Some(timer) = signals.posix_timers.get(&timer_id) else {
                return;
            };
            if timer.armed_seq != armed_seq || timer.deadline_ns == 0 {
                return;
            }
            timer.deadline_ns
        };

        let now_ns = monotonic_time_nanos();
        if now_ns < deadline_ns {
            let sleep_ns = deadline_ns.saturating_sub(now_ns);
            if trace_clock_settime03_task(&owner) {
                warn!(
                        "[clock_settime03-worker] state=sleep owner_tid={} owner_pid={} timerid={} seq={} now_ns={} deadline_ns={} sleep_ns={}",
                        owner.id().as_u64(),
                        owner.task_ext().proc_id,
                        timer_id,
                        armed_seq,
                        now_ns,
                        deadline_ns,
                        sleep_ns
                    );
            }
            axtask::sleep(core::time::Duration::from_nanos(sleep_ns));
        }

        let now_ns = monotonic_time_nanos();
        if trace_clock_settime03_task(&owner) {
            warn!(
                    "[clock_settime03-worker] state=wake owner_tid={} owner_pid={} timerid={} seq={} now_ns={}",
                    owner.id().as_u64(),
                    owner.task_ext().proc_id,
                    timer_id,
                    armed_seq,
                    now_ns
                );
        }
        let expired = {
            let mut signals = owner.task_ext().signals.lock();
            let Some(timer) = signals.posix_timers.get_mut(&timer_id) else {
                return;
            };
            if timer.armed_seq != armed_seq || timer.deadline_ns == 0 {
                return;
            }
            if now_ns < timer.deadline_ns {
                None
            } else {
                let notify = timer.notify;
                let signum = timer.notify_signum;
                let notify_tid = timer.notify_tid;
                if timer.interval_ns == 0 {
                    timer.deadline_ns = 0;
                    timer.overrun = 0;
                } else {
                    let overdue = now_ns - timer.deadline_ns;
                    let steps = overdue / timer.interval_ns + 1;
                    timer.deadline_ns = timer
                        .deadline_ns
                        .saturating_add(steps.saturating_mul(timer.interval_ns));
                    timer.overrun = steps.saturating_sub(1).min(u32::MAX as u64) as u32;
                }
                Some((notify, signum, notify_tid, timer.interval_ns != 0))
            }
        };

        let Some((notify, signum, notify_tid, periodic)) = expired else {
            continue;
        };
        queue_posix_timer_signal(&owner, notify, signum, notify_tid);
        if !periodic {
            return;
        }
    }, "signal-posix-timer".into(), SIGNAL_WORKER_STACK_SIZE);
}

fn thread_group_next_posix_timer_deadline(proc_id: usize) -> Option<u64> {
    let mut next_deadline: Option<u64> = None;
    for task in thread_group_tasks(proc_id) {
        let signals = task.task_ext().signals.lock();
        for timer in signals.posix_timers.values() {
            if timer.deadline_ns == 0 {
                continue;
            }
            next_deadline = Some(match next_deadline {
                Some(current) => current.min(timer.deadline_ns),
                None => timer.deadline_ns,
            });
        }
    }
    next_deadline
}

fn trace_clock_settime03() -> bool {
    trace_clock_settime03_task(current().as_task_ref())
}

fn trace_clock_settime03_task(task: &AxTaskRef) -> bool {
    let exec_path = task.task_ext().exec_path();
    exec_path.ends_with("/clock_settime03") || exec_path.ends_with("/clock_settime03.exe")
}

fn take_matching_pending_signal(
    task: &AxTaskRef,
    wait_mask: u64,
    now_ns: usize,
) -> Option<(usize, UserSigInfo)> {
    let mut signals = task.task_ext().signals.lock();
    refresh_timers(&mut signals, now_ns);
    let ready = signals.pending_mask & wait_mask;
    if ready == 0 {
        return None;
    }

    let signum = ready.trailing_zeros() as usize + 1;
    if trace_clock_settime03() {
        warn!(
            "[clock_settime03-sigwait] curr_tid={} source_tid={} proc_id={} ready_signum={} pending_mask={:#x} wait_mask={:#x}",
            current().id().as_u64(),
            task.id().as_u64(),
            task.task_ext().proc_id,
            signum,
            signals.pending_mask,
            wait_mask
        );
    }
    signals.pending_mask &= !SignalState::signal_bit(signum);
    Some((signum, signals.take_pending_info(signum)))
}

fn take_thread_group_pending_signal(
    curr: &AxTaskRef,
    wait_mask: u64,
    now_ns: usize,
) -> Option<(usize, UserSigInfo)> {
    if let Some(ready) = take_matching_pending_signal(curr, wait_mask, now_ns) {
        return Some(ready);
    }

    for task in thread_group_tasks(curr.task_ext().proc_id) {
        if task.id().as_u64() == curr.id().as_u64() {
            continue;
        }
        if let Some(ready) = take_matching_pending_signal(&task, wait_mask, now_ns) {
            return Some(ready);
        }
    }

    None
}

fn prepare_signal_delivery() -> Option<PreparedSignal> {
    let now_ns = current_now_ns();
    let curr = current();
    let mut signals = curr.task_ext().signals.lock();
    refresh_timers(&mut signals, now_ns);
    if signals.in_handler {
        return None;
    }

    loop {
        let ready = signals.pending_mask & !signals.blocked_mask;
        if ready == 0 {
            return None;
        }

        let signum = ready.trailing_zeros() as usize + 1;
        let bit = SignalState::signal_bit(signum);
        signals.pending_mask &= !bit;
        let siginfo = signals.take_pending_info(signum);
        let action = signals.action(signum);

        if signum == SIGKILL {
            return Some(PreparedSignal::Terminate(signum));
        }
        if signum == SIGSTOP {
            return Some(PreparedSignal::Stop(signum));
        }

        if action.handler == SIG_IGN
            || (action.handler == SIG_DFL && signal_default_ignored(signum))
        {
            continue;
        }
        if action.handler == SIG_DFL {
            if signal_default_stops(signum) {
                return Some(PreparedSignal::Stop(signum));
            }
            return Some(PreparedSignal::Terminate(signum));
        }

        let restore_mask = signals
            .sigsuspend_restore_mask
            .unwrap_or(signals.blocked_mask);
        let current_mask = signals.blocked_mask;
        let mut new_mask = current_mask | action.mask;
        if action.flags & SA_NODEFER == 0 {
            new_mask |= bit;
        }
        signals.blocked_mask = sanitize_mask(new_mask);
        signals.sigsuspend_restore_mask = None;
        signals.in_handler = true;
        if action.flags & SA_RESETHAND != 0 {
            signals.set_action(signum, SignalAction::default());
        }
        return Some(PreparedSignal::Handler {
            signum,
            handler: action.handler,
            flags: action.flags,
            restorer: action.restorer,
            old_mask: restore_mask,
            siginfo,
        });
    }
}

fn deliver_signal(
    tf: &mut TrapFrame,
    signum: usize,
    mut handler: usize,
    flags: usize,
    mut restorer: usize,
    old_mask: u64,
    siginfo: UserSigInfo,
) {
    let exec_image_base = current().task_ext().exec_image_base() as usize;
    let needs_bias =
        |addr: usize| exec_image_base != 0 && addr > 1 && addr < axconfig::plat::USER_SPACE_BASE;
    let original_handler = handler;
    let original_restorer = restorer;
    if needs_bias(handler) {
        handler = handler.saturating_add(exec_image_base);
    }
    if needs_bias(restorer) {
        restorer = restorer.saturating_add(exec_image_base);
    }
    if trace_mprotect02_signal() && (handler != original_handler || restorer != original_restorer) {
        if let Some(slot) = take_mprotect02_signal_log_slot() {
            warn!(
                "[mprotect02-signal:{}] task={} pid={} action=normalize exec_base={:#x} handler={:#x}->{:#x} restorer={:#x}->{:#x}",
                slot,
                current().id_name(),
                current().task_ext().proc_id,
                exec_image_base,
                original_handler,
                handler,
                original_restorer,
                restorer,
            );
        }
    }
    if trace_mprotect02_signal() {
        if let Some(slot) = take_mprotect02_signal_log_slot() {
            let mut handler_bytes = [0u8; 8];
            let handler_query = current()
                .task_ext()
                .aspace
                .lock()
                .page_table()
                .query(VirtAddr::from_usize(handler))
                .ok();
            let handler_read = current()
                .task_ext()
                .aspace
                .lock()
                .read(VirtAddr::from_usize(handler), &mut handler_bytes)
                .map(|_| handler_bytes);
            warn!(
                "[mprotect02-signal:{}] task={} pid={} action=target handler={:#x} handler_query={:?} handler_read={:?}",
                slot,
                current().id_name(),
                current().task_ext().proc_id,
                handler,
                handler_query,
                handler_read,
            );
        }
    }
    let frame = SignalFrame {
        siginfo,
        ucontext: build_user_ucontext(tf, old_mask),
        magic: SIGNAL_FRAME_MAGIC,
    };
    let frame_size = size_of::<SignalFrame>();
    let frame_sp = match tf.get_sp().checked_sub(frame_size).map(|sp| sp & !0xfusize) {
        Some(sp) => sp,
        None => {
            warn!("signal stack underflow for signal {}", signum);
            exit_current_for_signal(-(signum as i32));
        }
    };

    let bytes = unsafe {
        core::slice::from_raw_parts((&frame as *const SignalFrame).cast::<u8>(), frame_size)
    };
    if let Err(err) = crate::usercopy::copy_to_user(frame_sp as *mut c_void, bytes) {
        warn!(
            "failed to write signal frame for signal {} at {:#x}: {:?}",
            signum, frame_sp, err
        );
        exit_current_for_signal(-(signum as i32));
    }

    tf.set_sp(frame_sp);
    tf.set_ip(handler);
    let use_restorer = flags & SA_RESTORER != 0 && !matches!(restorer, 0 | usize::MAX);
    tf.set_ra(if use_restorer {
        restorer
    } else {
        signal_trampoline_addr().as_usize()
    });
    tf.set_arg0(signum);
    if flags & SA_SIGINFO != 0 {
        let siginfo_addr = frame_sp + core::mem::offset_of!(SignalFrame, siginfo);
        let ucontext_addr = frame_sp + core::mem::offset_of!(SignalFrame, ucontext);
        tf.set_arg1(siginfo_addr);
        tf.set_arg2(ucontext_addr);
    } else {
        tf.set_arg1(0);
        tf.set_arg2(0);
    }
}

#[cfg(target_arch = "riscv64")]
fn build_user_ucontext(tf: &TrapFrame, old_mask: u64) -> UserUContext {
    let mut gregs = [0u64; 32];
    gregs[0] = tf.get_ip() as u64;
    gregs[1] = tf.regs.ra as u64;
    gregs[2] = tf.regs.sp as u64;
    gregs[3] = tf.regs.gp as u64;
    gregs[4] = tf.regs.tp as u64;
    gregs[5] = tf.regs.t0 as u64;
    gregs[6] = tf.regs.t1 as u64;
    gregs[7] = tf.regs.t2 as u64;
    gregs[8] = tf.regs.s0 as u64;
    gregs[9] = tf.regs.s1 as u64;
    gregs[10] = tf.regs.a0 as u64;
    gregs[11] = tf.regs.a1 as u64;
    gregs[12] = tf.regs.a2 as u64;
    gregs[13] = tf.regs.a3 as u64;
    gregs[14] = tf.regs.a4 as u64;
    gregs[15] = tf.regs.a5 as u64;
    gregs[16] = tf.regs.a6 as u64;
    gregs[17] = tf.regs.a7 as u64;
    gregs[18] = tf.regs.s2 as u64;
    gregs[19] = tf.regs.s3 as u64;
    gregs[20] = tf.regs.s4 as u64;
    gregs[21] = tf.regs.s5 as u64;
    gregs[22] = tf.regs.s6 as u64;
    gregs[23] = tf.regs.s7 as u64;
    gregs[24] = tf.regs.s8 as u64;
    gregs[25] = tf.regs.s9 as u64;
    gregs[26] = tf.regs.s10 as u64;
    gregs[27] = tf.regs.s11 as u64;
    gregs[28] = tf.regs.t3 as u64;
    gregs[29] = tf.regs.t4 as u64;
    gregs[30] = tf.regs.t5 as u64;
    gregs[31] = tf.regs.t6 as u64;
    UserUContext {
        uc_flags: 0,
        uc_link: 0,
        uc_stack: UserStack::default(),
        uc_sigmask: UserContextSigSet::from_mask(old_mask),
        _pad: 0,
        uc_mcontext: UserMContext {
            gregs,
            fpregs: [0; 528],
        },
    }
}

#[cfg(target_arch = "loongarch64")]
fn build_user_ucontext(tf: &TrapFrame, old_mask: u64) -> UserUContext {
    let mut gregs = [0u64; 32];
    for (index, value) in tf.regs.iter().enumerate() {
        gregs[index] = *value as u64;
    }
    UserUContext {
        uc_flags: 0,
        uc_link: 0,
        uc_stack: UserStack::default(),
        uc_sigmask: UserContextSigSet::from_mask(old_mask),
        uc_mcontext: UserMContext {
            pc: tf.get_ip() as u64,
            gregs,
            flags: 0,
            _pad: 0,
        },
    }
}

#[cfg(target_arch = "riscv64")]
fn restore_trapframe_from_ucontext(tf: &mut TrapFrame, ucontext: &UserUContext) {
    let gregs = &ucontext.uc_mcontext.gregs;
    tf.set_ip(gregs[0] as usize);
    tf.regs.ra = gregs[1] as usize;
    tf.regs.sp = gregs[2] as usize;
    tf.regs.gp = gregs[3] as usize;
    tf.regs.tp = gregs[4] as usize;
    tf.regs.t0 = gregs[5] as usize;
    tf.regs.t1 = gregs[6] as usize;
    tf.regs.t2 = gregs[7] as usize;
    tf.regs.s0 = gregs[8] as usize;
    tf.regs.s1 = gregs[9] as usize;
    tf.regs.a0 = gregs[10] as usize;
    tf.regs.a1 = gregs[11] as usize;
    tf.regs.a2 = gregs[12] as usize;
    tf.regs.a3 = gregs[13] as usize;
    tf.regs.a4 = gregs[14] as usize;
    tf.regs.a5 = gregs[15] as usize;
    tf.regs.a6 = gregs[16] as usize;
    tf.regs.a7 = gregs[17] as usize;
    tf.regs.s2 = gregs[18] as usize;
    tf.regs.s3 = gregs[19] as usize;
    tf.regs.s4 = gregs[20] as usize;
    tf.regs.s5 = gregs[21] as usize;
    tf.regs.s6 = gregs[22] as usize;
    tf.regs.s7 = gregs[23] as usize;
    tf.regs.s8 = gregs[24] as usize;
    tf.regs.s9 = gregs[25] as usize;
    tf.regs.s10 = gregs[26] as usize;
    tf.regs.s11 = gregs[27] as usize;
    tf.regs.t3 = gregs[28] as usize;
    tf.regs.t4 = gregs[29] as usize;
    tf.regs.t5 = gregs[30] as usize;
    tf.regs.t6 = gregs[31] as usize;
}

#[cfg(target_arch = "loongarch64")]
fn restore_trapframe_from_ucontext(tf: &mut TrapFrame, ucontext: &UserUContext) {
    tf.set_ip(ucontext.uc_mcontext.pc as usize);
    for index in 1..32 {
        tf.regs[index] = ucontext.uc_mcontext.gregs[index] as usize;
    }
}

fn handle_user_return(tf: &mut TrapFrame) {
    loop {
        let Some(prepared) = prepare_signal_delivery() else {
            return;
        };
        if trace_mprotect02_signal() {
            if let Some(slot) = take_mprotect02_signal_log_slot() {
                match prepared {
                    PreparedSignal::Terminate(signum) => warn!(
                        "[mprotect02-signal:{}] task={} pid={} action=terminate signum={}",
                        slot,
                        current().id_name(),
                        current().task_ext().proc_id,
                        signum
                    ),
                    PreparedSignal::Stop(signum) => warn!(
                        "[mprotect02-signal:{}] task={} pid={} action=stop signum={}",
                        slot,
                        current().id_name(),
                        current().task_ext().proc_id,
                        signum
                    ),
                    PreparedSignal::Handler {
                        signum, handler, ..
                    } => warn!(
                        "[mprotect02-signal:{}] task={} pid={} action=handler signum={} handler={:#x} exec_base={:#x} user_base={:#x}",
                        slot,
                        current().id_name(),
                        current().task_ext().proc_id,
                        signum,
                        handler,
                        current().task_ext().exec_image_base(),
                        axconfig::plat::USER_SPACE_BASE,
                    ),
                }
            }
        }
        if trace_setitimer01() {
            if let Some(slot) = take_setitimer_diag_slot() {
                match prepared {
                    PreparedSignal::Terminate(signum) => warn!(
                        "[setitimer-diag:{}] deliver action=terminate tid={} pid={} signum={}",
                        slot,
                        current().id().as_u64(),
                        current().task_ext().proc_id,
                        signum,
                    ),
                    PreparedSignal::Stop(signum) => warn!(
                        "[setitimer-diag:{}] deliver action=stop tid={} pid={} signum={}",
                        slot,
                        current().id().as_u64(),
                        current().task_ext().proc_id,
                        signum,
                    ),
                    PreparedSignal::Handler {
                        signum, handler, ..
                    } => warn!(
                        "[setitimer-diag:{}] deliver action=handler tid={} pid={} signum={} handler={:#x}",
                        slot,
                        current().id().as_u64(),
                        current().task_ext().proc_id,
                        signum,
                        handler,
                    ),
                }
            }
        }
        match prepared {
            PreparedSignal::Terminate(signum) => exit_current_for_signal(
                crate::task::wait_status_signaled(signum, signal_generates_core_dump(signum)),
            ),
            PreparedSignal::Stop(signum) => stop_current_for_signal(signum),
            PreparedSignal::Handler {
                signum,
                handler,
                flags,
                restorer,
                old_mask,
                siginfo,
            } => {
                deliver_signal(tf, signum, handler, flags, restorer, old_mask, siginfo);
                return;
            }
        }
    }
}

pub(crate) fn dispatch_current_signals(tf: &mut TrapFrame) {
    handle_user_return(tf);
}

fn exit_current_for_signal(status: i32) -> ! {
    crate::task::exit_current_task(status, true, true);
}

fn stop_current_for_signal(signum: usize) {
    let curr = current();
    let notified_parent = curr.task_ext().mark_stopped_for_wait(signum);
    if notified_parent {
        if let Some(parent) = curr.task_ext().parent_task() {
            if curr.task_ext().proc_id != parent.task_ext().proc_id {
                parent.task_ext().note_child_wait_event();
            }
        }
    }

    loop {
        let mut should_continue = false;
        let mut terminating_signal = None;
        {
            let now_ns = current_now_ns();
            let mut signals = curr.task_ext().signals.lock();
            refresh_timers(&mut signals, now_ns);

            if signals.pending_mask & SignalState::signal_bit(SIGCONT) != 0 {
                signals.clear_pending(SIGCONT);
                should_continue = true;
            } else {
                let mut ready = signals.pending_mask & !signals.blocked_mask;
                while ready != 0 {
                    let next = ready.trailing_zeros() as usize + 1;
                    let bit = SignalState::signal_bit(next);
                    ready &= !bit;

                    let action = signals.action(next);
                    if next == SIGKILL {
                        signals.clear_pending(next);
                        let _ = signals.take_pending_info(next);
                        terminating_signal = Some(next);
                        break;
                    }
                    if next == SIGSTOP {
                        break;
                    }

                    if action.handler == SIG_IGN
                        || (action.handler == SIG_DFL && signal_default_ignored(next))
                    {
                        continue;
                    }
                    if action.handler == SIG_DFL && signal_default_terminates(next) {
                        signals.clear_pending(next);
                        let _ = signals.take_pending_info(next);
                        terminating_signal = Some(next);
                    }
                    break;
                }
            }
        }

        if let Some(term) = terminating_signal {
            exit_current_for_signal(crate::task::wait_status_signaled(
                term,
                signal_generates_core_dump(term),
            ));
        }

        if should_continue {
            let resumed = curr.task_ext().mark_continued_for_wait();
            if resumed {
                if let Some(parent) = curr.task_ext().parent_task() {
                    if curr.task_ext().proc_id != parent.task_ext().proc_id {
                        parent.task_ext().note_child_wait_event();
                    }
                }
            }
            return;
        }

        curr.task_ext()
            .stop_wq
            .wait_timeout(core::time::Duration::from_millis(10));
    }
}

fn signal_generates_core_dump(signum: usize) -> bool {
    matches!(
        signum,
        SIGABRT
            | SIGBUS
            | SIGFPE
            | SIGILL
            | SIGQUIT
            | SIGSEGV
            | SIGSYS
            | SIGTRAP
            | SIGXCPU
            | SIGXFSZ
    )
}

pub fn init() {
    trap::set_user_trap_enter_handler(crate::task::time_stat_from_user_to_kernel);
    trap::set_user_return_handler(dispatch_signals_on_user_return);
    #[cfg(target_arch = "riscv64")]
    trap::set_user_trap_diagnostic_handler(handle_user_trap_diagnostic);
}

fn dispatch_signals_on_user_return(tf: &mut TrapFrame) {
    crate::task::time_stat_from_kernel_to_user();
    handle_user_return(tf);
}

pub(crate) fn send_current_signal(signum: usize) {
    if SignalState::signal_index(signum).is_err() {
        return;
    }
    let curr = current();
    if trace_mprotect02_signal() {
        if let Some(slot) = take_mprotect02_signal_log_slot() {
            warn!(
                "[mprotect02-queue:{}] task={} pid={} signum={}",
                slot,
                curr.id_name(),
                curr.task_ext().proc_id,
                signum
            );
        }
    }
    let mut signals = curr.task_ext().signals.lock();
    signals.queue_signal(signum, None);
}

fn wake_task_for_signal(task: &AxTaskRef, signum: usize) {
    let should_yield = !axtask::wake_task(task) && current().id().as_u64() != task.id().as_u64();
    if should_yield {
        let _ = signum;
        axtask::yield_now();
    }
}

fn queue_signal_and_wake(task: &AxTaskRef, signum: usize, siginfo: Option<UserSigInfo>) {
    let mut signals = task.task_ext().signals.lock();
    signals.queue_signal(signum, siginfo);
    drop(signals);
    wake_task_for_signal(task, signum);
}

pub(crate) fn task_ignores_signal_by_default(task: &AxTaskRef, signum: usize) -> bool {
    if SignalState::signal_index(signum).is_err() {
        return false;
    }
    let signals = task.task_ext().signals.lock();
    let action = signals.action(signum);
    action.handler == SIG_DFL && signal_default_ignored(signum)
}

pub(crate) fn send_signal_to_task(task: &AxTaskRef, signum: usize) {
    if SignalState::signal_index(signum).is_err() {
        return;
    }
    let curr = current();
    if signal_is_cancel(signum) {
        warn!(
            "queue_cancel_signal from_tid={} from_pid={} to_tid={} to_pid={} signum={}",
            curr.id().as_u64(),
            curr.task_ext().proc_id,
            task.id().as_u64(),
            task.task_ext().proc_id,
            signum
        );
        queue_signal_and_wake(
            task,
            signum,
            Some(UserSigInfo::tkill(
                signum,
                curr.task_ext().proc_id as i32,
                axfs::api::current_uid(),
            )),
        );
        return;
    }
    let broadcast_group = if signum == SIGKILL {
        true
    } else {
        let signals = task.task_ext().signals.lock();
        let action = signals.action(signum);
        action.handler == SIG_DFL && signal_default_terminates(signum)
    };
    if broadcast_group {
        for member in thread_group_tasks(task.task_ext().proc_id) {
            queue_signal_and_wake(&member, signum, None);
        }
    } else {
        queue_signal_and_wake(task, signum, None);
    }
}

pub(crate) fn send_signal_to_task_with_siginfo(
    task: &AxTaskRef,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
    value: usize,
) {
    if SignalState::signal_index(signum).is_err() {
        return;
    }
    let siginfo = UserSigInfo::queued(signum, sender_pid, sender_uid, value);
    let broadcast_group = if signum == SIGKILL {
        true
    } else {
        let signals = task.task_ext().signals.lock();
        let action = signals.action(signum);
        action.handler == SIG_DFL && signal_default_terminates(signum)
    };
    if broadcast_group {
        for member in thread_group_tasks(task.task_ext().proc_id) {
            queue_signal_and_wake(&member, signum, Some(siginfo));
        }
    } else {
        queue_signal_and_wake(task, signum, Some(siginfo));
    }
}

pub(crate) fn send_tkill_signal_to_task(
    task: &AxTaskRef,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
) {
    if SignalState::signal_index(signum).is_err() {
        return;
    }
    let siginfo = UserSigInfo::tkill(signum, sender_pid, sender_uid);
    queue_signal_and_wake(task, signum, Some(siginfo));
}

pub(crate) fn send_user_signal_to_task(
    task: &AxTaskRef,
    signum: usize,
    sender_pid: i32,
    sender_uid: u32,
) {
    if SignalState::signal_index(signum).is_err() {
        return;
    }
    let siginfo = UserSigInfo::user(signum, sender_pid, sender_uid);
    let action = {
        let signals = task.task_ext().signals.lock();
        signals.action(signum)
    };
    let broadcast_group = signum == SIGKILL
        || (action.handler == SIG_DFL && signal_default_terminates(signum));
    if broadcast_group {
        for member in thread_group_tasks(task.task_ext().proc_id) {
            queue_signal_and_wake(&member, signum, Some(siginfo));
        }
    } else {
        queue_signal_and_wake(task, signum, Some(siginfo));
    }
}

pub(crate) fn current_has_pending_signal() -> bool {
    current_has_interrupting_signal(false)
}

pub(crate) fn current_has_interrupting_signal(restartable: bool) -> bool {
    let curr = current();
    let now_ns = current_now_ns();
    let mut signals = curr.task_ext().signals.lock();
    refresh_timers(&mut signals, now_ns);
    has_interrupting_pending_signal(&signals, restartable)
}

pub fn map_signal_trampoline(uspace: &mut AddrSpace) -> axerrno::AxResult {
    let tramp = signal_trampoline_addr();
    if uspace.page_table().query(tramp).is_ok() {
        return Ok(());
    }

    uspace.map_alloc(
        tramp,
        PAGE_SIZE_4K,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER,
        true,
    )?;
    uspace.write(tramp, SIGNAL_TRAMPOLINE_BYTES)?;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence.i");
    }
    #[cfg(target_arch = "loongarch64")]
    unsafe {
        core::arch::asm!("ibar 0");
    }
    Ok(())
}

pub(crate) fn sys_rt_sigaction(
    signum: i32,
    act: *const c_void,
    oldact: *mut c_void,
    _sigsetsize: usize,
) -> isize {
    syscall_body!(sys_rt_sigaction, {
        let signum = usize::try_from(signum).map_err(|_| LinuxError::EINVAL)?;
        SignalState::signal_index(signum)?;
        if matches!(signum, SIGKILL | SIGSTOP) {
            return Err(LinuxError::EINVAL);
        }

        let curr = current();
        let mut debug_loops = 0usize;
        if !oldact.is_null() {
            let signals = curr.task_ext().signals.lock();
            let action = signals.action(signum);
            write_value_to_user(
                oldact as *mut UserSigAction,
                UserSigAction {
                    handler: action.handler,
                    mask: UserSigSet::from_mask(action.mask),
                    flags: action.flags,
                    restorer: action.restorer,
                },
            )?;
        }
        if !act.is_null() {
            let new_action = read_value_from_user(act as *const UserSigAction)?;
            if signum == SIGCHLD {
                let curr = current();
                if curr.name().contains("userboot") {
                    crate::diag_warn!(
                        "sigaction task={} SIGCHLD handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                        curr.id_name(),
                        new_action.handler,
                        new_action.flags,
                        new_action.restorer,
                        new_action.mask.as_mask()
                    );
                }
            }
            let action = SignalAction {
                handler: new_action.handler,
                mask: sanitize_mask(new_action.mask.as_mask()),
                flags: new_action.flags
                    & (SA_SIGINFO | SA_RESTORER | SA_RESTART | SA_NODEFER | SA_RESETHAND),
                restorer: new_action.restorer,
            };
            for task in thread_group_tasks(curr.task_ext().proc_id) {
                task.task_ext().signals.lock().set_action(signum, action);
            }
        }
        Ok(0)
    })
}

pub(crate) fn sys_rt_sigprocmask(
    how: i32,
    set: *const c_void,
    oldset: *mut c_void,
    _sigsetsize: usize,
) -> isize {
    syscall_body!(sys_rt_sigprocmask, {
        let curr = current();
        let mut signals = curr.task_ext().signals.lock();
        if !oldset.is_null() {
            write_value_to_user(
                oldset as *mut UserSigSet,
                UserSigSet::from_mask(signals.blocked_mask),
            )?;
        }
        if !set.is_null() {
            let set = read_value_from_user(set as *const UserSigSet)?.as_mask();
            signals.blocked_mask = match how {
                SIG_BLOCK => sanitize_mask(signals.blocked_mask | set),
                SIG_UNBLOCK => sanitize_mask(signals.blocked_mask & !set),
                SIG_SETMASK => sanitize_mask(set),
                _ => return Err(LinuxError::EINVAL),
            };
            signals.sigsuspend_restore_mask = None;
        }
        Ok(0)
    })
}

pub(crate) fn sys_rt_sigsuspend(set: *const c_void, _sigsetsize: usize) -> isize {
    syscall_body!(sys_rt_sigsuspend, {
        if set.is_null() {
            return Err::<isize, LinuxError>(LinuxError::EFAULT);
        }
        let new_mask = sanitize_mask(read_value_from_user(set as *const UserSigSet)?.as_mask());
        let curr = current();
        {
            let mut signals = curr.task_ext().signals.lock();
            let old_mask = signals.blocked_mask;
            signals.blocked_mask = new_mask;
            signals.sigsuspend_restore_mask = Some(old_mask);
        }
        let mut debug_loops = 0usize;

        loop {
            let interrupted = {
                let now_ns = current_now_ns();
                let mut signals = curr.task_ext().signals.lock();
                refresh_timers(&mut signals, now_ns);
                has_interrupting_pending_signal(&signals, false)
            };
            if interrupted {
                return Err::<isize, LinuxError>(LinuxError::EINTR);
            }
            if let Some(next_timer_deadline) =
                thread_group_next_posix_timer_deadline(curr.task_ext().proc_id)
            {
                let now_ns = current_now_ns() as u64;
                if next_timer_deadline.saturating_sub(now_ns) <= 5 * NANOS_PER_SEC {
                    core::hint::spin_loop();
                    continue;
                }
            }
            if trace_clock_settime03() {
                debug_loops = debug_loops.saturating_add(1);
                if debug_loops == 1 || debug_loops % 1000 == 0 {
                    warn!(
                        "[clock_settime03-sigsuspend] tid={} proc_id={} loops={} now_ns={} blocked_mask={:#x}",
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        debug_loops,
                        current_now_ns(),
                        curr.task_ext().signals.lock().blocked_mask
                    );
                }
            }
            axtask::sleep(core::time::Duration::from_millis(1));
        }
    })
}

pub(crate) fn sys_rt_sigtimedwait(
    set: *const c_void,
    info: *mut c_void,
    timeout: *const c_void,
    sigsetsize: usize,
) -> isize {
    syscall_body!(sys_rt_sigtimedwait, {
        if set.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if sigsetsize < size_of::<UserSigSet>() {
            return Err(LinuxError::EINVAL);
        }

        let wait_mask = read_value_from_user(set as *const UserSigSet)?.as_mask();
        let deadline_ns = if timeout.is_null() {
            None
        } else {
            let timeout = read_value_from_user(timeout as *const UserTimespec)?;
            Some(current_now_ns().saturating_add(timespec_to_ns(timeout)?))
        };
        let curr = current();
        let mut debug_loops = 0usize;

        loop {
            let now_ns = current_now_ns();
            let ready_signum =
                take_thread_group_pending_signal(curr.as_task_ref(), wait_mask, now_ns);

            if let Some((signum, siginfo)) = ready_signum {
                if !info.is_null() {
                    write_value_to_user(info as *mut UserSigInfo, siginfo)?;
                }
                return Ok(signum as isize);
            }

            let interrupted = {
                let mut signals = curr.task_ext().signals.lock();
                refresh_timers(&mut signals, now_ns);
                has_interrupting_pending_signal_with_ignored_mask(&signals, false, wait_mask)
            };
            if interrupted {
                return Err(LinuxError::EINTR);
            }

            if let Some(deadline_ns) = deadline_ns {
                if now_ns >= deadline_ns {
                    return Err(LinuxError::EAGAIN);
                }
            }
            if let Some(next_timer_deadline) =
                thread_group_next_posix_timer_deadline(curr.task_ext().proc_id)
            {
                if next_timer_deadline.saturating_sub(now_ns as u64) <= 5 * NANOS_PER_SEC {
                    core::hint::spin_loop();
                    continue;
                }
            }
            if trace_clock_settime03() {
                debug_loops = debug_loops.saturating_add(1);
                if debug_loops == 1 || debug_loops % 1000 == 0 {
                    warn!(
                        "[clock_settime03-sigtimedwait] tid={} proc_id={} loops={} now_ns={} wait_mask={:#x}",
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        debug_loops,
                        now_ns,
                        wait_mask
                    );
                }
            }
            axtask::sleep(core::time::Duration::from_millis(1));
        }
    })
}

pub(crate) fn sys_rt_sigreturn() -> isize {
    syscall_body!(sys_rt_sigreturn, {
        let curr = current();
        let kstack_top = curr.get_kernel_stack_top().unwrap();
        let current_tf = read_trapframe_from_kstack(kstack_top);
        let mut frame = SignalFrame::default();
        let frame_bytes = unsafe {
            core::slice::from_raw_parts_mut(
                (&mut frame as *mut SignalFrame).cast::<u8>(),
                size_of::<SignalFrame>(),
            )
        };
        curr.task_ext()
            .aspace
            .lock()
            .read(VirtAddr::from_usize(current_tf.get_sp()), frame_bytes)
            .map_err(|_| LinuxError::EFAULT)?;
        if frame.magic != SIGNAL_FRAME_MAGIC {
            return Err(LinuxError::EINVAL);
        }

        curr.task_ext()
            .signals
            .lock()
            .finish_handler(frame.ucontext.uc_sigmask.as_mask());

        let mut restored = current_tf;
        restore_trapframe_from_ucontext(&mut restored, &frame.ucontext);
        let saved_ret = restored.arg0() as isize;
        restored.rewind_pc_for_syscall();
        write_trapframe_to_kstack(kstack_top, &restored);
        Ok(saved_ret)
    })
}

pub(crate) fn sys_getitimer(which: i32, curr_value: *mut c_void) -> isize {
    syscall_body!(sys_getitimer, {
        if curr_value.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let curr = current();
        let proc_id = curr.task_ext().proc_id;
        let now_ns = current_now_ns();
        let (interval_ns, value_ns) = {
            let mut signals = curr.task_ext().signals.lock();
            match which {
                ITIMER_REAL => {
                    refresh_timers(&mut signals, now_ns);
                    signals.real_timer_value(now_ns)
                }
                ITIMER_VIRTUAL => {
                    let now_cpu_ns = process_itimer_clock_ns(proc_id, which);
                    signals.virtual_timer_value(now_cpu_ns)
                }
                ITIMER_PROF => {
                    let now_cpu_ns = process_itimer_clock_ns(proc_id, which);
                    signals.prof_timer_value(now_cpu_ns)
                }
                _ => return Err(LinuxError::EINVAL),
            }
        };
        fill_itimerval(curr_value, interval_ns, value_ns)?;
        Ok(0)
    })
}

pub(crate) fn sys_setitimer(which: i32, new_value: *const c_void, old_value: *mut c_void) -> isize {
    syscall_body!(sys_setitimer, {
        if new_value.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let new_value = read_value_from_user(new_value as *const UserItimerval)?;
        let interval_ns = timeval_to_ns(new_value.it_interval)?;
        let value_ns = timeval_to_ns(new_value.it_value)?;
        let now_ns = current_now_ns();

        let curr = current();
        let proc_id = curr.task_ext().proc_id;
        let diag_slot = take_setitimer_diag_slot();
        let mut signals = curr.task_ext().signals.lock();
        let (old_interval_ns, old_timer_ns, armed_seq) = match which {
            ITIMER_REAL => {
                refresh_timers(&mut signals, now_ns);
                let old = signals.real_timer_value(now_ns);
                let armed_seq = signals.set_real_timer(interval_ns, value_ns, now_ns);
                (old.0, old.1, armed_seq)
            }
            ITIMER_VIRTUAL => {
                let now_cpu_ns = process_itimer_clock_ns(proc_id, which);
                let old = signals.virtual_timer_value(now_cpu_ns);
                let armed_seq = signals.set_virtual_timer(interval_ns, value_ns, now_cpu_ns);
                (old.0, old.1, armed_seq)
            }
            ITIMER_PROF => {
                let now_cpu_ns = process_itimer_clock_ns(proc_id, which);
                let old = signals.prof_timer_value(now_cpu_ns);
                let armed_seq = signals.set_prof_timer(interval_ns, value_ns, now_cpu_ns);
                (old.0, old.1, armed_seq)
            }
            _ => return Err(LinuxError::EINVAL),
        };
        drop(signals);

        if let Some(slot) = diag_slot {
            warn!(
                "[setitimer-diag:{}] syscall=setitimer tid={} pid={} which={} interval_ns={} value_ns={} old_interval_ns={} old_value_ns={} seq={}",
                slot,
                curr.id().as_u64(),
                proc_id,
                which,
                interval_ns,
                value_ns,
                old_interval_ns,
                old_timer_ns,
                armed_seq,
            );
        }

        if value_ns != 0 {
            match which {
                ITIMER_REAL => spawn_real_timer_worker(curr.as_task_ref(), armed_seq),
                ITIMER_VIRTUAL | ITIMER_PROF => {
                    spawn_cpu_itimer_worker(curr.as_task_ref(), which, armed_seq)
                }
                _ => {}
            }
        }

        fill_itimerval(old_value, old_interval_ns, old_timer_ns)?;
        Ok(0)
    })
}

fn validate_timer_clock(clock_id: i32) -> Result<(), LinuxError> {
    match clock_id {
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_BOOTTIME => Ok(()),
        CLOCK_BOOTTIME_ALARM | CLOCK_REALTIME_ALARM | CLOCK_TAI => Err(LinuxError::EOPNOTSUPP),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn sys_timer_create(clock_id: i32, sevp: *const c_void, timerid: *mut i32) -> isize {
    syscall_body!(sys_timer_create, {
        if timerid.is_null() {
            return Err(LinuxError::EFAULT);
        }
        validate_timer_clock(clock_id)?;

        let (notify, notify_signum, notify_tid) = if sevp.is_null() {
            (SIGEV_SIGNAL, SIGALRM, 0u64)
        } else {
            let ev = read_value_from_user(sevp as *const UserSigevent)?;
            let notify = ev.sigev_notify;
            let signum = if ev.sigev_signo == 0 {
                SIGALRM
            } else {
                usize::try_from(ev.sigev_signo).map_err(|_| LinuxError::EINVAL)?
            };
            SignalState::signal_index(signum)?;
            match notify {
                SIGEV_SIGNAL | SIGEV_NONE | SIGEV_THREAD | SIGEV_THREAD_ID => {}
                _ => return Err(LinuxError::EINVAL),
            }
            (notify, signum, ev.sigev_notify_thread_id.max(0) as u64)
        };

        let curr = current();
        let mut signals = curr.task_ext().signals.lock();
        let timer = signals.create_posix_timer(clock_id, notify, notify_signum, notify_tid);
        if trace_clock_settime03() {
            warn!(
                "[clock_settime03-timer_create] tid={} proc_id={} timerid={} clock_id={} notify={} signum={} notify_tid={}",
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                timer,
                clock_id,
                notify,
                notify_signum,
                notify_tid
            );
        }
        write_value_to_user(timerid, timer)?;
        Ok(0)
    })
}

pub(crate) fn sys_timer_settime(
    timerid: i32,
    flags: i32,
    new_value: *const c_void,
    old_value: *mut c_void,
) -> isize {
    syscall_body!(sys_timer_settime, {
        if new_value.is_null() {
            return Err(LinuxError::EINVAL);
        }
        if flags & !TIMER_ABSTIME != 0 {
            return Err(LinuxError::EINVAL);
        }

        let spec = read_value_from_user(new_value as *const UserItimerspec)?;
        let interval_ns = timespec_to_ns(spec.it_interval)? as u64;
        let value_ns = timespec_to_ns(spec.it_value)? as u64;
        let now_ns = current_now_ns();

        let curr = current();
        let mut signals = curr.task_ext().signals.lock();
        refresh_timers(&mut signals, now_ns);
        let (old_interval_ns, old_deadline_ns) = signals.posix_timer_value(timerid, now_ns)?;
        let timer = *signals
            .posix_timers
            .get(&timerid)
            .ok_or(LinuxError::EINVAL)?;
        let current_clock_ns = current_clock_nanos(timer.clock_id)?;
        let new_deadline_ns = if value_ns == 0 {
            0
        } else {
            monotonic_deadline_from_clock(timer.clock_id, value_ns, (flags & TIMER_ABSTIME) != 0)?
        };
        if trace_clock_settime03() {
            warn!(
                "[clock_settime03-timer_settime] tid={} proc_id={} timerid={} clock_id={} flags={:#x} value_ns={} now_mono={} now_clock={} deadline_ns={}",
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                timerid,
                timer.clock_id,
                flags,
                value_ns,
                now_ns,
                current_clock_ns,
                new_deadline_ns
            );
        }
        let (_, _, armed_seq) = signals.set_posix_timer(timerid, interval_ns, new_deadline_ns)?;
        write_itimerspec(old_value, old_interval_ns, old_deadline_ns)?;
        drop(signals);
        if new_deadline_ns != 0 {
            spawn_posix_timer_worker(curr.as_task_ref(), timerid, armed_seq);
        }
        Ok(0)
    })
}

pub(crate) fn sys_timer_gettime(timerid: i32, curr_value: *mut c_void) -> isize {
    syscall_body!(sys_timer_gettime, {
        if curr_value.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let now_ns = current_now_ns();
        let curr = current();
        let mut signals = curr.task_ext().signals.lock();
        refresh_timers(&mut signals, now_ns);
        let (interval_ns, value_ns) = signals.posix_timer_value(timerid, now_ns)?;
        write_itimerspec(curr_value, interval_ns, value_ns)?;
        Ok(0)
    })
}

pub(crate) fn sys_timer_delete(timerid: i32) -> isize {
    syscall_body!(sys_timer_delete, {
        let curr = current();
        let mut signals = curr.task_ext().signals.lock();
        signals.delete_posix_timer(timerid)?;
        Ok(0)
    })
}

pub(crate) fn sys_timer_getoverrun(timerid: i32) -> isize {
    syscall_body!(sys_timer_getoverrun, {
        let curr = current();
        let signals = curr.task_ext().signals.lock();
        Ok(signals.posix_timer_overrun(timerid)? as isize)
    })
}
