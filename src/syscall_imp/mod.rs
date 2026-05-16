mod fs;
mod mm;
mod task;
mod utils;

use alloc::collections::BTreeSet;
use axerrno::LinuxError;
use axhal::{
    arch::TrapFrame,
    trap::{register_trap_handler, SYSCALL},
};
use axsync::Mutex;
use axtask::TaskExtRef;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Once;
use syscalls::Sysno;

fn should_trace_clone08() -> bool {
    false
}

pub(crate) use self::fs::*;
use self::mm::*;
pub(crate) use self::task::*;
pub(crate) use self::utils::*;

const MPROTECT02_SYSCALL_TRACE_LIMIT: usize = 256;
static MPROTECT02_SYSCALL_TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
const UNIQUE_SYSCALL_WARN_CAP: usize = 256;

fn logged_unimplemented_syscalls() -> &'static Mutex<BTreeSet<usize>> {
    static LOGGED: Once<Mutex<BTreeSet<usize>>> = Once::new();
    LOGGED.call_once(|| Mutex::new(BTreeSet::new()))
}

fn logged_invalid_syscalls() -> &'static Mutex<BTreeSet<usize>> {
    static LOGGED: Once<Mutex<BTreeSet<usize>>> = Once::new();
    LOGGED.call_once(|| Mutex::new(BTreeSet::new()))
}

fn should_log_unique_syscall_number(
    logged: &'static Mutex<BTreeSet<usize>>,
    syscall_num: usize,
) -> bool {
    let mut logged = logged.lock();
    if logged.contains(&syscall_num) {
        return false;
    }
    if logged.len() < UNIQUE_SYSCALL_WARN_CAP {
        logged.insert(syscall_num);
        return true;
    }
    false
}

fn should_log_unimplemented_syscall(syscall_num: usize) -> bool {
    should_log_unique_syscall_number(logged_unimplemented_syscalls(), syscall_num)
}

fn should_log_invalid_syscall(syscall_num: usize) -> bool {
    should_log_unique_syscall_number(logged_invalid_syscalls(), syscall_num)
}

fn should_trace_mprotect02_syscalls() -> bool {
    let curr = axtask::current();
    let exec_path = curr.task_ext().exec_path();
    exec_path.ends_with("/mprotect02") || exec_path == "mprotect02"
}

fn take_mprotect02_syscall_trace_slot() -> Option<usize> {
    if !should_trace_mprotect02_syscalls() {
        return None;
    }
    let slot = MPROTECT02_SYSCALL_TRACE_COUNT.fetch_add(1, Ordering::Relaxed);
    (slot < MPROTECT02_SYSCALL_TRACE_LIMIT).then_some(slot + 1)
}

fn should_log_mprotect02_syscall(syscall_num: usize) -> bool {
    matches!(
        Sysno::new(syscall_num),
        Some(
            Sysno::clone
                | Sysno::clone3
                | Sysno::wait4
                | Sysno::waitid
                | Sysno::exit
                | Sysno::exit_group
                | Sysno::rt_sigreturn
                | Sysno::mprotect
        )
    )
}

fn log_mprotect02_syscall_enter(curr: &axtask::CurrentTask, tf: &TrapFrame, syscall_num: usize) {
    if !should_log_mprotect02_syscall(syscall_num) {
        return;
    }
    let Some(slot) = take_mprotect02_syscall_trace_slot() else {
        return;
    };
    let sysno_name = Sysno::new(syscall_num)
        .map(|sysno| alloc::format!("{sysno:?}"))
        .unwrap_or_else(|| alloc::format!("raw-{syscall_num}"));
    warn!(
        "[mprotect02-syscall:{}] phase=enter task={} pid={} tid={} num={} name={} ip={:#x} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
        slot,
        curr.id_name(),
        curr.task_ext().proc_id,
        curr.id().as_u64(),
        syscall_num,
        sysno_name,
        tf.get_ip(),
        tf.arg0(),
        tf.arg1(),
        tf.arg2(),
        tf.arg3(),
        tf.arg4(),
        tf.arg5(),
    );
}

fn log_mprotect02_syscall_exit(curr: &axtask::CurrentTask, syscall_num: usize, ret: isize) {
    if !should_log_mprotect02_syscall(syscall_num) {
        return;
    }
    let Some(slot) = take_mprotect02_syscall_trace_slot() else {
        return;
    };
    let sysno_name = Sysno::new(syscall_num)
        .map(|sysno| alloc::format!("{sysno:?}"))
        .unwrap_or_else(|| alloc::format!("raw-{syscall_num}"));
    warn!(
        "[mprotect02-syscall:{}] phase=exit task={} pid={} tid={} num={} name={} ret={}",
        slot,
        curr.id_name(),
        curr.task_ext().proc_id,
        curr.id().as_u64(),
        syscall_num,
        sysno_name,
        ret,
    );
}

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_MAIN_BASE: usize = 0x1000;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_BSS_START: usize = CLONE08_RV_MAIN_BASE + 0x29cf0;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_CASE_START: usize = CLONE08_RV_MAIN_BASE + 0x28008;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_GOT_START: usize = CLONE08_RV_MAIN_BASE + 0x285a0;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_PERSONALITY_GOT: usize = CLONE08_RV_MAIN_BASE + 0x28698;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_CLONE_GOT: usize = CLONE08_RV_MAIN_BASE + 0x28b68;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_FORK_GOT: usize = CLONE08_RV_MAIN_BASE + 0x28950;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_VFORK_GOT: usize = CLONE08_RV_MAIN_BASE + 0x28a90;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_SYSCALL_GOT: usize = CLONE08_RV_MAIN_BASE + 0x28658;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_CLONE_PLT: usize = CLONE08_RV_MAIN_BASE + 0x6580;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_FORK_PLT: usize = CLONE08_RV_MAIN_BASE + 0x6150;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_VFORK_PLT: usize = CLONE08_RV_MAIN_BASE + 0x6260;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_LTP_CLONE7: usize = CLONE08_RV_MAIN_BASE + 0x6e2a;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_TGID_ADDR: usize = CLONE08_RV_MAIN_BASE + 0x28d00;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_PTID_ADDR: usize = CLONE08_RV_MAIN_BASE + 0x28d04;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_CTID_ADDR: usize = CLONE08_RV_MAIN_BASE + 0x28d08;

#[cfg(target_arch = "riscv64")]
const CLONE08_RV_CHILD_STACK_ADDR: usize = CLONE08_RV_MAIN_BASE + 0x28d10;

#[cfg(target_arch = "riscv64")]
fn probe_clone08_rv_word(current: &axtask::CurrentTask, addr: usize) -> Option<u32> {
    let mut value = 0u32;
    current
        .task_ext()
        .aspace
        .lock()
        .read(memory_addr::VirtAddr::from_usize(addr), unsafe {
            core::slice::from_raw_parts_mut(
                (&mut value as *mut u32).cast::<u8>(),
                core::mem::size_of::<u32>(),
            )
        })
        .ok()?;
    Some(value)
}

#[cfg(target_arch = "riscv64")]
fn probe_clone08_rv_u64(current: &axtask::CurrentTask, addr: usize) -> Option<u64> {
    let mut value = 0u64;
    current
        .task_ext()
        .aspace
        .lock()
        .read(memory_addr::VirtAddr::from_usize(addr), unsafe {
            core::slice::from_raw_parts_mut(
                (&mut value as *mut u64).cast::<u8>(),
                core::mem::size_of::<u64>(),
            )
        })
        .ok()?;
    Some(value)
}

#[cfg(target_arch = "riscv64")]
fn probe_clone08_rv_bytes(
    current: &axtask::CurrentTask,
    addr: usize,
    len: usize,
) -> Option<alloc::vec::Vec<u8>> {
    let mut bytes = alloc::vec![0u8; len];
    current
        .task_ext()
        .aspace
        .lock()
        .read(
            memory_addr::VirtAddr::from_usize(addr),
            bytes.as_mut_slice(),
        )
        .ok()?;
    Some(bytes)
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_ip_bytes(current: &axtask::CurrentTask, tf: &TrapFrame, tag: &str) {
    let ip = tf.get_ip();
    let start = ip.saturating_sub(16);
    let Some(bytes) = probe_clone08_rv_bytes(current, start, 32) else {
        warn!(
            "clone08 {} ip-bytes ip={:#x} start={:#x} <unreadable>",
            tag, ip, start
        );
        return;
    };
    warn!(
        "clone08 {} ip-bytes ip={:#x} start={:#x} bytes={:02x?}",
        tag, ip, start, bytes
    );
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_globals(current: &axtask::CurrentTask, tag: &str) {
    const TEST_PAGE_START: usize = CLONE08_RV_MAIN_BASE + 0x29d28;
    const TEST_CASE_SIZE: usize = 32;
    const TEST_CASE_DO_CHILD_OFFSET: usize = 24;
    const DUMP_WORDS: usize = 16;
    let mut bss = [0u32; DUMP_WORDS];
    let mut cases = [0u32; 8];
    let mut got = [0u32; 4];
    let mut test_page = [0u32; 16];
    for (index, slot) in bss.iter_mut().enumerate() {
        *slot = probe_clone08_rv_word(
            current,
            CLONE08_RV_BSS_START + index * core::mem::size_of::<u32>(),
        )
        .unwrap_or(u32::MAX);
    }
    for (index, slot) in cases.iter_mut().enumerate() {
        *slot = probe_clone08_rv_word(
            current,
            CLONE08_RV_CASE_START + index * core::mem::size_of::<u32>(),
        )
        .unwrap_or(u32::MAX);
    }
    for (index, slot) in got.iter_mut().enumerate() {
        *slot = probe_clone08_rv_word(
            current,
            CLONE08_RV_GOT_START + index * core::mem::size_of::<u32>(),
        )
        .unwrap_or(u32::MAX);
    }
    for (index, slot) in test_page.iter_mut().enumerate() {
        *slot = probe_clone08_rv_word(
            current,
            TEST_PAGE_START + index * core::mem::size_of::<u32>(),
        )
        .unwrap_or(u32::MAX);
    }
    let personality_got =
        probe_clone08_rv_u64(current, CLONE08_RV_PERSONALITY_GOT).unwrap_or(u64::MAX);
    let clone_got = probe_clone08_rv_u64(current, CLONE08_RV_CLONE_GOT).unwrap_or(u64::MAX);
    let fork_got = probe_clone08_rv_u64(current, CLONE08_RV_FORK_GOT).unwrap_or(u64::MAX);
    let vfork_got = probe_clone08_rv_u64(current, CLONE08_RV_VFORK_GOT).unwrap_or(u64::MAX);
    let syscall_got = probe_clone08_rv_u64(current, CLONE08_RV_SYSCALL_GOT).unwrap_or(u64::MAX);
    let tgid = probe_clone08_rv_word(current, CLONE08_RV_TGID_ADDR).unwrap_or(u32::MAX);
    let ptid = probe_clone08_rv_word(current, CLONE08_RV_PTID_ADDR).unwrap_or(u32::MAX);
    let ctid = probe_clone08_rv_word(current, CLONE08_RV_CTID_ADDR).unwrap_or(u32::MAX);
    let child_stack =
        probe_clone08_rv_u64(current, CLONE08_RV_CHILD_STACK_ADDR).unwrap_or(u64::MAX);
    let clone_thread_do_child = probe_clone08_rv_u64(
        current,
        CLONE08_RV_CASE_START + TEST_CASE_SIZE * 3 + TEST_CASE_DO_CHILD_OFFSET,
    )
    .unwrap_or(u64::MAX);
    let clone_plt = probe_clone08_rv_bytes(current, CLONE08_RV_CLONE_PLT, 16)
        .unwrap_or_else(|| alloc::vec![0xff; 16]);
    let fork_plt = probe_clone08_rv_bytes(current, CLONE08_RV_FORK_PLT, 16)
        .unwrap_or_else(|| alloc::vec![0xff; 16]);
    let vfork_plt = probe_clone08_rv_bytes(current, CLONE08_RV_VFORK_PLT, 16)
        .unwrap_or_else(|| alloc::vec![0xff; 16]);
    let ltp_clone7 = probe_clone08_rv_bytes(current, CLONE08_RV_LTP_CLONE7, 48)
        .unwrap_or_else(|| alloc::vec![0xff; 48]);
    warn!(
        "clone08 {} task={} pie_base={:#x} bss@{:#x}={:x?} test@{:#x}={:x?} cases@{:#x}={:x?} got@{:#x}={:x?} tgid@{:#x}={:#x} ptid@{:#x}={:#x} ctid@{:#x}={:#x} child_stack@{:#x}={:#x} clone_thread_do_child@{:#x}={:#x} personality_got@{:#x}={:#x} syscall_got@{:#x}={:#x} fork_got@{:#x}={:#x} vfork_got@{:#x}={:#x} clone_got@{:#x}={:#x} clone_plt@{:#x}={:02x?} fork_plt@{:#x}={:02x?} vfork_plt@{:#x}={:02x?} ltp_clone7@{:#x}={:02x?}",
        tag,
        current.id_name(),
        CLONE08_RV_MAIN_BASE,
        CLONE08_RV_BSS_START,
        bss,
        TEST_PAGE_START,
        test_page,
        CLONE08_RV_CASE_START,
        cases,
        CLONE08_RV_GOT_START,
        got,
        CLONE08_RV_TGID_ADDR,
        tgid,
        CLONE08_RV_PTID_ADDR,
        ptid,
        CLONE08_RV_CTID_ADDR,
        ctid,
        CLONE08_RV_CHILD_STACK_ADDR,
        child_stack,
        CLONE08_RV_CASE_START + TEST_CASE_SIZE * 3 + TEST_CASE_DO_CHILD_OFFSET,
        clone_thread_do_child,
        CLONE08_RV_PERSONALITY_GOT,
        personality_got,
        CLONE08_RV_SYSCALL_GOT,
        syscall_got,
        CLONE08_RV_FORK_GOT,
        fork_got,
        CLONE08_RV_VFORK_GOT,
        vfork_got,
        CLONE08_RV_CLONE_GOT,
        clone_got,
        CLONE08_RV_CLONE_PLT,
        clone_plt,
        CLONE08_RV_FORK_PLT,
        fork_plt,
        CLONE08_RV_VFORK_PLT,
        vfork_plt,
        CLONE08_RV_LTP_CLONE7,
        ltp_clone7,
    );
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_regs(tf: &TrapFrame, tag: &str) {
    warn!(
        "clone08 {} regs: sp={:#x} ra={:#x} gp={:#x} tp={:#x} s0={:#x} s1={:#x} s2={:#x} s3={:#x} s4={:#x} s5={:#x}",
        tag,
        tf.regs.sp,
        tf.regs.ra,
        tf.regs.gp,
        tf.regs.tp,
        tf.regs.s0,
        tf.regs.s1,
        tf.regs.s2,
        tf.regs.s3,
        tf.regs.s4,
        tf.regs.s5,
    );
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_stack_frames(current: &axtask::CurrentTask, tf: &TrapFrame, tag: &str) {
    let base = tf.regs.sp.saturating_sub(0x20);
    let addrs = [
        base,
        base + 0x08,
        base + 0x10,
        base + 0x18,
        base + 0x20,
        base + 0x28,
    ];
    let mut values = [0u64; 6];
    for (slot, addr) in values.iter_mut().zip(addrs) {
        *slot = probe_clone08_rv_u64(current, addr).unwrap_or(u64::MAX);
    }
    warn!(
        "clone08 {} stack around sp={:#x}: [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x}",
        tag,
        tf.regs.sp,
        addrs[0],
        values[0],
        addrs[1],
        values[1],
        addrs[2],
        values[2],
        addrs[3],
        values[3],
        addrs[4],
        values[4],
        addrs[5],
        values[5],
    );
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_safe_fork_frame(current: &axtask::CurrentTask, tag: &str) {
    let addrs = [
        0x3fffff9e0usize,
        0x3fffff9e8usize,
        0x3fffff9f0usize,
        0x3fffff9f8usize,
        0x3fffffa00usize,
    ];
    let mut values = [0u64; 5];
    for (slot, addr) in values.iter_mut().zip(addrs) {
        *slot = probe_clone08_rv_u64(current, addr).unwrap_or(u64::MAX);
    }
    warn!(
        "clone08 {} safe_fork frame: [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x}",
        tag,
        addrs[0],
        values[0],
        addrs[1],
        values[1],
        addrs[2],
        values[2],
        addrs[3],
        values[3],
        addrs[4],
        values[4],
    );
}

#[cfg(target_arch = "riscv64")]
fn log_clone08_rv_tp_header(current: &axtask::CurrentTask, tf: &TrapFrame, tag: &str) {
    let tp = tf.regs.tp;
    let addrs = [
        tp.wrapping_sub(200),
        tp.wrapping_sub(192),
        tp.wrapping_sub(184),
        tp.wrapping_sub(176),
        tp.wrapping_sub(168),
        tp.wrapping_sub(160),
        tp.wrapping_sub(80),
        tp.wrapping_sub(16),
        tp.wrapping_sub(8),
    ];
    let mut values = [0u64; 9];
    for (slot, addr) in values.iter_mut().zip(addrs) {
        *slot = probe_clone08_rv_u64(current, addr).unwrap_or(u64::MAX);
    }
    let dtv = probe_clone08_rv_u64(current, addrs[8] as usize)
        .and_then(|ptr| usize::try_from(ptr).ok())
        .unwrap_or(0);
    let dtv_words = [
        (dtv != 0)
            .then(|| probe_clone08_rv_u64(current, dtv).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX),
        (dtv != 0)
            .then(|| probe_clone08_rv_u64(current, dtv + 8).unwrap_or(u64::MAX))
            .unwrap_or(u64::MAX),
    ];
    warn!(
        "clone08 {} tp-header tp={:#x}: self={:#x} prev={:#x} next={:#x} sysinfo={:#x} tid={:#x} detach={:#x} robust_head={:#x} canary={:#x} dtv={:#x} dtv[0]={:#x} dtv[1]={:#x}",
        tag,
        tp,
        values[0],
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        values[8],
        dtv_words[0],
        dtv_words[1],
    );
}

/// Macro to generate syscall body
///
/// It will receive a function which return Result<_, LinuxError> and convert it to
/// the type which is specified by the caller.
#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    let curr = axtask::current();
    let trace_clone08 = should_trace_clone08() && curr.name().contains("clone08");
    log_mprotect02_syscall_enter(&curr, tf, syscall_num);
    if curr.id().as_u64() <= 8 {
        trace!(
            "trace_syscall tid={} num={} a0={:#x} a1={:#x} a2={:#x}",
            curr.id().as_u64(),
            syscall_num,
            tf.arg0(),
            tf.arg1(),
            tf.arg2()
        );
    }
    if trace_clone08 {
        warn!(
            "clone08 syscall enter tid={} pid={} num={} ip={:#x} a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x}",
            curr.id().as_u64(),
            curr.task_ext().proc_id,
            syscall_num,
            tf.get_ip(),
            tf.arg0(),
            tf.arg1(),
            tf.arg2(),
            tf.arg3(),
            tf.arg4()
        );
        #[cfg(target_arch = "riscv64")]
        if syscall_num == 64
            || syscall_num == 96
            || syscall_num == 135
            || syscall_num == 172
            || syscall_num == 220
        {
            log_clone08_rv_globals(&curr, "sys-enter");
            log_clone08_rv_regs(tf, "sys-enter");
            log_clone08_rv_stack_frames(&curr, tf, "sys-enter");
            log_clone08_rv_safe_fork_frame(&curr, "sys-enter");
            log_clone08_rv_tp_header(&curr, tf, "sys-enter");
            if syscall_num == 220 {
                log_clone08_rv_ip_bytes(&curr, tf, "sys-enter");
            }
        }
    }
    let ans = if syscall_num == 39 {
        sys_umount(tf.arg0() as _, tf.arg1() as _) as _
    } else if syscall_num == 40 {
        sys_mount(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
        ) as _
    } else if syscall_num == 131 {
        sys_tgkill(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
    } else if syscall_num == 261 {
        sys_prlimit64(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
        ) as _
    } else {
        match Sysno::new(syscall_num) {
            Some(sysno) => match sysno {
                Sysno::read => sys_read(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::pread64 => sys_pread64(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::preadv => sys_preadv(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::preadv2 => sys_preadv2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg5() as _,
                ),
                Sysno::pwrite64 => sys_pwrite64(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::readv => sys_readv(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::write => sys_write(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::socket => sys_socket(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::socketpair => sys_socketpair(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::io_setup => sys_io_setup(tf.arg0() as _, tf.arg1() as _),
                Sysno::io_destroy => sys_io_destroy(tf.arg0() as _),
                Sysno::io_submit => sys_io_submit(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::io_cancel => sys_io_cancel(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::io_getevents => sys_io_getevents(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::bind => sys_bind(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::connect => sys_connect(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::listen => sys_listen(tf.arg0() as _, tf.arg1() as _),
                Sysno::accept => sys_accept(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::accept4 => sys_accept4(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::epoll_create1 => sys_epoll_create1(tf.arg0() as _),
                Sysno::eventfd2 => sys_eventfd2(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::epoll_ctl => sys_epoll_ctl(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::epoll_pwait => sys_epoll_pwait(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::io_pgetevents => sys_io_pgetevents(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::epoll_pwait2 => sys_epoll_pwait2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::sendto => sys_sendto(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::recvfrom => sys_recvfrom(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::shutdown => sys_shutdown(tf.arg0() as _, tf.arg1() as _),
                Sysno::getsockname => {
                    sys_getsockname(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::getpeername => {
                    sys_getpeername(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::setsockopt => sys_setsockopt(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::getsockopt => sys_getsockopt(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::sendfile => sys_sendfile(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::splice => sys_splice(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::copy_file_range => sys_copy_file_range(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::readlinkat => sys_readlinkat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::faccessat => sys_faccessat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                Sysno::faccessat2 => sys_faccessat2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::fchownat => sys_fchownat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::fchown => sys_fchown(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::mmap => sys_mmap(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ) as _,
                Sysno::shmget => sys_shmget(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::shmat => sys_shmat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::shmdt => sys_shmdt(tf.arg0() as _),
                Sysno::shmctl => sys_shmctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::msgget => sys_msgget(tf.arg0() as _, tf.arg1() as _),
                Sysno::msgctl => sys_msgctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::msgrcv => sys_msgrcv(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::msgsnd => sys_msgsnd(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::ioctl => sys_ioctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::fcntl => sys_fcntl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::flock => sys_flock(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::lseek => sys_lseek(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::writev => sys_writev(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::pwritev => sys_pwritev(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::pwritev2 => sys_pwritev2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg5() as _,
                ),
                Sysno::rt_sigaction => sys_rt_sigaction(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::rt_sigreturn => sys_rt_sigreturn(),
                Sysno::rt_sigprocmask => sys_rt_sigprocmask(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::rt_sigsuspend => sys_rt_sigsuspend(tf.arg0() as _, tf.arg1() as _),
                Sysno::rt_sigtimedwait => sys_rt_sigtimedwait(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::getitimer => sys_getitimer(tf.arg0() as _, tf.arg1() as _),
                Sysno::setitimer => sys_setitimer(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::ppoll => sys_ppoll(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::pselect6 => sys_pselect6(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::sched_yield => sys_sched_yield() as isize,
                Sysno::sched_setparam => sys_sched_setparam(tf.arg0() as _, tf.arg1() as _),
                Sysno::sched_setattr => {
                    sys_sched_setattr(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::sched_setscheduler => {
                    sys_sched_setscheduler(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::sched_getattr => sys_sched_getattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::sched_getscheduler => sys_sched_getscheduler(tf.arg0() as _),
                Sysno::sched_get_priority_max => sys_sched_get_priority_max(tf.arg0() as _),
                Sysno::sched_get_priority_min => sys_sched_get_priority_min(tf.arg0() as _),
                Sysno::sched_getparam => sys_sched_getparam(tf.arg0() as _, tf.arg1() as _),
                Sysno::sched_rr_get_interval => {
                    sys_sched_rr_get_interval(tf.arg0() as _, tf.arg1() as _)
                }
                Sysno::sched_setaffinity => {
                    sys_sched_setaffinity(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::sched_getaffinity => {
                    sys_sched_getaffinity(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::mbind => sys_mbind(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::get_mempolicy => sys_get_mempolicy(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::set_mempolicy => {
                    sys_set_mempolicy(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::nanosleep => sys_nanosleep(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::clock_nanosleep => sys_clock_nanosleep(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::clock_settime | Sysno::clock_settime64 => {
                    sys_clock_settime(tf.arg0() as _, tf.arg1() as _) as _
                }
                Sysno::timerfd_create => sys_timerfd_create(tf.arg0() as _, tf.arg1() as _),
                Sysno::timerfd_settime | Sysno::timerfd_settime64 => sys_timerfd_settime(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::timerfd_gettime | Sysno::timerfd_gettime64 => {
                    sys_timerfd_gettime(tf.arg0() as _, tf.arg1() as _)
                }
                Sysno::timer_create => {
                    sys_timer_create(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::timer_settime | Sysno::timer_settime64 => sys_timer_settime(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::timer_gettime | Sysno::timer_gettime64 => {
                    sys_timer_gettime(tf.arg0() as _, tf.arg1() as _)
                }
                Sysno::timer_getoverrun => sys_timer_getoverrun(tf.arg0() as _),
                Sysno::timer_delete => sys_timer_delete(tf.arg0() as _),
                Sysno::adjtimex => sys_adjtimex(tf.arg0() as _) as _,
                Sysno::clock_adjtime | Sysno::clock_adjtime64 => {
                    sys_clock_adjtime(tf.arg0() as _, tf.arg1() as _) as _
                }
                Sysno::getpid => sys_getpid() as isize,
                Sysno::getppid => sys_getppid() as isize,
                Sysno::getuid => sys_getuid() as isize,
                Sysno::geteuid => sys_geteuid() as isize,
                Sysno::getgid => sys_getgid() as isize,
                Sysno::getegid => sys_getegid() as isize,
                Sysno::setfsuid => sys_setfsuid(tf.arg0() as _) as _,
                Sysno::setfsgid => sys_setfsgid(tf.arg0() as _) as _,
                Sysno::setuid => sys_setuid(tf.arg0() as _) as _,
                Sysno::setgid => sys_setgid(tf.arg0() as _) as _,
                Sysno::setreuid => sys_setreuid(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::setregid => sys_setregid(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::setresuid => {
                    sys_setresuid(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::getresuid => {
                    sys_getresuid(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::setresgid => {
                    sys_setresgid(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::getresgid => {
                    sys_getresgid(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::setgroups => sys_setgroups(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::getgroups => sys_getgroups(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::capget => sys_capget(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::capset => sys_capset(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::add_key => sys_add_key(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::request_key => sys_request_key(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::keyctl => sys_keyctl(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::gettid => sys_gettid() as isize,
                Sysno::prctl => sys_prctl(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::personality => sys_personality(tf.arg0() as _),
                Sysno::acct => sys_acct(tf.arg0() as _) as _,
                Sysno::getpgid => sys_getpgid(tf.arg0() as _),
                Sysno::getsid => sys_getsid(tf.arg0() as _),
                Sysno::setpgid => sys_setpgid(tf.arg0() as _, tf.arg1() as _),
                Sysno::setsid => sys_setsid(),
                Sysno::getpriority => sys_getpriority(tf.arg0() as _, tf.arg1() as _),
                Sysno::setpriority => {
                    sys_setpriority(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::kill => sys_kill(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::tkill => sys_tkill(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::exit => sys_exit(tf.arg0() as _),
                Sysno::gettimeofday => sys_get_time_of_day(tf.arg0() as _) as _,
                Sysno::getcwd => sys_getcwd(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::dup => sys_dup(tf.arg0() as _) as _,
                Sysno::dup3 => sys_dup3(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::clone => sys_clone(
                    tf,
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::unshare => sys_unshare(tf.arg0() as _) as _,
                Sysno::setns => sys_setns(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::wait4 => sys_wait4(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::waitid => sys_waitid(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::pipe2 => sys_pipe2(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::close => sys_close(tf.arg0() as _) as _,
                Sysno::chdir => sys_chdir(tf.arg0() as _) as _,
                Sysno::chroot => sys_chroot(tf.arg0() as _) as _,
                Sysno::mkdirat => sys_mkdirat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::mknodat => sys_mknodat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::fchmodat => {
                    sys_fchmodat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _, 0) as _
                }
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                Sysno::fchmodat2 => sys_fchmodat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::fchmod => sys_fchmod(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::utimensat => sys_utimensat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
                Sysno::utimensat_time64 => sys_utimensat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::execve => sys_execve(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::execveat => sys_execveat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::openat => sys_openat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::getdents64 => sys_getdents64(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::linkat => sys_linkat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::symlinkat => {
                    sys_symlinkat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::unlinkat => sys_unlinkat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::renameat => sys_renameat2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    0,
                ),
                Sysno::renameat2 => sys_renameat2(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::uname => sys_uname(tf.arg0() as _) as _,
                Sysno::statfs => sys_statfs(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::fstatfs => sys_fstatfs(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::truncate => sys_truncate(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::ftruncate => sys_ftruncate(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::fallocate => sys_fallocate(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::syslog => sys_syslog(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::setxattr => sys_setxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::lsetxattr => sys_lsetxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::fsetxattr => sys_fsetxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::getxattr => sys_getxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::lgetxattr => sys_lgetxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::fgetxattr => sys_fgetxattr(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::listxattr => sys_listxattr(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::llistxattr => sys_llistxattr(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::flistxattr => sys_flistxattr(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::removexattr => sys_removexattr(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::lremovexattr => sys_lremovexattr(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::fremovexattr => sys_fremovexattr(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::fstat => sys_fstat(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::sync => sys_sync() as _,
                Sysno::syncfs => sys_syncfs(tf.arg0() as _) as _,
                Sysno::fsync => sys_fsync(tf.arg0() as _) as _,
                Sysno::fdatasync => sys_fdatasync(tf.arg0() as _) as _,
                Sysno::readahead => sys_readahead(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::sysinfo => sys_sysinfo(tf.arg0() as _) as _,
                Sysno::delete_module => sys_delete_module(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::statx => sys_statx(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::fstatat => sys_newfstatat(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ) as _,
                Sysno::mprotect => {
                    sys_mprotect(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::mremap => sys_mremap(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ) as _,
                Sysno::msync => sys_msync(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::munmap => sys_munmap(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::times => sys_times(tf.arg0() as _) as _,
                Sysno::brk => sys_brk(tf.arg0() as _) as _,
                Sysno::umask => sys_umask(tf.arg0() as _) as _,
                #[cfg(target_arch = "x86_64")]
                Sysno::arch_prctl => sys_arch_prctl(tf.arg0() as _, tf.arg1() as _),
                Sysno::set_tid_address => sys_set_tid_address(tf.arg0() as _),
                Sysno::set_robust_list => sys_set_robust_list(tf.arg0() as _, tf.arg1() as _),
                Sysno::get_robust_list => {
                    sys_get_robust_list(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::clock_getres | Sysno::clock_getres_time64 => {
                    sys_clock_getres(tf.arg0() as _, tf.arg1() as _) as _
                }
                Sysno::clock_gettime | Sysno::clock_gettime64 => {
                    sys_clock_gettime(tf.arg0() as _, tf.arg1() as _) as _
                }
                Sysno::getrusage => sys_getrusage(tf.arg0() as _, tf.arg1() as _) as _,
                Sysno::getcpu => sys_getcpu(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
                Sysno::getrandom => sys_getrandom(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::membarrier => sys_membarrier(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::madvise => sys_madvise(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
                Sysno::fadvise64 => sys_fadvise64(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::mlock => sys_mlock(tf.arg0() as _, tf.arg1() as _),
                Sysno::munlock => sys_munlock(tf.arg0() as _, tf.arg1() as _),
                Sysno::mlockall => sys_mlockall(tf.arg0() as _),
                Sysno::munlockall => sys_munlockall(),
                Sysno::futex => sys_futex(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                    tf.arg5() as _,
                ),
                Sysno::pidfd_send_signal => sys_pidfd_send_signal(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                ),
                Sysno::pidfd_open => sys_pidfd_open(tf.arg0() as _, tf.arg1() as _),
                Sysno::pidfd_getfd => {
                    sys_pidfd_getfd(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _)
                }
                Sysno::kcmp => sys_kcmp(
                    tf.arg0() as _,
                    tf.arg1() as _,
                    tf.arg2() as _,
                    tf.arg3() as _,
                    tf.arg4() as _,
                ),
                Sysno::clone3 => sys_clone3(tf, tf.arg0() as _, tf.arg1() as _),
                Sysno::close_range => {
                    sys_close_range(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _
                }
                Sysno::exit_group => sys_exit_group(tf.arg0() as _),
                _ => {
                    if should_log_unimplemented_syscall(syscall_num) {
                        warn!("Unimplemented syscall: {}", syscall_num);
                    }
                    -(LinuxError::ENOSYS.code() as isize)
                }
            },
            None => {
                if should_log_invalid_syscall(syscall_num) {
                    warn!("Invalid syscall number: {}", syscall_num);
                }
                -(LinuxError::ENOSYS.code() as isize)
            }
        }
    };
    if trace_clone08 {
        #[cfg(target_arch = "riscv64")]
        warn!(
            "clone08 syscall exit tid={} pid={} num={} ret={} post-sp={:#x} post-ra={:#x} post-s0={:#x} post-s1={:#x} post-s2={:#x} post-s3={:#x}",
            curr.id().as_u64(),
            curr.task_ext().proc_id,
            syscall_num,
            ans,
            tf.regs.sp,
            tf.regs.ra,
            tf.regs.s0,
            tf.regs.s1,
            tf.regs.s2,
            tf.regs.s3,
        );
        #[cfg(target_arch = "loongarch64")]
        warn!(
            "clone08 syscall exit tid={} pid={} num={} ret={}",
            curr.id().as_u64(),
            curr.task_ext().proc_id,
            syscall_num,
            ans,
        );
    }
    log_mprotect02_syscall_exit(&curr, syscall_num, ans);
    ans
}
