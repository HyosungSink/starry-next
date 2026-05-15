use alloc::vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;

use arceos_posix_api as api;
use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use axhal::time::{monotonic_time_nanos, wall_time};
use axtask::TaskExtRef;

use super::thread::task_by_pid;
use crate::{
    signal::current_has_pending_signal,
    syscall_body,
    task::{find_live_task_by_tid, find_process_leader_by_pid},
    timekeeping::{current_clock_nanos, is_cpu_time_clock, monotonic_deadline_from_clock},
    usercopy::{
        copy_from_user, copy_to_user, ensure_user_range, read_value_from_user, write_value_to_user,
    },
};

const TIMER_ABSTIME: i32 = 1;
const SCHED_OTHER: i32 = 0;
const SCHED_FIFO: i32 = 1;
const SCHED_RR: i32 = 2;
const SCHED_BATCH: i32 = 3;
const SCHED_IDLE: i32 = 5;
const SCHED_DEADLINE: i32 = 6;
const SCHED_RESET_ON_FORK: i32 = 0x4000_0000;
const SCHED_ATTR_FLAG_RESET_ON_FORK: u64 = 0x01;
const MAX_RT_PRIORITY: i32 = 99;
const PERSONALITY_QUERY: usize = 0xffff_ffff;
const PRIO_PROCESS: i32 = 0;
const PRIO_PGRP: i32 = 1;
const PRIO_USER: i32 = 2;
const NICE_MIN: i32 = -20;
const NICE_MAX: i32 = 19;
const GETPRIORITY_RAW_BASE: i32 = 20;
#[cfg(target_arch = "loongarch64")]
const CYCLICTEST_SCHED_DIAG_LOG_LIMIT: usize = 64;

#[cfg(target_arch = "loongarch64")]
static CYCLICTEST_SCHED_DIAG_LOG_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);
static NICE05_DIAG_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SchedParam {
    sched_priority: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct SchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
}

#[cfg(target_arch = "loongarch64")]
fn take_cyclictest_sched_diag_slot() -> Option<usize> {
    let curr = axtask::current();
    let exec_path = curr.task_ext().exec_path();
    if !exec_path.contains("cyclictest") {
        return None;
    }
    let slot = CYCLICTEST_SCHED_DIAG_LOG_COUNT.fetch_add(1, Ordering::Relaxed);
    (slot < CYCLICTEST_SCHED_DIAG_LOG_LIMIT).then_some(slot + 1)
}

fn validate_sched_policy(policy: i32, priority: i32) -> Result<(), LinuxError> {
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => {
            if priority != 0 {
                return Err(LinuxError::EINVAL);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if !(1..=MAX_RT_PRIORITY).contains(&priority) {
                return Err(LinuxError::EINVAL);
            }
        }
        _ => return Err(LinuxError::EINVAL),
    }
    Ok(())
}

fn validate_sched_attr(attr: &SchedAttr) -> Result<(), LinuxError> {
    let policy = attr.sched_policy as i32;
    let priority = attr.sched_priority as i32;
    let reset_on_fork = attr.sched_flags & !SCHED_ATTR_FLAG_RESET_ON_FORK;
    if reset_on_fork != 0 {
        return Err(LinuxError::EINVAL);
    }
    validate_sched_policy(policy, priority)?;
    match policy {
        SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => {
            if !(NICE_MIN..=NICE_MAX).contains(&attr.sched_nice) {
                return Err(LinuxError::EINVAL);
            }
        }
        SCHED_FIFO | SCHED_RR => {
            if attr.sched_nice != 0 {
                return Err(LinuxError::EINVAL);
            }
        }
        SCHED_DEADLINE => {
            if attr.sched_nice != 0
                || attr.sched_runtime == 0
                || attr.sched_deadline == 0
                || attr.sched_period == 0
                || attr.sched_runtime > attr.sched_deadline
                || attr.sched_deadline > attr.sched_period
            {
                return Err(LinuxError::EINVAL);
            }
        }
        _ => return Err(LinuxError::EINVAL),
    }
    Ok(())
}

fn take_nice05_diag_slot() -> Option<usize> {
    let curr = axtask::current();
    let exec_path = curr.task_ext().exec_path();
    if !exec_path.contains("nice05") {
        return None;
    }
    let slot = NICE05_DIAG_LOG_COUNT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    (slot < 64).then_some(slot + 1)
}

fn scheduler_priority_for_task(policy: i32, rt_priority: i32, nice: i32) -> isize {
    match policy {
        SCHED_FIFO | SCHED_RR => rt_priority as isize,
        _ => {
            let _ = nice;
            0
        }
    }
}

fn scheduler_time_slice_for_task(policy: i32, nice: i32) -> usize {
    match policy {
        SCHED_FIFO | SCHED_RR => 5,
        _ => (5 - clamp_nice(nice)).clamp(1, 25) as usize,
    }
}

fn apply_sched_state(task: &axtask::AxTaskRef, policy: i32, priority: i32, reset_on_fork: bool) {
    task.task_ext()
        .set_sched_state(policy, priority, reset_on_fork);
    if policy != SCHED_DEADLINE {
        task.task_ext().set_sched_deadline(0, 0, 0);
    }
    let _ = axtask::set_task_priority(
        task,
        scheduler_priority_for_task(policy, priority, task.task_ext().nice()),
    );
    let _ = axtask::set_task_time_slice(
        task,
        scheduler_time_slice_for_task(policy, task.task_ext().nice()),
    );
}

fn clamp_nice(nice: i32) -> i32 {
    nice.clamp(NICE_MIN, NICE_MAX)
}

fn raw_getpriority_from_nice(nice: i32) -> isize {
    (GETPRIORITY_RAW_BASE - clamp_nice(nice)) as isize
}

fn target_task_for_priority(which: i32, who: i32) -> Result<axtask::AxTaskRef, LinuxError> {
    if who < 0 {
        return Err(LinuxError::ESRCH);
    }
    match which {
        PRIO_PROCESS => {
            if who == 0 {
                Ok(axtask::current().as_task_ref().clone())
            } else {
                find_live_task_by_tid(who as u64)
                    .or_else(|| find_process_leader_by_pid(who as usize))
                    .ok_or(LinuxError::ESRCH)
            }
        }
        PRIO_PGRP | PRIO_USER => Err(LinuxError::EACCES),
        _ => Err(LinuxError::EINVAL),
    }
}

fn timespec_to_nanos(ts: api::ctypes::timespec) -> Result<i128, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(LinuxError::EINVAL);
    }
    Ok((ts.tv_sec as i128) * 1_000_000_000i128 + ts.tv_nsec as i128)
}

fn nanos_to_timespec(ns: i128) -> api::ctypes::timespec {
    let clamped = ns.max(0);
    api::ctypes::timespec {
        tv_sec: (clamped / 1_000_000_000i128) as _,
        tv_nsec: (clamped % 1_000_000_000i128) as _,
    }
}

pub(crate) fn sys_sched_yield() -> i32 {
    api::sys_sched_yield()
}

pub(crate) fn sys_getpriority(which: i32, who: i32) -> isize {
    syscall_body!(sys_getpriority, {
        let diag_slot = take_nice05_diag_slot();
        let task = target_task_for_priority(which, who)?;
        let ret = raw_getpriority_from_nice(task.task_ext().nice());
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[nice05-diag:{}] syscall=getpriority curr_tid={} curr_pid={} which={} who={} target_tid={} target_pid={} nice={} raw_ret={}",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                which,
                who,
                task.id().as_u64(),
                task.task_ext().proc_id,
                task.task_ext().nice(),
                ret,
            );
        }
        Ok(ret)
    })
}

pub(crate) fn sys_setpriority(which: i32, who: i32, prio: i32) -> isize {
    syscall_body!(sys_setpriority, {
        let diag_slot = take_nice05_diag_slot();
        let task = target_task_for_priority(which, who)?;
        let target_nice = clamp_nice(prio);
        let current_nice = task.task_ext().nice();
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[nice05-diag:{}] syscall=setpriority curr_tid={} curr_pid={} which={} who={} target_tid={} target_pid={} old_nice={} new_nice={} policy={} rt_prio={} euid={}",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                which,
                who,
                task.id().as_u64(),
                task.task_ext().proc_id,
                current_nice,
                target_nice,
                task.task_ext().schedule_policy(),
                task.task_ext().schedule_priority(),
                axfs::api::current_euid(),
            );
        }
        if target_nice < current_nice && axfs::api::current_euid() != 0 {
            return Err(LinuxError::EPERM);
        }
        if !axtask::set_task_priority(
            &task,
            scheduler_priority_for_task(
                task.task_ext().schedule_policy(),
                task.task_ext().schedule_priority(),
                target_nice,
            ),
        ) {
            return Err(LinuxError::EINVAL);
        }
        let _ = axtask::set_task_time_slice(
            &task,
            scheduler_time_slice_for_task(task.task_ext().schedule_policy(), target_nice),
        );
        task.task_ext().set_nice(target_nice);
        if let Some(slot) = diag_slot {
            warn!(
                "[nice05-diag:{}] syscall=setpriority applied target_tid={} applied_nice={}",
                slot,
                task.id().as_u64(),
                task.task_ext().nice(),
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_personality(persona: usize) -> isize {
    syscall_body!(sys_personality, {
        let task = axtask::current();
        let previous = task.task_ext().personality();
        if persona != PERSONALITY_QUERY {
            task.task_ext().set_personality(persona as u32);
        }
        Ok(previous as isize)
    })
}

pub(crate) fn sys_sched_getscheduler(pid: i32) -> isize {
    syscall_body!(sys_sched_getscheduler, {
        #[cfg(target_arch = "loongarch64")]
        let diag_slot = take_cyclictest_sched_diag_slot();
        if pid < 0 {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_getscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} result=EINVAL reason=negative-pid",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                );
            }
            return Err(LinuxError::EINVAL);
        }
        let task = match task_by_pid(pid) {
            Ok(task) => task,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_getscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} result={:?}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let policy = task.task_ext().schedule_policy();
        #[cfg(target_arch = "loongarch64")]
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[online-cyclictest-sched:{}] syscall=sched_getscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} target_tid={} target_pid={} policy={} prio={} result=0",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                curr.task_ext().exec_path(),
                pid,
                task.id().as_u64(),
                task.task_ext().proc_id,
                policy,
                task.task_ext().schedule_priority(),
            );
        }
        Ok(policy as isize)
    })
}

pub(crate) fn sys_sched_get_priority_max(policy: i32) -> isize {
    syscall_body!(sys_sched_get_priority_max, {
        match policy {
            SCHED_FIFO | SCHED_RR => Ok(MAX_RT_PRIORITY as isize),
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Ok(0),
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub(crate) fn sys_sched_get_priority_min(policy: i32) -> isize {
    syscall_body!(sys_sched_get_priority_min, {
        match policy {
            SCHED_FIFO | SCHED_RR => Ok(1),
            SCHED_OTHER | SCHED_BATCH | SCHED_IDLE => Ok(0),
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub(crate) fn sys_sched_getparam(pid: i32, param: *mut SchedParam) -> isize {
    syscall_body!(sys_sched_getparam, {
        #[cfg(target_arch = "loongarch64")]
        let diag_slot = take_cyclictest_sched_diag_slot();
        if pid < 0 {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_getparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result=EINVAL reason=negative-pid",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                );
            }
            return Err(LinuxError::EINVAL);
        }
        if param.is_null() {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_getparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result=EFAULT reason=null-param",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                );
            }
            return Err(LinuxError::EFAULT);
        }
        let task = match task_by_pid(pid) {
            Ok(task) => task,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_getparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result={:?}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        param as usize,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let value = SchedParam {
            sched_priority: task.task_ext().schedule_priority(),
        };
        if let Err(err) = write_value_to_user(param, value) {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_getparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} target_tid={} target_pid={} policy={} prio={} result={:?}",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                    task.id().as_u64(),
                    task.task_ext().proc_id,
                    task.task_ext().schedule_policy(),
                    value.sched_priority,
                    err,
                );
            }
            return Err(err);
        }
        #[cfg(target_arch = "loongarch64")]
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[online-cyclictest-sched:{}] syscall=sched_getparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} target_tid={} target_pid={} policy={} prio={} result=0",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                curr.task_ext().exec_path(),
                pid,
                param as usize,
                task.id().as_u64(),
                task.task_ext().proc_id,
                task.task_ext().schedule_policy(),
                value.sched_priority,
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_sched_setparam(pid: i32, param: *const SchedParam) -> isize {
    syscall_body!(sys_sched_setparam, {
        #[cfg(target_arch = "loongarch64")]
        let diag_slot = take_cyclictest_sched_diag_slot();
        if pid < 0 {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result=EINVAL reason=negative-pid",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                );
            }
            return Err(LinuxError::EINVAL);
        }
        if param.is_null() {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result=EFAULT reason=null-param",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                );
            }
            return Err(LinuxError::EFAULT);
        }
        let new_param = match read_value_from_user(param) {
            Ok(value) => value,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} result={:?} reason=read-user",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        param as usize,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let task = match task_by_pid(pid) {
            Ok(task) => task,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} requested_prio={} result={:?}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        param as usize,
                        new_param.sched_priority,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let policy = task.task_ext().schedule_policy();
        if let Err(err) = validate_sched_policy(policy, new_param.sched_priority) {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} target_tid={} target_pid={} policy={} requested_prio={} result={:?} reason=validate",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    param as usize,
                    task.id().as_u64(),
                    task.task_ext().proc_id,
                    policy,
                    new_param.sched_priority,
                    err,
                );
            }
            return Err(err);
        }
        apply_sched_state(
            &task,
            policy,
            new_param.sched_priority,
            task.task_ext().schedule_reset_on_fork(),
        );
        #[cfg(target_arch = "loongarch64")]
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[online-cyclictest-sched:{}] syscall=sched_setparam curr_tid={} curr_pid={} exec_path={} pid_arg={} param={:#x} target_tid={} target_pid={} policy={} requested_prio={} result=0",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                curr.task_ext().exec_path(),
                pid,
                param as usize,
                task.id().as_u64(),
                task.task_ext().proc_id,
                policy,
                new_param.sched_priority,
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_sched_setscheduler(pid: i32, policy: i32, param: *const SchedParam) -> isize {
    syscall_body!(sys_sched_setscheduler, {
        #[cfg(target_arch = "loongarch64")]
        let diag_slot = take_cyclictest_sched_diag_slot();
        if pid < 0 {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} param={:#x} result=EINVAL reason=negative-pid",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    policy,
                    param as usize,
                );
            }
            return Err(LinuxError::EINVAL);
        }
        if param.is_null() {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} param={:#x} result=EFAULT reason=null-param",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    policy,
                    param as usize,
                );
            }
            return Err(LinuxError::EFAULT);
        }
        let new_param = match read_value_from_user(param) {
            Ok(value) => value,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} param={:#x} result={:?} reason=read-user",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        policy,
                        param as usize,
                        err,
                    );
                }
                return Err(err);
            }
        };
        let reset_on_fork = (policy & SCHED_RESET_ON_FORK) != 0;
        let base_policy = policy & !SCHED_RESET_ON_FORK;
        if let Err(err) = validate_sched_policy(base_policy, new_param.sched_priority) {
            #[cfg(target_arch = "loongarch64")]
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} base_policy={} param={:#x} requested_prio={} result={:?} reason=validate",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    curr.task_ext().exec_path(),
                    pid,
                    policy,
                    base_policy,
                    param as usize,
                    new_param.sched_priority,
                    err,
                );
            }
            return Err(err);
        }
        let task = match task_by_pid(pid) {
            Ok(task) => task,
            Err(err) => {
                #[cfg(target_arch = "loongarch64")]
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} base_policy={} param={:#x} requested_prio={} result={:?}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        curr.task_ext().exec_path(),
                        pid,
                        policy,
                        base_policy,
                        param as usize,
                        new_param.sched_priority,
                        err,
                    );
                }
                return Err(err);
            }
        };
        apply_sched_state(&task, base_policy, new_param.sched_priority, reset_on_fork);
        #[cfg(target_arch = "loongarch64")]
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[online-cyclictest-sched:{}] syscall=sched_setscheduler curr_tid={} curr_pid={} exec_path={} pid_arg={} policy_arg={} base_policy={} param={:#x} target_tid={} target_pid={} requested_prio={} reset_on_fork={} result=0",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                curr.task_ext().exec_path(),
                pid,
                policy,
                base_policy,
                param as usize,
                task.id().as_u64(),
                task.task_ext().proc_id,
                new_param.sched_priority,
                reset_on_fork,
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_sched_setattr(pid: i32, attr: *const SchedAttr, flags: u32) -> isize {
    syscall_body!(sys_sched_setattr, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        if attr.is_null() || flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        let new_attr = read_value_from_user(attr)?;
        if (new_attr.size as usize) < core::mem::size_of::<SchedAttr>() {
            return Err(LinuxError::EINVAL);
        }
        validate_sched_attr(&new_attr)?;
        let task = task_by_pid(pid)?;
        let policy = new_attr.sched_policy as i32;
        let priority = new_attr.sched_priority as i32;
        let nice = clamp_nice(new_attr.sched_nice);
        let reset_on_fork = (new_attr.sched_flags & SCHED_ATTR_FLAG_RESET_ON_FORK) != 0;

        if !axtask::set_task_priority(&task, scheduler_priority_for_task(policy, priority, nice)) {
            return Err(LinuxError::EINVAL);
        }
        let _ = axtask::set_task_time_slice(&task, scheduler_time_slice_for_task(policy, nice));
        task.task_ext().set_nice(nice);
        task.task_ext()
            .set_sched_state(policy, priority, reset_on_fork);
        if policy == SCHED_DEADLINE {
            task.task_ext().set_sched_deadline(
                new_attr.sched_runtime,
                new_attr.sched_deadline,
                new_attr.sched_period,
            );
        } else {
            task.task_ext().set_sched_deadline(0, 0, 0);
        }
        Ok(0)
    })
}

pub(crate) fn sys_sched_getattr(pid: i32, attr: *mut SchedAttr, size: u32, flags: u32) -> isize {
    syscall_body!(sys_sched_getattr, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        if attr.is_null() {
            return Err(LinuxError::EINVAL);
        }
        if (size as usize) < core::mem::size_of::<SchedAttr>() || flags != 0 {
            return Err(LinuxError::EINVAL);
        }
        let task = task_by_pid(pid)?;
        let reset_on_fork = if task.task_ext().schedule_reset_on_fork() {
            SCHED_ATTR_FLAG_RESET_ON_FORK
        } else {
            0
        };
        let value = SchedAttr {
            size: core::mem::size_of::<SchedAttr>() as u32,
            sched_policy: task.task_ext().schedule_policy() as u32,
            sched_flags: reset_on_fork,
            sched_nice: task.task_ext().nice(),
            sched_priority: task.task_ext().schedule_priority() as u32,
            sched_runtime: task.task_ext().schedule_runtime(),
            sched_deadline: task.task_ext().schedule_deadline(),
            sched_period: task.task_ext().schedule_period(),
        };
        write_value_to_user(attr, value)?;
        Ok(0)
    })
}

pub(crate) fn sys_sched_setaffinity(pid: i32, cpusetsize: usize, mask: *const u8) -> isize {
    syscall_body!(sys_sched_setaffinity, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        if cpusetsize == 0 {
            return Err(LinuxError::EINVAL);
        }
        if mask.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let _task = task_by_pid(pid)?;
        ensure_user_range((mask as usize).into(), 1, MappingFlags::READ)?;
        let mut first = [0u8; 1];
        copy_from_user(&mut first, mask.cast())?;
        if first[0] & 1 == 0 {
            return Err(LinuxError::EINVAL);
        }
        Ok(0)
    })
}

pub(crate) fn sys_sched_getaffinity(pid: i32, cpusetsize: usize, mask: *mut u8) -> isize {
    syscall_body!(sys_sched_getaffinity, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        if cpusetsize == 0 {
            return Err(LinuxError::EINVAL);
        }
        if mask.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let _task = task_by_pid(pid)?;
        let mut cpu_mask = vec![0u8; cpusetsize];
        cpu_mask[0] = 1;
        copy_to_user(mask.cast(), &cpu_mask)?;
        Ok(cpusetsize as isize)
    })
}

pub(crate) fn sys_sched_rr_get_interval(pid: i32, interval: *mut api::ctypes::timespec) -> isize {
    syscall_body!(sys_sched_rr_get_interval, {
        if pid < 0 {
            return Err(LinuxError::EINVAL);
        }
        if interval.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let task = task_by_pid(pid)?;
        let slice_ns = if task.task_ext().schedule_policy() == SCHED_RR {
            10_000_000i128
        } else {
            0
        };
        write_value_to_user(interval, nanos_to_timespec(slice_ns))?;
        Ok(0)
    })
}

pub(crate) fn sys_nanosleep(
    req: *const api::ctypes::timespec,
    rem: *mut api::ctypes::timespec,
) -> i32 {
    syscall_body!(sys_nanosleep, {
        let diag_slot = take_nice05_diag_slot();
        if req.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let req_local = read_value_from_user(req)?;
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[nice05-diag:{}] syscall=nanosleep enter tid={} pid={} sec={} nsec={}",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                req_local.tv_sec,
                req_local.tv_nsec,
            );
        }
        let mut rem_local = api::ctypes::timespec::default();
        let rem_ptr = if rem.is_null() {
            core::ptr::null_mut()
        } else {
            &mut rem_local
        };
        let ret = unsafe { api::sys_nanosleep(&req_local, rem_ptr) };
        if ret < 0 {
            if !rem.is_null() {
                write_value_to_user(rem, rem_local)?;
            }
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[nice05-diag:{}] syscall=nanosleep exit tid={} pid={} ret={} errno={}",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    ret,
                    -ret,
                );
            }
            return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EINVAL));
        }
        if !rem.is_null() {
            write_value_to_user(rem, rem_local)?;
        }
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[nice05-diag:{}] syscall=nanosleep exit tid={} pid={} ret=0",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_clock_nanosleep(
    clock_id: i32,
    flags: i32,
    req: *const api::ctypes::timespec,
    rem: *mut api::ctypes::timespec,
) -> i32 {
    const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
    const CLOCK_THREAD_CPUTIME_ID: i32 = 3;

    syscall_body!(sys_clock_nanosleep, {
        let diag_slot = take_nice05_diag_slot();
        fn write_remaining(
            rem: *mut api::ctypes::timespec,
            remaining_ns: u64,
        ) -> Result<(), LinuxError> {
            if rem.is_null() {
                return Ok(());
            }
            write_value_to_user(rem, nanos_to_timespec(remaining_ns as i128))
        }

        if req.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if flags & !TIMER_ABSTIME != 0 {
            return Err(LinuxError::EINVAL);
        }
        if is_cpu_time_clock(clock_id) {
            return Err(LinuxError::EOPNOTSUPP);
        }

        let req_local = read_value_from_user(req)?;
        let requested_ns = timespec_to_nanos(req_local)? as u64;
        if let Some(slot) = diag_slot {
            let curr = axtask::current();
            warn!(
                "[nice05-diag:{}] syscall=clock_nanosleep enter tid={} pid={} clock_id={} flags={} sec={} nsec={}",
                slot,
                curr.id().as_u64(),
                curr.task_ext().proc_id,
                clock_id,
                flags,
                req_local.tv_sec,
                req_local.tv_nsec,
            );
        }

        if flags & TIMER_ABSTIME != 0 {
            loop {
                let now_clock_ns = current_clock_nanos(clock_id)?;
                if now_clock_ns >= requested_ns {
                    if let Some(slot) = diag_slot {
                        let curr = axtask::current();
                        warn!(
                            "[nice05-diag:{}] syscall=clock_nanosleep exit tid={} pid={} ret=0 mode=abs",
                            slot,
                            curr.id().as_u64(),
                            curr.task_ext().proc_id,
                        );
                    }
                    return Ok(0);
                }

                let deadline_mono_ns = monotonic_deadline_from_clock(clock_id, requested_ns, true)?;
                let now_mono_ns = monotonic_time_nanos();
                let remaining_ns = deadline_mono_ns.saturating_sub(now_mono_ns);
                if remaining_ns == 0 {
                    continue;
                }
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[nice05-diag:{}] syscall=clock_nanosleep sleep tid={} pid={} mode=abs remaining_ns={}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        remaining_ns,
                    );
                }

                axtask::sleep_until(wall_time() + Duration::from_nanos(remaining_ns));
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[nice05-diag:{}] syscall=clock_nanosleep woke tid={} pid={} mode=abs now_mono_ns={}",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                        monotonic_time_nanos(),
                    );
                }

                if current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
            }
        }

        let _ = current_clock_nanos(clock_id)?;
        let deadline_mono_ns = monotonic_time_nanos()
            .checked_add(requested_ns)
            .ok_or(LinuxError::EINVAL)?;

        loop {
            let now_mono_ns = monotonic_time_nanos();
            if now_mono_ns >= deadline_mono_ns {
                write_remaining(rem, 0)?;
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[nice05-diag:{}] syscall=clock_nanosleep exit tid={} pid={} ret=0 mode=rel",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                    );
                }
                return Ok(0);
            }

            let remaining_ns = deadline_mono_ns - now_mono_ns;
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[nice05-diag:{}] syscall=clock_nanosleep sleep tid={} pid={} mode=rel remaining_ns={}",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    remaining_ns,
                );
            }
            axtask::sleep_until(wall_time() + Duration::from_nanos(remaining_ns));
            if let Some(slot) = diag_slot {
                let curr = axtask::current();
                warn!(
                    "[nice05-diag:{}] syscall=clock_nanosleep woke tid={} pid={} mode=rel now_mono_ns={}",
                    slot,
                    curr.id().as_u64(),
                    curr.task_ext().proc_id,
                    monotonic_time_nanos(),
                );
            }

            let now_mono_ns = monotonic_time_nanos();
            if now_mono_ns >= deadline_mono_ns {
                write_remaining(rem, 0)?;
                if let Some(slot) = diag_slot {
                    let curr = axtask::current();
                    warn!(
                        "[nice05-diag:{}] syscall=clock_nanosleep exit tid={} pid={} ret=0 mode=rel-postwake",
                        slot,
                        curr.id().as_u64(),
                        curr.task_ext().proc_id,
                    );
                }
                return Ok(0);
            }

            if current_has_pending_signal() {
                write_remaining(rem, deadline_mono_ns - now_mono_ns)?;
                return Err(LinuxError::EINTR);
            }
        }
    })
}

pub(crate) fn sys_timer_create(
    clock_id: i32,
    sevp: *const core::ffi::c_void,
    timerid: *mut i32,
) -> isize {
    crate::signal::sys_timer_create(clock_id, sevp, timerid)
}

pub(crate) fn sys_timer_settime(
    timerid: i32,
    flags: i32,
    new_value: *const core::ffi::c_void,
    old_value: *mut core::ffi::c_void,
) -> isize {
    crate::signal::sys_timer_settime(timerid, flags, new_value, old_value)
}

pub(crate) fn sys_timer_gettime(timerid: i32, curr_value: *mut core::ffi::c_void) -> isize {
    crate::signal::sys_timer_gettime(timerid, curr_value)
}

pub(crate) fn sys_timer_delete(timerid: i32) -> isize {
    crate::signal::sys_timer_delete(timerid)
}

pub(crate) fn sys_timer_getoverrun(timerid: i32) -> isize {
    crate::signal::sys_timer_getoverrun(timerid)
}
