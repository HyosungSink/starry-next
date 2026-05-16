use alloc::{
    collections::{BTreeMap, VecDeque},
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use arceos_posix_api::{
    close_all_fds_fast, close_on_exec_fds, FD_FLAGS, FD_TABLE, PROC_NET_IPV4_CONF_DEFAULT_TAG,
    PROC_NET_IPV4_CONF_LO_TAG, RESOURCE_LIMITS,
};
use axalloc::global_allocator;
use axerrno::{AxError, AxResult, LinuxError};
use axfs::{CURRENT_DIR, CURRENT_DIR_PATH, CURRENT_FS_CRED};
use core::{
    alloc::Layout,
    cell::UnsafeCell,
    sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU64, AtomicUsize, Ordering},
};
use spin::Once;

use crate::ctypes::{CloneFlags, TimeStat, WaitStatus};
use crate::signal::SignalState;
use crate::usercopy::{read_value_from_user, write_value_to_user};
use axhal::{
    arch::{TrapFrame, UspaceContext},
    paging::MappingFlags,
    time::{monotonic_time_nanos, NANOS_PER_MICROS, NANOS_PER_SEC},
};
use axmm::AddrSpace;
use axns::{AxNamespace, AxNamespaceIf};
use axsync::Mutex;
use axtask::{current, AxTaskRef, TaskExtRef, TaskInner};
use axtask::{WaitQueue, WeakAxTaskRef};
use memory_addr::{MemoryAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};

#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_PTHREAD_SIZE: usize = 200;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_SELF_OFFSET: usize = 0;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_PREV_OFFSET: usize = 8;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_NEXT_OFFSET: usize = 16;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_TID_OFFSET: usize = 32;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_ROBUST_HEAD_OFFSET: usize = 120;
#[cfg(target_arch = "riscv64")]
const RISCV_MUSL_DTV_PTR_OFFSET_FROM_TP: usize = 8;

static COMPETITION_FAIL_FAST: AtomicBool = AtomicBool::new(false);
static NEXT_COMPETITION_SCRIPT_TAG: AtomicU64 = AtomicU64::new(1);
static COMPETITION_ABORTING_SCRIPT_TAG: AtomicU64 = AtomicU64::new(0);
static NEXT_PROCESS_ID: AtomicU64 = AtomicU64::new(0);
static PROC_PID_MAX: AtomicU64 = AtomicU64::new(32768);
static PRIVATE_FORK_PRESSURE_LOG_COUNT: AtomicU64 = AtomicU64::new(0);
static LOAD_APP_OOM_BUSYBOX_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAD_APP_OOM_SHELL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAD_APP_OOM_LTP_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static LOAD_APP_OOM_OTHER_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static EXEC_OOM_BUSYBOX_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static EXEC_OOM_SHELL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static EXEC_OOM_LTP_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static EXEC_OOM_OTHER_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_RECLAIM_LOG_COUNT: AtomicU64 = AtomicU64::new(0);
static TASK_ALLOC_PRESSURE_LOG_COUNT: AtomicU64 = AtomicU64::new(0);
static EXEC_PREPARE_LOG_COUNT: AtomicU64 = AtomicU64::new(0);
static EXEC_PREPARE_SEQ: AtomicU64 = AtomicU64::new(0);

const REPEATED_LOG_BURST: usize = 4;
const REPEATED_LOG_PERIOD: usize = 64;
const EXEC_OOM_LOG_BURST: usize = 2;
const EXEC_OOM_LOG_PERIOD: usize = 128;
const EXEC_PREPARE_RECLAIM_PERIOD: u64 = 128;

#[derive(Clone, Copy, Default)]
pub(crate) struct RuntimeReclaimStats {
    pub exited_tasks: usize,
    pub stack_pages: usize,
    pub exec_cache_pages: usize,
    pub fs_cache_entries: usize,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct DiagnosticTaskCounts {
    pub live_tasks: usize,
    pub live_exited_tasks: usize,
    pub process_leaders: usize,
    pub zombie_processes: usize,
    pub script_tagged_tasks: usize,
    pub script_tagged_exited_tasks: usize,
}

fn competition_script_root() -> &'static Mutex<Option<AxTaskRef>> {
    static COMPETITION_SCRIPT_ROOT: Once<Mutex<Option<AxTaskRef>>> = Once::new();
    COMPETITION_SCRIPT_ROOT.call_once(|| Mutex::new(None))
}

fn live_tasks() -> &'static Mutex<BTreeMap<u64, WeakAxTaskRef>> {
    static LIVE_TASKS: Once<Mutex<BTreeMap<u64, WeakAxTaskRef>>> = Once::new();
    LIVE_TASKS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn process_leaders() -> &'static Mutex<BTreeMap<u64, WeakAxTaskRef>> {
    static PROCESS_LEADERS: Once<Mutex<BTreeMap<u64, WeakAxTaskRef>>> = Once::new();
    PROCESS_LEADERS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn zombie_processes() -> &'static Mutex<BTreeMap<u64, ZombieProcess>> {
    static ZOMBIE_PROCESSES: Once<Mutex<BTreeMap<u64, ZombieProcess>>> = Once::new();
    ZOMBIE_PROCESSES.call_once(|| Mutex::new(BTreeMap::new()))
}

fn task_is_live(task: &AxTaskRef) -> bool {
    task.state() != axtask::TaskState::Exited
}

fn repeated_log_sample(counter: &AtomicUsize, burst: usize, period: usize) -> Option<usize> {
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= burst || (period != 0 && count % period == 0) {
        Some(count)
    } else {
        None
    }
}

fn exec_failure_bucket(path: &str) -> (&'static str, &'static AtomicUsize, &'static AtomicUsize) {
    if path == "/busybox" || path.ends_with("/busybox") {
        return (
            "busybox",
            &LOAD_APP_OOM_BUSYBOX_LOG_COUNT,
            &EXEC_OOM_BUSYBOX_LOG_COUNT,
        );
    }
    if path == "/bin/sh" || path.ends_with("/bin/sh") {
        return (
            "shell",
            &LOAD_APP_OOM_SHELL_LOG_COUNT,
            &EXEC_OOM_SHELL_LOG_COUNT,
        );
    }
    if path.contains("/ltp/testcases/bin/") {
        return ("ltp", &LOAD_APP_OOM_LTP_LOG_COUNT, &EXEC_OOM_LTP_LOG_COUNT);
    }
    (
        "other",
        &LOAD_APP_OOM_OTHER_LOG_COUNT,
        &EXEC_OOM_OTHER_LOG_COUNT,
    )
}

pub(crate) fn log_user_program_load_failure(path: &str, err: &AxError) {
    if matches!(err, AxError::NoMemory) {
        let (kind, counter, _) = exec_failure_bucket(path);
        if let Some(count) = repeated_log_sample(counter, REPEATED_LOG_BURST, REPEATED_LOG_PERIOD)
        {
            error!(
                "Failed to load app {}: {:?} [sampled kind={} count={}]",
                path, err, kind, count
            );
        }
        return;
    }
    error!("Failed to load app {}: {:?}", path, err);
}

pub(crate) fn log_exec_failure(path: &str, err: &AxError) {
    if matches!(err, AxError::NoMemory) {
        let (kind, _, counter) = exec_failure_bucket(path);
        if let Some(count) = repeated_log_sample(counter, EXEC_OOM_LOG_BURST, EXEC_OOM_LOG_PERIOD)
        {
            error!(
                "Failed to exec path={} err={:?} [sampled kind={} count={}]",
                path, err, kind, count
            );
        }
        return;
    }
    error!("Failed to exec path={} err={:?}", path, err);
}

fn allocate_process_id() -> usize {
    let pid_max = PROC_PID_MAX.load(Ordering::Acquire).max(1) as usize;
    let mut candidate = NEXT_PROCESS_ID.load(Ordering::Relaxed) as usize;
    let leaders = process_leaders().lock();
    let zombies = zombie_processes().lock();

    for _ in 0..pid_max {
        candidate = if candidate >= pid_max {
            1
        } else {
            candidate + 1
        };
        if !leaders.contains_key(&(candidate as u64)) && !zombies.contains_key(&(candidate as u64)) {
            NEXT_PROCESS_ID.store(candidate as u64, Ordering::Relaxed);
            return candidate;
        }
    }

    warn!(
        "allocate_process_id exhausted pid space: pid_max={} last_pid={}",
        pid_max,
        NEXT_PROCESS_ID.load(Ordering::Relaxed)
    );
    1
}

fn should_trace_clone08() -> bool {
    false
}

fn should_log_runtime_reclaim() -> bool {
    let slot = RUNTIME_RECLAIM_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    slot <= REPEATED_LOG_BURST as u64 || slot % REPEATED_LOG_PERIOD as u64 == 0
}

fn should_log_task_alloc_pressure() -> bool {
    let slot = TASK_ALLOC_PRESSURE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    slot <= REPEATED_LOG_BURST as u64 || slot.is_power_of_two()
}

fn should_log_exec_prepare_pressure() -> bool {
    let slot = EXEC_PREPARE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    slot <= REPEATED_LOG_BURST as u64 || slot.is_power_of_two()
}

fn runtime_reclaim_low_watermark_pages() -> usize {
    let total_pages = axconfig::plat::PHYS_MEMORY_SIZE / PAGE_SIZE_4K;
    total_pages.div_ceil(32).clamp(4096, 16384)
}

pub(crate) fn user_task_kernel_stack_size() -> usize {
    let default = axconfig::plat::KERNEL_STACK_SIZE;
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        default.min(64 * 1024)
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        default
    }
}

pub(crate) fn reclaim_runtime_memory_detail(reason: &str) -> RuntimeReclaimStats {
    let stats = RuntimeReclaimStats {
        exited_tasks: axtask::reclaim_exited_tasks(usize::MAX),
        stack_pages: axtask::reclaim_task_stack_cache(0),
        exec_cache_pages: crate::mm::reclaim_exec_caches(),
        fs_cache_entries: axfs::api::reclaim_caches(),
    };
    if (stats.exited_tasks > 0
        || stats.stack_pages > 0
        || stats.exec_cache_pages > 0
        || stats.fs_cache_entries > 0)
        && should_log_runtime_reclaim()
    {
        warn!(
            "runtime reclaim reason={} reclaimed_exited_tasks={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reclaimed_fs_cache_entries={}",
            reason,
            stats.exited_tasks,
            stats.stack_pages,
            stats.exec_cache_pages,
            stats.fs_cache_entries
        );
    }
    stats
}

pub(crate) fn reclaim_runtime_memory(reason: &str) -> (usize, usize) {
    let stats = reclaim_runtime_memory_detail(reason);
    (stats.stack_pages, stats.exec_cache_pages)
}

pub(crate) fn diagnostic_task_counts() -> DiagnosticTaskCounts {
    let script_tag = competition_script_root()
        .lock()
        .as_ref()
        .map(|task| task.task_ext().competition_script_tag())
        .unwrap_or(0);
    let mut counts = DiagnosticTaskCounts::default();
    {
        let tasks = live_tasks().lock();
        for task in tasks.values().filter_map(|task| task.upgrade()) {
            counts.live_tasks += 1;
            let exited = task.state() == axtask::TaskState::Exited;
            if exited {
                counts.live_exited_tasks += 1;
            }
            if script_tag != 0 && task.task_ext().competition_script_tag() == script_tag {
                counts.script_tagged_tasks += 1;
                if exited {
                    counts.script_tagged_exited_tasks += 1;
                }
            }
        }
    }
    counts.process_leaders = process_leaders().lock().len();
    counts.zombie_processes = zombie_processes().lock().len();
    counts
}

pub(crate) fn prepare_runtime_for_exec(reason: &str, path: &str) {
    let available_before = global_allocator().available_pages();
    let low_watermark = runtime_reclaim_low_watermark_pages();
    let sequence = EXEC_PREPARE_SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let low_memory = available_before <= low_watermark;
    if !low_memory && sequence % EXEC_PREPARE_RECLAIM_PERIOD != 0 {
        return;
    }

    let mut reclaimed = reclaim_runtime_memory_detail(reason);
    let mut available_after = global_allocator().available_pages();
    if low_memory && available_after <= low_watermark.saturating_div(2).max(1024) {
        crate::mm::invalidate_exec_cache_path(path);
        let retry = reclaim_runtime_memory_detail("exec_prepare_retry");
        reclaimed.stack_pages = reclaimed.stack_pages.saturating_add(retry.stack_pages);
        reclaimed.exec_cache_pages =
            reclaimed.exec_cache_pages.saturating_add(retry.exec_cache_pages);
        reclaimed.fs_cache_entries =
            reclaimed.fs_cache_entries.saturating_add(retry.fs_cache_entries);
        available_after = global_allocator().available_pages();
    }

    if should_log_exec_prepare_pressure()
        && (low_memory
            || reclaimed.stack_pages > 0
            || reclaimed.exec_cache_pages > 0
            || reclaimed.fs_cache_entries > 0)
    {
        warn!(
            "exec prepare reason={} path={} available_pages={} -> {} low_watermark={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reclaimed_fs_cache_entries={}",
            reason,
            path,
            available_before,
            available_after,
            low_watermark,
            reclaimed.stack_pages,
            reclaimed.exec_cache_pages,
            reclaimed.fs_cache_entries
        );
    }
}

pub(crate) fn proc_pid_max_contents() -> String {
    alloc::format!("{}\n", PROC_PID_MAX.load(Ordering::Acquire))
}

pub(crate) fn set_proc_pid_max_value(value: usize) -> Result<(), LinuxError> {
    if value == 0 {
        return Err(LinuxError::EINVAL);
    }
    PROC_PID_MAX.store(value as u64, Ordering::Release);
    Ok(())
}

fn task_is_process_leader(task: &AxTaskRef) -> bool {
    task.id().as_u64() == task.task_ext().leader_tid()
}

pub(crate) fn proc_pid_stat_contents(pid: u64, state: char) -> String {
    let utime = (monotonic_time_nanos() as u64 / 10_000_000).max(1);
    alloc::format!(
        "{pid} (busybox) {state} 0 0 0 0 0 0 0 0 0 0 {utime} 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

fn ensure_proc_pid_entries(pid: u64) {
    let _ = pid;
}

fn remove_proc_pid_entries(pid: u64) {
    let _ = pid;
}

fn task_state_char(task: &AxTaskRef) -> char {
    match task.state() {
        axtask::TaskState::Running | axtask::TaskState::Ready => 'R',
        axtask::TaskState::Blocked => 'S',
        axtask::TaskState::Exited => 'Z',
    }
}

pub(crate) fn live_pid_stat_contents(pid: u64) -> Option<String> {
    let task = find_process_leader_by_pid(pid as usize)?;
    Some(proc_pid_stat_contents(pid, task_state_char(&task)))
}

fn live_thread_count_for_process(proc_id: usize) -> usize {
    let mut stale = Vec::new();
    let mut count = 0usize;
    {
        let tasks = live_tasks().lock();
        for (tid, task) in tasks.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task_is_live(&task) && task.task_ext().proc_id == proc_id {
                count += 1;
            }
        }
    }
    if !stale.is_empty() {
        let mut tasks = live_tasks().lock();
        for tid in stale {
            tasks.remove(&tid);
        }
    }
    count.max(1)
}

pub(crate) fn live_pid_status_contents(pid: u64) -> Option<String> {
    let task = find_process_leader_by_pid(pid as usize)?;
    let proc_id = task.task_ext().proc_id;
    let ppid = task.task_ext().get_parent();
    let state = task_state_char(&task);
    let threads = live_thread_count_for_process(proc_id);
    Some(alloc::format!(
        "Name:\t{}\nState:\t{} (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nThreads:\t{}\n",
        task.name(),
        state,
        proc_id,
        pid,
        ppid,
        threads,
    ))
}

fn proc_pid_from_path(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("/proc/")?;
    let pid = rest.split('/').next()?;
    if pid.is_empty() || !pid.bytes().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

fn live_process_leader_ids() -> Vec<u64> {
    let mut stale = Vec::new();
    let mut pids = Vec::new();
    {
        let tasks = live_tasks().lock();
        for (tid, task) in tasks.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task_is_live(&task) && task_is_process_leader(&task) {
                pids.push(task.task_ext().proc_id as u64);
            }
        }
    }
    if !stale.is_empty() {
        let mut tasks = live_tasks().lock();
        for tid in stale {
            tasks.remove(&tid);
        }
    }
    pids
}

fn sync_proc_pid_root_dirs() {
    let live_pids = live_process_leader_ids();
    for pid in &live_pids {
        let dir = alloc::format!("/proc/{pid}");
        let _ = axfs::api::create_dir(dir.as_str());
    }
    if let Ok(entries) = axfs::api::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if !name.bytes().all(|ch| ch.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name.parse::<u64>() else {
                continue;
            };
            if live_pids.iter().any(|live| *live == pid) {
                continue;
            }
            let dir = alloc::format!("/proc/{pid}");
            let _ = axfs::api::remove_dir(dir.as_str());
        }
    }
}

pub(crate) fn sync_proc_pid_entries_for_path(path: &str) {
    if path == "/proc" || path == "/proc/" {
        sync_proc_pid_root_dirs();
        return;
    }
    let Some(pid) = proc_pid_from_path(path) else {
        return;
    };
    if find_process_leader_by_pid(pid as usize).is_some() {
        let dir = alloc::format!("/proc/{pid}");
        let _ = axfs::api::create_dir(dir.as_str());
    } else {
        let dir = alloc::format!("/proc/{pid}");
        let _ = axfs::api::remove_dir(dir.as_str());
    }
}

#[cfg(target_arch = "loongarch64")]
fn should_loongarch_eager_private_fork_pages() -> bool {
    false
}

fn private_fork_low_memory_reserve_pages(aspace: &AddrSpace) -> usize {
    let stack_pages = user_task_kernel_stack_size() / PAGE_SIZE_4K;
    let mapped_pages = aspace.total_area_size().saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
    let leaf_pt_pages = mapped_pages.div_ceil(512).max(1);
    let upper_pt_pages = 4;
    let metadata_pages = aspace.area_count().saturating_mul(2);
    stack_pages
        .saturating_mul(2)
        .saturating_add(leaf_pt_pages.saturating_mul(2))
        .saturating_add(upper_pt_pages)
        .saturating_add(metadata_pages)
        .saturating_add(64)
        .clamp(96, 384)
}

fn should_log_private_fork_pressure() -> bool {
    let slot = PRIVATE_FORK_PRESSURE_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    slot <= 8 || slot.is_power_of_two()
}

fn should_reject_private_fork_for_low_memory(
    clone_flags: CloneFlags,
    aspace: &AddrSpace,
) -> bool {
    if clone_flags.contains(CloneFlags::CLONE_VM) || clone_flags.contains(CloneFlags::CLONE_VFORK) {
        return false;
    }

    let reserve_pages = private_fork_low_memory_reserve_pages(aspace);
    let deny_reserve_pages = reserve_pages.saturating_div(5).max(24);
    let mut available_pages = global_allocator().available_pages();
    let low_watermark = runtime_reclaim_low_watermark_pages();
    let reclaim_threshold = reserve_pages.saturating_mul(4).clamp(128, low_watermark.max(128));
    if available_pages <= reclaim_threshold {
        let stats = reclaim_runtime_memory_detail("private_fork_prepare");
        available_pages = global_allocator().available_pages();
        if available_pages > reclaim_threshold
            && (stats.stack_pages > 0
                || stats.exec_cache_pages > 0
                || stats.fs_cache_entries > 0)
        {
            debug!(
                "private fork reclaimed before clone: available_pages={} reclaim_threshold={} reserve_pages={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reclaimed_fs_cache_entries={}",
                available_pages,
                reclaim_threshold,
                reserve_pages,
                stats.stack_pages,
                stats.exec_cache_pages,
                stats.fs_cache_entries,
            );
        }
    }
    if available_pages >= deny_reserve_pages {
        return false;
    }

    let reclaimed_stack_pages = axtask::reclaim_task_stack_cache(0);
    let reclaimed_exec_cache_pages = crate::mm::reclaim_exec_caches();
    available_pages = global_allocator().available_pages();
    if available_pages >= deny_reserve_pages {
        debug!(
            "private fork resumed after reclaim: available_pages={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reserve_pages={} deny_reserve_pages={}",
            available_pages,
            reclaimed_stack_pages,
            reclaimed_exec_cache_pages,
            reserve_pages,
            deny_reserve_pages
        );
        return false;
    }

    if should_log_private_fork_pressure() {
        warn!(
            "private fork denied under memory pressure: available_pages={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reserve_pages={} deny_reserve_pages={} total_area_size={} area_count={}",
            available_pages,
            reclaimed_stack_pages,
            reclaimed_exec_cache_pages,
            reserve_pages,
            deny_reserve_pages,
            aspace.total_area_size(),
            aspace.area_count(),
        );
    }
    true
}

pub(crate) fn set_competition_fail_fast(enabled: bool) {
    COMPETITION_FAIL_FAST.store(enabled, Ordering::Relaxed);
}

pub(crate) fn set_competition_script_root(task: Option<AxTaskRef>) {
    let tagged_task = task.map(|task| {
        let tag = NEXT_COMPETITION_SCRIPT_TAG.fetch_add(1, Ordering::Relaxed);
        task.task_ext().set_competition_script_tag(tag);
        task
    });
    COMPETITION_ABORTING_SCRIPT_TAG.store(0, Ordering::Release);
    *competition_script_root().lock() = tagged_task;
}

pub(crate) fn register_live_task(task: &AxTaskRef) {
    live_tasks()
        .lock()
        .insert(task.id().as_u64(), Arc::downgrade(task));
    if task_is_process_leader(task) {
        process_leaders()
            .lock()
            .insert(task.task_ext().proc_id as u64, Arc::downgrade(task));
        ensure_proc_pid_entries(task.task_ext().proc_id as u64);
    }
}

pub(crate) fn unregister_live_task(task: &AxTaskRef) {
    live_tasks().lock().remove(&task.id().as_u64());
    if task_is_process_leader(task) {
        let pid = task.task_ext().proc_id as u64;
        let mut leaders = process_leaders().lock();
        let should_remove = leaders
            .get(&pid)
            .and_then(|leader| leader.upgrade())
            .is_none_or(|leader| leader.id().as_u64() == task.id().as_u64());
        if should_remove {
            leaders.remove(&pid);
        }
    }
}

pub(crate) fn register_zombie_process(zombie: ZombieProcess) {
    zombie_processes().lock().insert(zombie.pid, zombie);
}

pub(crate) fn unregister_zombie_process(pid: u64) {
    zombie_processes().lock().remove(&pid);
}

pub(crate) fn find_zombie_process_by_pid(pid: usize) -> Option<ZombieProcess> {
    zombie_processes().lock().get(&(pid as u64)).copied()
}

pub(crate) fn find_live_task_by_tid(tid: u64) -> Option<AxTaskRef> {
    let mut tasks = live_tasks().lock();
    let task = tasks
        .get(&tid)
        .and_then(|task| task.upgrade())
        .filter(task_is_live);
    if task.is_none() {
        tasks.remove(&tid);
    }
    task
}

pub(crate) fn find_process_leader_by_pid(pid: usize) -> Option<AxTaskRef> {
    let pid = pid as u64;
    let mut leaders = process_leaders().lock();
    let task = leaders.get(&pid).and_then(|task| task.upgrade());
    if task.as_ref().is_some_and(|task| {
        task_is_live(task) && task_is_process_leader(task) && task.task_ext().proc_id as u64 == pid
    }) {
        task
    } else {
        leaders.remove(&pid);
        None
    }
}

pub(crate) fn is_exec_path_in_use(path: &str) -> bool {
    let canonical_target = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    let mut stale = Vec::new();
    let mut in_use = false;
    {
        let tasks = live_tasks().lock();
        for (tid, task) in tasks.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task.state() == axtask::TaskState::Exited {
                continue;
            }
            let exec_path = task.task_ext().exec_path();
            let canonical_exec = axfs::api::canonicalize(exec_path.as_str()).unwrap_or(exec_path);
            if canonical_exec == canonical_target {
                in_use = true;
                break;
            }
        }
    }
    if !stale.is_empty() {
        let mut tasks = live_tasks().lock();
        for tid in stale {
            tasks.remove(&tid);
        }
    }
    in_use
}

pub(crate) fn is_path_open_for_write(path: &str) -> bool {
    let canonical_target = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    let mut stale = Vec::new();
    let mut in_use = false;
    {
        let tasks = live_tasks().lock();
        for (tid, task) in tasks.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task.state() == axtask::TaskState::Exited {
                continue;
            }

            let table = FD_TABLE.deref_from(&task.task_ext().ns).read();
            for (_, file) in table.iter() {
                let flags = file.status_flags() as u32;
                let access = flags & 0b11;
                let write_like = access != arceos_posix_api::ctypes::O_RDONLY
                    || (flags
                        & (arceos_posix_api::ctypes::O_TRUNC
                            | arceos_posix_api::ctypes::O_APPEND))
                        != 0;
                if !write_like {
                    continue;
                }
                let Ok(file) = file.clone().into_any().downcast::<arceos_posix_api::File>() else {
                    continue;
                };
                let canonical_file =
                    axfs::api::canonicalize(file.path()).unwrap_or_else(|_| file.path().to_string());
                if canonical_file == canonical_target {
                    in_use = true;
                    break;
                }
            }
            if in_use {
                break;
            }
        }
    }
    if !stale.is_empty() {
        let mut tasks = live_tasks().lock();
        for tid in stale {
            tasks.remove(&tid);
        }
    }
    in_use
}

pub(crate) fn thread_group_tasks(proc_id: usize) -> Vec<AxTaskRef> {
    let mut stale = Vec::new();
    let mut members = Vec::new();
    {
        let tasks = live_tasks().lock();
        for (tid, task) in tasks.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task_is_live(&task) && task.task_ext().proc_id == proc_id {
                members.push(task);
            }
        }
    }
    if !stale.is_empty() {
        let mut tasks = live_tasks().lock();
        for tid in stale {
            tasks.remove(&tid);
        }
    }
    members
}

pub(crate) fn process_leader_tasks() -> Vec<AxTaskRef> {
    let mut leaders = Vec::new();
    let mut stale = Vec::new();
    {
        let process_leaders = process_leaders().lock();
        for (pid, task) in process_leaders.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*pid);
                continue;
            };
            if task_is_live(&task)
                && task_is_process_leader(&task)
                && task.task_ext().proc_id as u64 == *pid
            {
                leaders.push(task);
            } else {
                stale.push(*pid);
            }
        }
    }
    if !stale.is_empty() {
        let mut process_leaders = process_leaders().lock();
        for pid in stale {
            process_leaders.remove(&pid);
        }
    }
    leaders
}

fn collect_task_tree_postorder(task: &AxTaskRef, tasks: &mut Vec<AxTaskRef>) {
    if tasks
        .iter()
        .any(|existing| existing.id().as_u64() == task.id().as_u64())
    {
        return;
    }

    let children = task.task_ext().children.lock().clone();
    for child in children {
        collect_task_tree_postorder(&child, tasks);
    }
    tasks.push(task.clone());
}

fn collect_live_tasks_with_script_tag(tag: u64, tasks: &mut Vec<AxTaskRef>) {
    if tag == 0 {
        return;
    }

    let mut stale = Vec::new();
    {
        let live = live_tasks().lock();
        for (tid, task) in live.iter() {
            let Some(task) = task.upgrade() else {
                stale.push(*tid);
                continue;
            };
            if task.task_ext().competition_script_tag() != tag {
                continue;
            }
            if tasks
                .iter()
                .any(|existing| existing.id().as_u64() == task.id().as_u64())
            {
                continue;
            }
            tasks.push(task);
        }
    }
    if !stale.is_empty() {
        let mut live = live_tasks().lock();
        for tid in stale {
            live.remove(&tid);
        }
    }
}

fn tagged_tasks_all_exited(tasks: &[AxTaskRef]) -> bool {
    tasks.iter()
        .all(|task| task.state() == axtask::TaskState::Exited)
}

fn kill_competition_script_tree_with_tag(expected_tag: Option<u64>, signum: usize) -> usize {
    let root = {
        let guard = competition_script_root().lock();
        guard.clone()
    };
    let Some(root) = root else {
        return 0;
    };

    let tag = root.task_ext().competition_script_tag();
    if let Some(expected_tag) = expected_tag {
        if tag != expected_tag {
            return 0;
        }
    }
    let mut tasks = Vec::new();
    collect_task_tree_postorder(&root, &mut tasks);
    collect_live_tasks_with_script_tag(tag, &mut tasks);
    for task in &tasks {
        if task.state() != axtask::TaskState::Exited {
            crate::signal::send_signal_to_task(task, signum);
        }
    }

    if root.state() == axtask::TaskState::Blocked {
        let _ = axtask::force_exit_task(&root, 128 + signum as i32);
    }

    for _ in 0..256 {
        if tagged_tasks_all_exited(&tasks) {
            break;
        }
        axtask::yield_now();
    }

    let mut forced = 0usize;
    for task in &tasks {
        if task.state() != axtask::TaskState::Exited
            && axtask::force_exit_task(task, 128 + signum as i32)
        {
            forced += 1;
        }
    }

    if forced > 0 {
        warn!(
            "Competition script cleanup escalated: tag={} signum={} forced_tasks={}",
            tag, signum, forced
        );
    }

    for _ in 0..256 {
        if tagged_tasks_all_exited(&tasks) {
            break;
        }
        axtask::yield_now();
    }

    if tagged_tasks_all_exited(&tasks) {
        set_competition_script_root(None);
    } else {
        let remaining = tasks
            .iter()
            .filter(|task| task.state() != axtask::TaskState::Exited)
            .count();
        warn!(
            "Competition script cleanup incomplete: tag={} signum={} remaining_tasks={}",
            tag, signum, remaining
        );
    }

    tasks.len()
}

pub(crate) fn kill_current_competition_script_tree(signum: usize) -> usize {
    kill_competition_script_tree_with_tag(None, signum)
}

pub(crate) fn competition_script_root_is_alive() -> bool {
    competition_script_root()
        .lock()
        .as_ref()
        .is_some_and(task_is_live)
}

fn wait_status_signal_number(status: i32) -> Option<usize> {
    let signum = (status & 0x7f) as usize;
    (signum != 0 && signum != 0x7f).then_some(signum)
}

fn signal_is_competition_fatal(signum: usize) -> bool {
    matches!(signum, 4 | 5 | 6 | 7 | 8 | 11 | 31)
}

fn current_is_competition_script_root() -> bool {
    let curr = current();
    let guard = competition_script_root().lock();
    let Some(root) = guard.as_ref() else {
        return false;
    };
    root.id().as_u64() == curr.id().as_u64()
        && root.task_ext().competition_script_tag() == curr.task_ext().competition_script_tag()
}

fn abort_competition_script_with_tag(
    tag: u64,
    signum: usize,
    reason: String,
    tid: u64,
    pid: usize,
    exec_path: String,
) -> bool {
    if tag == 0 {
        return false;
    }

    let root = {
        let guard = competition_script_root().lock();
        guard.clone()
    };
    let Some(root) = root else {
        return false;
    };
    if root.task_ext().competition_script_tag() != tag {
        return false;
    }

    if COMPETITION_ABORTING_SCRIPT_TAG
        .compare_exchange(0, tag, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }

    if let Some(task) = TaskInner::try_new(
        {
            let reason = reason.clone();
            let exec_path = exec_path.clone();
            move || {
                warn!(
                    "Competition script abort triggered: reason={} signum={} tid={} pid={} exec_path={} tag={}",
                    reason, signum, tid, pid, exec_path, tag,
                );
                axtask::yield_now();
                let killed = kill_competition_script_tree_with_tag(Some(tag), signum);
                warn!(
                    "Competition script abort cleanup complete: reason={} signum={} tag={} killed_tasks={}",
                    reason, signum, tag, killed,
                );
                COMPETITION_ABORTING_SCRIPT_TAG.store(0, Ordering::Release);
            }
        },
        "competition-abort".into(),
        axconfig::TASK_STACK_SIZE,
    ) {
        let _ = axtask::spawn_task(task);
    } else {
        warn!(
            "Competition script abort fallback to inline cleanup: signum={} pid={} tag={}",
            signum, pid, tag
        );
        let _ = reclaim_runtime_memory("competition_abort");
        warn!(
            "Competition script abort triggered: reason={} signum={} tid={} pid={} exec_path={} tag={}",
            reason, signum, tid, pid, exec_path, tag,
        );
        axtask::yield_now();
        let killed = kill_competition_script_tree_with_tag(Some(tag), signum);
        warn!(
            "Competition script abort cleanup complete: reason={} signum={} tag={} killed_tasks={}",
            reason, signum, tag, killed,
        );
        COMPETITION_ABORTING_SCRIPT_TAG.store(0, Ordering::Release);
    }
    true
}

pub(crate) fn abort_current_competition_script(signum: usize, reason: &str) -> bool {
    let curr = current();
    abort_competition_script_with_tag(
        curr.task_ext().competition_script_tag(),
        signum,
        reason.to_string(),
        curr.id().as_u64(),
        curr.task_ext().proc_id,
        curr.task_ext().exec_path(),
    )
}

pub(crate) fn maybe_abort_current_competition_script_on_fatal_signal(status: i32) {
    if !current_is_competition_script_root() {
        return;
    }
    let Some(signum) = wait_status_signal_number(status) else {
        return;
    };
    if !signal_is_competition_fatal(signum) {
        return;
    }

    let curr = current();
    let exec_path = curr.task_ext().exec_path();
    let tid = curr.id().as_u64();
    let pid = curr.task_ext().proc_id;
    let _ = abort_competition_script_with_tag(
        curr.task_ext().competition_script_tag(),
        9,
        alloc::format!("fatal-signal-{signum}"),
        tid,
        pid,
        exec_path,
    );
}

pub(crate) fn maybe_terminate_on_exec_failure(path: &str, err: &AxError) {
    if !COMPETITION_FAIL_FAST.load(Ordering::Relaxed) || !matches!(err, AxError::NotFound) {
        return;
    }

    error!(
        "Competition fail-fast triggered: path={} cwd={:?} err={:?}",
        path,
        axfs::api::current_dir().ok(),
        err
    );
    crate::diag::print_competition_layout_snapshot();
    axhal::misc::terminate();
}

/// Task extended data for the monolithic kernel.
pub struct TaskExt {
    /// The process ID.
    pub proc_id: usize,
    /// The thread ID of the process leader.
    leader_tid: AtomicU64,
    /// The parent process ID.
    pub parent_id: AtomicU64,
    /// The process group ID.
    pub process_group_id: AtomicU64,
    /// The session ID.
    pub session_id: AtomicU64,
    /// children process
    pub children: Mutex<Vec<AxTaskRef>>,
    /// exited children waiting to be collected by wait/waitpid
    pub zombie_children: Mutex<Vec<ZombieChild>>,
    /// waiters blocked in wait/waitpid for child exit changes
    pub child_exit_wq: WaitQueue,
    /// monotonic sequence for child wait-visible events
    child_wait_event_seq: AtomicU64,
    /// whether the task is currently stopped by a default-action stop signal
    wait_stopped: AtomicBool,
    /// last stop signal reported to the parent
    wait_stop_signal: AtomicU64,
    /// whether a stop event is pending for wait/waitid
    wait_stop_pending: AtomicBool,
    /// whether a continued event is pending for wait/waitid
    wait_continue_pending: AtomicBool,
    /// wait queue used while the task is stopped
    pub stop_wq: WaitQueue,
    /// Weak reference to the parent task.
    parent_task: Mutex<Option<WeakAxTaskRef>>,
    /// The clear thread tid field
    ///
    /// See <https://manpages.debian.org/unstable/manpages-dev/set_tid_address.2.en.html#clear_child_tid>
    ///
    /// When the thread exits, the kernel clears the word at this address if it is not NULL.
    clear_child_tid: AtomicU64,
    /// Whether a vfork-style child has finished the blocking phase.
    vfork_done: AtomicBool,
    /// Waiters blocked for a vfork child to exec/exit.
    vfork_wait_wq: WaitQueue,
    /// Whether this task is a vfork child still sharing its parent's address space.
    is_vfork_child: AtomicBool,
    /// The user space context.
    pub uctx: UspaceContext,
    /// The virtual memory address space.
    pub aspace: Arc<Mutex<AddrSpace>>,
    /// The resource namespace
    pub ns: AxNamespace,
    /// The time statistics
    pub time: UnsafeCell<TimeStat>,
    /// Signal handling state
    pub signals: Mutex<SignalState>,
    /// The user heap bottom
    pub heap_bottom: AtomicU64,
    /// The user heap top
    pub heap_top: AtomicU64,
    /// The base address used to map the main executable image.
    exec_image_base: AtomicU64,
    /// The process umask.
    pub umask: AtomicU64,
    /// Per-netns sysctl /proc/sys/net/ipv4/conf/lo/tag
    netns_lo_tag: AtomicI32,
    /// Per-netns sysctl /proc/sys/net/ipv4/conf/default/tag
    netns_default_tag: AtomicI32,
    /// Current task's active CLOCK_MONOTONIC namespace offset.
    time_ns_monotonic_offset_ns: AtomicI64,
    /// Current task's active CLOCK_BOOTTIME namespace offset.
    time_ns_boottime_offset_ns: AtomicI64,
    /// Pending child CLOCK_MONOTONIC namespace offset after unshare(CLONE_NEWTIME).
    time_ns_children_monotonic_offset_ns: AtomicI64,
    /// Pending child CLOCK_BOOTTIME namespace offset after unshare(CLONE_NEWTIME).
    time_ns_children_boottime_offset_ns: AtomicI64,
    /// Whether children should enter a distinct time namespace.
    time_ns_for_children_isolated: AtomicBool,
    /// The current scheduling policy.
    schedule_policy: AtomicU64,
    /// The current scheduling priority.
    schedule_priority: AtomicU64,
    /// The current per-thread nice value.
    nice: AtomicI32,
    /// Whether scheduling state resets across fork.
    schedule_reset_on_fork: AtomicBool,
    /// SCHED_DEADLINE runtime in nanoseconds.
    schedule_runtime: AtomicU64,
    /// SCHED_DEADLINE deadline in nanoseconds.
    schedule_deadline: AtomicU64,
    /// SCHED_DEADLINE period in nanoseconds.
    schedule_period: AtomicU64,
    /// The executable path of the current process.
    exec_path: Mutex<String>,
    competition_script_tag: AtomicU64,
    robust_list_head: AtomicU64,
    robust_list_len: AtomicU64,
    exit_signal: AtomicU64,
    personality: AtomicU64,
    io_context_id: AtomicU64,
    sysvsem_id: AtomicU64,
    start_wall_time_sec: AtomicU64,
    start_monotonic_ns: AtomicU64,
}

#[derive(Clone, Copy)]
pub(crate) struct ZombieChild {
    pub pid: u64,
    pub process_group: u64,
    pub wait_status: i32,
}

#[derive(Clone, Copy)]
pub(crate) struct ZombieProcess {
    pub pid: u64,
    pub process_group: u64,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
}

#[derive(Clone, Copy)]
pub(crate) enum WaitChildSelector {
    Any,
    Pid(u64),
    ProcessGroup(u64),
}

impl TaskExt {
    pub fn new(
        proc_id: usize,
        leader_tid: u64,
        uctx: UspaceContext,
        aspace: Arc<Mutex<AddrSpace>>,
        heap_bottom: u64,
        exec_image_base: u64,
        exec_path: String,
    ) -> Self {
        Self {
            start_wall_time_sec: AtomicU64::new(axhal::time::wall_time().as_secs()),
            start_monotonic_ns: AtomicU64::new(monotonic_time_nanos() as u64),
            proc_id,
            leader_tid: AtomicU64::new(leader_tid),
            parent_id: AtomicU64::new(1),
            process_group_id: AtomicU64::new(proc_id as u64),
            session_id: AtomicU64::new(proc_id as u64),
            children: Mutex::new(Vec::new()),
            zombie_children: Mutex::new(Vec::new()),
            child_exit_wq: WaitQueue::new(),
            child_wait_event_seq: AtomicU64::new(0),
            wait_stopped: AtomicBool::new(false),
            wait_stop_signal: AtomicU64::new(0),
            wait_stop_pending: AtomicBool::new(false),
            wait_continue_pending: AtomicBool::new(false),
            stop_wq: WaitQueue::new(),
            parent_task: Mutex::new(None),
            uctx,
            clear_child_tid: AtomicU64::new(0),
            vfork_done: AtomicBool::new(true),
            vfork_wait_wq: WaitQueue::new(),
            is_vfork_child: AtomicBool::new(false),
            aspace,
            ns: AxNamespace::new_thread_local(),
            time: TimeStat::new().into(),
            signals: Mutex::new(SignalState::new()),
            heap_bottom: AtomicU64::new(heap_bottom),
            heap_top: AtomicU64::new(heap_bottom),
            exec_image_base: AtomicU64::new(exec_image_base),
            umask: AtomicU64::new(0o022),
            netns_lo_tag: AtomicI32::new(0),
            netns_default_tag: AtomicI32::new(0),
            time_ns_monotonic_offset_ns: AtomicI64::new(0),
            time_ns_boottime_offset_ns: AtomicI64::new(0),
            time_ns_children_monotonic_offset_ns: AtomicI64::new(0),
            time_ns_children_boottime_offset_ns: AtomicI64::new(0),
            time_ns_for_children_isolated: AtomicBool::new(false),
            schedule_policy: AtomicU64::new(0),
            schedule_priority: AtomicU64::new(0),
            nice: AtomicI32::new(0),
            schedule_reset_on_fork: AtomicBool::new(false),
            schedule_runtime: AtomicU64::new(0),
            schedule_deadline: AtomicU64::new(0),
            schedule_period: AtomicU64::new(0),
            exec_path: Mutex::new(exec_path),
            competition_script_tag: AtomicU64::new(0),
            robust_list_head: AtomicU64::new(0),
            robust_list_len: AtomicU64::new(0),
            exit_signal: AtomicU64::new(17),
            personality: AtomicU64::new(0),
            io_context_id: AtomicU64::new(proc_id as u64),
            sysvsem_id: AtomicU64::new(proc_id as u64),
        }
    }

    pub fn clone_task(
        &self,
        trap_frame: &TrapFrame,
        flags: usize,
        stack: Option<usize>,
        ptid: usize,
        tls: usize,
        ctid: usize,
    ) -> AxResult<u64> {
        let clone_flags = CloneFlags::from_bits_truncate((flags & !0x3f) as u32);
        #[cfg(target_arch = "riscv64")]
        let trace_clone08 = should_trace_clone08() && current().name().contains("clone08");
        let trace_fork13 = false;
        debug!(
            "clone_task raw_flags={:#x} parsed_flags={:?} stack={:?}",
            flags, clone_flags, stack
        );
        if trace_fork13 {
            warn!(
                "[fork13-clone-task] enter task={} pid={} flags={:#x} parsed={:?} stack={:?} ptid={:#x} tls={:#x} ctid={:#x}",
                current().id_name(),
                current().task_ext().proc_id,
                flags,
                clone_flags,
                stack,
                ptid,
                tls,
                ctid,
            );
        }
        let child_task_name = current().name().to_string();
        {
            let current_task = current();
            let current_aspace = current_task.task_ext().aspace.lock();
            if should_reject_private_fork_for_low_memory(clone_flags, &current_aspace) {
                return Err(AxError::NoMemory);
            }
        }
        let user_stack_size = user_task_kernel_stack_size();
        let make_task = || {
            TaskInner::try_new(
                || {
                    let curr = axtask::current();
                    let kstack_top = curr.kernel_stack_top().unwrap();
                    #[cfg(target_arch = "riscv64")]
                    if should_trace_clone08() && curr.name().contains("clone08") {
                        let tf = curr.task_ext().uctx.trap_frame();
                        let ip_start = tf.get_ip().saturating_sub(16);
                        let mut ip_bytes = [0u8; 32];
                        let ip_bytes_ok = curr
                            .task_ext()
                            .aspace
                            .lock()
                            .read(VirtAddr::from_usize(ip_start), ip_bytes.as_mut_slice())
                            .is_ok();
                        warn!(
                            "clone08 child enter_uspace task={} pid={} ip={:#x} sp={:#x} ra={:#x} gp={:#x} tp={:#x} s0={:#x} s1={:#x} s2={:#x} s3={:#x} ip_start={:#x} ip_bytes_ok={} ip_bytes={:02x?}",
                            curr.id_name(),
                            curr.task_ext().proc_id,
                            tf.get_ip(),
                            tf.get_sp(),
                            tf.regs.ra,
                            tf.regs.gp,
                            tf.regs.tp,
                            tf.regs.s0,
                            tf.regs.s1,
                            tf.regs.s2,
                            tf.regs.s3,
                            ip_start,
                            ip_bytes_ok,
                            ip_bytes,
                        );
                    }
                    info!(
                        "Enter user space: entry={:#x}, ustack={:#x}, kstack={:#x}",
                        curr.task_ext().uctx.get_ip(),
                        curr.task_ext().uctx.get_sp(),
                        kstack_top,
                    );
                    unsafe { curr.task_ext().uctx.enter_uspace(kstack_top) };
                },
                child_task_name.clone(),
                user_stack_size,
            )
        };
        let mut new_task = match make_task() {
            Some(task) => task,
            None => {
                let (reclaimed_stack_pages, reclaimed_exec_cache_pages) =
                    reclaim_runtime_memory("clone_task");
                if should_log_task_alloc_pressure() {
                    warn!(
                        "retry clone task alloc after reclaim: child_name={} stack_size={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} available_pages={}",
                        child_task_name,
                        user_stack_size,
                        reclaimed_stack_pages,
                        reclaimed_exec_cache_pages,
                        global_allocator().available_pages(),
                    );
                }
                make_task().ok_or(AxError::NoMemory)?
            }
        };
        let current_task = current();
        let mut current_aspace = current_task.task_ext().aspace.lock();
        let current_heap_bottom = current_task.task_ext().get_heap_bottom();
        let current_heap_top = current_task.task_ext().get_heap_top();
        let share_vm = clone_flags.contains(CloneFlags::CLONE_VM);
        #[cfg(target_arch = "loongarch64")]
        let force_deep_copy = !share_vm
            && !clone_flags.contains(CloneFlags::CLONE_VFORK)
            && should_loongarch_eager_private_fork_pages();
        #[cfg(not(target_arch = "loongarch64"))]
        let force_deep_copy = false;
        let share_aspace = share_vm && !force_deep_copy;
        let (new_aspace, new_page_table_root) = if share_aspace {
            (
                Arc::clone(&current_task.task_ext().aspace),
                current_aspace.page_table_root(),
            )
        } else {
            #[cfg(target_arch = "loongarch64")]
            {
                let private_fork_commit_limit =
                    axconfig::plat::PHYS_MEMORY_SIZE.saturating_mul(64);
                if !clone_flags.contains(CloneFlags::CLONE_VFORK)
                    && current_aspace.total_area_size() > private_fork_commit_limit
                {
                    return Err(AxError::NoMemory);
                }
            }
            let new_aspace = current_aspace.clone_or_err(force_deep_copy)?;
            let new_page_table_root = new_aspace.page_table_root();
            (Arc::new(Mutex::new(new_aspace)), new_page_table_root)
        };
        new_task.ctx_mut().set_page_table_root(new_page_table_root);

        #[cfg(target_arch = "riscv64")]
        let mut private_tp = None;
        #[cfg(target_arch = "riscv64")]
        if share_aspace
            && !clone_flags.contains(CloneFlags::CLONE_THREAD)
            && !clone_flags.contains(CloneFlags::CLONE_SETTLS)
        {
            let old_tp = trap_frame.regs.tp as usize;
            if old_tp != 0 {
                let old_tp_va = VirtAddr::from_usize(old_tp);
                let old_page = old_tp_va.align_down_4k();
                let tp_offset = old_tp_va.as_usize() - old_page.as_usize();
                let mut page = [0u8; PAGE_SIZE_4K];
                if current_aspace.read(old_page, &mut page).is_ok() {
                    let mut old_dtv = 0usize;
                    let mut old_dtv_bytes = [0u8; core::mem::size_of::<usize>()];
                    let _ = current_aspace.read(
                        VirtAddr::from_usize(old_tp - RISCV_MUSL_DTV_PTR_OFFSET_FROM_TP),
                        &mut old_dtv_bytes,
                    );
                    old_dtv = usize::from_ne_bytes(old_dtv_bytes);
                    let build_private_tp =
                        |target_aspace: &mut AddrSpace| -> AxResult<Option<usize>> {
                            let limit = VirtAddrRange::from_start_size(
                                target_aspace.base(),
                                target_aspace.size(),
                            );
                            let hint = (old_page + PAGE_SIZE_4K).align_up_4k();
                            let Some(new_page) =
                                target_aspace.find_free_area(hint, PAGE_SIZE_4K, limit)
                            else {
                                return Ok(None);
                            };

                            target_aspace.map_alloc(
                                new_page,
                                PAGE_SIZE_4K,
                                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                                false,
                            )?;
                            target_aspace.alloc_for_lazy(new_page, PAGE_SIZE_4K)?;
                            target_aspace.write(new_page, &page)?;

                            let new_td = new_page.as_usize() + tp_offset - RISCV_MUSL_PTHREAD_SIZE;
                            let new_tp = new_page.as_usize() + tp_offset;
                            let new_robust_head = new_td + RISCV_MUSL_ROBUST_HEAD_OFFSET;
                            let new_dtv = if (old_page.as_usize()
                                ..old_page.as_usize() + PAGE_SIZE_4K)
                                .contains(&old_dtv)
                            {
                                new_page.as_usize() + (old_dtv - old_page.as_usize())
                            } else {
                                old_dtv
                            };

                            target_aspace.write(
                                VirtAddr::from_usize(new_td + RISCV_MUSL_SELF_OFFSET),
                                &new_td.to_ne_bytes(),
                            )?;
                            target_aspace.write(
                                VirtAddr::from_usize(new_td + RISCV_MUSL_PREV_OFFSET),
                                &new_td.to_ne_bytes(),
                            )?;
                            target_aspace.write(
                                VirtAddr::from_usize(new_td + RISCV_MUSL_NEXT_OFFSET),
                                &new_td.to_ne_bytes(),
                            )?;
                            target_aspace.write(
                                VirtAddr::from_usize(new_td + RISCV_MUSL_TID_OFFSET),
                                &0i32.to_ne_bytes(),
                            )?;
                            target_aspace.write(
                                VirtAddr::from_usize(new_td + RISCV_MUSL_ROBUST_HEAD_OFFSET),
                                &new_robust_head.to_ne_bytes(),
                            )?;
                            target_aspace.write(
                                VirtAddr::from_usize(new_tp - RISCV_MUSL_DTV_PTR_OFFSET_FROM_TP),
                                &new_dtv.to_ne_bytes(),
                            )?;
                            Ok(Some(new_tp))
                        };

                    if share_aspace {
                        private_tp = build_private_tp(&mut current_aspace)?;
                    } else {
                        private_tp = build_private_tp(&mut new_aspace.lock())?;
                    }
                }
            }
        }

        let mut new_uctx = UspaceContext::from(trap_frame);
        if let Some(stack) = stack {
            new_uctx.set_sp(stack);
        }
        if clone_flags.contains(CloneFlags::CLONE_SETTLS) && tls != 0 {
            new_uctx.set_thread_pointer(tls);
        } else {
            #[cfg(target_arch = "riscv64")]
            if let Some(tp) = private_tp {
                new_uctx.set_thread_pointer(tp);
            }
        }
        // Skip current instruction
        new_uctx.set_ip(new_uctx.get_ip() + 4);
        new_uctx.set_retval(0);
        #[cfg(target_arch = "riscv64")]
        if !share_aspace && !clone_flags.contains(CloneFlags::CLONE_THREAD) {
            let child_tf = *new_uctx.trap_frame();
            let mut child_aspace = new_aspace.lock();
            let mut warm_page = |addr: usize, access: MappingFlags| {
                if addr == 0 {
                    return;
                }
                let vaddr = VirtAddr::from_usize(addr);
                if child_aspace.contains_range(vaddr, 1) {
                    let _ = child_aspace.handle_page_fault(vaddr, access | MappingFlags::USER);
                }
            };
            warm_page(child_tf.get_ip(), MappingFlags::EXECUTE);
            warm_page(child_tf.regs.gp, MappingFlags::READ);
            warm_page(child_tf.regs.tp, MappingFlags::READ | MappingFlags::WRITE);
            warm_page(
                child_tf.get_sp().saturating_sub(core::mem::size_of::<usize>()),
                MappingFlags::WRITE,
            );
        }
        drop(current_aspace);
        #[cfg(target_arch = "riscv64")]
        if trace_clone08 {
            warn!(
                "clone08 clone_task parent task={} pid={} raw_flags={:#x} child_ip={:#x} child_sp={:#x} parent_ra={:#x} parent_gp={:#x} parent_tp={:#x} parent_s0={:#x} parent_s1={:#x} parent_s2={:#x} child_ra={:#x} child_gp={:#x} child_tp={:#x} child_s0={:#x} child_s1={:#x} child_s2={:#x}",
                current_task.id_name(),
                current_task.task_ext().proc_id,
                flags,
                new_uctx.get_ip(),
                new_uctx.get_sp(),
                trap_frame.regs.ra,
                trap_frame.regs.gp,
                trap_frame.regs.tp,
                trap_frame.regs.s0,
                trap_frame.regs.s1,
                trap_frame.regs.s2,
                new_uctx.trap_frame().regs.ra,
                new_uctx.trap_frame().regs.gp,
                new_uctx.trap_frame().regs.tp,
                new_uctx.trap_frame().regs.s0,
                new_uctx.trap_frame().regs.s1,
                new_uctx.trap_frame().regs.s2,
            );
        }
        let return_id: u64 = new_task.id().as_u64();
        let new_proc_id = if clone_flags.contains(CloneFlags::CLONE_THREAD) {
            self.proc_id
        } else {
            allocate_process_id()
        };
        let child_visible_tid = if clone_flags.contains(CloneFlags::CLONE_THREAD) {
            return_id
        } else {
            new_proc_id as u64
        };
        let new_leader_tid = if clone_flags.contains(CloneFlags::CLONE_THREAD) {
            self.leader_tid()
        } else {
            return_id
        };
        #[cfg(target_arch = "riscv64")]
        if let Some(tp) = private_tp {
            let td_base = tp
                .checked_sub(RISCV_MUSL_PTHREAD_SIZE)
                .ok_or(AxError::BadAddress)?;
            let child_tid = child_visible_tid as i32;
            new_aspace
                .lock()
                .write(
                    VirtAddr::from_usize(td_base + RISCV_MUSL_TID_OFFSET),
                    &child_tid.to_ne_bytes(),
                )
                .map_err(|_| AxError::BadAddress)?;
        }
        let new_task_ext = TaskExt::new(
            new_proc_id,
            new_leader_tid,
            new_uctx,
            new_aspace,
            current_heap_bottom,
            self.exec_image_base(),
            self.exec_path(),
        );
        if trace_fork13 {
            warn!(
                "[fork13-clone-task] child ids return_tid={} new_proc_id={} child_visible_tid={} leader_tid={} share_aspace={}",
                return_id,
                new_proc_id,
                child_visible_tid,
                new_leader_tid,
                share_aspace,
            );
        }
        new_task_ext.set_exit_signal((flags & 0x3f) as u64);
        new_task_ext.set_heap_top(current_heap_top);
        new_task_ext.set_process_group(self.process_group());
        new_task_ext.set_session(self.session());
        new_task_ext.set_personality(self.personality());
        new_task_ext.set_io_context_id(if clone_flags.contains(CloneFlags::CLONE_IO) {
            self.io_context_id()
        } else {
            new_proc_id as u64
        });
        new_task_ext.set_sysvsem_id(if clone_flags.contains(CloneFlags::CLONE_SYSVSEM) {
            self.sysvsem_id()
        } else {
            new_proc_id as u64
        });
        new_task_ext.set_competition_script_tag(self.competition_script_tag());
        if !clone_flags.contains(CloneFlags::CLONE_THREAD) && self.schedule_reset_on_fork() {
            new_task_ext.set_sched_state(0, 0, false);
            new_task_ext.set_sched_deadline(0, 0, 0);
        } else {
            new_task_ext.set_sched_state(
                self.schedule_policy(),
                self.schedule_priority(),
                self.schedule_reset_on_fork(),
            );
            new_task_ext.set_sched_deadline(
                self.schedule_runtime(),
                self.schedule_deadline(),
                self.schedule_period(),
            );
        }
        new_task_ext.set_nice(self.nice());
        if clone_flags.contains(CloneFlags::CLONE_CHILD_CLEARTID) {
            new_task_ext.set_clear_child_tid(ctid as u64);
        }
        {
            let parent_signals = self.signals.lock().clone();
            *new_task_ext.signals.lock() = SignalState::fork_from_parent(
                &parent_signals,
                clone_flags.contains(CloneFlags::CLONE_SIGHAND),
            );
        }
        let parent_id = if clone_flags.contains(CloneFlags::CLONE_PARENT)
            || clone_flags.contains(CloneFlags::CLONE_THREAD)
        {
            self.get_parent()
        } else {
            current_task.task_ext().proc_id as u64
        };
        let parent_task = if clone_flags.contains(CloneFlags::CLONE_THREAD) {
            Some(Arc::downgrade(current_task.as_task_ref()))
        } else if clone_flags.contains(CloneFlags::CLONE_PARENT) {
            self.parent_task.lock().clone()
        } else {
            Some(Arc::downgrade(current_task.as_task_ref()))
        };
        new_task_ext.set_parent(parent_id);
        new_task_ext.set_parent_task(parent_task);
        new_task_ext
            .umask
            .store(self.umask.load(Ordering::Acquire), Ordering::Release);
        if clone_flags.contains(CloneFlags::CLONE_VFORK) {
            new_task_ext.vfork_done.store(false, Ordering::Release);
            new_task_ext.is_vfork_child.store(true, Ordering::Release);
        }
        new_task_ext.ns_init_clone_from(
            clone_flags.contains(CloneFlags::CLONE_FILES),
            clone_flags.contains(CloneFlags::CLONE_FS),
        );
        let (child_mono_offset_ns, child_boot_offset_ns) =
            if clone_flags.contains(CloneFlags::CLONE_NEWTIME) {
                self.child_time_ns_offsets()
            } else {
                self.child_time_ns_offsets()
            };
        new_task_ext.set_active_time_ns_offsets(child_mono_offset_ns, child_boot_offset_ns);
        new_task_ext.reset_child_time_namespace();
        if !clone_flags.contains(CloneFlags::CLONE_THREAD) {
            crate::syscall_imp::clone_sysv_shm_process(self.proc_id, new_proc_id);
        }
        let parent_default_net_tag = *PROC_NET_IPV4_CONF_DEFAULT_TAG.lock();
        if clone_flags.contains(CloneFlags::CLONE_NEWNET) {
            PROC_NET_IPV4_CONF_DEFAULT_TAG
                .deref_from(&new_task_ext.ns)
                .init_new(Mutex::new(parent_default_net_tag));
            PROC_NET_IPV4_CONF_LO_TAG
                .deref_from(&new_task_ext.ns)
                .init_new(Mutex::new(parent_default_net_tag));
        } else {
            PROC_NET_IPV4_CONF_DEFAULT_TAG
                .deref_from(&new_task_ext.ns)
                .init_shared(PROC_NET_IPV4_CONF_DEFAULT_TAG.share());
            PROC_NET_IPV4_CONF_LO_TAG
                .deref_from(&new_task_ext.ns)
                .init_shared(PROC_NET_IPV4_CONF_LO_TAG.share());
        }
        if clone_flags.contains(CloneFlags::CLONE_PARENT_SETTID) && ptid != 0 {
            write_value_to_user(ptid as *mut i32, child_visible_tid as i32)
                .map_err(|_| AxError::BadAddress)?;
        }
        if clone_flags.contains(CloneFlags::CLONE_CHILD_SETTID) && ctid != 0 {
            let value = (child_visible_tid as i32).to_ne_bytes();
            new_task_ext
                .aspace
                .lock()
                .write(VirtAddr::from_usize(ctid), &value)
                .map_err(|_| AxError::BadAddress)?;
        }
        new_task.init_task_ext(new_task_ext);
        let new_task_ref = axtask::spawn_task(new_task);
        register_live_task(&new_task_ref);
        let desired_priority = new_task_ref.task_ext().scheduler_class_priority() as isize;
        if desired_priority != 0 {
            let _ = axtask::set_task_priority(&new_task_ref, desired_priority);
        }
        let desired_time_slice = new_task_ref.task_ext().scheduler_class_time_slice();
        if desired_time_slice != 5 {
            let _ = axtask::set_task_time_slice(&new_task_ref, desired_time_slice);
        }
        if clone_flags.contains(CloneFlags::CLONE_THREAD) && self.exec_path().contains("nice05") {
            warn!(
                "[nice05-diag] clone_thread parent_tid={} parent_pid={} child_tid={} child_pid={} child_nice={} child_sched_prio={}",
                current_task.id().as_u64(),
                current_task.task_ext().proc_id,
                new_task_ref.id().as_u64(),
                new_task_ref.task_ext().proc_id,
                new_task_ref.task_ext().nice(),
                new_task_ref.task_ext().scheduler_class_priority(),
            );
        }
        if !clone_flags.contains(CloneFlags::CLONE_THREAD) {
            let child_parent = new_task_ref.task_ext().parent_task();
            if let Some(parent) = child_parent.as_ref() {
                parent.task_ext().children.lock().push(new_task_ref.clone());
            } else {
                current_task
                    .task_ext()
                    .children
                    .lock()
                    .push(new_task_ref.clone());
            }
        }
        if clone_flags.contains(CloneFlags::CLONE_VFORK) {
            let child = new_task_ref.clone();
            child.task_ext().vfork_wait_wq.wait_until(|| {
                child.task_ext().vfork_done.load(Ordering::Acquire)
                    || child.state() == axtask::TaskState::Exited
            });
        }
        Ok(child_visible_tid)
    }

    pub(crate) fn clear_child_tid(&self) -> u64 {
        self.clear_child_tid
            .load(core::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn set_clear_child_tid(&self, clear_child_tid: u64) {
        self.clear_child_tid
            .store(clear_child_tid, core::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn get_parent(&self) -> u64 {
        self.parent_id.load(Ordering::Acquire)
    }

    pub(crate) fn leader_tid(&self) -> u64 {
        self.leader_tid.load(Ordering::Acquire)
    }

    pub(crate) fn complete_vfork(&self) {
        self.vfork_done.store(true, Ordering::Release);
        self.vfork_wait_wq.notify_all(false);
    }

    pub(crate) fn process_group(&self) -> u64 {
        self.process_group_id.load(Ordering::Acquire)
    }

    pub(crate) fn set_process_group(&self, pgid: u64) {
        self.process_group_id.store(pgid, Ordering::Release);
    }

    pub(crate) fn session(&self) -> u64 {
        self.session_id.load(Ordering::Acquire)
    }

    pub(crate) fn set_session(&self, sid: u64) {
        self.session_id.store(sid, Ordering::Release);
    }

    pub(crate) fn competition_script_tag(&self) -> u64 {
        self.competition_script_tag.load(Ordering::Acquire)
    }

    pub(crate) fn set_competition_script_tag(&self, tag: u64) {
        self.competition_script_tag.store(tag, Ordering::Release);
    }

    pub(crate) fn personality(&self) -> u32 {
        self.personality.load(Ordering::Acquire) as u32
    }

    pub(crate) fn set_personality(&self, personality: u32) {
        self.personality
            .store(personality as u64, Ordering::Release);
    }

    pub(crate) fn io_context_id(&self) -> u64 {
        self.io_context_id.load(Ordering::Acquire)
    }

    pub(crate) fn set_io_context_id(&self, id: u64) {
        self.io_context_id.store(id, Ordering::Release);
    }

    pub(crate) fn sysvsem_id(&self) -> u64 {
        self.sysvsem_id.load(Ordering::Acquire)
    }

    pub(crate) fn set_sysvsem_id(&self, id: u64) {
        self.sysvsem_id.store(id, Ordering::Release);
    }

    pub(crate) fn schedule_policy(&self) -> i32 {
        self.schedule_policy.load(Ordering::Acquire) as i32
    }

    pub(crate) fn schedule_priority(&self) -> i32 {
        self.schedule_priority.load(Ordering::Acquire) as i32
    }

    pub(crate) fn schedule_reset_on_fork(&self) -> bool {
        self.schedule_reset_on_fork.load(Ordering::Acquire)
    }

    pub(crate) fn schedule_runtime(&self) -> u64 {
        self.schedule_runtime.load(Ordering::Acquire)
    }

    pub(crate) fn schedule_deadline(&self) -> u64 {
        self.schedule_deadline.load(Ordering::Acquire)
    }

    pub(crate) fn schedule_period(&self) -> u64 {
        self.schedule_period.load(Ordering::Acquire)
    }

    pub(crate) fn scheduler_class_priority(&self) -> i32 {
        match self.schedule_policy() {
            1 | 2 => self.schedule_priority(),
            _ => 0,
        }
    }

    pub(crate) fn scheduler_class_time_slice(&self) -> usize {
        match self.schedule_policy() {
            1 | 2 => 5,
            _ => (5 - self.nice()).clamp(1, 25) as usize,
        }
    }

    pub(crate) fn nice(&self) -> i32 {
        self.nice.load(Ordering::Acquire)
    }

    pub(crate) fn set_nice(&self, nice: i32) {
        self.nice.store(nice, Ordering::Release);
    }

    pub(crate) fn set_sched_state(&self, policy: i32, priority: i32, reset_on_fork: bool) {
        self.schedule_policy.store(policy as u64, Ordering::Release);
        self.schedule_priority
            .store(priority as u64, Ordering::Release);
        self.schedule_reset_on_fork
            .store(reset_on_fork, Ordering::Release);
    }

    pub(crate) fn set_sched_deadline(&self, runtime: u64, deadline: u64, period: u64) {
        self.schedule_runtime.store(runtime, Ordering::Release);
        self.schedule_deadline.store(deadline, Ordering::Release);
        self.schedule_period.store(period, Ordering::Release);
    }

    pub(crate) fn parent_task(&self) -> Option<AxTaskRef> {
        self.parent_task
            .lock()
            .as_ref()
            .and_then(|parent| parent.upgrade())
    }

    pub(crate) fn wait_is_stopped(&self) -> bool {
        self.wait_stopped.load(Ordering::Acquire)
    }

    pub(crate) fn wait_stop_signal(&self) -> i32 {
        self.wait_stop_signal.load(Ordering::Acquire) as i32
    }

    pub(crate) fn wait_stop_pending(&self) -> bool {
        self.wait_stop_pending.load(Ordering::Acquire)
    }

    pub(crate) fn child_wait_event_seq(&self) -> u64 {
        self.child_wait_event_seq.load(Ordering::Acquire)
    }

    pub(crate) fn note_child_wait_event(&self) {
        self.child_wait_event_seq.fetch_add(1, Ordering::AcqRel);
        self.child_exit_wq.notify_all(false);
    }

    pub(crate) fn wait_continue_pending(&self) -> bool {
        self.wait_continue_pending.load(Ordering::Acquire)
    }

    pub(crate) fn mark_stopped_for_wait(&self, signum: usize) -> bool {
        let was_stopped = self.wait_stopped.swap(true, Ordering::AcqRel);
        self.wait_stop_signal
            .store(signum as u64, Ordering::Release);
        self.wait_stop_pending.store(true, Ordering::Release);
        self.wait_continue_pending.store(false, Ordering::Release);
        !was_stopped
    }

    pub(crate) fn mark_continued_for_wait(&self) -> bool {
        let was_stopped = self.wait_stopped.swap(false, Ordering::AcqRel);
        if was_stopped {
            self.wait_continue_pending.store(true, Ordering::Release);
            self.stop_wq.notify_all(false);
        }
        was_stopped
    }

    pub(crate) fn consume_wait_stop_pending(&self) -> bool {
        self.wait_stop_pending.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn consume_wait_continue_pending(&self) -> bool {
        self.wait_continue_pending.swap(false, Ordering::AcqRel)
    }

    pub(crate) fn is_vfork_child(&self) -> bool {
        self.is_vfork_child.load(Ordering::Acquire)
    }

    pub(crate) fn clear_vfork_child(&self) {
        self.is_vfork_child.store(false, Ordering::Release);
    }

    #[allow(unused)]
    pub(crate) fn set_parent(&self, parent_id: u64) {
        self.parent_id.store(parent_id, Ordering::Release);
    }

    pub(crate) fn set_leader_tid(&self, leader_tid: u64) {
        self.leader_tid.store(leader_tid, Ordering::Release);
    }

    pub(crate) fn set_parent_task(&self, parent_task: Option<WeakAxTaskRef>) {
        *self.parent_task.lock() = parent_task;
    }

    pub(crate) fn robust_list_head(&self) -> u64 {
        self.robust_list_head.load(Ordering::Acquire)
    }

    pub(crate) fn robust_list_len(&self) -> u64 {
        self.robust_list_len.load(Ordering::Acquire)
    }

    pub(crate) fn set_robust_list(&self, head: u64, len: u64) {
        self.robust_list_head.store(head, Ordering::Release);
        self.robust_list_len.store(len, Ordering::Release);
    }

    pub(crate) fn exit_signal(&self) -> u64 {
        self.exit_signal.load(Ordering::Acquire)
    }

    pub(crate) fn set_exit_signal(&self, signum: u64) {
        self.exit_signal.store(signum, Ordering::Release);
    }

    pub(crate) fn ns_init_new(&self) {
        FD_TABLE
            .deref_from(&self.ns)
            .init_new(FD_TABLE.copy_inner());
        FD_FLAGS
            .deref_from(&self.ns)
            .init_new(FD_FLAGS.copy_inner());
        RESOURCE_LIMITS
            .deref_from(&self.ns)
            .init_new(RESOURCE_LIMITS.copy_inner());
        CURRENT_DIR
            .deref_from(&self.ns)
            .init_new(CURRENT_DIR.copy_inner());
        CURRENT_DIR_PATH
            .deref_from(&self.ns)
            .init_new(CURRENT_DIR_PATH.copy_inner());
        CURRENT_FS_CRED
            .deref_from(&self.ns)
            .init_new(CURRENT_FS_CRED.copy_inner());
        PROC_NET_IPV4_CONF_LO_TAG
            .deref_from(&self.ns)
            .init_new(PROC_NET_IPV4_CONF_LO_TAG.copy_inner());
        PROC_NET_IPV4_CONF_DEFAULT_TAG
            .deref_from(&self.ns)
            .init_new(PROC_NET_IPV4_CONF_DEFAULT_TAG.copy_inner());
    }

    pub(crate) fn ns_init_clone_from(&self, share_files: bool, share_fs: bool) {
        if share_files {
            FD_TABLE.deref_from(&self.ns).init_shared(FD_TABLE.share());
            FD_FLAGS.deref_from(&self.ns).init_shared(FD_FLAGS.share());
            RESOURCE_LIMITS
                .deref_from(&self.ns)
                .init_shared(RESOURCE_LIMITS.share());
        } else {
            FD_TABLE
                .deref_from(&self.ns)
                .init_new(FD_TABLE.copy_inner());
            FD_FLAGS
                .deref_from(&self.ns)
                .init_new(FD_FLAGS.copy_inner());
            RESOURCE_LIMITS
                .deref_from(&self.ns)
                .init_new(RESOURCE_LIMITS.copy_inner());
        }

        if share_fs {
            CURRENT_DIR
                .deref_from(&self.ns)
                .init_shared(CURRENT_DIR.share());
            CURRENT_DIR_PATH
                .deref_from(&self.ns)
                .init_shared(CURRENT_DIR_PATH.share());
            CURRENT_FS_CRED
                .deref_from(&self.ns)
                .init_shared(CURRENT_FS_CRED.share());
        } else {
            CURRENT_DIR
                .deref_from(&self.ns)
                .init_new(CURRENT_DIR.copy_inner());
            CURRENT_DIR_PATH
                .deref_from(&self.ns)
                .init_new(CURRENT_DIR_PATH.copy_inner());
            CURRENT_FS_CRED
                .deref_from(&self.ns)
                .init_new(CURRENT_FS_CRED.copy_inner());
        }
    }

    pub(crate) fn time_stat_from_kernel_to_user(&self, current_tick: usize) {
        let time = self.time.get();
        unsafe {
            (*time).switch_into_user_mode(current_tick);
        }
    }

    pub(crate) fn time_stat_from_user_to_kernel(&self, current_tick: usize) {
        let time = self.time.get();
        unsafe {
            (*time).switch_into_kernel_mode(current_tick);
        }
    }

    pub(crate) fn time_stat_switch_from_old_task(&self, current_tick: usize) {
        let time = self.time.get();
        unsafe {
            (*time).switch_from_old_task(current_tick);
        }
    }

    pub(crate) fn time_stat_switch_to_new_task(&self, current_tick: usize) {
        let time = self.time.get();
        unsafe {
            (*time).switch_to_new_task(current_tick);
        }
    }

    pub(crate) fn time_stat_output(&self) -> (usize, usize) {
        let time = self.time.get();
        unsafe { (*time).output() }
    }

    pub(crate) fn get_heap_bottom(&self) -> u64 {
        self.heap_bottom.load(Ordering::Acquire)
    }

    #[allow(unused)]
    pub(crate) fn set_heap_bottom(&self, bottom: u64) {
        self.heap_bottom.store(bottom, Ordering::Release)
    }

    pub(crate) fn get_heap_top(&self) -> u64 {
        self.heap_top.load(Ordering::Acquire)
    }

    pub(crate) fn set_heap_top(&self, top: u64) {
        self.heap_top.store(top, Ordering::Release)
    }

    pub(crate) fn exec_image_base(&self) -> u64 {
        self.exec_image_base.load(Ordering::Acquire)
    }

    pub(crate) fn set_exec_image_base(&self, base: u64) {
        self.exec_image_base.store(base, Ordering::Release)
    }

    pub(crate) fn swap_umask(&self, new_mask: u32) -> u32 {
        self.umask.swap((new_mask & 0o777) as u64, Ordering::AcqRel) as u32
    }

    pub(crate) fn active_time_ns_offsets(&self) -> (i64, i64) {
        (
            self.time_ns_monotonic_offset_ns.load(Ordering::Acquire),
            self.time_ns_boottime_offset_ns.load(Ordering::Acquire),
        )
    }

    pub(crate) fn child_time_ns_offsets(&self) -> (i64, i64) {
        if self.time_ns_for_children_isolated.load(Ordering::Acquire) {
            (
                self.time_ns_children_monotonic_offset_ns
                    .load(Ordering::Acquire),
                self.time_ns_children_boottime_offset_ns
                    .load(Ordering::Acquire),
            )
        } else {
            self.active_time_ns_offsets()
        }
    }

    pub(crate) fn unshare_time_namespace(&self) {
        let (mono, boot) = self.active_time_ns_offsets();
        self.time_ns_children_monotonic_offset_ns
            .store(mono, Ordering::Release);
        self.time_ns_children_boottime_offset_ns
            .store(boot, Ordering::Release);
        self.time_ns_for_children_isolated
            .store(true, Ordering::Release);
    }

    pub(crate) fn reset_child_time_namespace(&self) {
        let (mono, boot) = self.active_time_ns_offsets();
        self.time_ns_children_monotonic_offset_ns
            .store(mono, Ordering::Release);
        self.time_ns_children_boottime_offset_ns
            .store(boot, Ordering::Release);
        self.time_ns_for_children_isolated
            .store(false, Ordering::Release);
    }

    pub(crate) fn configure_child_time_ns_offset(
        &self,
        clock_id: i32,
        offset_ns: i64,
    ) -> Result<(), LinuxError> {
        if !self.time_ns_for_children_isolated.load(Ordering::Acquire) {
            return Err(LinuxError::EPERM);
        }
        match clock_id {
            1 => {
                crate::timekeeping::note_time_namespace_offsets(offset_ns, 0);
                self.time_ns_children_monotonic_offset_ns
                    .store(offset_ns, Ordering::Release)
            }
            7 => {
                crate::timekeeping::note_time_namespace_offsets(0, offset_ns);
                self.time_ns_children_boottime_offset_ns
                    .store(offset_ns, Ordering::Release)
            }
            _ => return Err(LinuxError::EINVAL),
        }
        Ok(())
    }

    pub(crate) fn set_active_time_ns_offsets(
        &self,
        monotonic_offset_ns: i64,
        boottime_offset_ns: i64,
    ) {
        crate::timekeeping::note_time_namespace_offsets(monotonic_offset_ns, boottime_offset_ns);
        self.time_ns_monotonic_offset_ns
            .store(monotonic_offset_ns, Ordering::Release);
        self.time_ns_boottime_offset_ns
            .store(boottime_offset_ns, Ordering::Release);
    }

    pub(crate) fn netns_lo_tag(&self) -> i32 {
        self.netns_lo_tag.load(Ordering::Acquire)
    }

    pub(crate) fn set_netns_lo_tag(&self, value: i32) {
        self.netns_lo_tag.store(value, Ordering::Release);
    }

    pub(crate) fn netns_default_tag(&self) -> i32 {
        self.netns_default_tag.load(Ordering::Acquire)
    }

    pub(crate) fn set_netns_default_tag(&self, value: i32) {
        self.netns_default_tag.store(value, Ordering::Release);
    }

    pub(crate) fn exec_path(&self) -> String {
        self.exec_path.lock().clone()
    }

    pub(crate) fn set_exec_path(&self, path: String) {
        *self.exec_path.lock() = path;
    }

    pub(crate) fn start_wall_time_sec(&self) -> u64 {
        self.start_wall_time_sec.load(Ordering::Acquire)
    }

    pub(crate) fn start_monotonic_ns(&self) -> u64 {
        self.start_monotonic_ns.load(Ordering::Acquire)
    }
}

struct AxNamespaceImpl;
#[crate_interface::impl_interface]
impl AxNamespaceIf for AxNamespaceImpl {
    fn current_namespace_base() -> *mut u8 {
        // Namespace for kernel task
        static KERNEL_NS_BASE: Once<usize> = Once::new();
        let current = axtask::current();
        // Safety: We only check whether the task extended data is null and do not access it.
        if unsafe { current.task_ext_ptr() }.is_null() {
            return *(KERNEL_NS_BASE.call_once(|| {
                let global_ns = AxNamespace::global();
                let layout = Layout::from_size_align(global_ns.size(), 64).unwrap();
                // Safety: The global namespace is a static readonly variable and will not be dropped.
                let dst = unsafe { alloc::alloc::alloc(layout) };
                let src = global_ns.base();
                unsafe { core::ptr::copy_nonoverlapping(src, dst, global_ns.size()) };
                dst as usize
            })) as *mut u8;
        }
        current.task_ext().ns.base()
    }
}

axtask::def_task_ext!(TaskExt);

pub fn spawn_user_task(
    aspace: Arc<Mutex<AddrSpace>>,
    uctx: UspaceContext,
    heap_bottom: u64,
    exec_image_base: u64,
    exec_path: String,
) -> AxResult<AxTaskRef> {
    let proc_id = allocate_process_id();
    let user_stack_size = user_task_kernel_stack_size();
    let make_task = || {
        TaskInner::try_new(
            || {
                let curr = axtask::current();
                let kstack_top = curr.kernel_stack_top().unwrap();
                info!(
                    "Enter user space: entry={:#x}, ustack={:#x}, kstack={:#x}",
                    curr.task_ext().uctx.get_ip(),
                    curr.task_ext().uctx.get_sp(),
                    kstack_top,
                );
                unsafe { curr.task_ext().uctx.enter_uspace(kstack_top) };
            },
            "userboot".into(),
            user_stack_size,
        )
        .ok_or(AxError::NoMemory)
    };
    let mut task = match make_task() {
        Ok(task) => task,
        Err(AxError::NoMemory) => {
            let (reclaimed_stack_pages, reclaimed_exec_cache_pages) =
                reclaim_runtime_memory("spawn_user_task");
            if should_log_task_alloc_pressure() {
                warn!(
                    "retry user task alloc after reclaim: exec_path={} stack_size={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} available_pages={}",
                    exec_path,
                    user_stack_size,
                    reclaimed_stack_pages,
                    reclaimed_exec_cache_pages,
                    global_allocator().available_pages(),
                );
            }
            make_task()?
        }
        Err(err) => return Err(err),
    };
    task.ctx_mut()
        .set_page_table_root(aspace.lock().page_table_root());
    task.init_task_ext(TaskExt::new(
        proc_id,
        task.id().as_u64(),
        uctx,
        aspace,
        heap_bottom,
        exec_image_base,
        exec_path,
    ));
    task.task_ext().ns_init_new();
    let task = axtask::spawn_task(task);
    register_live_task(&task);
    Ok(task)
}

#[allow(unused)]
pub fn write_trapframe_to_kstack(kstack_top: usize, trap_frame: &TrapFrame) {
    let trap_frame_size = core::mem::size_of::<TrapFrame>();
    let trap_frame_ptr = (kstack_top - trap_frame_size) as *mut TrapFrame;
    unsafe {
        *trap_frame_ptr = *trap_frame;
    }
}

pub fn read_trapframe_from_kstack(kstack_top: usize) -> TrapFrame {
    let trap_frame_size = core::mem::size_of::<TrapFrame>();
    let trap_frame_ptr = (kstack_top - trap_frame_size) as *mut TrapFrame;
    unsafe { *trap_frame_ptr }
}

pub fn wait_pid(pid: i32) -> Result<(u64, i32), WaitStatus> {
    let selector = match wait_child_selector_from_waitpid(current().as_task_ref(), pid) {
        Ok(selector) => selector,
        Err(_) => return Err(WaitStatus::NotExist),
    };
    wait_child(selector)
}

pub(crate) fn wait_child(selector: WaitChildSelector) -> Result<(u64, i32), WaitStatus> {
    let curr_task = current();

    {
        let mut zombies = curr_task.task_ext().zombie_children.lock();
        let zombie_index = zombies.iter().position(|zombie| {
            wait_selector_matches_zombie(selector, zombie.pid, zombie.process_group)
        });
        if let Some(index) = zombie_index {
            let zombie = zombies.remove(index);
            unregister_zombie_process(zombie.pid);
            drop(zombies);
            let _ = axtask::reclaim_exited_tasks(usize::MAX);
            info!(
                "wait pid _{}_ with code _{}_",
                zombie.pid, zombie.wait_status
            );
            return Ok((zombie.pid, zombie.wait_status));
        }
    }

    Err(wait_child_status(curr_task.as_task_ref(), selector))
}

pub(crate) fn wait_pid_status(curr_task: &AxTaskRef, pid: i32) -> WaitStatus {
    let selector = match wait_child_selector_from_waitpid(curr_task, pid) {
        Ok(selector) => selector,
        Err(_) => return WaitStatus::NotExist,
    };
    wait_child_status(curr_task, selector)
}

pub(crate) fn wait_child_status(curr_task: &AxTaskRef, selector: WaitChildSelector) -> WaitStatus {
    let curr_proc_id = curr_task.task_ext().proc_id;
    {
        let zombies = curr_task.task_ext().zombie_children.lock();
        if zombies
            .iter()
            .any(|zombie| wait_selector_matches_zombie(selector, zombie.pid, zombie.process_group))
        {
            return WaitStatus::Exited;
        }
    }

    for child in curr_task.task_ext().children.lock().iter() {
        if wait_selector_matches_live(curr_proc_id, selector, child) {
            return WaitStatus::Running;
        }
    }

    WaitStatus::NotExist
}

pub(crate) fn wait_status_exited(exit_code: i32) -> i32 {
    (exit_code & 0xff) << 8
}

pub(crate) fn wait_status_stopped(signum: usize) -> i32 {
    0x7f | ((signum as i32 & 0xff) << 8)
}

pub(crate) fn wait_status_continued() -> i32 {
    0xffff
}

pub(crate) fn wait_status_signaled(signum: usize, dumped_core: bool) -> i32 {
    ((signum & 0x7f) | if dumped_core { 0x80 } else { 0 }) as i32
}

pub(crate) fn wait_child_selector_from_waitpid(
    curr_task: &AxTaskRef,
    pid: i32,
) -> Result<WaitChildSelector, LinuxError> {
    match pid {
        -1 => Ok(WaitChildSelector::Any),
        0 => Ok(WaitChildSelector::ProcessGroup(
            curr_task.task_ext().process_group(),
        )),
        1.. => Ok(WaitChildSelector::Pid(pid as u64)),
        i32::MIN => Err(LinuxError::ESRCH),
        _ => Ok(WaitChildSelector::ProcessGroup((-pid) as u64)),
    }
}

pub(crate) fn wait_selector_matches_live(
    curr_proc_id: usize,
    selector: WaitChildSelector,
    child: &AxTaskRef,
) -> bool {
    if child.task_ext().proc_id == curr_proc_id {
        return false;
    }
    wait_selector_matches_zombie(
        selector,
        child.task_ext().proc_id as u64,
        child.task_ext().process_group(),
    )
}

pub(crate) fn wait_selector_matches_zombie(
    selector: WaitChildSelector,
    child_pid: u64,
    child_process_group: u64,
) -> bool {
    match selector {
        WaitChildSelector::Any => true,
        WaitChildSelector::Pid(pid) => child_pid == pid,
        WaitChildSelector::ProcessGroup(pgid) => child_process_group == pgid,
    }
}

#[allow(dead_code)]
pub fn exec(name: &str) -> AxResult<()> {
    exec_with_args_env(
        name,
        vec![name.to_string()],
        crate::mm::runtime_env_for(name),
    )
}

#[allow(dead_code)]
pub fn exec_with_args(path: &str, args: Vec<String>) -> AxResult<()> {
    exec_with_args_env(path, args, crate::mm::runtime_env_for(path))
}

fn exec_with_args_env_loader<F>(
    path: &str,
    args: Vec<String>,
    env: Vec<String>,
    mut loader: F,
) -> AxResult<()>
where
    F: FnMut(
        &str,
        &mut VecDeque<String>,
        &[String],
        &mut AddrSpace,
    ) -> AxResult<(VirtAddr, VirtAddr, VirtAddr, usize, usize)>,
{
    fn activate_user_page_table_root(new_root: memory_addr::PhysAddr) {
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            axhal::arch::write_page_table_root0(new_root);
        }
        #[cfg(not(target_arch = "loongarch64"))]
        unsafe {
            axhal::arch::write_page_table_root(new_root);
        }
    }

    let current_task = current();
    let task_name = args.first().cloned().unwrap_or_else(|| path.to_string());
    let argc = args.len();
    let task_ext = unsafe { &mut *(current_task.task_ext_ptr() as *mut TaskExt) };

    let use_fresh_aspace = if task_ext.is_vfork_child() {
        true
    } else if Arc::strong_count(&task_ext.aspace) != 1 {
        warn!("Address space is shared by multiple tasks, exec is not supported.");
        return Err(AxError::Unsupported);
    } else {
        true
    };
    let (entry_point, user_stack_base, heap_bottom, user_tp, exec_image_base) = if use_fresh_aspace
    {
        let mut load_fresh =
            || -> AxResult<(AddrSpace, (VirtAddr, VirtAddr, VirtAddr, usize, usize))> {
                prepare_runtime_for_exec("exec_prepare", path);
                let mut new_aspace = axmm::new_user_aspace(
                    memory_addr::VirtAddr::from_usize(axconfig::plat::USER_SPACE_BASE),
                    axconfig::plat::USER_SPACE_SIZE,
                )
                .map_err(|_| AxError::NoMemory)?;
                let mut args_deque = VecDeque::from(args.clone());
                let loaded = loader(path, &mut args_deque, &env, &mut new_aspace)?;
                Ok((new_aspace, loaded))
            };
        let (new_aspace, loaded) = match load_fresh() {
            Ok(loaded) => loaded,
            Err(AxError::NoMemory) => {
                let _ = reclaim_runtime_memory("execve");
                load_fresh().map_err(|err| {
                    if !crate::mm::is_expected_exec_lookup_error(&err) {
                        log_user_program_load_failure(path, &err);
                    }
                    maybe_terminate_on_exec_failure(path, &err);
                    err
                })?
            }
            Err(err) => {
                if !crate::mm::is_expected_exec_lookup_error(&err) {
                    log_user_program_load_failure(path, &err);
                }
                maybe_terminate_on_exec_failure(path, &err);
                return Err(err);
            }
        };
        let new_root = new_aspace.page_table_root();
        {
            let mut old_aspace = task_ext.aspace.lock();
            crate::syscall_imp::detach_sysv_shm_process(task_ext.proc_id, &mut old_aspace);
        }
        let old_aspace = core::mem::replace(&mut task_ext.aspace, Arc::new(Mutex::new(new_aspace)));
        if task_ext.is_vfork_child() {
            task_ext.clear_vfork_child();
        }
        let task_ptr = Arc::as_ptr(current_task.as_task_ref()) as *mut TaskInner;
        unsafe {
            (*task_ptr).ctx_mut().set_page_table_root(new_root);
        }
        activate_user_page_table_root(new_root);
        axhal::arch::flush_tlb(None);
        drop(old_aspace);
        loaded
    } else {
        unreachable!()
    };
    current_task.set_name(&task_name);
    close_on_exec_fds();
    task_ext.set_exec_path(crate::mm::absolute_exec_path(path));
    task_ext.signals.lock().reset_for_exec();
    task_ext.uctx = UspaceContext::new(entry_point.as_usize(), user_stack_base, 0);
    #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
    {
        let argv_ptr = user_stack_base.as_usize() + core::mem::size_of::<usize>();
        task_ext.uctx.set_retval(argc);
        task_ext.uctx.set_arg1(argv_ptr);
        task_ext
            .uctx
            .set_arg2(user_stack_base.as_usize() + (argc + 2) * core::mem::size_of::<usize>());
    }
    #[cfg(any(target_arch = "loongarch64", target_arch = "riscv64"))]
    if user_tp != 0 {
        task_ext.uctx.set_thread_pointer(user_tp);
    }
    task_ext.set_heap_bottom(heap_bottom.as_usize() as u64);
    task_ext.set_heap_top(heap_bottom.as_usize() as u64);
    task_ext.set_exec_image_base(exec_image_base as u64);
    task_ext.complete_vfork();
    unsafe {
        task_ext.uctx.enter_uspace(
            current_task
                .kernel_stack_top()
                .expect("No kernel stack top"),
        );
    }
}

pub fn exec_with_args_env(path: &str, args: Vec<String>, env: Vec<String>) -> AxResult<()> {
    exec_with_args_env_loader(path, args, env, crate::mm::load_user_app)
}

pub fn exec_with_args_env_from_bytes(
    path: &str,
    image: Vec<u8>,
    args: Vec<String>,
    env: Vec<String>,
) -> AxResult<()> {
    let mut image = Some(image);
    exec_with_args_env_loader(path, args, env, move |path, args, env, uspace| {
        if let Some(image) = image.take() {
            crate::mm::load_user_app_from_bytes(path, image, args, env, uspace)
        } else {
            crate::mm::load_user_app(path, args, env, uspace)
        }
    })
}

pub(crate) fn notify_parent_sigchld() {
    let curr = current();
    let signum = curr.task_ext().exit_signal() as usize;
    if signum == 0 {
        return;
    }
    if let Some(parent) = curr.task_ext().parent_task() {
        if crate::signal::task_ignores_signal_by_default(&parent, signum) {
            return;
        }
        crate::signal::send_signal_to_task(&parent, signum);
    }
}

pub(crate) fn terminate_other_threads_in_group(proc_id: usize, skip_tid: u64, signum: usize) {
    for task in thread_group_tasks(proc_id) {
        if task.id().as_u64() == skip_tid {
            continue;
        }
        if task.state() != axtask::TaskState::Exited {
            crate::signal::send_signal_to_task(&task, signum);
        }
    }
}

pub(crate) fn wait_for_other_threads_in_group_to_exit(proc_id: usize, skip_tid: u64) {
    loop {
        let mut other_live = false;
        for task in thread_group_tasks(proc_id) {
            if task.id().as_u64() != skip_tid {
                other_live = true;
                break;
            }
        }
        if !other_live {
            break;
        }
        axtask::yield_now();
    }
}

pub(crate) fn exit_current_task(
    status: i32,
    notify_parent_if_leader: bool,
    close_fds_if_leader: bool,
) -> ! {
    {
        let curr = current();
        if curr.task_ext().is_vfork_child() {
            curr.task_ext().clear_vfork_child();
            curr.task_ext().complete_vfork();
        }
        reparent_orphaned_children_on_exit(curr.as_task_ref());
    }
    record_exit_for_parent(status);
    crate::syscall_imp::record_process_accounting(status);
    let (tid, clear_child_tid, is_thread_group_leader, fd_table_refs) = {
        let curr = current();
        (
            curr.id().as_u64(),
            curr.task_ext().clear_child_tid() as *mut i32,
            curr.id().as_u64() == curr.task_ext().leader_tid(),
            FD_TABLE.deref_from(&curr.task_ext().ns).strong_count(),
        )
    };
    if notify_parent_if_leader && is_thread_group_leader {
        notify_parent_sigchld();
    }
    maybe_abort_current_competition_script_on_fatal_signal(status);
    handle_robust_list_on_exit();
    if is_thread_group_leader {
        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        crate::syscall_imp::detach_sysv_shm_process(curr.task_ext().proc_id, &mut aspace);
    }
    crate::syscall_imp::clear_child_tid_and_wake(clear_child_tid);
    if close_fds_if_leader && is_thread_group_leader && fd_table_refs == 1 {
        crate::syscall_imp::cleanup_all_fd_tracking_for_current_process();
        close_all_fds_fast();
    }
    unregister_live_task(current().as_task_ref());
    if is_thread_group_leader {
        remove_proc_pid_entries(current().task_ext().proc_id as u64);
    }
    axtask::exit(status);
}

pub(crate) fn record_exit_for_parent(exit_code: i32) {
    let curr = current();
    if let Some(parent) = curr.task_ext().parent_task() {
        let curr_tid = curr.id().as_u64();
        let curr_pid = curr.task_ext().proc_id as u64;
        let is_thread_exit = curr.task_ext().proc_id == parent.task_ext().proc_id;
        let mut removed = false;
        {
            let mut children = parent.task_ext().children.lock();
            if let Some(index) = children
                .iter()
                .position(|child| child.id().as_u64() == curr_tid)
            {
                children.remove(index);
                removed = true;
            }
        }
        let zombie_count = if is_thread_exit {
            0
        } else {
            let creds = *CURRENT_FS_CRED.deref_from(&curr.task_ext().ns).lock();
            let mut zombies = parent.task_ext().zombie_children.lock();
            zombies.push(ZombieChild {
                pid: curr_pid,
                process_group: curr.task_ext().process_group(),
                wait_status: exit_code,
            });
            register_zombie_process(ZombieProcess {
                pid: curr_pid,
                process_group: curr.task_ext().process_group(),
                ruid: creds.ruid,
                euid: creds.euid,
                suid: creds.suid,
            });
            zombies.len()
        };
        parent.task_ext().note_child_wait_event();
        if !is_thread_exit && (!removed || zombie_count >= 32 && zombie_count % 32 == 0) {
            debug!(
                "record_exit_for_parent parent_pid={} child_pid={} removed_live={} live_children={} zombie_children={}",
                parent.id().as_u64(),
                curr_pid,
                removed,
                parent.task_ext().children.lock().len(),
                zombie_count
            );
        }
    }
}

fn reparent_orphaned_children_on_exit(curr: &AxTaskRef) {
    if !task_is_process_leader(curr) {
        return;
    }

    let Some(init_task) = find_process_leader_by_pid(1)
        .filter(|init| init.id().as_u64() != curr.id().as_u64())
    else {
        let children = {
            let mut children = curr.task_ext().children.lock();
            core::mem::take(&mut *children)
        };
        for child in children {
            child.task_ext().set_parent(0);
            child.task_ext().set_parent_task(None);
        }
        let zombies = {
            let mut zombies = curr.task_ext().zombie_children.lock();
            core::mem::take(&mut *zombies)
        };
        for zombie in zombies {
            unregister_zombie_process(zombie.pid);
        }
        return;
    };

    let init_pid = init_task.task_ext().proc_id as u64;
    let init_weak = Arc::downgrade(&init_task);
    let live_children = {
        let mut children = curr.task_ext().children.lock();
        core::mem::take(&mut *children)
    };
    let zombie_children = {
        let mut zombies = curr.task_ext().zombie_children.lock();
        core::mem::take(&mut *zombies)
    };

    for child in live_children.iter() {
        child.task_ext().set_parent(init_pid);
        child.task_ext().set_parent_task(Some(init_weak.clone()));
    }
    if !live_children.is_empty() {
        init_task
            .task_ext()
            .children
            .lock()
            .extend(live_children.into_iter());
    }
    if !zombie_children.is_empty() {
        init_task
            .task_ext()
            .zombie_children
            .lock()
            .extend(zombie_children.into_iter());
        init_task.task_ext().note_child_wait_event();
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RobustList {
    next: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RobustListHead {
    list: RobustList,
    futex_offset: isize,
    list_op_pending: usize,
}

pub(crate) fn handle_robust_list_on_exit() {
    const FUTEX_WAITERS: u32 = 0x8000_0000;
    const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
    const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
    const ROBUST_LIST_LIMIT: usize = 2048;

    let curr = current();
    let head_addr = curr.task_ext().robust_list_head() as usize;
    if head_addr == 0 {
        return;
    }
    let Ok(head) = read_value_from_user(head_addr as *const RobustListHead) else {
        return;
    };
    let tid = curr.id().as_u64() as u32;

    let mut process_node = |node_addr: usize| {
        if node_addr == 0 {
            return;
        }
        let futex_addr = (node_addr as isize).saturating_add(head.futex_offset) as usize;
        let futex_ptr = futex_addr as *mut u32;
        let Ok(value) = read_value_from_user(futex_ptr as *const u32) else {
            return;
        };
        if value & FUTEX_TID_MASK != tid {
            return;
        }
        let new_value = (value & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        let _ = write_value_to_user(futex_ptr, new_value);
        crate::syscall_imp::wake_futex_word(futex_ptr);
    };

    process_node(head.list_op_pending);

    let mut next = head.list.next;
    for _ in 0..ROBUST_LIST_LIMIT {
        if next == 0 || next == head_addr {
            break;
        }
        let node_addr = next;
        let Ok(node) = read_value_from_user(node_addr as *const RobustList) else {
            break;
        };
        process_node(node_addr);
        next = node.next;
    }
}

pub fn time_stat_from_kernel_to_user() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_kernel_to_user(monotonic_time_nanos() as usize);
}

pub fn time_stat_from_user_to_kernel() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_user_to_kernel(monotonic_time_nanos() as usize);
}

pub fn time_stat_output() -> (usize, usize, usize, usize) {
    let curr_task = current();
    let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
    (
        utime_ns / NANOS_PER_SEC as usize,
        utime_ns / NANOS_PER_MICROS as usize,
        stime_ns / NANOS_PER_SEC as usize,
        stime_ns / NANOS_PER_MICROS as usize,
    )
}

pub(crate) fn record_task_switch_time(
    prev_task_ext: *mut u8,
    next_task_ext: *mut u8,
    current_tick: usize,
) {
    unsafe {
        if !prev_task_ext.is_null() {
            let prev = &*(prev_task_ext as *const TaskExt);
            prev.time_stat_switch_from_old_task(current_tick);
        }
        if !next_task_ext.is_null() {
            let next = &*(next_task_ext as *const TaskExt);
            next.time_stat_switch_to_new_task(current_tick);
        }
    }
}
