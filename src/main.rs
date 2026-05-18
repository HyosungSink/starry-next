#![no_std]
#![no_main]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;
extern crate alloc;
extern crate axstd;

mod ctypes;
mod diag;
mod embedded_runtime {
    include!(concat!(env!("OUT_DIR"), "/embedded_runtime.rs"));
}

mod mm;
mod signal;
mod syscall_imp;
mod task;
mod timekeeping;
mod usercopy;
use alloc::collections::VecDeque;
use alloc::{string::String, vec::Vec};
use alloc::{string::ToString, sync::Arc, vec};
use core::{
    mem,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use axalloc::global_allocator;
use axerrno::{AxError, AxResult};
use axfs::api::File;
use axhal::arch::UspaceContext;
use axhal::time::monotonic_time_nanos;
use axstd::io::{Read, Write};
use axstd::println;
use axsync::Mutex;
use memory_addr::VirtAddr;

const CONTEST_GROUPS: [&str; 11] = [
    "basic",
    "busybox",
    "cyclictest",
    "iozone",
    "iperf",
    "libcbench",
    "libctest",
    "lmbench",
    "ltp",
    "lua",
    "netperf",
];
const WATCHDOG_STACK_SIZE: usize = 16 * 1024;

const RUNTIME_SCRIPT_DIRS: [&str; 2] = ["/glibc", "/musl"];
const OFFICIAL_ALLOWED_GROUPS_PATH: &str = "/.osk_allowed_runtime_groups";

static COMPETITION_SCRIPT_WATCHDOG_TOKEN: AtomicU64 = AtomicU64::new(0);
static COMPETITION_SCRIPT_PROGRESS_NS: AtomicU64 = AtomicU64::new(0);
static COMPETITION_WATCHDOG_SCRIPT: Mutex<Option<String>> = Mutex::new(None);
static COMPETITION_STDOUT_LINE_BUFFER: Mutex<String> = Mutex::new(String::new());
static COMPETITION_TOTAL_WATCHDOG_TOKEN: AtomicU64 = AtomicU64::new(0);
static COMPETITION_TOTAL_DEADLINE_NS: AtomicU64 = AtomicU64::new(0);
static COMPETITION_TOTAL_TIMED_OUT: AtomicU64 = AtomicU64::new(0);
static LTP_DIAG_RUN_SEQ: AtomicU64 = AtomicU64::new(0);
static LTP_DIAG_DONE_SEQ: AtomicU64 = AtomicU64::new(0);
static LTP_ACTIVE_CASE: Mutex<Option<String>> = Mutex::new(None);
static LTP_ACTIVE_CASE_PGID: AtomicU64 = AtomicU64::new(0);
static LTP_ACTIVE_CASE_DEADLINE_NS: AtomicU64 = AtomicU64::new(0);

const SIGKILL_SIGNUM: usize = 9;
// Some LTP cases, notably fork13 and timerfd_settime02, may legally run for
// minutes. Keep the total guard well above a complete libc matrix run; per-case
// watchdogs still catch individual hangs.
const COMPETITION_TOTAL_TIMEOUT: Duration = Duration::from_secs(4 * 3600);
const NETPERF_SCRIPT_SILENCE_TIMEOUT: Duration = Duration::from_secs(90);

fn script_silence_watchdog_timeout(script: &str) -> Option<Duration> {
    match script_group_name(script) {
        "netperf" => Some(NETPERF_SCRIPT_SILENCE_TIMEOUT),
        _ => None,
    }
}

fn arm_script_watchdog(script: &str) -> u64 {
    let token = COMPETITION_SCRIPT_WATCHDOG_TOKEN.fetch_add(1, Ordering::SeqCst) + 1;
    COMPETITION_SCRIPT_PROGRESS_NS.store(monotonic_time_nanos(), Ordering::SeqCst);
    COMPETITION_STDOUT_LINE_BUFFER.lock().clear();
    *COMPETITION_WATCHDOG_SCRIPT.lock() = Some(script.to_string());
    if script_group_name(script) == "ltp" {
        axtask::spawn_raw(
            move || loop {
                if COMPETITION_SCRIPT_WATCHDOG_TOKEN.load(Ordering::Acquire) != token {
                    break;
                }
                let deadline_ns = LTP_ACTIVE_CASE_DEADLINE_NS.load(Ordering::Acquire);
                let now_ns = monotonic_time_nanos();
                if deadline_ns != 0 && now_ns >= deadline_ns {
                    let pgid = LTP_ACTIVE_CASE_PGID.load(Ordering::Acquire);
                    let case = LTP_ACTIVE_CASE
                        .lock()
                        .clone()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    if pgid != 0 {
                        // Move the deadline forward before killing so a stubborn task can be
                        // retried without flooding the console.
                        LTP_ACTIVE_CASE_DEADLINE_NS.store(
                            now_ns.saturating_add(Duration::from_secs(5).as_nanos() as u64),
                            Ordering::Release,
                        );
                        let killed =
                            task::kill_current_competition_process_group(pgid, SIGKILL_SIGNUM);
                        warn!(
                            "[osk-ltp-diag] case={} phase=kernel-watchdog-timeout pgid={} killed_tasks={}",
                            case, pgid, killed
                        );
                    }
                }
                axtask::sleep(Duration::from_millis(200));
            },
            "ltp-case-watchdog".into(),
            WATCHDOG_STACK_SIZE,
        );
    }
    if let Some(timeout) = script_silence_watchdog_timeout(script) {
        let script_name = script.to_string();
        axtask::spawn_raw(
            move || {
                let timeout_ns = timeout.as_nanos() as u64;
                loop {
                    if COMPETITION_SCRIPT_WATCHDOG_TOKEN.load(Ordering::Acquire) != token {
                        break;
                    }
                    let progress_ns = COMPETITION_SCRIPT_PROGRESS_NS.load(Ordering::Acquire);
                    if progress_ns != 0 {
                        let now_ns = monotonic_time_nanos();
                        let idle_ns = now_ns.saturating_sub(progress_ns);
                        if idle_ns >= timeout_ns {
                            COMPETITION_SCRIPT_PROGRESS_NS.store(now_ns, Ordering::Release);
                            let killed = task::kill_current_competition_script_tree(SIGKILL_SIGNUM);
                            warn!(
                                "[online-diag] kind=script phase=silence-watchdog-timeout path={} idle_ms={} killed_tasks={}",
                                script_name,
                                idle_ns / 1_000_000,
                                killed
                            );
                            break;
                        }
                    }
                    axtask::sleep(Duration::from_millis(500));
                }
            },
            "script-silence-watchdog".into(),
            WATCHDOG_STACK_SIZE,
        );
    }
    token
}

fn disarm_script_watchdog(token: u64) {
    let disarmed = COMPETITION_SCRIPT_WATCHDOG_TOKEN.compare_exchange(
        token,
        token + 1,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    if disarmed.is_ok() {
        COMPETITION_SCRIPT_PROGRESS_NS.store(0, Ordering::SeqCst);
        COMPETITION_STDOUT_LINE_BUFFER.lock().clear();
        *COMPETITION_WATCHDOG_SCRIPT.lock() = None;
        *LTP_ACTIVE_CASE.lock() = None;
        LTP_ACTIVE_CASE_PGID.store(0, Ordering::Release);
        LTP_ACTIVE_CASE_DEADLINE_NS.store(0, Ordering::Release);
    }
}

fn arm_total_competition_watchdog() -> u64 {
    let token = COMPETITION_TOTAL_WATCHDOG_TOKEN.fetch_add(1, Ordering::SeqCst) + 1;
    let deadline_ns =
        monotonic_time_nanos().saturating_add(COMPETITION_TOTAL_TIMEOUT.as_nanos() as u64);
    COMPETITION_TOTAL_DEADLINE_NS.store(deadline_ns, Ordering::SeqCst);
    COMPETITION_TOTAL_TIMED_OUT.store(0, Ordering::SeqCst);
    axtask::spawn_raw(
        move || loop {
            if COMPETITION_TOTAL_WATCHDOG_TOKEN.load(Ordering::Acquire) != token {
                break;
            }
            let now_ns = monotonic_time_nanos();
            let deadline_ns = COMPETITION_TOTAL_DEADLINE_NS.load(Ordering::Acquire);
            if deadline_ns != 0 && now_ns >= deadline_ns {
                if COMPETITION_TOTAL_TIMED_OUT
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    warn!(
                        "Competition total watchdog timeout: elapsed_s={} limit_s={} -> stopping online evaluation",
                        now_ns.saturating_sub(
                            deadline_ns.saturating_sub(COMPETITION_TOTAL_TIMEOUT.as_nanos() as u64)
                        ) / 1_000_000_000,
                        COMPETITION_TOTAL_TIMEOUT.as_secs()
                    );
                    let killed = task::kill_current_competition_script_tree(SIGKILL_SIGNUM);
                    warn!(
                        "Competition total watchdog cleanup complete: killed_tasks={} limit_s={}",
                        killed,
                        COMPETITION_TOTAL_TIMEOUT.as_secs()
                    );
                }
                break;
            }
            axtask::sleep(Duration::from_millis(200));
        },
        "competition-watchdog".into(),
        WATCHDOG_STACK_SIZE,
    );
    token
}

fn disarm_total_competition_watchdog(token: u64) {
    let disarmed = COMPETITION_TOTAL_WATCHDOG_TOKEN.compare_exchange(
        token,
        token + 1,
        Ordering::SeqCst,
        Ordering::SeqCst,
    );
    if disarmed.is_ok() {
        COMPETITION_TOTAL_DEADLINE_NS.store(0, Ordering::SeqCst);
    }
}

fn competition_total_watchdog_timed_out() -> bool {
    COMPETITION_TOTAL_TIMED_OUT.load(Ordering::Acquire) != 0
}

fn script_group_name(path: &str) -> &str {
    let basename = script_basename(path).trim_start_matches('.');
    if let Some(rest) = basename.strip_prefix("osk_") {
        if let Some((_, group_with_suffix)) = rest.split_once('_') {
            if let Some(group) = group_with_suffix
                .strip_suffix("_testcode.sh")
                .or_else(|| group_with_suffix.strip_suffix("_testcode.sh.raw"))
            {
                return group;
            }
        }
    }
    basename
        .strip_suffix("_testcode.sh.raw")
        .or_else(|| basename.strip_suffix("_testcode.sh"))
        .or_else(|| basename.strip_suffix(".sh"))
        .unwrap_or(basename)
}

fn line_counts_as_pass_point(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed == "Pass!"
        || trimmed.contains(" TPASS ")
        || trimmed.contains("TPASS:")
        || trimmed.ends_with(" success")
        || trimmed.ends_with(" success.")
        || trimmed.ends_with(" successfully.")
        || trimmed.ends_with(" successfully!")
        || trimmed.ends_with(" end: success ======")
        || trimmed.starts_with("PASS LTP CASE ")
        || trimmed.starts_with("FAIL LTP CASE ")
        || trimmed.starts_with("SKIP LTP CASE ")
        || trimmed.starts_with("  time:")
        || trimmed.starts_with("Simple ")
        || trimmed.starts_with("Select on ")
        || trimmed.starts_with("Signal handler ")
        || trimmed.starts_with("Protection fault:")
        || trimmed.starts_with("Pipe latency:")
        || trimmed.starts_with("Process fork+")
        || trimmed.starts_with("File /var/tmp/XXX write bandwidth:")
        || trimmed.starts_with("Pipe bandwidth:")
        || trimmed.starts_with("Pagefaults on /var/tmp/XXX:")
        || trimmed.starts_with("0k\t")
        || trimmed.starts_with("1k\t")
        || trimmed.starts_with("4k\t")
        || trimmed.starts_with("10k\t")
        || matches!(
            trimmed.split_once(' '),
            Some((left, right))
                if matches!(left, "2" | "4" | "8" | "16" | "24" | "32" | "64" | "96")
                    && right.parse::<f64>().is_ok()
        )
        || matches!(
            trimmed.split_once(' '),
            Some((left, right))
                if left.parse::<f64>().is_ok() && right.parse::<f64>().is_ok()
        )
}

fn script_counts_any_output_activity(script: &str) -> bool {
    matches!(
        script_group_name(script),
        "iozone" | "lmbench" | "libcbench"
    )
}

fn line_counts_as_script_progress(script: &str, line: &str) -> bool {
    if line_counts_as_pass_point(line) {
        return true;
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    match script_group_name(script) {
        "ltp" => {
            trimmed.starts_with("RUN LTP CASE ")
                || trimmed.starts_with("PASS LTP CASE ")
                || trimmed.starts_with("FAIL LTP CASE ")
                || trimmed.starts_with("SKIP LTP CASE ")
                || trimmed.starts_with("[ltp-heartbeat]")
        }
        "libctest" => {
            trimmed.starts_with("========== START ")
                || trimmed.starts_with("========== END ")
                || trimmed.starts_with("src/")
        }
        _ => false,
    }
}

fn parse_ltp_case_timestamp_event(line: &str) -> Option<(&str, &'static str)> {
    let trimmed = line.trim();
    if let Some(case_name) = trimmed.strip_prefix("RUN LTP CASE ") {
        let case_name = case_name.trim();
        if !case_name.is_empty() {
            return Some((case_name, "run"));
        }
    }
    for prefix in ["PASS LTP CASE ", "FAIL LTP CASE ", "SKIP LTP CASE "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let case_name = rest.split(" : ").next().unwrap_or(rest).trim();
            if !case_name.is_empty() {
                return Some((case_name, "done"));
            }
        }
    }
    None
}

fn parse_osk_ltp_case_started(line: &str) -> Option<(&str, u64)> {
    let trimmed = line.trim();
    let rest = trimmed.strip_prefix("[osk-ltp-diag] ")?;
    let mut case_name = None;
    let mut pid = None;
    let mut started = false;
    for part in rest.split_whitespace() {
        if let Some(value) = part.strip_prefix("case=") {
            case_name = Some(value);
        } else if let Some(value) = part.strip_prefix("pid=") {
            pid = value.parse::<u64>().ok();
        } else if part == "phase=started" {
            started = true;
        }
    }
    match (case_name, pid, started) {
        (Some(case_name), Some(pid), true) if !case_name.is_empty() && pid != 0 => {
            Some((case_name, pid))
        }
        _ => None,
    }
}

fn ltp_case_watchdog_timeout(case_name: &str) -> Duration {
    match case_name {
        "fork13" => Duration::from_secs(750),
        "timerfd_settime02" => Duration::from_secs(240),
        _ => Duration::from_secs(180),
    }
}

fn note_ltp_case_started(line: &str) {
    let Some((case_name, pgid)) = parse_osk_ltp_case_started(line) else {
        return;
    };
    let deadline_ns = monotonic_time_nanos()
        .saturating_add(ltp_case_watchdog_timeout(case_name).as_nanos() as u64);
    *LTP_ACTIVE_CASE.lock() = Some(case_name.to_string());
    LTP_ACTIVE_CASE_PGID.store(pgid, Ordering::Release);
    LTP_ACTIVE_CASE_DEADLINE_NS.store(deadline_ns, Ordering::Release);
}

fn ltp_case_needs_online_diag(case_name: &str, phase: &str, seq: u64) -> bool {
    seq <= 8
        || seq % 25 == 0
        || case_name == "epoll_ctl01"
        || case_name == "execve05"
        || case_name == "fallocate05"
        || case_name == "geteuid01_16"
        || case_name.starts_with("exec")
        || case_name.starts_with("faccessat")
        || case_name.starts_with("fallocate")
        || case_name.starts_with("shmctl")
        || phase == "done" && seq <= 8
}

fn emit_online_task_memory_diag(kind: &str, phase: &str, name: &str, seq: u64) {
    let allocator = global_allocator();
    let counts = task::diagnostic_task_counts();
    let frame_refs = axmm::frame_ref_stats();
    let mounts = axfs::api::diagnostic_mount_stats();
    let ramfs = axfs::api::diagnostic_ramfs_quota_stats();
    let loopdev = arceos_posix_api::diagnostic_loop_device_state();
    let tmpfiles = arceos_posix_api::diagnostic_named_tmpfiles();
    println!(
        "[online-diag] kind={kind} phase={phase} name={name} seq={seq} now_ms={} available_pages={} used_pages={} used_bytes={} available_bytes={} frame_refs={} frame_ref_total={} frame_ref_max={} mounts_total={} mounts_ext4={} mounts_ramfs={} ramfs_live={} ramfs_used_bytes={} ramfs_max_bytes={} loop_backing={} loop_configured={} loop_size={} named_tmpfiles={} named_tmpfile_bytes={} live_tasks={} live_exited_tasks={} process_leaders={} zombie_processes={} script_tagged_tasks={} script_tagged_exited_tasks={}",
        monotonic_time_nanos() / 1_000_000,
        allocator.available_pages(),
        allocator.used_pages(),
        allocator.used_bytes(),
        allocator.available_bytes(),
        frame_refs.tracked_frames,
        frame_refs.total_refs,
        frame_refs.max_refcount,
        mounts.total,
        mounts.ext4,
        mounts.ramfs,
        ramfs.live_filesystems,
        ramfs.used_bytes,
        ramfs.max_bytes,
        loopdev.has_backing,
        loopdev.configured,
        loopdev.visible_size,
        tmpfiles.entries,
        tmpfiles.allocated_bytes,
        counts.live_tasks,
        counts.live_exited_tasks,
        counts.process_leaders,
        counts.zombie_processes,
        counts.script_tagged_tasks,
        counts.script_tagged_exited_tasks
    );
}

fn emit_kernel_ltp_case_timestamp(line: &str) {
    let Some((case_name, phase)) = parse_ltp_case_timestamp_event(line) else {
        return;
    };
    let now_ns = monotonic_time_nanos();
    let seconds = now_ns / 1_000_000_000;
    let centis = (now_ns % 1_000_000_000) / 10_000_000;
    println!("[ltp-ts {seconds}.{centis:02}] case={case_name} phase={phase}");
    let seq = match phase {
        "run" => LTP_DIAG_RUN_SEQ.fetch_add(1, Ordering::SeqCst) + 1,
        _ => LTP_DIAG_DONE_SEQ.fetch_add(1, Ordering::SeqCst) + 1,
    };
    if phase == "run" {
        *LTP_ACTIVE_CASE.lock() = Some(case_name.to_string());
        LTP_ACTIVE_CASE_PGID.store(0, Ordering::Release);
        LTP_ACTIVE_CASE_DEADLINE_NS.store(0, Ordering::Release);
    }
    if phase == "done" {
        let should_clear = LTP_ACTIVE_CASE
            .lock()
            .as_ref()
            .is_some_and(|active| active == case_name);
        if should_clear {
            *LTP_ACTIVE_CASE.lock() = None;
            LTP_ACTIVE_CASE_PGID.store(0, Ordering::Release);
            LTP_ACTIVE_CASE_DEADLINE_NS.store(0, Ordering::Release);
        }
        task::reclaim_runtime_memory_detail("ltp_case_done");
    }
    if ltp_case_needs_online_diag(case_name, phase, seq) {
        emit_online_task_memory_diag("ltp-case", phase, case_name, seq);
    }
}

pub(crate) fn note_competition_pass_point() {
    COMPETITION_SCRIPT_PROGRESS_NS.store(monotonic_time_nanos(), Ordering::SeqCst);
}

pub(crate) fn note_competition_output_activity(fd: i32, bytes: &[u8]) {
    if bytes.is_empty() || !(fd == 1 || fd == 2) {
        return;
    }
    let active_script = COMPETITION_WATCHDOG_SCRIPT.lock().clone();
    let Some(active_script) = active_script else {
        return;
    };
    if script_counts_any_output_activity(active_script.as_str()) {
        note_competition_pass_point();
    }
    let mut buffer = COMPETITION_STDOUT_LINE_BUFFER.lock();
    for &byte in bytes {
        match byte {
            b'\n' => {
                let line = mem::take(&mut *buffer);
                let line = line.trim_end_matches('\r');
                if script_group_name(active_script.as_str()) == "ltp" {
                    note_ltp_case_started(line);
                    emit_kernel_ltp_case_timestamp(line);
                }
                if line_counts_as_script_progress(active_script.as_str(), line) {
                    note_competition_pass_point();
                }
            }
            b'\r' => {}
            b'\t' | b' '..=b'~' => {
                if buffer.len() < 4096 {
                    buffer.push(byte as char);
                }
            }
            _ => {
                if buffer.len() < 4096 {
                    buffer.push('?');
                }
            }
        }
    }
}

fn script_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn script_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => "/",
        Some((dir, _)) => dir,
    }
}

fn script_shell(script: &str) -> Option<String> {
    let dir = script_dir(script);
    if dir != "/" {
        for candidate in [
            alloc::format!("{dir}/busybox"),
            alloc::format!("{dir}/bin/busybox"),
        ] {
            if axfs::api::absolute_path_exists(candidate.as_str()) {
                return Some(candidate);
            }
        }
    }

    for candidate in ["/busybox", "/bin/busybox"] {
        if axfs::api::absolute_path_exists(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn group_script_path(dir: &str, group: &str) -> String {
    if dir == "/" {
        alloc::format!("/{group}_testcode.sh")
    } else {
        alloc::format!("{dir}/{group}_testcode.sh")
    }
}

fn generated_group_script_path(dir: &str, group: &str) -> String {
    let runtime = runtime_name(dir);
    alloc::format!("/tmp/.osk_{runtime}_{group}_testcode.sh")
}

fn has_script_path(path: &str) -> bool {
    axfs::api::absolute_path_exists(path) && script_shell(path).is_some()
}

fn runtime_name(dir: &str) -> &str {
    match dir {
        "/glibc" => "glibc",
        "/musl" => "musl",
        "/" => "root",
        other => other.trim_start_matches('/'),
    }
}

fn overwrite_script(path: &str, script: &str) {
    if let Ok(mut file) = File::create(path) {
        let _ = file.write_all(script.as_bytes());
    }
    let _ = axfs::api::set_mode(path, 0o755);
}

fn runtime_ltp_runtest_path(dir: &str) -> Option<String> {
    let candidate = if dir == "/" {
        "/ltp/runtest/syscalls".to_string()
    } else {
        alloc::format!("{dir}/ltp/runtest/syscalls")
    };
    axfs::api::absolute_path_exists(candidate.as_str()).then_some(candidate)
}

fn runtime_ltp_target_dir(dir: &str) -> Option<String> {
    let candidate = if dir == "/" {
        "/ltp/testcases/bin".to_string()
    } else {
        alloc::format!("{dir}/ltp/testcases/bin")
    };
    axfs::api::absolute_path_exists(candidate.as_str()).then_some(candidate)
}

fn runtime_ltp_search_path(dir: &str, target_dir: &str) -> String {
    if dir == "/" {
        alloc::format!("/bin:/sbin:/usr/bin:/usr/sbin:{target_dir}:$PATH")
    } else {
        alloc::format!("{dir}/bin:{dir}/sbin:{dir}/usr/bin:{dir}/usr/sbin:{target_dir}:$PATH")
    }
}

fn runtime_ltp_library_path(dir: &str) -> String {
    if dir == "/" {
        "/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib".to_string()
    } else {
        alloc::format!("{dir}/lib:{dir}/lib64:/lib64:/lib")
    }
}

fn runtime_ltp_script_paths(dir: &str) -> (String, String) {
    let raw_path = if dir == "/" {
        "/.ltp_testcode.sh.raw".to_string()
    } else {
        alloc::format!("{dir}/.ltp_testcode.sh.raw")
    };
    let wrapper_path = group_script_path(dir, "ltp");
    (raw_path, wrapper_path)
}

fn generated_ltp_script_paths(dir: &str) -> (String, String) {
    let runtime = runtime_name(dir);
    (
        alloc::format!("/tmp/.osk_{runtime}_ltp_testcode.sh.raw"),
        generated_group_script_path(dir, "ltp"),
    )
}

fn ensure_runtime_ltp_scripts() {
    for dir in ["/glibc", "/musl", "/"] {
        let Some(runtest_path) = runtime_ltp_runtest_path(dir) else {
            continue;
        };
        let Some(target_dir) = runtime_ltp_target_dir(dir) else {
            continue;
        };
        let (raw_path, wrapper_path) = runtime_ltp_script_paths(dir);
        let (generated_raw_path, generated_wrapper_path) = generated_ltp_script_paths(dir);
        if !axfs::api::absolute_path_exists(raw_path.as_str())
            && !axfs::api::absolute_path_exists(wrapper_path.as_str())
            && !axfs::api::absolute_path_exists(runtest_path.as_str())
        {
            continue;
        }
        let marker = if dir == "/" {
            "ltp".to_string()
        } else {
            alloc::format!("ltp-{}", runtime_name(dir))
        };
        let ltp_root = if dir == "/" {
            "/ltp".to_string()
        } else {
            alloc::format!("{dir}/ltp")
        };
        let runtime_path = runtime_ltp_search_path(dir, target_dir.as_str());
        let runtime_library_path = runtime_ltp_library_path(dir);
        let raw_script = alloc::format!(
            r#"#!/bin/bash

target_dir="{target_dir}"
ltp_root="{ltp_root}"
PATH="{runtime_path}"
export PATH
export LTPROOT="$ltp_root"
export LIBRARY_PATH="{runtime_library_path}"
export LD_LIBRARY_PATH="{runtime_library_path}"
# Keep LTP's per-case max_runtime meaningful. Long cases such as fork13 carry
# their own larger limits; short cases should still time out instead of blocking
# the whole syscall suite.
: "${{LTP_TIMEOUT_MUL:=1}}"
export LTP_TIMEOUT_MUL
: "${{LTP_RUNTIME_MUL:=1}}"
export LTP_RUNTIME_MUL

ltp_should_suppress_line() {{
  case "$1" in
    "tst_memutils.c:152: TINFO: oom_score_adj does not exist, skipping the adjustment"|\
    "tst_test.c:1733: TINFO: LTP version: 20240524"|\
    "tst_test.c:1617: TINFO: Timeout per run is 83h 20m 00s"|\
    "tst_buffers.c:57: TINFO: Test is using guarded buffers"|\
    "precision: 1"|"tolerance: 0"|"mode: 0"|"tick: 10000"|\
    "time_constant: 0"|"esterror: 0"|"maxerror: 0"|"frequency: 0"|\
    "status: 8192 (0x2000)")
      return 0
      ;;
  esac
  return 1
}}

ltp_count_value() {{
  local value="$1"
  case "$value" in
    ""|*[!0-9]*)
      echo 0
      return
      ;;
  esac
  if [ "$value" -gt 10000 ] 2>/dev/null; then
    echo 0
  else
    echo "$value"
  fi
}}

ltp_failure_count_value() {{
  local value="$1"
  case "$value" in
    ""|*[!0-9]*)
      echo 0
      return
      ;;
  esac
  if [ "$value" -gt 10000 ] 2>/dev/null; then
    echo 1
  else
    echo "$value"
  fi
}}

ltp_sanitize_count_line() {{
  local key value
  set -- $1
  key="${{1:-}}"
  value="${{2:-}}"
  case "$key" in
    passed|skipped|warnings)
      printf '%s   %s\n' "$key" "$(ltp_count_value "$value")"
      return 0
      ;;
    failed|broken)
      printf '%s   %s\n' "$key" "$(ltp_failure_count_value "$value")"
      return 0
      ;;
  esac
  return 1
}}

ltp_colorize_result_line() {{
  local marker color prefix suffix
  case "$1" in
    *"TPASS:"*)
      marker="TPASS:"
      color="32"
      ;;
    *"TFAIL:"*|*"TBROK:"*)
      case "$1" in
        *"TFAIL:"*) marker="TFAIL:" ;;
        *) marker="TBROK:" ;;
      esac
      color="31"
      ;;
    *"TCONF:"*)
      marker="TCONF:"
      color="33"
      ;;
    *"TWARN:"*)
      marker="TWARN:"
      color="35"
      ;;
    *)
      return 1
      ;;
  esac
  prefix="${{1%%"$marker"*}}"
  suffix="${{1#*"$marker"}}"
  printf '%s\033[1;%sm%s \033[0m%s\n' "$prefix" "$color" "$marker" "$suffix"
  return 0
}}

ltp_flush_repeated_line() {{
  if [ "$has_prev" -eq 1 ]; then
    echo "$prev_line"
    if [ "$repeat_count" -gt 0 ]; then
      echo "[ltp-repeat] previous line repeated $repeat_count times"
    fi
  fi
  prev_line=""
  repeat_count=0
  has_prev=0
}}

ltp_emit_log_file() {{
  local log_file_path="$1"
  local line prev_line repeat_count=0 has_prev=0 in_summary=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$in_summary" -eq 1 ]; then
      if sanitized_line="$(ltp_sanitize_count_line "$line")" && [ -n "$sanitized_line" ]; then
        echo "$sanitized_line"
      else
        echo "$line"
      fi
      case "$line" in
        warnings*) in_summary=0 ;;
      esac
      continue
    fi
    if ltp_should_suppress_line "$line"; then
      continue
    fi
    if [ "$line" = "Summary:" ]; then
      ltp_flush_repeated_line
      echo "$line"
      in_summary=1
      continue
    fi
    if colorized_line="$(ltp_colorize_result_line "$line")"; then
      line="$colorized_line"
    fi
    if [ "$has_prev" -eq 1 ] && [ "$line" = "$prev_line" ]; then
      repeat_count=$((repeat_count + 1))
      continue
    fi
    ltp_flush_repeated_line
    prev_line="$line"
    repeat_count=0
    has_prev=1
  done < "$log_file_path"
  ltp_flush_repeated_line
}}

run_ltp_case() {{
  local case_name="$1"
  shift
  local log_file="/tmp/.ltp_${{case_name}}_$$.log"
  local case_pid ret log_bytes watchdog_pid case_timeout watchdog_file
  : > "$log_file"

  kill_case_session() {{
    local sig="$1"
    kill "-$sig" "-$case_pid" 2>/dev/null || kill "-$sig" "$case_pid" 2>/dev/null || /busybox kill "-$sig" "-$case_pid" 2>/dev/null || /busybox kill "-$sig" "$case_pid" 2>/dev/null
  }}

  (cd "$target_dir" && /busybox setsid "$@") >"$log_file" 2>&1 &
  case_pid=$!
  watchdog_file="/tmp/.ltp_watchdog_${{case_name}}_${{case_pid}}"
  echo "$case_pid" > "$watchdog_file"
  echo "[osk-ltp-diag] case=$case_name pid=$case_pid phase=started"
  case_timeout="$LTP_CASE_TIMEOUT_SECONDS"
  if [ -z "$case_timeout" ]; then
    case_timeout=180
  fi
  case "$case_name" in
    fork13)
      case_timeout=750
      ;;
    timerfd_settime02)
      case_timeout=240
      ;;
  esac
  /busybox setsid /busybox sh -c '
    timeout="$1"
    pid="$2"
    name="$3"
    marker="$4"
    /busybox sleep "$timeout"
    if [ -f "$marker" ] && [ "$(/busybox cat "$marker" 2>/dev/null)" = "$pid" ] && /busybox kill -0 "$pid" 2>/dev/null; then
      echo "[osk-ltp-diag] case=$name phase=watchdog-timeout seconds=$timeout"
      /busybox kill -TERM "-$pid" 2>/dev/null || /busybox kill -TERM "$pid" 2>/dev/null || true
      /busybox sleep 1
      /busybox kill -KILL "-$pid" 2>/dev/null || /busybox kill -KILL "$pid" 2>/dev/null || true
    fi
  ' ltp-case-watchdog "$case_timeout" "$case_pid" "$case_name" "$watchdog_file" &
  watchdog_pid=$!
  wait "$case_pid"
  ret=$?
  /busybox rm -f "$watchdog_file"
  /busybox kill -TERM "-$watchdog_pid" 2>/dev/null || /busybox kill "$watchdog_pid" 2>/dev/null || true
  /busybox kill -KILL "-$watchdog_pid" 2>/dev/null || true
  wait "$watchdog_pid" 2>/dev/null || true
  log_bytes=$(/busybox wc -c < "$log_file" 2>/dev/null || echo -1)
  echo "[osk-ltp-diag] case=$case_name phase=wait-done ret=$ret log_bytes=$log_bytes"
  kill_case_session TERM
  kill_case_session KILL
  ltp_emit_log_file "$log_file"

  local failed=0 broken=0 skipped=0 in_summary=0 line
  while IFS= read -r line; do
    case "$line" in
      Summary:)
        in_summary=1
        ;;
      failed*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          failed="${{2:-0}}"
          case "$failed" in
            ""|*[!0-9]*) failed=0 ;;
          esac
          if [ "$failed" -gt 10000 ] 2>/dev/null; then
            failed=1
          fi
        fi
        ;;
      broken*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          broken="${{2:-0}}"
          case "$broken" in
            ""|*[!0-9]*) broken=0 ;;
          esac
          if [ "$broken" -gt 10000 ] 2>/dev/null; then
            broken=1
          fi
        fi
        ;;
      skipped*)
        if [ "$in_summary" -eq 1 ]; then
          set -- $line
          skipped="${{2:-0}}"
          case "$skipped" in
            ""|*[!0-9]*) skipped=0 ;;
          esac
          if [ "$skipped" -gt 10000 ] 2>/dev/null; then
            skipped=0
          fi
        fi
        ;;
    esac
  done < "$log_file"
  echo "[osk-ltp-diag] case=$case_name phase=summary failed=$failed broken=$broken skipped=$skipped ret=$ret log_bytes=$log_bytes"
  if [ "$ret" -eq 0 ] && [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ]; then
    echo "PASS LTP CASE $case_name : 0"
    echo "FAIL LTP CASE $case_name : 0"
  elif [ "$failed" -eq 0 ] && [ "$broken" -eq 0 ] && [ "$skipped" -gt 0 ]; then
    echo "SKIP LTP CASE $case_name : $ret"
    echo "FAIL LTP CASE $case_name : $ret"
  else
    echo "FAIL LTP CASE $case_name : $ret"
  fi
  /busybox rm -f "$log_file"
  /busybox rm -f "$watchdog_file"
}}

while IFS= read -r line; do
  case "$line" in
    ""|\#*) continue ;;
  esac

  set -- $line
  name=$1
  shift

  echo "RUN LTP CASE $name"
  run_ltp_case "$name" "$@"
done < {runtest_path}
exit 0
"#
        );
        let wrapper_script = alloc::format!(
            "#!/busybox sh\n/busybox echo \"#### OS COMP TEST GROUP START {marker} ####\"\n/busybox sh {raw_path}\nstatus=$?\n/busybox echo \"#### OS COMP TEST GROUP END {marker} ####\"\nexit $status\n"
        );
        let generated_wrapper_script = alloc::format!(
            "#!/busybox sh\n/busybox echo \"#### OS COMP TEST GROUP START {marker} ####\"\n/busybox sh {generated_raw_path}\nstatus=$?\n/busybox echo \"#### OS COMP TEST GROUP END {marker} ####\"\nexit $status\n"
        );
        overwrite_script(generated_raw_path.as_str(), raw_script.as_str());
        overwrite_script(
            generated_wrapper_path.as_str(),
            generated_wrapper_script.as_str(),
        );
        overwrite_script(raw_path.as_str(), raw_script.as_str());
        overwrite_script(wrapper_path.as_str(), wrapper_script.as_str());
    }
}

fn should_schedule_group(runtime: &str, group: &str) -> bool {
    let Ok(raw) = axfs::api::read(OFFICIAL_ALLOWED_GROUPS_PATH) else {
        return true;
    };
    let Ok(text) = core::str::from_utf8(&raw) else {
        return true;
    };
    let expected = alloc::format!("{runtime}:{group}");
    text.lines().any(|line| line.trim() == expected)
}

fn should_schedule_group_any_runtime(group: &str) -> bool {
    RUNTIME_SCRIPT_DIRS
        .iter()
        .map(|dir| runtime_name(dir))
        .any(|runtime| should_schedule_group(runtime, group))
}

fn contest_schedule_start_index() -> usize {
    let Ok(raw) = axfs::api::read(OFFICIAL_ALLOWED_GROUPS_PATH) else {
        return CONTEST_GROUPS
            .iter()
            .position(|group| group == &"ltp")
            .unwrap_or(0);
    };
    let Ok(text) = core::str::from_utf8(&raw) else {
        return CONTEST_GROUPS
            .iter()
            .position(|group| group == &"ltp")
            .unwrap_or(0);
    };
    CONTEST_GROUPS
        .iter()
        .position(|group| {
            text.lines().any(|line| {
                let trimmed = line.trim();
                trimmed
                    .split_once(':')
                    .map(|(_runtime, allowed_group)| allowed_group == *group)
                    .unwrap_or(false)
            })
        })
        .or_else(|| CONTEST_GROUPS.iter().position(|group| group == &"ltp"))
        .unwrap_or(0)
}

fn copy_file_if_missing(src: &str, dst: &str) {
    if src == dst || axfs::api::absolute_path_exists(dst) || !axfs::api::absolute_path_exists(src) {
        return;
    }
    let Ok(data) = axfs::api::read(src) else {
        return;
    };
    if let Ok(mut file) = File::create(dst) {
        let _ = file.write_all(&data);
    }
}

fn copy_first_existing(dst: &str, srcs: &[&str]) {
    if axfs::api::absolute_path_exists(dst) {
        return;
    }
    for src in srcs {
        if axfs::api::absolute_path_exists(src) {
            copy_file_if_missing(src, dst);
            if axfs::api::absolute_path_exists(dst) {
                return;
            }
        }
    }
}

fn write_script_if_missing(path: &str, script: &str) {
    if axfs::api::absolute_path_exists(path) {
        return;
    }
    if let Ok(mut file) = File::create(path) {
        let _ = file.write_all(script.as_bytes());
    }
    let _ = axfs::api::set_mode(path, 0o755);
}

fn ensure_parent_dirs(path: &str) {
    let Some((parent, _)) = path.rsplit_once('/') else {
        return;
    };
    if parent.is_empty() {
        return;
    }

    let mut current = String::from("/");
    for component in parent.split('/').filter(|component| !component.is_empty()) {
        if current.len() > 1 {
            current.push('/');
        }
        current.push_str(component);
        if !axfs::api::absolute_path_exists(current.as_str()) {
            let _ = axfs::api::create_dir(current.as_str());
        }
    }
}

fn write_binary(path: &str, data: &[u8], executable: bool) {
    if data.is_empty() {
        return;
    }
    ensure_parent_dirs(path);
    #[cfg(target_arch = "loongarch64")]
    if data.len() >= 1024 * 1024 {
        warn!(
            "seed large embedded file start path={} size={} now_ms={}",
            path,
            data.len(),
            monotonic_time_nanos() / 1_000_000
        );
    }
    if let Ok(mut file) = File::create(path) {
        let _ = file.write_all(data);
    }
    if executable {
        let _ = axfs::api::set_mode(path, 0o755);
    }
    #[cfg(target_arch = "loongarch64")]
    if data.len() >= 1024 * 1024 {
        warn!(
            "seed large embedded file done path={} size={} now_ms={}",
            path,
            data.len(),
            monotonic_time_nanos() / 1_000_000
        );
    }
}

enum EmbeddedRuntimeSeedResult {
    Skipped,
    Created,
    Refreshed,
}

fn seed_embedded_runtime_file(
    file: &embedded_runtime::EmbeddedRuntimeFile,
) -> EmbeddedRuntimeSeedResult {
    if file.data.is_empty() || !should_seed_embedded_runtime_file(file.path) {
        if file.executable && axfs::api::absolute_path_exists(file.path) {
            let _ = axfs::api::set_mode(file.path, 0o755);
        }
        return EmbeddedRuntimeSeedResult::Skipped;
    }

    if axfs::api::absolute_path_exists(file.path) {
        if !file.refresh_if_exists {
            if file.executable {
                let _ = axfs::api::set_mode(file.path, 0o755);
            }
            return EmbeddedRuntimeSeedResult::Skipped;
        }
        if let Ok(existing) = axfs::api::read(file.path) {
            if existing == file.data {
                if file.executable {
                    let _ = axfs::api::set_mode(file.path, 0o755);
                }
                return EmbeddedRuntimeSeedResult::Skipped;
            }
        }
        write_binary(file.path, file.data, file.executable);
        return EmbeddedRuntimeSeedResult::Refreshed;
    }

    write_binary(file.path, file.data, file.executable);
    EmbeddedRuntimeSeedResult::Created
}

fn should_seed_embedded_runtime_file(path: &str) -> bool {
    match path {
        "/lib/ld-musl-loongarch64.so.1" => {
            !axfs::api::absolute_path_exists("/musl/lib/ld-musl-loongarch64.so.1")
                && !axfs::api::absolute_path_exists("/musl/lib64/ld-musl-loongarch-lp64d.so.1")
        }
        "/lib64/ld-musl-loongarch-lp64d.so.1" => {
            !axfs::api::absolute_path_exists("/musl/lib64/ld-musl-loongarch-lp64d.so.1")
                && !axfs::api::absolute_path_exists("/musl/lib/ld-musl-loongarch64.so.1")
        }
        "/lib/ld-musl-riscv64.so.1" | "/lib/ld-musl-riscv64-sf.so.1" => {
            !axfs::api::absolute_path_exists("/musl/lib/ld-musl-riscv64.so.1")
                && !axfs::api::absolute_path_exists("/musl/lib/ld-musl-riscv64-sf.so.1")
        }
        "/lib/libc.so" | "/lib64/libc.so" => {
            !axfs::api::absolute_path_exists("/musl/lib/libc.so")
                && !axfs::api::absolute_path_exists("/musl/lib64/libc.so")
        }
        _ => true,
    }
}

fn ensure_busybox_applets(applets: &[&str], dirs: &[&str]) {
    if !axfs::api::absolute_path_exists("/busybox") {
        return;
    }
    for dir in dirs {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
        for applet in applets {
            let path = alloc::format!("{dir}/{applet}");
            if axfs::api::absolute_path_exists(path.as_str()) {
                continue;
            }
            let script = if *applet == "busybox" {
                "#!/busybox sh\nexec /busybox \"$@\"\n".to_string()
            } else {
                alloc::format!("#!/busybox sh\nexec /busybox {applet} \"$@\"\n")
            };
            write_script_if_missing(path.as_str(), script.as_str());
        }
    }
}

fn ensure_runtime_command_wrapper(path: &str, command: &str) {
    let script = alloc::format!("#!/busybox sh\nexec {command} \"$@\"\n");
    write_script_if_missing(path, script.as_str());
}

fn ensure_lmbench_runtime_compat() {
    for dir in [
        "/code",
        "/code/lmbench_src",
        "/code/lmbench_src/bin",
        "/code/lmbench_src/bin/build",
    ] {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
    }

    write_script_if_missing(
        "/code/lmbench_src/bin/build/lmbench_all",
        r#"#!/busybox sh
for candidate in /glibc/lmbench_all /musl/lmbench_all /lmbench_all
do
    if [ -x "$candidate" ]; then
        exec "$candidate" "$@"
    fi
done
exit 127
"#,
    );
    let _ = axfs::api::set_mode("/code/lmbench_src/bin/build/lmbench_all", 0o755);

    copy_first_existing("/hello", &["/glibc/hello", "/musl/hello"]);
    copy_first_existing("/tmp/hello", &["/hello", "/glibc/hello", "/musl/hello"]);
    copy_first_existing(
        "/tmp/hello-s",
        &["/hello-s", "/glibc/hello-s", "/musl/hello-s"],
    );

    let has_lmbench = ["/glibc/lmbench_all", "/musl/lmbench_all", "/lmbench_all"]
        .into_iter()
        .any(axfs::api::absolute_path_exists);
    if has_lmbench && !axfs::api::absolute_path_exists("/tmp/hello") {
        write_script_if_missing("/tmp/hello", "#!/busybox sh\nexit 0\n");
    }
    if has_lmbench && !axfs::api::absolute_path_exists("/tmp/hello-s") {
        write_script_if_missing("/tmp/hello-s", "#!/busybox sh\nexit 0\n");
    }
    for path in ["/hello", "/tmp/hello", "/tmp/hello-s"] {
        if axfs::api::absolute_path_exists(path) {
            let _ = axfs::api::set_mode(path, 0o755);
        }
    }
}

fn ensure_busybox_root() {
    let backing = [
        "/busybox",
        "/glibc/busybox",
        "/musl/busybox",
        "/bin/busybox",
    ]
    .into_iter()
    .find(|path| *path != "/busybox" && axfs::api::absolute_path_exists(path))
    .unwrap_or("/busybox");

    if !axfs::api::absolute_path_exists("/busybox")
        && backing != "/busybox"
        && axfs::api::absolute_path_exists(backing)
    {
        let script = alloc::format!("#!{backing} sh\nexec {backing} \"$@\"\n");
        write_script_if_missing("/busybox", script.as_str());
    }
    if !axfs::api::absolute_path_exists("/bin/busybox") && axfs::api::absolute_path_exists(backing)
    {
        let script = alloc::format!("#!{backing} sh\nexec {backing} \"$@\"\n");
        write_script_if_missing("/bin/busybox", script.as_str());
    }
}

fn ensure_runtime_busybox_binary(dst: &str) {
    if axfs::api::absolute_path_exists(dst) {
        let _ = axfs::api::set_mode(dst, 0o755);
        return;
    }

    for src in [
        "/busybox",
        "/bin/busybox",
        "/glibc/busybox",
        "/musl/busybox",
    ] {
        if src == dst || !axfs::api::absolute_path_exists(src) {
            continue;
        }
        copy_file_if_missing(src, dst);
        if axfs::api::absolute_path_exists(dst) {
            let _ = axfs::api::set_mode(dst, 0o755);
            return;
        }
    }
}

fn mirror_runtime_file(path: &str) {
    let Some(name) = path.rsplit('/').next() else {
        return;
    };
    if name.is_empty() {
        return;
    }
    if !axfs::api::absolute_path_exists(path) {
        for src in [
            alloc::format!("/musl/{name}"),
            alloc::format!("/glibc/{name}"),
        ] {
            copy_file_if_missing(src.as_str(), path);
            if axfs::api::absolute_path_exists(path) {
                break;
            }
        }
    }
    for dir in ["/musl", "/glibc"] {
        if !axfs::api::absolute_path_exists(dir) {
            continue;
        }
        let dst = alloc::format!("{dir}/{name}");
        copy_file_if_missing(path, dst.as_str());
    }
}

fn ensure_runtime_library_dirs() {
    for dir in ["/lib", "/lib64"] {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
    }
}

fn ensure_glibc_locale_tree() {
    let base = "/usr/lib/locale/C.utf8";
    let nested = "/usr/lib/locale/C.utf8/C.utf8";
    let alias_base = "/usr/lib/locale/C.UTF-8";
    let alias_nested = "/usr/lib/locale/C.UTF-8/C.UTF-8";
    for dir in [
        "/usr/lib",
        "/usr/lib/locale",
        base,
        nested,
        "/usr/lib/locale/C.utf8/LC_MESSAGES",
        "/usr/lib/locale/C.utf8/C.utf8/LC_MESSAGES",
        alias_base,
        alias_nested,
        "/usr/lib/locale/C.UTF-8/LC_MESSAGES",
        "/usr/lib/locale/C.UTF-8/C.UTF-8/LC_MESSAGES",
    ] {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
    }

    for rel in [
        "LC_ADDRESS",
        "LC_COLLATE",
        "LC_CTYPE",
        "LC_IDENTIFICATION",
        "LC_MEASUREMENT",
        "LC_MESSAGES/SYS_LC_MESSAGES",
        "LC_MONETARY",
        "LC_NAME",
        "LC_NUMERIC",
        "LC_PAPER",
        "LC_TELEPHONE",
        "LC_TIME",
    ] {
        let top = alloc::format!("{base}/{rel}");
        let duplicate = alloc::format!("{nested}/{rel}");
        let alias = alloc::format!("{alias_base}/{rel}");
        let alias_duplicate = alloc::format!("{alias_nested}/{rel}");
        copy_first_existing(top.as_str(), &[duplicate.as_str()]);
        copy_file_if_missing(top.as_str(), duplicate.as_str());
        copy_first_existing(alias.as_str(), &[top.as_str(), duplicate.as_str()]);
        copy_file_if_missing(alias.as_str(), alias_duplicate.as_str());
    }
}

fn seed_systemd_detect_virt() {
    let script = r#"#!/busybox sh
if [ -n "$LTP_VIRT_OVERRIDE" ]; then
    echo "$LTP_VIRT_OVERRIDE"
    exit 0
fi

if [ -r /proc/cpuinfo ] && /bin/grep -q "QEMU Virtual CPU" /proc/cpuinfo 2>/dev/null; then
    echo qemu
    exit 0
fi

exit 1
"#;

    for path in [
        "/bin/systemd-detect-virt",
        "/usr/bin/systemd-detect-virt",
        "/usr/sbin/systemd-detect-virt",
        "/ltp/testcases/bin/systemd-detect-virt",
        "/glibc/ltp/testcases/bin/systemd-detect-virt",
        "/musl/ltp/testcases/bin/systemd-detect-virt",
    ] {
        write_script_if_missing(path, script);
    }
}

type LoadedUserProgram = (VirtAddr, VirtAddr, VirtAddr, usize, usize);

fn try_load_user_program(
    program_path: &str,
    args: &[String],
) -> AxResult<(axmm::AddrSpace, LoadedUserProgram)> {
    task::prepare_runtime_for_exec("boot_exec_prepare", program_path);
    let mut uspace = axmm::new_user_aspace(
        VirtAddr::from_usize(axconfig::plat::USER_SPACE_BASE),
        axconfig::plat::USER_SPACE_SIZE,
    )
    .map_err(|_| AxError::NoMemory)?;
    let env = mm::runtime_env_for(program_path);
    let mut argv = VecDeque::from(args.to_vec());
    let loaded = mm::load_user_app(program_path, &mut argv, &env, &mut uspace)?;
    Ok((uspace, loaded))
}

fn run_user_program(args: Vec<String>) -> AxResult<Option<i32>> {
    let argc = args.len();
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    let _ = argc;
    let program_path = args
        .first()
        .cloned()
        .unwrap_or_else(|| String::from("<unknown>"));
    let display_name = args
        .last()
        .cloned()
        .unwrap_or_else(|| String::from("<unknown>"));
    let (uspace, (entry_vaddr, ustack_top, heap_bottom, user_tp, exec_image_base)) =
        match try_load_user_program(&program_path, &args) {
            Ok(loaded) => loaded,
            Err(AxError::NoMemory) => {
                emit_online_task_memory_diag(
                    "user-program",
                    "load-nomem",
                    program_path.as_str(),
                    0,
                );
                let (reclaimed_stack_pages, reclaimed_exec_cache_pages) =
                    task::reclaim_runtime_memory("boot_run_user_program");
                if reclaimed_stack_pages > 0 || reclaimed_exec_cache_pages > 0 {
                    warn!(
                        "retry load after reclaim: program={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={}",
                        program_path, reclaimed_stack_pages, reclaimed_exec_cache_pages
                    );
                }
                try_load_user_program(&program_path, &args).map_err(|err| {
                    error!(
                        "Failed to load app after reclaim: program={} err={:?}",
                        program_path, err
                    );
                    err
                })?
            }
            Err(err) => {
                error!("Failed to load app {}: {:?}", program_path, err);
                return Err(err);
            }
        };
    let mut uctx = UspaceContext::new(entry_vaddr.into(), ustack_top, 0);
    #[cfg(not(any(target_arch = "loongarch64", target_arch = "riscv64")))]
    {
        let argv_ptr = ustack_top.as_usize() + core::mem::size_of::<usize>();
        uctx.set_retval(argc);
        uctx.set_arg1(argv_ptr);
        uctx.set_arg2(ustack_top.as_usize() + (argc + 2) * core::mem::size_of::<usize>());
    }
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        if user_tp != 0 {
            uctx.set_thread_pointer(user_tp);
        }
    }
    let user_task = task::spawn_user_task(
        Arc::new(Mutex::new(uspace)),
        uctx,
        heap_bottom.as_usize() as u64,
        exec_image_base as u64,
        mm::absolute_exec_path(&program_path),
    )?;
    task::set_competition_script_root(Some(user_task.clone()));
    let exit_code = user_task.join();
    let cleaned = task::kill_current_competition_script_tree(SIGKILL_SIGNUM);
    task::set_competition_script_root(None);
    warn!(
        "[online-diag] kind=user-program phase=exit program={} display={} exit_code={:?} cleaned_tasks={}",
        program_path, display_name, exit_code, cleaned
    );
    if cleaned > 1 {
        warn!(
            "Cleaned residual script tasks after exit: program={} tasks={}",
            program_path, cleaned
        );
    }
    info!(
        "User task {} exited with code: {:?}",
        display_name, exit_code
    );
    Ok(exit_code)
}

fn run_test_script(script: String) {
    let Some(shell) = script_shell(script.as_str()) else {
        warn!("Skip test script without busybox shell: {}", script);
        return;
    };

    *COMPETITION_WATCHDOG_SCRIPT.lock() = Some(script.clone());
    let watchdog_token = arm_script_watchdog(script.as_str());
    let script_dir = script_dir(script.as_str()).to_string();
    let prev_cwd = axfs::api::current_dir().ok();
    if let Err(err) = axfs::api::set_current_dir(script_dir.as_str()) {
        warn!(
            "Failed to change cwd for test script {} to {}: {:?}",
            script, script_dir, err
        );
    }
    warn!(
        "boot stage start script={} now_ms={}",
        script,
        monotonic_time_nanos() / 1_000_000
    );
    emit_online_task_memory_diag("script", "start", script.as_str(), 0);
    match run_user_program(vec![shell, "sh".to_string(), script.clone()]) {
        Ok(exit_code) => {
            task::reclaim_runtime_memory_detail("script_end");
            emit_online_task_memory_diag("script", "end", script.as_str(), 0);
            warn!(
                "[online-diag] kind=script phase=exit path={} exit_code={:?}",
                script, exit_code
            );
        }
        Err(err) => {
            task::reclaim_runtime_memory_detail("script_start_failed");
            emit_online_task_memory_diag("script", "start-failed", script.as_str(), 0);
            warn!("Failed to start test script {}: {:?}", script, err);
        }
    }
    if let Some(prev_cwd) = prev_cwd {
        let _ = axfs::api::set_current_dir(prev_cwd.as_str());
    }
    disarm_script_watchdog(watchdog_token);
}

fn maybe_run_direct_command() -> bool {
    let path = "/.__osk_direct_run__";
    if !axfs::api::absolute_path_exists(path) {
        return false;
    }
    let Ok(mut file) = File::open(path) else {
        warn!("Failed to open direct-run command file: {}", path);
        return false;
    };
    let mut content = String::new();
    if file.read_to_string(&mut content).is_err() {
        warn!("Failed to read direct-run command file: {}", path);
        return false;
    }
    let args: Vec<String> = content
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect();
    if args.is_empty() {
        warn!("Empty direct-run command file: {}", path);
        return false;
    }
    warn!("Running direct command: {:?}", args);
    if let Err(err) = run_user_program(args.clone()) {
        warn!("Direct command failed to start {:?}: {:?}", args, err);
    }
    true
}

fn discover_test_scripts() -> Option<Vec<String>> {
    let mut ordered = Vec::new();
    let mut found_groups = [false; CONTEST_GROUPS.len()];
    let start_index = contest_schedule_start_index();
    let start_group = CONTEST_GROUPS.get(start_index).copied().unwrap_or("ltp");
    warn!(
        "Contest scheduler starts from contest group: {}",
        start_group
    );
    for dir in RUNTIME_SCRIPT_DIRS {
        let runtime = runtime_name(dir);
        for (group_index, group) in CONTEST_GROUPS.iter().enumerate().skip(start_index) {
            if !should_schedule_group(runtime, group) {
                warn!("Skip contest group by scheduler policy: runtime={runtime} group={group}");
                continue;
            }
            let generated_path = generated_group_script_path(dir, group);
            let path =
                if group == &"ltp" && axfs::api::absolute_path_exists(generated_path.as_str()) {
                    generated_path
                } else {
                    group_script_path(dir, group)
                };
            if has_script_path(path.as_str()) {
                ordered.push(path);
                found_groups[group_index] = true;
            }
        }
    }
    for (group_index, group) in CONTEST_GROUPS.iter().enumerate().skip(start_index) {
        if !should_schedule_group_any_runtime(group) {
            continue;
        }
        if found_groups[group_index] {
            continue;
        }
        let root_path = group_script_path("/", group);
        if has_script_path(root_path.as_str()) {
            ordered.push(root_path);
        }
    }
    (!ordered.is_empty()).then_some(ordered)
}

fn seed_runtime_files() {
    const SEEDED_KERNEL_CONFIG: &str = "\
CONFIG_64BIT=y\n\
CONFIG_MMU=y\n\
CONFIG_PROC_FS=y\n\
CONFIG_TMPFS=y\n\
CONFIG_SHMEM=y\n\
CONFIG_SYSVIPC=y\n\
CONFIG_EVENTFD=y\n\
CONFIG_AIO=y\n\
CONFIG_TIME_NS=y\n\
CONFIG_BSD_PROCESS_ACCT=y\n\
CONFIG_HAVE_ARCH_MMAP_RND_COMPAT_BITS=y\n\
CONFIG_ARCH_MMAP_RND_BITS_MIN=18\n\
CONFIG_ARCH_MMAP_RND_COMPAT_BITS_MIN=8\n\
# CONFIG_RPS is not set\n\
# CONFIG_HUGETLBFS is not set\n\
# CONFIG_BSD_PROCESS_ACCT_V3 is not set\n\
# CONFIG_PREEMPT_RT is not set\n\
# CONFIG_PREEMPT_RT_FULL is not set\n\
# CONFIG_MODULES is not set\n";

    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=cleanup now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    for stale_path in [
        "/test_dir",
        "/test",
        "/test.txt",
        "/busybox_cmd.bak",
        "/basic/test_mkdir",
        "/basic/test_chdir",
    ] {
        let _ = axfs::api::remove_file(stale_path);
        let _ = axfs::api::remove_dir(stale_path);
    }

    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=mkdir-runtime now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    for dir in [
        "/etc",
        "/home",
        "/proc",
        "/proc/self",
        "/proc/1",
        "/proc/self/ns",
        "/proc/1/ns",
        "/proc/sys",
        "/proc/sysvipc",
        "/proc/sys/fs",
        "/proc/sys/kernel",
        "/proc/sys/kernel/keys",
        "/tmp",
        "/var",
        "/var/tmp",
        "/lib",
        "/lib64",
        "/bin",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib/locale",
        "/usr/lib/locale/C.utf8",
        "/usr/lib/locale/C.utf8/C.utf8",
        "/usr/lib/locale/C.utf8/LC_MESSAGES",
        "/usr/lib/locale/C.utf8/C.utf8/LC_MESSAGES",
        "/usr/lib/locale/C.UTF-8",
        "/usr/lib/locale/C.UTF-8/C.UTF-8",
        "/usr/lib/locale/C.UTF-8/LC_MESSAGES",
        "/usr/lib/locale/C.UTF-8/C.UTF-8/LC_MESSAGES",
        "/usr/sbin",
        "/dev",
        "/dev/misc",
        "/boot",
        "/musl",
        "/musl/ltp",
        "/musl/ltp/testcases",
        "/musl/ltp/testcases/bin",
        "/musl/lib",
        "/musl/lib64",
        "/glibc",
        "/glibc/ltp",
        "/glibc/ltp/runtest",
        "/glibc/ltp/testcases",
        "/glibc/ltp/testcases/bin",
        "/glibc/lib",
        "/glibc/lib64",
        "/ltp",
        "/ltp/runtest",
        "/ltp/testcases",
        "/ltp/testcases/bin",
    ] {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
    }

    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=mkdir-system now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    for dir in [
        "/lib/modules",
        "/lib/modules/10.0.0",
        "/lib/modules/10.0.0/build",
        "/sys/fs",
        "/sys/fs/cgroup",
    ] {
        if !axfs::api::absolute_path_exists(dir) {
            let _ = axfs::api::create_dir(dir);
        }
    }

    for (path, contents) in [
        ("/sys/fs/cgroup/cgroup.procs", ""),
        ("/sys/fs/cgroup/cgroup.subtree_control", ""),
        ("/sys/fs/cgroup/cgroup.controllers", "memory\n"),
    ] {
        if !axfs::api::absolute_path_exists(path) {
            let _ = axfs::api::write(path, contents);
        }
    }

    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=embedded now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    let mut embedded_created = 0usize;
    let mut embedded_refreshed = 0usize;
    for file in embedded_runtime::EMBEDDED_RUNTIME_FILES {
        match seed_embedded_runtime_file(file) {
            EmbeddedRuntimeSeedResult::Created => embedded_created += 1,
            EmbeddedRuntimeSeedResult::Refreshed => embedded_refreshed += 1,
            EmbeddedRuntimeSeedResult::Skipped => {}
        }
    }
    warn!(
        "[embedded-runtime-sync] created={} refreshed={}",
        embedded_created, embedded_refreshed
    );
    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=embedded-done now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    ensure_busybox_root();
    ensure_runtime_busybox_binary("/glibc/busybox");
    ensure_runtime_busybox_binary("/musl/busybox");
    ensure_runtime_busybox_binary("/busybox");
    ensure_runtime_busybox_binary("/bin/busybox");
    ensure_lmbench_runtime_compat();
    ensure_runtime_library_dirs();
    ensure_glibc_locale_tree();
    #[cfg(target_arch = "loongarch64")]
    warn!(
        "seed_runtime_files phase=proc-files now_ms={}",
        monotonic_time_nanos() / 1_000_000
    );
    let files = [
        (
            "/proc/mounts",
            "rootfs / rootfs rw 0 0\ndevfs /dev devfs rw 0 0\ntmpfs /dev/shm tmpfs rw 0 0\nproc /proc proc rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
        ),
        (
            "/proc/meminfo",
            "MemTotal:       262144 kB\nMemFree:        196608 kB\nMemAvailable:   196608 kB\nBuffers:             0 kB\nCached:              0 kB\nSwapTotal:           0 kB\nSwapFree:            0 kB\n",
        ),
        (
            "/proc/cpuinfo",
            "processor\t: 0\n\
hart\t\t: 0\n\
model name\t: QEMU Virtual CPU\n\
cpu cores\t: 1\n\
siblings\t: 1\n\
physical id\t: 0\n\
isa\t\t: rv64imafdch\n\
mmu\t\t: sv39\n",
        ),
        ("/proc/cmdline", "module.sig_enforce=0\n"),
        ("/proc/loadavg", "0.00 0.00 0.00 1/1 1\n"),
        ("/proc/uptime", "9.00 9.00\n"),
        ("/proc/stat", "cpu  0 0 0 0 0 0 0 0 0 0\n"),
        (
            "/proc/self/stat",
            "1 (busybox) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        ),
        (
            "/proc/1/stat",
            "1 (busybox) R 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
        ),
        ("/proc/self/timens_offsets", "1 0 0\n7 0 0\n"),
        ("/proc/self/ns/time_for_children", "time:[0]\n"),
        ("/proc/self/coredump_filter", "00000033\n"),
        (
            "/proc/sysvipc/shm",
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime\n",
        ),
        (
            "/proc/sysvipc/msg",
            "       key      msqid perms                  cbytes      qnum   lspid   lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
        ),
        (
            "/proc/sysvipc/sem",
            "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n",
        ),
        ("/proc/sys/fs/aio-max-nr", "65536\n"),
        ("/proc/sys/fs/aio-nr", "0\n"),
        ("/proc/sys/fs/lease-break-time", "45\n"),
        ("/proc/sys/kernel/core_pattern", "core\n"),
        ("/proc/sys/kernel/core_uses_pid", "0\n"),
        ("/proc/sys/kernel/pid_max", "32768\n"),
        ("/proc/sys/kernel/ns_last_pid", "1\n"),
        ("/proc/sys/kernel/shmmax", "1073741824\n"),
        ("/proc/sys/kernel/shmmni", "4096\n"),
        ("/proc/sys/kernel/shm_next_id", "-1\n"),
        ("/proc/sys/kernel/msgmni", "4096\n"),
        ("/proc/sys/kernel/msg_next_id", "-1\n"),
        ("/proc/sys/kernel/tainted", "0\n"),
        ("/proc/sys/kernel/keys/root_maxkeys", "1000\n"),
        ("/proc/sys/kernel/keys/root_maxbytes", "25000000\n"),
        ("/proc/sys/kernel/keys/maxkeys", "1000\n"),
        ("/proc/sys/kernel/keys/maxbytes", "25000000\n"),
        ("/proc/sys/kernel/keys/gc_delay", "5\n"),
        (
            "/etc/passwd",
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/bin/sh\n",
        ),
        (
            "/etc/group",
            "root:x:0:\ndaemon:x:1:\nusers:x:100:\nnogroup:x:65534:\nnobody:x:65534:\n",
        ),
        ("/etc/hosts", "127.0.0.1 localhost\n"),
        (
            "/etc/nsswitch.conf",
            "passwd: files\n\
group: files\n\
hosts: files dns\n\
networks: files dns\n\
protocols: files\n\
services: files\n",
        ),
        (
            "/etc/protocols",
            "ip 0 IP\nicmp 1 ICMP\ntcp 6 TCP\nudp 17 UDP\n",
        ),
        (
            "/etc/services",
            "discard 9/tcp sink null\ndiscard 9/udp sink null\n",
        ),
    ];
    for (path, content) in files {
        if let Ok(mut file) = File::create(path) {
            let _ = file.write_all(content.as_bytes());
        }
    }
    write_script_if_missing(
        "/usr/sbin/useradd",
        r#"#!/bin/sh
set -e
user="$1"
[ -n "$user" ] || exit 1
mkdir -p /etc /home
[ -f /etc/passwd ] || printf 'root:x:0:0:root:/root:/bin/sh\n' >/etc/passwd
[ -f /etc/group ] || printf 'root:x:0:\n' >/etc/group
[ -f /etc/shadow ] || printf 'root:*:0:0:99999:7:::\n' >/etc/shadow
grep -q "^${user}:" /etc/passwd 2>/dev/null && exit 0
uid=1000
while grep -q "^[^:]*:[^:]*:${uid}:" /etc/passwd 2>/dev/null || grep -q "^[^:]*:[^:]*:${uid}:" /etc/group 2>/dev/null
do
    uid=$((uid + 1))
done
printf '%s:x:%s:%s:%s:/home/%s:/bin/sh\n' "$user" "$uid" "$uid" "$user" "$user" >>/etc/passwd
printf '%s:x:%s:\n' "$user" "$uid" >>/etc/group
printf '%s:*:0:0:99999:7:::\n' "$user" >>/etc/shadow
mkdir -p "/home/$user"
exit 0
"#,
    );
    write_script_if_missing(
        "/usr/sbin/userdel",
        r#"#!/bin/sh
set -e
remove_home=0
if [ "$1" = "-r" ]; then
    remove_home=1
    shift
fi
user="$1"
[ -n "$user" ] || exit 1
for f in /etc/passwd /etc/group /etc/shadow
do
    if [ -f "$f" ]; then
        grep -v "^${user}:" "$f" > "${f}.tmp" || true
        mv "${f}.tmp" "$f"
    fi
done
if [ "$remove_home" = "1" ]; then
    rm -rf "/home/$user"
fi
exit 0
"#,
    );
    write_script_if_missing(
        "/usr/sbin/groupdel",
        r#"#!/bin/sh
set -e
group="$1"
[ -n "$group" ] || exit 1
if [ -f /etc/group ]; then
    grep -v "^${group}:" /etc/group > /etc/group.tmp || true
    mv /etc/group.tmp /etc/group
fi
exit 0
"#,
    );
    for (src, dst) in [
        ("/usr/sbin/useradd", "/glibc/ltp/testcases/bin/useradd"),
        ("/usr/sbin/useradd", "/ltp/testcases/bin/useradd"),
        ("/usr/sbin/useradd", "/bin/useradd"),
        ("/usr/sbin/useradd", "/usr/bin/useradd"),
        ("/usr/sbin/userdel", "/glibc/ltp/testcases/bin/userdel"),
        ("/usr/sbin/userdel", "/ltp/testcases/bin/userdel"),
        ("/usr/sbin/userdel", "/bin/userdel"),
        ("/usr/sbin/userdel", "/usr/bin/userdel"),
        ("/usr/sbin/groupdel", "/glibc/ltp/testcases/bin/groupdel"),
        ("/usr/sbin/groupdel", "/ltp/testcases/bin/groupdel"),
        ("/usr/sbin/groupdel", "/bin/groupdel"),
        ("/usr/sbin/groupdel", "/usr/bin/groupdel"),
    ] {
        copy_file_if_missing(src, dst);
        let _ = axfs::api::set_mode(dst, 0o755);
    }
    copy_first_existing(
        "/ltp/runtest/syscalls",
        &["/glibc/ltp/runtest/syscalls", "/musl/ltp/runtest/syscalls"],
    );
    for path in [
        "/boot/config-10.0.0",
        "/lib/modules/10.0.0/build/.config",
        "/lib/modules/10.0.0/config",
    ] {
        if let Ok(mut file) = File::create(path) {
            let _ = file.write_all(SEEDED_KERNEL_CONFIG.as_bytes());
        }
    }
    let _ = File::create("/dev/misc/rtc");
    let _ = File::create("/dev/null");
    if let Ok(mut file) = File::create("/dev/zero") {
        let zeros = [0u8; 256];
        let _ = file.write_all(&zeros);
    }
    for path in ["/dev/random", "/dev/urandom"] {
        if let Ok(mut file) = File::create(path) {
            let mut seed = 0x6d5a_56a9_3c4f_2b17u64;
            let mut bytes = [0u8; 4096];
            for byte in &mut bytes {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                *byte = seed as u8;
            }
            let _ = file.write_all(&bytes);
        }
    }

    const BUSYBOX_BOOT_APPLETS: &[&str] = &[
        "busybox",
        "sh",
        "ash",
        "sleep",
        "kill",
        "touch",
        "true",
        "false",
        "cat",
        "rm",
        "mkdir",
        "mv",
        "cp",
        "echo",
        "chmod",
        "pwd",
        "uname",
        "ls",
        "df",
        "du",
        "ps",
        "free",
        "hwclock",
        "cut",
        "od",
        "head",
        "tail",
        "hexdump",
        "md5sum",
        "sort",
        "uniq",
        "stat",
        "strings",
        "wc",
        "more",
        "rmdir",
        "grep",
        "find",
        "uptime",
        "printf",
        "basename",
        "dirname",
        "dmesg",
        "expr",
        "which",
        "date",
        "clear",
        "cal",
        "mke2fs",
        "mkfs.ext2",
        "mkfs.vfat",
    ];
    ensure_busybox_applets(
        BUSYBOX_BOOT_APPLETS,
        &[
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/glibc/bin",
            "/glibc/sbin",
            "/glibc/usr/bin",
            "/glibc/usr/sbin",
            "/musl/bin",
            "/musl/sbin",
            "/musl/usr/bin",
            "/musl/usr/sbin",
            "/ltp/testcases/bin",
            "/glibc/ltp/testcases/bin",
            "/musl/ltp/testcases/bin",
        ],
    );
    for path in [
        "/sbin/mkfs.ext4",
        "/usr/sbin/mkfs.ext4",
        "/glibc/sbin/mkfs.ext4",
        "/glibc/usr/sbin/mkfs.ext4",
        "/musl/sbin/mkfs.ext4",
        "/musl/usr/sbin/mkfs.ext4",
    ] {
        ensure_runtime_command_wrapper(path, "/busybox mke2fs");
    }
    ensure_runtime_ltp_scripts();
    seed_systemd_detect_virt();
}

#[unsafe(no_mangle)]
fn main() {
    signal::init();
    axtask::set_wait_interrupt_hook(signal::current_has_pending_signal);
    axtask::set_task_switch_hook(task::record_task_switch_time);
    let boot_start_ms = monotonic_time_nanos() / 1_000_000;
    seed_runtime_files();
    warn!(
        "boot stage seed_runtime_files done elapsed_ms={}",
        monotonic_time_nanos() / 1_000_000 - boot_start_ms
    );
    if maybe_run_direct_command() {
        *COMPETITION_WATCHDOG_SCRIPT.lock() = None;
        return;
    }
    if let Some(scripts) = discover_test_scripts() {
        warn!(
            "boot stage discover_test_scripts done elapsed_ms={} scripts={:?}",
            monotonic_time_nanos() / 1_000_000 - boot_start_ms,
            scripts
        );
        if scripts
            .iter()
            .any(|script| script.ends_with("busybox_testcode.sh"))
        {
            mirror_runtime_file("/sort.src");
        }
        task::set_competition_fail_fast(false);
        let total_watchdog_token = arm_total_competition_watchdog();
        for script in scripts {
            if competition_total_watchdog_timed_out() {
                warn!(
                    "Skip remaining online evaluation scripts after total timeout limit_s={}",
                    COMPETITION_TOTAL_TIMEOUT.as_secs()
                );
                break;
            }
            run_test_script(script);
            if competition_total_watchdog_timed_out() {
                warn!(
                    "Stop online evaluation after total timeout limit_s={}",
                    COMPETITION_TOTAL_TIMEOUT.as_secs()
                );
                break;
            }
        }
        disarm_total_competition_watchdog(total_watchdog_token);
        *COMPETITION_WATCHDOG_SCRIPT.lock() = None;
        task::set_competition_fail_fast(false);
        return;
    }

    let testcases = option_env!("AX_TESTCASES_LIST")
        .unwrap_or_else(|| "Please specify the testcases list by making user_apps")
        .split(',')
        .filter(|&x| !x.is_empty());
    println!("#### OS COMP TEST GROUP START basic ####");
    for testcase in testcases {
        println!("Testing {}: ", testcase.split('/').next_back().unwrap());
        if let Err(err) = run_user_program(vec![testcase.to_string()]) {
            warn!("Failed to start testcase {}: {:?}", testcase, err);
        }
    }
    println!("#### OS COMP TEST GROUP END basic ####");
    *COMPETITION_WATCHDOG_SCRIPT.lock() = None;
}
