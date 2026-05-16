use alloc::{format, string::String, sync::Arc};
use core::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use arceos_posix_api::ctypes::{self, stat, timespec};
use arceos_posix_api::{add_file_like, get_file_like, FileLike, PollState};
use axerrno::LinuxError;
use axhal::time::{monotonic_time_nanos, wall_time_nanos};
use axsync::Mutex;
use axtask::{current, TaskExtRef};

use crate::task::{find_live_task_by_tid, thread_group_tasks};

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
const CLOCK_THREAD_CPUTIME_ID: i32 = 3;
const CLOCK_MONOTONIC_RAW: i32 = 4;
const CLOCK_REALTIME_COARSE: i32 = 5;
const CLOCK_MONOTONIC_COARSE: i32 = 6;
const CLOCK_BOOTTIME: i32 = 7;
const CLOCK_REALTIME_ALARM: i32 = 8;
const CLOCK_BOOTTIME_ALARM: i32 = 9;

static REALTIME_OFFSET_NS: AtomicI64 = AtomicI64::new(0);
static TIME_NAMESPACE_OFFSETS_ACTIVE: AtomicBool = AtomicBool::new(false);
static LEASE_BREAK_TIME_SEC: AtomicI64 = AtomicI64::new(45);
const CPUCLOCK_PROF: i32 = 0;
const CPUCLOCK_VIRT: i32 = 1;
const CPUCLOCK_SCHED: i32 = 2;
const CPUCLOCK_CLOCK_MASK: i32 = 3;
const CPUCLOCK_PERTHREAD_MASK: i32 = 4;
const CLOCKFD: i32 = 3;

struct ProcTimeNsOffsetsFile {
    pos: Mutex<usize>,
}

struct ProcTimeNsFile {
    monotonic_offset_ns: i64,
    boottime_offset_ns: i64,
}

struct ProcUptimeFile {
    pos: Mutex<usize>,
}

struct ProcKeyUsersFile {
    pos: Mutex<usize>,
}

struct ProcSysvipcShmFile {
    pos: Mutex<usize>,
}

struct ProcSysvipcMsgFile {
    pos: Mutex<usize>,
}

#[derive(Clone, Copy)]
enum ProcSysctlIntKind {
    PidMax,
    Shmmax,
    Shmmni,
    ShmNextId,
    Msgmni,
    MsgNextId,
    ThreadsMax,
    LeaseBreakTime,
    PipeMaxSize,
}

struct ProcSysctlIntFile {
    pos: Mutex<usize>,
    kind: ProcSysctlIntKind,
}

struct ProcPidStatFile {
    pid: u64,
    pos: Mutex<usize>,
}

struct ProcPidStatusFile {
    pid: u64,
    pos: Mutex<usize>,
}

struct ProcSelfStatusFile {
    pos: Mutex<usize>,
}

impl ProcTimeNsOffsetsFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcTimeNsFile {
    fn new(monotonic_offset_ns: i64, boottime_offset_ns: i64) -> Self {
        Self {
            monotonic_offset_ns,
            boottime_offset_ns,
        }
    }
}

impl ProcUptimeFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcKeyUsersFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcSysvipcShmFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcSysvipcMsgFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcSysctlIntFile {
    fn new(kind: ProcSysctlIntKind) -> Self {
        Self {
            pos: Mutex::new(0),
            kind,
        }
    }
}

impl ProcPidStatFile {
    fn new(pid: u64) -> Self {
        Self {
            pid,
            pos: Mutex::new(0),
        }
    }
}

impl ProcPidStatusFile {
    fn new(pid: u64) -> Self {
        Self {
            pid,
            pos: Mutex::new(0),
        }
    }
}

impl ProcSelfStatusFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

fn current_time_ns_offsets() -> (i64, i64) {
    current().task_ext().active_time_ns_offsets()
}

fn current_child_time_ns_offsets() -> (i64, i64) {
    current().task_ext().child_time_ns_offsets()
}

pub(crate) fn note_time_namespace_offsets(monotonic_offset_ns: i64, boottime_offset_ns: i64) {
    if monotonic_offset_ns != 0 || boottime_offset_ns != 0 {
        TIME_NAMESPACE_OFFSETS_ACTIVE.store(true, Ordering::Release);
    }
}

fn add_offset(base: u64, offset_ns: i64) -> u64 {
    (base as i128).saturating_add(offset_ns as i128).max(0) as u64
}

#[derive(Clone, Copy)]
enum CpuClockTarget {
    Process(usize),
    Thread(u64),
}

#[derive(Clone, Copy)]
enum CpuClockKind {
    Prof,
    Virt,
    Sched,
}

fn cpu_clock_kind_from_bits(bits: i32) -> Result<CpuClockKind, LinuxError> {
    match bits & CPUCLOCK_CLOCK_MASK {
        CPUCLOCK_PROF => Ok(CpuClockKind::Prof),
        CPUCLOCK_VIRT => Ok(CpuClockKind::Virt),
        CPUCLOCK_SCHED => Ok(CpuClockKind::Sched),
        _ => Err(LinuxError::EINVAL),
    }
}

fn decode_cpu_clock_id(
    clock_id: i32,
) -> Result<Option<(CpuClockTarget, CpuClockKind)>, LinuxError> {
    match clock_id {
        CLOCK_PROCESS_CPUTIME_ID => Ok(Some((
            CpuClockTarget::Process(current().task_ext().proc_id),
            CpuClockKind::Sched,
        ))),
        CLOCK_THREAD_CPUTIME_ID => Ok(Some((
            CpuClockTarget::Thread(current().id().as_u64()),
            CpuClockKind::Sched,
        ))),
        id if id < 0 => {
            if (id & CPUCLOCK_CLOCK_MASK) == CLOCKFD {
                return Ok(None);
            }
            let kind = cpu_clock_kind_from_bits(id)?;
            let raw_id = (!(id >> 3)) as u32 as u64;
            let target = if (id & CPUCLOCK_PERTHREAD_MASK) != 0 {
                CpuClockTarget::Thread(if raw_id == 0 {
                    current().id().as_u64()
                } else {
                    raw_id
                })
            } else {
                CpuClockTarget::Process(if raw_id == 0 {
                    current().task_ext().proc_id
                } else {
                    raw_id as usize
                })
            };
            Ok(Some((target, kind)))
        }
        _ => Ok(None),
    }
}

fn cpu_clock_nanos_from_stats(kind: CpuClockKind, utime_ns: usize, stime_ns: usize) -> u64 {
    match kind {
        CpuClockKind::Virt => utime_ns as u64,
        CpuClockKind::Prof | CpuClockKind::Sched => utime_ns.saturating_add(stime_ns) as u64,
    }
}

fn cpu_clock_nanos(clock_id: i32) -> Result<Option<u64>, LinuxError> {
    let Some((target, kind)) = decode_cpu_clock_id(clock_id)? else {
        return Ok(None);
    };
    let ns = match target {
        CpuClockTarget::Thread(tid) => {
            let task = find_live_task_by_tid(tid).ok_or(LinuxError::ESRCH)?;
            let (utime_ns, stime_ns) = task.task_ext().time_stat_output();
            cpu_clock_nanos_from_stats(kind, utime_ns, stime_ns)
        }
        CpuClockTarget::Process(pid) => {
            let members = thread_group_tasks(pid);
            if members.is_empty() {
                return Err(LinuxError::ESRCH);
            }
            members.into_iter().fold(0u64, |acc, task| {
                let (utime_ns, stime_ns) = task.task_ext().time_stat_output();
                acc.saturating_add(cpu_clock_nanos_from_stats(kind, utime_ns, stime_ns))
            })
        }
    };
    Ok(Some(ns))
}

pub(crate) fn is_cpu_time_clock(clock_id: i32) -> bool {
    matches!(decode_cpu_clock_id(clock_id), Ok(Some(_)))
}

fn proc_uptime_contents() -> String {
    let uptime_ns = current_clock_nanos(CLOCK_BOOTTIME).unwrap_or_else(|_| monotonic_time_nanos());
    let seconds = uptime_ns / 1_000_000_000;
    format!("{seconds}.00 {seconds}.00\n")
}

fn proc_self_status_contents() -> String {
    let curr = current();
    let pid = curr.task_ext().proc_id;
    let ppid = curr.task_ext().get_parent();
    let (ruid, euid, suid) = axfs::api::current_res_uid();
    let (rgid, egid, sgid) = axfs::api::current_res_gid();
    let (groups, group_count) = axfs::api::current_supplementary_gids();
    let mut group_line = String::new();
    for group in groups[..group_count].iter() {
        if !group_line.is_empty() {
            group_line.push(' ');
        }
        group_line.push_str(format!("{group}").as_str());
    }
    if group_line.is_empty() {
        group_line.push('0');
    }
    format!(
        "Name:\t{}\nState:\tR (running)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{} {} {} {}\nGid:\t{} {} {} {}\nGroups:\t{}\n",
        curr.name(),
        pid,
        pid,
        ppid,
        ruid,
        euid,
        suid,
        euid,
        rgid,
        egid,
        sgid,
        egid,
        group_line
    )
}

fn proc_timens_offsets_contents() -> String {
    let (mono, boot) = current_child_time_ns_offsets();
    let mono_sec = mono.div_euclid(1_000_000_000);
    let mono_nsec = mono.rem_euclid(1_000_000_000);
    let boot_sec = boot.div_euclid(1_000_000_000);
    let boot_nsec = boot.rem_euclid(1_000_000_000);
    format!("{CLOCK_MONOTONIC} {mono_sec} {mono_nsec}\n{CLOCK_BOOTTIME} {boot_sec} {boot_nsec}\n")
}

fn parse_single_timens_offset(buf: &[u8]) -> Result<(i32, i64), LinuxError> {
    let text = core::str::from_utf8(buf).map_err(|_| LinuxError::EINVAL)?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    let mut parts = trimmed.split_whitespace();
    let clock_id = parts
        .next()
        .ok_or(LinuxError::EINVAL)?
        .parse::<i32>()
        .map_err(|_| LinuxError::EINVAL)?;
    let seconds = parts
        .next()
        .ok_or(LinuxError::EINVAL)?
        .parse::<i64>()
        .map_err(|_| LinuxError::EINVAL)?;
    let nanos = parts
        .next()
        .ok_or(LinuxError::EINVAL)?
        .parse::<i64>()
        .map_err(|_| LinuxError::EINVAL)?;
    if parts.next().is_some() {
        return Err(LinuxError::EINVAL);
    }
    if nanos < 0 || nanos >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }
    if clock_id != CLOCK_MONOTONIC && clock_id != CLOCK_BOOTTIME {
        return Err(LinuxError::EINVAL);
    }
    let offset = (seconds as i128)
        .checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos as i128))
        .ok_or(LinuxError::ERANGE)?;
    if offset < i64::MIN as i128 || offset > i64::MAX as i128 {
        return Err(LinuxError::ERANGE);
    }
    Ok((clock_id, offset as i64))
}

pub(crate) fn open_special_proc_file(path: &str, _flags: i32) -> Option<isize> {
    if let Some(pid) = special_proc_pid_stat_path(path) {
        if crate::task::live_pid_stat_contents(pid).is_some() {
            return Some(
                add_file_like(Arc::new(ProcPidStatFile::new(pid)))
                    .map(|fd| fd as isize)
                    .unwrap_or_else(|err| -(err.code() as isize)),
            );
        }
    }
    if let Some(pid) = special_proc_pid_status_path(path) {
        if crate::task::live_pid_status_contents(pid).is_some() {
            return Some(
                add_file_like(Arc::new(ProcPidStatusFile::new(pid)))
                    .map(|fd| fd as isize)
                    .unwrap_or_else(|err| -(err.code() as isize)),
            );
        }
    }
    match path {
        "/proc/sysvipc/shm" => Some(
            add_file_like(Arc::new(ProcSysvipcShmFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sysvipc/msg" => Some(
            add_file_like(Arc::new(ProcSysvipcMsgFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/shmmax" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(ProcSysctlIntKind::Shmmax)))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/pid_max" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(ProcSysctlIntKind::PidMax)))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/shmmni" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(ProcSysctlIntKind::Shmmni)))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/shm_next_id" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(
                ProcSysctlIntKind::ShmNextId,
            )))
            .map(|fd| fd as isize)
            .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/msgmni" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(ProcSysctlIntKind::Msgmni)))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/msg_next_id" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(
                ProcSysctlIntKind::MsgNextId,
            )))
            .map(|fd| fd as isize)
            .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/kernel/threads-max" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(
                ProcSysctlIntKind::ThreadsMax,
            )))
            .map(|fd| fd as isize)
            .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/fs/lease-break-time" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(
                ProcSysctlIntKind::LeaseBreakTime,
            )))
            .map(|fd| fd as isize)
            .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/sys/fs/pipe-max-size" => Some(
            add_file_like(Arc::new(ProcSysctlIntFile::new(
                ProcSysctlIntKind::PipeMaxSize,
            )))
            .map(|fd| fd as isize)
            .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/key-users" => Some(
            add_file_like(Arc::new(ProcKeyUsersFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/self/status" => Some(
            add_file_like(Arc::new(ProcSelfStatusFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/self/timens_offsets" => Some(
            add_file_like(Arc::new(ProcTimeNsOffsetsFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        "/proc/self/ns/time_for_children" => {
            let (mono, boot) = current_child_time_ns_offsets();
            Some(
                add_file_like(Arc::new(ProcTimeNsFile::new(mono, boot)))
                    .map(|fd| fd as isize)
                    .unwrap_or_else(|err| -(err.code() as isize)),
            )
        }
        "/proc/uptime" => Some(
            add_file_like(Arc::new(ProcUptimeFile::new()))
                .map(|fd| fd as isize)
                .unwrap_or_else(|err| -(err.code() as isize)),
        ),
        _ => None,
    }
}

pub(crate) fn special_proc_file_stat(path: &str) -> Option<stat> {
    if let Some(kind) = match path {
        "/proc/sys/kernel/pid_max" => Some(ProcSysctlIntKind::PidMax),
        "/proc/sys/kernel/shmmax" => Some(ProcSysctlIntKind::Shmmax),
        "/proc/sys/kernel/shmmni" => Some(ProcSysctlIntKind::Shmmni),
        "/proc/sys/kernel/shm_next_id" => Some(ProcSysctlIntKind::ShmNextId),
        "/proc/sys/kernel/msgmni" => Some(ProcSysctlIntKind::Msgmni),
        "/proc/sys/kernel/msg_next_id" => Some(ProcSysctlIntKind::MsgNextId),
        "/proc/sys/kernel/threads-max" => Some(ProcSysctlIntKind::ThreadsMax),
        "/proc/sys/fs/lease-break-time" => Some(ProcSysctlIntKind::LeaseBreakTime),
        "/proc/sys/fs/pipe-max-size" => Some(ProcSysctlIntKind::PipeMaxSize),
        _ => None,
    } {
        let contents = proc_sysctl_int_contents(kind);
        return Some(stat {
            st_ino: 0x7072_6f63,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o644,
            st_uid: axfs::api::current_uid(),
            st_gid: axfs::api::current_gid(),
            st_size: contents.len() as i64,
            st_blocks: contents.len().div_ceil(512) as i64,
            st_blksize: 512,
            ..Default::default()
        });
    }
    if path == "/proc/self/status" {
        let contents = proc_self_status_contents();
        return Some(stat {
            st_ino: 0x7374_6174,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: axfs::api::current_uid(),
            st_gid: axfs::api::current_gid(),
            st_size: contents.len() as i64,
            st_blocks: contents.len().div_ceil(512) as i64,
            st_blksize: 512,
            ..Default::default()
        });
    }
    if let Some(pid) = special_proc_pid_status_path(path) {
        let contents = crate::task::live_pid_status_contents(pid)?;
        return Some(stat {
            st_ino: pid ^ 0x7374_6174,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: axfs::api::current_uid(),
            st_gid: axfs::api::current_gid(),
            st_size: contents.len() as i64,
            st_blocks: contents.len().div_ceil(512) as i64,
            st_blksize: 512,
            ..Default::default()
        });
    }
    let pid = special_proc_pid_stat_path(path)?;
    let contents = crate::task::live_pid_stat_contents(pid)?;
    Some(stat {
        st_ino: pid,
        st_nlink: 1,
        st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
        st_uid: axfs::api::current_uid(),
        st_gid: axfs::api::current_gid(),
        st_size: contents.len() as i64,
        st_blocks: contents.len().div_ceil(512) as i64,
        st_blksize: 512,
        ..Default::default()
    })
}

pub(crate) fn special_proc_file_exists(path: &str) -> bool {
    special_proc_file_stat(path).is_some()
}

fn special_proc_pid_stat_path(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, suffix) = rest.split_once('/')?;
    if suffix != "stat" || pid.is_empty() || !pid.bytes().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

fn special_proc_pid_status_path(path: &str) -> Option<u64> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, suffix) = rest.split_once('/')?;
    if suffix != "status" || pid.is_empty() || !pid.bytes().all(|ch| ch.is_ascii_digit()) {
        return None;
    }
    pid.parse().ok()
}

fn read_proc_text_with_pos(
    pos: &Mutex<usize>,
    content: String,
    buf: &mut [u8],
) -> Result<usize, LinuxError> {
    let data = content.as_bytes();
    let mut pos = pos.lock();
    if *pos >= data.len() {
        return Ok(0);
    }
    let read_len = buf.len().min(data.len() - *pos);
    buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
    *pos += read_len;
    Ok(read_len)
}

fn proc_sysctl_int_contents(kind: ProcSysctlIntKind) -> String {
    match kind {
        ProcSysctlIntKind::PidMax => crate::task::proc_pid_max_contents(),
        ProcSysctlIntKind::Shmmax => crate::syscall_imp::proc_shmmax_contents(),
        ProcSysctlIntKind::Shmmni => crate::syscall_imp::proc_shmmni_contents(),
        ProcSysctlIntKind::ShmNextId => crate::syscall_imp::proc_shm_next_id_contents(),
        ProcSysctlIntKind::Msgmni => crate::syscall_imp::proc_msgmni_contents(),
        ProcSysctlIntKind::MsgNextId => crate::syscall_imp::proc_msg_next_id_contents(),
        ProcSysctlIntKind::ThreadsMax => "32768\n".into(),
        ProcSysctlIntKind::LeaseBreakTime => {
            format!("{}\n", LEASE_BREAK_TIME_SEC.load(Ordering::Acquire))
        }
        ProcSysctlIntKind::PipeMaxSize => format!("{}\n", arceos_posix_api::pipe_max_size()),
    }
}

fn write_proc_sysctl_int(kind: ProcSysctlIntKind, buf: &[u8]) -> Result<usize, LinuxError> {
    let text = core::str::from_utf8(buf)
        .map_err(|_| LinuxError::EINVAL)?
        .trim();
    let value = text.parse::<i64>().map_err(|_| LinuxError::EINVAL)?;
    match kind {
        ProcSysctlIntKind::PidMax => crate::task::set_proc_pid_max_value(
            usize::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::Shmmax => crate::syscall_imp::set_proc_shmmax_value(
            usize::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::Shmmni => crate::syscall_imp::set_proc_shmmni_value(
            usize::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::ShmNextId => crate::syscall_imp::set_proc_shm_next_id_value(
            i32::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::Msgmni => crate::syscall_imp::set_proc_msgmni_value(
            usize::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::MsgNextId => crate::syscall_imp::set_proc_msg_next_id_value(
            i32::try_from(value).map_err(|_| LinuxError::EINVAL)?,
        )?,
        ProcSysctlIntKind::ThreadsMax => return Err(LinuxError::EPERM),
        ProcSysctlIntKind::LeaseBreakTime => {
            if value < 0 {
                return Err(LinuxError::EINVAL);
            }
            LEASE_BREAK_TIME_SEC.store(value, Ordering::Release);
        }
        ProcSysctlIntKind::PipeMaxSize => {
            arceos_posix_api::set_pipe_max_size(
                usize::try_from(value).map_err(|_| LinuxError::EINVAL)?,
            )?;
        }
    }
    Ok(buf.len())
}

pub(crate) fn setns_time_namespace_from_fd(fd: i32) -> Result<(), LinuxError> {
    let file = get_file_like(fd)?;
    let ns = file
        .into_any()
        .downcast::<ProcTimeNsFile>()
        .map_err(|_| LinuxError::EINVAL)?;
    current()
        .task_ext()
        .set_active_time_ns_offsets(ns.monotonic_offset_ns, ns.boottime_offset_ns);
    current().task_ext().reset_child_time_namespace();
    Ok(())
}

impl FileLike for ProcTimeNsOffsetsFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let content = proc_timens_offsets_contents();
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        let (clock_id, offset_ns) = parse_single_timens_offset(buf)?;
        current()
            .task_ext()
            .configure_child_time_ns_offset(clock_id, offset_ns)?;
        *self.pos.lock() = 0;
        Ok(buf.len())
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = proc_timens_offsets_contents().len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x7469_6d65,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o644,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcSysvipcShmFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        read_proc_text_with_pos(
            &self.pos,
            crate::syscall_imp::proc_sysvipc_shm_contents(),
            buf,
        )
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = crate::syscall_imp::proc_sysvipc_shm_contents().len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x7379_7376,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcSysvipcMsgFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        read_proc_text_with_pos(
            &self.pos,
            crate::syscall_imp::proc_sysvipc_msg_contents(),
            buf,
        )
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = crate::syscall_imp::proc_sysvipc_msg_contents().len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x6d73_6771,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcSysctlIntFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        read_proc_text_with_pos(&self.pos, proc_sysctl_int_contents(self.kind), buf)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        let written = write_proc_sysctl_int(self.kind, buf)?;
        *self.pos.lock() = 0;
        Ok(written)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = proc_sysctl_int_contents(self.kind).len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x7368_6d30 + self.kind as u64,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o644,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcPidStatFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let Some(content) = crate::task::live_pid_stat_contents(self.pid) else {
            return Ok(0);
        };
        read_proc_text_with_pos(&self.pos, content, buf)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> Result<stat, LinuxError> {
        special_proc_file_stat(format!("/proc/{}/stat", self.pid).as_str())
            .ok_or(LinuxError::ENOENT)
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcPidStatusFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let Some(content) = crate::task::live_pid_status_contents(self.pid) else {
            return Ok(0);
        };
        read_proc_text_with_pos(&self.pos, content, buf)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> Result<stat, LinuxError> {
        special_proc_file_stat(format!("/proc/{}/status", self.pid).as_str())
            .ok_or(LinuxError::ENOENT)
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcSelfStatusFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        read_proc_text_with_pos(&self.pos, proc_self_status_contents(), buf)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        special_proc_file_stat("/proc/self/status").ok_or(LinuxError::ENOENT)
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcTimeNsFile {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, LinuxError> {
        Ok(0)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        Ok(ctypes::stat {
            st_ino: 0x7469_6d6e,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcUptimeFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let content = proc_uptime_contents();
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = proc_uptime_contents().len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x7570_7469,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

impl FileLike for ProcKeyUsersFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let content = crate::syscall_imp::proc_key_users_contents();
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, LinuxError> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> Result<ctypes::stat, LinuxError> {
        let size = crate::syscall_imp::proc_key_users_contents().len() as i64;
        Ok(ctypes::stat {
            st_ino: 0x6b65_7975,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> Result<(), LinuxError> {
        Ok(())
    }
}

pub(crate) fn current_realtime_nanos() -> u64 {
    let base = wall_time_nanos() as i128;
    let offset = REALTIME_OFFSET_NS.load(Ordering::Relaxed) as i128;
    base.saturating_add(offset).max(0) as u64
}

pub(crate) fn current_clock_nanos(clock_id: i32) -> Result<u64, LinuxError> {
    if let Some(ns) = cpu_clock_nanos(clock_id)? {
        return Ok(ns);
    }
    match clock_id {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_REALTIME_ALARM => {
            Ok(current_realtime_nanos())
        }
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE => {
            if !TIME_NAMESPACE_OFFSETS_ACTIVE.load(Ordering::Acquire) {
                return Ok(monotonic_time_nanos());
            }
            let (monotonic_offset_ns, _) = current_time_ns_offsets();
            Ok(add_offset(monotonic_time_nanos(), monotonic_offset_ns))
        }
        CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => {
            if !TIME_NAMESPACE_OFFSETS_ACTIVE.load(Ordering::Acquire) {
                return Ok(monotonic_time_nanos());
            }
            let (_, boottime_offset_ns) = current_time_ns_offsets();
            Ok(add_offset(monotonic_time_nanos(), boottime_offset_ns))
        }
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn clock_settime(clock_id: i32, ts: timespec) -> Result<(), LinuxError> {
    if clock_id != CLOCK_REALTIME {
        return Err(LinuxError::EINVAL);
    }
    let target_ns = timespec_to_nanos(ts)?;
    let base = wall_time_nanos() as i128;
    let offset = target_ns as i128 - base;
    let offset = offset.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    REALTIME_OFFSET_NS.store(offset, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn monotonic_deadline_from_clock(
    clock_id: i32,
    expires_ns: u64,
    absolute: bool,
) -> Result<u64, LinuxError> {
    let now_mono = monotonic_time_nanos();
    if !absolute {
        return now_mono.checked_add(expires_ns).ok_or(LinuxError::EINVAL);
    }
    let now_clock = current_clock_nanos(clock_id)?;
    Ok(now_mono.saturating_add(expires_ns.saturating_sub(now_clock)))
}

pub(crate) fn timespec_to_nanos(ts: timespec) -> Result<u64, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }
    let secs = ts.tv_sec as u64;
    let nanos = ts.tv_nsec as u64;
    secs.checked_mul(1_000_000_000)
        .and_then(|base| base.checked_add(nanos))
        .ok_or(LinuxError::EINVAL)
}

pub(crate) fn nanos_to_timespec(ns: u64) -> timespec {
    timespec {
        tv_sec: (ns / 1_000_000_000) as _,
        tv_nsec: (ns % 1_000_000_000) as _,
    }
}
