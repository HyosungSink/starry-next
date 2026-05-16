use core::ffi::c_int;
use core::sync::atomic::{AtomicU64, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;
use arceos_posix_api as api;
use axerrno::LinuxError;
use axtask::{current, TaskExtRef, WaitQueue};
use spin::Mutex;

use crate::signal::send_user_signal_to_task;
use crate::syscall_body;
use crate::task::{find_live_task_by_tid, find_process_leader_by_pid, process_leader_tasks};
use crate::usercopy::{read_value_from_user, write_value_to_user};

const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;
const F_SETLEASE: u32 = 1024;
const F_GETLEASE: u32 = 1025;
const F_OFD_GETLK: u32 = 36;
const F_OFD_SETLK: u32 = 37;
const F_OFD_SETLKW: u32 = 38;
const F_SETOWN_EX: u32 = 15;
const F_GETOWN_EX: u32 = 16;
const F_OWNER_TID: i32 = 0;
const F_OWNER_PID: i32 = 1;
const F_OWNER_PGRP: i32 = 2;
const SIGIO: usize = 29;
const LOCK_SH: i32 = 1;
const LOCK_EX: i32 = 2;
const LOCK_NB: i32 = 4;
const LOCK_UN: i32 = 8;

#[repr(C)]
#[derive(Clone, Copy, Default)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileKey {
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy)]
struct LockRecord {
    key: FileKey,
    owner_pid: i32,
    typ: i16,
    start: i64,
    end: i64,
}

#[derive(Clone, Copy)]
struct OfdLockRecord {
    key: FileKey,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
}

#[derive(Clone, Copy)]
struct LeaseRecord {
    key: FileKey,
    owner_pid: i32,
    identity: usize,
    typ: i32,
    last_break_write_like: bool,
}

#[derive(Clone, Copy)]
struct FlockRecord {
    key: FileKey,
    owner_identity: usize,
    exclusive: bool,
}

#[derive(Clone, Copy)]
struct AsyncFdControl {
    identity: usize,
    owner_kind: i32,
    owner_id: i32,
    signal: i32,
    enabled: bool,
}

#[derive(Clone)]
struct WaitingLockRecord {
    owner_pid: i32,
    blocked_by: Vec<i32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LockWaiterKind {
    Posix,
    Ofd,
}

#[derive(Clone, Copy)]
struct LockWaiterRecord {
    ticket: u64,
    kind: LockWaiterKind,
    key: FileKey,
    owner_pid: i32,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
}

static FILE_LOCKS: Mutex<Vec<LockRecord>> = Mutex::new(Vec::new());
static OFD_FILE_LOCKS: Mutex<Vec<OfdLockRecord>> = Mutex::new(Vec::new());
static FLOCK_LOCKS: Mutex<Vec<FlockRecord>> = Mutex::new(Vec::new());
static FILE_LEASES: Mutex<Vec<LeaseRecord>> = Mutex::new(Vec::new());
static ASYNC_FD_CONTROLS: Mutex<Vec<AsyncFdControl>> = Mutex::new(Vec::new());
static WAITING_FILE_LOCKS: Mutex<Vec<WaitingLockRecord>> = Mutex::new(Vec::new());
static LOCK_WAITERS: Mutex<Vec<LockWaiterRecord>> = Mutex::new(Vec::new());
static LOCK_WAIT_QUEUE: WaitQueue = WaitQueue::new();
static NEXT_LOCK_WAITER_TICKET: AtomicU64 = AtomicU64::new(1);

fn api_ret(ret: c_int) -> Result<c_int, LinuxError> {
    if ret < 0 {
        Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL))
    } else {
        Ok(ret)
    }
}

fn current_pid() -> i32 {
    current().task_ext().proc_id as i32
}

fn current_uid() -> u32 {
    axfs::api::current_uid()
}

fn file_key_from_fd(fd: c_int) -> Result<FileKey, LinuxError> {
    let file = api::get_file_like(fd)?;
    let (dev, ino) = if let Some(key) = file.lock_key() {
        key
    } else {
        let stat = file.stat()?;
        (stat.st_dev, stat.st_ino)
    };
    Ok(FileKey { dev, ino })
}

fn file_identity_from_fd(fd: c_int) -> Result<usize, LinuxError> {
    Ok(api::get_file_like(fd)?.fcntl_identity())
}

fn file_current_offset(fd: c_int) -> Result<i64, LinuxError> {
    let ret = api::sys_lseek(fd, 0, 1);
    if ret < 0 {
        Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL))
    } else {
        Ok(ret as i64)
    }
}

fn file_size(fd: c_int) -> Result<i64, LinuxError> {
    Ok(api::get_file_like(fd)?.stat()?.st_size)
}

fn validate_flock(lock: &UserFlock) -> Result<(), LinuxError> {
    if !matches!(
        lock.l_type as u32,
        api::ctypes::F_RDLCK | api::ctypes::F_WRLCK | api::ctypes::F_UNLCK
    ) {
        return Err(LinuxError::EINVAL);
    }
    if !matches!(lock.l_whence as i32, 0..=2) {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn normalize_flock_range(fd: c_int, lock: &UserFlock) -> Result<(i64, i64), LinuxError> {
    let base = match lock.l_whence as i32 {
        0 => 0,
        1 => file_current_offset(fd)?,
        2 => file_size(fd)?,
        _ => return Err(LinuxError::EINVAL),
    };
    let raw_start = base.checked_add(lock.l_start).ok_or(LinuxError::EINVAL)?;
    let raw_end = if lock.l_len == 0 {
        i64::MAX
    } else {
        raw_start
            .checked_add(lock.l_len)
            .ok_or(LinuxError::EINVAL)?
    };
    let start = raw_start.min(raw_end);
    let end = raw_start.max(raw_end);
    if start < 0 || end < 0 || end < start {
        return Err(LinuxError::EINVAL);
    }
    Ok((start, end))
}

fn locks_conflict(left: &LockRecord, right_typ: i16, right_start: i64, right_end: i64) -> bool {
    if left.end <= right_start || right_end <= left.start {
        return false;
    }
    left.typ == api::ctypes::F_WRLCK as i16 || right_typ == api::ctypes::F_WRLCK as i16
}

fn merge_owner_locks(locks: &mut Vec<LockRecord>) {
    locks.sort_by_key(|lock| {
        (
            lock.key.dev,
            lock.key.ino,
            lock.owner_pid,
            lock.start,
            lock.end,
        )
    });
    let mut merged: Vec<LockRecord> = Vec::with_capacity(locks.len());
    for lock in locks.drain(..) {
        if let Some(prev) = merged.last_mut() {
            if prev.key == lock.key
                && prev.owner_pid == lock.owner_pid
                && prev.typ == lock.typ
                && lock.start <= prev.end
            {
                prev.end = prev.end.max(lock.end);
                continue;
            }
        }
        merged.push(lock);
    }
    *locks = merged;
}

fn update_owner_lock(
    locks: &mut Vec<LockRecord>,
    key: FileKey,
    owner_pid: i32,
    typ: i16,
    start: i64,
    end: i64,
) {
    let mut next = Vec::with_capacity(locks.len() + 1);
    for existing in locks.drain(..) {
        if existing.key != key
            || existing.owner_pid != owner_pid
            || existing.end <= start
            || end <= existing.start
        {
            next.push(existing);
            continue;
        }
        if existing.start < start {
            next.push(LockRecord {
                end: start,
                ..existing
            });
        }
        if end < existing.end {
            next.push(LockRecord {
                start: end,
                ..existing
            });
        }
    }
    if typ != api::ctypes::F_UNLCK as i16 {
        next.push(LockRecord {
            key,
            owner_pid,
            typ,
            start,
            end,
        });
    }
    merge_owner_locks(&mut next);
    *locks = next;
}

fn merge_ofd_locks(locks: &mut Vec<OfdLockRecord>) {
    locks.sort_by_key(|lock| {
        (
            lock.key.dev,
            lock.key.ino,
            lock.owner_identity,
            lock.start,
            lock.end,
        )
    });
    let mut merged: Vec<OfdLockRecord> = Vec::with_capacity(locks.len());
    for lock in locks.drain(..) {
        if let Some(prev) = merged.last_mut() {
            if prev.key == lock.key
                && prev.owner_identity == lock.owner_identity
                && prev.typ == lock.typ
                && lock.start <= prev.end
            {
                prev.end = prev.end.max(lock.end);
                continue;
            }
        }
        merged.push(lock);
    }
    *locks = merged;
}

fn update_ofd_lock(
    locks: &mut Vec<OfdLockRecord>,
    key: FileKey,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
) {
    let mut next = Vec::with_capacity(locks.len() + 1);
    for existing in locks.drain(..) {
        if existing.key != key
            || existing.owner_identity != owner_identity
            || existing.end <= start
            || end <= existing.start
        {
            next.push(existing);
            continue;
        }
        if existing.start < start {
            next.push(OfdLockRecord {
                end: start,
                ..existing
            });
        }
        if end < existing.end {
            next.push(OfdLockRecord {
                start: end,
                ..existing
            });
        }
    }
    if typ != api::ctypes::F_UNLCK as i16 {
        next.push(OfdLockRecord {
            key,
            owner_identity,
            typ,
            start,
            end,
        });
    }
    merge_ofd_locks(&mut next);
    *locks = next;
}

fn conflicting_lock_owners(
    locks: &[LockRecord],
    key: FileKey,
    owner_pid: i32,
    typ: i16,
    start: i64,
    end: i64,
) -> Vec<i32> {
    if typ == api::ctypes::F_UNLCK as i16 {
        return Vec::new();
    }

    let mut owners = Vec::new();
    for existing in locks {
        if existing.key != key
            || existing.owner_pid == owner_pid
            || !locks_conflict(existing, typ, start, end)
        {
            continue;
        }
        if !owners.contains(&existing.owner_pid) {
            owners.push(existing.owner_pid);
        }
    }
    owners
}

fn has_conflicting_ofd_locks(
    locks: &[OfdLockRecord],
    key: FileKey,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
) -> bool {
    if typ == api::ctypes::F_UNLCK as i16 {
        return false;
    }
    locks.iter().any(|existing| {
        existing.key == key
            && existing.owner_identity != owner_identity
            && locks_conflict(
                &LockRecord {
                    key: existing.key,
                    owner_pid: 0,
                    typ: existing.typ,
                    start: existing.start,
                    end: existing.end,
                },
                typ,
                start,
                end,
            )
    })
}

fn has_conflicting_any_ofd_lock(
    locks: &[OfdLockRecord],
    key: FileKey,
    typ: i16,
    start: i64,
    end: i64,
) -> bool {
    if typ == api::ctypes::F_UNLCK as i16 {
        return false;
    }
    locks.iter().any(|existing| {
        existing.key == key
            && locks_conflict(
                &LockRecord {
                    key: existing.key,
                    owner_pid: 0,
                    typ: existing.typ,
                    start: existing.start,
                    end: existing.end,
                },
                typ,
                start,
                end,
            )
    })
}

fn is_write_lock(typ: i16) -> bool {
    typ == api::ctypes::F_WRLCK as i16
}

fn next_lock_waiter_ticket() -> u64 {
    NEXT_LOCK_WAITER_TICKET.fetch_add(1, Ordering::Relaxed)
}

fn store_lock_waiter(waiter: LockWaiterRecord) {
    let mut waiters = LOCK_WAITERS.lock();
    if let Some(slot) = waiters.iter_mut().find(|slot| slot.ticket == waiter.ticket) {
        *slot = waiter;
    } else {
        waiters.push(waiter);
    }
}

fn clear_lock_waiter(ticket: u64) {
    LOCK_WAITERS.lock().retain(|waiter| waiter.ticket != ticket);
}

fn waiter_is_same_owner(
    waiter: &LockWaiterRecord,
    kind: LockWaiterKind,
    owner_pid: i32,
    owner_identity: usize,
) -> bool {
    match (waiter.kind, kind) {
        (LockWaiterKind::Posix, LockWaiterKind::Posix) => waiter.owner_pid == owner_pid,
        (LockWaiterKind::Ofd, LockWaiterKind::Ofd) => waiter.owner_identity == owner_identity,
        _ => false,
    }
}

fn has_waiting_writer_conflict(
    ticket: Option<u64>,
    kind: LockWaiterKind,
    key: FileKey,
    owner_pid: i32,
    owner_identity: usize,
    start: i64,
    end: i64,
) -> bool {
    LOCK_WAITERS.lock().iter().any(|waiter| {
        ticket != Some(waiter.ticket)
            && waiter.key == key
            && is_write_lock(waiter.typ)
            && !waiter_is_same_owner(waiter, kind, owner_pid, owner_identity)
            && locks_conflict(
                &LockRecord {
                    key: waiter.key,
                    owner_pid: waiter.owner_pid,
                    typ: waiter.typ,
                    start: waiter.start,
                    end: waiter.end,
                },
                api::ctypes::F_RDLCK as i16,
                start,
                end,
            )
    })
}

fn has_prior_conflicting_waiter(
    ticket: u64,
    kind: LockWaiterKind,
    key: FileKey,
    owner_pid: i32,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
) -> bool {
    LOCK_WAITERS.lock().iter().any(|waiter| {
        waiter.ticket < ticket
            && waiter.key == key
            && !waiter_is_same_owner(waiter, kind, owner_pid, owner_identity)
            && locks_conflict(
                &LockRecord {
                    key: waiter.key,
                    owner_pid: waiter.owner_pid,
                    typ: waiter.typ,
                    start: waiter.start,
                    end: waiter.end,
                },
                typ,
                start,
                end,
            )
    })
}

#[derive(Clone, Copy)]
struct ConflictingLockInfo {
    typ: i16,
    start: i64,
    end: i64,
    pid: i32,
}

fn find_conflicting_lock(
    fd: c_int,
    key: FileKey,
    typ: i16,
    start: i64,
    end: i64,
    owner_pid_ignored: Option<i32>,
    owner_identity_ignored: Option<usize>,
) -> Result<Option<ConflictingLockInfo>, LinuxError> {
    let posix_conflict = FILE_LOCKS
        .lock()
        .iter()
        .copied()
        .filter(|existing| {
            existing.key == key
                && owner_pid_ignored != Some(existing.owner_pid)
                && locks_conflict(existing, typ, start, end)
        })
        .map(|existing| ConflictingLockInfo {
            typ: existing.typ,
            start: existing.start,
            end: existing.end,
            pid: existing.owner_pid,
        })
        .min_by_key(|existing| (existing.start, existing.pid));

    let ofd_conflict = OFD_FILE_LOCKS
        .lock()
        .iter()
        .copied()
        .filter(|existing| {
            existing.key == key
                && owner_identity_ignored != Some(existing.owner_identity)
                && locks_conflict(
                    &LockRecord {
                        key: existing.key,
                        owner_pid: 0,
                        typ: existing.typ,
                        start: existing.start,
                        end: existing.end,
                    },
                    typ,
                    start,
                    end,
                )
        })
        .map(|existing| ConflictingLockInfo {
            typ: existing.typ,
            start: existing.start,
            end: existing.end,
            pid: -1,
        })
        .min_by_key(|existing| (existing.start, existing.pid));

    Ok(match (posix_conflict, ofd_conflict) {
        (Some(left), Some(right)) => Some(if (left.start, left.pid) <= (right.start, right.pid) {
            left
        } else {
            right
        }),
        (Some(conflict), None) | (None, Some(conflict)) => Some(conflict),
        (None, None) => {
            let _ = fd;
            None
        }
    })
}

fn clear_waiting_lock(owner_pid: i32) {
    WAITING_FILE_LOCKS
        .lock()
        .retain(|record| record.owner_pid != owner_pid);
}

fn store_waiting_lock(owner_pid: i32, blocked_by: &[i32]) {
    let mut blocked_vec = blocked_by.to_vec();
    blocked_vec.sort_unstable();
    blocked_vec.dedup();

    let mut waiting = WAITING_FILE_LOCKS.lock();
    if blocked_vec.is_empty() {
        waiting.retain(|record| record.owner_pid != owner_pid);
        return;
    }
    if let Some(record) = waiting
        .iter_mut()
        .find(|record| record.owner_pid == owner_pid)
    {
        record.blocked_by = blocked_vec;
    } else {
        waiting.push(WaitingLockRecord {
            owner_pid,
            blocked_by: blocked_vec,
        });
    }
}

fn waiting_lock_deadlock(owner_pid: i32, blocked_by: &[i32]) -> bool {
    fn dfs(
        owner_pid: i32,
        current: i32,
        waiting: &[WaitingLockRecord],
        visited: &mut Vec<i32>,
    ) -> bool {
        if current == owner_pid {
            return true;
        }
        if visited.contains(&current) {
            return false;
        }
        visited.push(current);
        let Some(record) = waiting.iter().find(|record| record.owner_pid == current) else {
            return false;
        };
        record
            .blocked_by
            .iter()
            .copied()
            .any(|next| dfs(owner_pid, next, waiting, visited))
    }

    let waiting = WAITING_FILE_LOCKS.lock();
    blocked_by
        .iter()
        .copied()
        .any(|blocked_owner| dfs(owner_pid, blocked_owner, &waiting, &mut Vec::new()))
}

fn posix_lock_state(
    key: FileKey,
    owner_pid: i32,
    typ: i16,
    start: i64,
    end: i64,
    waiter_ticket: Option<u64>,
) -> (Vec<i32>, bool, bool) {
    let blocked_by = {
        let locks = FILE_LOCKS.lock();
        conflicting_lock_owners(&locks, key, owner_pid, typ, start, end)
    };
    let ofd_conflict = {
        let ofd_locks = OFD_FILE_LOCKS.lock();
        has_conflicting_any_ofd_lock(&ofd_locks, key, typ, start, end)
    };
    let queued_waiter_conflict = waiter_ticket.is_some_and(|ticket| {
        has_prior_conflicting_waiter(
            ticket,
            LockWaiterKind::Posix,
            key,
            owner_pid,
            0,
            typ,
            start,
            end,
        )
    });
    let writer_waiter_conflict = typ == api::ctypes::F_RDLCK as i16
        && has_waiting_writer_conflict(
            waiter_ticket,
            LockWaiterKind::Posix,
            key,
            owner_pid,
            0,
            start,
            end,
        );
    (
        blocked_by,
        ofd_conflict,
        queued_waiter_conflict || writer_waiter_conflict,
    )
}

fn ofd_lock_state(
    key: FileKey,
    owner_identity: usize,
    typ: i16,
    start: i64,
    end: i64,
    waiter_ticket: Option<u64>,
) -> (bool, bool, bool) {
    let posix_conflict = {
        let posix_locks = FILE_LOCKS.lock();
        posix_locks
            .iter()
            .any(|existing| existing.key == key && locks_conflict(existing, typ, start, end))
    };
    let ofd_conflict = {
        let ofd_locks = OFD_FILE_LOCKS.lock();
        has_conflicting_ofd_locks(&ofd_locks, key, owner_identity, typ, start, end)
    };
    let queued_waiter_conflict = waiter_ticket.is_some_and(|ticket| {
        has_prior_conflicting_waiter(
            ticket,
            LockWaiterKind::Ofd,
            key,
            0,
            owner_identity,
            typ,
            start,
            end,
        )
    });
    let writer_waiter_conflict = typ == api::ctypes::F_RDLCK as i16
        && has_waiting_writer_conflict(
            waiter_ticket,
            LockWaiterKind::Ofd,
            key,
            0,
            owner_identity,
            start,
            end,
        );
    (
        posix_conflict,
        ofd_conflict,
        queued_waiter_conflict || writer_waiter_conflict,
    )
}

fn fcntl_getlk(fd: c_int, arg: usize, ofd: bool) -> Result<c_int, LinuxError> {
    let key = file_key_from_fd(fd)?;
    let mut lock = read_value_from_user(arg as *const UserFlock)?;
    validate_flock(&lock)?;
    let (start, end) = normalize_flock_range(fd, &lock)?;
    let conflict = find_conflicting_lock(
        fd,
        key,
        lock.l_type,
        start,
        end,
        if ofd { None } else { Some(current_pid()) },
        if ofd {
            Some(file_identity_from_fd(fd)?)
        } else {
            None
        },
    )?;
    if let Some(conflict) = conflict {
        lock.l_type = conflict.typ;
        lock.l_whence = 0;
        lock.l_start = conflict.start;
        lock.l_len = if conflict.end == i64::MAX {
            0
        } else {
            conflict.end - conflict.start
        };
        lock.l_pid = conflict.pid;
    } else {
        lock.l_type = api::ctypes::F_UNLCK as i16;
        lock.l_pid = 0;
    }
    write_value_to_user(arg as *mut UserFlock, lock)?;
    Ok(0)
}

fn fcntl_setlk(fd: c_int, arg: usize, wait: bool) -> Result<c_int, LinuxError> {
    let key = file_key_from_fd(fd)?;
    let lock = read_value_from_user(arg as *const UserFlock)?;
    validate_flock(&lock)?;
    let owner_pid = current_pid();
    let (start, end) = normalize_flock_range(fd, &lock)?;
    let mut waiter_ticket = None;
    loop {
        let (blocked_by, ofd_conflict, writer_waiter_conflict) =
            posix_lock_state(key, owner_pid, lock.l_type, start, end, waiter_ticket);
        if !blocked_by.is_empty() || ofd_conflict || writer_waiter_conflict {
            if !wait {
                clear_waiting_lock(owner_pid);
                if let Some(ticket) = waiter_ticket.take() {
                    clear_lock_waiter(ticket);
                }
                return Err(LinuxError::EAGAIN);
            }
            let ticket = *waiter_ticket.get_or_insert_with(next_lock_waiter_ticket);
            store_lock_waiter(LockWaiterRecord {
                ticket,
                kind: LockWaiterKind::Posix,
                key,
                owner_pid,
                owner_identity: 0,
                typ: lock.l_type,
                start,
                end,
            });
            if blocked_by.is_empty() {
                clear_waiting_lock(owner_pid);
            } else {
                store_waiting_lock(owner_pid, &blocked_by);
            }
            if !blocked_by.is_empty() && waiting_lock_deadlock(owner_pid, &blocked_by) {
                clear_waiting_lock(owner_pid);
                clear_lock_waiter(ticket);
                waiter_ticket = None;
                return Err(LinuxError::EDEADLK);
            }
            LOCK_WAIT_QUEUE.wait_until(|| {
                let (blocked_by, ofd_conflict, writer_waiter_conflict) =
                    posix_lock_state(key, owner_pid, lock.l_type, start, end, waiter_ticket);
                blocked_by.is_empty() && !ofd_conflict && !writer_waiter_conflict
            });
            continue;
        }
        clear_waiting_lock(owner_pid);
        let mut locks = FILE_LOCKS.lock();
        update_owner_lock(&mut locks, key, owner_pid, lock.l_type, start, end);
        drop(locks);
        if let Some(ticket) = waiter_ticket.take() {
            clear_lock_waiter(ticket);
        }
        LOCK_WAIT_QUEUE.notify_all(true);
        return Ok(0);
    }
}

fn fcntl_setlk_ofd(fd: c_int, arg: usize, wait: bool) -> Result<c_int, LinuxError> {
    let key = file_key_from_fd(fd)?;
    let owner_identity = file_identity_from_fd(fd)?;
    let lock = read_value_from_user(arg as *const UserFlock)?;
    validate_flock(&lock)?;
    let (start, end) = normalize_flock_range(fd, &lock)?;
    let mut waiter_ticket = None;
    loop {
        let (posix_conflict, ofd_conflict, writer_waiter_conflict) =
            ofd_lock_state(key, owner_identity, lock.l_type, start, end, waiter_ticket);
        if posix_conflict || ofd_conflict || writer_waiter_conflict {
            if !wait {
                if let Some(ticket) = waiter_ticket.take() {
                    clear_lock_waiter(ticket);
                }
                return Err(LinuxError::EAGAIN);
            }
            let ticket = *waiter_ticket.get_or_insert_with(next_lock_waiter_ticket);
            store_lock_waiter(LockWaiterRecord {
                ticket,
                kind: LockWaiterKind::Ofd,
                key,
                owner_pid: 0,
                owner_identity,
                typ: lock.l_type,
                start,
                end,
            });
            LOCK_WAIT_QUEUE.wait_until(|| {
                let (posix_conflict, ofd_conflict, writer_waiter_conflict) =
                    ofd_lock_state(key, owner_identity, lock.l_type, start, end, waiter_ticket);
                !posix_conflict && !ofd_conflict && !writer_waiter_conflict
            });
            continue;
        }
        let mut ofd_locks = OFD_FILE_LOCKS.lock();
        update_ofd_lock(&mut ofd_locks, key, owner_identity, lock.l_type, start, end);
        drop(ofd_locks);
        if let Some(ticket) = waiter_ticket.take() {
            clear_lock_waiter(ticket);
        }
        LOCK_WAIT_QUEUE.notify_all(true);
        return Ok(0);
    }
}

fn current_process_open_count(key: FileKey) -> usize {
    let table = api::FD_TABLE.read();
    table
        .iter()
        .filter(|(_, file)| {
            file.stat()
                .is_ok_and(|stat| stat.st_dev == key.dev && stat.st_ino == key.ino)
        })
        .count()
}

fn access_mode(flags: usize) -> u32 {
    (flags as u32) & api::ctypes::O_ACCMODE
}

fn get_async_control(identity: usize) -> AsyncFdControl {
    ASYNC_FD_CONTROLS
        .lock()
        .iter()
        .copied()
        .find(|control| control.identity == identity)
        .unwrap_or(AsyncFdControl {
            identity,
            owner_kind: F_OWNER_PID,
            owner_id: 0,
            signal: 0,
            enabled: false,
        })
}

fn store_async_control(control: AsyncFdControl) {
    let mut controls = ASYNC_FD_CONTROLS.lock();
    if let Some(slot) = controls
        .iter_mut()
        .find(|slot| slot.identity == control.identity)
    {
        *slot = control;
    } else {
        controls.push(control);
    }
}

fn fcntl_setlease(fd: c_int, arg: usize) -> Result<c_int, LinuxError> {
    let key = file_key_from_fd(fd)?;
    let identity = file_identity_from_fd(fd)?;
    let owner_pid = current_pid();
    let access = access_mode(api::get_file_like(fd)?.status_flags());
    let typ = arg as i32;
    let mut leases = FILE_LEASES.lock();
    let existing = leases
        .iter()
        .copied()
        .find(|lease| lease.identity == identity && lease.owner_pid == owner_pid);
    leases.retain(|lease| !(lease.identity == identity && lease.owner_pid == owner_pid));
    match typ as u32 {
        api::ctypes::F_UNLCK => Ok(0),
        api::ctypes::F_WRLCK => {
            if current_process_open_count(key) > 1 {
                return Err(LinuxError::EAGAIN);
            }
            leases.push(LeaseRecord {
                key,
                owner_pid,
                identity,
                typ,
                last_break_write_like: false,
            });
            Ok(0)
        }
        api::ctypes::F_RDLCK => {
            if existing.is_some_and(|lease| {
                lease.typ == api::ctypes::F_WRLCK as i32 && lease.last_break_write_like
            }) {
                return Err(LinuxError::EAGAIN);
            }
            if access != api::ctypes::O_RDONLY {
                return Err(LinuxError::EAGAIN);
            }
            leases.push(LeaseRecord {
                key,
                owner_pid,
                identity,
                typ,
                last_break_write_like: false,
            });
            Ok(0)
        }
        _ => Err(LinuxError::EINVAL),
    }
}

fn fcntl_getlease(fd: c_int) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    Ok(FILE_LEASES
        .lock()
        .iter()
        .find(|lease| lease.identity == identity)
        .map(|lease| lease.typ)
        .unwrap_or(api::ctypes::F_UNLCK as i32))
}

fn validate_owner_ex(owner: UserFOwnerEx) -> Result<(), LinuxError> {
    if matches!(owner.type_, F_OWNER_TID | F_OWNER_PID | F_OWNER_PGRP) {
        Ok(())
    } else {
        Err(LinuxError::EINVAL)
    }
}

fn fcntl_setown(fd: c_int, arg: i32) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    let (owner_kind, owner_id) = if arg < 0 {
        (F_OWNER_PGRP, -arg)
    } else {
        (F_OWNER_PID, arg)
    };
    let mut control = get_async_control(identity);
    control.owner_kind = owner_kind;
    control.owner_id = owner_id;
    store_async_control(control);
    Ok(0)
}

fn fcntl_getown(fd: c_int) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    let control = get_async_control(identity);
    Ok(match control.owner_kind {
        F_OWNER_PGRP => -control.owner_id,
        _ => control.owner_id,
    })
}

fn fcntl_setown_ex(fd: c_int, arg: usize) -> Result<c_int, LinuxError> {
    let owner = read_value_from_user(arg as *const UserFOwnerEx)?;
    validate_owner_ex(owner)?;
    let identity = file_identity_from_fd(fd)?;
    let mut control = get_async_control(identity);
    control.owner_kind = owner.type_;
    control.owner_id = owner.pid;
    store_async_control(control);
    Ok(0)
}

fn fcntl_getown_ex(fd: c_int, arg: usize) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    let control = get_async_control(identity);
    write_value_to_user(
        arg as *mut UserFOwnerEx,
        UserFOwnerEx {
            type_: control.owner_kind,
            pid: control.owner_id,
        },
    )?;
    Ok(0)
}

fn fcntl_setsig(fd: c_int, sig: i32) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    let mut control = get_async_control(identity);
    control.signal = sig;
    store_async_control(control);
    Ok(0)
}

fn fcntl_getsig(fd: c_int) -> Result<c_int, LinuxError> {
    let identity = file_identity_from_fd(fd)?;
    Ok(get_async_control(identity).signal)
}

fn update_async_enabled(fd: c_int, arg: usize) {
    if let Ok(identity) = file_identity_from_fd(fd) {
        let mut control = get_async_control(identity);
        control.enabled = (arg & api::ctypes::O_ASYNC as usize) != 0;
        store_async_control(control);
    }
}

fn fd_identity_open_count(identity: usize) -> usize {
    api::FD_TABLE
        .read()
        .iter()
        .filter(|(_, file)| file.fcntl_identity() == identity)
        .count()
}

fn fd_identity_shared_outside_current_table(identity: usize) -> bool {
    let table = api::FD_TABLE.read();
    let local_count = table
        .iter()
        .filter(|(_, file)| file.fcntl_identity() == identity)
        .count();
    table
        .iter()
        .filter(|(_, file)| file.fcntl_identity() == identity)
        .any(|(_, file)| Arc::strong_count(file) > local_count)
}

fn fd_tracking_identity_can_be_released(identity: usize) -> bool {
    fd_identity_open_count(identity) <= 1 && !fd_identity_shared_outside_current_table(identity)
}

fn cleanup_fd_tracking(fd: c_int) {
    let owner_pid = current_pid();
    let mut changed = false;
    if let Ok(key) = file_key_from_fd(fd) {
        let mut locks = FILE_LOCKS.lock();
        let before = locks.len();
        locks.retain(|lock| !(lock.key == key && lock.owner_pid == owner_pid));
        changed |= locks.len() != before;
    }
    if let Ok(identity) = file_identity_from_fd(fd) {
        if fd_tracking_identity_can_be_released(identity) {
            let mut ofd_locks = OFD_FILE_LOCKS.lock();
            let before = ofd_locks.len();
            ofd_locks.retain(|lock| lock.owner_identity != identity);
            changed |= ofd_locks.len() != before;
            drop(ofd_locks);
            let mut flock_locks = FLOCK_LOCKS.lock();
            let before = flock_locks.len();
            flock_locks.retain(|lock| lock.owner_identity != identity);
            changed |= flock_locks.len() != before;
            drop(flock_locks);
            FILE_LEASES
                .lock()
                .retain(|lease| lease.identity != identity);
            ASYNC_FD_CONTROLS
                .lock()
                .retain(|control| control.identity != identity);
        }
    }
    if changed {
        LOCK_WAIT_QUEUE.notify_all(true);
    }
}

pub(crate) fn cleanup_all_fd_tracking_for_current_process() {
    clear_waiting_lock(current_pid());
    let (open_fds, identities): (Vec<c_int>, Vec<usize>) = {
        let table = api::FD_TABLE.read();
        (
            table.iter().map(|(fd, _)| fd as c_int).collect(),
            table
                .iter()
                .filter_map(|(_, file)| {
                    let identity = file.fcntl_identity();
                    let local_count = table
                        .iter()
                        .filter(|(_, other)| other.fcntl_identity() == identity)
                        .count();
                    (Arc::strong_count(file) <= local_count).then_some(identity)
                })
                .collect(),
        )
    };
    for fd in open_fds {
        cleanup_fd_tracking(fd);
    }
    OFD_FILE_LOCKS
        .lock()
        .retain(|lock| !identities.contains(&lock.owner_identity));
    FLOCK_LOCKS
        .lock()
        .retain(|lock| !identities.contains(&lock.owner_identity));
    FILE_LEASES
        .lock()
        .retain(|lease| !identities.contains(&lease.identity));
    ASYNC_FD_CONTROLS
        .lock()
        .retain(|control| !identities.contains(&control.identity));
    let curr_pid = current_pid();
    LOCK_WAITERS.lock().retain(|waiter| match waiter.kind {
        LockWaiterKind::Posix => waiter.owner_pid != curr_pid,
        LockWaiterKind::Ofd => !identities.contains(&waiter.owner_identity),
    });
    LOCK_WAIT_QUEUE.notify_all(true);
}

fn send_async_signal(control: AsyncFdControl) {
    if !control.enabled || control.owner_id <= 0 {
        return;
    }
    let signum = if control.signal > 0 {
        control.signal as usize
    } else {
        SIGIO
    };
    let sender_pid = current_pid();
    let sender_uid = current_uid();
    match control.owner_kind {
        F_OWNER_TID => {
            if let Some(task) = find_live_task_by_tid(control.owner_id as u64) {
                send_user_signal_to_task(&task, signum, sender_pid, sender_uid);
            }
        }
        F_OWNER_PGRP => {
            for leader in process_leader_tasks() {
                if leader.task_ext().process_group() as i32 == control.owner_id {
                    send_user_signal_to_task(&leader, signum, sender_pid, sender_uid);
                }
            }
        }
        _ => {
            if let Some(task) = find_process_leader_by_pid(control.owner_id as usize) {
                send_user_signal_to_task(&task, signum, sender_pid, sender_uid);
            }
        }
    }
}

pub(crate) fn notify_fd_write_event(fd: c_int) {
    if let Ok(identity) = file_identity_from_fd(fd) {
        let control = get_async_control(identity);
        send_async_signal(control);
    }
}

fn lease_conflicts(lease: &LeaseRecord, write_like: bool, truncating: bool) -> bool {
    lease.typ == api::ctypes::F_WRLCK as i32 || write_like || truncating
}

pub(crate) fn notify_lease_break_for_fd(fd: c_int, write_like: bool, truncating: bool) {
    let Ok(key) = file_key_from_fd(fd) else {
        return;
    };
    let curr_pid = current_pid();
    let sender_uid = current_uid();
    let mut leases = FILE_LEASES.lock();
    let targets: Vec<_> = leases
        .iter_mut()
        .filter(|lease| {
            lease.key == key
                && lease.owner_pid != curr_pid
                && lease_conflicts(lease, write_like, truncating)
        })
        .map(|lease| {
            lease.last_break_write_like = write_like || truncating;
            *lease
        })
        .collect();
    drop(leases);
    for lease in targets {
        if let Some(task) = find_process_leader_by_pid(lease.owner_pid as usize) {
            send_user_signal_to_task(&task, SIGIO, curr_pid, sender_uid);
        }
    }
}

pub(crate) fn sys_dup(old_fd: c_int) -> c_int {
    api::sys_dup(old_fd)
}

pub(crate) fn sys_eventfd2(initval: u32, flags: c_int) -> c_int {
    api::sys_eventfd2(initval, flags)
}

pub(crate) fn sys_dup3(old_fd: c_int, new_fd: c_int, flags: c_int) -> c_int {
    syscall_body!(sys_dup3, {
        let flags = flags as u32;
        if old_fd == new_fd {
            return Err(LinuxError::EINVAL);
        }
        if flags & !(api::ctypes::O_CLOEXEC) != 0 {
            return Err(LinuxError::EINVAL);
        }

        let duped = api_ret(api::sys_dup2(old_fd, new_fd))?;
        let fd_flags = if flags & api::ctypes::O_CLOEXEC != 0 {
            1
        } else {
            0
        };
        api_ret(api::sys_fcntl(new_fd, api::ctypes::F_SETFD as _, fd_flags))?;
        Ok(duped)
    })
}

pub(crate) fn sys_close(fd: c_int) -> c_int {
    cleanup_fd_tracking(fd);
    api::sys_close(fd)
}

pub(crate) fn sys_fcntl(fd: c_int, cmd: c_int, arg: usize) -> c_int {
    syscall_body!(sys_fcntl, {
        match cmd as u32 {
            api::ctypes::F_GETLK => fcntl_getlk(fd, arg, false),
            api::ctypes::F_SETLK => fcntl_setlk(fd, arg, false),
            api::ctypes::F_SETLKW => fcntl_setlk(fd, arg, true),
            F_OFD_GETLK => fcntl_getlk(fd, arg, true),
            F_OFD_SETLK => fcntl_setlk_ofd(fd, arg, false),
            F_OFD_SETLKW => fcntl_setlk_ofd(fd, arg, true),
            F_SETLEASE => fcntl_setlease(fd, arg),
            F_GETLEASE => fcntl_getlease(fd),
            api::ctypes::F_SETOWN => fcntl_setown(fd, arg as i32),
            api::ctypes::F_GETOWN => fcntl_getown(fd),
            F_SETOWN_EX => fcntl_setown_ex(fd, arg),
            F_GETOWN_EX => fcntl_getown_ex(fd, arg),
            api::ctypes::F_SETSIG => fcntl_setsig(fd, arg as i32),
            api::ctypes::F_GETSIG => fcntl_getsig(fd),
            api::ctypes::F_SETFL => {
                let ret = api_ret(api::sys_fcntl(fd, cmd, arg))?;
                update_async_enabled(fd, arg);
                Ok(ret)
            }
            _ => api_ret(api::sys_fcntl(fd, cmd, arg)),
        }
    })
}

pub(crate) fn sys_flock(fd: c_int, operation: c_int) -> c_int {
    syscall_body!(sys_flock, {
        let op = operation & !LOCK_NB;
        if !matches!(op, LOCK_SH | LOCK_EX | LOCK_UN) {
            return Err(LinuxError::EINVAL);
        }
        let key = file_key_from_fd(fd)?;
        let identity = file_identity_from_fd(fd)?;
        if op == LOCK_UN {
            FLOCK_LOCKS
                .lock()
                .retain(|lock| lock.owner_identity != identity);
            LOCK_WAIT_QUEUE.notify_all(true);
            return Ok(0);
        }
        let exclusive = op == LOCK_EX;
        loop {
            let blocked = {
                let locks = FLOCK_LOCKS.lock();
                locks.iter().any(|lock| {
                    lock.key == key
                        && lock.owner_identity != identity
                        && (exclusive || lock.exclusive)
                })
            };
            if blocked {
                if operation & LOCK_NB != 0 {
                    return Err(LinuxError::EAGAIN);
                }
                LOCK_WAIT_QUEUE.wait_until(|| {
                    let locks = FLOCK_LOCKS.lock();
                    !locks.iter().any(|lock| {
                        lock.key == key
                            && lock.owner_identity != identity
                            && (exclusive || lock.exclusive)
                    })
                });
                continue;
            }
            let mut locks = FLOCK_LOCKS.lock();
            locks.retain(|lock| lock.owner_identity != identity);
            locks.push(FlockRecord {
                key,
                owner_identity: identity,
                exclusive,
            });
            return Ok(0);
        }
    })
}

pub(crate) fn sys_sync() -> c_int {
    0
}

pub(crate) fn sys_fsync(fd: c_int) -> c_int {
    syscall_body!(sys_fsync, {
        api::get_file_like(fd)?.sync_all()?;
        Ok(0)
    })
}

pub(crate) fn sys_syncfs(fd: c_int) -> c_int {
    syscall_body!(sys_syncfs, {
        api::get_file_like(fd)?.sync_all()?;
        Ok(0)
    })
}

pub(crate) fn sys_fdatasync(fd: c_int) -> c_int {
    sys_fsync(fd)
}

pub(crate) fn sys_close_range(first: u32, last: u32, flags: u32) -> isize {
    syscall_body!(sys_close_range, {
        let supported = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
        if flags & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }
        if first > last {
            return Err(LinuxError::EINVAL);
        }

        let first = first as usize;
        if first >= api::AX_FILE_LIMIT {
            return Ok(0);
        }
        let last = (last as usize).min(api::AX_FILE_LIMIT - 1);

        if flags & CLOSE_RANGE_UNSHARE != 0 {
            let current = current();
            let ns = &current.task_ext().ns;
            let new_fd_table = api::FD_TABLE.copy_inner();
            let new_fd_flags = api::FD_FLAGS.copy_inner();
            api::FD_TABLE
                .deref_from(ns)
                .replace_shared(Arc::new(new_fd_table));
            api::FD_FLAGS
                .deref_from(ns)
                .replace_shared(Arc::new(new_fd_flags));
        }

        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            let present_fds = {
                let table = api::FD_TABLE.read();
                let mut fds = Vec::new();
                for fd in first..=last {
                    if table.get(fd).is_some() {
                        fds.push(fd);
                    }
                }
                fds
            };
            let mut flag_table = api::FD_FLAGS.write();
            for fd in present_fds {
                if flag_table.get(fd).is_some() {
                    let _ = flag_table.remove(fd);
                }
                flag_table
                    .add_at(fd, api::ctypes::FD_CLOEXEC as usize)
                    .map_err(|_| LinuxError::EMFILE)?;
            }
            return Ok(0);
        }

        let close_fds = {
            let table = api::FD_TABLE.read();
            let mut fds = Vec::new();
            for fd in first..=last {
                if table.get(fd).is_some() {
                    fds.push(fd as c_int);
                }
            }
            fds
        };
        for fd in close_fds {
            let _ = sys_close(fd);
        }
        Ok(0)
    })
}
