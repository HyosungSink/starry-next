use alloc::sync::Arc;
use core::{
    ffi::c_int,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use arceos_posix_api::{self as api, add_file_like, get_file_like, FileLike, PollState};
use axerrno::{LinuxError, LinuxResult};
use axsync::spin::SpinNoIrq;
use axtask::WaitQueue;

use crate::{
    syscall_body,
    timekeeping::{
        current_realtime_nanos, monotonic_deadline_from_clock, nanos_to_timespec,
        timespec_to_nanos,
    },
    usercopy::{read_value_from_user, write_value_to_user},
};

const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const CLOCK_BOOTTIME: i32 = 7;
const CLOCK_REALTIME_ALARM: i32 = 8;
const CLOCK_BOOTTIME_ALARM: i32 = 9;

const TFD_TIMER_ABSTIME: i32 = 1;
const TFD_TIMER_CANCEL_ON_SET: i32 = 2;
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct TimerFdItimerspec {
    it_interval: api::ctypes::timespec,
    it_value: api::ctypes::timespec,
}

struct TimerFdState {
    interval_ns: u64,
    next_deadline_ns: u64,
    expirations: u64,
}

pub struct TimerFd {
    clock_id: i32,
    wait_queue: WaitQueue,
    state: SpinNoIrq<TimerFdState>,
    disarmed: AtomicBool,
    nonblocking: AtomicBool,
    waiters: AtomicUsize,
}

impl TimerFd {
    fn new(clock_id: i32, nonblocking: bool) -> Self {
        Self {
            clock_id,
            wait_queue: WaitQueue::new(),
            state: SpinNoIrq::new(TimerFdState {
                interval_ns: 0,
                next_deadline_ns: 0,
                expirations: 0,
            }),
            disarmed: AtomicBool::new(true),
            nonblocking: AtomicBool::new(nonblocking),
            waiters: AtomicUsize::new(0),
        }
    }

    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let file = get_file_like(fd)?;
        file.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::EINVAL)
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    fn current_mono_ns() -> u64 {
        axhal::time::monotonic_time_nanos()
    }

    fn saturating_duration_until(deadline_ns: u64, now_ns: u64) -> Duration {
        Duration::from_nanos(deadline_ns.saturating_sub(now_ns))
    }

    fn deadline_from_clock(&self, value_ns: u64, absolute: bool) -> LinuxResult<u64> {
        let now_mono = Self::current_mono_ns();
        if !absolute {
            return now_mono.checked_add(value_ns).ok_or(LinuxError::EINVAL);
        }
        if self.clock_id == CLOCK_REALTIME {
            let now_clock = current_realtime_nanos();
            return Ok(now_mono.saturating_add(value_ns.saturating_sub(now_clock)));
        }
        monotonic_deadline_from_clock(self.clock_id, value_ns, true)
    }

    fn notify_waiters_if_any(&self) {
        if self.waiters.load(Ordering::Acquire) != 0 && self.wait_queue.has_waiters() {
            self.wait_queue.notify_all(true);
        }
    }

    fn wait_for_change(&self, wait_duration: Option<Duration>) {
        self.waiters.fetch_add(1, Ordering::AcqRel);
        match wait_duration {
            Some(duration) => {
                let _ = self.wait_queue.wait_timeout(duration);
            }
            None => self.wait_queue.wait(),
        }
        self.waiters.fetch_sub(1, Ordering::AcqRel);
    }

    fn update_state_locked(state: &mut TimerFdState, now_ns: u64) {
        if state.next_deadline_ns == 0 || now_ns < state.next_deadline_ns {
            return;
        }

        if state.interval_ns == 0 {
            state.expirations = state.expirations.saturating_add(1);
            state.next_deadline_ns = 0;
            return;
        }

        let overdue = now_ns.saturating_sub(state.next_deadline_ns);
        let intervals = overdue / state.interval_ns;
        let new_expirations = intervals.saturating_add(1);
        state.expirations = state.expirations.saturating_add(new_expirations);
        let advance = state.interval_ns.saturating_mul(new_expirations);
        state.next_deadline_ns = state.next_deadline_ns.saturating_add(advance);
    }

    fn snapshot_value_locked(state: &TimerFdState, now_ns: u64) -> (u64, u64) {
        let value_ns = if state.next_deadline_ns == 0 {
            0
        } else {
            state.next_deadline_ns.saturating_sub(now_ns)
        };
        (state.interval_ns, value_ns)
    }

    fn state_is_disarmed(state: &TimerFdState) -> bool {
        state.interval_ns == 0 && state.next_deadline_ns == 0 && state.expirations == 0
    }

    fn set_time(&self, flags: i32, new_value: TimerFdItimerspec) -> LinuxResult<TimerFdItimerspec> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(LinuxError::EINVAL);
        }
        if (flags & TFD_TIMER_CANCEL_ON_SET) != 0 && self.clock_id != CLOCK_REALTIME {
            return Err(LinuxError::EINVAL);
        }

        let interval_ns = timespec_to_nanos(new_value.it_interval)?;
        let value_ns = timespec_to_nanos(new_value.it_value)?;
        let now_ns = Self::current_mono_ns();

        let mut state = self.state.lock();
        Self::update_state_locked(&mut state, now_ns);
        let had_expirations = state.expirations > 0;
        let (old_interval_ns, old_value_ns) = Self::snapshot_value_locked(&state, now_ns);

        if value_ns == 0 {
            state.interval_ns = 0;
            state.next_deadline_ns = 0;
            state.expirations = 0;
        } else {
            state.interval_ns = interval_ns;
            state.next_deadline_ns =
                self.deadline_from_clock(value_ns, (flags & TFD_TIMER_ABSTIME) != 0)?;
            state.expirations = 0;
        }
        self.disarmed
            .store(Self::state_is_disarmed(&state), Ordering::Release);
        let should_notify = had_expirations || old_value_ns != 0 || value_ns != 0;
        drop(state);
        if should_notify {
            self.notify_waiters_if_any();
        }

        Ok(TimerFdItimerspec {
            it_interval: nanos_to_timespec(old_interval_ns),
            it_value: nanos_to_timespec(old_value_ns),
        })
    }

    fn set_time_without_old_value(
        &self,
        flags: i32,
        new_value: TimerFdItimerspec,
    ) -> LinuxResult<()> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(LinuxError::EINVAL);
        }
        if (flags & TFD_TIMER_CANCEL_ON_SET) != 0 && self.clock_id != CLOCK_REALTIME {
            return Err(LinuxError::EINVAL);
        }

        let value_ns = timespec_to_nanos(new_value.it_value)?;

        if value_ns == 0 && self.disarmed.load(Ordering::Acquire) {
            return Ok(());
        }

        let interval_ns = timespec_to_nanos(new_value.it_interval)?;

        if value_ns == 0 {
            let mut state = self.state.lock();
            let was_active =
                state.interval_ns != 0 || state.next_deadline_ns != 0 || state.expirations != 0;
            state.interval_ns = 0;
            state.next_deadline_ns = 0;
            state.expirations = 0;
            self.disarmed.store(true, Ordering::Release);
            drop(state);
            if was_active {
                self.notify_waiters_if_any();
            }
            return Ok(());
        }

        let mut state = self.state.lock();
        state.interval_ns = interval_ns;
        state.next_deadline_ns =
            self.deadline_from_clock(value_ns, (flags & TFD_TIMER_ABSTIME) != 0)?;
        state.expirations = 0;
        self.disarmed.store(false, Ordering::Release);
        drop(state);
        self.notify_waiters_if_any();
        Ok(())
    }

    fn get_time(&self) -> TimerFdItimerspec {
        let now_ns = Self::current_mono_ns();
        let mut state = self.state.lock();
        Self::update_state_locked(&mut state, now_ns);
        let (interval_ns, value_ns) = Self::snapshot_value_locked(&state, now_ns);
        TimerFdItimerspec {
            it_interval: nanos_to_timespec(interval_ns),
            it_value: nanos_to_timespec(value_ns),
        }
    }
}

impl FileLike for TimerFd {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.len() < core::mem::size_of::<u64>() {
            return Err(LinuxError::EINVAL);
        }

        loop {
            let wait_duration = {
                let now_ns = Self::current_mono_ns();
                let mut state = self.state.lock();
                Self::update_state_locked(&mut state, now_ns);

                if state.expirations > 0 {
                    let expirations = state.expirations;
                    state.expirations = 0;
                    self.disarmed
                        .store(Self::state_is_disarmed(&state), Ordering::Release);
                    buf[..8].copy_from_slice(&expirations.to_ne_bytes());
                    return Ok(8);
                }

                if self.is_nonblocking() {
                    return Err(LinuxError::EAGAIN);
                }

                if state.next_deadline_ns == 0 {
                    None
                } else {
                    Some(Self::saturating_duration_until(
                        state.next_deadline_ns,
                        now_ns,
                    ))
                }
            };

            match wait_duration {
                Some(duration) => {
                    if duration.is_zero() {
                        core::hint::spin_loop();
                    } else {
                        self.wait_for_change(Some(duration));
                    }
                }
                None => self.wait_for_change(None),
            }
        }
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> LinuxResult<api::ctypes::stat> {
        Ok(api::ctypes::stat {
            st_ino: 1,
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

    fn poll(&self) -> LinuxResult<PollState> {
        let now_ns = Self::current_mono_ns();
        let mut state = self.state.lock();
        Self::update_state_locked(&mut state, now_ns);
        Ok(PollState {
            readable: state.expirations > 0,
            writable: true,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        if nonblocking {
            self.wait_queue.notify_all(true);
        }
        Ok(())
    }

    fn status_flags(&self) -> usize {
        let mut flags = api::ctypes::O_RDWR as usize;
        if self.is_nonblocking() {
            flags |= api::ctypes::O_NONBLOCK as usize;
        }
        flags
    }
}

fn validate_timerfd_clock(clock_id: i32) -> LinuxResult<()> {
    match clock_id {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => Ok(()),
        CLOCK_REALTIME_ALARM | CLOCK_BOOTTIME_ALARM => Err(LinuxError::EOPNOTSUPP),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn sys_timerfd_create(clock_id: i32, flags: c_int) -> isize {
    syscall_body!(sys_timerfd_create, {
        validate_timerfd_clock(clock_id)?;
        let flags = flags as u32;
        let supported = api::ctypes::O_CLOEXEC | api::ctypes::O_NONBLOCK;
        if flags & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }

        let fd = add_file_like(Arc::new(TimerFd::new(
            clock_id,
            (flags & api::ctypes::O_NONBLOCK) != 0,
        )))? as c_int;

        if (flags & api::ctypes::O_CLOEXEC) != 0 {
            let ret = api::sys_fcntl(
                fd,
                api::ctypes::F_SETFD as _,
                api::ctypes::FD_CLOEXEC as usize,
            );
            if ret < 0 {
                let _ = api::sys_close(fd);
                return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EINVAL));
            }
        }

        Ok(fd as isize)
    })
}

pub(crate) fn sys_timerfd_settime(
    fd: c_int,
    flags: i32,
    new_value: *const TimerFdItimerspec,
    old_value: *mut TimerFdItimerspec,
) -> isize {
    if new_value.is_null() {
        return -LinuxError::EFAULT.code() as isize;
    }
    let timerfd = match TimerFd::from_fd(fd) {
        Ok(timerfd) => timerfd,
        Err(err) => return -err.code() as isize,
    };
    let new_value = match read_value_from_user(new_value) {
        Ok(new_value) => new_value,
        Err(err) => return -err.code() as isize,
    };
    if old_value.is_null() {
        if let Err(err) = timerfd.set_time_without_old_value(flags, new_value) {
            return -err.code() as isize;
        }
    } else {
        let old_spec = match timerfd.set_time(flags, new_value) {
            Ok(old_spec) => old_spec,
            Err(err) => return -err.code() as isize,
        };
        if let Err(err) = write_value_to_user(old_value, old_spec) {
            return -err.code() as isize;
        }
    }
    0
}

pub(crate) fn sys_timerfd_gettime(fd: c_int, curr_value: *mut TimerFdItimerspec) -> isize {
    syscall_body!(sys_timerfd_gettime, {
        let timerfd = TimerFd::from_fd(fd)?;
        if curr_value.is_null() {
            return Err(LinuxError::EFAULT);
        }
        write_value_to_user(curr_value, timerfd.get_time())?;
        Ok(0)
    })
}
