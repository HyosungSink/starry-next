use alloc::sync::Arc;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use axsync::Mutex;
use axtask::WaitQueue;

use super::fd_ops::{FD_CLOEXEC_FLAG, FileLike, add_file_like_with_fd_flags};
use crate::ctypes;

const EFD_SEMAPHORE: u32 = 0x1;
const EVENTFD_MAX: u64 = u64::MAX - 1;

struct EventFdState {
    counter: u64,
    overflowed: bool,
}

pub struct EventFd {
    state: Mutex<EventFdState>,
    wait_queue: WaitQueue,
    semaphore: bool,
    nonblocking: AtomicBool,
}

impl EventFd {
    fn new(initval: u32, flags: u32) -> Self {
        Self {
            state: Mutex::new(EventFdState {
                counter: initval as u64,
                overflowed: false,
            }),
            wait_queue: WaitQueue::new(),
            semaphore: (flags & EFD_SEMAPHORE) != 0,
            nonblocking: AtomicBool::new((flags & ctypes::O_NONBLOCK) != 0),
        }
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    fn kernel_add(&self, value: u64) {
        if value == 0 {
            return;
        }
        let mut state = self.state.lock();
        if state.overflowed {
            return;
        }
        if value > EVENTFD_MAX.saturating_sub(state.counter) {
            state.counter = u64::MAX;
            state.overflowed = true;
        } else {
            state.counter += value;
        }
        drop(state);
        self.wait_queue.notify_all(true);
    }

    fn poll_extra_revents(&self) -> i16 {
        if self.state.lock().overflowed { 0x008 } else { 0 }
    }
}

impl FileLike for EventFd {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.len() < 8 {
            return Err(LinuxError::EINVAL);
        }
        loop {
            let value = {
                let mut state = self.state.lock();
                if state.counter == 0 && !state.overflowed {
                    if self.is_nonblocking() {
                        return Err(LinuxError::EAGAIN);
                    }
                    None
                } else if state.overflowed {
                    state.counter = 0;
                    state.overflowed = false;
                    Some(u64::MAX)
                } else if self.semaphore {
                    state.counter -= 1;
                    Some(1u64)
                } else {
                    let value = state.counter;
                    state.counter = 0;
                    Some(value)
                }
            };
            if let Some(value) = value {
                buf[..8].copy_from_slice(&value.to_ne_bytes());
                self.wait_queue.notify_all(true);
                return Ok(8);
            }
            self.wait_queue.wait_until(|| self.state.lock().counter > 0);
        }
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if buf.len() != 8 {
            return Err(LinuxError::EINVAL);
        }
        let value = u64::from_ne_bytes(buf[..8].try_into().unwrap());
        if value == u64::MAX {
            return Err(LinuxError::EINVAL);
        }
        loop {
            let writable = {
                let mut state = self.state.lock();
                if !state.overflowed && value <= EVENTFD_MAX.saturating_sub(state.counter) {
                    state.counter += value;
                    true
                } else if self.is_nonblocking() {
                    return Err(LinuxError::EAGAIN);
                } else {
                    false
                }
            };
            if writable {
                self.wait_queue.notify_all(true);
                return Ok(8);
            }
            self.wait_queue
                .wait_until(|| {
                    let state = self.state.lock();
                    !state.overflowed && state.counter <= EVENTFD_MAX.saturating_sub(value)
                });
        }
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o600,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 4096,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let state = self.state.lock();
        Ok(PollState {
            readable: state.counter > 0 || state.overflowed,
            writable: !state.overflowed && state.counter < EVENTFD_MAX,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn status_flags(&self) -> usize {
        let mut flags = ctypes::O_RDWR as usize;
        if self.is_nonblocking() {
            flags |= ctypes::O_NONBLOCK as usize;
        }
        flags
    }
}

pub fn sys_eventfd2(initval: u32, flags: c_int) -> c_int {
    debug!("sys_eventfd2 <= initval: {} flags: {:#x}", initval, flags);
    syscall_body!(sys_eventfd2, {
        let flags = flags as u32;
        let supported = EFD_SEMAPHORE | ctypes::O_CLOEXEC | ctypes::O_NONBLOCK;
        if flags & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }
        let fd_flags = if (flags & ctypes::O_CLOEXEC) != 0 {
            FD_CLOEXEC_FLAG
        } else {
            0
        };
        add_file_like_with_fd_flags(Arc::new(EventFd::new(initval, flags)), fd_flags)
    })
}

pub fn signal_eventfd(fd: c_int, value: u64) -> LinuxResult {
    let file = super::fd_ops::get_file_like(fd)?;
    let eventfd = file
        .into_any()
        .downcast::<EventFd>()
        .map_err(|_| LinuxError::EINVAL)?;
    eventfd.kernel_add(value);
    Ok(())
}

pub fn poll_extra_revents(fd: c_int) -> LinuxResult<i16> {
    let file = super::fd_ops::get_file_like(fd)?;
    if let Ok(eventfd) = file.into_any().downcast::<EventFd>() {
        return Ok(eventfd.poll_extra_revents());
    }
    Ok(0)
}
