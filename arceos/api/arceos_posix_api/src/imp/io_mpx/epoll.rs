//! `epoll` implementation.
//!
//! TODO: do not support `EPOLLET` flag

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::collections::btree_map::Entry;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::{ffi::c_int, time::Duration};

use axerrno::{LinuxError, LinuxResult};
use axhal::time::wall_time;
use axio::PollState;
use axsync::Mutex;

use crate::ctypes;
use crate::imp::fd_ops::{FileLike, add_file_like, get_file_like};
#[cfg(feature = "net")]
use crate::imp::net::Socket;

pub struct EpollInstance {
    events: Mutex<BTreeMap<usize, StoredEpollEvent>>,
}

const EPOLL_MAX_NEST_DEPTH: usize = 5;

#[derive(Copy, Clone)]
struct StoredEpollEvent {
    events: u32,
    data_u64: u64,
    last_ready: u32,
    disabled: bool,
}

fn read_epoll_event(raw: &ctypes::epoll_event) -> StoredEpollEvent {
    let events = unsafe { core::ptr::addr_of!(raw.events).read_unaligned() };
    let data_u64 = unsafe { core::ptr::addr_of!(raw.data.u64_).read_unaligned() };
    StoredEpollEvent {
        events,
        data_u64,
        last_ready: 0,
        disabled: false,
    }
}

fn write_epoll_event(raw: &mut ctypes::epoll_event, event: StoredEpollEvent) {
    unsafe {
        core::ptr::addr_of_mut!(raw.events).write_unaligned(event.events);
        core::ptr::addr_of_mut!(raw.data.u64_).write_unaligned(event.data_u64);
    }
}

fn fd_supports_epoll(fd: c_int) -> LinuxResult<bool> {
    let st_mode = get_file_like(fd)?.stat()?.st_mode & 0o170000;
    Ok(!matches!(st_mode, 0o100000 | 0o040000))
}

impl EpollInstance {
    // TODO: parse flags
    pub fn new(_flags: usize) -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }

    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        get_file_like(fd)?
            .into_any()
            .downcast::<EpollInstance>()
            .map_err(|_| LinuxError::EINVAL)
    }

    fn try_from_fd(fd: c_int) -> LinuxResult<Option<Arc<Self>>> {
        Ok(get_file_like(fd)?
            .into_any()
            .downcast::<EpollInstance>()
            .ok())
    }

    fn instance_id(&self) -> usize {
        self as *const Self as usize
    }

    fn nested_epolls(&self) -> LinuxResult<Vec<Arc<Self>>> {
        let fds: Vec<_> = self.events.lock().keys().copied().collect();
        let mut nested = Vec::new();
        for fd in fds {
            if let Some(epoll) = Self::try_from_fd(fd as c_int)? {
                nested.push(epoll);
            }
        }
        Ok(nested)
    }

    fn contains_fd(&self, needle_fd: c_int, visited: &mut BTreeSet<usize>) -> LinuxResult<bool> {
        let self_id = self.instance_id();
        if !visited.insert(self_id) {
            return Ok(false);
        }
        let fds: Vec<_> = self.events.lock().keys().copied().collect();
        if fds.iter().any(|&fd| fd as c_int == needle_fd) {
            return Ok(true);
        }
        for nested in self.nested_epolls()? {
            if nested.contains_fd(needle_fd, visited)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn nesting_depth(&self, visited: &mut BTreeSet<usize>) -> LinuxResult<usize> {
        let self_id = self.instance_id();
        if !visited.insert(self_id) {
            return Ok(0);
        }
        let mut max_depth = 1usize;
        for nested in self.nested_epolls()? {
            max_depth = max_depth.max(1 + nested.nesting_depth(visited)?);
        }
        Ok(max_depth)
    }

    fn validate_add_target(&self, epfd: c_int, fd: c_int) -> LinuxResult<()> {
        if fd == epfd {
            return Err(LinuxError::EINVAL);
        }
        let Some(target) = Self::try_from_fd(fd)? else {
            return Ok(());
        };
        if target.contains_fd(epfd, &mut BTreeSet::new())? {
            return Err(LinuxError::ELOOP);
        }
        if target.nesting_depth(&mut BTreeSet::new())? >= EPOLL_MAX_NEST_DEPTH {
            return Err(LinuxError::EINVAL);
        }
        Ok(())
    }

    fn ready_events(ev: &StoredEpollEvent, state: PollState) -> u32 {
        let mut ready = 0u32;
        if state.readable && (ev.events & ctypes::EPOLLIN != 0) {
            ready |= ctypes::EPOLLIN;
        }
        if state.writable && (ev.events & ctypes::EPOLLOUT != 0) {
            ready |= ctypes::EPOLLOUT;
        }
        ready
    }

    fn extra_ready_events(fd: c_int, requested: u32) -> LinuxResult<u32> {
        #[cfg(feature = "net")]
        {
            if let Ok(socket) = get_file_like(fd)?
                .into_any()
                .downcast::<Socket>()
            {
                return Ok(socket.epoll_extra_events(requested));
            }
        }
        Ok(0)
    }

    fn reportable_ready(fd: c_int, ev: &StoredEpollEvent, state: PollState) -> LinuxResult<u32> {
        Ok(Self::ready_events(ev, state) | Self::extra_ready_events(fd, ev.events)?)
    }

    fn control(
        &self,
        epfd: c_int,
        op: usize,
        fd: usize,
        event: &ctypes::epoll_event,
    ) -> LinuxResult<usize> {
        if !fd_supports_epoll(fd as c_int)? {
            return Err(LinuxError::EPERM);
        }
        let stored_event = read_epoll_event(event);
        match op as u32 {
            ctypes::EPOLL_CTL_ADD => {
                get_file_like(fd as c_int)?;
                self.validate_add_target(epfd, fd as c_int)?;
                if let Entry::Vacant(e) = self.events.lock().entry(fd) {
                    e.insert(stored_event);
                } else {
                    return Err(LinuxError::EEXIST);
                }
            }
            ctypes::EPOLL_CTL_MOD => {
                get_file_like(fd as c_int)?;
                let mut events = self.events.lock();
                if let Entry::Occupied(mut ocp) = events.entry(fd) {
                    ocp.insert(stored_event);
                } else {
                    return Err(LinuxError::ENOENT);
                }
            }
            ctypes::EPOLL_CTL_DEL => {
                get_file_like(fd as c_int)?;
                let mut events = self.events.lock();
                if let Entry::Occupied(ocp) = events.entry(fd) {
                    ocp.remove_entry();
                } else {
                    return Err(LinuxError::ENOENT);
                }
            }
            _ => {
                return Err(LinuxError::EINVAL);
            }
        }
        Ok(0)
    }

    fn poll_all(&self, events: &mut [ctypes::epoll_event]) -> LinuxResult<usize> {
        let mut ready_list = self.events.lock();
        let mut events_num = 0;

        for (infd, ev) in ready_list.iter_mut() {
            if events_num >= events.len() {
                break;
            }
            let fd = *infd as c_int;
            match get_file_like(fd)?.poll() {
                Err(_) => {
                    if (ev.events & ctypes::EPOLLERR) != 0 {
                        write_epoll_event(
                            &mut events[events_num],
                            StoredEpollEvent {
                                events: ctypes::EPOLLERR,
                                data_u64: ev.data_u64,
                                last_ready: 0,
                                disabled: false,
                            },
                        );
                        events_num += 1;
                    }
                }
                Ok(state) => {
                    let ready = Self::reportable_ready(fd, ev, state)?;
                    let report = if ev.disabled {
                        0
                    } else if ev.events & ctypes::EPOLLET != 0 {
                        ready & !ev.last_ready
                    } else {
                        ready
                    };
                    ev.last_ready = ready;
                    if report != 0 {
                        if ev.events & ctypes::EPOLLONESHOT != 0 {
                            ev.disabled = true;
                        }
                        write_epoll_event(
                            &mut events[events_num],
                            StoredEpollEvent {
                                events: report,
                                data_u64: ev.data_u64,
                                last_ready: 0,
                                disabled: false,
                            },
                        );
                        events_num += 1;
                    }
                }
            }
        }
        Ok(events_num)
    }

    fn has_ready_events(&self) -> LinuxResult<bool> {
        let ready_list = self.events.lock();
        for (infd, ev) in ready_list.iter() {
            let fd = *infd as c_int;
            if ev.disabled {
                continue;
            }
            match get_file_like(fd)?.poll() {
                Err(_) => {
                    if ev.events & ctypes::EPOLLERR != 0 {
                        return Ok(true);
                    }
                }
                Ok(state) => {
                    let ready = Self::reportable_ready(fd, ev, state)?;
                    let report = if ev.events & ctypes::EPOLLET != 0 {
                        ready & !ev.last_ready
                    } else {
                        ready
                    };
                    if report != 0 {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
}

impl FileLike for EpollInstance {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::ENOSYS)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::ENOSYS)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let st_mode = 0o600u32; // rw-------
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> alloc::sync::Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<axio::PollState> {
        Ok(PollState {
            readable: self.has_ready_events()?,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

/// Creates a new epoll instance.
///
/// It returns a file descriptor referring to the new epoll instance.
pub fn sys_epoll_create(size: c_int) -> c_int {
    debug!("sys_epoll_create <= {}", size);
    syscall_body!(sys_epoll_create, {
        if size <= 0 {
            return Err(LinuxError::EINVAL);
        }
        let epoll_instance = EpollInstance::new(0);
        add_file_like(Arc::new(epoll_instance))
    })
}

/// Control interface for an epoll file descriptor
pub unsafe fn sys_epoll_ctl(
    epfd: c_int,
    op: c_int,
    fd: c_int,
    event: *mut ctypes::epoll_event,
) -> c_int {
    debug!("sys_epoll_ctl <= epfd: {} op: {} fd: {}", epfd, op, fd);
    syscall_body!(sys_epoll_ctl, {
        let default_event = ctypes::epoll_event {
            events: 0,
            data: ctypes::epoll_data { u64_: 0 },
        };
        let event_ref = if op as u32 == ctypes::EPOLL_CTL_DEL {
            &default_event
        } else {
            if event.is_null() {
                return Err(LinuxError::EFAULT);
            }
            unsafe { &*event }
        };
        let ret =
            EpollInstance::from_fd(epfd)?.control(epfd, op as usize, fd as usize, event_ref)?
                as c_int;
        Ok(ret)
    })
}

/// Waits for events on the epoll instance referred to by the file descriptor epfd.
pub unsafe fn sys_epoll_wait(
    epfd: c_int,
    events: *mut ctypes::epoll_event,
    maxevents: c_int,
    timeout: c_int,
) -> c_int {
    debug!(
        "sys_epoll_wait <= epfd: {}, maxevents: {}, timeout: {}",
        epfd, maxevents, timeout
    );

    syscall_body!(sys_epoll_wait, {
        if maxevents <= 0 {
            return Err(LinuxError::EINVAL);
        }
        let events = unsafe { core::slice::from_raw_parts_mut(events, maxevents as usize) };
        let deadline =
            (!timeout.is_negative()).then(|| wall_time() + Duration::from_millis(timeout as u64));
        let epoll_instance = EpollInstance::from_fd(epfd)?;
        loop {
            #[cfg(feature = "net")]
            let net_progress = axnet::poll_interfaces();
            #[cfg(not(feature = "net"))]
            let net_progress = false;
            if axtask::current_wait_should_interrupt() {
                return Err(LinuxError::EINTR);
            }
            let events_num = epoll_instance.poll_all(events)?;
            if events_num > 0 {
                return Ok(events_num as c_int);
            }

            if deadline.is_some_and(|ddl| wall_time() >= ddl) {
                debug!("    timeout!");
                return Ok(0);
            }
            if net_progress {
                axtask::yield_now();
            } else {
                axtask::sleep(Duration::from_millis(1));
            }
        }
    })
}
