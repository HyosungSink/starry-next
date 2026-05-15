use core::ffi::c_int;
use core::ffi::c_ulong;
use core::time::Duration;

use axerrno::{LinuxError, LinuxResult};
use axhal::time::wall_time;

use crate::{ctypes, imp::fd_ops::get_file_like};

const FD_SETSIZE: usize = 1024;
const BITS_PER_ULONG: usize = c_ulong::BITS as usize;
const FD_SETSIZE_ULONGS: usize = FD_SETSIZE.div_ceil(BITS_PER_ULONG);

struct FdSets {
    nfds: usize,
    read_bits: [c_ulong; FD_SETSIZE_ULONGS],
    write_bits: [c_ulong; FD_SETSIZE_ULONGS],
    except_bits: [c_ulong; FD_SETSIZE_ULONGS],
}

impl FdSets {
    unsafe fn from_user(
        nfds: usize,
        read_fds: *const ctypes::fd_set,
        write_fds: *const ctypes::fd_set,
        except_fds: *const ctypes::fd_set,
    ) -> Self {
        let nfds = nfds.min(FD_SETSIZE);
        Self {
            nfds,
            read_bits: unsafe { read_fd_set_bits(read_fds, nfds) },
            write_bits: unsafe { read_fd_set_bits(write_fds, nfds) },
            except_bits: unsafe { read_fd_set_bits(except_fds, nfds) },
        }
    }

    fn poll_all(&self, res: &mut ReadyFdSets) -> LinuxResult<usize> {
        let mut res_num = 0usize;
        let mut i = 0;
        for (&read_bits, (&write_bits, &except_bits)) in self
            .read_bits
            .iter()
            .zip(self.write_bits.iter().zip(self.except_bits.iter()))
        {
            if i >= self.nfds {
                break;
            }
            let all_bits = read_bits | write_bits | except_bits;
            if all_bits == 0 {
                i += BITS_PER_ULONG;
                continue;
            }
            let mut j = 0;
            while j < BITS_PER_ULONG && i + j < self.nfds {
                let bit = 1 << j;
                if all_bits & bit == 0 {
                    j += 1;
                    continue;
                }
                let fd = i + j;
                let mut hit = false;
                match get_file_like(fd as _)?.poll() {
                    Ok(state) => {
                        if state.readable && read_bits & bit != 0 {
                            res.set_read(fd);
                            hit = true;
                        }
                        if state.writable && write_bits & bit != 0 {
                            res.set_write(fd);
                            hit = true;
                        }
                    }
                    Err(e) => {
                        debug!("    except: {} {:?}", fd, e);
                        if except_bits & bit != 0 {
                            res.set_except(fd);
                            hit = true;
                        }
                    }
                }
                if hit {
                    res_num += 1;
                }
                j += 1;
            }
            i += BITS_PER_ULONG;
        }
        Ok(res_num)
    }
}

struct ReadyFdSets {
    read_bits: [c_ulong; FD_SETSIZE_ULONGS],
    write_bits: [c_ulong; FD_SETSIZE_ULONGS],
    except_bits: [c_ulong; FD_SETSIZE_ULONGS],
}

impl ReadyFdSets {
    const fn new() -> Self {
        Self {
            read_bits: [0; FD_SETSIZE_ULONGS],
            write_bits: [0; FD_SETSIZE_ULONGS],
            except_bits: [0; FD_SETSIZE_ULONGS],
        }
    }

    fn clear(&mut self) {
        self.read_bits.fill(0);
        self.write_bits.fill(0);
        self.except_bits.fill(0);
    }

    fn set_read(&mut self, fd: usize) {
        self.read_bits[fd / BITS_PER_ULONG] |= (1 as c_ulong) << (fd % BITS_PER_ULONG);
    }

    fn set_write(&mut self, fd: usize) {
        self.write_bits[fd / BITS_PER_ULONG] |= (1 as c_ulong) << (fd % BITS_PER_ULONG);
    }

    fn set_except(&mut self, fd: usize) {
        self.except_bits[fd / BITS_PER_ULONG] |= (1 as c_ulong) << (fd % BITS_PER_ULONG);
    }
}

/// Monitor multiple file descriptors, waiting until one or more of the file descriptors become "ready" for some class of I/O operation
pub unsafe fn sys_select(
    nfds: c_int,
    readfds: *mut ctypes::fd_set,
    writefds: *mut ctypes::fd_set,
    exceptfds: *mut ctypes::fd_set,
    timeout: *mut ctypes::timeval,
) -> c_int {
    debug!(
        "sys_select <= {} {:#x} {:#x} {:#x}",
        nfds, readfds as usize, writefds as usize, exceptfds as usize
    );
    syscall_body!(sys_select, {
        if nfds < 0 {
            return Err(LinuxError::EINVAL);
        }
        let nfds = (nfds as usize).min(FD_SETSIZE);
        let timeout_value = if timeout.is_null() {
            None
        } else {
            Some(unsafe { *timeout })
        };
        let deadline = timeout_value.map(|t| wall_time() + t.into());
        let fd_sets = unsafe { FdSets::from_user(nfds, readfds, writefds, exceptfds) };
        let mut ready_sets = ReadyFdSets::new();

        loop {
            #[cfg(feature = "net")]
            let net_progress = axnet::poll_interfaces();
            #[cfg(not(feature = "net"))]
            let net_progress = false;
            if axtask::current_wait_should_interrupt() {
                unsafe {
                    write_fd_set_bits(readfds, &ready_sets.read_bits, nfds);
                    write_fd_set_bits(writefds, &ready_sets.write_bits, nfds);
                    write_fd_set_bits(exceptfds, &ready_sets.except_bits, nfds);
                    write_timeout_remaining(timeout, deadline);
                }
                return Err(LinuxError::EINTR);
            }
            ready_sets.clear();
            let res = fd_sets.poll_all(&mut ready_sets)?;
            if res > 0 {
                unsafe {
                    write_fd_set_bits(readfds, &ready_sets.read_bits, nfds);
                    write_fd_set_bits(writefds, &ready_sets.write_bits, nfds);
                    write_fd_set_bits(exceptfds, &ready_sets.except_bits, nfds);
                    write_timeout_remaining(timeout, deadline);
                }
                return Ok(res);
            }

            if deadline.is_some_and(|ddl| wall_time() >= ddl) {
                debug!("    timeout!");
                unsafe {
                    write_fd_set_bits(readfds, &ready_sets.read_bits, nfds);
                    write_fd_set_bits(writefds, &ready_sets.write_bits, nfds);
                    write_fd_set_bits(exceptfds, &ready_sets.except_bits, nfds);
                    write_timeout_remaining(timeout, Some(wall_time()));
                }
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

unsafe fn read_fd_set_bits(
    src: *const ctypes::fd_set,
    nfds: usize,
) -> [c_ulong; FD_SETSIZE_ULONGS] {
    let mut bits = [0; FD_SETSIZE_ULONGS];
    if src.is_null() {
        return bits;
    }
    let nfds_ulongs = nfds.div_ceil(BITS_PER_ULONG);
    unsafe {
        core::ptr::copy_nonoverlapping((*src).fds_bits.as_ptr(), bits.as_mut_ptr(), nfds_ulongs);
    }
    bits
}

unsafe fn write_fd_set_bits(
    dst: *mut ctypes::fd_set,
    src: &[c_ulong; FD_SETSIZE_ULONGS],
    nfds: usize,
) {
    if dst.is_null() {
        return;
    }
    unsafe {
        (*dst).fds_bits.fill(0);
    }
    let nfds_ulongs = nfds.div_ceil(BITS_PER_ULONG);
    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), (*dst).fds_bits.as_mut_ptr(), nfds_ulongs);
    }
}

unsafe fn write_timeout_remaining(timeout: *mut ctypes::timeval, deadline: Option<Duration>) {
    if timeout.is_null() {
        return;
    }
    let remaining = deadline
        .and_then(|ddl| ddl.checked_sub(wall_time()))
        .unwrap_or(Duration::ZERO);
    unsafe {
        *timeout = remaining.into();
    }
}
