use crate::ctypes;
use axerrno::LinuxError;
use axns::{ResArc, def_resource};
use core::ffi::c_int;
use spin::Mutex;

const RLIM_INFINITY: u64 = u64::MAX;

#[derive(Clone, Copy)]
pub struct ResourceLimits {
    pub fsize_cur: u64,
    pub fsize_max: u64,
    pub nofile_cur: u64,
    pub nofile_max: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fsize_cur: RLIM_INFINITY,
            fsize_max: RLIM_INFINITY,
            nofile_cur: super::fd_ops::AX_FILE_LIMIT as u64,
            nofile_max: super::fd_ops::AX_FILE_LIMIT as u64,
        }
    }
}

def_resource! {
    pub static RESOURCE_LIMITS: ResArc<Mutex<ResourceLimits>> = ResArc::new();
}

impl RESOURCE_LIMITS {
    pub fn copy_inner(&self) -> Mutex<ResourceLimits> {
        Mutex::new(*self.lock())
    }
}

#[ctor_bare::register_ctor]
fn init_resource_limits() {
    RESOURCE_LIMITS.init_new(Mutex::new(ResourceLimits::default()));
}

pub fn current_nofile_limit() -> usize {
    RESOURCE_LIMITS
        .lock()
        .nofile_cur
        .min(super::fd_ops::AX_FILE_LIMIT as u64) as usize
}

/// Get resource limitations
///
/// TODO: support more resource types
pub unsafe fn sys_getrlimit(resource: c_int, rlimits: *mut ctypes::rlimit) -> c_int {
    debug!("sys_getrlimit <= {} {:#x}", resource, rlimits as usize);
    syscall_body!(sys_getrlimit, {
        match resource as u32 {
            ctypes::RLIMIT_CPU => {}
            ctypes::RLIMIT_FSIZE => {}
            ctypes::RLIMIT_DATA => {}
            ctypes::RLIMIT_STACK => {}
            ctypes::RLIMIT_CORE => {}
            ctypes::RLIMIT_RSS => {}
            ctypes::RLIMIT_NPROC => {}
            ctypes::RLIMIT_NOFILE => {}
            ctypes::RLIMIT_AS => {}
            ctypes::RLIMIT_LOCKS => {}
            ctypes::RLIMIT_SIGPENDING => {}
            ctypes::RLIMIT_MSGQUEUE => {}
            ctypes::RLIMIT_NICE => {}
            ctypes::RLIMIT_RTPRIO => {}
            ctypes::RLIMIT_MEMLOCK => {}
            ctypes::RLIMIT_RTTIME => {}
            _ => return Err(LinuxError::EINVAL),
        }
        if rlimits.is_null() {
            return Ok(0);
        }
        match resource as u32 {
            ctypes::RLIMIT_CPU
            | ctypes::RLIMIT_DATA
            | ctypes::RLIMIT_CORE
            | ctypes::RLIMIT_RSS
            | ctypes::RLIMIT_NPROC
            | ctypes::RLIMIT_AS
            | ctypes::RLIMIT_LOCKS
            | ctypes::RLIMIT_SIGPENDING
            | ctypes::RLIMIT_MSGQUEUE
            | ctypes::RLIMIT_NICE
            | ctypes::RLIMIT_RTTIME => unsafe {
                (*rlimits).rlim_cur = RLIM_INFINITY;
                (*rlimits).rlim_max = RLIM_INFINITY;
            },
            ctypes::RLIMIT_FSIZE => {
                let limits = *RESOURCE_LIMITS.lock();
                unsafe {
                    (*rlimits).rlim_cur = limits.fsize_cur;
                    (*rlimits).rlim_max = limits.fsize_max;
                }
            }
            ctypes::RLIMIT_STACK => unsafe {
                (*rlimits).rlim_cur = axconfig::plat::USER_STACK_SIZE as _;
                (*rlimits).rlim_max = axconfig::plat::USER_STACK_SIZE as _;
            },
            #[cfg(feature = "fd")]
            ctypes::RLIMIT_NOFILE => {
                let limits = *RESOURCE_LIMITS.lock();
                unsafe {
                    (*rlimits).rlim_cur = limits.nofile_cur;
                    (*rlimits).rlim_max = limits.nofile_max;
                }
            }
            ctypes::RLIMIT_RTPRIO => unsafe {
                (*rlimits).rlim_cur = 99;
                (*rlimits).rlim_max = 99;
            },
            ctypes::RLIMIT_MEMLOCK => unsafe {
                (*rlimits).rlim_cur = RLIM_INFINITY;
                (*rlimits).rlim_max = RLIM_INFINITY;
            },
            _ => {}
        }
        Ok(0)
    })
}

/// Set resource limitations
///
/// TODO: support more resource types
pub unsafe fn sys_setrlimit(resource: c_int, rlimits: *mut crate::ctypes::rlimit) -> c_int {
    debug!("sys_setrlimit <= {} {:#x}", resource, rlimits as usize);
    syscall_body!(sys_setrlimit, {
        match resource as u32 {
            crate::ctypes::RLIMIT_CPU => {}
            crate::ctypes::RLIMIT_FSIZE => {}
            crate::ctypes::RLIMIT_DATA => {}
            crate::ctypes::RLIMIT_STACK => {}
            crate::ctypes::RLIMIT_CORE => {}
            crate::ctypes::RLIMIT_RSS => {}
            crate::ctypes::RLIMIT_NPROC => {}
            crate::ctypes::RLIMIT_NOFILE => {}
            crate::ctypes::RLIMIT_AS => {}
            crate::ctypes::RLIMIT_LOCKS => {}
            crate::ctypes::RLIMIT_SIGPENDING => {}
            crate::ctypes::RLIMIT_MSGQUEUE => {}
            crate::ctypes::RLIMIT_NICE => {}
            crate::ctypes::RLIMIT_RTPRIO => {}
            crate::ctypes::RLIMIT_MEMLOCK => {}
            crate::ctypes::RLIMIT_RTTIME => {}
            _ => return Err(LinuxError::EINVAL),
        }
        if !rlimits.is_null() {
            let limits = unsafe { *rlimits };
            if limits.rlim_cur > limits.rlim_max {
                return Err(LinuxError::EINVAL);
            }
            if resource as u32 == crate::ctypes::RLIMIT_FSIZE {
                let mut current = RESOURCE_LIMITS.lock();
                current.fsize_cur = limits.rlim_cur;
                current.fsize_max = limits.rlim_max;
            }
            #[cfg(feature = "fd")]
            if resource as u32 == crate::ctypes::RLIMIT_NOFILE {
                let mut current = RESOURCE_LIMITS.lock();
                current.nofile_cur = limits.rlim_cur.min(super::fd_ops::AX_FILE_LIMIT as u64);
                current.nofile_max = limits.rlim_max.min(super::fd_ops::AX_FILE_LIMIT as u64);
            }
        }
        Ok(0)
    })
}
