use alloc::boxed::Box;

use crate::{ctypes, utils::check_null_mut_ptr};

use axerrno::{LinuxError, LinuxResult};
use axsync::Mutex;

use core::ffi::c_int;
use core::mem::{ManuallyDrop, size_of};

static_assertions::const_assert_eq!(
    size_of::<ctypes::pthread_mutex_t>(),
    size_of::<PthreadMutex>()
);
static_assertions::const_assert_eq!(size_of::<ctypes::pthread_mutex_t>() % size_of::<usize>(), 0);

#[repr(C)]
pub struct PthreadMutex {
    words: [usize; size_of::<ctypes::pthread_mutex_t>() / size_of::<usize>()],
}

impl PthreadMutex {
    const fn new() -> Self {
        Self {
            words: [0; size_of::<ctypes::pthread_mutex_t>() / size_of::<usize>()],
        }
    }

    fn ptr(&self) -> usize {
        self.words[0]
    }

    fn ptr_mut(&mut self) -> &mut usize {
        &mut self.words[0]
    }

    fn init(&mut self) {
        if self.ptr() == 0 {
            *self.ptr_mut() = Box::into_raw(Box::new(Mutex::new(()))) as usize;
        }
    }

    fn inner(&self) -> LinuxResult<&Mutex<()>> {
        if self.ptr() == 0 {
            return Err(LinuxError::EINVAL);
        }
        Ok(unsafe { &*(self.ptr() as *const Mutex<()>) })
    }

    fn lock(&self) -> LinuxResult {
        let _guard = ManuallyDrop::new(self.inner()?.lock());
        Ok(())
    }

    fn unlock(&self) -> LinuxResult {
        unsafe { self.inner()?.force_unlock() };
        Ok(())
    }
}

/// Initialize a mutex.
pub fn sys_pthread_mutex_init(
    mutex: *mut ctypes::pthread_mutex_t,
    _attr: *const ctypes::pthread_mutexattr_t,
) -> c_int {
    debug!("sys_pthread_mutex_init <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_init, {
        check_null_mut_ptr(mutex)?;
        unsafe {
            mutex.cast::<PthreadMutex>().write(PthreadMutex::new());
            (*mutex.cast::<PthreadMutex>()).init();
        }
        Ok(0)
    })
}

/// Lock the given mutex.
pub fn sys_pthread_mutex_lock(mutex: *mut ctypes::pthread_mutex_t) -> c_int {
    debug!("sys_pthread_mutex_lock <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_lock, {
        check_null_mut_ptr(mutex)?;
        unsafe {
            (*mutex.cast::<PthreadMutex>()).lock()?;
        }
        Ok(0)
    })
}

/// Unlock the given mutex.
pub fn sys_pthread_mutex_unlock(mutex: *mut ctypes::pthread_mutex_t) -> c_int {
    debug!("sys_pthread_mutex_unlock <= {:#x}", mutex as usize);
    syscall_body!(sys_pthread_mutex_unlock, {
        check_null_mut_ptr(mutex)?;
        unsafe {
            (*mutex.cast::<PthreadMutex>()).unlock()?;
        }
        Ok(0)
    })
}
