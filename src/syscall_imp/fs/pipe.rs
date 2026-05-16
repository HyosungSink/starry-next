use core::ffi::c_int;
use core::ffi::c_void;

use arceos_posix_api as api;
use axtask::current;

pub(crate) fn sys_pipe2(fds: *mut i32, flags: i32) -> c_int {
    let curr = current();
    if curr.name().contains("userboot") {
        crate::diag_warn!(
            "pipe2 task={} fds_ptr={:#x} flags={:#x} now_ms={}",
            curr.id_name(),
            fds as usize,
            flags,
            axhal::time::monotonic_time_nanos() / 1_000_000
        );
    }
    let mut local_fds = [0i32; 2];
    let ret = api::sys_pipe2(&mut local_fds, flags);
    if ret == 0 {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                local_fds.as_ptr().cast::<u8>(),
                core::mem::size_of_val(&local_fds),
            )
        };
        if crate::usercopy::copy_to_user(fds.cast::<c_void>(), bytes).is_err() {
            return -axerrno::LinuxError::EFAULT.code() as c_int;
        }
    }
    ret
}
