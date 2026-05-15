use core::ffi::{c_int, c_long, c_uint};

use arceos_posix_api::{self as api, ctypes::timeval};
use axerrno::LinuxError;
use axhal::time::{monotonic_time_nanos, nanos_to_ticks};
use axtask::TaskExtRef;

use crate::usercopy::{read_value_from_user, write_value_to_user};
use crate::{
    ctypes::Tms,
    syscall_body,
    task::time_stat_output,
    timekeeping::{
        clock_settime, current_clock_nanos, current_realtime_nanos, nanos_to_timespec,
        timespec_to_nanos,
    },
};

const ADJ_OFFSET: c_uint = 0x0001;
const ADJ_FREQUENCY: c_uint = 0x0002;
const ADJ_MAXERROR: c_uint = 0x0004;
const ADJ_ESTERROR: c_uint = 0x0008;
const ADJ_STATUS: c_uint = 0x0010;
const ADJ_TIMECONST: c_uint = 0x0020;
const ADJ_TAI: c_uint = 0x0080;
const ADJ_SETOFFSET: c_uint = 0x0100;
const ADJ_MICRO: c_uint = 0x1000;
const ADJ_NANO: c_uint = 0x2000;
const ADJ_TICK: c_uint = 0x4000;
const ADJ_OFFSET_SINGLESHOT: c_uint = 0x8001;
const ADJ_OFFSET_SS_READ: c_uint = 0xa001;
const TIME_OK: i32 = 0;
const STA_NANO: i32 = 0x2000;
const SETTABLE_TIMEX_MODES: c_uint = ADJ_OFFSET
    | ADJ_FREQUENCY
    | ADJ_MAXERROR
    | ADJ_ESTERROR
    | ADJ_STATUS
    | ADJ_TIMECONST
    | ADJ_TAI
    | ADJ_SETOFFSET
    | ADJ_MICRO
    | ADJ_NANO
    | ADJ_TICK
    | ADJ_OFFSET_SINGLESHOT
    | ADJ_OFFSET_SS_READ;
const TIMEX_MIN_TICK: c_long = 9_000;
const TIMEX_MAX_TICK: c_long = 11_000;

fn valid_timex_modes(modes: c_uint) -> bool {
    if modes == ADJ_OFFSET_SINGLESHOT || modes == ADJ_OFFSET_SS_READ {
        return true;
    }
    if (modes & 0x8000) != 0 {
        return false;
    }
    modes & !SETTABLE_TIMEX_MODES == 0
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserTimex {
    modes: c_uint,
    offset: c_long,
    freq: c_long,
    maxerror: c_long,
    esterror: c_long,
    status: i32,
    constant: c_long,
    precision: c_long,
    tolerance: c_long,
    time: timeval,
    tick: c_long,
    ppsfreq: c_long,
    jitter: c_long,
    shift: i32,
    stabil: c_long,
    jitcnt: c_long,
    calcnt: c_long,
    errcnt: c_long,
    stbcnt: c_long,
    tai: i32,
    padding: [i32; 11],
}

static TIMEX_STATE: spin::Mutex<UserTimex> = spin::Mutex::new(UserTimex {
    modes: 0,
    offset: 0,
    freq: 0,
    maxerror: 0,
    esterror: 0,
    status: 0,
    constant: 0,
    precision: 1,
    tolerance: 0,
    time: timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
    tick: 10_000,
    ppsfreq: 0,
    jitter: 0,
    shift: 0,
    stabil: 0,
    jitcnt: 0,
    calcnt: 0,
    errcnt: 0,
    stbcnt: 0,
    tai: 0,
    padding: [0; 11],
});

pub(crate) fn sys_clock_gettime(clock_id: i32, tp: *mut api::ctypes::timespec) -> i32 {
    if tp.is_null() {
        return -LinuxError::EFAULT.code();
    }
    let local = match current_clock_nanos(clock_id) {
        Ok(ns) => nanos_to_timespec(ns),
        Err(err) => return -err.code(),
    };
    if let Err(err) = write_value_to_user(tp, local) {
        return -err.code();
    }
    let curr = axtask::current();
    if curr.name().contains("nice05") {
        warn!(
            "[nice05-diag] syscall=clock_gettime tid={} pid={} clock_id={} sec={} nsec={}",
            curr.id().as_u64(),
            curr.task_ext().proc_id,
            clock_id,
            local.tv_sec,
            local.tv_nsec,
        );
    }
    0
}

pub(crate) fn sys_clock_getres(clock_id: i32, tp: *mut api::ctypes::timespec) -> i32 {
    syscall_body!(sys_clock_getres, {
        let mut local = api::ctypes::timespec::default();
        let ret = unsafe { api::sys_clock_getres(clock_id, &mut local) };
        if ret < 0 {
            return Err(LinuxError::try_from(-ret).unwrap_or(LinuxError::EINVAL));
        }
        if !tp.is_null() {
            write_value_to_user(tp, local)?;
        }
        Ok(0)
    })
}

pub(crate) fn sys_get_time_of_day(ts: *mut timeval) -> c_int {
    syscall_body!(sys_get_time_of_day, {
        if ts.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let current_us = current_realtime_nanos() / 1_000;
        let local = timeval {
            tv_sec: (current_us / 1_000_000) as i64,
            tv_usec: (current_us % 1_000_000) as i64,
        };
        write_value_to_user(ts, local)?;
        Ok(0)
    })
}

pub(crate) fn sys_clock_settime(clock_id: i32, tp: *const api::ctypes::timespec) -> i32 {
    syscall_body!(sys_clock_settime, {
        if tp.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let local = read_value_from_user(tp)?;
        let _ = timespec_to_nanos(local)?;
        clock_settime(clock_id, local)?;
        Ok(0)
    })
}

pub(crate) fn sys_adjtimex(buf: *mut UserTimex) -> i32 {
    syscall_body!(sys_adjtimex, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let input = read_value_from_user(buf as *const UserTimex)?;
        if (input.modes & ADJ_TICK) != 0
            && (input.tick < TIMEX_MIN_TICK || input.tick > TIMEX_MAX_TICK)
        {
            return Err(LinuxError::EINVAL);
        }
        if !valid_timex_modes(input.modes) {
            return Err(LinuxError::EINVAL);
        }

        let mut state = TIMEX_STATE.lock();
        if input.modes != 0 {
            if axfs::api::current_euid() != 0 {
                return Err(LinuxError::EPERM);
            }
            if (input.modes & ADJ_OFFSET) != 0 || input.modes == ADJ_OFFSET_SINGLESHOT {
                state.offset = input.offset;
            }
            if (input.modes & ADJ_FREQUENCY) != 0 {
                state.freq = input.freq;
            }
            if (input.modes & ADJ_MAXERROR) != 0 {
                state.maxerror = input.maxerror;
            }
            if (input.modes & ADJ_ESTERROR) != 0 {
                state.esterror = input.esterror;
            }
            if (input.modes & ADJ_STATUS) != 0 {
                state.status = input.status;
            }
            if (input.modes & ADJ_TIMECONST) != 0 {
                state.constant = input.constant;
            }
            if (input.modes & ADJ_TICK) != 0 {
                state.tick = input.tick;
            }
            if (input.modes & ADJ_NANO) != 0 {
                state.status |= STA_NANO;
            } else if (input.modes & ADJ_MICRO) != 0 {
                state.status &= !STA_NANO;
            }
            if (input.modes & ADJ_TAI) != 0 {
                state.tai = input.tai;
            }
        }
        let now_us = current_realtime_nanos() / 1_000;
        state.time = timeval {
            tv_sec: (now_us / 1_000_000) as i64,
            tv_usec: (now_us % 1_000_000) as i64,
        };
        write_value_to_user(buf, *state)?;
        Ok(TIME_OK)
    })
}

pub(crate) fn sys_clock_adjtime(clock_id: i32, buf: *mut UserTimex) -> i32 {
    syscall_body!(sys_clock_adjtime, {
        if clock_id != 0 {
            return Err(LinuxError::EINVAL);
        }
        let ret = sys_adjtimex(buf);
        if ret < 0 {
            return Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL));
        }
        Ok(ret)
    })
}

pub fn sys_times(tms: *mut Tms) -> isize {
    syscall_body!(sys_times, {
        if tms.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let (_, utime_us, _, stime_us) = time_stat_output();
        write_value_to_user(
            tms,
            Tms {
                tms_utime: utime_us,
                tms_stime: stime_us,
                tms_cutime: utime_us,
                tms_cstime: stime_us,
            },
        )?;
        Ok(nanos_to_ticks(monotonic_time_nanos()) as isize)
    })
}
