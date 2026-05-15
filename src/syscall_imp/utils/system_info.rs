use crate::{
    syscall_body,
    timekeeping::current_clock_nanos,
    usercopy::{copy_to_user, write_value_to_user},
};
use axerrno::LinuxError;
use axtask::TaskExtRef;

const UNAME26: u32 = 0x0020_0000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UtsName {
    /// sysname
    pub sysname: [u8; 65],
    /// nodename
    pub nodename: [u8; 65],
    /// release
    pub release: [u8; 65],
    /// version
    pub version: [u8; 65],
    /// machine
    pub machine: [u8; 65],
    /// domainname
    pub domainname: [u8; 65],
}

impl Default for UtsName {
    fn default() -> Self {
        Self {
            sysname: Self::from_str("Linux"),
            nodename: Self::from_str("localhost"),
            release: Self::from_str("10.0.0"),
            version: Self::from_str("#1 SMP PREEMPT"),
            machine: Self::from_str(Self::machine_name()),
            domainname: Self::from_str("localdomain"),
        }
    }
}

impl UtsName {
    #[cfg(target_arch = "riscv64")]
    fn machine_name() -> &'static str {
        "riscv64"
    }

    #[cfg(target_arch = "loongarch64")]
    fn machine_name() -> &'static str {
        "loongarch64"
    }

    #[cfg(target_arch = "x86_64")]
    fn machine_name() -> &'static str {
        "x86_64"
    }

    fn current() -> Self {
        let mut uts = Self::default();
        if axtask::current().task_ext().personality() & UNAME26 != 0 {
            uts.release = Self::from_str("2.6.40");
        }
        uts
    }
}

impl UtsName {
    fn from_str(info: &str) -> [u8; 65] {
        let mut data: [u8; 65] = [0; 65];
        data[..info.len()].copy_from_slice(info.as_bytes());
        data
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SysInfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
}

pub fn sys_uname(name: *mut UtsName) -> i64 {
    syscall_body!(sys_uname, {
        if name.is_null() {
            return Err(LinuxError::EFAULT);
        }
        write_value_to_user(name, UtsName::current())?;
        Ok(0)
    })
}

pub fn sys_syslog(log_type: i32, bufp: *mut u8, len: i32) -> i64 {
    const SYSLOG_ACTION_READ_ALL: i32 = 3;
    const SYSLOG_ACTION_READ_CLEAR: i32 = 4;
    const SYSLOG_ACTION_SIZE_UNREAD: i32 = 9;
    const SYSLOG_ACTION_SIZE_BUFFER: i32 = 10;
    const KMSG: &[u8] = b"[    0.000000] Starry kernel booted\n";

    syscall_body!(sys_syslog, {
        match log_type {
            SYSLOG_ACTION_SIZE_UNREAD | SYSLOG_ACTION_SIZE_BUFFER => Ok(KMSG.len() as i64),
            SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
                if len < 0 {
                    return Err(LinuxError::EINVAL);
                }
                if len > 0 && bufp.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let copy_len = KMSG.len().min(len as usize);
                if copy_len > 0 {
                    copy_to_user(bufp.cast(), &KMSG[..copy_len])?;
                }
                Ok(copy_len as i64)
            }
            _ => Ok(0),
        }
    })
}

pub fn sys_sysinfo(info: *mut SysInfo) -> i64 {
    syscall_body!(sys_sysinfo, {
        if info.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let uptime = (current_clock_nanos(7)? / 1_000_000_000) as i64;
        write_value_to_user(
            info,
            SysInfo {
                uptime,
                loads: [0, 0, 0],
                totalram: 256 * 1024 * 1024,
                freeram: 192 * 1024 * 1024,
                sharedram: 0,
                bufferram: 0,
                totalswap: 0,
                freeswap: 0,
                procs: 1,
                pad: 0,
                totalhigh: 0,
                freehigh: 0,
                mem_unit: 1,
            },
        )?;
        Ok(0)
    })
}
