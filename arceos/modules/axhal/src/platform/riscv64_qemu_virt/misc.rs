use crate::mem::phys_to_virt;
use memory_addr::pa;

const LEGACY_SBI_SHUTDOWN_EID: usize = 0x8;
const SIFIVE_TEST_PADDR: usize = 0x0010_0000;
const SIFIVE_TEST_FAIL: u32 = 0x3333;
const PANIC_EXIT_CODE: u32 = 1;

#[inline(always)]
fn sifive_test_fail_once(code: u32) {
    let value = (code << 16) | SIFIVE_TEST_FAIL;
    let test_finisher = phys_to_virt(pa!(SIFIVE_TEST_PADDR)).as_mut_ptr() as *mut u32;
    unsafe {
        test_finisher.write_volatile(value);
    }
}

#[inline(always)]
fn legacy_shutdown_once() {
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") LEGACY_SBI_SHUTDOWN_EID,
            lateout("a0") _,
            lateout("a1") _,
            options(nomem, nostack),
        );
    }
}

#[inline(never)]
fn terminate_with_reason<R: sbi_rt::ResetReason>(reason: R, log_shutdown: bool) -> ! {
    if log_shutdown {
        info!("Shutting down...");
    }

    let ret = sbi_rt::system_reset(sbi_rt::Shutdown, reason);
    warn!(
        "SBI SRST shutdown returned unexpectedly: error={:#x} value={:#x}",
        ret.error, ret.value
    );

    legacy_shutdown_once();
    warn!("Legacy SBI shutdown returned unexpectedly");

    loop {
        let _ = sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
        legacy_shutdown_once();
        core::hint::spin_loop();
    }
}

#[inline(never)]
fn terminate_on_panic_with_retries() -> ! {
    loop {
        sifive_test_fail_once(PANIC_EXIT_CODE);
        let _ = sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::SystemFailure);
        legacy_shutdown_once();
        core::hint::spin_loop();
    }
}

/// Shutdown the whole system, including all CPUs.
pub fn terminate() -> ! {
    terminate_with_reason(sbi_rt::NoReason, true)
}

/// Shutdown path used specifically for kernel panic on RISC-V QEMU.
pub fn terminate_on_panic() -> ! {
    sifive_test_fail_once(PANIC_EXIT_CODE);
    warn!("SiFive test finisher panic exit returned unexpectedly");
    terminate_on_panic_with_retries()
}
