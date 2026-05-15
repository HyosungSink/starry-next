use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    error!("{}", info);
    #[cfg(target_arch = "riscv64")]
    {
        axhal::misc::terminate_on_panic()
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        axhal::misc::terminate()
    }
}
