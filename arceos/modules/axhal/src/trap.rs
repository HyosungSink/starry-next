//! Trap handling.

use core::sync::atomic::{AtomicUsize, Ordering};

use linkme::distributed_slice as def_trap_handler;
use memory_addr::VirtAddr;
use page_table_entry::MappingFlags;

#[cfg(feature = "uspace")]
use crate::arch::TrapFrame;

pub use linkme::distributed_slice as register_trap_handler;

/// A slice of IRQ handler functions.
#[def_trap_handler]
pub static IRQ: [fn(usize) -> bool];

/// A slice of page fault handler functions.
#[def_trap_handler]
pub static PAGE_FAULT: [fn(VirtAddr, MappingFlags, bool) -> bool];

/// A slice of syscall handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static SYSCALL: [fn(&TrapFrame, usize) -> isize];

#[cfg(feature = "uspace")]
static USER_RETURN_HANDLER: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "uspace")]
static USER_TRAP_DIAGNOSTIC_HANDLER: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "uspace")]
static USER_TRAP_ENTER_HANDLER: AtomicUsize = AtomicUsize::new(0);

#[allow(unused_macros)]
macro_rules! handle_trap {
    ($trap:ident, $($args:tt)*) => {{
        let mut iter = $crate::trap::$trap.iter();
        if let Some(func) = iter.next() {
            if iter.next().is_some() {
                warn!("Multiple handlers for trap {} are not currently supported", stringify!($trap));
            }
            func($($args)*)
        } else {
            warn!("No registered handler for trap {}", stringify!($trap));
            false
        }
    }}
}

/// Call the external syscall handler.
#[cfg(feature = "uspace")]
pub(crate) fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    SYSCALL[0](tf, syscall_num)
}

/// Sets the handler that runs before returning to user space.
#[cfg(feature = "uspace")]
pub fn set_user_return_handler(handler: fn(&mut TrapFrame)) {
    USER_RETURN_HANDLER.store(handler as usize, Ordering::Release);
}

/// Sets the handler that runs before panicking on an unhandled user trap.
#[cfg(feature = "uspace")]
pub fn set_user_trap_diagnostic_handler(handler: fn(&TrapFrame, usize, usize, bool)) {
    USER_TRAP_DIAGNOSTIC_HANDLER.store(handler as usize, Ordering::Release);
}

/// Sets the handler that runs immediately after entering the kernel from user space.
#[cfg(feature = "uspace")]
pub fn set_user_trap_enter_handler(handler: fn()) {
    USER_TRAP_ENTER_HANDLER.store(handler as usize, Ordering::Release);
}

/// Call the registered user-trap-enter handler.
#[cfg(feature = "uspace")]
pub(crate) fn handle_user_enter() {
    let handler = USER_TRAP_ENTER_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        let handler: fn() = unsafe { core::mem::transmute(handler) };
        handler();
    }
}

/// Call the registered user-return handlers.
#[cfg(feature = "uspace")]
pub(crate) fn handle_user_return(tf: &mut TrapFrame) {
    let handler = USER_RETURN_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        let handler: fn(&mut TrapFrame) = unsafe { core::mem::transmute(handler) };
        handler(tf);
    }
}

/// Call the registered user-trap diagnostic handler.
#[cfg(feature = "uspace")]
pub(crate) fn handle_user_trap_diagnostic(
    tf: &TrapFrame,
    trap_bits: usize,
    trap_value: usize,
    from_user: bool,
) {
    let handler = USER_TRAP_DIAGNOSTIC_HANDLER.load(Ordering::Acquire);
    if handler != 0 {
        let handler: fn(&TrapFrame, usize, usize, bool) = unsafe { core::mem::transmute(handler) };
        handler(tf, trap_bits, trap_value, from_user);
    }
}
