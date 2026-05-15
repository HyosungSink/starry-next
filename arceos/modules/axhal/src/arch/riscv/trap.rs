use page_table_entry::MappingFlags;
use riscv::interrupt::Trap;
use riscv::interrupt::supervisor::{Exception as E, Interrupt as I};
use riscv::register::{scause, stval};

use super::TrapFrame;

core::arch::global_asm!(
    include_asm_macros!(),
    include_str!("trap.S"),
    trapframe_size = const core::mem::size_of::<TrapFrame>(),
);

fn handle_breakpoint(sepc: &mut usize) {
    debug!("Exception(Breakpoint) @ {:#x} ", sepc);
    *sepc += 2
}

#[inline(never)]
fn terminate_unhandled_trap(tf: &TrapFrame, message: core::fmt::Arguments<'_>) -> ! {
    error!("{}", message);
    error!("{:#x?}", tf);
    crate::misc::terminate_on_panic()
}

fn handle_page_fault(tf: &TrapFrame, mut access_flags: MappingFlags, is_user: bool) {
    if is_user {
        access_flags |= MappingFlags::USER;
    }
    let trap_value = stval::read();
    let vaddr = va!(trap_value);
    if !handle_trap!(PAGE_FAULT, vaddr, access_flags, is_user) {
        #[cfg(feature = "uspace")]
        crate::trap::handle_user_trap_diagnostic(tf, scause::read().bits(), trap_value, is_user);
        terminate_unhandled_trap(
            tf,
            format_args!(
                "Unhandled {} Page Fault @ {:#x}, fault_vaddr={:#x} ({:?}), from_user={}, scause={:#x}, stval={:#x}",
                if is_user { "User" } else { "Supervisor" },
                tf.sepc,
                vaddr,
                access_flags,
                is_user,
                scause::read().bits(),
                trap_value,
            ),
        );
    }
}

#[unsafe(no_mangle)]
fn riscv_trap_handler(tf: &mut TrapFrame, from_user: bool) {
    if from_user {
        crate::trap::handle_user_enter();
    }
    let scause = scause::read();
    if let Ok(cause) = scause.cause().try_into::<I, E>() {
        match cause {
            #[cfg(feature = "uspace")]
            Trap::Exception(E::UserEnvCall) => {
                tf.regs.a0 = crate::trap::handle_syscall(tf, tf.regs.a7) as usize;
                tf.sepc += 4;
            }
            Trap::Exception(E::LoadPageFault) => {
                handle_page_fault(tf, MappingFlags::READ, from_user)
            }
            Trap::Exception(E::StorePageFault) => {
                handle_page_fault(tf, MappingFlags::WRITE, from_user)
            }
            Trap::Exception(E::InstructionPageFault) => {
                handle_page_fault(tf, MappingFlags::EXECUTE, from_user)
            }
            Trap::Exception(E::Breakpoint) => handle_breakpoint(&mut tf.sepc),
            Trap::Interrupt(_) => {
                handle_trap!(IRQ, scause.bits());
            }
            _ => {
                #[cfg(feature = "uspace")]
                crate::trap::handle_user_trap_diagnostic(
                    tf,
                    scause.bits(),
                    stval::read(),
                    from_user,
                );
                terminate_unhandled_trap(
                    tf,
                    format_args!(
                        "Unhandled trap {:?} @ {:#x}, from_user={}, scause={:#x}, stval={:#x}",
                        cause,
                        tf.sepc,
                        from_user,
                        scause.bits(),
                        stval::read()
                    ),
                );
            }
        }
    } else {
        #[cfg(feature = "uspace")]
        crate::trap::handle_user_trap_diagnostic(tf, scause.bits(), stval::read(), from_user);
        terminate_unhandled_trap(
            tf,
            format_args!(
                "Unknown trap {:?} @ {:#x}, from_user={}, scause={:#x}, stval={:#x}",
                scause.cause(),
                tf.sepc,
                from_user,
                scause.bits(),
                stval::read()
            ),
        );
    }
    if from_user {
        crate::trap::handle_user_return(tf);
    }
}
