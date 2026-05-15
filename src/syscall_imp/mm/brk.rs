use axhal::paging::MappingFlags;
use axtask::{current, TaskExtRef};
use core::sync::atomic::AtomicBool;
#[cfg(target_arch = "riscv64")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_arch = "loongarch64")]
use core::sync::atomic::{AtomicUsize, Ordering};
use memory_addr::{MemoryAddr, VirtAddr, PAGE_SIZE_4K};

use crate::syscall_body;

const MAX_HEAP_SIZE: usize = 0x0800_0000;
static LARGE_LIBCBENCH_BRK_LOGGED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "loongarch64")]
fn should_trace_loongarch_libcbench_brk() -> bool {
    false
}

#[cfg(target_arch = "loongarch64")]
fn take_loongarch_libcbench_brk_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < limit
}

#[cfg(target_arch = "riscv64")]
fn should_trace_riscv_libcbench_brk() -> bool {
    false
}

#[cfg(target_arch = "riscv64")]
fn take_riscv_libcbench_brk_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < limit
}

pub fn sys_brk(addr: usize) -> isize {
    syscall_body!(sys_brk, {
        let current_task = current();
        let mut return_val: isize = current_task.task_ext().get_heap_top() as isize;
        let heap_bottom = current_task.task_ext().get_heap_bottom() as usize;
        #[cfg(target_arch = "loongarch64")]
        let trace_brk =
            should_trace_loongarch_libcbench_brk() && take_loongarch_libcbench_brk_trace_slot(1024);
        #[cfg(target_arch = "riscv64")]
        let trace_brk = current_task.task_ext().exec_path().contains("libc-bench")
            && should_trace_riscv_libcbench_brk()
            && take_riscv_libcbench_brk_trace_slot(1024);
        #[cfg(target_arch = "loongarch64")]
        if trace_brk {
            warn!(
                "[la-libcbench-brk] task={} heap_bottom={:#x} old_top={:#x} req={:#x}",
                current_task.id_name(),
                heap_bottom,
                current_task.task_ext().get_heap_top() as usize,
                addr
            );
        }
        #[cfg(target_arch = "riscv64")]
        if trace_brk {
            warn!(
                "[rv-libcbench-brk] task={} heap_bottom={:#x} old_top={:#x} req={:#x}",
                current_task.id_name(),
                heap_bottom,
                current_task.task_ext().get_heap_top() as usize,
                addr
            );
        }
        if addr != 0 && addr >= heap_bottom && addr <= heap_bottom + MAX_HEAP_SIZE {
            let old_top = current_task.task_ext().get_heap_top() as usize;
            if current_task.task_ext().exec_path().contains("libc-bench")
                && addr > old_top
                && addr - old_top >= (1 << 20)
                && !LARGE_LIBCBENCH_BRK_LOGGED.swap(true, Ordering::Relaxed)
            {
                warn!(
                    "[libcbench-large-brk] task={} old_top={:#x} new_top={:#x} delta={:#x}",
                    current_task.id_name(),
                    old_top,
                    addr,
                    addr - old_top
                );
            }
            if addr > old_top {
                let mut aspace = current_task.task_ext().aspace.lock();
                let map_start = VirtAddr::from_usize(old_top).align_down_4k();
                let map_end = VirtAddr::from_usize(addr).align_up_4k();
                #[cfg(target_arch = "loongarch64")]
                if trace_brk {
                    warn!(
                        "[la-libcbench-brk] grow old_top={:#x} new_top={:#x} map=[{:#x},{:#x})",
                        old_top,
                        addr,
                        map_start.as_usize(),
                        map_end.as_usize()
                    );
                }
                #[cfg(target_arch = "riscv64")]
                if trace_brk {
                    warn!(
                        "[rv-libcbench-brk] grow old_top={:#x} new_top={:#x} map=[{:#x},{:#x})",
                        old_top,
                        addr,
                        map_start.as_usize(),
                        map_end.as_usize()
                    );
                }
                if map_start < map_end {
                    let first_page_ready = match aspace.page_table().query(map_start) {
                        Ok((_, flags, _)) => !flags.is_empty(),
                        Err(_) => false,
                    };
                    if !first_page_ready {
                        aspace.map_alloc(
                            map_start,
                            PAGE_SIZE_4K,
                            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                            true,
                        )?;
                    }

                    let bulk_start = map_start + PAGE_SIZE_4K;
                    if bulk_start < map_end {
                        aspace.map_alloc(
                            bulk_start,
                            map_end - bulk_start,
                            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                            true,
                        )?;
                    }
                }
                axhal::arch::flush_tlb(None);
            } else if addr < old_top {
                let mut aspace = current_task.task_ext().aspace.lock();
                let unmap_start = VirtAddr::from_usize(addr).align_up_4k();
                let unmap_end = VirtAddr::from_usize(old_top).align_up_4k();
                if unmap_start < unmap_end {
                    let _ = aspace.unmap(unmap_start, unmap_end - unmap_start);
                }
                axhal::arch::flush_tlb(None);
            }
            current_task.task_ext().set_heap_top(addr as u64);
            return_val = addr as isize;
        }
        #[cfg(target_arch = "loongarch64")]
        if trace_brk {
            warn!("[la-libcbench-brk] ret={:#x}", return_val as usize);
        }
        #[cfg(target_arch = "riscv64")]
        if trace_brk {
            warn!("[rv-libcbench-brk] ret={:#x}", return_val as usize);
        }
        Ok(return_val)
    })
}
