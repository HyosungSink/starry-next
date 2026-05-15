use crate::mem::{MemRegion, MemRegionFlags, virt_to_phys};

const LOW_RAM_BASE: usize = 0x0;
const LOW_RAM_SIZE: usize = 0x1000_0000;
const HIGH_RAM_END: usize = 0xB000_0000;

/// Returns platform-specific memory regions.
///
/// QEMU loongarch64 `virt` exposes RAM in two discontiguous regions:
///   - [0x0000_0000, 0x1000_0000)  (256 MiB)
///   - [0x8000_0000, 0xB000_0000)  (768 MiB)
///
/// The area [0xB000_0000, 0xC000_0000) is not RAM. Treating the whole 1 GiB
/// range above 0x8000_0000 as free memory makes the allocator eventually touch
/// non-existent physical memory and panic under fork/epoll-heavy LTP cases.
pub(crate) fn platform_regions() -> impl Iterator<Item = MemRegion> {
    let high_ram_start = memory_addr::align_up_4k(virt_to_phys((_ekernel as usize).into()).as_usize());
    [
        MemRegion {
            paddr: pa!(LOW_RAM_BASE),
            size: LOW_RAM_SIZE,
            flags: MemRegionFlags::FREE | MemRegionFlags::READ | MemRegionFlags::WRITE,
            name: "free memory",
        },
        MemRegion {
            paddr: pa!(high_ram_start),
            size: HIGH_RAM_END.saturating_sub(high_ram_start),
            flags: MemRegionFlags::FREE | MemRegionFlags::READ | MemRegionFlags::WRITE,
            name: "free memory",
        },
    ]
    .into_iter()
    .chain(crate::mem::default_mmio_regions())
}

unsafe extern "C" {
    fn _ekernel();
}
