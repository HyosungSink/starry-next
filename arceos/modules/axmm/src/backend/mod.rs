//! Memory mapping backends.

use ::alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use axhal::paging::{MappingFlags, PageTable};
use kspin::SpinNoIrq;
use memory_addr::{PAGE_SIZE_4K, PhysAddr, VirtAddr};
use memory_set::MappingBackend;

mod alloc;
mod linear;

pub use self::alloc::{SharedFrames, alloc_user_frame, dec_frame_ref};
pub(crate) use self::alloc::{CowPageRegistry, SharedPageRegistry};
pub(crate) use self::alloc::{inc_frame_ref, inc_frame_refs};

/// A unified enum type for different memory mapping backends.
///
/// Currently, two backends are implemented:
///
/// - **Linear**: used for linear mappings. The target physical frames are
///   contiguous and their addresses should be known when creating the mapping.
/// - **Allocation**: used in general, or for lazy mappings. The target physical
///   frames are obtained from the global allocator.
#[derive(Clone)]
pub enum Backend {
    /// Linear mapping backend.
    ///
    /// The offset between the virtual address and the physical address is
    /// constant, which is specified by `pa_va_offset`. For example, the virtual
    /// address `vaddr` is mapped to the physical address `vaddr - pa_va_offset`.
    Linear {
        /// `vaddr - paddr`.
        pa_va_offset: usize,
    },
    /// Allocation mapping backend.
    ///
    /// If `populate` is `true`, all physical frames are allocated when the
    /// mapping is created, and no page faults are triggered during the memory
    /// access. Otherwise, the physical frames are allocated on demand (by
    /// handling page faults).
    Alloc {
        /// Whether to populate the physical frames when creating the mapping.
        populate: bool,
        /// Shared frame registry for `MAP_SHARED` mappings.
        shared: Option<Arc<SharedPageRegistry>>,
        /// Instantiated page registry for this mapping.
        pages: Arc<SpinNoIrq<BTreeMap<usize, PhysAddr>>>,
    },
    /// Copy-on-write mapping backend used by `fork`.
    Cow {
        /// Per-process snapshot of instantiated pages within the area.
        ///
        /// The registry tracks the current backing frame for each mapped page.
        /// Pages dirtied by the parent after the last fork are recorded so the
        /// next fork only needs to re-protect that small subset.
        pages: Arc<CowPageRegistry>,
    },
    /// Shared mapping backend used for `MAP_SHARED` pages inherited across `fork()`.
    Shared {
        /// The mapped page frames for pages that were already instantiated.
        frames: Arc<SharedPageRegistry>,
    },
    /// Shared mapping backend backed by a fixed frame vector indexed by page offset.
    SegmentShared {
        /// One frame per page within the memory area.
        frames: Arc<SharedFrames>,
    },
}

impl MappingBackend for Backend {
    type Addr = VirtAddr;
    type Flags = MappingFlags;
    type PageTable = PageTable;
    fn map(&self, start: VirtAddr, size: usize, flags: MappingFlags, pt: &mut PageTable) -> bool {
        match *self {
            Self::Linear { pa_va_offset } => self.map_linear(start, size, flags, pt, pa_va_offset),
            Self::Alloc { populate, .. } => self.map_alloc(start, size, flags, pt, populate),
            Self::Cow { ref pages } => self.map_cow(start, size, flags, pt, pages),
            Self::Shared { ref frames } => self.map_shared(start, size, flags, pt, frames),
            Self::SegmentShared { ref frames } => {
                self.map_segment_shared(start, size, flags, pt, frames)
            }
        }
    }

    fn unmap(&self, start: VirtAddr, size: usize, pt: &mut PageTable) -> bool {
        match *self {
            Self::Linear { pa_va_offset } => self.unmap_linear(start, size, pt, pa_va_offset),
            Self::Alloc { populate, .. } => self.unmap_alloc(start, size, pt, populate),
            Self::Cow { .. } => self.unmap_cow(start, size, pt),
            Self::Shared { .. } => self.unmap_shared(start, size, pt),
            Self::SegmentShared { .. } => self.unmap_segment_shared(start, size, pt),
        }
    }

    fn protect(
        &self,
        start: Self::Addr,
        size: usize,
        new_flags: Self::Flags,
        page_table: &mut Self::PageTable,
    ) -> bool {
        let mut vaddr = start;
        let end = start + size;
        while vaddr < end {
            match page_table.query(vaddr) {
                Ok((_, cur_flags, page_size)) => {
                    if !cur_flags.is_empty()
                        && page_table
                            .protect(vaddr, new_flags)
                            .map(|(_, tlb)| tlb.ignore())
                            .is_err()
                    {
                        return false;
                    }
                    vaddr += page_size as usize;
                }
                Err(_) => {
                    vaddr += PAGE_SIZE_4K;
                }
            }
        }
        true
    }

    fn clone_for_range(
        &self,
        old_start: Self::Addr,
        new_start: Self::Addr,
        new_size: usize,
    ) -> Self {
        let range_start = new_start.as_usize();
        let range_end = range_start.saturating_add(new_size);
        let page_offset = new_start
            .as_usize()
            .saturating_sub(old_start.as_usize())
            / PAGE_SIZE_4K;
        let page_count = new_size / PAGE_SIZE_4K;
        match self {
            Self::Linear { .. } => self.clone(),
            Self::Alloc {
                populate,
                shared,
                pages,
            } => {
                let page_snapshot: Vec<(usize, PhysAddr)> = pages
                    .lock()
                    .range(range_start..range_end)
                    .map(|(page, frame)| (*page, *frame))
                    .collect();
                let page_frames: Vec<PhysAddr> =
                    page_snapshot.iter().map(|(_, frame)| *frame).collect();
                inc_frame_refs(&page_frames);
                let new_pages =
                    Arc::new(SpinNoIrq::new(page_snapshot.into_iter().collect::<BTreeMap<_, _>>()));
                let new_shared = shared.as_ref().map(|shared_frames| {
                    let shared_snapshot = shared_frames.snapshot_range(range_start, range_end);
                    let shared_refs: Vec<PhysAddr> =
                        shared_snapshot.iter().map(|(_, frame)| *frame).collect();
                    inc_frame_refs(&shared_refs);
                    Arc::new(SharedPageRegistry::from_snapshot(shared_snapshot))
                });
                Self::Alloc {
                    populate: *populate,
                    shared: new_shared,
                    pages: new_pages,
                }
            }
            Self::Cow { pages } => {
                let snapshot = pages.snapshot_range(page_offset, page_count);
                let refs: Vec<PhysAddr> = snapshot.iter().map(|(_, frame)| *frame).collect();
                inc_frame_refs(&refs);
                let dirty = pages.dirty_pages_range(page_offset, page_count);
                Self::Cow {
                    pages: Arc::new(CowPageRegistry::from_snapshot_with_dirty(snapshot, dirty)),
                }
            }
            Self::Shared { frames } => {
                let snapshot = frames.snapshot_range(range_start, range_end);
                let refs: Vec<PhysAddr> = snapshot.iter().map(|(_, frame)| *frame).collect();
                inc_frame_refs(&refs);
                Self::Shared {
                    frames: Arc::new(SharedPageRegistry::from_snapshot(snapshot)),
                }
            }
            Self::SegmentShared { frames } => {
                let snapshot = frames.slice_range(page_offset, page_count);
                inc_frame_refs(&snapshot);
                Self::SegmentShared {
                    frames: Arc::new(SharedFrames::new(snapshot)),
                }
            }
        }
    }
}

impl Backend {
    pub(crate) fn is_empty_private_lazy_alloc(&self) -> bool {
        match self {
            Self::Alloc {
                populate,
                shared,
                pages,
            } => !*populate && shared.is_none() && pages.lock().is_empty(),
            _ => false,
        }
    }

    pub(crate) fn handle_page_fault(
        &self,
        area_start: VirtAddr,
        vaddr: VirtAddr,
        access_flags: MappingFlags,
        orig_flags: MappingFlags,
        page_table: &mut PageTable,
    ) -> bool {
        match *self {
            Self::Linear { .. } => false, // Linear mappings should not trigger page faults.
            Self::Alloc { populate, .. } => {
                self.handle_page_fault_alloc(vaddr, access_flags, orig_flags, page_table, populate)
            }
            Self::Cow { ref pages } => {
                self.handle_page_fault_cow(area_start, vaddr, access_flags, orig_flags, page_table, pages)
            }
            Self::Shared { ref frames } => {
                self.handle_page_fault_shared(vaddr, orig_flags, page_table, frames)
            }
            Self::SegmentShared { ref frames } => self.handle_page_fault_segment_shared(
                vaddr,
                orig_flags,
                page_table,
                area_start,
                frames,
            ),
        }
    }
}
