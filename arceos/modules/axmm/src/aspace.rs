use core::fmt;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use axerrno::{ax_err, AxError, AxResult};
use axhal::mem::phys_to_virt;
use axhal::paging::{MappingFlags, PageTable, PagingError};
use memory_addr::{
    is_aligned_4k, MemoryAddr, PageIter4K, PhysAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K,
};
use memory_set::{MappingBackend, MemoryArea, MemorySet};

use crate::backend::{Backend, CowPageRegistry, SharedFrames, inc_frame_ref, inc_frame_refs};
use crate::{mapping_err_to_ax_err, KERNEL_ASPACE};

#[inline]
unsafe fn copy_kernel_bytes(dst: *mut u8, src: *const u8, len: usize) {
    #[cfg(target_arch = "loongarch64")]
    {
        let mut offset = 0usize;
        while offset < len {
            let byte = unsafe { core::ptr::read(src.add(offset)) };
            unsafe { core::ptr::write(dst.add(offset), byte) };
            offset += 1;
        }
    }
    #[cfg(not(target_arch = "loongarch64"))]
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
}

/// The virtual memory address space.
pub struct AddrSpace {
    va_range: VirtAddrRange,
    areas: MemorySet<Backend>,
    pt: PageTable,
}

impl AddrSpace {
    fn detach_shared_kernel_mappings_in_pt(pt: &mut PageTable) {
        if cfg!(target_arch = "aarch64") || cfg!(target_arch = "loongarch64") {
            return;
        }
        let kernel_aspace = KERNEL_ASPACE.lock();
        pt.clear_root_entries(kernel_aspace.base(), kernel_aspace.size());
    }

    /// Returns the address space base.
    pub const fn base(&self) -> VirtAddr {
        self.va_range.start
    }

    /// Returns the address space end.
    pub const fn end(&self) -> VirtAddr {
        self.va_range.end
    }

    /// Returns the address space size.
    pub fn size(&self) -> usize {
        self.va_range.size()
    }

    /// Returns the number of tracked mapped areas.
    pub fn area_count(&self) -> usize {
        self.areas.len()
    }

    /// Returns the total virtual size covered by tracked areas.
    pub fn total_area_size(&self) -> usize {
        self.areas.iter().map(|area| area.size()).sum()
    }

    /// Returns the reference to the inner page table.
    pub const fn page_table(&self) -> &PageTable {
        &self.pt
    }

    /// Returns the root physical address of the inner page table.
    pub const fn page_table_root(&self) -> PhysAddr {
        self.pt.root_paddr()
    }

    /// Checks if the address space contains the given address range.
    pub fn contains_range(&self, start: VirtAddr, size: usize) -> bool {
        VirtAddrRange::try_from_start_size(start, size)
            .is_some_and(|range| self.va_range.contains_range(range))
    }

    /// Creates a new empty address space.
    pub(crate) fn new_empty(base: VirtAddr, size: usize) -> AxResult<Self> {
        Ok(Self {
            va_range: VirtAddrRange::from_start_size(base, size),
            areas: MemorySet::new(),
            pt: PageTable::try_new().map_err(|_| AxError::NoMemory)?,
        })
    }

    /// Copies page table mappings from another address space.
    ///
    /// It copies the page table entries only rather than the memory regions,
    /// usually used to copy a portion of the kernel space mapping to the
    /// user space.
    ///
    /// Returns an error if the two address spaces overlap.
    pub fn copy_mappings_from(&mut self, other: &AddrSpace) -> AxResult {
        if self.va_range.overlaps(other.va_range) {
            return ax_err!(InvalidInput, "address space overlap");
        }
        self.pt.copy_from(&other.pt, other.base(), other.size());
        Ok(())
    }

    /// Finds a free area that can accommodate the given size.
    ///
    /// The search starts from the given hint address, and the area should be within the given limit range.
    ///
    /// Returns the start address of the free area. Returns None if no such area is found.
    pub fn find_free_area(
        &self,
        hint: VirtAddr,
        size: usize,
        limit: VirtAddrRange,
    ) -> Option<VirtAddr> {
        self.areas.find_free_area(hint, size, limit)
    }

    /// Returns the mapping flags when a single tracked area fully covers the range.
    pub fn area_flags_for_range(&self, start: VirtAddr, size: usize) -> Option<MappingFlags> {
        if size == 0 || !self.contains_range(start, size) {
            return None;
        }
        let end = start.checked_add(size)?;
        let area = self.areas.find(start)?;
        (end <= area.end()).then(|| area.flags())
    }

    /// Add a new linear mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_linear(
        &mut self,
        start_vaddr: VirtAddr,
        start_paddr: PhysAddr,
        size: usize,
        flags: MappingFlags,
    ) -> AxResult {
        if !self.contains_range(start_vaddr, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start_vaddr.is_aligned_4k() || !start_paddr.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let offset = start_vaddr.as_usize() - start_paddr.as_usize();
        let area = MemoryArea::new(start_vaddr, size, flags, Backend::new_linear(offset));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new allocation mapping.
    ///
    /// See [`Backend`] for more details about the mapping backends.
    ///
    /// The `flags` parameter indicates the mapping permissions and attributes.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn map_alloc(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        populate: bool,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        if !populate {
            if let Some(prev_area) = self.areas.iter().last() {
                if prev_area.end() == start
                    && prev_area.flags() == flags
                    && prev_area.backend().is_empty_private_lazy_alloc()
                {
                    let merged_start = prev_area.start();
                    let merged_size = prev_area.size() + size;
                    self.areas
                        .unmap(merged_start, prev_area.size(), &mut self.pt)
                        .map_err(mapping_err_to_ax_err)?;
                    let merged = MemoryArea::new(
                        merged_start,
                        merged_size,
                        flags,
                        Backend::new_alloc(false),
                    );
                    self.areas
                        .map(merged, &mut self.pt, false)
                        .map_err(mapping_err_to_ax_err)?;
                    return Ok(());
                }
            }
        }

        let area = MemoryArea::new(start, size, flags, Backend::new_alloc(populate));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new shared allocation mapping.
    pub fn map_alloc_shared(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        populate: bool,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let area = MemoryArea::new(start, size, flags, Backend::new_shared_alloc(populate));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a new zero-initialized allocation mapping.
    pub fn alloc_for_lazy(&mut self, start: VirtAddr, size: usize) -> AxResult {
        let end = (start + size).align_up_4k();
        let mut start = start.align_down_4k();
        let size = end - start;
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        while let Some(area) = self.areas.find(start) {
            let area_backend = area.backend();
            if let Backend::Alloc { populate, .. } = area_backend {
                if !*populate {
                    let count = (area.end().min(end) - start).align_up_4k() / PAGE_SIZE_4K;
                    for i in 0..count {
                        let addr = start + i * PAGE_SIZE_4K;
                        area_backend.handle_page_fault_alloc(
                            addr,
                            MappingFlags::empty(),
                            area.flags(),
                            &mut self.pt,
                            *populate,
                        );
                    }
                }
            }
            start = area.end();
            assert!(start.is_aligned_4k());
        }
        if start < end {
            ax_err!(InvalidInput, "address out of range")?;
        }
        Ok(())
    }

    /// Add a shared read-only mapping backed by preallocated frames.
    pub fn map_shared(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        frames: Arc<Vec<PhysAddr>>,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        for &frame in frames.iter() {
            if frame.as_usize() != 0 {
                inc_frame_ref(frame);
            }
        }
        let indexed_frames: Vec<(usize, PhysAddr)> = frames
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, frame)| frame.as_usize() != 0)
            .collect();
        let area = MemoryArea::new(
            start,
            size,
            flags,
            Backend::new_cow(Arc::new(CowPageRegistry::from_snapshot(indexed_frames))),
        );
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a truly shared mapping backed by a fixed frame vector.
    pub fn map_segment_shared(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        frames: Arc<SharedFrames>,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        if frames.len() * PAGE_SIZE_4K != size {
            return ax_err!(InvalidInput, "frame vector size mismatch");
        }
        let area = MemoryArea::new(start, size, flags, Backend::new_segment_shared(frames));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Add a shared mapping backed by fixed frames keyed by virtual page.
    pub fn map_shared_frames(
        &mut self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        frames: Arc<SharedFrames>,
    ) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }
        if frames.len() * PAGE_SIZE_4K != size {
            return ax_err!(InvalidInput, "frame vector size mismatch");
        }
        let indexed_frames = frames
            .iter()
            .enumerate()
            .map(|(index, frame)| (start.as_usize() + index * PAGE_SIZE_4K, *frame))
            .collect();
        let area = MemoryArea::new(start, size, flags, Backend::new_shared_pages(indexed_frames));
        self.areas
            .map(area, &mut self.pt, false)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Removes mappings within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn unmap(&mut self, start: VirtAddr, size: usize) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        self.areas
            .unmap(start, size, &mut self.pt)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// To remove user area mappings from address space.
    pub fn unmap_user_areas(&mut self) -> AxResult {
        for area in self.areas.iter() {
            assert!(area.start().is_aligned_4k());
            assert!(area.size() % PAGE_SIZE_4K == 0);
            assert!(area.flags().contains(MappingFlags::USER));
            assert!(
                self.va_range
                    .contains_range(VirtAddrRange::from_start_size(area.start(), area.size())),
                "MemorySet contains out-of-va-range area"
            );
        }
        self.areas.clear(&mut self.pt).unwrap();
        self.pt.reclaim_empty(self.base(), self.size());
        Ok(())
    }

    /// To process data in this area with the given function.
    ///
    /// Now it supports reading and writing data in the given interval.
    ///
    /// # Arguments
    /// - `start`: The start virtual address to process.
    /// - `size`: The size of the data to process.
    /// - `f`: The function to process the data, whose arguments are the start virtual address,
    ///   the offset and the size of the data.
    ///
    /// # Notes
    ///   The caller must ensure that the permission of the operation is allowed.
    fn process_area_data<F>(&self, start: VirtAddr, size: usize, f: F) -> AxResult
    where
        F: FnMut(VirtAddr, usize, usize),
    {
        Self::process_area_data_with_page_table(&self.pt, &self.va_range, start, size, f)
    }

    fn ensure_area_ready(
        &mut self,
        start: VirtAddr,
        size: usize,
        for_kernel_write: bool,
    ) -> AxResult {
        if size == 0 {
            return Ok(());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        let end = (start + size).align_up_4k();
        for page in
            PageIter4K::new(start.align_down_4k(), end).expect("Failed to create page iterator")
        {
            let area_flags = self
                .areas
                .find(page)
                .map(|area| area.flags())
                .ok_or(AxError::BadAddress)?;
            let prefer_write_fault = for_kernel_write && area_flags.contains(MappingFlags::WRITE);

            let mut flags = match self.pt.query(page) {
                Ok((_paddr, flags, _)) if !flags.is_empty() => flags,
                _ => {
                    let fault_access = if prefer_write_fault {
                        MappingFlags::WRITE
                    } else {
                        MappingFlags::READ
                    };
                    if !self.handle_page_fault(page, fault_access) {
                        return Err(AxError::BadAddress);
                    }
                    match self.pt.query(page) {
                        Ok((_paddr, flags, _)) if !flags.is_empty() => flags,
                        _ => return Err(AxError::BadAddress),
                    }
                }
            };

            if prefer_write_fault && !flags.contains(MappingFlags::WRITE) {
                if !self.handle_page_fault(page, MappingFlags::WRITE) {
                    return Err(AxError::BadAddress);
                }
                flags = match self.pt.query(page) {
                    Ok((_paddr, flags, _)) if !flags.is_empty() => flags,
                    _ => return Err(AxError::BadAddress),
                };
            }

            if for_kernel_write || flags.contains(MappingFlags::READ) {
                continue;
            }
            return Err(AxError::BadAddress);
        }
        Ok(())
    }

    fn process_area_data_with_page_table<F>(
        pt: &PageTable,
        va_range: &VirtAddrRange,
        start: VirtAddr,
        size: usize,
        mut f: F,
    ) -> AxResult
    where
        F: FnMut(VirtAddr, usize, usize),
    {
        if !va_range.contains_range(VirtAddrRange::from_start_size(start, size)) {
            return ax_err!(InvalidInput, "address out of range");
        }
        let mut cnt = 0;
        // If start is aligned to 4K, start_align_down will be equal to start_align_up.
        let end_align_up = (start + size).align_up_4k();
        for vaddr in PageIter4K::new(start.align_down_4k(), end_align_up)
            .expect("Failed to create page iterator")
        {
            let (mut paddr, _, _) = pt.query(vaddr).map_err(|_| AxError::BadAddress)?;

            let mut copy_size = (size - cnt).min(PAGE_SIZE_4K);

            if copy_size == 0 {
                break;
            }
            if vaddr == start.align_down_4k() && start.align_offset_4k() != 0 {
                let align_offset = start.align_offset_4k();
                copy_size = copy_size.min(PAGE_SIZE_4K - align_offset);
                paddr += align_offset;
            }
            f(phys_to_virt(paddr), cnt, copy_size);
            cnt += copy_size;
        }
        Ok(())
    }

    /// To read data from the address space.
    ///
    /// # Arguments
    ///
    /// * `start` - The start virtual address to read.
    /// * `buf` - The buffer to store the data.
    pub fn read(&mut self, start: VirtAddr, buf: &mut [u8]) -> AxResult {
        if buf.is_empty() {
            return Ok(());
        }
        self.ensure_area_ready(start, buf.len(), false)?;
        let end = start + (buf.len() - 1);
        if start.align_down_4k() == end.align_down_4k() {
            let (paddr, _, _) = self
                .pt
                .query(start.align_down_4k())
                .map_err(|_| AxError::BadAddress)?;
            let src = phys_to_virt(paddr.align_down_4k()) + start.align_offset_4k();
            unsafe {
                copy_kernel_bytes(buf.as_mut_ptr(), src.as_ptr(), buf.len());
            }
            return Ok(());
        }
        self.process_area_data(start, buf.len(), |src, offset, read_size| unsafe {
            copy_kernel_bytes(buf.as_mut_ptr().add(offset), src.as_ptr(), read_size);
        })
    }

    /// To write data to the address space.
    ///
    /// # Arguments
    ///
    /// * `start_vaddr` - The start virtual address to write.
    /// * `buf` - The buffer to write to the address space.
    pub fn write(&mut self, start: VirtAddr, buf: &[u8]) -> AxResult {
        if buf.is_empty() {
            return Ok(());
        }
        self.ensure_area_ready(start, buf.len(), true)?;
        let end = start + (buf.len() - 1);
        if start.align_down_4k() == end.align_down_4k() {
            let (paddr, _, _) = self
                .pt
                .query(start.align_down_4k())
                .map_err(|_| AxError::BadAddress)?;
            let dst = phys_to_virt(paddr.align_down_4k()) + start.align_offset_4k();
            unsafe {
                copy_kernel_bytes(dst.as_mut_ptr(), buf.as_ptr(), buf.len());
            }
            return Ok(());
        }
        self.process_area_data(start, buf.len(), |dst, offset, write_size| unsafe {
            copy_kernel_bytes(dst.as_mut_ptr(), buf.as_ptr().add(offset), write_size);
        })
    }

    /// Updates mapping within the specified virtual address range.
    ///
    /// Returns an error if the address range is out of the address space or not
    /// aligned.
    pub fn protect(&mut self, start: VirtAddr, size: usize, flags: MappingFlags) -> AxResult {
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        self.areas
            .protect(start, size, |_| Some(flags), &mut self.pt)
            .map_err(mapping_err_to_ax_err)?;
        Ok(())
    }

    /// Removes all mappings in the address space.
    pub fn clear(&mut self) {
        self.areas.clear(&mut self.pt).unwrap();
    }

    /// Handles a page fault at the given address.
    ///
    /// `access_flags` indicates the access type that caused the page fault.
    ///
    /// Returns `true` if the page fault is handled successfully (not a real
    /// fault).
    pub fn handle_page_fault(&mut self, vaddr: VirtAddr, access_flags: MappingFlags) -> bool {
        if !self.va_range.contains(vaddr) {
            warn!(
                "handle_page_fault outside range: vaddr={:#x} access={:?} range=[{:#x}, {:#x})",
                vaddr,
                access_flags,
                self.base(),
                self.end()
            );
            return false;
        }
        if let Some(area) = self.areas.find(vaddr) {
            let orig_flags = area.flags();
            if orig_flags.contains(access_flags) {
                let handled =
                    area.backend()
                        .handle_page_fault(area.start(), vaddr, access_flags, orig_flags, &mut self.pt);
                if !handled {
                    let backend = match area.backend() {
                        Backend::Linear { .. } => "linear",
                        Backend::Alloc {
                            populate, shared, ..
                        } => {
                            if *populate {
                                if shared.is_some() {
                                    "alloc(shared-populate)"
                                } else {
                                    "alloc(populate)"
                                }
                            } else {
                                if shared.is_some() {
                                    "alloc(shared-lazy)"
                                } else {
                                    "alloc(lazy)"
                                }
                            }
                        }
                        Backend::Cow { .. } => "cow",
                        Backend::Shared { .. } => "shared",
                        Backend::SegmentShared { .. } => "segment-shared",
                    };
                    warn!(
                        "handle_page_fault failed: vaddr={:#x} access={:?} area=[{:#x}, {:#x}) flags={:?} backend={} query={:?}",
                        vaddr,
                        access_flags,
                        area.start(),
                        area.end(),
                        orig_flags,
                        backend,
                        self.pt.query(vaddr.align_down_4k())
                    );
                }
                return handled;
            }
            debug!(
                "handle_page_fault denied by area flags: vaddr={:#x} access={:?} area=[{:#x}, {:#x}) flags={:?}",
                vaddr,
                access_flags,
                area.start(),
                area.end(),
                orig_flags
            );
            return false;
        }
        debug!(
            "handle_page_fault no area: vaddr={:#x} access={:?}",
            vaddr, access_flags
        );
        false
    }

    /// Returns a stable key address for shared futexes.
    pub fn shared_futex_key_addr(&mut self, vaddr: VirtAddr) -> Option<usize> {
        if !self.va_range.contains(vaddr) {
            return None;
        }
        let (area_start, area_flags, backend) = {
            let area = self.areas.find(vaddr)?;
            let is_shared = matches!(
                area.backend(),
                Backend::Shared { .. }
                    | Backend::SegmentShared { .. }
                    | Backend::Alloc {
                        shared: Some(_),
                        ..
                    }
            );
            if !is_shared {
                return None;
            }
            (area.start(), area.flags(), area.backend().clone())
        };

        let page = vaddr.align_down_4k();
        let mut query = self.pt.query(page).ok();
        if query.is_none() && area_flags.contains(MappingFlags::READ) {
            let _ = backend.handle_page_fault(
                area_start,
                page,
                MappingFlags::READ,
                area_flags,
                &mut self.pt,
            );
            query = self.pt.query(page).ok();
        }
        let (paddr, flags, _) = query?;
        if flags.is_empty() {
            return None;
        }

        let page_offset = vaddr.as_usize() & (PAGE_SIZE_4K - 1);
        Some(paddr.align_down_4k().as_usize() + page_offset)
    }

    /// Invalidates currently installed PTEs for shared-backed mappings in the range.
    ///
    /// The virtual memory areas remain intact, so future accesses can remap the
    /// same shared frames via the normal page-fault path.
    pub fn invalidate_shared_range(&mut self, start: VirtAddr, size: usize) -> AxResult {
        if size == 0 {
            return Ok(());
        }
        if !self.contains_range(start, size) {
            return ax_err!(InvalidInput, "address out of range");
        }
        if !start.is_aligned_4k() || !is_aligned_4k(size) {
            return ax_err!(InvalidInput, "address not aligned");
        }

        let end = start + size;
        let mut cursor = start;
        while cursor < end {
            let Some(area) = self.areas.find(cursor) else {
                cursor += PAGE_SIZE_4K;
                continue;
            };
            let overlap_end = area.end().min(end);
            match area.backend() {
                Backend::Shared { .. } | Backend::SegmentShared { .. } => {
                    if !area
                        .backend()
                        .unmap(cursor, overlap_end - cursor, &mut self.pt)
                    {
                        return Err(AxError::BadState);
                    }
                }
                _ => {}
            }
            cursor = overlap_end;
        }
        Ok(())
    }

    /// 克隆 AddrSpace。这将创建一个新的页表，并将旧页表中的所有区域（包括内核区域）映射到新的页表中，但仅将用户区域的映射到新的 MemorySet 中。
    ///
    /// 如果发生错误，新创建的 MemorySet 将被丢弃并返回错误。
    pub fn clone_or_err(&mut self, force_deep_copy: bool) -> AxResult<Self> {
        // 由于要克隆的这个地址空间可能是用户空间，而用户空间在一开始创建时不会在MemorySet中管理内核区域，而是直接把相关的页表项复制到了新页表中，所以在MemorySet中没有内核区域，需要另外处理。
        let mut new_pt = PageTable::try_new().map_err(|_| AxError::NoMemory)?;
        // 如果不是 ARMv8 架构，将内核部分复制到用户页表中。
        if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
            // ARMv8 使用一个单独的页表 (TTBR0_EL1) 用于用户空间，不需要将内核部分复制到用户页表中。
            let kernel_aspace = KERNEL_ASPACE.lock();
            new_pt.copy_from(
                &kernel_aspace.pt,
                kernel_aspace.base(),
                kernel_aspace.size(),
            );
        }

        let total_area_size: usize = self.areas.iter().map(|area| area.size()).sum();
        debug!(
            "clone_or_err total_area_size={} area_count={}",
            total_area_size,
            self.areas.len()
        );
        if force_deep_copy {
            debug!("clone_or_err using deep-copy path");
            let mut new_areas = MemorySet::new();
            for area in self.areas.iter() {
                let (new_backend, copy_mapped_pages) = match area.backend() {
                    Backend::Alloc { .. } | Backend::Cow { .. } | Backend::Shared { .. } => {
                        (Backend::new_alloc(false), true)
                    }
                    _ => (area.backend().clone(), false),
                };
                let area_backend = new_backend.clone();
                let new_area =
                    MemoryArea::new(area.start(), area.size(), area.flags(), new_backend);
                if let Err(err) = new_areas.map(new_area, &mut new_pt, false) {
                    new_areas.clear(&mut new_pt).ok();
                    Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                    return Err(mapping_err_to_ax_err(err));
                }
                if copy_mapped_pages {
                    for addr in PageIter4K::new(area.start(), area.end()).unwrap() {
                        let Ok((src_paddr, src_flags, _)) = self.pt.query(addr) else {
                            continue;
                        };
                        if src_flags.is_empty() {
                            continue;
                        }
                        if !area_backend.handle_page_fault_alloc(
                            addr,
                            MappingFlags::READ,
                            area.flags(),
                            &mut new_pt,
                            false,
                        ) {
                            new_areas.clear(&mut new_pt).ok();
                            Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                            return Err(AxError::NoMemory);
                        }
                        let Ok((dst_paddr, _, _)) = new_pt.query(addr) else {
                            new_areas.clear(&mut new_pt).ok();
                            Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                            return Err(AxError::BadAddress);
                        };
                        unsafe {
                            copy_kernel_bytes(
                                phys_to_virt(dst_paddr.align_down_4k()).as_mut_ptr(),
                                phys_to_virt(src_paddr.align_down_4k()).as_ptr(),
                                PAGE_SIZE_4K,
                            );
                        }
                    }
                }
            }
            return Ok(Self {
                va_range: self.va_range,
                areas: new_areas,
                pt: new_pt,
            });
        }

        debug!("clone_or_err using cow path");
        let mut new_areas = MemorySet::new();
        let pt = &mut self.pt as *mut PageTable;
        for area in self.areas.iter_mut() {
            let area_flags = area.flags();
            let original_backend = area.backend().clone();
            let new_backend = match original_backend {
                Backend::Alloc {
                    shared: Some(frames),
                    ..
                } => {
                    let snapshot = frames
                        .snapshot_range(area.start().as_usize(), area.end().as_usize());
                    let refs: Vec<PhysAddr> =
                        snapshot.iter().map(|(_, frame)| *frame).collect();
                    inc_frame_refs(&refs);
                    Backend::new_shared(Arc::new(
                        crate::backend::SharedPageRegistry::from_snapshot(snapshot),
                    ))
                }
                Backend::Alloc { ref pages, .. } => {
                    let snapshot: Vec<(usize, PhysAddr)> =
                        pages.lock().iter().map(|(addr, frame)| (*addr, *frame)).collect();
                    let mut frames = Vec::new();
                    let mut ref_frames = Vec::new();
                    if !area_flags.contains(MappingFlags::WRITE) {
                        let readonly_pages: Vec<(usize, PhysAddr)> = snapshot
                            .into_iter()
                            .filter(|(addr_usize, _)| {
                                let addr = VirtAddr::from_usize(*addr_usize);
                                addr >= area.start() && addr < area.end()
                            })
                            .collect();
                        ref_frames.extend(readonly_pages.iter().map(|(_, frame)| *frame));
                        inc_frame_refs(&ref_frames);
                        let shared =
                            Arc::new(crate::backend::SharedPageRegistry::from_snapshot(readonly_pages));
                        area.set_backend(Backend::new_shared(Arc::clone(&shared)));
                        Backend::new_shared(shared)
                    } else {
                        let cow_flags = area_flags & !MappingFlags::WRITE;
                        for (addr_usize, frame) in snapshot {
                            let addr = VirtAddr::from_usize(addr_usize);
                            if addr < area.start() || addr >= area.end() {
                                continue;
                            }
                            let page_index =
                                (addr.as_usize() - area.start().as_usize()) / PAGE_SIZE_4K;
                            ref_frames.push(frame);
                            match unsafe { (&mut *pt).protect(addr, cow_flags) } {
                                Ok((_, tlb)) => {
                                    tlb.flush();
                                }
                                Err(PagingError::NotMapped) => {}
                                Err(_) => {
                                    new_areas.clear(&mut new_pt).ok();
                                    Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                                    return Err(AxError::BadState);
                                }
                            }
                            frames.push((page_index, frame));
                        }
                        inc_frame_refs(&ref_frames);
                        let shared_pages = Arc::new(frames.into_iter().collect::<BTreeMap<_, _>>());
                        let parent_pages =
                            Arc::new(CowPageRegistry::from_shared_pages(Arc::clone(&shared_pages)));
                        let child_pages =
                            Arc::new(CowPageRegistry::from_shared_pages(shared_pages));
                        area.set_backend(Backend::new_cow(parent_pages));
                        Backend::new_cow(child_pages)
                    }
                }
                Backend::Cow { ref pages } => {
                    if !area_flags.contains(MappingFlags::WRITE) {
                        let snapshot = pages.snapshot();
                        let readonly_pages: Vec<(usize, PhysAddr)> = snapshot
                            .into_iter()
                            .map(|(page_index, frame)| {
                                (area.start().as_usize() + page_index * PAGE_SIZE_4K, frame)
                            })
                            .collect();
                        let ref_frames: Vec<PhysAddr> =
                            readonly_pages.iter().map(|(_, frame)| *frame).collect();
                        inc_frame_refs(&ref_frames);
                        let shared = Arc::new(
                            crate::backend::SharedPageRegistry::from_snapshot(readonly_pages),
                        );
                        area.set_backend(Backend::new_shared(Arc::clone(&shared)));
                        Backend::new_shared(shared)
                    } else {
                        let dirty_pages = pages.take_dirty_pages();
                        let cow_flags = area_flags & !MappingFlags::WRITE;
                        for page_index in dirty_pages {
                            let addr = area.start() + page_index * PAGE_SIZE_4K;
                            match unsafe { (&mut *pt).protect(addr, cow_flags) } {
                                Ok((_, tlb)) => {
                                    tlb.flush();
                                }
                                Err(PagingError::NotMapped) => {}
                                Err(_) => {
                                    new_areas.clear(&mut new_pt).ok();
                                    Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                                    return Err(AxError::BadState);
                                }
                            }
                        }

                        let ref_frames = pages.frames();
                        inc_frame_refs(&ref_frames);
                        Backend::new_cow(Arc::new(pages.share_pages()))
                    }
                }
                Backend::Shared { ref frames } => {
                    let snapshot = frames
                        .snapshot_range(area.start().as_usize(), area.end().as_usize());
                    let refs: Vec<PhysAddr> =
                        snapshot.iter().map(|(_, frame)| *frame).collect();
                    inc_frame_refs(&refs);
                    Backend::new_shared(Arc::new(
                        crate::backend::SharedPageRegistry::from_snapshot(snapshot),
                    ))
                }
                Backend::SegmentShared { ref frames } => {
                    Backend::new_segment_shared(Arc::clone(frames))
                }
                _ => original_backend,
            };
            let backend_desc = match &new_backend {
                Backend::Linear { .. } => alloc::format!("linear"),
                Backend::Alloc {
                    populate, shared, ..
                } => {
                    alloc::format!("alloc(populate={populate}, shared={})", shared.is_some())
                }
                Backend::Cow { pages } => alloc::format!("cow(frames={})", pages.len()),
                Backend::Shared { frames } => {
                    alloc::format!("shared(frames={})", frames.lock().len())
                }
                Backend::SegmentShared { frames } => {
                    alloc::format!("segment-shared(frames={})", frames.len())
                }
            };
            let new_area = MemoryArea::new(area.start(), area.size(), area_flags, new_backend);
            if let Err(err) = new_areas.map(new_area, &mut new_pt, false) {
                warn!(
                    "clone_or_err map failed: area=[{:#x}, {:#x}) size={} flags={:?} backend={}",
                    area.start(),
                    area.end(),
                    area.size(),
                    area_flags,
                    backend_desc
                );
                new_areas.clear(&mut new_pt).ok();
                Self::detach_shared_kernel_mappings_in_pt(&mut new_pt);
                return Err(mapping_err_to_ax_err(err));
            }
        }
        Ok(Self {
            va_range: self.va_range,
            areas: new_areas,
            pt: new_pt,
        })
    }
}

impl fmt::Debug for AddrSpace {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AddrSpace")
            .field("va_range", &self.va_range)
            .field("page_table_root", &self.pt.root_paddr())
            .field("areas", &self.areas)
            .finish()
    }
}

impl Drop for AddrSpace {
    fn drop(&mut self) {
        self.clear();
        Self::detach_shared_kernel_mappings_in_pt(&mut self.pt);
    }
}
