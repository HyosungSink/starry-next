use alloc::{collections::{BTreeMap, BTreeSet}, sync::Arc, vec::Vec};
use axalloc::global_allocator;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable, PagingError};
use core::{
    ops::Deref,
    sync::atomic::{AtomicUsize, Ordering},
};
use kspin::SpinNoIrq;
use lazyinit::LazyInit;
use memory_addr::{MemoryAddr, PageIter4K, PhysAddr, VirtAddr, PAGE_SIZE_4K};

use super::Backend;

static MAP_ALLOC_OOM_WARN_COUNT: AtomicUsize = AtomicUsize::new(0);
const MAP_ALLOC_OOM_WARN_BURST: usize = 4;
const MAP_ALLOC_OOM_WARN_PERIOD: usize = 32;

pub struct SharedFrames {
    frames: Vec<PhysAddr>,
}

pub(crate) struct SharedPageRegistry {
    pages: SpinNoIrq<BTreeMap<usize, PhysAddr>>,
}

pub(crate) struct CowPageRegistry {
    pages: SpinNoIrq<Arc<BTreeMap<usize, PhysAddr>>>,
    dirty_pages: SpinNoIrq<BTreeSet<usize>>,
}

impl SharedPageRegistry {
    pub(crate) fn new() -> Self {
        Self {
            pages: SpinNoIrq::new(BTreeMap::new()),
        }
    }

    pub(crate) fn from_snapshot(frames: Vec<(usize, PhysAddr)>) -> Self {
        Self {
            pages: SpinNoIrq::new(frames.into_iter().collect()),
        }
    }

    pub(crate) fn snapshot_range(&self, start: usize, end: usize) -> Vec<(usize, PhysAddr)> {
        self.pages
            .lock()
            .range(start..end)
            .map(|(page, frame)| (*page, *frame))
            .collect()
    }
}

impl CowPageRegistry {
    pub(crate) fn from_snapshot(frames: Vec<(usize, PhysAddr)>) -> Self {
        Self {
            pages: SpinNoIrq::new(Arc::new(frames.into_iter().collect())),
            dirty_pages: SpinNoIrq::new(BTreeSet::new()),
        }
    }

    pub(crate) fn from_shared_pages(pages: Arc<BTreeMap<usize, PhysAddr>>) -> Self {
        Self {
            pages: SpinNoIrq::new(pages),
            dirty_pages: SpinNoIrq::new(BTreeSet::new()),
        }
    }

    pub(crate) fn share_pages(&self) -> Self {
        Self::from_shared_pages(Arc::clone(&self.pages.lock()))
    }

    pub(crate) fn snapshot(&self) -> Vec<(usize, PhysAddr)> {
        self.pages
            .lock()
            .iter()
            .map(|(page, frame)| (*page, *frame))
            .collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.pages.lock().len()
    }

    pub(crate) fn frames(&self) -> Vec<PhysAddr> {
        self.pages.lock().values().copied().collect()
    }

    pub(crate) fn page_indices(&self) -> Vec<usize> {
        self.pages.lock().keys().copied().collect()
    }

    pub(crate) fn get_page(&self, page_index: usize) -> Option<PhysAddr> {
        self.pages.lock().get(&page_index).copied()
    }

    pub(crate) fn update_page(&self, page_index: usize, frame: PhysAddr) {
        let mut pages = self.pages.lock();
        if Arc::strong_count(&pages) > 1 {
            *pages = Arc::new((**pages).clone());
        }
        Arc::get_mut(&mut *pages)
            .expect("cow page registry must be unique after clone-on-write")
            .insert(page_index, frame);
    }

    pub(crate) fn mark_dirty(&self, page_index: usize) {
        self.dirty_pages.lock().insert(page_index);
    }

    pub(crate) fn take_dirty_pages(&self) -> Vec<usize> {
        let mut dirty = self.dirty_pages.lock();
        let pages: Vec<usize> = dirty.iter().copied().collect();
        dirty.clear();
        pages
    }

    pub(crate) fn from_snapshot_with_dirty(
        frames: Vec<(usize, PhysAddr)>,
        dirty_pages: Vec<usize>,
    ) -> Self {
        Self {
            pages: SpinNoIrq::new(Arc::new(frames.into_iter().collect())),
            dirty_pages: SpinNoIrq::new(dirty_pages.into_iter().collect()),
        }
    }

    pub(crate) fn snapshot_range(
        &self,
        page_offset: usize,
        page_count: usize,
    ) -> Vec<(usize, PhysAddr)> {
        let end = page_offset.saturating_add(page_count);
        self.pages
            .lock()
            .range(page_offset..end)
            .map(|(page, frame)| (page - page_offset, *frame))
            .collect()
    }

    pub(crate) fn dirty_pages_range(&self, page_offset: usize, page_count: usize) -> Vec<usize> {
        let end = page_offset.saturating_add(page_count);
        self.dirty_pages
            .lock()
            .range(page_offset..end)
            .map(|page| page - page_offset)
            .collect()
    }
}

impl Deref for SharedPageRegistry {
    type Target = SpinNoIrq<BTreeMap<usize, PhysAddr>>;

    fn deref(&self) -> &Self::Target {
        &self.pages
    }
}

impl SharedFrames {
    pub fn new(frames: Vec<PhysAddr>) -> Self {
        Self { frames }
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn get(&self, index: usize) -> Option<PhysAddr> {
        self.frames.get(index).copied()
    }

    pub fn iter(&self) -> core::slice::Iter<'_, PhysAddr> {
        self.frames.iter()
    }

    pub(crate) fn slice_range(&self, page_offset: usize, page_count: usize) -> Vec<PhysAddr> {
        let end = page_offset.saturating_add(page_count).min(self.frames.len());
        self.frames[page_offset.min(end)..end].to_vec()
    }
}

impl Drop for SharedFrames {
    fn drop(&mut self) {
        dec_frame_refs(&self.frames);
    }
}

impl Drop for SharedPageRegistry {
    fn drop(&mut self) {
        let frames: Vec<PhysAddr> = {
            let pages = self.pages.lock();
            pages.values().copied().collect()
        };
        dec_frame_refs(&frames);
    }
}

#[inline]
fn install_page_mapping(
    pt: &mut PageTable,
    addr: VirtAddr,
    frame: PhysAddr,
    flags: MappingFlags,
) -> bool {
    match pt.remap(addr, frame, flags) {
        Ok((_, tlb)) => {
            tlb.flush();
            true
        }
        Err(PagingError::NotMapped) => pt
            .map(addr, frame, PageSize::Size4K, flags)
            .map(|tlb| tlb.flush())
            .is_ok(),
        Err(_) => false,
    }
}

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

fn frame_refcounts() -> &'static SpinNoIrq<BTreeMap<usize, usize>> {
    static FRAME_REFCOUNTS: LazyInit<SpinNoIrq<BTreeMap<usize, usize>>> = LazyInit::new();
    if let Some(refs) = FRAME_REFCOUNTS.get() {
        refs
    } else {
        FRAME_REFCOUNTS.init_once(SpinNoIrq::new(BTreeMap::new()))
    }
}

fn alloc_frame(zeroed: bool) -> Option<PhysAddr> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(1, PAGE_SIZE_4K).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, PAGE_SIZE_4K) };
    }
    let paddr = virt_to_phys(vaddr);
    frame_refcounts().lock().insert(paddr.as_usize(), 1);
    Some(paddr)
}

pub fn alloc_user_frame(zeroed: bool) -> Option<PhysAddr> {
    alloc_frame(zeroed)
}

fn dealloc_frame(frame: PhysAddr) {
    let vaddr = phys_to_virt(frame);
    global_allocator().dealloc_pages(vaddr.as_usize(), 1);
}

pub(crate) fn inc_frame_refs(frames: &[PhysAddr]) {
    let mut refs = frame_refcounts().lock();
    for &frame in frames {
        if frame.as_usize() == 0 {
            continue;
        }
        let key = frame.align_down_4k().as_usize();
        // Some frames enter COW/shared tracking after they have already been mapped
        // once (for example, executable or file-backed user pages). In that case the
        // baseline refcount is 1 for the existing mapping, not 0.
        *refs.entry(key).or_insert(1) += 1;
    }
}

pub(crate) fn inc_frame_ref(frame: PhysAddr) {
    inc_frame_refs(core::slice::from_ref(&frame));
}

pub fn dec_frame_refs(frames: &[PhysAddr]) {
    let mut deltas = BTreeMap::new();
    for &frame in frames {
        if frame.as_usize() == 0 {
            continue;
        }
        let frame = frame.align_down_4k();
        let entry = deltas.entry(frame.as_usize()).or_insert((frame, 0usize));
        entry.1 += 1;
    }
    if deltas.is_empty() {
        return;
    }
    let mut refs = frame_refcounts().lock();
    let mut to_free = Vec::new();
    for (key, (frame, delta)) in deltas {
        match refs.get_mut(&key) {
            Some(count) if *count > delta => {
                *count -= delta;
            }
            Some(_) => {
                refs.remove(&key);
                to_free.push(frame);
            }
            None => {
                to_free.push(frame);
            }
        }
    }
    drop(refs);
    for frame in to_free {
        dealloc_frame(frame);
    }
}

pub fn dec_frame_ref(frame: PhysAddr) {
    if frame.as_usize() == 0 {
        return;
    }
    let key = frame.align_down_4k().as_usize();
    let mut refs = frame_refcounts().lock();
    match refs.get_mut(&key) {
        Some(count) if *count > 1 => {
            *count -= 1;
        }
        Some(_) => {
            refs.remove(&key);
            drop(refs);
            dealloc_frame(frame.align_down_4k());
        }
        None => {
            drop(refs);
            dealloc_frame(frame.align_down_4k());
        }
    }
}

impl Backend {
    /// Creates a new allocation mapping backend.
    pub fn new_alloc(populate: bool) -> Self {
        Self::Alloc {
            populate,
            shared: None,
            pages: Arc::new(SpinNoIrq::new(BTreeMap::new())),
        }
    }

    /// Creates a new shared allocation mapping backend.
    pub fn new_shared_alloc(populate: bool) -> Self {
        let shared = Arc::new(SharedPageRegistry::new());
        let pages = Arc::new(SpinNoIrq::new(BTreeMap::new()));
        Self::Alloc {
            populate,
            shared: Some(shared),
            pages,
        }
    }

    /// Creates a new copy-on-write mapping backend.
    pub(crate) fn new_cow(pages: Arc<CowPageRegistry>) -> Self {
        Self::Cow { pages }
    }

    /// Creates a new shared mapping backend from existing frames.
    pub(crate) fn new_shared(frames: Arc<SharedPageRegistry>) -> Self {
        Self::Shared { frames }
    }

    /// Creates a new shared mapping backend from a page-address snapshot.
    pub(crate) fn new_shared_pages(frames: Vec<(usize, PhysAddr)>) -> Self {
        Self::Shared {
            frames: Arc::new(SharedPageRegistry::from_snapshot(frames)),
        }
    }

    /// Creates a new shared mapping backend from a fixed frame vector.
    pub fn new_segment_shared(frames: Arc<SharedFrames>) -> Self {
        Self::SegmentShared { frames }
    }

    pub(crate) fn map_alloc(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        debug!(
            "map_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            flags,
            populate
        );
        if populate {
            // allocate all possible physical frames for populated mapping.
            let mut mapped = Vec::new();
            let (shared_frames, pages) = match self {
                Backend::Alloc { shared, pages, .. } => (shared.clone(), Some(Arc::clone(pages))),
                _ => (None, None),
            };
            for addr in PageIter4K::new(start, start + size).unwrap() {
                if let Some(frame) = alloc_frame(true) {
                    if let Ok(tlb) = pt.map(addr, frame, PageSize::Size4K, flags) {
                        tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                        if let Some(shared_frames) = shared_frames.as_ref() {
                            shared_frames.lock().insert(addr.as_usize(), frame);
                            inc_frame_ref(frame);
                        }
                        if let Some(pages) = pages.as_ref() {
                            pages.lock().insert(addr.as_usize(), frame);
                        }
                        mapped.push(addr);
                    } else {
                        dec_frame_ref(frame);
                        for mapped_addr in mapped {
                            if let Ok((mapped_frame, _, tlb)) = pt.unmap(mapped_addr) {
                                tlb.flush();
                                if let Some(shared_frames) = shared_frames.as_ref() {
                                    if let Some(shared_frame) =
                                        shared_frames.lock().remove(&mapped_addr.as_usize())
                                    {
                                        dec_frame_ref(shared_frame);
                                    }
                                }
                                if let Some(pages) = pages.as_ref() {
                                    pages.lock().remove(&mapped_addr.as_usize());
                                }
                                dec_frame_ref(mapped_frame);
                            }
                        }
                        return false;
                    }
                } else {
                    let count = MAP_ALLOC_OOM_WARN_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                    if count <= MAP_ALLOC_OOM_WARN_BURST
                        || count % MAP_ALLOC_OOM_WARN_PERIOD == 0
                    {
                        warn!(
                            "map_alloc out of memory: addr={:#x} size={} [sampled count={}]",
                            addr, size, count
                        );
                    }
                    for &mapped_addr in &mapped {
                        if let Ok((mapped_frame, _, tlb)) = pt.unmap(mapped_addr) {
                            tlb.flush();
                            if let Some(shared_frames) = shared_frames.as_ref() {
                                if let Some(shared_frame) =
                                    shared_frames.lock().remove(&mapped_addr.as_usize())
                                {
                                    dec_frame_ref(shared_frame);
                                }
                            }
                            if let Some(pages) = pages.as_ref() {
                                pages.lock().remove(&mapped_addr.as_usize());
                            }
                            dec_frame_ref(mapped_frame);
                        }
                    }
                    return false;
                }
            }
            true
        } else {
            let _ = (start, size, flags, pt);
            true
        }
    }

    pub(crate) fn unmap_alloc(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
        _populate: bool,
    ) -> bool {
        debug!("unmap_alloc: [{:#x}, {:#x})", start, start + size);
        let pages = match self {
            Backend::Alloc { pages, .. } => Some(Arc::clone(pages)),
            _ => None,
        };
        if pages
            .as_ref()
            .is_some_and(|pages| pages.lock().is_empty())
        {
            return true;
        }
        let mut unmapped_frames = Vec::new();
        for addr in PageIter4K::new(start, start + size).unwrap() {
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                // Deallocate the physical frame if there is a mapping in the
                // page table.
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
                if let Some(pages) = pages.as_ref() {
                    pages.lock().remove(&addr.as_usize());
                }
                unmapped_frames.push(frame);
            } else {
                // Deallocation is needn't if the page is not mapped.
                if let Some(pages) = pages.as_ref() {
                    pages.lock().remove(&addr.as_usize());
                }
            }
        }
        dec_frame_refs(&unmapped_frames);
        true
    }

    pub(crate) fn handle_page_fault_alloc(
        &self,
        vaddr: VirtAddr,
        access_flags: MappingFlags,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        let page = vaddr.align_down_4k();
        let (shared_frames, pages) = match self {
            Backend::Alloc { shared, pages, .. } => (shared.clone(), Arc::clone(pages)),
            _ => return false,
        };
        if let Some(shared_frames) = shared_frames.as_ref() {
            if let Some(frame) = shared_frames.lock().get(&page.as_usize()).copied() {
                pages.lock().insert(page.as_usize(), frame);
                inc_frame_ref(frame);
                return install_page_mapping(pt, page, frame, orig_flags);
            }
        }
        if access_flags.contains(MappingFlags::WRITE) && orig_flags.contains(MappingFlags::WRITE) {
            if let Ok((old_paddr, cur_flags, _)) = pt.query(page) {
                if !cur_flags.is_empty() && !cur_flags.contains(MappingFlags::WRITE) {
                    let new_frame = match alloc_frame(false) {
                        Some(frame) => frame,
                        None => return false,
                    };
                    unsafe {
                        copy_kernel_bytes(
                            phys_to_virt(new_frame).as_mut_ptr(),
                            phys_to_virt(old_paddr.align_down_4k()).as_ptr(),
                            PAGE_SIZE_4K,
                        );
                    }
                    return if install_page_mapping(pt, page, new_frame, orig_flags) {
                        pages.lock().insert(page.as_usize(), new_frame);
                        dec_frame_ref(old_paddr.align_down_4k());
                        true
                    } else {
                        dec_frame_ref(new_frame);
                        false
                    };
                }
            }
        }

        if populate {
            false
        } else if let Some(frame) = alloc_frame(true) {
            if let Some(shared_frames) = shared_frames.as_ref() {
                shared_frames.lock().insert(page.as_usize(), frame);
                inc_frame_ref(frame);
            }
            pages.lock().insert(page.as_usize(), frame);
            // Allocate a physical frame lazily and map it to the fault address.
            install_page_mapping(pt, page, frame, orig_flags)
        } else {
            false
        }
    }

    pub(crate) fn map_cow(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        pages: &Arc<CowPageRegistry>,
    ) -> bool {
        let _ = (start, size, flags, pt, pages);
        true
    }

    pub(crate) fn unmap_cow(&self, start: VirtAddr, size: usize, pt: &mut PageTable) -> bool {
        let pages = match self {
            Backend::Cow { pages } => pages,
            _ => return false,
        };
        let mut unmapped_frames = Vec::new();
        for page_index in pages.page_indices() {
            let addr = start + (page_index * PAGE_SIZE_4K);
            if addr < start || addr >= start + size {
                continue;
            }
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
                unmapped_frames.push(frame);
            }
        }
        dec_frame_refs(&unmapped_frames);
        true
    }

    pub(crate) fn handle_page_fault_cow(
        &self,
        area_start: VirtAddr,
        vaddr: VirtAddr,
        access_flags: MappingFlags,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        pages: &Arc<CowPageRegistry>,
    ) -> bool {
        let page = vaddr.align_down_4k();
        let page_index = (page.as_usize().saturating_sub(area_start.as_usize())) / PAGE_SIZE_4K;
        let tracked_frame = pages.get_page(page_index);
        if let Ok((old_paddr, cur_flags, _)) = pt.query(page) {
            if cur_flags.is_empty() {
                let Some(frame) = alloc_frame(true) else {
                    warn!(
                        "handle_page_fault_cow alloc zeroed frame failed: page={:#x} available_pages={}",
                        page,
                        global_allocator().available_pages()
                    );
                    return false;
                };
                let ok = install_page_mapping(pt, page, frame, orig_flags);
                if ok {
                    pages.update_page(page_index, frame);
                    if orig_flags.contains(MappingFlags::WRITE) {
                        pages.mark_dirty(page_index);
                    }
                } else {
                    dec_frame_ref(frame);
                }
                return ok;
            }
            if !access_flags.contains(MappingFlags::WRITE)
                || !orig_flags.contains(MappingFlags::WRITE)
                || cur_flags.contains(MappingFlags::WRITE)
            {
                return false;
            }
            let new_frame = match alloc_frame(false) {
                Some(frame) => frame,
                None => {
                    warn!(
                        "handle_page_fault_cow alloc private frame failed: page={:#x} old_paddr={:#x} available_pages={}",
                        page,
                        old_paddr.align_down_4k(),
                        global_allocator().available_pages()
                    );
                    return false;
                }
            };
            unsafe {
                copy_kernel_bytes(
                    phys_to_virt(new_frame).as_mut_ptr(),
                    phys_to_virt(old_paddr.align_down_4k()).as_ptr(),
                    PAGE_SIZE_4K,
                );
            }
            if install_page_mapping(pt, page, new_frame, orig_flags) {
                pages.update_page(page_index, new_frame);
                pages.mark_dirty(page_index);
                dec_frame_ref(old_paddr.align_down_4k());
                true
            } else {
                warn!(
                    "handle_page_fault_cow remap failed: page={:#x} new_frame={:#x} old_paddr={:#x} orig_flags={:?}",
                    page,
                    new_frame,
                    old_paddr.align_down_4k(),
                    orig_flags
                );
                dec_frame_ref(new_frame);
                false
            }
        } else if let Some(old_frame) = tracked_frame {
            if access_flags.contains(MappingFlags::WRITE) && orig_flags.contains(MappingFlags::WRITE)
            {
                let Some(new_frame) = alloc_frame(false) else {
                    warn!(
                        "handle_page_fault_cow alloc private frame failed: page={:#x} old_paddr={:#x} available_pages={}",
                        page,
                        old_frame,
                        global_allocator().available_pages()
                    );
                    return false;
                };
                unsafe {
                    copy_kernel_bytes(
                        phys_to_virt(new_frame).as_mut_ptr(),
                        phys_to_virt(old_frame.align_down_4k()).as_ptr(),
                        PAGE_SIZE_4K,
                    );
                }
                if install_page_mapping(pt, page, new_frame, orig_flags) {
                    pages.update_page(page_index, new_frame);
                    pages.mark_dirty(page_index);
                    dec_frame_ref(old_frame.align_down_4k());
                    true
                } else {
                    dec_frame_ref(new_frame);
                    false
                }
            } else {
                inc_frame_ref(old_frame);
                if install_page_mapping(pt, page, old_frame, orig_flags & !MappingFlags::WRITE) {
                    true
                } else {
                    dec_frame_ref(old_frame);
                    false
                }
            }
        } else {
            let Some(frame) = alloc_frame(true) else {
                warn!(
                    "handle_page_fault_cow alloc missing-page frame failed: page={:#x} available_pages={}",
                    page,
                    global_allocator().available_pages()
                );
                return false;
            };
            if install_page_mapping(pt, page, frame, orig_flags) {
                pages.update_page(page_index, frame);
                if orig_flags.contains(MappingFlags::WRITE) {
                    pages.mark_dirty(page_index);
                }
                true
            } else {
                warn!(
                    "handle_page_fault_cow map missing-page failed: page={:#x} frame={:#x} orig_flags={:?}",
                    page,
                    frame,
                    orig_flags
                );
                dec_frame_ref(frame);
                false
            }
        }
    }

    pub(crate) fn map_shared(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        frames: &Arc<SharedPageRegistry>,
    ) -> bool {
        let _ = (start, size, flags, pt, frames);
        true
    }

    pub(crate) fn unmap_shared(&self, start: VirtAddr, size: usize, pt: &mut PageTable) -> bool {
        let frames = match self {
            Backend::Shared { frames } => frames,
            _ => return false,
        };
        let snapshot: Vec<usize> = frames.lock().keys().copied().collect();
        let mut unmapped_frames = Vec::new();
        for page_addr in snapshot {
            let addr = VirtAddr::from_usize(page_addr);
            if addr < start || addr >= start + size {
                continue;
            }
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
                unmapped_frames.push(frame);
            }
        }
        dec_frame_refs(&unmapped_frames);
        true
    }

    pub(crate) fn handle_page_fault_shared(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        frames: &Arc<SharedPageRegistry>,
    ) -> bool {
        let page = vaddr.align_down_4k();
        if let Some(frame) = frames.lock().get(&page.as_usize()).copied() {
            inc_frame_ref(frame);
            if install_page_mapping(pt, page, frame, orig_flags) {
                return true;
            }
            dec_frame_ref(frame);
            return false;
        }
        if let Some(frame) = alloc_frame(true) {
            frames.lock().insert(page.as_usize(), frame);
            inc_frame_ref(frame);
            if install_page_mapping(pt, page, frame, orig_flags) {
                true
            } else {
                frames.lock().remove(&page.as_usize());
                dec_frame_ref(frame);
                dec_frame_ref(frame);
                false
            }
        } else {
            false
        }
    }

    pub(crate) fn handle_page_fault_segment_shared(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        area_start: VirtAddr,
        frames: &Arc<SharedFrames>,
    ) -> bool {
        let page = vaddr.align_down_4k();
        let Some(page_offset) = page.as_usize().checked_sub(area_start.as_usize()) else {
            return false;
        };
        let page_index = page_offset / PAGE_SIZE_4K;
        let Some(frame) = frames.get(page_index) else {
            return false;
        };
        inc_frame_ref(frame);
        if install_page_mapping(pt, page, frame, orig_flags) {
            true
        } else {
            dec_frame_ref(frame);
            false
        }
    }

    pub(crate) fn map_segment_shared(
        &self,
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        frames: &Arc<SharedFrames>,
    ) -> bool {
        if frames.len() * PAGE_SIZE_4K != size {
            warn!(
                "map_segment_shared size mismatch: start={:#x} size={} frames={}",
                start,
                size,
                frames.len()
            );
            return false;
        }
        let _ = (start, flags, pt);
        true
    }

    pub(crate) fn unmap_segment_shared(
        &self,
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
    ) -> bool {
        let frames = match self {
            Backend::SegmentShared { frames } => frames,
            _ => return false,
        };
        let mut unmapped_frames = Vec::new();
        for (index, _) in frames.iter().enumerate() {
            let addr = start + index * PAGE_SIZE_4K;
            if addr >= start + size {
                break;
            }
            if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                if page_size.is_huge() {
                    return false;
                }
                tlb.flush();
                unmapped_frames.push(frame);
            }
        }
        dec_frame_refs(&unmapped_frames);
        true
    }
}
