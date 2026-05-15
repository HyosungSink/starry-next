use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use arceos_posix_api::FileLike;
use axerrno::LinuxError;
use axhal::mem::phys_to_virt;
use axhal::paging::MappingFlags;
#[cfg(feature = "contest_diag_logs")]
use axhal::time::monotonic_time_nanos;
use axmm::{alloc_user_frame, SharedFrames};
use axtask::{current, TaskExtRef};
use core::sync::atomic::AtomicBool;
#[cfg(target_arch = "riscv64")]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_arch = "loongarch64")]
use core::sync::atomic::{AtomicUsize, Ordering};
use memory_addr::{PageIter4K, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};
use spin::{Mutex, Once};

use crate::syscall_body;

static LARGE_LIBCBENCH_MMAP_LOGGED: AtomicBool = AtomicBool::new(false);

fn checked_align_up_4k(value: usize) -> Result<usize, LinuxError> {
    value
        .checked_add(PAGE_SIZE_4K - 1)
        .map(memory_addr::align_down_4k)
        .ok_or(LinuxError::EINVAL)
}

fn trace_mremap_case(exec_path: &str) -> bool {
    exec_path.contains("/mremap0") || exec_path.starts_with("mremap0")
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SharedFileMappingKey {
    path: String,
    offset: usize,
    length: usize,
}

fn shared_file_mapping_registry(
) -> &'static Mutex<BTreeMap<SharedFileMappingKey, Arc<SharedFrames>>> {
    static REGISTRY: Once<Mutex<BTreeMap<SharedFileMappingKey, Arc<SharedFrames>>>> = Once::new();
    REGISTRY.call_once(|| Mutex::new(BTreeMap::new()))
}

fn shared_file_mapping_frames(
    file: &arceos_posix_api::File,
    offset: usize,
    length: usize,
) -> Result<Arc<SharedFrames>, LinuxError> {
    let key = SharedFileMappingKey {
        path: file.path().to_string(),
        offset,
        length,
    };

    if let Some(frames) = shared_file_mapping_registry().lock().get(&key).cloned() {
        return Ok(frames);
    }

    let file_size = file.stat()?.st_size as usize;
    let page_count = length / PAGE_SIZE_4K;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(page_count)
        .map_err(|_| LinuxError::ENOMEM)?;
    let mut file_handle = file.inner().lock();

    for page_index in 0..page_count {
        let frame = alloc_user_frame(true).ok_or(LinuxError::ENOMEM)?;
        let page_file_offset = offset + page_index * PAGE_SIZE_4K;
        if page_file_offset < file_size {
            let available = core::cmp::min(PAGE_SIZE_4K, file_size - page_file_offset);
            let mut read = 0usize;
            let dst = unsafe {
                core::slice::from_raw_parts_mut(phys_to_virt(frame).as_mut_ptr(), available)
            };
            while read < available {
                let n = file_handle.read_at((page_file_offset + read) as u64, &mut dst[read..])?;
                if n == 0 {
                    break;
                }
                read += n;
            }
        }
        frames.push(frame);
    }

    let frames = Arc::new(SharedFrames::new(frames));
    let mut registry = shared_file_mapping_registry().lock();
    if let Some(existing) = registry.get(&key).cloned() {
        drop(registry);
        drop(frames);
        return Ok(existing);
    }
    registry.insert(key, frames.clone());
    Ok(frames)
}

#[cfg(target_arch = "loongarch64")]
fn should_trace_loongarch_libcbench_mm() -> bool {
    false
}

#[cfg(target_arch = "loongarch64")]
fn take_loongarch_libcbench_mm_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < limit
}

#[cfg(target_arch = "riscv64")]
fn should_trace_riscv_libcbench_mm() -> bool {
    false
}

#[cfg(target_arch = "riscv64")]
fn take_riscv_libcbench_mm_trace_slot(limit: usize) -> bool {
    static TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);
    TRACE_COUNT.fetch_add(1, Ordering::Relaxed) < limit
}

bitflags::bitflags! {
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    #[derive(Debug)]
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
        const PROT_EXEC = 1 << 2;
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct MsyncFlags: i32 {
        const MS_ASYNC = 1 << 0;
        const MS_INVALIDATE = 1 << 1;
        const MS_SYNC = 1 << 2;
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct MremapFlags: i32 {
        const MAYMOVE = 1 << 0;
        const FIXED = 1 << 1;
        const DONTUNMAP = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            // RISC-V leaf PTEs cannot be writable without also being readable.
            // Linux also commonly treats writable user mappings as readable.
            flags |= MappingFlags::READ;
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    #[derive(Debug)]
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

pub(crate) fn sys_mmap(
    mut addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: isize,
) -> usize {
    syscall_body!(sys_mmap, {
        let curr = current();
        let curr_ext = curr.task_ext();
        let exec_path = curr_ext.exec_path();
        let trace_mremap = trace_mremap_case(exec_path.as_str());
        let trace_alloc =
            curr.name().contains("la_meta_dump") || curr.name().contains("la_sparse_debug2");
        #[cfg(target_arch = "loongarch64")]
        let trace_libcbench =
            should_trace_loongarch_libcbench_mm() && take_loongarch_libcbench_mm_trace_slot(128);
        #[cfg(target_arch = "riscv64")]
        let trace_libcbench = curr_ext.exec_path().contains("libc-bench")
            && should_trace_riscv_libcbench_mm()
            && take_riscv_libcbench_mm_trace_slot(256);
        if curr_ext.exec_path().contains("libc-bench")
            && length >= (1 << 20)
            && !LARGE_LIBCBENCH_MMAP_LOGGED.swap(true, Ordering::Relaxed)
        {
            warn!(
                "[libcbench-large-mmap] task={} req_addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={} off={}",
                curr.id_name(),
                addr as usize,
                length,
                prot,
                flags,
                fd,
                offset
            );
        }
        let mut aspace = curr_ext.aspace.lock();
        let permission_flags = MmapProt::from_bits_truncate(prot);
        // TODO: check illegal flags for mmap
        // An example is the flags contained none of MAP_PRIVATE, MAP_SHARED, or MAP_SHARED_VALIDATE.
        let map_flags = MmapFlags::from_bits_truncate(flags);
        let requested_addr = addr as usize;
        let mut aligned_length = length;

        if addr.is_null() {
            aligned_length = checked_align_up_4k(aligned_length)?;
        } else {
            let start = addr as usize;
            let aligned_start = memory_addr::align_down_4k(start);
            let end = start
                .checked_add(aligned_length)
                .ok_or(LinuxError::EINVAL)?;
            let aligned_end = checked_align_up_4k(end)?;
            if aligned_end < aligned_start {
                return Err(LinuxError::EINVAL);
            }
            addr = aligned_start as *mut usize;
            aligned_length = aligned_end - aligned_start;
        }

        let search_hint = if addr.is_null() {
            let heap_top = curr_ext.get_heap_top() as usize;
            let default_base = heap_top.saturating_add(0x4000_0000);
            VirtAddr::from(memory_addr::align_up_4k(default_base))
        } else {
            VirtAddr::from(addr as usize)
        };

        let start_addr = if map_flags.contains(MmapFlags::MAP_FIXED) {
            VirtAddr::from(addr as usize)
        } else {
            aspace
                .find_free_area(
                    search_hint,
                    aligned_length,
                    VirtAddrRange::new(aspace.base(), aspace.end()),
                )
                .or(aspace.find_free_area(
                    aspace.base(),
                    aligned_length,
                    VirtAddrRange::new(aspace.base(), aspace.end()),
                ))
                .ok_or(LinuxError::ENOMEM)?
        };
        if trace_mremap {
            warn!(
                "[mremap-mmap-plan] task={} req_addr={:#x} len={:#x} aligned_len={:#x} search_hint={:#x} start={:#x} heap_top={:#x} fd={} flags={:#x} prot={:#x}",
                curr.id_name(),
                requested_addr,
                length,
                aligned_length,
                search_hint.as_usize(),
                start_addr.as_usize(),
                curr_ext.get_heap_top() as usize,
                fd,
                flags,
                prot,
            );
        }

        let file_backed = fd != -1 && !map_flags.contains(MmapFlags::MAP_ANONYMOUS);
        let populate = false;

        if map_flags.contains(MmapFlags::MAP_FIXED) {
            let _ = aspace.unmap(start_addr, aligned_length);
        }

        let mut shared_file_frames = None;
        if file_backed && map_flags.contains(MmapFlags::MAP_SHARED) {
            if offset < 0 {
                return Err(LinuxError::EINVAL);
            }
            let offset = offset as usize;
            if offset % memory_addr::PAGE_SIZE_4K != 0 {
                return Err(LinuxError::EINVAL);
            }
            let file_like = arceos_posix_api::get_file_like(fd)?;
            let file = file_like
                .into_any()
                .downcast::<arceos_posix_api::File>()
                .map_err(|_| LinuxError::EBADF)?;
            shared_file_frames = Some(shared_file_mapping_frames(&file, offset, aligned_length)?);
        }

        if let Some(frames) = shared_file_frames.clone() {
            aspace.map_shared_frames(
                start_addr,
                aligned_length,
                permission_flags.into(),
                frames,
            )?;
        } else if map_flags.contains(MmapFlags::MAP_SHARED) {
            aspace.map_alloc_shared(
                start_addr,
                aligned_length,
                permission_flags.into(),
                populate,
            )?;
        } else {
            aspace.map_alloc(
                start_addr,
                aligned_length,
                permission_flags.into(),
                populate,
            )?;
        }
        if trace_alloc {
            warn!(
                "mmap task={} req_addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={} off={} -> start={:#x} aligned_len={:#x} populate={}",
                curr.id_name(),
                addr as usize,
                length,
                prot,
                flags,
                fd,
                offset,
                start_addr.as_usize(),
                aligned_length,
                populate
            );
        }
        #[cfg(target_arch = "loongarch64")]
        if trace_libcbench {
            warn!(
                "[la-libcbench-mmap] task={} req_addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={} off={} -> start={:#x} aligned_len={:#x} populate={} heap_top={:#x}",
                curr.id_name(),
                addr as usize,
                length,
                prot,
                flags,
                fd,
                offset,
                start_addr.as_usize(),
                aligned_length,
                populate,
                curr_ext.get_heap_top() as usize
            );
        }
        #[cfg(target_arch = "riscv64")]
        if trace_libcbench {
            warn!(
                "[rv-libcbench-mmap] task={} req_addr={:#x} len={:#x} prot={:#x} flags={:#x} fd={} off={} -> start={:#x} aligned_len={:#x} populate={} heap_top={:#x}",
                curr.id_name(),
                addr as usize,
                length,
                prot,
                flags,
                fd,
                offset,
                start_addr.as_usize(),
                aligned_length,
                populate,
                curr_ext.get_heap_top() as usize
            );
        }

        if file_backed && shared_file_frames.is_none() {
            let file_like = arceos_posix_api::get_file_like(fd)?;
            let file_size = file_like.stat()?.st_size as usize;
            if offset < 0 {
                return Err(LinuxError::EINVAL);
            }
            let offset = offset as usize;
            if offset % memory_addr::PAGE_SIZE_4K != 0 {
                return Err(LinuxError::EINVAL);
            }
            let addr_bias = if map_flags.contains(MmapFlags::MAP_FIXED) {
                requested_addr.saturating_sub(start_addr.as_usize())
            } else {
                0
            };
            let copy_start = start_addr + addr_bias;
            let copy_len = aligned_length.saturating_sub(addr_bias);
            let length = core::cmp::min(copy_len, file_size.saturating_sub(offset));
            const MMAP_POPULATE_CHUNK: usize = 64 * 1024;
            let mut copied = 0usize;
            let buf_len = core::cmp::min(length.max(1), MMAP_POPULATE_CHUNK);
            let mut buf = Vec::new();
            buf.try_reserve_exact(buf_len)
                .map_err(|_| LinuxError::ENOMEM)?;
            buf.resize(buf_len, 0);
            while copied < length {
                let chunk_len = core::cmp::min(buf.len(), length - copied);
                let slice = &mut buf[..chunk_len];
                let mut read = 0usize;
                while read < chunk_len {
                    let n =
                        file_like.read_at((offset + copied + read) as u64, &mut slice[read..])?;
                    if n == 0 {
                        break;
                    }
                    read += n;
                }
                if read == 0 {
                    break;
                }
                aspace.write(copy_start + copied, &slice[..read])?;
                copied += read;
            }
        }
        axhal::arch::flush_tlb(None);
        if trace_mremap {
            warn!(
                "[mremap-mmap-ok] task={} start={:#x} len={:#x} file_backed={} shared={} populate={}",
                curr.id_name(),
                start_addr.as_usize(),
                aligned_length,
                file_backed,
                map_flags.contains(MmapFlags::MAP_SHARED),
                populate,
            );
        }
        Ok(start_addr.as_usize())
    })
}

pub(crate) fn sys_munmap(addr: *mut usize, mut length: usize) -> i32 {
    syscall_body!(sys_munmap, {
        let curr = current();
        let trace_mremap = trace_mremap_case(curr.task_ext().exec_path().as_str());
        let trace_alloc =
            curr.name().contains("la_meta_dump") || curr.name().contains("la_sparse_debug2");
        if trace_mremap {
            warn!(
                "[mremap-munmap-enter] task={} addr={:#x} len={:#x}",
                curr.id_name(),
                addr as usize,
                length,
            );
        }
        #[cfg(target_arch = "loongarch64")]
        let trace_libcbench =
            should_trace_loongarch_libcbench_mm() && take_loongarch_libcbench_mm_trace_slot(128);
        if length == 0 {
            return Ok(0);
        }
        let start = addr as usize;
        let end = start.checked_add(length).ok_or(LinuxError::EINVAL)?;
        let aligned_start = memory_addr::align_down_4k(start);
        let aligned_end = memory_addr::align_up_4k(end);
        length = aligned_end.saturating_sub(aligned_start);
        if length == 0 {
            return Ok(0);
        }

        let curr_ext = curr.task_ext();
        #[cfg(feature = "contest_diag_logs")]
        if curr.name().contains("userboot") {
            let trap =
                crate::task::read_trapframe_from_kstack(curr.get_kernel_stack_top().unwrap());
            crate::diag_warn!(
                "munmap task={} addr={:#x} len={:#x} aligned=[{:#x},{:#x}) sp={:#x} heap_top={:#x} now_ms={}",
                curr.id_name(),
                start,
                end - start,
                aligned_start,
                aligned_end,
                trap.get_sp(),
                curr_ext.get_heap_top() as usize,
                monotonic_time_nanos() / 1_000_000
            );
        }

        let mut aspace = curr_ext.aspace.lock();
        aspace.unmap(VirtAddr::from(aligned_start), length)?;
        if trace_mremap {
            warn!(
                "[mremap-munmap-ok] task={} aligned=[{:#x},{:#x})",
                curr.id_name(),
                aligned_start,
                aligned_end,
            );
        }
        if trace_alloc {
            warn!(
                "munmap task={} addr={:#x} len={:#x} aligned=[{:#x},{:#x})",
                curr.id_name(),
                start,
                end - start,
                aligned_start,
                aligned_end
            );
        }
        #[cfg(target_arch = "loongarch64")]
        if trace_libcbench {
            warn!(
                "[la-libcbench-munmap] task={} addr={:#x} len={:#x} aligned=[{:#x},{:#x}) heap_top={:#x}",
                curr.id_name(),
                start,
                end - start,
                aligned_start,
                aligned_end,
                curr_ext.get_heap_top() as usize
            );
        }
        axhal::arch::flush_tlb(None);
        Ok(0)
    })
}

pub(crate) fn sys_mprotect(addr: *mut usize, length: usize, prot: i32) -> i32 {
    syscall_body!(sys_mprotect, {
        let curr = current();
        let trace_alloc =
            curr.name().contains("la_meta_dump") || curr.name().contains("la_sparse_debug2");
        if length == 0 {
            return Ok(0);
        }

        let start = addr as usize;
        let end = start.checked_add(length).ok_or(LinuxError::EINVAL)?;
        let aligned_start = memory_addr::align_down_4k(start);
        let aligned_end = memory_addr::align_up_4k(end);

        let curr_ext = curr.task_ext();
        let mut aspace = curr_ext.aspace.lock();
        aspace.protect(
            VirtAddr::from(aligned_start),
            aligned_end - aligned_start,
            MmapProt::from_bits_truncate(prot).into(),
        )?;
        if trace_alloc {
            warn!(
                "mprotect task={} addr={:#x} len={:#x} prot={:#x} aligned=[{:#x},{:#x})",
                curr.id_name(),
                start,
                length,
                prot,
                aligned_start,
                aligned_end
            );
        }
        axhal::arch::flush_tlb(None);
        Ok(0)
    })
}

pub(crate) fn sys_msync(addr: *mut usize, length: usize, flags: i32) -> i32 {
    syscall_body!(sys_msync, {
        let curr = current();
        let trace_mremap = trace_mremap_case(curr.task_ext().exec_path().as_str());
        if trace_mremap {
            warn!(
                "[mremap-msync-enter] task={} addr={:#x} len={:#x} flags={:#x}",
                curr.id_name(),
                addr as usize,
                length,
                flags,
            );
        }
        if length == 0 {
            return Ok(0);
        }
        let start = addr as usize;
        if start % PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        let end = memory_addr::align_up_4k(start.checked_add(length).ok_or(LinuxError::EINVAL)?);
        let mut aspace = curr.task_ext().aspace.lock();
        if !aspace.contains_range(VirtAddr::from(start), end - start) {
            return Err(LinuxError::ENOMEM);
        }
        let msync_flags = MsyncFlags::from_bits_truncate(flags);
        if msync_flags.contains(MsyncFlags::MS_INVALIDATE) {
            aspace.invalidate_shared_range(VirtAddr::from(start), end - start)?;
            axhal::arch::flush_tlb(None);
        }
        if trace_mremap {
            warn!(
                "[mremap-msync-ok] task={} start={:#x} len={:#x} invalidate={}",
                curr.id_name(),
                start,
                end - start,
                msync_flags.contains(MsyncFlags::MS_INVALIDATE),
            );
        }
        Ok(0)
    })
}

pub(crate) fn sys_mremap(
    old_addr: *mut usize,
    old_size: usize,
    new_size: usize,
    flags: i32,
    new_addr: *mut usize,
) -> usize {
    syscall_body!(sys_mremap, {
        let curr = current();
        let curr_ext = curr.task_ext();
        let trace_mremap = trace_mremap_case(curr_ext.exec_path().as_str());
        if trace_mremap {
            warn!(
                "[mremap-enter] task={} old_addr={:#x} old_size={:#x} new_size={:#x} flags={:#x} new_addr={:#x}",
                curr.id_name(),
                old_addr as usize,
                old_size,
                new_size,
                flags,
                new_addr as usize,
            );
        }
        let remap_flags = MremapFlags::from_bits_truncate(flags);
        if remap_flags.contains(MremapFlags::DONTUNMAP)
            || flags
                & !((MremapFlags::MAYMOVE | MremapFlags::FIXED | MremapFlags::DONTUNMAP).bits())
                != 0
        {
            return Err(LinuxError::EINVAL);
        }
        if old_size == 0 || new_size == 0 {
            return Err(LinuxError::EINVAL);
        }
        let old_start = old_addr as usize;
        if old_start % PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }
        if remap_flags.contains(MremapFlags::FIXED) && !remap_flags.contains(MremapFlags::MAYMOVE) {
            return Err(LinuxError::EINVAL);
        }

        let old_len = memory_addr::align_up_4k(old_size);
        let new_len = memory_addr::align_up_4k(new_size);
        let fixed_requested = remap_flags.contains(MremapFlags::FIXED);
        let requested_fixed_addr = if fixed_requested {
            let requested = new_addr as usize;
            if requested % PAGE_SIZE_4K != 0 {
                return Err(LinuxError::EINVAL);
            }
            Some(requested)
        } else {
            None
        };
        if old_len == new_len && !fixed_requested {
            return Ok(old_start);
        }

        let mut aspace = curr_ext.aspace.lock();
        let old_start_va = VirtAddr::from(old_start);
        let old_end_va = old_start_va + old_len;
        let old_flags = aspace
            .area_flags_for_range(old_start_va, old_len)
            .ok_or(LinuxError::EFAULT)?;

        if new_len < old_len {
            aspace.unmap(old_start_va + new_len, old_len - new_len)?;
            axhal::arch::flush_tlb(None);
            return Ok(old_start);
        }

        let extra_len = new_len - old_len;
        let can_extend = !fixed_requested
            && memory_addr::is_aligned_4k(extra_len)
            && aspace.contains_range(old_end_va, extra_len)
            && PageIter4K::new(old_end_va, old_end_va + extra_len)
                .ok_or(LinuxError::ENOMEM)?
                .all(|page| {
                    matches!(
                        aspace.page_table().query(page),
                        Ok((_paddr, flags, _)) if flags.is_empty()
                    ) || aspace.page_table().query(page).is_err()
                });
        if trace_mremap {
            warn!(
                "[mremap-plan] task={} old=[{:#x},{:#x}) new_len={:#x} extra_len={:#x} can_extend={} maymove={} fixed={}",
                curr.id_name(),
                old_start,
                old_start + old_len,
                new_len,
                extra_len,
                can_extend,
                remap_flags.contains(MremapFlags::MAYMOVE),
                remap_flags.contains(MremapFlags::FIXED),
            );
        }
        if can_extend {
            aspace.map_alloc(old_end_va, extra_len, old_flags, false)?;
            axhal::arch::flush_tlb(None);
            if trace_mremap {
                warn!(
                    "[mremap-extend-ok] task={} start={:#x} old_len={:#x} new_len={:#x}",
                    curr.id_name(),
                    old_start,
                    old_len,
                    new_len,
                );
            }
            return Ok(old_start);
        }

        if !remap_flags.contains(MremapFlags::MAYMOVE) {
            return Err(LinuxError::ENOMEM);
        }

        let new_start_va = if let Some(requested) = requested_fixed_addr {
            let requested_end = requested.checked_add(new_len).ok_or(LinuxError::EINVAL)?;
            let old_end = old_start.checked_add(old_len).ok_or(LinuxError::EINVAL)?;
            if requested < old_end && old_start < requested_end {
                return Err(LinuxError::EINVAL);
            }
            let requested_va = VirtAddr::from(requested);
            if !aspace.contains_range(requested_va, new_len) {
                return Err(LinuxError::ENOMEM);
            }
            let _ = aspace.unmap(requested_va, new_len);
            requested_va
        } else {
            aspace
                .find_free_area(
                    old_end_va,
                    new_len,
                    VirtAddrRange::new(aspace.base(), aspace.end()),
                )
                .or(aspace.find_free_area(
                    aspace.base(),
                    new_len,
                    VirtAddrRange::new(aspace.base(), aspace.end()),
                ))
                .ok_or(LinuxError::ENOMEM)?
        };

        aspace.map_alloc(new_start_va, new_len, old_flags, false)?;
        const COPY_CHUNK: usize = 64 * 1024;
        let mut copied = 0usize;
        let mut buffer = vec![0u8; COPY_CHUNK.min(old_len.max(1))];
        while copied < old_len {
            let chunk = buffer.len().min(old_len - copied);
            aspace.read(old_start_va + copied, &mut buffer[..chunk])?;
            aspace.write(new_start_va + copied, &buffer[..chunk])?;
            copied += chunk;
        }
        aspace.unmap(old_start_va, old_len)?;
        axhal::arch::flush_tlb(None);
        if trace_mremap {
            warn!(
                "[mremap-move-ok] task={} old=[{:#x},{:#x}) new=[{:#x},{:#x}) copied={:#x}",
                curr.id_name(),
                old_start,
                old_start + old_len,
                new_start_va.as_usize(),
                new_start_va.as_usize() + new_len,
                copied,
            );
        }
        Ok(new_start_va.as_usize())
    })
}
