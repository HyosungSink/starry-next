use core::{
    str::from_utf8,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{
    collections::vec_deque::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use axalloc::global_allocator;
use axerrno::{AxError, AxResult};
use axfs::api::File;
use axhal::{
    mem::phys_to_virt,
    paging::MappingFlags,
    trap::{register_trap_handler, PAGE_FAULT},
};
use axstd::io::Read;
use axsync::Mutex;

use axmm::{alloc_user_frame, AddrSpace, SharedFrames};
use axtask::{current, TaskExtRef};
use kernel_elf_parser::{app_stack_region, AuxvEntry, AuxvType, ELFParser};
use memory_addr::{MemoryAddr, PageIter4K, VirtAddr, PAGE_SIZE_4K};
use spin::Once;
use xmas_elf::{
    program::{ProgramHeader, SegmentData},
    ElfFile,
};

use crate::embedded_runtime::MUSL_INTERP_BYTES;

const EXEC_IMAGE_CACHE_MAX_ENTRIES: usize = 8;
const EXEC_SEGMENT_CACHE_MAX_ENTRIES: usize = 32;
const EXEC_IMAGE_CACHE_MAX_FILE_SIZE: usize = 16 * 1024 * 1024;
const EXEC_IMAGE_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;
const EXEC_SEGMENT_CACHE_MAX_BYTES: usize = 16 * 1024 * 1024;
const ONLINE_INTERP_DIAG_LOG_LIMIT: usize = 24;
const ONLINE_LOAD_DIAG_LOG_LIMIT: usize = 32;
#[cfg(target_arch = "loongarch64")]
const ONLINE_BASIC_LA_FAULT_LOG_LIMIT: usize = 32;
const MPROTECT02_FAULT_LOG_LIMIT: usize = 64;
const MREMAP_FAULT_LOG_LIMIT: usize = 96;
const MAP_ALLOC_FAIL_LOG_BURST: usize = 4;
const MAP_ALLOC_FAIL_LOG_PERIOD: usize = 64;
#[cfg(target_arch = "riscv64")]
const USER_TLS_PRE_TCB_SIZE: usize = 1888;
#[cfg(target_arch = "loongarch64")]
const USER_TLS_PRE_TCB_SIZE: usize = PAGE_SIZE_4K;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const USER_TLS_TCBHEAD_SIZE: usize = 2 * core::mem::size_of::<usize>();
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const USER_TLS_DTV_ENTRY_SIZE: usize = 2 * core::mem::size_of::<usize>();
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const USER_TLS_DTV_SLOTS: usize = 4;
#[cfg(target_arch = "riscv64")]
const USER_TLS_DTV_OFFSET_BIAS: usize = 0x800;
#[cfg(target_arch = "loongarch64")]
const USER_TLS_DTV_OFFSET_BIAS: usize = 0;
#[cfg(target_arch = "riscv64")]
const USER_TLS_BLOCK_OFFSET: usize = USER_TLS_PRE_TCB_SIZE;
#[cfg(target_arch = "loongarch64")]
const USER_TLS_BLOCK_OFFSET: usize = USER_TLS_PRE_TCB_SIZE + USER_TLS_TCBHEAD_SIZE;
const USER_PIE_MIN_BIAS: usize = PAGE_SIZE_4K;

static ONLINE_INTERP_DIAG_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static ONLINE_LOAD_DIAG_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_arch = "loongarch64")]
static ONLINE_BASIC_LA_FAULT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static MPROTECT02_FAULT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static MREMAP_FAULT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static MAP_ALLOC_FAIL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn should_trace_clone08() -> bool {
    false
}

struct ElfTlsInfo {
    image: Vec<u8>,
    mem_size: usize,
    align: usize,
    vaddr: usize,
    layout: InitialTlsLayout,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InitialTlsLayout {
    Generic,
    Musl,
}

fn take_diag_slot(counter: &AtomicUsize, limit: usize) -> Option<usize> {
    let slot = counter.fetch_add(1, Ordering::Relaxed);
    (slot < limit).then_some(slot + 1)
}

fn should_trace_mprotect02_fault(exec_path: &str) -> bool {
    exec_path.ends_with("/mprotect02") || exec_path == "mprotect02"
}

fn should_trace_mremap_fault(exec_path: &str) -> bool {
    exec_path.contains("/mremap0") || exec_path.starts_with("mremap0")
}

fn should_trace_online_loader(program_path: &str) -> bool {
    let cwd = axfs::api::current_dir().ok();
    program_path.contains("/libctest/")
        || cwd.as_deref().is_some_and(|cwd| cwd.contains("/libctest"))
        || program_path.ends_with("entry-static.exe")
        || program_path.ends_with("entry-dynamic.exe")
}

fn runtime_exec_cache_low_watermark_pages() -> usize {
    let total_pages = axconfig::plat::PHYS_MEMORY_SIZE / PAGE_SIZE_4K;
    total_pages.div_ceil(32).clamp(4096, 16384)
}

fn should_admit_exec_image_cache_entry() -> bool {
    global_allocator().available_pages() > runtime_exec_cache_low_watermark_pages()
}

fn should_admit_exec_segment_cache_entry() -> bool {
    let low_watermark = runtime_exec_cache_low_watermark_pages();
    global_allocator().available_pages() > low_watermark.saturating_div(4).max(1024)
}

fn should_log_map_alloc_failure() -> Option<usize> {
    let count = MAP_ALLOC_FAIL_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= MAP_ALLOC_FAIL_LOG_BURST || count % MAP_ALLOC_FAIL_LOG_PERIOD == 0 {
        Some(count)
    } else {
        None
    }
}

fn env_value<'a>(env: &'a [String], key: &str) -> Option<&'a str> {
    env.iter().find_map(|entry| {
        entry
            .strip_prefix(key)
            .and_then(|suffix| suffix.strip_prefix('='))
    })
}

fn auxv_value(auxv: &[AuxvEntry], ty: AuxvType) -> usize {
    auxv.iter()
        .find(|entry| entry.get_type() == ty)
        .map(|entry| entry.value())
        .unwrap_or(0)
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn tls_layout_name(layout: InitialTlsLayout) -> &'static str {
    match layout {
        InitialTlsLayout::Generic => "generic",
        InitialTlsLayout::Musl => "musl",
    }
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn tls_info_summary(tls: Option<&ElfTlsInfo>) -> String {
    match tls {
        Some(tls) => alloc::format!(
            "mem={} image={} align={} vaddr={:#x} layout={}",
            tls.mem_size,
            tls.image.len(),
            tls.align,
            tls.vaddr,
            tls_layout_name(tls.layout)
        ),
        None => "none".into(),
    }
}

fn log_online_load_diag(
    program_path: &str,
    env: &[String],
    entry: VirtAddr,
    user_sp: VirtAddr,
    heap_bottom: VirtAddr,
    user_tp: usize,
    auxv: &[AuxvEntry],
) {
    if !should_trace_online_loader(program_path) {
        return;
    }
    let Some(slot) = take_diag_slot(&ONLINE_LOAD_DIAG_LOG_COUNT, ONLINE_LOAD_DIAG_LOG_LIMIT) else {
        return;
    };

    let cwd = axfs::api::current_dir().unwrap_or_else(|_| "/".into());
    let locale_prefix = runtime_search_prefixes(program_path)
        .into_iter()
        .find(|prefix| {
            axfs::api::absolute_path_exists(alloc::format!("{prefix}/usr/lib/locale").as_str())
                || axfs::api::absolute_path_exists(alloc::format!("{prefix}/lib/locale").as_str())
        })
        .unwrap_or_else(|| "/".into());
    let locale_archive = if locale_prefix == "/" {
        "/usr/lib/locale/locale-archive".into()
    } else {
        alloc::format!("{locale_prefix}/usr/lib/locale/locale-archive")
    };
    let c_utf8 = if locale_prefix == "/" {
        "/usr/lib/locale/C.UTF-8/LC_CTYPE".into()
    } else {
        alloc::format!("{locale_prefix}/usr/lib/locale/C.UTF-8/LC_CTYPE")
    };
    let c_dot_utf8 = if locale_prefix == "/" {
        "/usr/lib/locale/C.utf8/LC_CTYPE".into()
    } else {
        alloc::format!("{locale_prefix}/usr/lib/locale/C.utf8/LC_CTYPE")
    };

    warn!(
        "[online-load:{}] program_path={} cwd={} entry={:#x} user_sp={:#x} heap_bottom={:#x} user_tp={:#x} phdr={:#x} phent={} phnum={} base={:#x} LC_ALL={} LANG={} LC_CTYPE={} LOCPATH={} LIBRARY_PATH={} LD_LIBRARY_PATH={} locale_archive={}({}) c_utf8={}({}) c_dot_utf8={}({})",
        slot,
        program_path,
        cwd,
        entry.as_usize(),
        user_sp.as_usize(),
        heap_bottom.as_usize(),
        user_tp,
        auxv_value(auxv, AuxvType::PHDR),
        auxv_value(auxv, AuxvType::PHENT),
        auxv_value(auxv, AuxvType::PHNUM),
        auxv_value(auxv, AuxvType::BASE),
        env_value(env, "LC_ALL").unwrap_or("<unset>"),
        env_value(env, "LANG").unwrap_or("<unset>"),
        env_value(env, "LC_CTYPE").unwrap_or("<unset>"),
        env_value(env, "LOCPATH").unwrap_or("<unset>"),
        env_value(env, "LIBRARY_PATH").unwrap_or("<unset>"),
        env_value(env, "LD_LIBRARY_PATH").unwrap_or("<unset>"),
        locale_archive,
        axfs::api::absolute_path_exists(locale_archive.as_str()),
        c_utf8,
        axfs::api::absolute_path_exists(c_utf8.as_str()),
        c_dot_utf8,
        axfs::api::absolute_path_exists(c_dot_utf8.as_str()),
    );
}

fn align_up_usize(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn elf_tls_info(elf: &ElfFile, file_data: &[u8], layout: InitialTlsLayout) -> Option<ElfTlsInfo> {
    let tls = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Tls))?;
    tls_info_from_ph(file_data, &tls, layout)
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn tls_info_from_ph(
    file_data: &[u8],
    ph: &ProgramHeader,
    layout: InitialTlsLayout,
) -> Option<ElfTlsInfo> {
    let offset = ph.offset() as usize;
    let filesz = ph.file_size() as usize;
    let memsz = ph.mem_size() as usize;
    let align = (ph.align() as usize).max(core::mem::size_of::<usize>());
    let image = file_data.get(offset..offset + filesz)?.to_vec();
    Some(ElfTlsInfo {
        image,
        mem_size: memsz,
        align,
        vaddr: ph.virtual_addr() as usize,
        layout,
    })
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn map_initial_thread_tls(
    uspace: &mut AddrSpace,
    tls: &ElfTlsInfo,
    ustack_start: VirtAddr,
) -> AxResult<Option<VirtAddr>> {
    if tls.mem_size == 0 {
        return Ok(None);
    }

    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    if tls.layout == InitialTlsLayout::Musl {
        return map_initial_thread_tls_musl(uspace, tls, ustack_start);
    }

    let static_tls_size = align_up_usize(tls.mem_size, tls.align.max(16));
    let tls_block_offset = USER_TLS_BLOCK_OFFSET;
    let dtv_offset = align_up_usize(tls_block_offset + static_tls_size, 16);
    let dtv_entry_count = USER_TLS_DTV_SLOTS + 1;
    let area_size = align_up_usize(
        dtv_offset + USER_TLS_DTV_ENTRY_SIZE * dtv_entry_count,
        PAGE_SIZE_4K,
    );
    let guard_gap = 2 * PAGE_SIZE_4K;
    let area_end = ustack_start
        .checked_sub(guard_gap)
        .ok_or(AxError::NoMemory)?;
    let area_start = VirtAddr::from_usize(
        area_end
            .checked_sub(area_size)
            .ok_or(AxError::NoMemory)?
            .align_down_4k()
            .as_usize(),
    );
    uspace.map_alloc(
        area_start,
        area_size,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        false,
    )?;
    uspace.alloc_for_lazy(area_start, area_size)?;

    let tp = area_start + tls_block_offset;
    if !tls.image.is_empty() {
        uspace.write(tp, &tls.image)?;
    }

    let dtv_base = area_start + dtv_offset;
    let mut dtv = [0usize; (USER_TLS_DTV_SLOTS + 1) * 2];
    dtv[0] = USER_TLS_DTV_SLOTS;
    dtv[2] = 1;
    let tls_pointer = tp.as_usize().saturating_sub(USER_TLS_DTV_OFFSET_BIAS);
    dtv[4] = tls_pointer;
    dtv[6] = tls_pointer;
    uspace.write(dtv_base, unsafe {
        core::slice::from_raw_parts(dtv.as_ptr().cast::<u8>(), core::mem::size_of_val(&dtv))
    })?;

    let tcb_head = [dtv_base.as_usize() + USER_TLS_DTV_ENTRY_SIZE, 0usize];
    uspace.write(tp - USER_TLS_TCBHEAD_SIZE, unsafe {
        core::slice::from_raw_parts(
            tcb_head.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&tcb_head),
        )
    })?;

    Ok(Some(tp))
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_PTHREAD_SIZE: usize = 200;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_DTV_SLOTS: usize = 4;
#[cfg(target_arch = "riscv64")]
const MUSL_DTP_OFFSET: usize = 0x800;
#[cfg(target_arch = "loongarch64")]
const MUSL_DTP_OFFSET: usize = 0;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_DETACH_JOINABLE: i32 = 2;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_SELF_OFFSET: usize = 0;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_PREV_OFFSET: usize = 8;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_NEXT_OFFSET: usize = 16;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_SYSINFO_OFFSET: usize = 24;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_TID_OFFSET: usize = 32;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_DETACH_STATE_OFFSET: usize = 40;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_ROBUST_HEAD_OFFSET: usize = 120;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_CANARY_OFFSET_FROM_TP: usize = 16;
#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
const MUSL_DTV_PTR_OFFSET_FROM_TP: usize = 8;

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn write_usize_to_uspace(uspace: &mut AddrSpace, addr: VirtAddr, value: usize) -> AxResult {
    uspace.write(addr, &value.to_ne_bytes())
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn write_i32_to_uspace(uspace: &mut AddrSpace, addr: VirtAddr, value: i32) -> AxResult {
    uspace.write(addr, &value.to_ne_bytes())
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
fn map_initial_thread_tls_musl(
    uspace: &mut AddrSpace,
    tls: &ElfTlsInfo,
    ustack_start: VirtAddr,
) -> AxResult<Option<VirtAddr>> {
    let tls_align = tls.align.max(16);
    let guard_gap = 2 * PAGE_SIZE_4K;
    let td_pad = (0usize.wrapping_sub(MUSL_PTHREAD_SIZE)) & (tls_align - 1);
    let td_size = td_pad + MUSL_PTHREAD_SIZE;
    let tls_offset = (0usize.wrapping_sub(tls.vaddr)) & (tls_align - 1);
    let tls_end = align_up_usize(tls_offset + tls.mem_size, tls_align);
    let dtv_offset = align_up_usize(td_size + tls_end, 16);
    let dtv_words = MUSL_DTV_SLOTS + 1;
    let area_size = align_up_usize(
        dtv_offset + dtv_words * core::mem::size_of::<usize>(),
        PAGE_SIZE_4K,
    );
    let area_end = ustack_start
        .checked_sub(guard_gap)
        .ok_or(AxError::NoMemory)?;
    let area_start = VirtAddr::from_usize(
        area_end
            .checked_sub(area_size)
            .ok_or(AxError::NoMemory)?
            .align_down_4k()
            .as_usize(),
    );
    uspace.map_alloc(
        area_start,
        area_size,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        false,
    )?;
    uspace.alloc_for_lazy(area_start, area_size)?;

    let td = area_start + td_pad;
    let tp = td + MUSL_PTHREAD_SIZE;
    let tls_block = tp + tls_offset;
    if !tls.image.is_empty() {
        uspace.write(tls_block, &tls.image)?;
    }

    let dtv = area_start + dtv_offset;
    let mut dtv_words_buf = [0usize; MUSL_DTV_SLOTS + 1];
    dtv_words_buf[0] = 1;
    dtv_words_buf[1] = tls_block.as_usize() + MUSL_DTP_OFFSET;
    uspace.write(dtv, unsafe {
        core::slice::from_raw_parts(
            dtv_words_buf.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&dtv_words_buf),
        )
    })?;

    let td_base = td.as_usize();
    let robust_head = td_base + MUSL_ROBUST_HEAD_OFFSET;
    let tid = current().id().as_u64() as i32;
    write_usize_to_uspace(
        uspace,
        VirtAddr::from_usize(td_base + MUSL_SELF_OFFSET),
        td_base,
    )?;
    write_usize_to_uspace(
        uspace,
        VirtAddr::from_usize(td_base + MUSL_PREV_OFFSET),
        td_base,
    )?;
    write_usize_to_uspace(
        uspace,
        VirtAddr::from_usize(td_base + MUSL_NEXT_OFFSET),
        td_base,
    )?;
    write_usize_to_uspace(
        uspace,
        VirtAddr::from_usize(td_base + MUSL_SYSINFO_OFFSET),
        0,
    )?;
    write_i32_to_uspace(uspace, VirtAddr::from_usize(td_base + MUSL_TID_OFFSET), tid)?;
    write_i32_to_uspace(
        uspace,
        VirtAddr::from_usize(td_base + MUSL_DETACH_STATE_OFFSET),
        MUSL_DETACH_JOINABLE,
    )?;
    write_usize_to_uspace(uspace, VirtAddr::from_usize(robust_head), robust_head)?;
    write_usize_to_uspace(uspace, tp - MUSL_CANARY_OFFSET_FROM_TP, 0)?;
    write_usize_to_uspace(uspace, tp - MUSL_DTV_PTR_OFFSET_FROM_TP, dtv.as_usize())?;

    Ok(Some(tp))
}

fn is_cacheable_exec_path(path: &str) -> bool {
    path.starts_with('/')
        && !matches!(path, "/proc" | "/sys" | "/dev")
        && !path.starts_with("/proc/")
        && !path.starts_with("/sys/")
        && !path.starts_with("/dev/")
}

fn should_cache_exec_image(path: &str, size: usize) -> bool {
    size <= EXEC_IMAGE_CACHE_MAX_FILE_SIZE && is_cacheable_exec_path(path)
}

fn should_page_back_exec_image(_path: &str, size: usize) -> bool {
    (128 * 1024..=EXEC_IMAGE_CACHE_MAX_FILE_SIZE).contains(&size)
}

#[cfg(feature = "contest_diag_logs")]
fn probe_usize(task: &axtask::CurrentTask, addr: VirtAddr) -> Option<usize> {
    let mut value = 0usize;
    task.task_ext()
        .aspace
        .lock()
        .read(addr, unsafe {
            core::slice::from_raw_parts_mut(
                (&mut value as *mut usize).cast::<u8>(),
                core::mem::size_of::<usize>(),
            )
        })
        .ok()?;
    Some(value)
}

#[cfg(feature = "contest_diag_logs")]
fn log_userboot_fault(current: &axtask::CurrentTask, vaddr: VirtAddr, access_flags: MappingFlags) {
    let stack_probe_addr = VirtAddr::from_usize(0x3fffff740);
    let localvar_stack_addr = VirtAddr::from_usize(0x17b660);
    let g_parsefile_addr = VirtAddr::from_usize(0x17b5b8);
    crate::diag_warn!(
        "user write page fault task={} vaddr={:#x} access={:?}",
        current.id_name(),
        vaddr,
        access_flags
    );
    if vaddr.align_down_4k().as_usize() == 0x3fffff000 {
        crate::diag_warn!(
            "stack probe before fault task={} slot@0x3fffff740={:#x}",
            current.id_name(),
            probe_usize(current, stack_probe_addr).unwrap_or(usize::MAX)
        );
    } else if vaddr.align_down_4k().as_usize() == 0x17b000 {
        crate::diag_warn!(
            "data probe before fault task={} localvar_stack={:#x} g_parsefile={:#x}",
            current.id_name(),
            probe_usize(current, localvar_stack_addr).unwrap_or(usize::MAX),
            probe_usize(current, g_parsefile_addr).unwrap_or(usize::MAX),
        );
    }
}

#[cfg(feature = "contest_diag_logs")]
fn log_userboot_fault_handled(
    current: &axtask::CurrentTask,
    vaddr: VirtAddr,
    access_flags: MappingFlags,
) {
    if !access_flags.contains(MappingFlags::WRITE) || !current.name().contains("userboot") {
        return;
    }
    let stack_probe_addr = VirtAddr::from_usize(0x3fffff740);
    let localvar_stack_addr = VirtAddr::from_usize(0x17b660);
    let g_parsefile_addr = VirtAddr::from_usize(0x17b5b8);
    if vaddr.align_down_4k().as_usize() == 0x3fffff000 {
        crate::diag_warn!(
            "stack probe after fault task={} slot@0x3fffff740={:#x}",
            current.id_name(),
            probe_usize(current, stack_probe_addr).unwrap_or(usize::MAX)
        );
    } else if vaddr.align_down_4k().as_usize() == 0x17b000 {
        crate::diag_warn!(
            "data probe after fault task={} localvar_stack={:#x} g_parsefile={:#x}",
            current.id_name(),
            probe_usize(current, localvar_stack_addr).unwrap_or(usize::MAX),
            probe_usize(current, g_parsefile_addr).unwrap_or(usize::MAX),
        );
    }
}

struct PageBackedBytes {
    bytes: Vec<u8>,
}

impl PageBackedBytes {
    fn from_slice(data: &[u8]) -> AxResult<Self> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(data.len())
            .map_err(|_| AxError::NoMemory)?;
        bytes.extend_from_slice(data);
        Ok(Self {
            bytes,
        })
    }

    fn read_from_path(path: &str) -> AxResult<Self> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len() as usize;
        if len == 0 {
            return Self::from_slice(&[]);
        }

        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(len)
            .map_err(|_| AxError::NoMemory)?;
        bytes.resize(len, 0);
        file.read_exact(&mut bytes)?;
        Ok(Self { bytes })
    }

    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

enum ExecImage {
    Heap(Vec<u8>),
    Paged(Arc<PageBackedBytes>),
}

impl ExecImage {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Heap(bytes) => bytes.as_slice(),
            Self::Paged(bytes) => bytes.as_slice(),
        }
    }
}

fn cache_bytes(len: usize) -> usize {
    let len = len.max(PAGE_SIZE_4K);
    (len + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1)
}

pub(crate) fn reclaim_exec_caches() -> usize {
    let image_pages = {
        let mut cache = exec_image_cache().lock();
        let bytes = cache.iter().map(|(_, bytes, _)| *bytes).sum::<usize>();
        cache.clear();
        bytes.div_ceil(PAGE_SIZE_4K)
    };
    let segment_pages = {
        let mut cache = exec_segment_cache().lock();
        let mut bytes = 0usize;
        cache.retain(|(_, entry_bytes, frames)| {
            if Arc::strong_count(frames) > 1 {
                true
            } else {
                bytes = bytes.saturating_add(*entry_bytes);
                false
            }
        });
        bytes.div_ceil(PAGE_SIZE_4K)
    };
    image_pages.saturating_add(segment_pages)
}

fn exec_image_cache() -> &'static Mutex<Vec<(String, usize, Arc<PageBackedBytes>)>> {
    static EXEC_IMAGE_CACHE: Once<Mutex<Vec<(String, usize, Arc<PageBackedBytes>)>>> = Once::new();
    EXEC_IMAGE_CACHE.call_once(|| Mutex::new(Vec::new()))
}

fn exec_segment_cache() -> &'static Mutex<Vec<(String, usize, Arc<SharedFrames>)>> {
    static EXEC_SEGMENT_CACHE: Once<Mutex<Vec<(String, usize, Arc<SharedFrames>)>>> = Once::new();
    EXEC_SEGMENT_CACHE.call_once(|| Mutex::new(Vec::new()))
}

fn trim_exec_image_cache(cache: &mut Vec<(String, usize, Arc<PageBackedBytes>)>, incoming: usize) {
    let mut total = cache.iter().map(|(_, bytes, _)| *bytes).sum::<usize>();
    while !cache.is_empty()
        && (cache.len() >= EXEC_IMAGE_CACHE_MAX_ENTRIES
            || total.saturating_add(incoming) > EXEC_IMAGE_CACHE_MAX_BYTES)
    {
        let (_, bytes, _) = cache.remove(0);
        total = total.saturating_sub(bytes);
    }
}

fn trim_exec_segment_cache(cache: &mut Vec<(String, usize, Arc<SharedFrames>)>, incoming: usize) {
    let mut total = cache.iter().map(|(_, bytes, _)| *bytes).sum::<usize>();
    while !cache.is_empty()
        && (cache.len() >= EXEC_SEGMENT_CACHE_MAX_ENTRIES
            || total.saturating_add(incoming) > EXEC_SEGMENT_CACHE_MAX_BYTES)
    {
        let (_, bytes, _) = cache.remove(0);
        total = total.saturating_sub(bytes);
    }
}

fn normalize_exec_cache_path(path: &str) -> String {
    if path.starts_with('/') {
        axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string())
    } else {
        path.to_string()
    }
}

pub(crate) fn invalidate_exec_cache_path(path: &str) {
    let normalized = normalize_exec_cache_path(path);
    exec_image_cache()
        .lock()
        .retain(|(cached_path, _, _)| cached_path != &normalized);
    let segment_prefix = alloc::format!("{normalized}@");
    exec_segment_cache()
        .lock()
        .retain(|(cached_key, _, _)| !cached_key.starts_with(segment_prefix.as_str()));
}

fn should_cache_exec_segment(path: &str, flags: MappingFlags, file_size: usize) -> bool {
    !flags.contains(MappingFlags::WRITE)
        && file_size <= EXEC_IMAGE_CACHE_MAX_FILE_SIZE
        && is_cacheable_exec_path(path)
}

fn exec_segment_key(
    path: &str,
    seg_start: VirtAddr,
    seg_size: usize,
    seg_vaddr: VirtAddr,
    seg_offset: usize,
    flags: MappingFlags,
) -> String {
    alloc::format!(
        "{}@{:x}:{:x}:{:x}:{:x}:{:x}",
        path,
        seg_start.as_usize(),
        seg_size,
        seg_vaddr.as_usize(),
        seg_offset,
        flags.bits()
    )
}

fn shared_exec_segment_frames(
    path: &str,
    seg_start: VirtAddr,
    seg_size: usize,
    seg_vaddr: VirtAddr,
    seg_offset: usize,
    seg_data: &[u8],
    flags: MappingFlags,
) -> AxResult<Option<Arc<SharedFrames>>> {
    if !should_cache_exec_segment(path, flags, seg_data.len()) {
        return Ok(None);
    }

    let key = exec_segment_key(path, seg_start, seg_size, seg_vaddr, seg_offset, flags);
    if let Some(frames) = exec_segment_cache()
        .lock()
        .iter()
        .find(|(cached_key, _, _)| cached_key == &key)
        .map(|(_, _, frames)| Arc::clone(frames))
    {
        return Ok(Some(frames));
    }

    let seg_pad = seg_vaddr.align_offset_4k();
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(seg_size / PAGE_SIZE_4K)
        .map_err(|_| AxError::NoMemory)?;
    for page in PageIter4K::new(seg_start, seg_start + seg_size).unwrap() {
        let frame = alloc_user_frame(true).ok_or(AxError::NoMemory)?;
        let page_off = page.as_usize() - seg_start.as_usize();
        let seg_off_in_page = seg_pad.saturating_sub(page_off).min(PAGE_SIZE_4K);
        let data_off = page_off.saturating_sub(seg_pad);
        if data_off < seg_data.len() && seg_off_in_page < PAGE_SIZE_4K {
            let copy_len = (PAGE_SIZE_4K - seg_off_in_page).min(seg_data.len() - data_off);
            unsafe {
                core::ptr::copy_nonoverlapping(
                    seg_data.as_ptr().add(data_off),
                    phys_to_virt(frame).as_mut_ptr().add(seg_off_in_page),
                    copy_len,
                );
            }
        }
        frames.push(frame);
    }

    let bytes = cache_bytes(frames.len() * PAGE_SIZE_4K);
    let frames = Arc::new(SharedFrames::new(frames));
    let mut cache = exec_segment_cache().lock();
    if should_admit_exec_segment_cache_entry()
        && !cache.iter().any(|(cached_key, _, _)| cached_key == &key)
        && bytes <= EXEC_SEGMENT_CACHE_MAX_BYTES
    {
        trim_exec_segment_cache(&mut cache, bytes);
        cache.push((key, bytes, Arc::clone(&frames)));
    }
    Ok(Some(frames))
}

pub(crate) fn is_expected_exec_lookup_error(err: &AxError) -> bool {
    matches!(
        err,
        AxError::NotFound
            | AxError::NotADirectory
            | AxError::IsADirectory
            | AxError::PermissionDenied
    )
}

fn read_user_image(path: &str) -> AxResult<ExecImage> {
    let resolved_path = if path.starts_with('/') {
        path.to_string()
    } else {
        axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string())
    };
    let resolved_path = resolve_final_symlink_path(resolved_path.as_str()).unwrap_or(resolved_path);
    let aliased_path = exec_alias_path(resolved_path.as_str()).unwrap_or_else(|| resolved_path.clone());

    if let Some(cached) = exec_image_cache()
        .lock()
        .iter()
        .find(|(cached_path, _, _)| cached_path == &aliased_path)
        .map(|(_, _, data)| Arc::clone(data))
    {
        return Ok(ExecImage::Paged(cached));
    }

    let read_path = aliased_path.as_str();
    let image = match File::open(read_path) {
        Ok(file) => {
            let size = file.metadata()?.len() as usize;
            drop(file);
            if should_cache_exec_image(aliased_path.as_str(), size)
                || should_page_back_exec_image(aliased_path.as_str(), size)
            {
                ExecImage::Paged(Arc::new(PageBackedBytes::read_from_path(read_path)?))
            } else {
                ExecImage::Heap(axfs::api::read(read_path)?)
            }
        }
        Err(err)
            if (is_musl_loader_path(path) || is_musl_loader_path(resolved_path.as_str()))
                && matches!(err, AxError::NotFound | AxError::Unsupported | AxError::Io) =>
        {
            if MUSL_INTERP_BYTES.is_empty() {
                warn!(
                    "missing dynamic loader fallback image: path={} resolved={} cwd={:?} err={:?}",
                    path,
                    resolved_path,
                    axfs::api::current_dir().ok(),
                    err
                );
                return Err(AxError::NotFound);
            }
            if should_cache_exec_image(aliased_path.as_str(), MUSL_INTERP_BYTES.len())
                || should_page_back_exec_image(aliased_path.as_str(), MUSL_INTERP_BYTES.len())
            {
                ExecImage::Paged(Arc::new(PageBackedBytes::from_slice(MUSL_INTERP_BYTES)?))
            } else {
                ExecImage::Heap(MUSL_INTERP_BYTES.to_vec())
            }
        }
        Err(err)
            if matches!(err, AxError::NotFound | AxError::Unsupported | AxError::Io)
                && synthetic_exec_wrapper(path).is_some() =>
        {
            return Ok(ExecImage::Heap(
                synthetic_exec_wrapper(path).unwrap().into_bytes(),
            ));
        }
        Err(err) => {
            if !is_expected_exec_lookup_error(&err) {
                warn!(
                    "read_user_image failed: path={} resolved={} aliased={} cwd={:?} err={:?}",
                    path,
                    resolved_path,
                    aliased_path,
                    axfs::api::current_dir().ok(),
                    err
                );
            }
            return Err(err);
        }
    };

    if should_cache_exec_image(aliased_path.as_str(), image.as_slice().len()) {
        let mut cache = exec_image_cache().lock();
        let cache_len = cache_bytes(image.as_slice().len());
        if should_admit_exec_image_cache_entry()
            && !cache
            .iter()
            .any(|(cached_path, _, _)| cached_path == &aliased_path)
            && cache_len <= EXEC_IMAGE_CACHE_MAX_BYTES
        {
            trim_exec_image_cache(&mut cache, cache_len);
            if let ExecImage::Paged(paged) = &image {
                cache.push((aliased_path, cache_len, Arc::clone(paged)));
            }
        }
    }

    Ok(image)
}

fn runtime_bin_alias_prefix(path: &str) -> Option<&'static str> {
    for prefix in [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/glibc/bin/",
        "/glibc/sbin/",
        "/glibc/usr/bin/",
        "/glibc/usr/sbin/",
        "/musl/bin/",
        "/musl/sbin/",
        "/musl/usr/bin/",
        "/musl/usr/sbin/",
    ] {
        if path.starts_with(prefix) {
            return Some(prefix);
        }
    }
    None
}

fn ltp_alias_path_for(path: &str) -> Option<String> {
    let prefix = runtime_bin_alias_prefix(path)?;
    let basename = path.strip_prefix(prefix)?;
    if basename.is_empty() || basename.contains('/') {
        return None;
    }
    let runtime_root = if prefix.starts_with("/glibc/") {
        "/glibc"
    } else if prefix.starts_with("/musl/") {
        "/musl"
    } else {
        ""
    };
    let candidate = if runtime_root.is_empty() {
        alloc::format!("/ltp/testcases/bin/{basename}")
    } else {
        alloc::format!("{runtime_root}/ltp/testcases/bin/{basename}")
    };
    axfs::api::absolute_path_exists(candidate.as_str()).then_some(candidate)
}

fn synthetic_exec_wrapper(path: &str) -> Option<String> {
    let prefix = runtime_bin_alias_prefix(path)?;
    let basename = path.strip_prefix(prefix)?;
    match basename {
        "mkfs.ext4" => Some("#!/busybox sh\nexec /busybox mke2fs \"$@\"\n".to_string()),
        _ => None,
    }
}

fn exec_alias_path(path: &str) -> Option<String> {
    ltp_alias_path_for(path)
}

fn is_busybox_symlink_applet(program_path: &str, applet: &str) -> bool {
    if applet.is_empty() || applet.contains('/') || applet == "busybox" {
        return false;
    }
    let absolute = absolute_exec_path(program_path);
    let Ok(canonical) = axfs::api::canonicalize(absolute.as_str()) else {
        return false;
    };
    canonical.ends_with("/busybox")
}

fn argv0_matches_exec_target(first: &str, program_path: &str, applet: &str) -> bool {
    first == program_path
        || first == absolute_exec_path(program_path).as_str()
        || first == applet
        || first == script_dir(program_path).rsplit('/').next().unwrap_or("")
        || first == program_path.rsplit('/').next().unwrap_or("")
}

fn rewrite_to_busybox_applet(
    program_path: &str,
    args: &VecDeque<String>,
    applet: &str,
) -> Option<(String, VecDeque<String>)> {
    let real_busybox = resolve_busybox_binary(program_path).or_else(|| {
        resolve_busybox_binary_candidate("/busybox", 0)
            .or_else(|| resolve_busybox_binary_candidate("/bin/busybox", 0))
    })?;
    let skip = args
        .front()
        .is_some_and(|first| argv0_matches_exec_target(first.as_str(), program_path, applet))
        as usize;
    let mut new_args = VecDeque::new();
    new_args.push_back(real_busybox.clone());
    new_args.push_back(applet.to_string());
    for arg in args.iter().skip(skip) {
        new_args.push_back(arg.clone());
    }
    Some((real_busybox, new_args))
}

fn virtual_busybox_applet(program_path: &str) -> Option<&'static str> {
    let prefix = runtime_bin_alias_prefix(program_path)?;
    let basename = program_path.strip_prefix(prefix)?;
    match basename {
        "mkfs.ext4" => Some("mke2fs"),
        _ => None,
    }
}

fn interp_basename_aliases(name: &str) -> &'static [&'static str] {
    match name {
        "ld-musl-riscv64.so.1" | "ld-musl-riscv64-sf.so.1" => {
            &["ld-musl-riscv64.so.1", "ld-musl-riscv64-sf.so.1"]
        }
        "ld-musl-loongarch64.so.1" | "ld-musl-loongarch-lp64d.so.1" => {
            &["ld-musl-loongarch64.so.1", "ld-musl-loongarch-lp64d.so.1"]
        }
        "ld-linux-riscv64-lp64d.so.1" => &["ld-linux-riscv64-lp64d.so.1"],
        "ld-linux-loongarch-lp64d.so.1" => &["ld-linux-loongarch-lp64d.so.1"],
        _ => &[],
    }
}

fn is_musl_interp_path(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    matches!(
        name,
        "ld-musl-riscv64.so.1"
            | "ld-musl-riscv64-sf.so.1"
            | "ld-musl-loongarch64.so.1"
            | "ld-musl-loongarch-lp64d.so.1"
    )
}

fn is_musl_loader_path(path: &str) -> bool {
    is_musl_interp_path(path)
        || (path.ends_with("/libc.so")
            && (path == "/musl/lib/libc.so"
                || path == "./musl/lib/libc.so"
                || path == "/musl/lib64/libc.so"
                || path == "./musl/lib64/libc.so"
                || path.contains("/musl/lib/")
                || path.contains("/musl/lib64/")))
}

fn canonical_musl_interp_path(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name {
        "ld-musl-riscv64.so.1" | "ld-musl-riscv64-sf.so.1" => "/lib/ld-musl-riscv64.so.1",
        "ld-musl-loongarch64.so.1" | "ld-musl-loongarch-lp64d.so.1" => {
            "/lib64/ld-musl-loongarch-lp64d.so.1"
        }
        _ => "/lib/libc.so",
    }
}

fn push_unique_path(candidates: &mut Vec<String>, candidate: String) {
    if !candidate.is_empty() && !candidates.iter().any(|existing| existing == &candidate) {
        candidates.push(candidate);
    }
}

fn resolve_final_symlink_path(path: &str) -> AxResult<String> {
    const MAX_SYMLINK_DEPTH: usize = 8;

    fn parent_dir_path(path: &str) -> &str {
        path.rsplit_once('/')
            .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
            .unwrap_or(".")
    }

    let mut resolved = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    if !resolved.starts_with('/') {
        let cwd = axfs::api::current_dir().map_err(|_| AxError::NotFound)?;
        resolved = if cwd.ends_with('/') {
            alloc::format!("{cwd}{resolved}")
        } else {
            alloc::format!("{cwd}/{resolved}")
        };
    }

    for _ in 0..MAX_SYMLINK_DEPTH {
        let target = match axfs::api::readlink(resolved.as_str()) {
            Ok(target) => target,
            Err(_) => return Ok(resolved),
        };
        let target = String::from_utf8(target).map_err(|_| AxError::InvalidInput)?;
        resolved = if target.starts_with('/') {
            target
        } else {
            let parent = parent_dir_path(resolved.as_str());
            if parent == "/" {
                alloc::format!("/{target}")
            } else if parent == "." {
                target
            } else {
                alloc::format!("{parent}/{target}")
            }
        };
    }

    Err(AxError::InvalidInput)
}

fn path_has_elf_magic(path: &str) -> bool {
    let resolved = resolve_final_symlink_path(path).unwrap_or_else(|_| path.to_string());
    let Ok(mut file) = File::open(resolved.as_str()) else {
        return false;
    };
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

fn interp_library_search_dirs(prefix: &str) -> Vec<String> {
    let mut dirs = Vec::new();
    if prefix == "/" {
        for dir in [
            "/lib",
            "/lib64",
            "/musl/lib",
            "/musl/lib64",
            "/glibc/lib",
            "/glibc/lib64",
        ] {
            push_unique_path(&mut dirs, dir.to_string());
        }
    } else {
        push_unique_path(&mut dirs, alloc::format!("{prefix}/lib"));
        push_unique_path(&mut dirs, alloc::format!("{prefix}/lib64"));
    }
    dirs
}

fn interp_path_candidates(program_path: &str, interp_path: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    let interp_name = interp_path.rsplit('/').next().unwrap_or(interp_path);
    let alias_names = interp_basename_aliases(interp_name);

    push_unique_path(&mut candidates, interp_path.to_string());
    for alias in alias_names {
        if interp_path.starts_with('/') {
            let dir = interp_path
                .rsplit_once('/')
                .map(|(dir, _)| if dir.is_empty() { "/" } else { dir })
                .unwrap_or("/");
            let joined = if dir == "/" {
                alloc::format!("/{alias}")
            } else {
                alloc::format!("{dir}/{alias}")
            };
            push_unique_path(&mut candidates, joined);
        } else {
            push_unique_path(&mut candidates, (*alias).to_string());
        }
    }

    for prefix in runtime_search_prefixes(program_path) {
        if prefix != "/" {
            if interp_path.starts_with('/') {
                push_unique_path(&mut candidates, alloc::format!("{prefix}{interp_path}"));
            } else {
                push_unique_path(
                    &mut candidates,
                    alloc::format!("{prefix}/{}", interp_path.trim_start_matches("./")),
                );
            }
        }

        for dir in interp_library_search_dirs(prefix.as_str()) {
            if !interp_name.is_empty() {
                push_unique_path(&mut candidates, alloc::format!("{dir}/{interp_name}"));
            }
            for alias in alias_names {
                push_unique_path(&mut candidates, alloc::format!("{dir}/{alias}"));
            }
        }
    }

    candidates
}

fn musl_libc_candidates(program_path: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for prefix in runtime_search_prefixes(program_path) {
        for dir in interp_library_search_dirs(prefix.as_str()) {
            push_unique_path(&mut candidates, alloc::format!("{dir}/libc.so"));
        }
    }
    candidates
}

fn parse_shebang(file_data: &[u8]) -> Option<(String, Option<String>)> {
    if !file_data.starts_with(b"#!") {
        return None;
    }
    let line_end = file_data
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(file_data.len());
    let line = from_utf8(&file_data[2..line_end]).ok()?.trim();
    if line.is_empty() {
        return None;
    }
    if let Some(split_at) = line.find(char::is_whitespace) {
        let interp = line[..split_at].trim();
        let arg = line[split_at..].trim();
        if interp.is_empty() {
            None
        } else if arg.is_empty() {
            Some((interp.to_string(), None))
        } else {
            Some((interp.to_string(), Some(arg.to_string())))
        }
    } else {
        Some((line.to_string(), None))
    }
}

fn parse_busybox_exec_wrapper(file_data: &[u8]) -> Option<(String, Option<String>)> {
    let text = from_utf8(file_data).ok()?;
    let mut lines = text.lines();
    let shebang = lines.next()?.trim();
    if !shebang.starts_with("#!") || !shebang.contains("busybox") {
        return None;
    }

    let exec_line = lines.next()?.trim();
    let mut parts = exec_line.strip_prefix("exec ")?.split_whitespace();
    let target = parts.next()?;
    if !target.contains("busybox") {
        return None;
    }

    let maybe_applet = match parts.next() {
        Some("\"$@\"") | None => None,
        Some(applet) => {
            if applet.is_empty() || applet.contains('/') || applet.contains(char::is_whitespace) {
                return None;
            }
            Some(applet.to_string())
        }
    };
    Some((target.to_string(), maybe_applet))
}

fn maybe_busybox_applet_path(program_path: &str) -> Option<String> {
    for prefix in [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/glibc/bin/",
        "/glibc/sbin/",
        "/glibc/usr/bin/",
        "/glibc/usr/sbin/",
        "/musl/bin/",
        "/musl/sbin/",
        "/musl/usr/bin/",
        "/musl/usr/sbin/",
    ] {
        let Some(applet) = program_path.strip_prefix(prefix) else {
            continue;
        };
        if !applet.is_empty() && !applet.contains('/') && applet != "busybox" {
            return Some(applet.to_string());
        }
    }
    None
}

fn inferred_busybox_applet_path(program_path: &str) -> Option<String> {
    maybe_busybox_applet_path(program_path).or_else(|| {
        let applet = program_path.rsplit('/').next().unwrap_or(program_path);
        if applet.is_empty() || applet.contains('/') || applet == "busybox" {
            None
        } else {
            Some(applet.to_string())
        }
    })
}

fn script_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some(("", _)) | None => ".",
        Some((dir, _)) => dir,
    }
}

pub(crate) fn absolute_exec_path(path: &str) -> String {
    if path.starts_with('/') {
        return axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    }
    if let Ok(canonical) = axfs::api::canonicalize(path) {
        return canonical;
    }
    let cwd = axfs::api::current_dir().unwrap_or_else(|_| "/".to_string());
    if cwd == "/" {
        alloc::format!("/{}", path.trim_start_matches("./"))
    } else {
        alloc::format!("{}/{}", cwd.trim_end_matches('/'), path)
    }
}

fn runtime_search_prefixes(program_path: &str) -> Vec<String> {
    let mut prefixes = Vec::new();
    let mut dir = script_dir(absolute_exec_path(program_path).as_str()).to_string();
    loop {
        push_shell_candidate(&mut prefixes, dir.clone());
        if dir == "/" {
            break;
        }
        match dir.rsplit_once('/') {
            Some(("", _)) | None => dir = "/".into(),
            Some((parent, _)) => dir = parent.to_string(),
        }
    }
    prefixes
}

fn push_shell_candidate(candidates: &mut Vec<String>, path: String) {
    if !candidates.iter().any(|candidate| candidate == &path) {
        candidates.push(path);
    }
}

fn shell_candidates(script_path: &str) -> Vec<String> {
    let mut candidates = Vec::new();
    for dir in runtime_search_prefixes(script_path) {
        push_shell_candidate(&mut candidates, alloc::format!("{dir}/busybox"));
        push_shell_candidate(&mut candidates, alloc::format!("{dir}/bin/busybox"));
    }
    candidates
}

fn resolve_shell_interpreter(script_path: &str, interp_path: &str) -> Option<String> {
    let needs_shell_lookup = matches!(
        interp_path,
        "/bin/sh" | "/bin/bash" | "/busybox" | "sh" | "bash" | "busybox"
    );
    if !needs_shell_lookup {
        return if interp_path.starts_with('/') {
            axfs::api::canonicalize(interp_path).ok()
        } else {
            Some(interp_path.to_string())
        };
    }

    shell_candidates(script_path)
        .into_iter()
        .find(|candidate| axfs::api::absolute_path_exists(candidate.as_str()))
}

fn resolve_busybox_binary_candidate(path: &str, depth: usize) -> Option<String> {
    if depth > 4 || !axfs::api::absolute_path_exists(path) {
        return None;
    }

    let canonical = axfs::api::canonicalize(path).ok()?;
    let file_data = read_user_image(canonical.as_str()).ok()?;
    if ElfFile::new(file_data.as_slice()).is_ok() {
        return Some(canonical);
    }

    let (target, _) = parse_busybox_exec_wrapper(file_data.as_slice())?;
    resolve_busybox_binary_candidate(target.as_str(), depth + 1)
}

fn resolve_busybox_binary(script_path: &str) -> Option<String> {
    let mut candidates = shell_candidates(script_path);
    push_shell_candidate(&mut candidates, "/busybox".to_string());
    push_shell_candidate(&mut candidates, "/bin/busybox".to_string());
    for candidate in candidates {
        if let Some(real_busybox) = resolve_busybox_binary_candidate(candidate.as_str(), 0) {
            return Some(real_busybox);
        }
    }
    None
}

fn resolve_interp_path(program_path: &str, interp_path: &str) -> AxResult<String> {
    if is_musl_interp_path(interp_path) {
        for candidate in interp_path_candidates(program_path, interp_path) {
            let resolved = resolve_final_symlink_path(candidate.as_str())
                .or_else(|_| axfs::api::canonicalize(candidate.as_str()))
                .unwrap_or(candidate);
            if path_has_elf_magic(resolved.as_str()) {
                return Ok(resolved);
            }
        }
    }

    let mut attempted = Vec::new();
    for candidate in interp_path_candidates(program_path, interp_path) {
        attempted.push(candidate.clone());
        if axfs::api::absolute_path_exists(candidate.as_str()) {
            let resolved = resolve_final_symlink_path(candidate.as_str())
                .or_else(|_| axfs::api::canonicalize(candidate.as_str()))
                .unwrap_or(candidate);
            return Ok(resolved);
        }
    }

    if is_musl_interp_path(interp_path) {
        for candidate in musl_libc_candidates(program_path) {
            attempted.push(candidate.clone());
            if axfs::api::absolute_path_exists(candidate.as_str()) {
                let resolved = resolve_final_symlink_path(candidate.as_str())
                    .or_else(|_| axfs::api::canonicalize(candidate.as_str()))
                    .unwrap_or(candidate);
                return Ok(resolved);
            }
        }
        if !MUSL_INTERP_BYTES.is_empty() {
            return Ok(canonical_musl_interp_path(interp_path).to_string());
        }
    }

    warn!(
        "resolve_interp_path failed: program_path={} interp_path={} cwd={:?} attempted={:?}",
        program_path,
        interp_path,
        axfs::api::current_dir().ok(),
        attempted
    );
    Err(AxError::NotFound)
}

fn rewrite_shebang_args(
    script_path: &str,
    args: &VecDeque<String>,
    interp_path: &str,
    interp_arg: Option<&str>,
) -> (String, VecDeque<String>) {
    let mut new_args = VecDeque::new();
    let real_interp = resolve_shell_interpreter(script_path, interp_path)
        .unwrap_or_else(|| interp_path.to_string());
    let is_shell_interp = matches!(
        interp_path,
        "/bin/sh" | "/bin/bash" | "/busybox" | "sh" | "bash" | "busybox"
    );
    if is_shell_interp {
        new_args.push_back(real_interp.clone());
    } else {
        new_args.push_back(real_interp.clone());
    }
    if let Some(arg) = interp_arg.filter(|arg| !arg.is_empty()) {
        new_args.push_back(arg.to_string());
    } else if is_shell_interp {
        new_args.push_back("sh".into());
    }
    new_args.push_back(script_path.to_string());
    for arg in args.iter().skip(1) {
        new_args.push_back(arg.clone());
    }
    (real_interp, new_args)
}

fn map_single_elf(path: &str, elf_parser: &ELFParser, uspace: &mut AddrSpace) -> AxResult {
    let elf = elf_parser.elf();
    for segement in elf_parser.ph_load() {
        debug!(
            "Mapping ELF segment: [{:#x?}, {:#x?}) flags: {:#x?}",
            segement.vaddr,
            segement.vaddr + segement.memsz as usize,
            segement.flags
        );
        let seg_pad = segement.vaddr.align_offset_4k();
        assert_eq!(seg_pad, segement.offset % PAGE_SIZE_4K);

        let seg_align_size =
            (segement.memsz as usize + seg_pad + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1);
        let seg_start = segement.vaddr.align_down_4k();
        let seg_end = seg_start + seg_align_size;
        let seg_file_offset = segement
            .offset
            .checked_sub(seg_pad)
            .ok_or(AxError::InvalidData)?;
        let seg_file_len = seg_pad
            .checked_add(segement.filesz as usize)
            .ok_or(AxError::InvalidData)?;
        let seg_file_data = elf
            .input
            .get(seg_file_offset..seg_file_offset + seg_file_len)
            .ok_or(AxError::InvalidData)?;
        let seg_data = elf
            .input
            .get(segement.offset..segement.offset + segement.filesz as usize)
            .ok_or(AxError::InvalidData)?;

        let can_share_segment = PageIter4K::new(seg_start, seg_end)
            .unwrap()
            .all(|page| !matches!(uspace.page_table().query(page), Ok((_, flags, _)) if !flags.is_empty()));
        if can_share_segment {
            if let Some(frames) = shared_exec_segment_frames(
                path,
                seg_start,
                seg_align_size,
                segement.vaddr,
                segement.offset,
                seg_data,
                segement.flags,
            )? {
                uspace.map_segment_shared(seg_start, seg_align_size, segement.flags, frames)?;
                #[cfg(target_arch = "riscv64")]
                unsafe {
                    core::arch::asm!("fence.i");
                }
                #[cfg(target_arch = "loongarch64")]
                unsafe {
                    core::arch::asm!("ibar 0");
                }
                continue;
            }
        }

        // Eagerly instantiate writable LOAD segments. Static glibc binaries rely
        // on writable tail pages in .data/.bss being present before later
        // startup mprotect/exit-handler activity, and the lazy path has been
        // observed to leave those pages unavailable in online repro cases.
        let populate_segment = true;
        let mut pending_start = None;
        let mut map_vaddr = seg_start;
        while map_vaddr < seg_end {
            match uspace.page_table().query(map_vaddr) {
                Ok((_, flags, _)) if !flags.is_empty() => {
                    if let Some(start) = pending_start.take() {
                        if let Err(err) = uspace.map_alloc(
                            start,
                            map_vaddr - start,
                            segement.flags,
                            populate_segment,
                        ) {
                            if let Some(count) = should_log_map_alloc_failure() {
                                warn!(
                                    "map_alloc failed for {} range [{:#x}, {:#x}) flags {:?} err={:?} [sampled count={}]",
                                    path,
                                    start.as_usize(),
                                    map_vaddr.as_usize(),
                                    segement.flags,
                                    err,
                                    count
                                );
                            }
                            return Err(err);
                        }
                    }
                    let merged = flags | segement.flags;
                    if merged != flags {
                        uspace.protect(map_vaddr, PAGE_SIZE_4K, merged)?;
                    }
                }
                _ => {
                    pending_start.get_or_insert(map_vaddr);
                }
            }
            map_vaddr += PAGE_SIZE_4K;
        }
        if let Some(start) = pending_start.take() {
            if let Err(err) =
                uspace.map_alloc(start, seg_end - start, segement.flags, populate_segment)
            {
                if let Some(count) = should_log_map_alloc_failure() {
                    warn!(
                        "map_alloc failed for {} range [{:#x}, {:#x}) flags {:?} err={:?} [sampled count={}]",
                        path,
                        start.as_usize(),
                        seg_end.as_usize(),
                        segement.flags,
                        err,
                        count
                    );
                }
                return Err(err);
            }
        }
        if !populate_segment && !seg_file_data.is_empty() {
            uspace.alloc_for_lazy(seg_start, seg_file_data.len())?;
        }
        if let Err(err) = uspace.write(seg_start, seg_file_data) {
            for page in
                PageIter4K::new(seg_start, (seg_start + seg_file_data.len()).align_up_4k()).unwrap()
            {
                match uspace.page_table().query(page) {
                    Ok((_, flags, _)) if !flags.is_empty() => {}
                    Ok((paddr, flags, _)) => {
                        warn!(
                            "segment page not present: path={} page={:#x} paddr={:#x} flags={:?}",
                            path,
                            page.as_usize(),
                            paddr.as_usize(),
                            flags
                        );
                        break;
                    }
                    Err(query_err) => {
                        warn!(
                            "segment page query failed: path={} page={:#x} err={:?}",
                            path,
                            page.as_usize(),
                            query_err
                        );
                        break;
                    }
                }
            }
            warn!(
                "write segment failed: path={} vaddr={:#x} len={} err={:?}",
                path,
                seg_start.as_usize(),
                seg_file_data.len(),
                err
            );
            return Err(err);
        }
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("fence.i");
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!("ibar 0");
        }
    }
    Ok(())
}

fn elf_heap_bottom(elf_parser: &ELFParser) -> VirtAddr {
    elf_parser
        .ph_load()
        .iter()
        .map(|seg| (seg.vaddr + seg.memsz as usize).align_up_4k())
        .max()
        .unwrap_or_else(|| elf_parser.entry().into())
}

fn elf_phdr_addr(elf_parser: &ELFParser) -> usize {
    if let Some(phdr) = elf_parser
        .elf()
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Phdr))
    {
        return phdr.virtual_addr() as usize + elf_parser.base();
    }

    let phoff = elf_parser.elf().header.pt2.ph_offset() as usize;
    if let Some(load) = elf_parser.elf().program_iter().find(|ph| {
        ph.get_type() == Ok(xmas_elf::program::Type::Load)
            && ph.offset() as usize <= phoff
            && phoff < ph.offset() as usize + ph.file_size() as usize
    }) {
        return elf_parser.base() + load.virtual_addr() as usize + phoff - load.offset() as usize;
    }

    phoff + elf_parser.base()
}

/// Map the elf file to the user address space.
///
/// # Arguments
/// - `args`: The arguments of the user app. The first argument is the path of the user app.
/// - `elf_parser`: The parser of the elf file.
/// - `uspace`: The address space of the user app.
///
/// # Returns
/// - The entry point of the user app.
fn map_elf(
    program_path: &str,
    _args: &mut VecDeque<String>,
    elf_parser: &ELFParser,
    uspace: &mut AddrSpace,
) -> AxResult<(VirtAddr, [AuxvEntry; 17], Option<ElfTlsInfo>)> {
    let elf = elf_parser.elf();
    map_single_elf(program_path, elf_parser, uspace)?;
    let mut auxv = elf_parser.auxv_vector(PAGE_SIZE_4K);
    if let Some(entry) = auxv
        .iter_mut()
        .find(|entry| entry.get_type() == AuxvType::PHDR)
    {
        *entry.value_mut_ref() = elf_phdr_addr(elf_parser);
    }
    if let Some(interp) = elf
        .program_iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Interp))
    {
        let interp = match interp.get_data(elf) {
            Ok(SegmentData::Undefined(data)) => data,
            _ => panic!("Invalid data in Interp Elf Program Header"),
        };

        let interp_path = from_utf8(interp)
            .map_err(|_| AxError::InvalidInput)?
            .trim_matches(char::from(0));
        let real_interp_path = resolve_interp_path(program_path, interp_path)?;
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        let tls_layout =
            if is_musl_loader_path(interp_path) || is_musl_loader_path(real_interp_path.as_str()) {
                InitialTlsLayout::Musl
            } else {
                InitialTlsLayout::Generic
            };
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        let main_tls = elf_tls_info(elf, elf.input, tls_layout);
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        let interp_log_slot = if should_trace_online_loader(program_path) {
            take_diag_slot(&ONLINE_INTERP_DIAG_LOG_COUNT, ONLINE_INTERP_DIAG_LOG_LIMIT)
        } else {
            None
        };
        debug!(
            "load interpreter: program_path={} interp_path={} real_interp_path={}",
            program_path, interp_path, real_interp_path
        );

        let interp_data = read_user_image(real_interp_path.as_str()).map_err(|err| {
            warn!(
                "read interpreter failed: program_path={} interp_path={} real_interp_path={} err={:?}",
                program_path,
                interp_path,
                real_interp_path,
                err
            );
            err
        })?;
        let interp_elf = ElfFile::new(interp_data.as_slice()).map_err(|err| {
            let bytes = interp_data.as_slice();
            let prefix_len = bytes.len().min(16);
            warn!(
                "parse interpreter elf failed: real_interp_path={} len={} prefix={:x?} err={}",
                real_interp_path,
                bytes.len(),
                &bytes[..prefix_len],
                err
            );
            AxError::InvalidData
        })?;
        let uspace_base = uspace.base().as_usize();

        let interp_elf_parser = ELFParser::new(
            &interp_elf,
            axconfig::plat::USER_INTERP_BASE,
            None,
            uspace_base,
        )
        .map_err(|err| {
            warn!(
                "build interpreter parser failed: real_interp_path={} err={}",
                real_interp_path, err
            );
            AxError::InvalidData
        })?;
        map_single_elf(real_interp_path.as_str(), &interp_elf_parser, uspace)?;
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        {
            let interp_tls = interp_elf
                .program_iter()
                .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Tls))
                .and_then(|ph| tls_info_from_ph(interp_data.as_slice(), &ph, tls_layout));
            let main_tls_summary = tls_info_summary(main_tls.as_ref());
            let interp_tls_summary = tls_info_summary(interp_tls.as_ref());
            let entry_tls = interp_tls.or(main_tls);
            if let Some(slot) = interp_log_slot {
                warn!(
                    "[online-interp:{}] program_path={} interp_path={} real_interp_path={} tls_layout={} main_tls={} interp_tls={} entry_tls={}",
                    slot,
                    program_path,
                    interp_path,
                    real_interp_path,
                    tls_layout_name(tls_layout),
                    main_tls_summary,
                    interp_tls_summary,
                    tls_info_summary(entry_tls.as_ref()),
                );
            }
            for entry in &mut auxv {
                if entry.get_type() == kernel_elf_parser::AuxvType::BASE {
                    *entry.value_mut_ref() = interp_elf_parser.base();
                    break;
                }
            }
            return Ok((interp_elf_parser.entry().into(), auxv, entry_tls));
        }
        for entry in &mut auxv {
            if entry.get_type() == kernel_elf_parser::AuxvType::BASE {
                *entry.value_mut_ref() = interp_elf_parser.base();
                break;
            }
        }
        return Ok((interp_elf_parser.entry().into(), auxv, None));
    }
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    {
        let entry_tls = elf_tls_info(elf, elf.input, InitialTlsLayout::Generic);
        Ok((elf_parser.entry().into(), auxv, entry_tls))
    }
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    {
        Ok((elf_parser.entry().into(), auxv, None))
    }
}

/// Load the user app to the user address space.
///
/// # Arguments
/// - `args`: The arguments of the user app. The first argument is the path of the user app.
/// - `uspace`: The address space of the user app.
///
/// # Returns
/// - The entry point of the user app.
/// - The stack pointer of the user app.
/// - The initial program break.
fn base_env() -> Vec<String> {
    vec![
        "SHLVL=1".into(),
        "HOME=/root".into(),
        "PWD=/".into(),
        "PATH=/ltp/testcases/bin:/bin:/usr/bin:/usr/sbin:/".into(),
        "TMPDIR=/tmp".into(),
        "LC_ALL=C".into(),
        "LANG=C".into(),
        "LC_CTYPE=C".into(),
        "LOCPATH=/usr/lib/locale".into(),
        "LTPROOT=/ltp".into(),
        "LTP_IPC_PATH=/tmp".into(),
        "GCC_EXEC_PREFIX=/riscv64-linux-musl-native/bin/../lib/gcc/".into(),
        "COLLECT_GCC=./riscv64-linux-musl-native/bin/riscv64-linux-musl-gcc".into(),
        "COLLECT_LTO_WRAPPER=/riscv64-linux-musl-native/bin/../libexec/gcc/riscv64-linux-musl/11.2.1/lto-wrapper".into(),
        "COLLECT_GCC_OPTIONS='-march=rv64gc' '-mabi=lp64d' '-march=rv64imafdc' '-dumpdir' 'a.'".into(),
        "LIBRARY_PATH=/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib".into(),
        "LD_LIBRARY_PATH=/glibc/lib:/glibc/lib64:/musl/lib:/musl/lib64:/lib64:/lib".into(),
    ]
}

pub fn runtime_env_for(program_path: &str) -> Vec<String> {
    let mut env = base_env();
    let cwd = axfs::api::current_dir().unwrap_or_else(|_| "/".into());
    for entry in &mut env {
        if entry.starts_with("PWD=") {
            *entry = alloc::format!("PWD={cwd}");
            break;
        }
    }
    let prefixes = runtime_search_prefixes(program_path);
    if let Some(ltp_prefix) = prefixes.iter().find(|prefix| {
        axfs::api::absolute_path_exists(alloc::format!("{prefix}/ltp/testcases/bin").as_str())
    }) {
        let ltp_root = alloc::format!("{ltp_prefix}/ltp");
        let ltp_bin = alloc::format!("{ltp_root}/testcases/bin");
        for entry in &mut env {
            if entry.starts_with("PATH=") {
                let base = entry.trim_start_matches("PATH=");
                *entry = alloc::format!("PATH={ltp_bin}:{base}");
            } else if entry.starts_with("LTPROOT=") {
                *entry = alloc::format!("LTPROOT={ltp_root}");
            }
        }
    }
    if let Some(prefix) = prefixes.into_iter().find(|prefix| {
        prefix != "/"
            && interp_library_search_dirs(prefix.as_str())
                .into_iter()
                .any(|dir| axfs::api::absolute_path_exists(dir.as_str()))
    }) {
        let mut lib_dirs = interp_library_search_dirs(prefix.as_str())
            .into_iter()
            .filter(|dir| axfs::api::absolute_path_exists(dir.as_str()))
            .collect::<Vec<_>>();
        lib_dirs.push("/lib64".into());
        lib_dirs.push("/lib".into());
        let joined = lib_dirs.join(":");
        for entry in &mut env {
            if entry.starts_with("LIBRARY_PATH=") {
                *entry = alloc::format!("LIBRARY_PATH={joined}");
            } else if entry.starts_with("LD_LIBRARY_PATH=") {
                *entry = alloc::format!("LD_LIBRARY_PATH={joined}");
            }
        }

        let locale_dirs = [
            alloc::format!("{prefix}/usr/lib/locale"),
            alloc::format!("{prefix}/lib/locale"),
            "/usr/lib/locale".into(),
            "/usr/lib/locale/C.utf8".into(),
            "/usr/lib/locale/C.UTF-8".into(),
        ];
        let locale_path = locale_dirs
            .into_iter()
            .filter(|dir| axfs::api::absolute_path_exists(dir.as_str()))
            .collect::<Vec<_>>()
            .join(":");
        if !locale_path.is_empty() {
            for entry in &mut env {
                if entry.starts_with("LOCPATH=") {
                    *entry = alloc::format!("LOCPATH={locale_path}");
                    break;
                }
            }
        }
    }
    env
}

#[allow(dead_code)]
pub fn default_env() -> Vec<String> {
    base_env()
}

fn load_user_app_inner(
    program_path: &str,
    args: &mut VecDeque<String>,
    env: &[String],
    uspace: &mut AddrSpace,
    depth: usize,
) -> AxResult<(VirtAddr, VirtAddr, VirtAddr, usize, usize)> {
    load_user_app_inner_with_image(program_path, args, env, uspace, depth, None)
}

fn load_user_app_inner_with_image(
    program_path: &str,
    args: &mut VecDeque<String>,
    env: &[String],
    uspace: &mut AddrSpace,
    depth: usize,
    initial_image: Option<ExecImage>,
) -> AxResult<(VirtAddr, VirtAddr, VirtAddr, usize, usize)> {
    if args.is_empty() {
        return Err(AxError::InvalidInput);
    }
    if depth > 4 {
        return Err(AxError::InvalidInput);
    }
    if let Some(applet) = virtual_busybox_applet(program_path) {
        if let Some((real_busybox, mut new_args)) =
            rewrite_to_busybox_applet(program_path, args, applet)
        {
            return load_user_app_inner(&real_busybox, &mut new_args, env, uspace, depth + 1);
        }
    }
    if let Some(applet) = maybe_busybox_applet_path(program_path) {
        if is_busybox_symlink_applet(program_path, applet.as_str()) {
            if let Some((real_busybox, mut new_args)) =
                rewrite_to_busybox_applet(program_path, args, applet.as_str())
            {
                return load_user_app_inner(
                    &real_busybox,
                    &mut new_args,
                    env,
                    uspace,
                    depth + 1,
                );
            }
        }
    }
    let file_data = match initial_image {
        Some(image) => image,
        None => read_user_image(program_path)?,
    };
    let elf = match ElfFile::new(file_data.as_slice()) {
        Ok(elf) => elf,
        Err(_) => {
            if let Some((busybox_target, applet)) = parse_busybox_exec_wrapper(file_data.as_slice())
            {
                let real_busybox = resolve_busybox_binary_candidate(busybox_target.as_str(), 0)
                    .unwrap_or_else(|| busybox_target.clone());
                let mut new_args = VecDeque::new();
                new_args.push_back(real_busybox.clone());
                let applet = applet
                    .filter(|applet| applet != "busybox")
                    .or_else(|| inferred_busybox_applet_path(program_path));
                let skip = if let Some(applet) = applet {
                    let skip = args
                        .front()
                        .is_some_and(|first| {
                            argv0_matches_exec_target(first.as_str(), program_path, applet.as_str())
                        }) as usize;
                    new_args.push_back(applet);
                    skip
                } else {
                    args.front()
                        .is_some_and(|first| {
                            first == program_path
                                || first == absolute_exec_path(program_path).as_str()
                                || first == program_path.rsplit('/').next().unwrap_or("")
                        }) as usize
                };
                for arg in args.iter().skip(skip) {
                    new_args.push_back(arg.clone());
                }
                return load_user_app_inner(&real_busybox, &mut new_args, env, uspace, depth + 1);
            }
            if let Some(applet) = maybe_busybox_applet_path(program_path) {
                let real_busybox = resolve_busybox_binary(program_path)
                    .unwrap_or_else(|| String::from("/busybox"));
                let mut new_args = VecDeque::new();
                new_args.push_back(real_busybox.clone());
                new_args.push_back(applet);
                for arg in args.iter().skip(1) {
                    new_args.push_back(arg.clone());
                }
                return load_user_app_inner(&real_busybox, &mut new_args, env, uspace, depth + 1);
            }
            let (interp_path, interp_arg) = parse_shebang(file_data.as_slice())
                .unwrap_or_else(|| (String::from("/bin/sh"), None));
            let (real_interp, mut new_args) =
                rewrite_shebang_args(program_path, args, &interp_path, interp_arg.as_deref());
            return load_user_app_inner(&real_interp, &mut new_args, env, uspace, depth + 1);
        }
    };

    let uspace_base = uspace.base().as_usize();
    let pie_bias = uspace_base.max(USER_PIE_MIN_BIAS);
    let elf_parser = ELFParser::new(
        &elf,
        axconfig::plat::USER_INTERP_BASE,
        Some(pie_bias as isize),
        uspace_base,
    )
    .map_err(|_| AxError::InvalidData)?;

    let heap_bottom = elf_heap_bottom(&elf_parser);
    let (entry, mut auxv, entry_tls) = map_elf(program_path, args, &elf_parser, uspace)?;
    // The user stack is divided into two parts:
    // `ustack_start` -> `ustack_pointer`: It is the stack space that users actually read and write.
    // `ustack_pointer` -> `ustack_end`: It is the space that contains the arguments, environment variables and auxv passed to the app.
    //  When the app starts running, the stack pointer points to `ustack_pointer`.
    let ustack_end = VirtAddr::from_usize(axconfig::plat::USER_STACK_TOP);
    let ustack_size = axconfig::plat::USER_STACK_SIZE;
    let ustack_start = ustack_end - ustack_size;
    #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
    let user_tp = entry_tls
        .as_ref()
        .map(|tls| map_initial_thread_tls(uspace, tls, ustack_start))
        .transpose()?
        .flatten()
        .map(|tp| tp.as_usize())
        .unwrap_or(0);
    #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
    let user_tp = 0usize;
    debug!(
        "Mapping user stack: {:#x?} -> {:#x?}",
        ustack_start, ustack_end
    );
    let stack_data = app_stack_region(
        args.make_contiguous(),
        env,
        &mut auxv,
        ustack_start,
        ustack_size,
    );
    uspace.map_alloc(
        ustack_start,
        ustack_size,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        false,
    )?;
    if let Err(err) = crate::signal::map_signal_trampoline(uspace) {
        warn!(
            "map signal trampoline failed for {}: {:?}",
            program_path, err
        );
        return Err(err);
    }

    let user_sp = ustack_end - stack_data.len();
    uspace.alloc_for_lazy(user_sp, stack_data.len())?;
    info!(
        "load_user_app path={} entry={:#x} user_sp={:#x} phdr={:#x} phent={} phnum={}",
        program_path,
        entry.as_usize(),
        user_sp.as_usize(),
        auxv[0].value(),
        auxv[1].value(),
        auxv[2].value(),
    );
    log_online_load_diag(
        program_path,
        env,
        entry,
        user_sp,
        heap_bottom,
        user_tp,
        &auxv,
    );

    if let Err(err) = uspace.write(user_sp, stack_data.as_slice()) {
        warn!(
            "write user stack failed: path={} user_sp={:#x} len={} err={:?}",
            program_path,
            user_sp.as_usize(),
            stack_data.len(),
            err
        );
        return Err(err);
    }
    Ok((entry, user_sp, heap_bottom, user_tp, elf_parser.base()))
}

pub fn load_user_app(
    program_path: &str,
    args: &mut VecDeque<String>,
    env: &[String],
    uspace: &mut AddrSpace,
) -> AxResult<(VirtAddr, VirtAddr, VirtAddr, usize, usize)> {
    load_user_app_inner(program_path, args, env, uspace, 0)
}

pub fn load_user_app_from_bytes(
    program_path: &str,
    image: Vec<u8>,
    args: &mut VecDeque<String>,
    env: &[String],
    uspace: &mut AddrSpace,
) -> AxResult<(VirtAddr, VirtAddr, VirtAddr, usize, usize)> {
    load_user_app_inner_with_image(
        program_path,
        args,
        env,
        uspace,
        0,
        Some(ExecImage::Heap(image)),
    )
}

#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool) -> bool {
    const SIGSEGV: usize = 11;
    #[cfg(target_arch = "riscv64")]
    fn clone08_stack_slots(current: &axtask::CurrentTask) -> Option<[u64; 4]> {
        let mut slots = [0u64; 4];
        let addrs = [0x3fffff8f0usize, 0x3fffff8f8, 0x3fffff900, 0x3fffff908];
        let mut aspace = current.task_ext().aspace.lock();
        for (slot, addr) in slots.iter_mut().zip(addrs) {
            aspace
                .read(VirtAddr::from_usize(addr), unsafe {
                    core::slice::from_raw_parts_mut(
                        (slot as *mut u64).cast::<u8>(),
                        core::mem::size_of::<u64>(),
                    )
                })
                .ok()?;
        }
        Some(slots)
    }

    let current = axtask::current();
    let exec_path = if !unsafe { current.task_ext_ptr() }.is_null() {
        current.task_ext().exec_path()
    } else {
        alloc::string::String::new()
    };
    let trace_mprotect02 = is_user && should_trace_mprotect02_fault(exec_path.as_str());
    let trace_mremap = is_user && should_trace_mremap_fault(exec_path.as_str());
    if trace_mprotect02 {
        if let Some(slot) = take_diag_slot(&MPROTECT02_FAULT_LOG_COUNT, MPROTECT02_FAULT_LOG_LIMIT)
        {
            warn!(
                "[mprotect02-fault:{}] task={} pid={} vaddr={:#x} access={:?} exec_path={}",
                slot,
                current.id_name(),
                current.task_ext().proc_id,
                vaddr,
                access_flags,
                exec_path,
            );
        }
    }
    if trace_mremap {
        if let Some(slot) = take_diag_slot(&MREMAP_FAULT_LOG_COUNT, MREMAP_FAULT_LOG_LIMIT) {
            warn!(
                "[mremap-fault:{}] task={} pid={} vaddr={:#x} access={:?} exec_path={}",
                slot,
                current.id_name(),
                current.task_ext().proc_id,
                vaddr,
                access_flags,
                exec_path,
            );
        }
    }
    if is_user && should_trace_clone08() && current.name().contains("clone08") {
        let page = vaddr.align_down_4k();
        let query = if !unsafe { current.task_ext_ptr() }.is_null() {
            current
                .task_ext()
                .aspace
                .lock()
                .page_table()
                .query(page)
                .ok()
        } else {
            None
        };
        warn!(
            "clone08 page fault enter task={} vaddr={:#x} page={:#x} access={:?} query={:?}",
            current.id_name(),
            vaddr,
            page,
            access_flags,
            query
        );
        #[cfg(target_arch = "riscv64")]
        if page.as_usize() == 0x3fffff000 {
            warn!(
                "clone08 stack slots before fault task={} page={:#x} slots={:x?}",
                current.id_name(),
                page,
                clone08_stack_slots(&current)
            );
        }
    }
    #[cfg(feature = "contest_diag_logs")]
    if is_user && access_flags.contains(MappingFlags::WRITE) && current.name().contains("userboot")
    {
        log_userboot_fault(&current, vaddr, access_flags);
    }
    let task_ext_ptr = unsafe { current.task_ext_ptr() };
    if !task_ext_ptr.is_null() {
        let aspace = &current.task_ext().aspace;
        let try_handle_fault = || {
            if aspace.is_owned_by_current() {
                unsafe { aspace.get_mut_unchecked() }.handle_page_fault(vaddr, access_flags)
            } else {
                aspace.lock().handle_page_fault(vaddr, access_flags)
            }
        };
        let mut handled = try_handle_fault();
        if !handled && is_user && global_allocator().available_pages() == 0 {
            let reclaimed = crate::task::reclaim_runtime_memory_detail("page_fault_oom");
            if reclaimed.exited_tasks > 0
                || reclaimed.stack_pages > 0
                || reclaimed.exec_cache_pages > 0
                || reclaimed.fs_cache_entries > 0
            {
                warn!(
                    "page fault retry after runtime reclaim: task={} pid={} vaddr={:#x} access={:?} reclaimed_exited_tasks={} reclaimed_stack_pages={} reclaimed_exec_cache_pages={} reclaimed_fs_cache_entries={}",
                    current.id_name(),
                    current.task_ext().proc_id,
                    vaddr,
                    access_flags,
                    reclaimed.exited_tasks,
                    reclaimed.stack_pages,
                    reclaimed.exec_cache_pages,
                    reclaimed.fs_cache_entries,
                );
                handled = try_handle_fault();
            }
            if !handled && global_allocator().available_pages() == 0 {
                warn!(
                    "unrecoverable user page fault under OOM: task={} pid={} exec_path={} vaddr={:#x} access={:?}; terminating task",
                    current.id_name(),
                    current.task_ext().proc_id,
                    current.task_ext().exec_path(),
                    vaddr,
                    access_flags,
                );
                crate::task::exit_current_task(
                    crate::task::wait_status_signaled(SIGSEGV, true),
                    true,
                    true,
                );
            }
        }
        if trace_mprotect02 {
            if let Some(slot) =
                take_diag_slot(&MPROTECT02_FAULT_LOG_COUNT, MPROTECT02_FAULT_LOG_LIMIT)
            {
                warn!(
                    "[mprotect02-fault-handled:{}] task={} pid={} handled={} vaddr={:#x} access={:?}",
                    slot,
                    current.id_name(),
                    current.task_ext().proc_id,
                    handled,
                    vaddr,
                    access_flags,
                );
            }
        }
        if trace_mremap {
            if let Some(slot) = take_diag_slot(&MREMAP_FAULT_LOG_COUNT, MREMAP_FAULT_LOG_LIMIT) {
                warn!(
                    "[mremap-fault-handled:{}] task={} pid={} handled={} vaddr={:#x} access={:?}",
                    slot,
                    current.id_name(),
                    current.task_ext().proc_id,
                    handled,
                    vaddr,
                    access_flags,
                );
            }
        }
        if handled {
            if is_user && should_trace_clone08() && current.name().contains("clone08") {
                let page = vaddr.align_down_4k();
                let query = if aspace.is_owned_by_current() {
                    unsafe { aspace.get_mut_unchecked() }
                        .page_table()
                        .query(page)
                        .ok()
                } else {
                    aspace.lock().page_table().query(page).ok()
                };
                warn!(
                    "clone08 page fault handled task={} vaddr={:#x} page={:#x} access={:?} query={:?}",
                    current.id_name(),
                    vaddr,
                    page,
                    access_flags,
                    query
                );
                #[cfg(target_arch = "riscv64")]
                if page.as_usize() == 0x3fffff000 {
                    warn!(
                        "clone08 stack slots after fault task={} page={:#x} slots={:x?}",
                        current.id_name(),
                        page,
                        clone08_stack_slots(&current)
                    );
                }
            }
            #[cfg(feature = "contest_diag_logs")]
            if is_user
                && access_flags.contains(MappingFlags::WRITE)
                && current.name().contains("userboot")
            {
                log_userboot_fault_handled(&current, vaddr, access_flags);
            }
            return true;
        }
    }

    if !is_user {
        return false;
    }

    let trap = crate::task::read_trapframe_from_kstack(current.get_kernel_stack_top().unwrap());
    #[cfg(target_arch = "riscv64")]
    let (thread_ptr, return_addr, global_ptr) = (trap.regs.tp, trap.regs.ra, trap.regs.gp);
    #[cfg(target_arch = "loongarch64")]
    let (thread_ptr, return_addr, global_ptr) = (trap.regs[2], trap.regs[1], 0usize);
    #[cfg(target_arch = "loongarch64")]
    {
        let exec_path = current.task_ext().exec_path();
        if exec_path.contains("/basic/") {
            if let Some(slot) = take_diag_slot(
                &ONLINE_BASIC_LA_FAULT_LOG_COUNT,
                ONLINE_BASIC_LA_FAULT_LOG_LIMIT,
            ) {
                let fault_page = vaddr.align_down_4k();
                let pc_page = VirtAddr::from_usize(trap.get_ip()).align_down_4k();
                let (fault_query, pc_query) = {
                    let mut aspace = current.task_ext().aspace.lock();
                    (
                        aspace.page_table().query(fault_page).ok(),
                        aspace.page_table().query(pc_page).ok(),
                    )
                };
                warn!(
                    "[online-basic-la-fault:{}] task={} pid={} exec_path={} vaddr={:#x} page={:#x} access={:?} ip={:#x} sp={:#x} tp={:#x} ra={:#x} a0={:#x} a1={:#x} a2={:#x} pc_page={:#x} pc_query={:?} fault_query={:?}",
                    slot,
                    current.id_name(),
                    current.task_ext().proc_id,
                    exec_path,
                    vaddr,
                    fault_page,
                    access_flags,
                    trap.get_ip(),
                    trap.get_sp(),
                    thread_ptr,
                    return_addr,
                    trap.arg0(),
                    trap.arg1(),
                    trap.arg2(),
                    pc_page,
                    pc_query,
                    fault_query,
                );
            }
        }
    }
    debug!(
        "{}: page fault at {:#x}, ip={:#x}, sp={:#x}, tp={:#x}, ra={:#x}, gp={:#x}, a0={:#x}, a1={:#x}, a2={:#x}, deliver SIGSEGV",
        current.id_name(),
        vaddr,
        trap.get_ip(),
        trap.get_sp(),
        thread_ptr,
        return_addr,
        global_ptr,
        trap.arg0(),
        trap.arg1(),
        trap.arg2(),
    );
    if trace_mprotect02 {
        if let Some(slot) = take_diag_slot(&MPROTECT02_FAULT_LOG_COUNT, MPROTECT02_FAULT_LOG_LIMIT)
        {
            warn!(
                "[mprotect02-sigsegv:{}] task={} pid={} vaddr={:#x} ip={:#x} sp={:#x}",
                slot,
                current.id_name(),
                current.task_ext().proc_id,
                vaddr,
                trap.get_ip(),
                trap.get_sp(),
            );
        }
    }
    if trace_mremap {
        if let Some(slot) = take_diag_slot(&MREMAP_FAULT_LOG_COUNT, MREMAP_FAULT_LOG_LIMIT) {
            warn!(
                "[mremap-sigsegv:{}] task={} pid={} vaddr={:#x} ip={:#x} sp={:#x}",
                slot,
                current.id_name(),
                current.task_ext().proc_id,
                vaddr,
                trap.get_ip(),
                trap.get_sp(),
            );
        }
    }
    crate::signal::send_current_signal(SIGSEGV);
    let kstack_top = current.get_kernel_stack_top().unwrap();
    let mut updated_trap = trap;
    crate::signal::dispatch_current_signals(&mut updated_trap);
    if trace_mprotect02 {
        if let Some(slot) = take_diag_slot(&MPROTECT02_FAULT_LOG_COUNT, MPROTECT02_FAULT_LOG_LIMIT)
        {
            warn!(
                "[mprotect02-dispatch:{}] task={} pid={} new_ip={:#x} new_sp={:#x}",
                slot,
                current.id_name(),
                current.task_ext().proc_id,
                updated_trap.get_ip(),
                updated_trap.get_sp(),
            );
        }
    }
    crate::task::write_trapframe_to_kstack(kstack_top, &updated_trap);
    true
}
