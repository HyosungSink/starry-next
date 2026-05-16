use core::ffi::c_void;
use core::mem::MaybeUninit;

use alloc::string::String;
use alloc::vec::Vec;
use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use axtask::{current, TaskExtRef};
use memory_addr::{MemoryAddr, PageIter4K, VirtAddr};

pub fn ensure_user_range(
    start: VirtAddr,
    len: usize,
    access: MappingFlags,
) -> Result<(), LinuxError> {
    if len == 0 {
        return Ok(());
    }
    let task = current();
    let mut aspace = task.task_ext().aspace.lock();
    if start.checked_add(len).is_none() {
        return Err(LinuxError::EFAULT);
    }
    if !aspace.contains_range(start, len) {
        return Err(LinuxError::EFAULT);
    }
    let end = (start + len).align_up_4k();
    for page in PageIter4K::new(start.align_down_4k(), end).unwrap() {
        let mapped = matches!(
            aspace.page_table().query(page),
            Ok((_paddr, flags, _)) if !flags.is_empty() && flags.contains(access)
        );
        if mapped {
            continue;
        }
        let _ = aspace.handle_page_fault(page, access);
        let mapped_after = matches!(
            aspace.page_table().query(page),
            Ok((_paddr, flags, _)) if !flags.is_empty() && flags.contains(access)
        );
        if !mapped_after {
            return Err(LinuxError::EFAULT);
        }
    }
    Ok(())
}

pub fn copy_to_user(dst: *mut c_void, src: &[u8]) -> Result<(), LinuxError> {
    let start = VirtAddr::from(dst as usize);
    current()
        .task_ext()
        .aspace
        .lock()
        .write(start, src)
        .map_err(|_| LinuxError::EFAULT)
}

pub fn copy_from_user(dst: &mut [u8], src: *const c_void) -> Result<(), LinuxError> {
    let start = VirtAddr::from(src as usize);
    current()
        .task_ext()
        .aspace
        .lock()
        .read(start, dst)
        .map_err(|_| LinuxError::EFAULT)
}

pub fn write_value_to_user<T: Copy>(dst: *mut T, value: T) -> Result<(), LinuxError> {
    let bytes = unsafe {
        core::slice::from_raw_parts((&value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    copy_to_user(dst.cast::<c_void>(), bytes)
}

pub fn read_value_from_user<T: Copy>(src: *const T) -> Result<T, LinuxError> {
    let mut value = MaybeUninit::<T>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>())
    };
    copy_from_user(bytes, src.cast::<c_void>())?;
    Ok(unsafe { value.assume_init() })
}

pub fn read_cstring_from_user(src: *const u8, max_len: usize) -> Result<String, LinuxError> {
    if src.is_null() {
        return Err(LinuxError::EFAULT);
    }
    let mut bytes = Vec::with_capacity(max_len.min(256));
    for offset in 0..max_len {
        let addr = (src as usize)
            .checked_add(offset)
            .ok_or(LinuxError::EFAULT)? as *const u8;
        let byte = read_value_from_user(addr)?;
        if byte == 0 {
            return String::from_utf8(bytes).map_err(|_| LinuxError::EINVAL);
        }
        bytes.push(byte);
    }
    Err(LinuxError::ENAMETOOLONG)
}
