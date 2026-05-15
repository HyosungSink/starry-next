use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::ffi::{c_char, c_void};

use arceos_posix_api::{self as api, get_file_like};
use axerrno::LinuxError;
use axsync::Mutex;
use spin::Once;

use super::{handle_kernel_path, read_user_path, resolve_existing_path};
use crate::{
    syscall_body,
    usercopy::{copy_from_user, copy_to_user},
};

const XATTR_CREATE: i32 = 1;
const XATTR_REPLACE: i32 = 2;
const XATTR_NAME_MAX: usize = 255;
const XATTR_SIZE_MAX: usize = 64 * 1024;
const S_IFMT: u32 = 0o170000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;
const S_IFDIR: u32 = 0o040000;
const S_IFBLK: u32 = 0o060000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct XattrKey {
    target: String,
    name: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetKind {
    Regular,
    Directory,
    Other,
}

struct XattrTarget {
    key: String,
    kind: TargetKind,
}

fn xattrs() -> &'static Mutex<BTreeMap<XattrKey, Vec<u8>>> {
    static XATTRS: Once<Mutex<BTreeMap<XattrKey, Vec<u8>>>> = Once::new();
    XATTRS.call_once(|| Mutex::new(BTreeMap::new()))
}

pub(crate) fn clear_xattrs_under_mount(path: &str) {
    let mut prefix = handle_kernel_path(api::AT_FDCWD, path, false)
        .map(|path| path.to_string())
        .unwrap_or_else(|_| path.to_string());
    while prefix.len() > 1 && prefix.ends_with('/') {
        prefix.pop();
    }
    let child_prefix = if prefix == "/" {
        String::from("/")
    } else {
        alloc::format!("{prefix}/")
    };
    xattrs()
        .lock()
        .retain(|key, _| key.target != prefix && !key.target.starts_with(child_prefix.as_str()));
}

fn validate_name(name: *const c_char) -> Result<String, LinuxError> {
    let name = read_user_path(name)?;
    if name.is_empty() || name.len() > XATTR_NAME_MAX {
        return Err(LinuxError::ERANGE);
    }
    let Some((namespace, suffix)) = name.split_once('.') else {
        return Err(LinuxError::EOPNOTSUPP);
    };
    if suffix.is_empty() {
        return Err(LinuxError::ERANGE);
    }
    if !matches!(namespace, "user" | "security" | "trusted" | "system") {
        return Err(LinuxError::EOPNOTSUPP);
    }
    Ok(name)
}

fn kind_from_attr(attr: axfs::fops::FileAttr) -> TargetKind {
    let file_type = attr.file_type();
    if file_type.is_file() {
        TargetKind::Regular
    } else if file_type.is_dir() {
        TargetKind::Directory
    } else {
        TargetKind::Other
    }
}

fn kind_from_stat_mode(mode: u32) -> TargetKind {
    match mode & S_IFMT {
        S_IFREG => TargetKind::Regular,
        S_IFDIR => TargetKind::Directory,
        S_IFIFO | S_IFCHR | S_IFBLK | S_IFSOCK => TargetKind::Other,
        _ => TargetKind::Other,
    }
}

fn target_from_path(
    path: *const c_char,
    follow_final_symlink: bool,
) -> Result<XattrTarget, LinuxError> {
    let raw = read_user_path(path)?;
    let resolved = handle_kernel_path(api::AT_FDCWD, raw.as_str(), false)?;
    let (resolved, attr) = resolve_existing_path(resolved.as_str(), follow_final_symlink)?;
    Ok(XattrTarget {
        key: resolved,
        kind: kind_from_attr(attr),
    })
}

fn target_from_fd(fd: i32) -> Result<XattrTarget, LinuxError> {
    let file = get_file_like(fd)?;
    if let Ok(file) = file.clone().into_any().downcast::<api::File>() {
        let path = file.path().to_string();
        let kind = axfs::api::metadata_raw_ax(path.as_str())
            .map(kind_from_attr)
            .unwrap_or(TargetKind::Regular);
        return Ok(XattrTarget { key: path, kind });
    }
    if let Ok(dir) = file.clone().into_any().downcast::<api::Directory>() {
        return Ok(XattrTarget {
            key: dir.path().to_string(),
            kind: TargetKind::Directory,
        });
    }
    let stat = file.stat()?;
    Ok(XattrTarget {
        key: alloc::format!("{}:{}", stat.st_dev, stat.st_ino),
        kind: kind_from_stat_mode(stat.st_mode),
    })
}

fn read_value(value: *const c_void, size: usize) -> Result<Vec<u8>, LinuxError> {
    if size > XATTR_SIZE_MAX {
        return Err(LinuxError::E2BIG);
    }
    if size > 0 && value.is_null() {
        return Err(LinuxError::EFAULT);
    }
    let mut data = vec![0u8; size];
    if size > 0 {
        copy_from_user(&mut data, value)?;
    }
    Ok(data)
}

fn get_xattr(
    target: XattrTarget,
    name: String,
    value: *mut c_void,
    size: usize,
) -> Result<isize, LinuxError> {
    let key = XattrKey {
        target: target.key,
        name,
    };
    let value_data = xattrs()
        .lock()
        .get(&key)
        .cloned()
        .ok_or(LinuxError::ENODATA)?;
    if size == 0 {
        return Ok(value_data.len() as isize);
    }
    if value.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if size < value_data.len() {
        return Err(LinuxError::ERANGE);
    }
    copy_to_user(value, value_data.as_slice())?;
    Ok(value_data.len() as isize)
}

fn set_xattr(
    target: XattrTarget,
    name: String,
    value: *const c_void,
    size: usize,
    flags: i32,
) -> Result<isize, LinuxError> {
    if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 {
        return Err(LinuxError::EINVAL);
    }
    if flags & XATTR_CREATE != 0 && flags & XATTR_REPLACE != 0 {
        return Err(LinuxError::EINVAL);
    }
    if name.starts_with("user.")
        && !matches!(target.kind, TargetKind::Regular | TargetKind::Directory)
    {
        return Err(LinuxError::EPERM);
    }
    let key = XattrKey {
        target: target.key,
        name,
    };
    let data = read_value(value, size)?;
    let mut xattrs = xattrs().lock();
    let exists = xattrs.contains_key(&key);
    if flags & XATTR_CREATE != 0 && exists {
        return Err(LinuxError::EEXIST);
    }
    if flags & XATTR_REPLACE != 0 && !exists {
        return Err(LinuxError::ENODATA);
    }
    xattrs.insert(key, data);
    Ok(0)
}

fn list_xattr(target: XattrTarget, list: *mut c_char, size: usize) -> Result<isize, LinuxError> {
    let mut names = Vec::new();
    for key in xattrs().lock().keys() {
        if key.target == target.key {
            names.extend_from_slice(key.name.as_bytes());
            names.push(0);
        }
    }
    if size == 0 {
        return Ok(names.len() as isize);
    }
    if list.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if size < names.len() {
        return Err(LinuxError::ERANGE);
    }
    copy_to_user(list.cast(), names.as_slice())?;
    Ok(names.len() as isize)
}

fn remove_xattr(target: XattrTarget, name: String) -> Result<isize, LinuxError> {
    let key = XattrKey {
        target: target.key,
        name,
    };
    if xattrs().lock().remove(&key).is_none() {
        return Err(LinuxError::ENODATA);
    }
    Ok(0)
}

pub(crate) fn sys_getxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    syscall_body!(sys_getxattr, {
        get_xattr(target_from_path(path, true)?, validate_name(name)?, value, size)
    })
}

pub(crate) fn sys_lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    syscall_body!(sys_lgetxattr, {
        get_xattr(
            target_from_path(path, false)?,
            validate_name(name)?,
            value,
            size,
        )
    })
}

pub(crate) fn sys_fgetxattr(
    fd: i32,
    name: *const c_char,
    value: *mut c_void,
    size: usize,
) -> isize {
    syscall_body!(sys_fgetxattr, {
        get_xattr(target_from_fd(fd)?, validate_name(name)?, value, size)
    })
}

pub(crate) fn sys_setxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: i32,
) -> isize {
    syscall_body!(sys_setxattr, {
        set_xattr(
            target_from_path(path, true)?,
            validate_name(name)?,
            value,
            size,
            flags,
        )
    })
}

pub(crate) fn sys_lsetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: i32,
) -> isize {
    syscall_body!(sys_lsetxattr, {
        set_xattr(
            target_from_path(path, false)?,
            validate_name(name)?,
            value,
            size,
            flags,
        )
    })
}

pub(crate) fn sys_fsetxattr(
    fd: i32,
    name: *const c_char,
    value: *const c_void,
    size: usize,
    flags: i32,
) -> isize {
    syscall_body!(sys_fsetxattr, {
        set_xattr(target_from_fd(fd)?, validate_name(name)?, value, size, flags)
    })
}

pub(crate) fn sys_listxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    syscall_body!(sys_listxattr, {
        list_xattr(target_from_path(path, true)?, list, size)
    })
}

pub(crate) fn sys_llistxattr(path: *const c_char, list: *mut c_char, size: usize) -> isize {
    syscall_body!(sys_llistxattr, {
        list_xattr(target_from_path(path, false)?, list, size)
    })
}

pub(crate) fn sys_flistxattr(fd: i32, list: *mut c_char, size: usize) -> isize {
    syscall_body!(sys_flistxattr, {
        list_xattr(target_from_fd(fd)?, list, size)
    })
}

pub(crate) fn sys_removexattr(path: *const c_char, name: *const c_char) -> isize {
    syscall_body!(sys_removexattr, {
        remove_xattr(target_from_path(path, true)?, validate_name(name)?)
    })
}

pub(crate) fn sys_lremovexattr(path: *const c_char, name: *const c_char) -> isize {
    syscall_body!(sys_lremovexattr, {
        remove_xattr(target_from_path(path, false)?, validate_name(name)?)
    })
}

pub(crate) fn sys_fremovexattr(fd: i32, name: *const c_char) -> isize {
    syscall_body!(sys_fremovexattr, {
        remove_xattr(target_from_fd(fd)?, validate_name(name)?)
    })
}
