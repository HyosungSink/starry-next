use alloc::{
    ffi::CString,
    string::{String, ToString},
    vec::Vec,
};
use core::ffi::c_char;

use arceos_posix_api::{self as api, FilePath};
use axerrno::LinuxError;
use axfs::fops::FileAttr;
mod aio;
mod ctl;
mod fd_ops;
mod io;
mod pipe;
mod stat;
mod xattr;

pub(crate) use self::aio::*;
pub(crate) use self::ctl::*;
pub(crate) use self::fd_ops::*;
pub(crate) use self::io::*;
pub(crate) use self::pipe::*;
pub(crate) use self::stat::*;
pub(crate) use self::xattr::*;

const MAX_PATH_COMPONENT_LEN: usize = 255;
const MAX_PATH_RESOLVE_DEPTH: usize = 40;

pub(crate) fn read_user_path(path: *const c_char) -> Result<String, LinuxError> {
    crate::usercopy::read_cstring_from_user(path.cast(), 4096)
}

pub(crate) fn validate_path_components(path: &str) -> Result<(), LinuxError> {
    if path.len() >= 4096 {
        return Err(LinuxError::ENAMETOOLONG);
    }
    for component in path.split('/').filter(|part| !part.is_empty()) {
        if component.len() > MAX_PATH_COMPONENT_LEN {
            return Err(LinuxError::ENAMETOOLONG);
        }
    }
    Ok(())
}

pub(crate) fn verify_searchable_prefixes(path: &str) -> Result<(), LinuxError> {
    let mut current = String::from("/");
    let parts: alloc::vec::Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    for component in parts.iter().take(parts.len().saturating_sub(1)) {
        current = if current == "/" {
            alloc::format!("/{component}")
        } else {
            alloc::format!("{current}/{component}")
        };
        let attr = axfs::api::metadata_raw_ax(current.as_str()).map_err(LinuxError::from)?;
        if !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
        if !axfs::api::can_access(current.as_str(), attr, true, false, false, true) {
            return Err(LinuxError::EACCES);
        }
    }
    Ok(())
}

fn normalize_lookup_path(path: &str) -> Result<String, LinuxError> {
    let mut resolved = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    if !resolved.starts_with('/') {
        let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
        resolved = if cwd == "/" {
            alloc::format!("/{resolved}")
        } else {
            alloc::format!("{cwd}/{resolved}")
        };
        resolved = axfs::api::canonicalize(resolved.as_str()).unwrap_or(resolved);
    }
    Ok(resolved)
}

fn join_path_component(parent: &str, component: &str) -> String {
    if parent == "/" {
        alloc::format!("/{component}")
    } else {
        alloc::format!("{parent}/{component}")
    }
}

fn append_path_component(path: &mut String, component: &str) {
    if path.is_empty() {
        path.push('/');
        path.push_str(component);
        return;
    }
    if path != "/" && !path.ends_with('/') {
        path.push('/');
    }
    path.push_str(component);
}

pub(crate) fn resolve_existing_path(
    path: &str,
    follow_final_symlink: bool,
) -> Result<(String, FileAttr), LinuxError> {
    let mut resolved = normalize_lookup_path(path)?;
    if resolved == "/proc" || resolved.starts_with("/proc/") {
        crate::task::sync_proc_pid_entries_for_path(resolved.as_str());
    }
    if crate::timekeeping::special_proc_file_exists(resolved.as_str()) {
        verify_searchable_prefixes(resolved.as_str())?;
        let attr = axfs::api::metadata_raw_ax("/proc/1/stat").map_err(LinuxError::from)?;
        return Ok((resolved, attr));
    }

    let require_final_dir = resolved.len() > 1 && resolved.ends_with('/');
    let mut components = resolved
        .split('/')
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect::<Vec<_>>();
    let mut current = String::from("/");
    let mut symlink_depth = 0usize;
    let mut index = 0usize;

    while index < components.len() {
        let is_final = index + 1 == components.len();
        let candidate = join_path_component(current.as_str(), components[index].as_str());
        if candidate == "/proc" || candidate.starts_with("/proc/") {
            crate::task::sync_proc_pid_entries_for_path(candidate.as_str());
        }
        if is_final && crate::timekeeping::special_proc_file_exists(candidate.as_str()) {
            let attr = axfs::api::metadata_raw_ax("/proc/1/stat").map_err(LinuxError::from)?;
            return Ok((candidate, attr));
        }

        if !is_final || follow_final_symlink {
            if let Ok(target) = axfs::api::readlink(candidate.as_str()) {
                symlink_depth += 1;
                if symlink_depth > MAX_PATH_RESOLVE_DEPTH {
                    return Err(LinuxError::ELOOP);
                }

                let target = String::from_utf8(target).map_err(|_| LinuxError::EINVAL)?;
                let mut next = if target.starts_with('/') {
                    target
                } else {
                    join_path_component(current.as_str(), target.as_str())
                };
                for component in components.iter().skip(index + 1) {
                    append_path_component(&mut next, component.as_str());
                }
                resolved = axfs::api::canonicalize(next.as_str()).unwrap_or(next);
                components = resolved
                    .split('/')
                    .filter(|part| !part.is_empty())
                    .map(String::from)
                    .collect();
                current.clear();
                current.push('/');
                index = 0;
                continue;
            }
        }

        let attr = if is_final && !follow_final_symlink {
            axfs::api::metadata_raw_nofollow(candidate.as_str()).map_err(LinuxError::from)?
        } else {
            axfs::api::metadata_raw_ax(candidate.as_str()).map_err(LinuxError::from)?
        };

        if !is_final {
            if !attr.is_dir() {
                return Err(LinuxError::ENOTDIR);
            }
            if !axfs::api::can_access(candidate.as_str(), attr, true, false, false, true) {
                return Err(LinuxError::EACCES);
            }
            current = candidate;
            index += 1;
            continue;
        }

        if require_final_dir && !attr.is_dir() {
            return Err(LinuxError::ENOTDIR);
        }
        axfs::api::note_mount_access(candidate.as_str());
        return Ok((candidate, attr));
    }

    let attr = axfs::api::metadata_raw_ax("/").map_err(LinuxError::from)?;
    axfs::api::note_mount_access("/");
    Ok((String::from("/"), attr))
}

pub(crate) fn handle_user_path(
    dirfd: isize,
    path: *const u8,
    force_dir: bool,
) -> Result<FilePath, LinuxError> {
    if path.is_null() {
        return api::handle_file_path(dirfd, None, force_dir).map_err(LinuxError::from);
    }
    let path = crate::usercopy::read_cstring_from_user(path, 4096)?;
    validate_path_components(path.as_str())?;
    let path_cstr = CString::new(path).map_err(|_| LinuxError::EINVAL)?;
    api::handle_file_path(dirfd, Some(path_cstr.as_ptr() as *const u8), force_dir)
        .map_err(LinuxError::from)
}

pub(crate) fn handle_kernel_path(
    dirfd: isize,
    path: &str,
    force_dir: bool,
) -> Result<FilePath, LinuxError> {
    let mut path = if path.is_empty() {
        if dirfd == api::AT_FDCWD {
            ".".to_string()
        } else {
            if dirfd < 0 {
                return Err(LinuxError::EINVAL);
            }
            api::Directory::from_fd(dirfd as i32)
                .map(|dir| dir.path().to_string())
                .map_err(|_| LinuxError::ENOENT)?
        }
    } else {
        path.to_string()
    };

    if !path.starts_with('/') {
        if dirfd == api::AT_FDCWD {
            let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
            path = if cwd == "/" {
                alloc::format!("/{path}")
            } else {
                alloc::format!("{cwd}/{path}")
            };
        } else {
            if dirfd < 0 {
                return Err(LinuxError::EINVAL);
            }
            let dir = api::Directory::from_fd(dirfd as i32).map_err(|_| LinuxError::ENOENT)?;
            path = if dir.path().ends_with('/') {
                alloc::format!("{}{}", dir.path(), path)
            } else {
                alloc::format!("{}/{}", dir.path(), path)
            };
        }
    }

    if force_dir && !path.ends_with('/') {
        path.push('/');
    }
    if path.ends_with('.') {
        path.push('/');
    }

    FilePath::new(&path).map_err(LinuxError::from)
}
