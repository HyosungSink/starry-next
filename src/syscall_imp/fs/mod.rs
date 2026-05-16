mod ctl;
mod fd_ops;
mod io;
mod pipe;
mod stat;

pub(crate) use self::ctl::*;
pub(crate) use self::fd_ops::*;
pub(crate) use self::io::*;
pub(crate) use self::pipe::*;
pub(crate) use self::stat::*;

pub(crate) fn read_user_path(
    path: *const core::ffi::c_char,
) -> Result<alloc::string::String, axerrno::LinuxError> {
    crate::usercopy::read_cstring_from_user(path.cast(), 4096)
}

pub(crate) fn validate_path_components(_path: &str) -> Result<(), axerrno::LinuxError> {
    Ok(())
}

pub(crate) fn resolve_existing_path(
    path: &str,
    follow_final_symlink: bool,
) -> Result<(alloc::string::String, axfs::fops::FileAttr), axerrno::LinuxError> {
    let attr = if follow_final_symlink {
        axfs::api::metadata_raw_ax(path)
    } else {
        axfs::api::metadata_raw_nofollow(path)
    }
    .map_err(axerrno::LinuxError::from)?;
    Ok((alloc::string::String::from(path), attr))
}

pub(crate) fn handle_user_path(
    dirfd: isize,
    path: *const u8,
    force_dir: bool,
) -> Result<arceos_posix_api::FilePath, axerrno::LinuxError> {
    if path.is_null() {
        return arceos_posix_api::handle_file_path(dirfd, None, force_dir)
            .map_err(axerrno::LinuxError::from);
    }
    let path = crate::usercopy::read_cstring_from_user(path, 4096)?;
    let path_cstr = alloc::ffi::CString::new(path).map_err(|_| axerrno::LinuxError::EINVAL)?;
    arceos_posix_api::handle_file_path(dirfd, Some(path_cstr.as_ptr().cast()), force_dir)
        .map_err(axerrno::LinuxError::from)
}

pub(crate) fn handle_kernel_path(
    dirfd: isize,
    path: &str,
    force_dir: bool,
) -> Result<arceos_posix_api::FilePath, axerrno::LinuxError> {
    validate_path_components(path)?;
    let path_cstr = alloc::ffi::CString::new(path).map_err(|_| axerrno::LinuxError::EINVAL)?;
    arceos_posix_api::handle_file_path(dirfd, Some(path_cstr.as_ptr().cast()), force_dir)
        .map_err(axerrno::LinuxError::from)
}

pub(crate) fn clear_xattrs_under_mount(_path: &str) {}
