//! POSIX-compatible APIs for [ArceOS] modules
//!
//! [ArceOS]: https://github.com/arceos-org/arceos

#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(doc_cfg)]
#![feature(doc_auto_cfg)]
#![allow(clippy::missing_safety_doc)]

#[macro_use]
extern crate axlog;
extern crate axruntime;

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod utils;

mod imp;
pub use axio::PollState;
pub use utils::char_ptr_to_str;

/// Platform-specific constants and parameters.
pub mod config {
    pub use axconfig::*;
}

/// POSIX C types.
pub mod ctypes {
    #![allow(
        dead_code,
        non_snake_case,
        non_camel_case_types,
        non_upper_case_globals,
        clippy::upper_case_acronyms,
        missing_docs
    )]

    #[rustfmt::skip]
    include!(concat!(env!("OUT_DIR"), "/ctypes_gen.rs"));
}

pub use imp::io::{sys_read, sys_write, sys_writev};
#[cfg(feature = "fs")]
pub use imp::path_link::{AT_FDCWD, FilePath, HARDLINK_MANAGER, handle_file_path};
pub use imp::resources::{RESOURCE_LIMITS, sys_getrlimit, sys_setrlimit};
pub use imp::sys::sys_sysconf;
pub use imp::task::{sys_exit, sys_getpid, sys_sched_yield};
pub use imp::time::{sys_clock_getres, sys_clock_gettime, sys_get_time_of_day, sys_nanosleep};

#[cfg(feature = "fd")]
pub use imp::eventfd::{poll_extra_revents, signal_eventfd, sys_eventfd2};
#[cfg(feature = "fd")]
pub use imp::fd_ops::{
    AX_FILE_LIMIT, FD_FLAGS, FD_TABLE, FileLike, add_file_like, close_all_fds,
    close_all_fds_fast, close_on_exec_fds, get_file_like, sys_close, sys_dup, sys_dup2,
    sys_fcntl,
};
#[cfg(feature = "fs")]
pub use imp::fs::{
    Directory, File, LoopControlDevice, LoopDeviceFile, PROC_NET_IPV4_CONF_DEFAULT_TAG,
    PROC_NET_IPV4_CONF_LO_TAG, clear_proc_cgroup_mount_path, get_file_times, get_path_times,
    has_open_writable_file_under, note_removed_directory, proc_cgroup_mount_path,
    remove_named_tmpfile_path, set_file_times, set_path_times, set_proc_cgroup_mount_path,
    sys_fstat, sys_getcwd, sys_lseek, sys_lstat, sys_open, sys_openat, sys_rename, sys_stat,
    virtual_device_stat,
};
#[cfg(feature = "select")]
pub use imp::io_mpx::sys_select;
#[cfg(feature = "epoll")]
pub use imp::io_mpx::{sys_epoll_create, sys_epoll_ctl, sys_epoll_wait};
#[cfg(feature = "net")]
pub use imp::net::{
    sys_accept, sys_bind, sys_connect, sys_freeaddrinfo, sys_getaddrinfo, sys_getpeername,
    sys_getsockname, sys_getsockopt, sys_listen, sys_recv, sys_recvfrom, sys_send, sys_sendto,
    sys_setsockopt, sys_shutdown, sys_socket, sys_socketpair,
};
#[cfg(feature = "pipe")]
pub use imp::pipe::{pipe_max_size, set_pipe_max_size, sys_pipe, sys_pipe2};
#[cfg(feature = "multitask")]
pub use imp::pthread::mutex::{
    sys_pthread_mutex_init, sys_pthread_mutex_lock, sys_pthread_mutex_unlock,
};
#[cfg(feature = "multitask")]
pub use imp::pthread::{sys_pthread_create, sys_pthread_exit, sys_pthread_join, sys_pthread_self};
