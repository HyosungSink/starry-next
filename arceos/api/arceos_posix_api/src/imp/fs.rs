use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::{c_char, c_int};
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use axerrno::{LinuxError, LinuxResult};
use axfs::fops::OpenOptions;
use axio::{PollState, SeekFrom};
use axns::{ResArc, def_resource};
use axsync::Mutex;

use super::fd_ops::{FD_CLOEXEC_FLAG, FileLike, get_file_like};
use crate::AT_FDCWD;
use crate::{ctypes, utils::char_ptr_to_str};

/// File wrapper for `axfs::fops::File`.
pub struct File {
    inner: Mutex<axfs::fops::File>,
    path: String,
    inode: u64,
    status_flags: AtomicUsize,
    dirty: AtomicBool,
    times: Mutex<FileTimes>,
}

struct TmpFile {
    backing: Arc<TmpFileBacking>,
    pos: Mutex<usize>,
    status_flags: AtomicUsize,
}

struct TmpFileBacking {
    state: Mutex<TmpFileState>,
    inode: u64,
    mode: ctypes::mode_t,
}

#[derive(Clone, Copy, Default)]
struct FileTimes {
    atime: ctypes::timespec,
    mtime: ctypes::timespec,
    ctime: ctypes::timespec,
}

#[derive(Default)]
struct TmpFileState {
    chunks: Vec<Vec<u8>>,
    len: usize,
    pos: usize,
    atime: ctypes::timespec,
    mtime: ctypes::timespec,
    ctime: ctypes::timespec,
}

struct RtcDevice;
struct NullDevice;
struct ZeroDevice;
struct RandomDevice;
struct TtyDevice;
pub struct LoopControlDevice;
pub struct LoopDeviceFile {
    pos: Mutex<u64>,
}
struct ProcSelfStatFile {
    pos: Mutex<usize>,
}
struct ProcSelfMapsFile {
    pos: Mutex<usize>,
}
struct ProcMountsFile {
    path: &'static str,
    pos: Mutex<usize>,
}
#[derive(Clone, Copy)]
enum ProcNetSysctlKind {
    LoTag,
    DefaultTag,
}

struct ProcNetSysctlFile {
    kind: ProcNetSysctlKind,
    pos: Mutex<usize>,
}

const O_TMPFILE: u32 = 0o20200000;
const O_PATH: u32 = 0o10000000;
const TMPFILE_CHUNK_SIZE: usize = 64 * 1024;
const DEFAULT_FILE_BLKSIZE: i64 = 4096;
const S_ISGID: u16 = 0o2000;
const MAX_FINAL_SYMLINK_DEPTH: usize = 40;
static LARGE_TMPFILE_LOGGED: AtomicBool = AtomicBool::new(false);
static PROC_CGROUP_MOUNT_PATH: Mutex<Option<String>> = Mutex::new(None);
static REMOVED_DIRECTORY_GENERATIONS: Mutex<BTreeMap<String, u64>> = Mutex::new(BTreeMap::new());
static NAMED_TMPFILES: Mutex<BTreeMap<String, Arc<TmpFileBacking>>> = Mutex::new(BTreeMap::new());
static PATH_TIMES: Mutex<BTreeMap<String, FileTimes>> = Mutex::new(BTreeMap::new());

const DEV_NULL_MAJOR: u32 = 1;
const DEV_NULL_MINOR: u32 = 3;
const DEV_ZERO_MAJOR: u32 = 1;
const DEV_ZERO_MINOR: u32 = 5;
const DEV_RANDOM_MAJOR: u32 = 1;
const DEV_RANDOM_MINOR: u32 = 8;
const DEV_URANDOM_MAJOR: u32 = 1;
const DEV_URANDOM_MINOR: u32 = 9;
const DEV_TTY_MAJOR: u32 = 5;
const DEV_TTY_MINOR: u32 = 0;
const DEV_RTC_MAJOR: u32 = 248;
const DEV_RTC_MINOR: u32 = 0;
const DEV_LOOP_CONTROL_MAJOR: u32 = 10;
const DEV_LOOP_CONTROL_MINOR: u32 = 237;
const DEV_LOOP_MAJOR: u32 = 7;
const REGULAR_FS_DEV_ID: u64 = 1;
const TMPFILE_FS_DEV_ID: u64 = 2;
static LOOP_DEVICE_STATE: Mutex<LoopDeviceState> = Mutex::new(LoopDeviceState::new());

struct LoopDeviceState {
    backing: Option<Arc<dyn FileLike>>,
    configured: bool,
    visible_size: u64,
}

impl LoopDeviceState {
    const fn new() -> Self {
        Self {
            backing: None,
            configured: false,
            visible_size: 0,
        }
    }
}

def_resource! {
    pub static PROC_NET_IPV4_CONF_LO_TAG: ResArc<Mutex<i32>> = ResArc::new();
    pub static PROC_NET_IPV4_CONF_DEFAULT_TAG: ResArc<Mutex<i32>> = ResArc::new();
}

impl PROC_NET_IPV4_CONF_LO_TAG {
    pub fn copy_inner(&self) -> Mutex<i32> {
        Mutex::new(*self.lock())
    }
}

impl PROC_NET_IPV4_CONF_DEFAULT_TAG {
    pub fn copy_inner(&self) -> Mutex<i32> {
        Mutex::new(*self.lock())
    }
}

#[ctor_bare::register_ctor]
fn init_proc_net_sysctl_resources() {
    PROC_NET_IPV4_CONF_LO_TAG.init_new(Mutex::new(0));
    PROC_NET_IPV4_CONF_DEFAULT_TAG.init_new(Mutex::new(0));
}

fn current_timespec() -> ctypes::timespec {
    let now_ns = axhal::time::wall_time().as_nanos() as i64;
    ctypes::timespec {
        tv_sec: now_ns / 1_000_000_000,
        tv_nsec: now_ns % 1_000_000_000,
    }
}

fn synthetic_inode_from_path(path: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in path.as_bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    let ino = hash & 0x7fff_ffff;
    if ino <= 1 { 2 } else { ino }
}

const fn linux_makedev(major: u32, minor: u32) -> u64 {
    ((minor as u64) & 0xff)
        | (((major as u64) & 0xfff) << 8)
        | (((minor as u64) & !0xff) << 12)
        | (((major as u64) & !0xfff) << 32)
}

pub fn virtual_device_stat(path: &str) -> Option<ctypes::stat> {
    match path {
        "/dev/loop-control" => Some(char_device_stat(
            0o600,
            DEV_LOOP_CONTROL_MAJOR,
            DEV_LOOP_CONTROL_MINOR,
        )),
        "/dev/loop0" => Some(block_device_stat(
            0o660,
            DEV_LOOP_MAJOR,
            0,
            loop_device_size_or_zero(),
        )),
        "/dev/rtc" | "/dev/rtc0" | "/dev/misc/rtc" => Some(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::CharDevice as u32) << 12) | 0o666,
            st_uid: 0,
            st_gid: 0,
            st_rdev: linux_makedev(DEV_RTC_MAJOR, DEV_RTC_MINOR),
            st_blksize: 512,
            ..Default::default()
        }),
        "/dev/null" => Some(char_device_stat(0o666, DEV_NULL_MAJOR, DEV_NULL_MINOR)),
        "/dev/zero" => Some(char_device_stat(0o666, DEV_ZERO_MAJOR, DEV_ZERO_MINOR)),
        "/dev/random" => Some(char_device_stat(0o666, DEV_RANDOM_MAJOR, DEV_RANDOM_MINOR)),
        "/dev/urandom" => Some(char_device_stat(
            0o666,
            DEV_URANDOM_MAJOR,
            DEV_URANDOM_MINOR,
        )),
        "/proc/mounts" | "/proc/self/mounts" => Some(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: synthetic_inode_from_path(path),
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 512,
            ..Default::default()
        }),
        "/proc/sys/net/ipv4/conf/lo/tag" | "/proc/sys/net/ipv4/conf/default/tag" => {
            Some(ctypes::stat {
                st_dev: REGULAR_FS_DEV_ID,
                st_ino: synthetic_inode_from_path(path),
                st_nlink: 1,
                st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o644,
                st_uid: 0,
                st_gid: 0,
                st_blksize: 512,
                ..Default::default()
            })
        }
        "/dev/tty" => Some(char_device_stat(0o666, DEV_TTY_MAJOR, DEV_TTY_MINOR)),
        _ => None,
    }
}

pub fn has_open_writable_file_under(path: &str) -> bool {
    let mount_path = path.trim_end_matches('/');
    let table = super::fd_ops::FD_TABLE.read();
    table.iter().any(|(_, file_like)| {
        let flags = file_like.status_flags() as u32;
        let write_open = (flags & 0b11) == ctypes::O_WRONLY
            || (flags & 0b11) == ctypes::O_RDWR
            || (flags & ctypes::O_APPEND) != 0;
        if !write_open {
            return false;
        }
        let Ok(file) = file_like.clone().into_any().downcast::<File>() else {
            return false;
        };
        let file_path = file.path().trim_end_matches('/');
        file_path == mount_path
            || file_path
                .strip_prefix(mount_path)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

fn current_proc_net_tag(kind: ProcNetSysctlKind) -> i32 {
    match kind {
        ProcNetSysctlKind::LoTag => *PROC_NET_IPV4_CONF_LO_TAG.lock(),
        ProcNetSysctlKind::DefaultTag => *PROC_NET_IPV4_CONF_DEFAULT_TAG.lock(),
    }
}

fn set_current_proc_net_tag(kind: ProcNetSysctlKind, value: i32) {
    match kind {
        ProcNetSysctlKind::LoTag => *PROC_NET_IPV4_CONF_LO_TAG.lock() = value,
        ProcNetSysctlKind::DefaultTag => *PROC_NET_IPV4_CONF_DEFAULT_TAG.lock() = value,
    }
}

fn proc_net_sysctl_contents(kind: ProcNetSysctlKind) -> String {
    format!("{}\n", current_proc_net_tag(kind))
}

fn normalize_fd_path(path: String, is_dir: bool) -> String {
    let mut normalized = axfs::api::canonicalize(&path).unwrap_or(path);
    if is_dir && !normalized.ends_with('/') {
        normalized.push('/');
    }
    normalized
}

fn path_times_for_key(path_key: &str, default: FileTimes) -> FileTimes {
    let mut map = PATH_TIMES.lock();
    *map.entry(path_key.to_string()).or_insert(default)
}

fn path_times_for(path: &str, is_dir: bool, default: FileTimes) -> FileTimes {
    let normalized = normalize_fd_path(path.to_string(), is_dir);
    path_times_for_key(normalized.as_str(), default)
}

fn store_path_times_key(path_key: &str, times: FileTimes) {
    PATH_TIMES.lock().insert(path_key.to_string(), times);
}

fn store_path_times(path: &str, is_dir: bool, times: FileTimes) {
    let normalized = normalize_fd_path(path.to_string(), is_dir);
    store_path_times_key(normalized.as_str(), times);
}

pub fn get_path_times(path: &str, is_dir: bool) -> (ctypes::timespec, ctypes::timespec, ctypes::timespec) {
    let now = current_timespec();
    let times = path_times_for(
        path,
        is_dir,
        FileTimes {
            atime: now,
            mtime: now,
            ctime: now,
        },
    );
    (times.atime, times.mtime, times.ctime)
}

pub fn set_path_times(
    path: &str,
    is_dir: bool,
    atime: ctypes::timespec,
    mtime: ctypes::timespec,
    ctime: ctypes::timespec,
) {
    store_path_times(
        path,
        is_dir,
        FileTimes {
            atime,
            mtime,
            ctime,
        },
    );
}

fn removed_directory_generation(path: &str) -> u64 {
    let normalized = normalize_fd_path(path.to_string(), true);
    REMOVED_DIRECTORY_GENERATIONS
        .lock()
        .get(normalized.as_str())
        .copied()
        .unwrap_or(0)
}

pub fn note_removed_directory(path: &str) {
    let normalized = normalize_fd_path(path.to_string(), true);
    let mut generations = REMOVED_DIRECTORY_GENERATIONS.lock();
    let next = generations
        .get(normalized.as_str())
        .copied()
        .unwrap_or(0)
        .wrapping_add(1);
    generations.insert(normalized, next);
}

fn current_umask_bits() -> u16 {
    0
}

fn creator_in_group(gid: u32) -> bool {
    let gids = axfs::api::current_res_gid();
    let (supplementary, supplementary_len) = axfs::api::current_supplementary_gids();
    gid == gids.0
        || gid == gids.1
        || gid == gids.2
        || supplementary[..supplementary_len].contains(&gid)
}

fn parent_dir_path(path: &str) -> &str {
    path.rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or(".")
}

fn resolve_final_symlink_for_open(path: &str) -> LinuxResult<String> {
    let mut resolved = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    if !resolved.starts_with('/') {
        let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
        resolved = if cwd.ends_with('/') {
            format!("{cwd}{resolved}")
        } else {
            format!("{cwd}/{resolved}")
        };
    }
    for _ in 0..MAX_FINAL_SYMLINK_DEPTH {
        let target = match axfs::api::readlink(resolved.as_str()) {
            Ok(target) => target,
            Err(_) => return Ok(resolved),
        };
        let target = String::from_utf8(target).map_err(|_| LinuxError::EINVAL)?;
        resolved = if target.starts_with('/') {
            target
        } else {
            let parent = parent_dir_path(resolved.as_str());
            if parent == "/" {
                format!("/{target}")
            } else if parent == "." {
                target
            } else {
                format!("{parent}/{target}")
            }
        };
    }
    Err(LinuxError::ELOOP)
}

fn apply_created_metadata(
    path: &str,
    requested_mode: ctypes::mode_t,
    is_dir: bool,
) -> LinuxResult<()> {
    let resolved = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    let parent = parent_dir_path(resolved.as_str());
    let parent_attr = axfs::api::metadata_raw_ax(parent).map_err(LinuxError::from)?;
    let (_uid, parent_gid, parent_mode) = axfs::api::path_owner_mode(parent, parent_attr);
    let target_gid = if parent_mode & S_ISGID != 0 {
        parent_gid
    } else {
        axfs::api::current_egid()
    };

    let mut final_mode = ((requested_mode as u16) & 0o7777) & !current_umask_bits();
    if is_dir {
        if parent_mode & S_ISGID != 0 {
            final_mode |= S_ISGID;
        }
    } else if final_mode & S_ISGID != 0
        && axfs::api::current_euid() != 0
        && !creator_in_group(target_gid)
    {
        final_mode &= !S_ISGID;
    }

    axfs::api::set_path_owner(
        resolved.as_str(),
        Some(axfs::api::current_euid()),
        Some(target_gid),
    );
    axfs::api::set_mode(resolved.as_str(), final_mode as u32).map_err(LinuxError::from)?;
    Ok(())
}

fn clock_ticks_from_nanos(ns: u64) -> u64 {
    (ns / 10_000_000).max(1)
}

fn proc_self_stat_contents() -> String {
    let pid = axtask::current().id().as_u64();
    let utime = clock_ticks_from_nanos(axhal::time::monotonic_time_nanos() as u64);
    format!(
        "{pid} (busybox) R 0 0 0 0 0 0 0 0 0 0 {utime} 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
    )
}

fn proc_stat_read(content: String, pos: &Mutex<usize>, buf: &mut [u8]) -> LinuxResult<usize> {
    let data = content.as_bytes();
    let mut pos = pos.lock();
    if *pos >= data.len() {
        return Ok(0);
    }
    let read_len = buf.len().min(data.len() - *pos);
    buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
    *pos += read_len;
    Ok(read_len)
}

fn proc_stat_seek(content_len: usize, pos: &Mutex<usize>, seek: SeekFrom) -> LinuxResult<u64> {
    let mut current = pos.lock();
    let next = match seek {
        SeekFrom::Start(off) => off as i64,
        SeekFrom::Current(off) => *current as i64 + off,
        SeekFrom::End(off) => content_len as i64 + off,
    };
    if next < 0 {
        return Err(LinuxError::EINVAL);
    }
    *current = (next as usize).min(content_len);
    Ok(*current as u64)
}

fn proc_stat_stat(path: &str, size: i64) -> ctypes::stat {
    ctypes::stat {
        st_dev: REGULAR_FS_DEV_ID,
        st_ino: synthetic_inode_from_path(path),
        st_nlink: 1,
        st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
        st_uid: 0,
        st_gid: 0,
        st_size: size,
        st_blocks: ((size + 511) / 512) as _,
        st_blksize: 512,
        ..Default::default()
    }
}

fn proc_self_maps_contents() -> String {
    String::from(
        "00400000-00401000 r-xp 00000000 00:00 0 /initproc\n\
7fff0000-7fff1000 rw-p 00000000 00:00 0 [stack]\n",
    )
}

fn proc_mounts_contents() -> &'static str {
    unreachable!()
}

fn proc_mounts_contents_owned() -> String {
    let mut mounts = axfs::api::proc_mounts_contents();
    if !mounts.contains("/dev/shm ") {
        mounts.push_str("tmpfs /dev/shm tmpfs rw 0 0\n");
    }
    if let Some(cgroup_mount) = PROC_CGROUP_MOUNT_PATH.lock().clone() {
        mounts.push_str(format!("cgroup2 {cgroup_mount} cgroup2 rw 0 0\n").as_str());
    }
    mounts
}

pub fn set_proc_cgroup_mount_path(path: &str) {
    *PROC_CGROUP_MOUNT_PATH.lock() = Some(path.to_string());
}

pub fn clear_proc_cgroup_mount_path() {
    *PROC_CGROUP_MOUNT_PATH.lock() = None;
}

pub fn proc_cgroup_mount_path() -> String {
    PROC_CGROUP_MOUNT_PATH
        .lock()
        .clone()
        .unwrap_or_else(|| "/sys/fs/cgroup".to_string())
}

impl ProcSelfStatFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcSelfMapsFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }
}

impl ProcMountsFile {
    fn new(path: &'static str) -> Self {
        Self {
            path,
            pos: Mutex::new(0),
        }
    }
}

impl ProcNetSysctlFile {
    fn new(kind: ProcNetSysctlKind) -> Self {
        Self {
            kind,
            pos: Mutex::new(0),
        }
    }
}

fn open_tmpfile(dir_path: &str, flags: c_int, mode: ctypes::mode_t) -> LinuxResult<c_int> {
    let mut dir_opts = OpenOptions::new();
    dir_opts.read(true);
    Directory::from_path(dir_path.to_string(), &dir_opts)?;
    super::fd_ops::add_file_like(Arc::new(TmpFile::new(flags as usize, mode)))
}

fn normalize_named_tmpfile_path(path: &str) -> String {
    let mut normalized = axfs::api::canonicalize(path).unwrap_or_else(|_| path.to_string());
    if !normalized.starts_with('/') {
        let cwd = axfs::api::current_dir().unwrap_or_else(|_| "/".to_string());
        normalized = if cwd.ends_with('/') {
            format!("{cwd}{normalized}")
        } else {
            format!("{cwd}/{normalized}")
        };
    }
    normalized
}

fn named_tmpfile_backing(path: &str) -> Option<Arc<TmpFileBacking>> {
    let normalized = normalize_named_tmpfile_path(path);
    NAMED_TMPFILES.lock().get(normalized.as_str()).cloned()
}

fn should_redirect_named_tmpfile(filename: &str, flags: c_int) -> bool {
    let flags = flags as u32;
    filename.starts_with("/tmp/")
        && (flags & ctypes::O_CREAT != 0)
        && (flags & ctypes::O_EXCL != 0)
        && (flags & 0b11) != ctypes::O_RDONLY
        && !filename["/tmp/".len()..].contains('/')
}

fn open_existing_named_tmpfile(filename: &str, flags: c_int) -> LinuxResult<c_int> {
    let options = flags_to_options(flags, 0);
    if options.has_directory() {
        return Err(LinuxError::ENOTDIR);
    }
    if (flags as u32 & ctypes::O_CREAT != 0) && (flags as u32 & ctypes::O_EXCL != 0) {
        return Err(LinuxError::EEXIST);
    }
    let file = Arc::new(TmpFile::from_backing(
        named_tmpfile_backing(filename).ok_or(LinuxError::ENOENT)?,
        file_status_flags(flags),
    ));
    if (flags as u32 & ctypes::O_TRUNC) != 0 {
        file.truncate(0)?;
    }
    super::fd_ops::add_file_like(file)
}

fn open_named_tmpfile(filename: &str, flags: c_int, mode: ctypes::mode_t) -> LinuxResult<c_int> {
    let normalized = normalize_named_tmpfile_path(filename);
    let options = flags_to_options(flags, mode);
    let created = !axfs::api::absolute_path_exists(normalized.as_str());
    let placeholder = axfs::fops::File::open(filename, &options)?;
    drop(placeholder);
    if created {
        apply_created_metadata(normalized.as_str(), mode, false)?;
    }
    let backing = Arc::new(TmpFileBacking::new(mode));
    NAMED_TMPFILES
        .lock()
        .insert(normalized.clone(), backing.clone());
    match super::fd_ops::add_file_like(Arc::new(TmpFile::from_backing(
        backing,
        file_status_flags(flags),
    ))) {
        Ok(fd) => Ok(fd),
        Err(err) => {
            NAMED_TMPFILES.lock().remove(normalized.as_str());
            let _ = axfs::api::remove_file(normalized.as_str());
            Err(err)
        }
    }
}

fn open_tmpfile_at(
    dirfd: c_int,
    filename: &str,
    flags: c_int,
    mode: ctypes::mode_t,
) -> LinuxResult<c_int> {
    if filename.starts_with('/') || dirfd == AT_FDCWD as _ {
        return open_tmpfile(filename, flags, mode);
    }

    let dir = Directory::from_fd(dirfd)?;
    let dir_path = dir.path().trim_end_matches('/');
    let full_path = if dir_path.is_empty() {
        alloc::format!("/{}", filename)
    } else {
        alloc::format!("{dir_path}/{}", filename)
    };
    open_tmpfile(full_path.as_str(), flags, mode)
}

impl File {
    fn new(inner: axfs::fops::File, path: String, status_flags: usize) -> Self {
        let path = normalize_fd_path(path, false);
        let now = current_timespec();
        let times = path_times_for_key(
            path.as_str(),
            FileTimes {
                atime: now,
                mtime: now,
                ctime: now,
            },
        );
        Self {
            inner: Mutex::new(inner),
            inode: synthetic_inode_from_path(&path),
            path,
            status_flags: AtomicUsize::new(status_flags),
            dirty: AtomicBool::new(false),
            times: Mutex::new(times),
        }
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    fn add_to_fd_table_with_flags(self, fd_flags: usize) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like_with_fd_flags(Arc::new(self), fd_flags)
    }

    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::EINVAL)
    }

    /// Get the path of the file.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the inner node of the file.    
    pub fn inner(&self) -> &Mutex<axfs::fops::File> {
        &self.inner
    }

    fn set_times(&self, atime: ctypes::timespec, mtime: ctypes::timespec) {
        let mut times = self.times.lock();
        times.atime = atime;
        times.mtime = mtime;
        times.ctime = mtime;
        store_path_times_key(self.path(), *times);
    }
}

impl TmpFile {
    fn new(status_flags: usize, mode: ctypes::mode_t) -> Self {
        Self::from_backing(Arc::new(TmpFileBacking::new(mode)), status_flags)
    }

    fn from_backing(backing: Arc<TmpFileBacking>, status_flags: usize) -> Self {
        Self {
            backing,
            pos: Mutex::new(0),
            status_flags: AtomicUsize::new(status_flags),
        }
    }

    fn set_times(&self, atime: ctypes::timespec, mtime: ctypes::timespec) {
        self.backing.set_times(atime, mtime);
    }
}

impl TmpFileBacking {
    fn new(mode: ctypes::mode_t) -> Self {
        static NEXT_TMPFILE_INODE: AtomicU64 = AtomicU64::new(2);
        let now = current_timespec();
        Self {
            state: Mutex::new(TmpFileState {
                atime: now,
                mtime: now,
                ctime: now,
                ..Default::default()
            }),
            inode: NEXT_TMPFILE_INODE.fetch_add(1, Ordering::Relaxed),
            mode,
        }
    }

    fn set_times(&self, atime: ctypes::timespec, mtime: ctypes::timespec) {
        let mut state = self.state.lock();
        state.atime = atime;
        state.mtime = mtime;
        state.ctime = mtime;
    }

    fn stat(&self) -> ctypes::stat {
        let state = self.state.lock();
        let size = state.len as i64;
        ctypes::stat {
            st_dev: TMPFILE_FS_DEV_ID,
            st_ino: self.inode,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | (self.mode & 0o777) as u32,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blocks: ((size + 511) / 512) as _,
            st_blksize: 512,
            st_atime: state.atime,
            st_mtime: state.mtime,
            st_ctime: state.ctime,
            ..Default::default()
        }
    }
}

impl TmpFileState {
    fn ensure_len(&mut self, len: usize) {
        if len <= self.len {
            return;
        }
        if len >= (1 << 20) && !LARGE_TMPFILE_LOGGED.swap(true, Ordering::Relaxed) {
            warn!(
                "tmpfile large grow len={} required_chunks={}",
                len,
                len.div_ceil(TMPFILE_CHUNK_SIZE)
            );
        }
        let required_chunks = len.div_ceil(TMPFILE_CHUNK_SIZE);
        while self.chunks.len() < required_chunks {
            let mut chunk = Vec::with_capacity(TMPFILE_CHUNK_SIZE);
            chunk.resize(TMPFILE_CHUNK_SIZE, 0);
            self.chunks.push(chunk);
        }
        self.len = len;
    }

    fn truncate(&mut self, len: usize) {
        if len > self.len {
            self.ensure_len(len);
        } else {
            self.len = len;
            self.pos = self.pos.min(len);
        }
    }
}

impl FileLike for RtcDevice {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::CharDevice as u32) << 12) | 0o666,
            st_uid: 0,
            st_gid: 0,
            st_rdev: linux_makedev(DEV_RTC_MAJOR, DEV_RTC_MINOR),
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

fn char_device_stat(perm: u32, major: u32, minor: u32) -> ctypes::stat {
    ctypes::stat {
        st_ino: 1,
        st_nlink: 1,
        st_mode: ((axfs::fops::FileType::CharDevice as u32) << 12) | perm,
        st_uid: 0,
        st_gid: 0,
        st_rdev: linux_makedev(major, minor),
        st_blksize: 512,
        ..Default::default()
    }
}

fn block_device_stat(perm: u32, major: u32, minor: u32, size: u64) -> ctypes::stat {
    ctypes::stat {
        st_ino: 1,
        st_nlink: 1,
        st_mode: ((axfs::fops::FileType::BlockDevice as u32) << 12) | perm,
        st_uid: 0,
        st_gid: 0,
        st_rdev: linux_makedev(major, minor),
        st_size: size as _,
        st_blocks: size.div_ceil(512) as _,
        st_blksize: 512,
        ..Default::default()
    }
}

fn loop_device_size_or_zero() -> u64 {
    LOOP_DEVICE_STATE.lock().visible_size
}

impl LoopControlDevice {
    pub fn free_index(&self) -> LinuxResult<i32> {
        let state = LOOP_DEVICE_STATE.lock();
        if state.backing.is_none() {
            Ok(0)
        } else {
            Err(LinuxError::EBUSY)
        }
    }
}

impl LoopDeviceFile {
    fn new() -> Self {
        Self { pos: Mutex::new(0) }
    }

    fn flush_cache(state: &mut LoopDeviceState) -> LinuxResult {
        let Some(backing) = state.backing.as_ref() else {
            return Err(LinuxError::ENXIO);
        };
        backing.sync_all()
    }

    pub fn attach_fd(&self, fd: c_int) -> LinuxResult {
        let backing = get_file_like(fd)?;
        let stat = backing.stat()?;
        if ((stat.st_mode >> 12) & 0xf) != axfs::fops::FileType::File as u32 {
            return Err(LinuxError::EINVAL);
        }
        let mut state = LOOP_DEVICE_STATE.lock();
        if state.backing.is_some() {
            return Err(LinuxError::EBUSY);
        }
        let backing_size = stat.st_size.max(0) as u64;
        let visible_size = if backing_size == 0 { 0 } else { backing_size };
        state.backing = Some(backing);
        state.configured = false;
        state.visible_size = visible_size;
        *self.pos.lock() = 0;
        Ok(())
    }

    pub fn set_status(&self) -> LinuxResult {
        let mut state = LOOP_DEVICE_STATE.lock();
        if state.backing.is_none() {
            return Err(LinuxError::ENXIO);
        }
        state.configured = true;
        Ok(())
    }

    pub fn clear_fd(&self) -> LinuxResult {
        let mut state = LOOP_DEVICE_STATE.lock();
        if state.backing.is_none() {
            return Err(LinuxError::ENXIO);
        }
        Self::flush_cache(&mut state)?;
        state.backing = None;
        state.configured = false;
        state.visible_size = 0;
        *self.pos.lock() = 0;
        Ok(())
    }

    pub fn has_status(&self) -> bool {
        LOOP_DEVICE_STATE.lock().backing.is_some()
    }

    pub fn size_bytes(&self) -> LinuxResult<u64> {
        let state = LOOP_DEVICE_STATE.lock();
        if state.backing.is_none() {
            return Err(LinuxError::ENXIO);
        }
        Ok(state.visible_size)
    }
}

impl FileLike for NullDevice {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Ok(0)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(char_device_stat(0o666, DEV_NULL_MAJOR, DEV_NULL_MINOR))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

impl FileLike for ZeroDevice {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        buf.fill(0);
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(char_device_stat(0o666, DEV_ZERO_MAJOR, DEV_ZERO_MINOR))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

impl FileLike for RandomDevice {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        static RNG_STATE: AtomicU64 = AtomicU64::new(0x6d5a_56a9_3c4f_2b17);
        let mut state = RNG_STATE.load(Ordering::Relaxed);
        for byte in buf.iter_mut() {
            state ^= state << 7;
            state ^= state >> 9;
            state ^= state << 8;
            *byte = state as u8;
        }
        RNG_STATE.store(state, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(char_device_stat(0o666, DEV_RANDOM_MAJOR, DEV_RANDOM_MINOR))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

impl FileLike for TtyDevice {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        Ok(super::stdio::tty_read_blocked(buf)?)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(super::stdio::tty_write(buf)?)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(char_device_stat(0o666, DEV_TTY_MAJOR, DEV_TTY_MINOR))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

impl FileLike for LoopControlDevice {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(char_device_stat(
            0o600,
            DEV_LOOP_CONTROL_MAJOR,
            DEV_LOOP_CONTROL_MINOR,
        ))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

impl FileLike for LoopDeviceFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let state = LOOP_DEVICE_STATE.lock();
        let Some(backing) = state.backing.as_ref() else {
            return Err(LinuxError::ENXIO);
        };
        let limit = state.visible_size;
        let mut pos = self.pos.lock();
        if *pos >= limit {
            return Ok(0);
        }
        let read_len = buf.len().min((limit - *pos) as usize);
        let read = backing.read_at(*pos, &mut buf[..read_len])?;
        if read < read_len {
            buf[read..read_len].fill(0);
        }
        *pos += read_len as u64;
        Ok(read_len)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let state = LOOP_DEVICE_STATE.lock();
        let Some(backing) = state.backing.as_ref() else {
            return Err(LinuxError::ENXIO);
        };
        let limit = state.visible_size;
        let mut pos = self.pos.lock();
        if *pos >= limit {
            return Err(LinuxError::ENOSPC);
        }
        let write_len = buf.len().min((limit - *pos) as usize);
        let written = backing.write_at(*pos, &buf[..write_len])?;
        *pos += written as u64;
        Ok(written)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(block_device_stat(
            0o660,
            DEV_LOOP_MAJOR,
            0,
            self.size_bytes()?,
        ))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        let size = self.size_bytes()? as i64;
        let mut current = self.pos.lock();
        let next = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::Current(off) => *current as i64 + off,
            SeekFrom::End(off) => size + off,
        };
        if next < 0 {
            return Err(LinuxError::EINVAL);
        }
        *current = next as u64;
        Ok(*current)
    }

    fn sync_all(&self) -> LinuxResult {
        let mut state = LOOP_DEVICE_STATE.lock();
        Self::flush_cache(&mut state)
    }
}

impl FileLike for ProcSelfStatFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        proc_stat_read(proc_self_stat_contents(), &self.pos, buf)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let size = proc_self_stat_contents().len() as i64;
        Ok(proc_stat_stat("/proc/self/stat", size))
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        proc_stat_seek(proc_self_stat_contents().len(), &self.pos, pos)
    }
}

impl FileLike for ProcSelfMapsFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let content = proc_self_maps_contents();
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let size = proc_self_maps_contents().len() as i64;
        Ok(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: synthetic_inode_from_path("/proc/self/maps"),
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blocks: ((size + 511) / 512) as _,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        let content_len = proc_self_maps_contents().len();
        let mut current = self.pos.lock();
        let next = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::Current(off) => *current as i64 + off,
            SeekFrom::End(off) => content_len as i64 + off,
        };
        if next < 0 {
            return Err(LinuxError::EINVAL);
        }
        *current = (next as usize).min(content_len);
        Ok(*current as u64)
    }
}

impl FileLike for ProcMountsFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let content = proc_mounts_contents_owned();
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let size = proc_mounts_contents_owned().len() as i64;
        Ok(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: synthetic_inode_from_path(self.path),
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o444,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blocks: ((size + 511) / 512) as _,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        let content_len = proc_mounts_contents_owned().len();
        let mut current = self.pos.lock();
        let next = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::Current(off) => *current as i64 + off,
            SeekFrom::End(off) => content_len as i64 + off,
        };
        if next < 0 {
            return Err(LinuxError::EINVAL);
        }
        *current = next as usize;
        Ok(*current as u64)
    }
}

impl FileLike for ProcNetSysctlFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let content = proc_net_sysctl_contents(self.kind);
        let data = content.as_bytes();
        let mut pos = self.pos.lock();
        if *pos >= data.len() {
            return Ok(0);
        }
        let read_len = buf.len().min(data.len() - *pos);
        buf[..read_len].copy_from_slice(&data[*pos..*pos + read_len]);
        *pos += read_len;
        Ok(read_len)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let text = core::str::from_utf8(buf).map_err(|_| LinuxError::EINVAL)?;
        let value = text.trim().parse::<i32>().map_err(|_| LinuxError::EINVAL)?;
        set_current_proc_net_tag(self.kind, value);
        *self.pos.lock() = 0;
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let path = match self.kind {
            ProcNetSysctlKind::LoTag => "/proc/sys/net/ipv4/conf/lo/tag",
            ProcNetSysctlKind::DefaultTag => "/proc/sys/net/ipv4/conf/default/tag",
        };
        let size = proc_net_sysctl_contents(self.kind).len() as i64;
        Ok(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: synthetic_inode_from_path(path),
            st_nlink: 1,
            st_mode: ((axfs::fops::FileType::File as u32) << 12) | 0o644,
            st_uid: 0,
            st_gid: 0,
            st_size: size,
            st_blocks: ((size + 511) / 512) as _,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        let content_len = proc_net_sysctl_contents(self.kind).len();
        let mut current = self.pos.lock();
        let next = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::Current(off) => *current as i64 + off,
            SeekFrom::End(off) => content_len as i64 + off,
        };
        if next < 0 {
            return Err(LinuxError::EINVAL);
        }
        *current = (next as usize).min(content_len);
        Ok(*current as u64)
    }
}

impl FileLike for File {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let read_len = self.inner.lock().read(buf)?;
        if self.status_flags.load(Ordering::Acquire) & (ctypes::O_NOATIME as usize) == 0 {
            let now = current_timespec();
            let mut times = self.times.lock();
            times.atime = now;
            store_path_times_key(self.path(), *times);
        }
        Ok(read_len)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut inner = self.inner.lock();
        let mut write_len = 0usize;
        while write_len < buf.len() {
            let written = match inner.write(&buf[write_len..]) {
                Ok(written) => written,
                Err(err) if write_len > 0 => break,
                Err(err) => return Err(err.into()),
            };
            if written == 0 {
                if write_len > 0 {
                    break;
                }
                return Err(LinuxError::ENOSPC);
            }
            write_len += written;
        }
        self.dirty.store(true, Ordering::Release);
        let now = current_timespec();
        let mut times = self.times.lock();
        times.mtime = now;
        times.ctime = now;
        store_path_times_key(self.path(), *times);
        Ok(write_len)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let read_len = self.inner.lock().read_at(offset, buf)?;
        if self.status_flags.load(Ordering::Acquire) & (ctypes::O_NOATIME as usize) == 0 {
            let now = current_timespec();
            let mut times = self.times.lock();
            times.atime = now;
            store_path_times_key(self.path(), *times);
        }
        Ok(read_len)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let append = self.status_flags.load(Ordering::Acquire) & (ctypes::O_APPEND as usize) != 0;
        let write_offset = if append {
            self.inner.lock().get_attr()?.size()
        } else {
            offset
        };
        let write_len = self.inner.lock().write_at(write_offset, buf)?;
        self.dirty.store(true, Ordering::Release);
        let now = current_timespec();
        let mut times = self.times.lock();
        times.mtime = now;
        times.ctime = now;
        store_path_times_key(self.path(), *times);
        Ok(write_len)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let metadata = self.inner.lock().get_attr()?;
        let meta = axfs::api::path_stat_metadata(self.path(), metadata);
        let ty = meta.special_type.unwrap_or(metadata.file_type()) as u8;
        let uid = meta.uid;
        let gid = meta.gid;
        let mode = meta.mode;
        let perm = mode as u32;
        let st_mode = ((ty as u32) << 12) | perm;
        let times = *self.times.lock();
        Ok(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: meta.ino,
            st_nlink: 1,
            st_mode,
            st_uid: uid,
            st_gid: gid,
            st_size: metadata.size() as _,
            st_blocks: metadata.blocks() as _,
            st_blksize: DEFAULT_FILE_BLKSIZE,
            st_atime: times.atime,
            st_mtime: times.mtime,
            st_ctime: times.ctime,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        let mut flags = self.status_flags.load(Ordering::Acquire);
        if _nonblocking {
            flags |= ctypes::O_NONBLOCK as usize;
        } else {
            flags &= !(ctypes::O_NONBLOCK as usize);
        }
        self.status_flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn set_append(&self, append: bool) -> LinuxResult {
        let mut flags = self.status_flags.load(Ordering::Acquire);
        if append {
            flags |= ctypes::O_APPEND as usize;
        } else {
            flags &= !(ctypes::O_APPEND as usize);
        }
        self.inner.lock().set_append(append);
        self.status_flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn status_flags(&self) -> usize {
        self.status_flags.load(Ordering::Acquire)
    }

    fn lock_key(&self) -> Option<(u64, u64)> {
        Some((REGULAR_FS_DEV_ID, self.inode))
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        Ok(self.inner.lock().seek(pos)?)
    }

    fn sync_all(&self) -> LinuxResult {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Ok(());
        }
        if !self.dirty.load(Ordering::Acquire) {
            return Ok(());
        }
        self.inner.lock().flush()?;
        self.dirty.store(false, Ordering::Release);
        Ok(())
    }

    fn truncate(&self, length: u64) -> LinuxResult {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        self.inner.lock().truncate(length)?;
        self.dirty.store(true, Ordering::Release);
        let now = current_timespec();
        let mut times = self.times.lock();
        times.mtime = now;
        times.ctime = now;
        store_path_times_key(self.path(), *times);
        Ok(())
    }
}

impl FileLike for TmpFile {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut state = self.backing.state.lock();
        let mut pos = self.pos.lock();
        let available = state.len.saturating_sub(*pos);
        let total = available.min(buf.len());
        let mut remaining = total;
        let mut src_pos = *pos;
        let mut dst_pos = 0;
        while remaining > 0 {
            let chunk_idx = src_pos / TMPFILE_CHUNK_SIZE;
            let chunk_off = src_pos % TMPFILE_CHUNK_SIZE;
            let copy_len = remaining.min(TMPFILE_CHUNK_SIZE - chunk_off);
            if let Some(chunk) = state.chunks.get(chunk_idx) {
                buf[dst_pos..dst_pos + copy_len]
                    .copy_from_slice(&chunk[chunk_off..chunk_off + copy_len]);
            } else {
                buf[dst_pos..dst_pos + copy_len].fill(0);
            }
            src_pos += copy_len;
            dst_pos += copy_len;
            remaining -= copy_len;
        }
        *pos = src_pos;
        state.atime = current_timespec();
        Ok(total)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut state = self.backing.state.lock();
        let mut pos = self.pos.lock();
        if self.status_flags.load(Ordering::Acquire) & (ctypes::O_APPEND as usize) != 0 {
            *pos = state.len;
        }
        let start = *pos;
        let end = start.saturating_add(buf.len());
        state.ensure_len(end);
        let mut remaining = buf.len();
        let mut src_pos = 0;
        let mut dst_pos = start;
        while remaining > 0 {
            let chunk_idx = dst_pos / TMPFILE_CHUNK_SIZE;
            let chunk_off = dst_pos % TMPFILE_CHUNK_SIZE;
            let copy_len = remaining.min(TMPFILE_CHUNK_SIZE - chunk_off);
            state.chunks[chunk_idx][chunk_off..chunk_off + copy_len]
                .copy_from_slice(&buf[src_pos..src_pos + copy_len]);
            src_pos += copy_len;
            dst_pos += copy_len;
            remaining -= copy_len;
        }
        *pos = end;
        let now = current_timespec();
        state.mtime = now;
        state.ctime = now;
        Ok(buf.len())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut state = self.backing.state.lock();
        let src_pos = offset as usize;
        let available = state.len.saturating_sub(src_pos);
        let total = available.min(buf.len());
        let mut remaining = total;
        let mut src_pos = src_pos;
        let mut dst_pos = 0;
        while remaining > 0 {
            let chunk_idx = src_pos / TMPFILE_CHUNK_SIZE;
            let chunk_off = src_pos % TMPFILE_CHUNK_SIZE;
            let copy_len = remaining.min(TMPFILE_CHUNK_SIZE - chunk_off);
            if let Some(chunk) = state.chunks.get(chunk_idx) {
                buf[dst_pos..dst_pos + copy_len]
                    .copy_from_slice(&chunk[chunk_off..chunk_off + copy_len]);
            } else {
                buf[dst_pos..dst_pos + copy_len].fill(0);
            }
            src_pos += copy_len;
            dst_pos += copy_len;
            remaining -= copy_len;
        }
        state.atime = current_timespec();
        Ok(total)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> LinuxResult<usize> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut state = self.backing.state.lock();
        let start = if self.status_flags.load(Ordering::Acquire) & (ctypes::O_APPEND as usize) != 0 {
            state.len
        } else {
            offset as usize
        };
        let end = start.saturating_add(buf.len());
        state.ensure_len(end);
        let mut remaining = buf.len();
        let mut src_pos = 0;
        let mut dst_pos = start;
        while remaining > 0 {
            let chunk_idx = dst_pos / TMPFILE_CHUNK_SIZE;
            let chunk_off = dst_pos % TMPFILE_CHUNK_SIZE;
            let copy_len = remaining.min(TMPFILE_CHUNK_SIZE - chunk_off);
            state.chunks[chunk_idx][chunk_off..chunk_off + copy_len]
                .copy_from_slice(&buf[src_pos..src_pos + copy_len]);
            src_pos += copy_len;
            dst_pos += copy_len;
            remaining -= copy_len;
        }
        let now = current_timespec();
        state.mtime = now;
        state.ctime = now;
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        Ok(self.backing.stat())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        let mut flags = self.status_flags.load(Ordering::Acquire);
        if nonblocking {
            flags |= ctypes::O_NONBLOCK as usize;
        } else {
            flags &= !(ctypes::O_NONBLOCK as usize);
        }
        self.status_flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn set_append(&self, append: bool) -> LinuxResult {
        let mut flags = self.status_flags.load(Ordering::Acquire);
        if append {
            flags |= ctypes::O_APPEND as usize;
        } else {
            flags &= !(ctypes::O_APPEND as usize);
        }
        self.status_flags.store(flags, Ordering::Release);
        Ok(())
    }

    fn lock_key(&self) -> Option<(u64, u64)> {
        Some((TMPFILE_FS_DEV_ID, self.backing.inode))
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let state = self.backing.state.lock();
        let mut current = self.pos.lock();
        let len = state.len as i64;
        let next = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::Current(off) => *current as i64 + off,
            SeekFrom::End(off) => len + off,
        };
        if next < 0 {
            return Err(LinuxError::EINVAL);
        }
        *current = next as usize;
        Ok(*current as u64)
    }

    fn status_flags(&self) -> usize {
        self.status_flags.load(Ordering::Acquire)
    }

    fn sync_all(&self) -> LinuxResult {
        Ok(())
    }

    fn truncate(&self, length: u64) -> LinuxResult {
        if self.status_flags.load(Ordering::Acquire) & (O_PATH as usize) != 0 {
            return Err(LinuxError::EBADF);
        }
        let mut state = self.backing.state.lock();
        let mut pos = self.pos.lock();
        state.truncate(length as usize);
        *pos = (*pos).min(length as usize);
        let now = current_timespec();
        state.mtime = now;
        state.ctime = now;
        Ok(())
    }
}

pub fn set_file_times(
    fd: c_int,
    atime: ctypes::timespec,
    mtime: ctypes::timespec,
) -> LinuxResult<()> {
    let file = get_file_like(fd)?;
    if let Ok(tmp) = file.clone().into_any().downcast::<TmpFile>() {
        tmp.set_times(atime, mtime);
    } else if let Ok(file) = file.into_any().downcast::<File>() {
        file.set_times(atime, mtime);
    }
    Ok(())
}

pub fn get_file_times(fd: c_int) -> LinuxResult<Option<(ctypes::timespec, ctypes::timespec)>> {
    let file = get_file_like(fd)?;
    if let Ok(tmp) = file.clone().into_any().downcast::<TmpFile>() {
        let state = tmp.backing.state.lock();
        return Ok(Some((state.atime, state.mtime)));
    }
    if let Ok(file) = file.into_any().downcast::<File>() {
        let times = *file.times.lock();
        return Ok(Some((times.atime, times.mtime)));
    }
    Ok(None)
}

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, _mode: ctypes::mode_t) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    if flags & O_PATH != 0 {
        options.path_only(true);
        if flags & ctypes::O_DIRECTORY != 0 {
            options.directory(true);
        }
        return options;
    }
    match flags & 0b11 {
        ctypes::O_RDONLY => options.read(true),
        ctypes::O_WRONLY => options.write(true),
        _ => {
            options.read(true);
            options.write(true);
        }
    };
    if flags & ctypes::O_APPEND != 0 {
        options.append(true);
    }
    if flags & ctypes::O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & ctypes::O_CREAT != 0 {
        options.create(true);
    }
    if flags & ctypes::O_EXEC != 0 {
        //options.create_new(true);
        options.execute(true);
    }
    if flags & ctypes::O_DIRECTORY != 0 {
        options.directory(true);
    }
    options
}

fn file_status_flags(flags: c_int) -> usize {
    (flags as usize) & !(ctypes::O_CLOEXEC as usize)
}

fn file_descriptor_flags(flags: c_int) -> usize {
    if (flags as u32 & ctypes::O_CLOEXEC) != 0 {
        FD_CLOEXEC_FLAG
    } else {
        0
    }
}

fn reject_final_symlink_for_nofollow(path: &str, flags: c_int) -> LinuxResult<()> {
    if (flags as u32 & ctypes::O_NOFOLLOW) == 0 {
        return Ok(());
    }
    let absolute = if path.starts_with('/') {
        path.to_string()
    } else {
        let cwd = axfs::api::current_dir().map_err(LinuxError::from)?;
        if cwd == "/" {
            format!("/{path}")
        } else {
            format!("{}/{}", cwd.trim_end_matches('/'), path)
        }
    };
    match axfs::api::readlink(absolute.as_str()).map_err(LinuxError::from) {
        Ok(_) => Err(LinuxError::ELOOP),
        Err(LinuxError::EINVAL) | Err(LinuxError::ENOENT) | Err(LinuxError::ENOTDIR) => Ok(()),
        Err(err) => Err(err),
    }
}

fn allow_directory_fallback(flags: c_int) -> bool {
    let flags = flags as u32;
    (flags & 0b11) == ctypes::O_RDONLY
        && (flags & (ctypes::O_CREAT | ctypes::O_TRUNC | ctypes::O_APPEND | O_TMPFILE)) == 0
}

fn open_path(filename: &str, flags: c_int, mode: ctypes::mode_t) -> LinuxResult<c_int> {
    reject_final_symlink_for_nofollow(filename, flags)?;
    let filename = resolve_final_symlink_for_open(filename)?;
    let write_like = (flags as u32 & 0b11) != ctypes::O_RDONLY
        || (flags as u32 & (ctypes::O_CREAT | ctypes::O_TRUNC | ctypes::O_APPEND)) != 0;
    if write_like && axfs::api::is_readonly_path(filename.as_str()).unwrap_or(false) {
        return Err(LinuxError::EROFS);
    }
    if (flags as u32 & O_TMPFILE) == O_TMPFILE {
        return open_tmpfile(filename.as_str(), flags, mode);
    }
    if named_tmpfile_backing(filename.as_str()).is_some() {
        return open_existing_named_tmpfile(filename.as_str(), flags);
    }
    if should_redirect_named_tmpfile(filename.as_str(), flags) {
        return open_named_tmpfile(filename.as_str(), flags, mode);
    }
    if matches!(
        filename.as_str(),
        "/dev/rtc" | "/dev/rtc0" | "/dev/misc/rtc"
    ) {
        return super::fd_ops::add_file_like(Arc::new(RtcDevice));
    }
    if matches!(filename.as_str(), "/dev/null") {
        return super::fd_ops::add_file_like(Arc::new(NullDevice));
    }
    if matches!(filename.as_str(), "/dev/zero") {
        return super::fd_ops::add_file_like(Arc::new(ZeroDevice));
    }
    if matches!(filename.as_str(), "/dev/random" | "/dev/urandom") {
        return super::fd_ops::add_file_like(Arc::new(RandomDevice));
    }
    if matches!(filename.as_str(), "/dev/tty") {
        return super::fd_ops::add_file_like(Arc::new(TtyDevice));
    }
    if matches!(filename.as_str(), "/dev/loop-control") {
        return super::fd_ops::add_file_like(Arc::new(LoopControlDevice));
    }
    if matches!(filename.as_str(), "/dev/loop0") {
        return super::fd_ops::add_file_like(Arc::new(LoopDeviceFile::new()));
    }
    if matches!(filename.as_str(), "/proc/self/stat") {
        return super::fd_ops::add_file_like(Arc::new(ProcSelfStatFile::new()));
    }
    if matches!(filename.as_str(), "/proc/self/maps") {
        return super::fd_ops::add_file_like(Arc::new(ProcSelfMapsFile::new()));
    }
    if matches!(filename.as_str(), "/proc/mounts") {
        return super::fd_ops::add_file_like(Arc::new(ProcMountsFile::new("/proc/mounts")));
    }
    if matches!(filename.as_str(), "/proc/self/mounts") {
        return super::fd_ops::add_file_like(Arc::new(ProcMountsFile::new("/proc/self/mounts")));
    }
    if matches!(filename.as_str(), "/proc/sys/net/ipv4/conf/lo/tag") {
        return super::fd_ops::add_file_like(Arc::new(ProcNetSysctlFile::new(
            ProcNetSysctlKind::LoTag,
        )));
    }
    if matches!(filename.as_str(), "/proc/sys/net/ipv4/conf/default/tag") {
        return super::fd_ops::add_file_like(Arc::new(ProcNetSysctlFile::new(
            ProcNetSysctlKind::DefaultTag,
        )));
    }
    let created = ((flags as u32) & ctypes::O_CREAT != 0)
        && !axfs::api::absolute_path_exists(filename.as_str());
    let options = flags_to_options(flags, mode);
    if options.has_directory() {
        return Directory::from_path(filename.clone(), &options)
            .and_then(Directory::add_to_fd_table);
    }
    let fd = add_file_or_directory_fd(
        axfs::fops::File::open,
        axfs::fops::Directory::open_dir,
        filename.as_str(),
        filename.as_str(),
        &options,
        allow_directory_fallback(flags),
        file_status_flags(flags),
        file_descriptor_flags(flags),
        (flags as u32 & ctypes::O_TRUNC) != 0,
    )?;
    if created {
        apply_created_metadata(filename.as_str(), mode, false)?;
    }
    Ok(fd)
}

/// Open a file by `filename` and insert it into the file descriptor table.
///
/// Return its index in the file table (`fd`). Return `EMFILE` if it already
/// has the maximum number of files open.
pub fn sys_open(filename: *const c_char, flags: c_int, mode: ctypes::mode_t) -> c_int {
    let filename = char_ptr_to_str(filename);
    debug!("sys_open <= {:?} {:#o} {:#o}", filename, flags, mode);
    syscall_body!(sys_open, { open_path(filename?, flags, mode) })
}

/// Open or create a file.
/// fd: file descriptor
/// filename: file path to be opened or created
/// flags: open flags
/// mode: see man 7 inode
/// return new file descriptor if succeed, or return -1.
pub fn sys_openat(
    dirfd: c_int,
    filename: *const c_char,
    flags: c_int,
    mode: ctypes::mode_t,
) -> c_int {
    let filename = char_ptr_to_str(filename);
    debug!(
        "sys_openat <= {} {:?} {:#o} {:#o}",
        dirfd, filename, flags, mode
    );
    syscall_body!(sys_openat, {
        let filename = filename?;
        if (flags as u32 & O_TMPFILE) == O_TMPFILE {
            return open_tmpfile_at(dirfd, filename, flags, mode);
        }

        if filename.starts_with('/') || dirfd == AT_FDCWD as _ {
            return open_path(filename, flags, mode);
        }

        let options = flags_to_options(flags, mode);
        Directory::from_fd(dirfd).and_then(|dir| {
            let dir_path = dir.path().trim_end_matches('/');
            let full_path = if dir_path.is_empty() {
                alloc::format!("/{}", filename)
            } else {
                alloc::format!("{dir_path}/{}", filename)
            };
            reject_final_symlink_for_nofollow(full_path.as_str(), flags)?;
            if named_tmpfile_backing(full_path.as_str()).is_some() {
                return open_existing_named_tmpfile(full_path.as_str(), flags);
            }
            if should_redirect_named_tmpfile(full_path.as_str(), flags) {
                return open_named_tmpfile(full_path.as_str(), flags, mode);
            }
            add_file_or_directory_fd(
                |filename, options| dir.inner.lock().open_file_at(filename, options),
                |filename, options| dir.inner.lock().open_dir_at(filename, options),
                filename,
                full_path.as_str(),
                &options,
                allow_directory_fallback(flags),
                file_status_flags(flags),
                file_descriptor_flags(flags),
                (flags as u32 & ctypes::O_TRUNC) != 0,
            )
        })
    })
}

/// Use the function to open file or directory, then add into file descriptor table.
/// First try opening files, if fails, try directory.
fn add_file_or_directory_fd<F, D, E>(
    open_file: F,
    open_dir: D,
    open_name: &str,
    record_path: &str,
    options: &OpenOptions,
    allow_directory_fallback: bool,
    status_flags: usize,
    fd_flags: usize,
    enforce_truncate: bool,
) -> LinuxResult<c_int>
where
    E: Into<LinuxError>,
    F: FnOnce(&str, &OpenOptions) -> Result<axfs::fops::File, E>,
    D: FnOnce(&str, &OpenOptions) -> Result<axfs::fops::Directory, E>,
{
    match open_file(open_name, options).map_err(Into::into) {
        Ok(f) => {
            if f.get_attr()?.file_type().is_dir() {
                drop(f);
                open_dir(open_name, options)
                    .map_err(Into::into)
                    .map(|d| Directory::new(d, record_path.into()))
                    .and_then(Directory::add_to_fd_table)
            } else {
                let file = File::new(f, record_path.into(), status_flags);
                if enforce_truncate {
                    file.inner.lock().truncate(0).map_err(LinuxError::from)?;
                    let now = current_timespec();
                    file.set_times(now, now);
                }
                file.add_to_fd_table_with_flags(fd_flags)
            }
        }
        Err(LinuxError::EISDIR) => {
            if !allow_directory_fallback {
                return Err(LinuxError::EISDIR);
            }
            open_dir(open_name, options)
                .map_err(Into::into)
                .map_err(|err| {
                    if matches!(err, LinuxError::EINVAL) {
                        LinuxError::EISDIR
                    } else {
                        err
                    }
                })
                .map(|d| Directory::new(d, record_path.into()))
                .and_then(Directory::add_to_fd_table)
        }
        Err(e) => Err(e),
    }
}

/// Set the position of the file indicated by `fd`.
///
/// Return its position after seek.
pub fn sys_lseek(fd: c_int, offset: ctypes::off_t, whence: c_int) -> ctypes::off_t {
    debug!("sys_lseek <= {} {} {}", fd, offset, whence);
    syscall_body!(sys_lseek, {
        let pos = match whence {
            0 => SeekFrom::Start(offset as _),
            1 => SeekFrom::Current(offset as _),
            2 => SeekFrom::End(offset as _),
            _ => return Err(LinuxError::EINVAL),
        };
        let off = get_file_like(fd)?.seek(pos)?;
        Ok(off)
    })
}

/// Get the file metadata by `path` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_stat(path: *const c_char, buf: *mut ctypes::stat) -> c_int {
    let path = char_ptr_to_str(path);
    debug!("sys_stat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_stat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if let Some(backing) = named_tmpfile_backing(path?) {
            unsafe { *buf = backing.stat() };
            return Ok(0);
        }
        if let Some(stat) = virtual_device_stat(path?) {
            unsafe { *buf = stat };
            return Ok(0);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        let file = axfs::fops::File::open(path?, &options)?;
        let st = File::new(file, path?.to_string(), ctypes::O_RDONLY as usize).stat()?;
        unsafe { *buf = st };
        Ok(0)
    })
}

/// Get file metadata by `fd` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_fstat(fd: c_int, buf: *mut ctypes::stat) -> c_int {
    debug!("sys_fstat <= {} {:#x}", fd, buf as usize);
    syscall_body!(sys_fstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }

        unsafe { *buf = get_file_like(fd)?.stat()? };
        Ok(0)
    })
}

/// Get the metadata of the symbolic link and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_lstat(path: *const c_char, buf: *mut ctypes::stat) -> ctypes::ssize_t {
    let path = char_ptr_to_str(path);
    debug!("sys_lstat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_lstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if let Some(backing) = named_tmpfile_backing(path?) {
            unsafe { *buf = backing.stat() };
            return Ok(0);
        }
        if let Some(stat) = virtual_device_stat(path?) {
            unsafe { *buf = stat };
            return Ok(0);
        }
        let mut options = OpenOptions::new();
        options.read(true);
        let file = axfs::fops::File::open(path?, &options)?;
        let st = File::new(file, path?.to_string(), ctypes::O_RDONLY as usize).stat()?;
        unsafe { *buf = st };
        Ok(0)
    })
}

/// Get the path of the current directory.
pub fn sys_getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    debug!("sys_getcwd <= {:#x} {}", buf as usize, size);
    syscall_body!(sys_getcwd, {
        if buf.is_null() {
            return Ok(core::ptr::null::<c_char>() as _);
        }
        let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size as _) };
        let cwd = axfs::api::current_dir()?;
        let cwd = cwd.as_bytes();
        if cwd.len() < size {
            dst[..cwd.len()].copy_from_slice(cwd);
            dst[cwd.len()] = 0;
            Ok(buf)
        } else {
            Err(LinuxError::ERANGE)
        }
    })
}

/// Rename `old` to `new`
/// If new exists, it is first removed.
///
/// Return 0 if the operation succeeds, otherwise return -1.
pub fn sys_rename(old: *const c_char, new: *const c_char) -> c_int {
    syscall_body!(sys_rename, {
        let old_path = char_ptr_to_str(old)?;
        let new_path = char_ptr_to_str(new)?;
        debug!("sys_rename <= old: {:?}, new: {:?}", old_path, new_path);
        axfs::api::rename(old_path, new_path)?;
        rename_named_tmpfile_path(old_path, new_path);
        Ok(0)
    })
}

pub fn remove_named_tmpfile_path(path: &str) {
    let normalized = normalize_named_tmpfile_path(path);
    NAMED_TMPFILES.lock().remove(normalized.as_str());
}

pub fn rename_named_tmpfile_path(old: &str, new: &str) {
    let old = normalize_named_tmpfile_path(old);
    let new = normalize_named_tmpfile_path(new);
    let mut named_tmpfiles = NAMED_TMPFILES.lock();
    if let Some(backing) = named_tmpfiles.remove(old.as_str()) {
        named_tmpfiles.insert(new, backing);
    }
}

/// Directory wrapper for `axfs::fops::Directory`.
pub struct Directory {
    inner: Mutex<axfs::fops::Directory>,
    path: String,
    removed_generation: u64,
}

impl Directory {
    fn new(inner: axfs::fops::Directory, path: String) -> Self {
        let path = normalize_fd_path(path, true);
        Self {
            inner: Mutex::new(inner),
            removed_generation: removed_directory_generation(path.as_str()),
            path,
        }
    }

    fn from_path(path: String, options: &OpenOptions) -> LinuxResult<Self> {
        axfs::fops::Directory::open_dir(&path, options)
            .map_err(Into::into)
            .map(|d| Self::new(d, path))
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    /// Open a directory by `fd`.
    pub fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any()
            .downcast::<Self>()
            .map_err(|_| LinuxError::EINVAL)
    }

    /// Get the path of the directory.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get the inner directory handle.
    pub fn inner(&self) -> &Mutex<axfs::fops::Directory> {
        &self.inner
    }

    /// Read directory entries using the per-fd cursor maintained by the
    /// underlying directory object.
    pub fn read_dir(&self, dirents: &mut [axfs::fops::DirEntry]) -> LinuxResult<usize> {
        if removed_directory_generation(self.path.as_str()) != self.removed_generation {
            return Err(LinuxError::ENOENT);
        }
        Ok(self.inner.lock().read_dir(dirents)?)
    }
}

impl FileLike for Directory {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let mut options = OpenOptions::new();
        options.read(true);
        let metadata = axfs::fops::File::open(self.path(), &options)?.get_attr()?;
        let ty = metadata.file_type() as u8;
        let (uid, gid, mode) = axfs::api::path_owner_mode(self.path(), metadata);
        let perm = mode as u32;
        let st_mode = ((ty as u32) << 12) | perm;
        let (atime, mtime, ctime) = get_path_times(self.path(), true);
        Ok(ctypes::stat {
            st_dev: REGULAR_FS_DEV_ID,
            st_ino: synthetic_inode_from_path(self.path()),
            st_nlink: 1,
            st_mode,
            st_uid: uid,
            st_gid: gid,
            st_size: metadata.size() as _,
            st_blocks: metadata.blocks() as _,
            st_blksize: DEFAULT_FILE_BLKSIZE,
            st_atime: atime,
            st_mtime: mtime,
            st_ctime: ctime,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}
