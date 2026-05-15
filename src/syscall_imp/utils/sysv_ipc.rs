use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use axerrno::LinuxError;
use axhal::{paging::MappingFlags, time::wall_time};
use axmm::SharedFrames;
use axsync::Mutex;
use axtask::{current, TaskExtRef, WaitQueue};
use core::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use memory_addr::{MemoryAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};
use spin::Once;

use crate::{
    syscall_body,
    usercopy::{copy_from_user, copy_to_user, read_value_from_user, write_value_to_user},
};

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: i32 = 0o1000;
const IPC_EXCL: i32 = 0o2000;
const IPC_NOWAIT: i32 = 0o4000;
const IPC_RMID: i32 = 0;
const IPC_SET: i32 = 1;
const IPC_STAT: i32 = 2;
const IPC_INFO: i32 = 3;

const SHM_RDONLY: i32 = 0o10000;
const SHM_RND: i32 = 0o20000;
const SHM_REMAP: i32 = 0o40000;
const SHM_HUGETLB: i32 = 0o4000;
const SHM_DEST: u32 = 0o1000;
const SHM_LOCKED: u32 = 0o2000;
const SHM_LOCK: i32 = 11;
const SHM_UNLOCK: i32 = 12;
const SHM_STAT: i32 = 13;
const SHM_INFO: i32 = 14;
const SHM_STAT_ANY: i32 = 15;

const MSG_STAT: i32 = 11;
const MSG_INFO: i32 = 12;
const MSG_STAT_ANY: i32 = 13;
const MSG_NOERROR: i32 = 0o10000;
const MSG_EXCEPT: i32 = 0o20000;
const MSG_COPY: i32 = 0o40000;

const SHMMNI: usize = 4096;
const DEFAULT_SHMMAX: usize = 1 << 30;
const MSGMNI: usize = 4096;
const DEFAULT_MSGMAX: usize = 8192;
const DEFAULT_MSGMNB: usize = 16384;

static SHMMAX_VALUE: AtomicUsize = AtomicUsize::new(DEFAULT_SHMMAX);
static SHMMNI_VALUE: AtomicUsize = AtomicUsize::new(SHMMNI);
static SHM_NEXT_ID_VALUE: AtomicI32 = AtomicI32::new(-1);
static MSGMNI_VALUE: AtomicUsize = AtomicUsize::new(MSGMNI);
static MSG_NEXT_ID_VALUE: AtomicI32 = AtomicI32::new(-1);

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserIpcPerm {
    __key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u16,
    __pad1: u16,
    __seq: u16,
    __pad2: u16,
    __unused1: u64,
    __unused2: u64,
}

#[cfg(target_arch = "loongarch64")]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserIpcPerm {
    __key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    __seq: u16,
    __pad2: u16,
    __unused1: u64,
    __unused2: u64,
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserShmidDs {
    shm_perm: UserIpcPerm,
    shm_segsz: usize,
    shm_atime: i64,
    shm_dtime: i64,
    shm_ctime: i64,
    shm_cpid: i32,
    shm_lpid: i32,
    shm_nattch: u64,
    __unused4: u64,
    __unused5: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserShminfo {
    shmmax: usize,
    shmmin: usize,
    shmmni: usize,
    shmseg: usize,
    shmall: usize,
    __unused: [usize; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserShmInfo {
    used_ids: i32,
    shm_tot: usize,
    shm_rss: usize,
    shm_swp: usize,
    swap_attempts: usize,
    swap_successes: usize,
}

#[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserMsqidDs {
    msg_perm: UserIpcPerm,
    msg_stime: i64,
    msg_rtime: i64,
    msg_ctime: i64,
    __msg_cbytes: u64,
    msg_qnum: u64,
    msg_qbytes: u64,
    msg_lspid: i32,
    msg_lrpid: i32,
    __unused4: u64,
    __unused5: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct UserMsginfo {
    msgpool: i32,
    msgmap: i32,
    msgmax: i32,
    msgmnb: i32,
    msgmni: i32,
    msgssz: i32,
    msgtql: i32,
    msgseg: u16,
}

#[derive(Clone)]
struct ShmAttachment {
    shmid: i32,
    addr: usize,
    map_size: usize,
}

#[derive(Clone)]
struct ShmSegment {
    key: Option<i32>,
    size: usize,
    map_size: usize,
    frames: Arc<SharedFrames>,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    cpid: i32,
    lpid: i32,
    atime: i64,
    dtime: i64,
    ctime: i64,
    nattch: usize,
    removed: bool,
}

struct SysvShmRegistry {
    next_id: i32,
    segments: BTreeMap<i32, ShmSegment>,
    keys: BTreeMap<i32, i32>,
    proc_attachments: BTreeMap<usize, Vec<ShmAttachment>>,
}

impl Default for SysvShmRegistry {
    fn default() -> Self {
        Self {
            next_id: 1,
            segments: BTreeMap::new(),
            keys: BTreeMap::new(),
            proc_attachments: BTreeMap::new(),
        }
    }
}

#[derive(Clone)]
struct MsgMessage {
    mtype: i64,
    data: Vec<u8>,
}

struct MsgQueueState {
    key: Option<i32>,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    qbytes: usize,
    cbytes: usize,
    messages: VecDeque<MsgMessage>,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: i32,
    lrpid: i32,
    removed: bool,
}

struct SysvMsgQueue {
    state: Mutex<MsgQueueState>,
    wait_queue: WaitQueue,
    change_seq: AtomicUsize,
}

impl SysvMsgQueue {
    fn new(state: MsgQueueState) -> Self {
        Self {
            state: Mutex::new(state),
            wait_queue: WaitQueue::new(),
            change_seq: AtomicUsize::new(0),
        }
    }

    fn notify_all(&self) {
        self.change_seq.fetch_add(1, Ordering::AcqRel);
        self.wait_queue.notify_all(true);
    }
}

struct SysvMsgRegistry {
    next_id: i32,
    queues: BTreeMap<i32, Arc<SysvMsgQueue>>,
    keys: BTreeMap<i32, i32>,
}

impl Default for SysvMsgRegistry {
    fn default() -> Self {
        Self {
            next_id: 1,
            queues: BTreeMap::new(),
            keys: BTreeMap::new(),
        }
    }
}

fn shm_registry() -> &'static Mutex<SysvShmRegistry> {
    static REGISTRY: Once<Mutex<SysvShmRegistry>> = Once::new();
    REGISTRY.call_once(|| Mutex::new(SysvShmRegistry::default()))
}

fn msg_registry() -> &'static Mutex<SysvMsgRegistry> {
    static REGISTRY: Once<Mutex<SysvMsgRegistry>> = Once::new();
    REGISTRY.call_once(|| Mutex::new(SysvMsgRegistry::default()))
}

fn current_uid() -> u32 {
    axfs::api::current_euid() as u32
}

fn current_gid() -> u32 {
    axfs::api::current_egid() as u32
}

fn current_pid() -> i32 {
    current().task_ext().proc_id as i32
}

fn current_proc_id() -> usize {
    current().task_ext().proc_id
}

fn current_is_root() -> bool {
    current_uid() == 0
}

fn now_time_sec() -> i64 {
    wall_time().as_secs() as i64
}

fn current_shmmax() -> usize {
    SHMMAX_VALUE.load(Ordering::Relaxed).max(1)
}

fn current_shmmni() -> usize {
    SHMMNI_VALUE.load(Ordering::Relaxed).max(1)
}

fn current_msgmni() -> usize {
    MSGMNI_VALUE.load(Ordering::Relaxed).max(1)
}

fn read_shm_next_id_request() -> Option<i32> {
    let value = SHM_NEXT_ID_VALUE.load(Ordering::Relaxed);
    (value >= 0).then_some(value)
}

fn reset_shm_next_id_request() {
    SHM_NEXT_ID_VALUE.store(-1, Ordering::Relaxed);
}

fn read_msg_next_id_request() -> Option<i32> {
    let value = MSG_NEXT_ID_VALUE.load(Ordering::Relaxed);
    (value >= 0).then_some(value)
}

fn reset_msg_next_id_request() {
    MSG_NEXT_ID_VALUE.store(-1, Ordering::Relaxed);
}

fn format_sysvipc_shm_contents_locked(registry: &SysvShmRegistry) -> String {
    let mut text =
        "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime\n"
            .to_string();
    for (&shmid, segment) in &registry.segments {
        let key = segment.key.unwrap_or(0);
        text.push_str(
            format!(
                "{key:10} {shmid:10} {:5o} {:21} {:5} {:5} {:6} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
                segment.mode,
                segment.size,
                segment.cpid,
                segment.lpid,
                segment.nattch,
                segment.uid,
                segment.gid,
                segment.cuid,
                segment.cgid,
                segment.atime,
                segment.dtime,
                segment.ctime,
            )
            .as_str(),
        );
    }
    text
}

fn format_sysvipc_msg_contents_locked(registry: &SysvMsgRegistry) -> String {
    let mut text =
        "       key      msqid perms                  cbytes      qnum   lspid   lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n"
            .to_string();
    for (&msqid, queue) in &registry.queues {
        let state = queue.state.lock();
        if state.removed {
            continue;
        }
        let key = state.key.unwrap_or(0);
        text.push_str(
            format!(
                "{key:10} {msqid:10} {:5o} {:23} {:9} {:7} {:7} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
                state.mode,
                state.cbytes,
                state.messages.len(),
                state.lspid,
                state.lrpid,
                state.uid,
                state.gid,
                state.cuid,
                state.cgid,
                state.stime,
                state.rtime,
                state.ctime,
            )
            .as_str(),
        );
    }
    text
}

fn sync_sysv_shm_procfs_locked(registry: &SysvShmRegistry) {
    let _ = registry;
}

fn sync_sysv_msg_procfs_locked(registry: &SysvMsgRegistry) {
    let _ = registry;
}

pub(crate) fn proc_sysvipc_shm_contents() -> String {
    let registry = shm_registry().lock();
    format_sysvipc_shm_contents_locked(&registry)
}

pub(crate) fn proc_sysvipc_msg_contents() -> String {
    let registry = msg_registry().lock();
    format_sysvipc_msg_contents_locked(&registry)
}

pub(crate) fn proc_shmmax_contents() -> String {
    format!("{}\n", current_shmmax())
}

pub(crate) fn proc_shmmni_contents() -> String {
    format!("{}\n", current_shmmni())
}

pub(crate) fn proc_shm_next_id_contents() -> String {
    format!("{}\n", SHM_NEXT_ID_VALUE.load(Ordering::Relaxed))
}

pub(crate) fn proc_msgmni_contents() -> String {
    format!("{}\n", current_msgmni())
}

pub(crate) fn proc_msg_next_id_contents() -> String {
    format!("{}\n", MSG_NEXT_ID_VALUE.load(Ordering::Relaxed))
}

pub(crate) fn set_proc_shmmax_value(value: usize) -> Result<(), LinuxError> {
    if value == 0 {
        return Err(LinuxError::EINVAL);
    }
    SHMMAX_VALUE.store(value, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn set_proc_shmmni_value(value: usize) -> Result<(), LinuxError> {
    if value == 0 {
        return Err(LinuxError::EINVAL);
    }
    SHMMNI_VALUE.store(value, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn set_proc_shm_next_id_value(value: i32) -> Result<(), LinuxError> {
    if value < -1 {
        return Err(LinuxError::EINVAL);
    }
    SHM_NEXT_ID_VALUE.store(value, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn set_proc_msgmni_value(value: usize) -> Result<(), LinuxError> {
    if value == 0 {
        return Err(LinuxError::EINVAL);
    }
    MSGMNI_VALUE.store(value, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn set_proc_msg_next_id_value(value: i32) -> Result<(), LinuxError> {
    if value < -1 {
        return Err(LinuxError::EINVAL);
    }
    MSG_NEXT_ID_VALUE.store(value, Ordering::Relaxed);
    Ok(())
}

fn alloc_shmid(registry: &mut SysvShmRegistry) -> i32 {
    loop {
        let shmid = registry.next_id;
        registry.next_id = registry.next_id.saturating_add(1).max(1);
        if !registry.segments.contains_key(&shmid) {
            return shmid;
        }
    }
}

fn alloc_shmid_with_request(registry: &mut SysvShmRegistry, requested: Option<i32>) -> i32 {
    if let Some(shmid) = requested {
        if !registry.segments.contains_key(&shmid) {
            registry.next_id = registry.next_id.max(shmid.saturating_add(1)).max(1);
            return shmid;
        }
    }
    alloc_shmid(registry)
}

fn alloc_msgid(registry: &mut SysvMsgRegistry) -> i32 {
    loop {
        let msgid = registry.next_id;
        registry.next_id = registry.next_id.saturating_add(1).max(1);
        if !registry.queues.contains_key(&msgid) {
            return msgid;
        }
    }
}

fn alloc_msgid_with_request(registry: &mut SysvMsgRegistry, requested: Option<i32>) -> i32 {
    if let Some(msgid) = requested {
        if !registry.queues.contains_key(&msgid) {
            registry.next_id = registry.next_id.max(msgid.saturating_add(1)).max(1);
            return msgid;
        }
    }
    alloc_msgid(registry)
}

fn segment_mode_bits_for_current(segment: &ShmSegment) -> u32 {
    let uid = current_uid();
    let gid = current_gid();
    let (supp_groups, supp_len) = axfs::api::current_supplementary_gids();
    let in_group = gid == segment.gid
        || gid == segment.cgid
        || supp_groups[..supp_len]
            .iter()
            .any(|group| *group == segment.gid || *group == segment.cgid);
    let shift = if uid == segment.uid || uid == segment.cuid {
        6
    } else if in_group {
        3
    } else {
        0
    };
    (segment.mode >> shift) & 0o7
}

fn segment_can_read(segment: &ShmSegment) -> bool {
    current_is_root() || (segment_mode_bits_for_current(segment) & 0o4) != 0
}

fn segment_can_write(segment: &ShmSegment) -> bool {
    current_is_root() || (segment_mode_bits_for_current(segment) & 0o2) != 0
}

fn segment_owner_or_root(segment: &ShmSegment) -> bool {
    let uid = current_uid();
    current_is_root() || uid == segment.uid || uid == segment.cuid
}

fn queue_mode_bits_for_current(state: &MsgQueueState) -> u32 {
    let uid = current_uid();
    let gid = current_gid();
    let (supp_groups, supp_len) = axfs::api::current_supplementary_gids();
    let in_group = gid == state.gid
        || gid == state.cgid
        || supp_groups[..supp_len]
            .iter()
            .any(|group| *group == state.gid || *group == state.cgid);
    let shift = if uid == state.uid || uid == state.cuid {
        6
    } else if in_group {
        3
    } else {
        0
    };
    (state.mode >> shift) & 0o7
}

fn queue_can_read(state: &MsgQueueState) -> bool {
    current_is_root() || (queue_mode_bits_for_current(state) & 0o4) != 0
}

fn queue_can_write(state: &MsgQueueState) -> bool {
    current_is_root() || (queue_mode_bits_for_current(state) & 0o2) != 0
}

fn queue_owner_or_root(state: &MsgQueueState) -> bool {
    let uid = current_uid();
    current_is_root() || uid == state.uid || uid == state.cuid
}

fn release_segment_storage(segment: ShmSegment) {
    drop(segment);
}

fn maybe_collect_removed_segment(registry: &mut SysvShmRegistry, shmid: i32) -> Option<ShmSegment> {
    if registry
        .segments
        .get(&shmid)
        .is_some_and(|segment| segment.removed && segment.nattch == 0)
    {
        registry.segments.remove(&shmid)
    } else {
        None
    }
}

fn detach_attachment_record(
    registry: &mut SysvShmRegistry,
    proc_id: usize,
    attachment: &ShmAttachment,
) -> Option<ShmSegment> {
    if let Some(entries) = registry.proc_attachments.get_mut(&proc_id) {
        if let Some(index) = entries
            .iter()
            .position(|entry| entry.shmid == attachment.shmid && entry.addr == attachment.addr)
        {
            entries.remove(index);
        }
        if entries.is_empty() {
            registry.proc_attachments.remove(&proc_id);
        }
    }
    if let Some(segment) = registry.segments.get_mut(&attachment.shmid) {
        segment.nattch = segment.nattch.saturating_sub(1);
        segment.dtime = now_time_sec();
        segment.lpid = current_pid();
    }
    sync_sysv_shm_procfs_locked(registry);
    maybe_collect_removed_segment(registry, attachment.shmid)
}

fn build_user_shmid_ds(segment: &ShmSegment) -> UserShmidDs {
    UserShmidDs {
        shm_perm: UserIpcPerm {
            __key: segment.key.unwrap_or(IPC_PRIVATE),
            uid: segment.uid,
            gid: segment.gid,
            cuid: segment.cuid,
            cgid: segment.cgid,
            mode: segment.mode as _,
            ..UserIpcPerm::default()
        },
        shm_segsz: segment.size,
        shm_atime: segment.atime,
        shm_dtime: segment.dtime,
        shm_ctime: segment.ctime,
        shm_cpid: segment.cpid,
        shm_lpid: segment.lpid,
        shm_nattch: segment.nattch as u64,
        ..UserShmidDs::default()
    }
}

fn build_user_shminfo() -> UserShminfo {
    UserShminfo {
        shmmax: current_shmmax(),
        shmmin: 1,
        shmmni: current_shmmni(),
        shmseg: current_shmmni(),
        shmall: usize::MAX >> 24,
        ..UserShminfo::default()
    }
}

fn build_user_shm_info(registry: &SysvShmRegistry) -> UserShmInfo {
    UserShmInfo {
        used_ids: registry
            .segments
            .values()
            .filter(|segment| !segment.removed)
            .count() as i32,
        shm_tot: registry
            .segments
            .values()
            .filter(|segment| !segment.removed)
            .map(|segment| segment.map_size / PAGE_SIZE_4K)
            .sum(),
        shm_rss: registry
            .segments
            .values()
            .filter(|segment| !segment.removed)
            .map(|segment| segment.map_size / PAGE_SIZE_4K)
            .sum(),
        shm_swp: 0,
        swap_attempts: 0,
        swap_successes: 0,
    }
}

fn build_user_msqid_ds(state: &MsgQueueState) -> UserMsqidDs {
    UserMsqidDs {
        msg_perm: UserIpcPerm {
            __key: state.key.unwrap_or(IPC_PRIVATE),
            uid: state.uid,
            gid: state.gid,
            cuid: state.cuid,
            cgid: state.cgid,
            mode: state.mode as _,
            ..UserIpcPerm::default()
        },
        msg_stime: state.stime,
        msg_rtime: state.rtime,
        msg_ctime: state.ctime,
        __msg_cbytes: state.cbytes as u64,
        msg_qnum: state.messages.len() as u64,
        msg_qbytes: state.qbytes as u64,
        msg_lspid: state.lspid,
        msg_lrpid: state.lrpid,
        ..UserMsqidDs::default()
    }
}

fn build_user_msginfo_ipc() -> UserMsginfo {
    UserMsginfo {
        msgpool: 0,
        msgmap: 0,
        msgmax: DEFAULT_MSGMAX as i32,
        msgmnb: DEFAULT_MSGMNB as i32,
        msgmni: current_msgmni() as i32,
        msgssz: 16,
        msgtql: 0,
        msgseg: 0,
    }
}

fn build_user_msginfo_stats(registry: &SysvMsgRegistry) -> UserMsginfo {
    let mut queue_count = 0i32;
    let mut msg_count = 0i32;
    let mut msg_bytes = 0i32;
    for queue in registry.queues.values() {
        let state = queue.state.lock();
        if state.removed {
            continue;
        }
        queue_count += 1;
        msg_count = msg_count.saturating_add(state.messages.len() as i32);
        msg_bytes = msg_bytes.saturating_add(state.cbytes as i32);
    }
    UserMsginfo {
        msgpool: queue_count,
        msgmap: msg_count,
        msgmax: DEFAULT_MSGMAX as i32,
        msgmnb: DEFAULT_MSGMNB as i32,
        msgmni: current_msgmni() as i32,
        msgssz: 16,
        msgtql: msg_bytes,
        msgseg: 0,
    }
}

fn shmid_from_index(registry: &SysvShmRegistry, index: i32) -> Option<i32> {
    if index < 0 {
        return None;
    }
    registry
        .segments
        .iter()
        .filter(|(_, segment)| !segment.removed)
        .nth(index as usize)
        .map(|(&shmid, _)| shmid)
}

fn max_live_shm_index(registry: &SysvShmRegistry) -> i32 {
    registry
        .segments
        .values()
        .filter(|segment| !segment.removed)
        .count()
        .saturating_sub(1) as i32
}

fn msgid_from_index(registry: &SysvMsgRegistry, index: i32) -> Option<i32> {
    if index < 0 {
        return None;
    }
    registry.queues.keys().nth(index as usize).copied()
}

fn max_live_msg_index(registry: &SysvMsgRegistry) -> i32 {
    registry.queues.len().saturating_sub(1) as i32
}

fn lookup_msg_queue(msqid: i32) -> Result<Arc<SysvMsgQueue>, LinuxError> {
    msg_registry()
        .lock()
        .queues
        .get(&msqid)
        .cloned()
        .ok_or(LinuxError::EINVAL)
}

fn find_message_index(
    messages: &VecDeque<MsgMessage>,
    msgtyp: i64,
    msgflg: i32,
) -> Result<Option<usize>, LinuxError> {
    if (msgflg & MSG_COPY) != 0 {
        if (msgflg & IPC_NOWAIT) == 0 || (msgflg & MSG_EXCEPT) != 0 || msgtyp < 0 {
            return Err(LinuxError::EINVAL);
        }
        return Ok(((msgtyp as usize) < messages.len()).then_some(msgtyp as usize));
    }

    if msgtyp == 0 {
        return Ok((!messages.is_empty()).then_some(0));
    }

    if msgtyp > 0 {
        if (msgflg & MSG_EXCEPT) != 0 {
            return Ok(messages.iter().position(|msg| msg.mtype != msgtyp));
        }
        return Ok(messages.iter().position(|msg| msg.mtype == msgtyp));
    }

    let limit = msgtyp.saturating_abs();
    let mut best_type = i64::MAX;
    let mut best_index = None;
    for (index, msg) in messages.iter().enumerate() {
        if msg.mtype <= limit && msg.mtype < best_type {
            best_type = msg.mtype;
            best_index = Some(index);
        }
    }
    Ok(best_index)
}

fn wait_for_msg_queue_change(queue: &SysvMsgQueue, expected_seq: usize) -> Result<(), LinuxError> {
    if axtask::current_wait_should_interrupt() {
        return Err(LinuxError::EINTR);
    }
    queue.wait_queue.wait_until(|| {
        axtask::current_wait_should_interrupt()
            || queue.change_seq.load(Ordering::Acquire) != expected_seq
    });
    if axtask::current_wait_should_interrupt()
        && queue.change_seq.load(Ordering::Acquire) == expected_seq
    {
        return Err(LinuxError::EINTR);
    }
    Ok(())
}

fn choose_shmat_addr(
    aspace: &axmm::AddrSpace,
    requested: usize,
    map_size: usize,
    shmflg: i32,
) -> Result<VirtAddr, LinuxError> {
    let range = VirtAddrRange::new(aspace.base(), aspace.end());
    if requested == 0 {
        let heap_top = current().task_ext().get_heap_top() as usize;
        let hint = VirtAddr::from_usize(memory_addr::align_up_4k(
            heap_top.saturating_add(0x4000_0000),
        ));
        return aspace
            .find_free_area(hint, map_size, range)
            .or_else(|| aspace.find_free_area(aspace.base(), map_size, range))
            .ok_or(LinuxError::ENOMEM);
    }

    if (shmflg & SHM_RND) != 0 {
        return Ok(VirtAddr::from_usize(memory_addr::align_down_4k(requested)));
    }
    if requested % PAGE_SIZE_4K != 0 {
        return Err(LinuxError::EINVAL);
    }
    let start = VirtAddr::from_usize(requested);
    if (shmflg & SHM_REMAP) == 0 && aspace.find_free_area(start, map_size, range) != Some(start) {
        return Err(LinuxError::EINVAL);
    }
    Ok(start)
}

pub(crate) fn clone_sysv_shm_process(parent_proc_id: usize, child_proc_id: usize) {
    if parent_proc_id == child_proc_id {
        return;
    }
    let mut registry = shm_registry().lock();
    if registry.proc_attachments.contains_key(&child_proc_id) {
        return;
    }
    let Some(parent_attachments) = registry.proc_attachments.get(&parent_proc_id).cloned() else {
        return;
    };
    let now = now_time_sec();
    for attachment in &parent_attachments {
        if let Some(segment) = registry.segments.get_mut(&attachment.shmid) {
            segment.nattch += 1;
            segment.atime = now;
            segment.lpid = child_proc_id as i32;
        }
    }
    registry
        .proc_attachments
        .insert(child_proc_id, parent_attachments);
    sync_sysv_shm_procfs_locked(&registry);
}

pub(crate) fn detach_sysv_shm_process(proc_id: usize, aspace: &mut axmm::AddrSpace) {
    let attachments = {
        shm_registry()
            .lock()
            .proc_attachments
            .get(&proc_id)
            .cloned()
            .unwrap_or_default()
    };
    if attachments.is_empty() {
        return;
    }

    for attachment in &attachments {
        let _ = aspace.unmap(VirtAddr::from_usize(attachment.addr), attachment.map_size);
    }

    let released_segments = {
        let mut registry = shm_registry().lock();
        let mut released = Vec::new();
        for attachment in &attachments {
            if let Some(segment) = detach_attachment_record(&mut registry, proc_id, attachment) {
                released.push(segment);
            }
        }
        released
    };
    for segment in released_segments {
        release_segment_storage(segment);
    }
}

pub(crate) fn sys_shmget(key: i32, size: usize, shmflg: i32) -> isize {
    syscall_body!(sys_shmget, {
        if (shmflg & SHM_HUGETLB) != 0 {
            return Err(LinuxError::EINVAL);
        }

        let mut registry = shm_registry().lock();
        if key != IPC_PRIVATE {
            if let Some(&shmid) = registry.keys.get(&key) {
                let segment = registry.segments.get(&shmid).ok_or(LinuxError::EINVAL)?;
                if (shmflg & IPC_CREAT) != 0 && (shmflg & IPC_EXCL) != 0 {
                    return Err(LinuxError::EEXIST);
                }
                if size != 0 && size > segment.size {
                    return Err(LinuxError::EINVAL);
                }
                let wants_write = (shmflg & 0o222) != 0;
                if !segment_can_read(segment) || (wants_write && !segment_can_write(segment)) {
                    return Err(LinuxError::EACCES);
                }
                return Ok(shmid as usize);
            }
            if (shmflg & IPC_CREAT) == 0 {
                return Err(LinuxError::ENOENT);
            }
        }

        if size == 0 || size > current_shmmax() {
            return Err(LinuxError::EINVAL);
        }
        if registry.segments.len() >= current_shmmni() {
            return Err(LinuxError::ENOSPC);
        }
        let requested_id = read_shm_next_id_request();

        let map_size = memory_addr::align_up_4k(size.max(1));
        let page_count = map_size / PAGE_SIZE_4K;
        let mut frames = Vec::with_capacity(page_count);
        for _ in 0..page_count {
            match axmm::alloc_user_frame(true) {
                Some(frame) => frames.push(frame),
                None => {
                    for frame in frames {
                        axmm::dec_frame_ref(frame);
                    }
                    return Err(LinuxError::ENOMEM);
                }
            }
        }

        let shmid = alloc_shmid_with_request(&mut registry, requested_id);
        let now = now_time_sec();
        let segment = ShmSegment {
            key: (key != IPC_PRIVATE).then_some(key),
            size,
            map_size,
            frames: Arc::new(SharedFrames::new(frames)),
            uid: current_uid(),
            gid: current_gid(),
            cuid: current_uid(),
            cgid: current_gid(),
            mode: (shmflg & 0o777) as u32,
            cpid: current_pid(),
            lpid: 0,
            atime: 0,
            dtime: 0,
            ctime: now,
            nattch: 0,
            removed: false,
        };
        if let Some(segment_key) = segment.key {
            registry.keys.insert(segment_key, shmid);
        }
        registry.segments.insert(shmid, segment);
        sync_sysv_shm_procfs_locked(&registry);
        reset_shm_next_id_request();
        Ok(shmid as usize)
    })
}

pub(crate) fn sys_shmat(shmid: i32, shmaddr: *const u8, shmflg: i32) -> isize {
    syscall_body!(sys_shmat, {
        let (segment, proc_id) = {
            let registry = shm_registry().lock();
            let segment = registry
                .segments
                .get(&shmid)
                .cloned()
                .ok_or(LinuxError::EINVAL)?;
            (segment, current_proc_id())
        };

        if segment.removed {
            return Err(LinuxError::EIDRM);
        }
        if !segment_can_read(&segment)
            || ((shmflg & SHM_RDONLY) == 0 && !segment_can_write(&segment))
        {
            return Err(LinuxError::EACCES);
        }

        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        let start = choose_shmat_addr(&aspace, shmaddr as usize, segment.map_size, shmflg)?;
        if (shmflg & SHM_REMAP) != 0 {
            let _ = aspace.unmap(start, segment.map_size);
        }
        let mut flags = MappingFlags::USER | MappingFlags::READ;
        if (shmflg & SHM_RDONLY) == 0 {
            flags |= MappingFlags::WRITE;
        }
        aspace
            .map_segment_shared(start, segment.map_size, flags, Arc::clone(&segment.frames))
            .map_err(|_| LinuxError::EINVAL)?;
        drop(aspace);

        let mut registry = shm_registry().lock();
        let live_segment = registry.segments.get_mut(&shmid).ok_or(LinuxError::EIDRM)?;
        if live_segment.removed {
            return Err(LinuxError::EIDRM);
        }
        live_segment.nattch += 1;
        live_segment.atime = now_time_sec();
        live_segment.lpid = current_pid();
        registry
            .proc_attachments
            .entry(proc_id)
            .or_default()
            .push(ShmAttachment {
                shmid,
                addr: start.as_usize(),
                map_size: segment.map_size,
            });
        sync_sysv_shm_procfs_locked(&registry);
        Ok(start.as_usize())
    })
}

pub(crate) fn sys_shmdt(shmaddr: *const u8) -> isize {
    syscall_body!(sys_shmdt, {
        let addr = shmaddr as usize;
        if addr == 0 || addr % PAGE_SIZE_4K != 0 {
            return Err(LinuxError::EINVAL);
        }

        let proc_id = current_proc_id();
        let attachment = {
            let registry = shm_registry().lock();
            registry
                .proc_attachments
                .get(&proc_id)
                .and_then(|entries| entries.iter().find(|entry| entry.addr == addr))
                .cloned()
                .ok_or(LinuxError::EINVAL)?
        };

        let curr = current();
        let mut aspace = curr.task_ext().aspace.lock();
        aspace
            .unmap(VirtAddr::from_usize(attachment.addr), attachment.map_size)
            .map_err(|_| LinuxError::EINVAL)?;
        drop(aspace);

        let released_segment = {
            let mut registry = shm_registry().lock();
            detach_attachment_record(&mut registry, proc_id, &attachment)
        };
        if let Some(segment) = released_segment {
            release_segment_storage(segment);
        }
        Ok(0)
    })
}

pub(crate) fn sys_shmctl(shmid: i32, cmd: i32, buf: *mut UserShmidDs) -> isize {
    syscall_body!(sys_shmctl, {
        match cmd {
            IPC_INFO => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                write_value_to_user(buf as *mut UserShminfo, build_user_shminfo())?;
                Ok(current_shmmni().saturating_sub(1))
            }
            SHM_INFO => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let registry = shm_registry().lock();
                write_value_to_user(buf as *mut UserShmInfo, build_user_shm_info(&registry))?;
                Ok(max_live_shm_index(&registry) as usize)
            }
            SHM_STAT | SHM_STAT_ANY => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let registry = shm_registry().lock();
                let real_shmid = shmid_from_index(&registry, shmid).ok_or(LinuxError::EINVAL)?;
                let segment = registry
                    .segments
                    .get(&real_shmid)
                    .cloned()
                    .ok_or(LinuxError::EINVAL)?;
                if segment.removed {
                    return Err(LinuxError::EINVAL);
                }
                if cmd == SHM_STAT && !segment_can_read(&segment) {
                    return Err(LinuxError::EACCES);
                }
                write_value_to_user(buf, build_user_shmid_ds(&segment))?;
                Ok(real_shmid as usize)
            }
            IPC_STAT => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let segment = shm_registry()
                    .lock()
                    .segments
                    .get(&shmid)
                    .cloned()
                    .ok_or(LinuxError::EINVAL)?;
                if segment.removed {
                    return Err(LinuxError::EINVAL);
                }
                if !segment_can_read(&segment) {
                    return Err(LinuxError::EACCES);
                }
                write_value_to_user(buf, build_user_shmid_ds(&segment))?;
                Ok(0)
            }
            IPC_SET => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let user_ds = read_value_from_user(buf as *const UserShmidDs)?;
                let mut registry = shm_registry().lock();
                let segment = registry
                    .segments
                    .get_mut(&shmid)
                    .ok_or(LinuxError::EINVAL)?;
                if segment.removed {
                    return Err(LinuxError::EINVAL);
                }
                if !segment_owner_or_root(segment) {
                    return Err(LinuxError::EPERM);
                }
                segment.uid = user_ds.shm_perm.uid;
                segment.gid = user_ds.shm_perm.gid;
                segment.mode = (segment.mode & !0o777) | ((user_ds.shm_perm.mode as u32) & 0o777);
                segment.ctime = now_time_sec();
                sync_sysv_shm_procfs_locked(&registry);
                Ok(0)
            }
            SHM_LOCK | SHM_UNLOCK => {
                let mut registry = shm_registry().lock();
                let segment = registry
                    .segments
                    .get_mut(&shmid)
                    .ok_or(LinuxError::EINVAL)?;
                if segment.removed {
                    return Err(LinuxError::EINVAL);
                }
                if !segment_owner_or_root(segment) {
                    return Err(LinuxError::EPERM);
                }
                if cmd == SHM_LOCK {
                    segment.mode |= SHM_LOCKED;
                } else {
                    segment.mode &= !SHM_LOCKED;
                }
                segment.ctime = now_time_sec();
                sync_sysv_shm_procfs_locked(&registry);
                Ok(0)
            }
            IPC_RMID => {
                let released_segment = {
                    let mut registry = shm_registry().lock();
                    let segment_key = {
                        let segment = registry
                            .segments
                            .get_mut(&shmid)
                            .ok_or(LinuxError::EINVAL)?;
                        if segment.removed {
                            return Err(LinuxError::EINVAL);
                        }
                        if !segment_owner_or_root(segment) {
                            return Err(LinuxError::EPERM);
                        }
                        let segment_key = segment.key.take();
                        segment.removed = true;
                        segment.mode |= SHM_DEST;
                        segment_key
                    };
                    if let Some(segment_key) = segment_key {
                        registry.keys.remove(&segment_key);
                    }
                    sync_sysv_shm_procfs_locked(&registry);
                    maybe_collect_removed_segment(&mut registry, shmid)
                };
                if let Some(segment) = released_segment {
                    release_segment_storage(segment);
                }
                Ok(0)
            }
            _ => Err(LinuxError::EINVAL),
        }
    })
}

pub(crate) fn sys_msgget(key: i32, msgflg: i32) -> isize {
    syscall_body!(sys_msgget, {
        let mut registry = msg_registry().lock();
        if key != IPC_PRIVATE {
            if let Some(&msgid) = registry.keys.get(&key) {
                let queue = registry
                    .queues
                    .get(&msgid)
                    .cloned()
                    .ok_or(LinuxError::EINVAL)?;
                let state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EINVAL);
                }
                if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                    return Err(LinuxError::EEXIST);
                }
                let wants_read = (msgflg & 0o444) != 0;
                let wants_write = (msgflg & 0o222) != 0;
                if (wants_read && !queue_can_read(&state))
                    || (wants_write && !queue_can_write(&state))
                {
                    return Err(LinuxError::EACCES);
                }
                return Ok(msgid as usize);
            }
            if (msgflg & IPC_CREAT) == 0 {
                return Err(LinuxError::ENOENT);
            }
        }

        if registry.queues.len() >= current_msgmni() {
            return Err(LinuxError::ENOSPC);
        }

        let msgid = alloc_msgid_with_request(&mut registry, read_msg_next_id_request());
        let queue = Arc::new(SysvMsgQueue::new(MsgQueueState {
            key: (key != IPC_PRIVATE).then_some(key),
            uid: current_uid(),
            gid: current_gid(),
            cuid: current_uid(),
            cgid: current_gid(),
            mode: (msgflg & 0o777) as u32,
            qbytes: DEFAULT_MSGMNB,
            cbytes: 0,
            messages: VecDeque::new(),
            stime: 0,
            rtime: 0,
            ctime: now_time_sec(),
            lspid: 0,
            lrpid: 0,
            removed: false,
        }));
        if key != IPC_PRIVATE {
            registry.keys.insert(key, msgid);
        }
        registry.queues.insert(msgid, queue);
        sync_sysv_msg_procfs_locked(&registry);
        reset_msg_next_id_request();
        Ok(msgid as usize)
    })
}

pub(crate) fn sys_msgsnd(msqid: i32, msgp: *const u8, msgsz: usize, msgflg: i32) -> isize {
    syscall_body!(sys_msgsnd, {
        if msgp.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if msgsz > DEFAULT_MSGMAX {
            return Err(LinuxError::EINVAL);
        }

        let mtype = read_value_from_user(msgp as *const i64)?;
        if mtype <= 0 {
            return Err(LinuxError::EINVAL);
        }

        let mut data = vec![0u8; msgsz];
        if msgsz != 0 {
            copy_from_user(
                data.as_mut_slice(),
                unsafe { msgp.add(core::mem::size_of::<i64>()) }.cast(),
            )?;
        }

        let queue = lookup_msg_queue(msqid)?;
        loop {
            let expected_seq = queue.change_seq.load(Ordering::Acquire);
            {
                let mut state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EIDRM);
                }
                if !queue_can_write(&state) {
                    return Err(LinuxError::EACCES);
                }
                if state.cbytes.saturating_add(msgsz) <= state.qbytes {
                    state.messages.push_back(MsgMessage {
                        mtype,
                        data: data.clone(),
                    });
                    state.cbytes = state.cbytes.saturating_add(msgsz);
                    state.stime = now_time_sec();
                    state.lspid = current_pid();
                    drop(state);
                    queue.notify_all();
                    return Ok(0);
                }
            }

            if (msgflg & IPC_NOWAIT) != 0 {
                return Err(LinuxError::EAGAIN);
            }

            wait_for_msg_queue_change(&queue, expected_seq)?;
        }
    })
}

pub(crate) fn sys_msgrcv(
    msqid: i32,
    msgp: *mut u8,
    msgsz: usize,
    msgtyp: i64,
    msgflg: i32,
) -> isize {
    syscall_body!(sys_msgrcv, {
        if msgp.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if msgsz > DEFAULT_MSGMAX {
            return Err(LinuxError::EINVAL);
        }

        let queue = lookup_msg_queue(msqid)?;
        loop {
            let expected_seq = queue.change_seq.load(Ordering::Acquire);
            let mut notify = false;
            {
                let mut state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EIDRM);
                }
                if !queue_can_read(&state) {
                    return Err(LinuxError::EACCES);
                }

                if let Some(index) = find_message_index(&state.messages, msgtyp, msgflg)? {
                    let message = state
                        .messages
                        .get(index)
                        .cloned()
                        .ok_or(LinuxError::EINVAL)?;
                    if message.data.len() > msgsz && (msgflg & MSG_NOERROR) == 0 {
                        return Err(LinuxError::E2BIG);
                    }
                    let copy_len = message.data.len().min(msgsz);

                    write_value_to_user(msgp.cast::<i64>(), message.mtype)?;
                    if copy_len != 0 {
                        copy_to_user(
                            unsafe { msgp.add(core::mem::size_of::<i64>()) }.cast(),
                            &message.data[..copy_len],
                        )?;
                    }

                    if (msgflg & MSG_COPY) == 0 {
                        let removed = state.messages.remove(index).ok_or(LinuxError::EINVAL)?;
                        state.cbytes = state.cbytes.saturating_sub(removed.data.len());
                        state.rtime = now_time_sec();
                        state.lrpid = current_pid();
                        notify = true;
                    }

                    drop(state);
                    if notify {
                        queue.notify_all();
                    }
                    return Ok(copy_len);
                }
            }

            if (msgflg & IPC_NOWAIT) != 0 {
                return Err(LinuxError::ENOMSG);
            }

            wait_for_msg_queue_change(&queue, expected_seq)?;
        }
    })
}

pub(crate) fn sys_msgctl(msqid: i32, cmd: i32, buf: *mut UserMsqidDs) -> isize {
    syscall_body!(sys_msgctl, {
        match cmd {
            IPC_INFO => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let registry = msg_registry().lock();
                write_value_to_user(buf as *mut UserMsginfo, build_user_msginfo_ipc())?;
                Ok(max_live_msg_index(&registry) as usize)
            }
            MSG_INFO => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let registry = msg_registry().lock();
                write_value_to_user(buf as *mut UserMsginfo, build_user_msginfo_stats(&registry))?;
                Ok(max_live_msg_index(&registry) as usize)
            }
            MSG_STAT | MSG_STAT_ANY => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let registry = msg_registry().lock();
                let real_msgid = if registry.queues.contains_key(&msqid) {
                    msqid
                } else {
                    msgid_from_index(&registry, msqid).ok_or(LinuxError::EINVAL)?
                };
                let queue = registry
                    .queues
                    .get(&real_msgid)
                    .cloned()
                    .ok_or(LinuxError::EINVAL)?;
                let state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EINVAL);
                }
                if cmd == MSG_STAT && !queue_can_read(&state) {
                    return Err(LinuxError::EACCES);
                }
                write_value_to_user(buf, build_user_msqid_ds(&state))?;
                Ok(real_msgid as usize)
            }
            IPC_STAT => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let queue = lookup_msg_queue(msqid)?;
                let state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EINVAL);
                }
                if !queue_can_read(&state) {
                    return Err(LinuxError::EACCES);
                }
                write_value_to_user(buf, build_user_msqid_ds(&state))?;
                Ok(0)
            }
            IPC_SET => {
                if buf.is_null() {
                    return Err(LinuxError::EFAULT);
                }
                let user_ds = read_value_from_user(buf as *const UserMsqidDs)?;
                let queue = lookup_msg_queue(msqid)?;
                let mut state = queue.state.lock();
                if state.removed {
                    return Err(LinuxError::EINVAL);
                }
                if !queue_owner_or_root(&state) {
                    return Err(LinuxError::EPERM);
                }
                let new_qbytes =
                    usize::try_from(user_ds.msg_qbytes).map_err(|_| LinuxError::EINVAL)?;
                if new_qbytes == 0 {
                    return Err(LinuxError::EINVAL);
                }
                state.uid = user_ds.msg_perm.uid;
                state.gid = user_ds.msg_perm.gid;
                state.mode = (state.mode & !0o777) | ((user_ds.msg_perm.mode as u32) & 0o777);
                state.qbytes = new_qbytes;
                state.ctime = now_time_sec();
                drop(state);
                queue.notify_all();
                Ok(0)
            }
            IPC_RMID => {
                let queue = {
                    let registry = msg_registry().lock();
                    registry
                        .queues
                        .get(&msqid)
                        .cloned()
                        .ok_or(LinuxError::EINVAL)?
                };
                {
                    let state = queue.state.lock();
                    if state.removed {
                        return Err(LinuxError::EINVAL);
                    }
                    if !queue_owner_or_root(&state) {
                        return Err(LinuxError::EPERM);
                    }
                }
                {
                    let mut registry = msg_registry().lock();
                    if let Some(state_key) = queue.state.lock().key {
                        registry.keys.remove(&state_key);
                    }
                    registry.queues.remove(&msqid);
                    sync_sysv_msg_procfs_locked(&registry);
                }
                {
                    let mut state = queue.state.lock();
                    state.removed = true;
                    state.ctime = now_time_sec();
                }
                queue.notify_all();
                Ok(0)
            }
            _ => Err(LinuxError::EINVAL),
        }
    })
}
