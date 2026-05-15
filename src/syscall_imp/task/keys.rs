use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::ffi::{c_char, c_void};

use axerrno::LinuxError;
use axhal::time::monotonic_time_nanos;
use axtask::{current, TaskExtRef};
use spin::Mutex;

use crate::{
    syscall_body,
    usercopy::{copy_from_user, copy_to_user, read_cstring_from_user},
};

const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_PROCESS_KEYRING: i32 = -2;
const KEY_SPEC_SESSION_KEYRING: i32 = -3;
const KEY_SPEC_USER_KEYRING: i32 = -4;
const KEY_SPEC_USER_SESSION_KEYRING: i32 = -5;

const KEY_REQKEY_DEFL_DEFAULT: i32 = 0;
const KEY_REQKEY_DEFL_THREAD_KEYRING: i32 = 1;
const KEY_REQKEY_DEFL_PROCESS_KEYRING: i32 = 2;
const KEY_REQKEY_DEFL_SESSION_KEYRING: i32 = 3;

const KEYCTL_GET_KEYRING_ID: i32 = 0;
const KEYCTL_JOIN_SESSION_KEYRING: i32 = 1;
const KEYCTL_UPDATE: i32 = 2;
const KEYCTL_REVOKE: i32 = 3;
const KEYCTL_SETPERM: i32 = 5;
const KEYCTL_CLEAR: i32 = 7;
const KEYCTL_UNLINK: i32 = 9;
const KEYCTL_READ: i32 = 11;
const KEYCTL_SET_REQKEY_KEYRING: i32 = 14;
const KEYCTL_SET_TIMEOUT: i32 = 15;
const KEYCTL_INVALIDATE: i32 = 21;

const KEY_POS_WRITE: u32 = 0x0400_0000;
const KEY_POS_ALL: u32 = 0x3f00_0000;

const USER_KEY_MAX: usize = 32_767;
const BIG_KEY_MAX: usize = (1 << 20) - 1;
const UNPRIV_MAX_KEYS: usize = 200;
const UNPRIV_MAX_BYTES: usize = 20_000;
const ROOT_MAX_KEYS: usize = 1_000;
const ROOT_MAX_BYTES: usize = 25_000_000;

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Keyring,
    User,
    Logon,
    BigKey,
}

#[derive(Clone)]
struct KeyEntry {
    serial: i32,
    kind: KeyKind,
    owner_uid: u32,
    description: String,
    payload: Vec<u8>,
    links: Vec<i32>,
    permissions: u32,
    revoked: bool,
    negative: bool,
    expires_at_ns: Option<u64>,
}

impl KeyEntry {
    fn is_keyring(&self) -> bool {
        self.kind == KeyKind::Keyring
    }
}

#[derive(Default)]
struct KeyRegistry {
    next_serial: i32,
    entries: BTreeMap<i32, KeyEntry>,
    thread_keyrings: BTreeMap<u64, i32>,
    process_keyrings: BTreeMap<u64, i32>,
    session_keyrings: BTreeMap<u64, i32>,
    user_keyrings: BTreeMap<u32, i32>,
    user_session_keyrings: BTreeMap<u32, i32>,
    request_key_defaults: BTreeMap<u64, i32>,
}

static KEY_REGISTRY: Mutex<KeyRegistry> = Mutex::new(KeyRegistry {
    next_serial: 1,
    entries: BTreeMap::new(),
    thread_keyrings: BTreeMap::new(),
    process_keyrings: BTreeMap::new(),
    session_keyrings: BTreeMap::new(),
    user_keyrings: BTreeMap::new(),
    user_session_keyrings: BTreeMap::new(),
    request_key_defaults: BTreeMap::new(),
});

fn current_ids() -> (u64, u64, u64, u32) {
    let task = current();
    (
        task.id().as_u64(),
        task.task_ext().proc_id as u64,
        task.task_ext().session(),
        axfs::api::current_uid(),
    )
}

fn new_keyring(registry: &mut KeyRegistry, description: String) -> i32 {
    let serial = registry.next_serial;
    registry.next_serial += 1;
    let (_, _, _, uid) = current_ids();
    registry.entries.insert(
        serial,
        KeyEntry {
            serial,
            kind: KeyKind::Keyring,
            owner_uid: uid,
            description,
            payload: Vec::new(),
            links: Vec::new(),
            permissions: KEY_POS_ALL,
            revoked: false,
            negative: false,
            expires_at_ns: None,
        },
    );
    serial
}

fn kind_from_name(name: &str) -> Result<KeyKind, LinuxError> {
    match name {
        "keyring" => Ok(KeyKind::Keyring),
        "user" => Ok(KeyKind::User),
        "logon" => Ok(KeyKind::Logon),
        "big_key" => Ok(KeyKind::BigKey),
        _ => Err(LinuxError::ENODEV),
    }
}

fn key_quota_for_uid(uid: u32) -> (usize, usize) {
    if uid == 0 {
        (ROOT_MAX_KEYS, ROOT_MAX_BYTES)
    } else {
        (UNPRIV_MAX_KEYS, UNPRIV_MAX_BYTES)
    }
}

fn key_quota_payload_bytes(description: &str, payload_len: usize) -> usize {
    description.len() + 1 + payload_len
}

fn key_usage_for_uid(registry: &KeyRegistry, uid: u32) -> (usize, usize) {
    let mut used_keys = 0usize;
    let mut used_bytes = 0usize;
    for entry in registry.entries.values() {
        if entry.owner_uid != uid
            || entry.kind == KeyKind::Keyring
            || entry.revoked
            || entry.negative
        {
            continue;
        }
        if is_expired(entry) {
            continue;
        }
        used_keys += 1;
        used_bytes += key_quota_payload_bytes(entry.description.as_str(), entry.payload.len());
    }
    (used_keys, used_bytes)
}

pub(crate) fn proc_key_users_contents() -> String {
    let registry = KEY_REGISTRY.lock();
    let mut uids = Vec::new();
    for entry in registry.entries.values() {
        if entry.kind == KeyKind::Keyring {
            continue;
        }
        if !uids.iter().any(|uid| *uid == entry.owner_uid) {
            uids.push(entry.owner_uid);
        }
    }
    if !uids.iter().any(|uid| *uid == 0) {
        uids.push(0);
    }
    uids.sort_unstable();

    let mut content = String::new();
    for uid in uids {
        let (used_keys, used_bytes) = key_usage_for_uid(&registry, uid);
        let (max_keys, max_bytes) = key_quota_for_uid(uid);
        content.push_str(
            alloc::format!(
                "{uid:5}: {uid:5} 0/0 {used_keys}/{max_keys} {used_bytes}/{max_bytes}\n"
            )
            .as_str(),
        );
    }
    content
}

fn max_payload_len(kind: KeyKind) -> usize {
    match kind {
        KeyKind::Keyring => 0,
        KeyKind::User | KeyKind::Logon => USER_KEY_MAX,
        KeyKind::BigKey => BIG_KEY_MAX,
    }
}

fn resolve_any_key_id(
    registry: &mut KeyRegistry,
    id: i32,
    create_special: bool,
) -> Result<i32, LinuxError> {
    if id < 0 {
        resolve_keyring_id(registry, id, create_special)
    } else if registry.entries.contains_key(&id) {
        Ok(id)
    } else {
        Err(LinuxError::ENOKEY)
    }
}

fn resolve_keyring_id(
    registry: &mut KeyRegistry,
    id: i32,
    create: bool,
) -> Result<i32, LinuxError> {
    let (tid, pid, sid, uid) = current_ids();
    let serial = match id {
        KEY_SPEC_THREAD_KEYRING => {
            if let Some(serial) = registry.thread_keyrings.get(&tid).copied() {
                serial
            } else if create {
                let serial = new_keyring(registry, alloc::format!("_tid.{tid}"));
                registry.thread_keyrings.insert(tid, serial);
                serial
            } else {
                return Err(LinuxError::ENOKEY);
            }
        }
        KEY_SPEC_PROCESS_KEYRING => {
            if let Some(serial) = registry.process_keyrings.get(&pid).copied() {
                serial
            } else if create {
                let serial = new_keyring(registry, alloc::format!("_pid.{pid}"));
                registry.process_keyrings.insert(pid, serial);
                serial
            } else {
                return Err(LinuxError::ENOKEY);
            }
        }
        KEY_SPEC_SESSION_KEYRING => {
            if let Some(serial) = registry.session_keyrings.get(&sid).copied() {
                serial
            } else if create {
                let serial = new_keyring(registry, alloc::format!("_sid.{sid}"));
                registry.session_keyrings.insert(sid, serial);
                serial
            } else {
                return Err(LinuxError::ENOKEY);
            }
        }
        KEY_SPEC_USER_KEYRING => {
            if let Some(serial) = registry.user_keyrings.get(&uid).copied() {
                serial
            } else {
                let serial = new_keyring(registry, alloc::format!("_uid.{uid}"));
                registry.user_keyrings.insert(uid, serial);
                serial
            }
        }
        KEY_SPEC_USER_SESSION_KEYRING => {
            if let Some(serial) = registry.user_session_keyrings.get(&uid).copied() {
                serial
            } else {
                let serial = new_keyring(registry, alloc::format!("_uid_ses.{uid}"));
                registry.user_session_keyrings.insert(uid, serial);
                serial
            }
        }
        serial if serial > 0 => {
            let entry = registry.entries.get(&serial).ok_or(LinuxError::ENOKEY)?;
            if !entry.is_keyring() {
                return Err(LinuxError::ENOKEY);
            }
            serial
        }
        _ => return Err(LinuxError::EINVAL),
    };
    Ok(serial)
}

fn remove_key_from_all_keyrings(registry: &mut KeyRegistry, serial: i32) {
    for entry in registry.entries.values_mut() {
        if entry.is_keyring() {
            entry.links.retain(|linked| *linked != serial);
        }
    }
}

fn remove_key(registry: &mut KeyRegistry, serial: i32) {
    remove_key_from_all_keyrings(registry, serial);
    registry.entries.remove(&serial);
    registry.thread_keyrings.retain(|_, value| *value != serial);
    registry
        .process_keyrings
        .retain(|_, value| *value != serial);
    registry
        .session_keyrings
        .retain(|_, value| *value != serial);
    registry.user_keyrings.retain(|_, value| *value != serial);
    registry
        .user_session_keyrings
        .retain(|_, value| *value != serial);
}

fn is_expired(entry: &KeyEntry) -> bool {
    entry
        .expires_at_ns
        .is_some_and(|expires| monotonic_time_nanos() >= expires)
}

fn key_lookup_result(registry: &mut KeyRegistry, serial: i32) -> Result<&mut KeyEntry, LinuxError> {
    let expired = registry
        .entries
        .get(&serial)
        .map(is_expired)
        .unwrap_or(false);
    if expired {
        remove_key(registry, serial);
        return Err(LinuxError::EKEYEXPIRED);
    }
    let entry = registry
        .entries
        .get_mut(&serial)
        .ok_or(LinuxError::ENOKEY)?;
    if entry.negative {
        return Err(LinuxError::ENOKEY);
    }
    if entry.revoked {
        return Err(LinuxError::EKEYREVOKED);
    }
    Ok(entry)
}

fn visible_keyring_ids(registry: &mut KeyRegistry) -> Vec<i32> {
    let (tid, pid, sid, uid) = current_ids();
    let mut ids = Vec::new();
    if let Some(id) = registry.thread_keyrings.get(&tid).copied() {
        ids.push(id);
    }
    if let Some(id) = registry.process_keyrings.get(&pid).copied() {
        ids.push(id);
    }
    if let Some(id) = registry.session_keyrings.get(&sid).copied() {
        ids.push(id);
    }
    if let Some(id) = registry.user_session_keyrings.get(&uid).copied() {
        ids.push(id);
    }
    if let Some(id) = registry.user_keyrings.get(&uid).copied() {
        ids.push(id);
    }
    ids
}

fn find_matching_key(
    registry: &mut KeyRegistry,
    kind: KeyKind,
    description: &str,
) -> Result<i32, LinuxError> {
    for ring_id in visible_keyring_ids(registry) {
        let Some(ring) = registry.entries.get(&ring_id).cloned() else {
            continue;
        };
        for serial in ring.links {
            let Some(entry) = registry.entries.get(&serial) else {
                continue;
            };
            if entry.kind != kind || entry.description != description {
                continue;
            }
            if is_expired(entry) {
                remove_key(registry, serial);
                return Err(LinuxError::EKEYEXPIRED);
            }
            if entry.revoked {
                return Err(LinuxError::EKEYREVOKED);
            }
            if entry.negative {
                return Err(LinuxError::ENOKEY);
            }
            return Ok(serial);
        }
    }
    Err(LinuxError::ENOKEY)
}

fn attach_key_to_keyring(
    registry: &mut KeyRegistry,
    keyring: i32,
    kind: KeyKind,
    description: &str,
    serial: i32,
) -> Result<(), LinuxError> {
    let existing = registry
        .entries
        .get(&keyring)
        .ok_or(LinuxError::ENOKEY)?
        .links
        .iter()
        .find_map(|linked| {
            let entry = registry.entries.get(linked)?;
            (entry.kind == kind && entry.description == description).then_some(*linked)
        });
    if let Some(old) = existing {
        remove_key(registry, old);
    }
    let ring = registry
        .entries
        .get_mut(&keyring)
        .ok_or(LinuxError::ENOKEY)?;
    if !ring.is_keyring() {
        return Err(LinuxError::EINVAL);
    }
    ring.links.retain(|linked| *linked != serial);
    ring.links.push(serial);
    Ok(())
}

fn serialize_keyring_links(registry: &KeyRegistry, serial: i32) -> Result<Vec<u8>, LinuxError> {
    let ring = registry.entries.get(&serial).ok_or(LinuxError::ENOKEY)?;
    let mut bytes = Vec::with_capacity(ring.links.len() * core::mem::size_of::<i32>());
    for linked in &ring.links {
        bytes.extend_from_slice(&linked.to_ne_bytes());
    }
    Ok(bytes)
}

fn read_payload_from_user(payload: *const c_void, plen: usize) -> Result<Vec<u8>, LinuxError> {
    if plen == 0 {
        return Ok(Vec::new());
    }
    if payload.is_null() {
        return Err(LinuxError::EFAULT);
    }
    let mut buf = vec![0u8; plen];
    copy_from_user(&mut buf, payload)?;
    Ok(buf)
}

fn keyring_for_request_default(
    registry: &mut KeyRegistry,
    default: i32,
) -> Result<i32, LinuxError> {
    match default {
        KEY_REQKEY_DEFL_THREAD_KEYRING => {
            resolve_keyring_id(registry, KEY_SPEC_THREAD_KEYRING, true)
        }
        KEY_REQKEY_DEFL_PROCESS_KEYRING => {
            resolve_keyring_id(registry, KEY_SPEC_PROCESS_KEYRING, true)
        }
        KEY_REQKEY_DEFL_SESSION_KEYRING | KEY_REQKEY_DEFL_DEFAULT => {
            resolve_keyring_id(registry, KEY_SPEC_SESSION_KEYRING, true)
        }
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn sys_add_key(
    type_ptr: *const c_char,
    description_ptr: *const c_char,
    payload: *const c_void,
    plen: usize,
    keyring: i32,
) -> isize {
    syscall_body!(sys_add_key, {
        let type_name = read_cstring_from_user(type_ptr.cast(), 256)?;
        let description = read_cstring_from_user(description_ptr.cast(), 4096)?;
        let kind = kind_from_name(&type_name)?;
        if plen > max_payload_len(kind) {
            return Err(LinuxError::EINVAL);
        }
        if kind == KeyKind::Logon && !description.contains(':') {
            return Err(LinuxError::EINVAL);
        }
        let payload = match kind {
            KeyKind::Keyring => {
                if plen != 0 {
                    return Err(LinuxError::EINVAL);
                }
                Vec::new()
            }
            _ => read_payload_from_user(payload, plen)?,
        };

        let mut registry = KEY_REGISTRY.lock();
        let (_, _, _, uid) = current_ids();
        let keyring = resolve_keyring_id(&mut registry, keyring, true)?;
        if kind != KeyKind::Keyring {
            let (used_keys, used_bytes) = key_usage_for_uid(&registry, uid);
            let (max_keys, max_bytes) = key_quota_for_uid(uid);
            let replacing = registry
                .entries
                .get(&keyring)
                .and_then(|entry| {
                    entry.links.iter().find_map(|serial| {
                        registry.entries.get(serial).and_then(|entry| {
                            (entry.kind == kind
                                && entry.owner_uid == uid
                                && entry.description == description
                                && !entry.revoked
                                && !entry.negative
                                && !is_expired(entry))
                            .then_some(*serial)
                        })
                    })
                })
                .and_then(|serial| registry.entries.get(&serial).cloned());
            let mut next_keys = used_keys + 1;
            let mut next_bytes =
                used_bytes + key_quota_payload_bytes(description.as_str(), payload.len());
            if let Some(old) = replacing {
                next_keys = next_keys.saturating_sub(1);
                next_bytes = next_bytes.saturating_sub(key_quota_payload_bytes(
                    old.description.as_str(),
                    old.payload.len(),
                ));
            }
            let extra_bytes = key_quota_payload_bytes(description.as_str(), payload.len());
            if next_keys > max_keys || next_bytes > max_bytes || extra_bytes > max_bytes {
                return Err(LinuxError::EDQUOT);
            }
        }
        let serial = registry.next_serial;
        registry.next_serial += 1;
        registry.entries.insert(
            serial,
            KeyEntry {
                serial,
                kind,
                owner_uid: uid,
                description: description.clone(),
                payload,
                links: Vec::new(),
                permissions: KEY_POS_ALL,
                revoked: false,
                negative: false,
                expires_at_ns: None,
            },
        );
        attach_key_to_keyring(&mut registry, keyring, kind, &description, serial)?;
        Ok(serial as isize)
    })
}

pub(crate) fn sys_request_key(
    type_ptr: *const c_char,
    description_ptr: *const c_char,
    callout_info_ptr: *const c_char,
    dest_keyring: i32,
) -> isize {
    let _ = callout_info_ptr;
    syscall_body!(sys_request_key, {
        let type_name = read_cstring_from_user(type_ptr.cast(), 256)?;
        let description = read_cstring_from_user(description_ptr.cast(), 4096)?;
        let kind = kind_from_name(&type_name)?;
        let mut registry = KEY_REGISTRY.lock();
        match find_matching_key(&mut registry, kind, &description) {
            Ok(serial) => return Ok(serial as isize),
            Err(LinuxError::ENOKEY) => {}
            Err(err) => return Err(err),
        }

        let target_keyring = if dest_keyring > 0 {
            resolve_keyring_id(&mut registry, dest_keyring, false)?
        } else if dest_keyring < 0 {
            resolve_keyring_id(&mut registry, dest_keyring, true)?
        } else {
            let (tid, _, _, _) = current_ids();
            let default = registry
                .request_key_defaults
                .get(&tid)
                .copied()
                .unwrap_or(KEY_REQKEY_DEFL_DEFAULT);
            keyring_for_request_default(&mut registry, default)?
        };
        if registry
            .entries
            .get(&target_keyring)
            .map(|entry| entry.permissions & KEY_POS_WRITE == 0)
            .unwrap_or(true)
        {
            return Err(LinuxError::EACCES);
        }

        let serial = registry.next_serial;
        registry.next_serial += 1;
        registry.entries.insert(
            serial,
            KeyEntry {
                serial,
                kind,
                owner_uid: axfs::api::current_uid(),
                description: description.clone(),
                payload: Vec::new(),
                links: Vec::new(),
                permissions: KEY_POS_ALL,
                revoked: false,
                negative: true,
                expires_at_ns: Some(monotonic_time_nanos() + 60_000_000_000),
            },
        );
        attach_key_to_keyring(&mut registry, target_keyring, kind, &description, serial)?;
        Err(LinuxError::ENOKEY)
    })
}

pub(crate) fn sys_keyctl(cmd: i32, arg2: usize, arg3: usize, arg4: usize, _arg5: usize) -> isize {
    syscall_body!(sys_keyctl, {
        let mut registry = KEY_REGISTRY.lock();
        match cmd {
            KEYCTL_GET_KEYRING_ID => {
                let id = arg2 as i32;
                let create = arg3 != 0
                    || matches!(id, KEY_SPEC_USER_KEYRING | KEY_SPEC_USER_SESSION_KEYRING);
                Ok(resolve_keyring_id(&mut registry, id, create)? as isize)
            }
            KEYCTL_JOIN_SESSION_KEYRING => {
                let name = if arg2 == 0 {
                    String::new()
                } else {
                    read_cstring_from_user(arg2 as *const u8, 4096)?
                };
                let (_, _, sid, _) = current_ids();
                let serial = new_keyring(
                    &mut registry,
                    if name.is_empty() {
                        alloc::format!("_ses.{sid}")
                    } else {
                        name
                    },
                );
                registry.session_keyrings.insert(sid, serial);
                Ok(serial as isize)
            }
            KEYCTL_SET_REQKEY_KEYRING => {
                match arg2 as i32 {
                    KEY_REQKEY_DEFL_DEFAULT
                    | KEY_REQKEY_DEFL_THREAD_KEYRING
                    | KEY_REQKEY_DEFL_PROCESS_KEYRING
                    | KEY_REQKEY_DEFL_SESSION_KEYRING => {}
                    _ => return Err(LinuxError::EINVAL),
                }
                let (tid, _, _, _) = current_ids();
                registry.request_key_defaults.insert(tid, arg2 as i32);
                Ok(0)
            }
            KEYCTL_READ => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                let entry = key_lookup_result(&mut registry, serial)?.clone();
                let bytes = if entry.is_keyring() {
                    serialize_keyring_links(&registry, serial)?
                } else {
                    entry.payload
                };
                if arg3 != 0 && arg4 != 0 {
                    let count = core::cmp::min(bytes.len(), arg4);
                    copy_to_user(arg3 as *mut c_void, &bytes[..count])?;
                }
                Ok(bytes.len() as isize)
            }
            KEYCTL_REVOKE => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                let expired = registry
                    .entries
                    .get(&serial)
                    .map(is_expired)
                    .unwrap_or(false);
                if expired {
                    remove_key(&mut registry, serial);
                    return Err(LinuxError::ENOKEY);
                }
                let entry = registry
                    .entries
                    .get_mut(&serial)
                    .ok_or(LinuxError::ENOKEY)?;
                if entry.negative {
                    return Err(LinuxError::ENOKEY);
                }
                entry.revoked = true;
                Ok(0)
            }
            KEYCTL_INVALIDATE => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                if !registry.entries.contains_key(&serial) {
                    return Err(LinuxError::ENOKEY);
                }
                remove_key(&mut registry, serial);
                Ok(0)
            }
            KEYCTL_UNLINK => {
                let serial = arg2 as i32;
                let keyring = resolve_keyring_id(&mut registry, arg3 as i32, false)?;
                let ring = registry
                    .entries
                    .get_mut(&keyring)
                    .ok_or(LinuxError::ENOKEY)?;
                let len_before = ring.links.len();
                ring.links.retain(|linked| *linked != serial);
                if ring.links.len() == len_before {
                    return Err(LinuxError::ENOKEY);
                }
                Ok(0)
            }
            KEYCTL_CLEAR => {
                let keyring = resolve_keyring_id(&mut registry, arg2 as i32, false)?;
                let ring = registry
                    .entries
                    .get_mut(&keyring)
                    .ok_or(LinuxError::ENOKEY)?;
                ring.links.clear();
                Ok(0)
            }
            KEYCTL_UPDATE => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                let (kind, _) = {
                    let entry = key_lookup_result(&mut registry, serial)?;
                    (entry.kind, entry.serial)
                };
                if kind == KeyKind::Keyring {
                    return Err(LinuxError::EINVAL);
                }
                if arg4 > max_payload_len(kind) {
                    return Err(LinuxError::EINVAL);
                }
                let payload = read_payload_from_user(arg3 as *const c_void, arg4)?;
                let (owner_uid, old_description, old_payload_len) = {
                    let entry = registry.entries.get(&serial).ok_or(LinuxError::ENOKEY)?;
                    (
                        entry.owner_uid,
                        entry.description.clone(),
                        entry.payload.len(),
                    )
                };
                let (_, used_bytes) = key_usage_for_uid(&registry, owner_uid);
                let (_, max_bytes) = key_quota_for_uid(owner_uid);
                let next_bytes = used_bytes
                    .saturating_sub(key_quota_payload_bytes(
                        old_description.as_str(),
                        old_payload_len,
                    ))
                    .saturating_add(key_quota_payload_bytes(
                        old_description.as_str(),
                        payload.len(),
                    ));
                if next_bytes > max_bytes {
                    return Err(LinuxError::EDQUOT);
                }
                let entry = registry
                    .entries
                    .get_mut(&serial)
                    .ok_or(LinuxError::ENOKEY)?;
                entry.payload = payload;
                entry.negative = false;
                entry.revoked = false;
                entry.expires_at_ns = None;
                Ok(0)
            }
            KEYCTL_SETPERM => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                let entry = registry
                    .entries
                    .get_mut(&serial)
                    .ok_or(LinuxError::ENOKEY)?;
                entry.permissions = arg3 as u32;
                Ok(0)
            }
            KEYCTL_SET_TIMEOUT => {
                let serial = resolve_any_key_id(&mut registry, arg2 as i32, false)?;
                let entry = registry
                    .entries
                    .get_mut(&serial)
                    .ok_or(LinuxError::ENOKEY)?;
                entry.expires_at_ns = Some(monotonic_time_nanos() + (arg3 as u64) * 1_000_000_000);
                Ok(0)
            }
            _ => Err(LinuxError::ENOSYS),
        }
    })
}
