//! RAM filesystem used by [ArceOS](https://github.com/arceos-org/arceos).
//!
//! The implementation is based on [`axfs_vfs`].

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod dir;
mod file;

#[cfg(test)]
mod tests;

pub use self::dir::DirNode;
pub use self::file::FileNode;

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use axfs_vfs::{VfsNodeRef, VfsOps, VfsResult};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, once::Once};

static RAMFS_QUOTAS: Mutex<Vec<Weak<FsQuota>>> = Mutex::new(Vec::new());

#[derive(Clone, Copy, Debug, Default)]
pub struct RamFsQuotaStats {
    pub live_filesystems: usize,
    pub used_bytes: usize,
    pub max_bytes: usize,
}

pub(crate) struct FsQuota {
    max_bytes: Option<usize>,
    used_bytes: AtomicUsize,
}

impl FsQuota {
    fn new(max_bytes: Option<usize>) -> Self {
        Self {
            max_bytes,
            used_bytes: AtomicUsize::new(0),
        }
    }

    pub(crate) fn reserve(&self, bytes: usize) -> VfsResult {
        if bytes == 0 {
            return Ok(());
        }
        if let Some(max_bytes) = self.max_bytes {
            let _ = self
                .used_bytes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(bytes)
                        .filter(|next| *next <= max_bytes)
                })
                .map_err(|_| axfs_vfs::VfsError::StorageFull)?;
            return Ok(());
        }
        self.used_bytes.fetch_add(bytes, Ordering::AcqRel);
        Ok(())
    }

    pub(crate) fn release(&self, bytes: usize) {
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }

    fn used_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }
}

fn register_quota(quota: &Arc<FsQuota>) {
    RAMFS_QUOTAS.lock().push(Arc::downgrade(quota));
}

pub fn diagnostic_quota_usage() -> RamFsQuotaStats {
    let mut stats = RamFsQuotaStats::default();
    let mut quotas = RAMFS_QUOTAS.lock();
    quotas.retain(|quota| {
        let Some(quota) = quota.upgrade() else {
            return false;
        };
        stats.live_filesystems += 1;
        stats.used_bytes += quota.used_bytes();
        stats.max_bytes += quota.max_bytes.unwrap_or(0);
        true
    });
    stats
}

/// A RAM filesystem that implements [`axfs_vfs::VfsOps`].
pub struct RamFileSystem {
    parent: Once<VfsNodeRef>,
    root: Arc<DirNode>,
}

impl RamFileSystem {
    /// Create a new instance.
    pub fn new() -> Self {
        Self::new_with_max_bytes(None)
    }

    pub fn new_with_max_bytes(max_bytes: Option<usize>) -> Self {
        let quota = Arc::new(FsQuota::new(max_bytes));
        register_quota(&quota);
        Self {
            parent: Once::new(),
            root: DirNode::new(None, quota),
        }
    }

    /// Returns the root directory node in [`Arc<DirNode>`](DirNode).
    pub fn root_dir_node(&self) -> Arc<DirNode> {
        self.root.clone()
    }
}

impl VfsOps for RamFileSystem {
    fn mount(&self, _path: &str, mount_point: VfsNodeRef) -> VfsResult {
        if let Some(parent) = mount_point.parent() {
            self.root.set_parent(Some(self.parent.call_once(|| parent)));
        } else {
            self.root.set_parent(None);
        }
        Ok(())
    }

    fn root_dir(&self) -> VfsNodeRef {
        self.root.clone()
    }
}

impl Default for RamFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
