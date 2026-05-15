use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use axfs_vfs::{
    impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsNodePerm, VfsNodeType, VfsResult,
};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

use crate::FsQuota;

const CHUNK_SIZE: usize = 4 * 1024;
const MAX_RESERVED_FALLOCATE_CHUNKS: usize = 4096;
static LARGE_RAMFS_WRITE_LOGGED: AtomicBool = AtomicBool::new(false);

struct FileContent {
    chunks: BTreeMap<usize, Box<[u8]>>,
    reserved_chunks: BTreeSet<usize>,
    len: usize,
}

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    ty: VfsNodeType,
    content: RwLock<FileContent>,
    perm: RwLock<VfsNodePerm>,
    quota: Arc<FsQuota>,
}

impl FileContent {
    const fn new() -> Self {
        Self {
            chunks: BTreeMap::new(),
            reserved_chunks: BTreeSet::new(),
            len: 0,
        }
    }

    fn allocated_bytes(&self) -> usize {
        (self.chunks.len() + self.reserved_chunks.len()) * CHUNK_SIZE
    }

    fn chunk_count_for_len(len: usize) -> usize {
        len.div_ceil(CHUNK_SIZE)
    }

    fn ensure_chunk_allocated(&mut self, chunk_idx: usize) -> &mut [u8] {
        self.reserved_chunks.remove(&chunk_idx);
        self.chunks
            .entry(chunk_idx)
            .or_insert_with(|| vec![0; CHUNK_SIZE].into_boxed_slice())
            .as_mut()
    }

    fn zero_range(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        let mut pos = start;
        while pos < end {
            let chunk_idx = pos / CHUNK_SIZE;
            let within_chunk = pos % CHUNK_SIZE;
            let chunk_end = ((chunk_idx + 1) * CHUNK_SIZE).min(end);
            if let Some(chunk) = self.chunks.get_mut(&chunk_idx) {
                chunk[within_chunk..within_chunk + (chunk_end - pos)].fill(0);
            }
            pos = chunk_end;
        }
    }

    fn missing_reserved_chunks(&self, start_chunk: usize, end_chunk: usize) -> usize {
        (start_chunk..end_chunk)
            .filter(|chunk_idx| {
                !self.chunks.contains_key(chunk_idx) && !self.reserved_chunks.contains(chunk_idx)
            })
            .count()
    }
}

impl FileNode {
    pub(super) fn new(quota: Arc<FsQuota>) -> Self {
        Self::new_with_type(VfsNodeType::File, quota)
    }

    pub(super) fn new_fifo(quota: Arc<FsQuota>) -> Self {
        Self::new_with_type(VfsNodeType::Fifo, quota)
    }

    pub(super) fn new_socket(quota: Arc<FsQuota>) -> Self {
        Self::new_with_type(VfsNodeType::Socket, quota)
    }

    fn new_with_type(ty: VfsNodeType, quota: Arc<FsQuota>) -> Self {
        Self {
            ty,
            content: RwLock::new(FileContent::new()),
            perm: RwLock::new(VfsNodePerm::default_file()),
            quota,
        }
    }

    pub fn set_perm(&self, perm: VfsNodePerm) {
        *self.perm.write() = perm;
    }

    pub fn allocate_range(&self, offset: u64, len: u64, keep_size: bool) -> VfsResult {
        let offset = offset as usize;
        let len = len as usize;
        if len == 0 {
            return Ok(());
        }
        let end = offset
            .checked_add(len)
            .ok_or(axfs_vfs::VfsError::InvalidInput)?;
        let mut content = self.content.write();
        let start_chunk = offset / CHUNK_SIZE;
        let end_chunk = end.div_ceil(CHUNK_SIZE);
        let new_chunks = content.missing_reserved_chunks(start_chunk, end_chunk);
        if new_chunks <= MAX_RESERVED_FALLOCATE_CHUNKS {
            self.quota.reserve(new_chunks * CHUNK_SIZE)?;
            for chunk_idx in start_chunk..end_chunk {
                if !content.chunks.contains_key(&chunk_idx) {
                    content.reserved_chunks.insert(chunk_idx);
                }
            }
        }
        if !keep_size {
            content.len = content.len.max(end);
        }
        Ok(())
    }

    pub fn punch_hole(&self, offset: u64, len: u64) -> VfsResult {
        let offset = offset as usize;
        let len = len as usize;
        if len == 0 {
            return Ok(());
        }
        let mut content = self.content.write();
        let end = offset
            .checked_add(len)
            .ok_or(axfs_vfs::VfsError::InvalidInput)?
            .min(content.len);
        if offset >= end {
            return Ok(());
        }
        content.zero_range(offset, end);

        let start_chunk = offset / CHUNK_SIZE;
        let end_chunk = end.div_ceil(CHUNK_SIZE);
        let mut released_chunks = 0usize;
        for chunk_idx in start_chunk..end_chunk {
            let chunk_start = chunk_idx * CHUNK_SIZE;
            let chunk_end = chunk_start + CHUNK_SIZE;
            if chunk_start >= offset && chunk_end <= end {
                if content.chunks.remove(&chunk_idx).is_some() {
                    released_chunks += 1;
                } else if content.reserved_chunks.remove(&chunk_idx) {
                    released_chunks += 1;
                }
            }
        }
        self.quota.release(released_chunks * CHUNK_SIZE);
        Ok(())
    }
}

impl Drop for FileNode {
    fn drop(&mut self) {
        let allocated = self.content.get_mut().allocated_bytes();
        self.quota.release(allocated);
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let content = self.content.read();
        Ok(VfsNodeAttr::new(
            *self.perm.read(),
            self.ty,
            content.len as _,
            content.allocated_bytes().div_ceil(512) as _,
        ))
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let mut content = self.content.write();
        let new_len = size as usize;
        if new_len < content.len {
            let old_len = content.len;
            content.zero_range(new_len, old_len);
            let new_chunks = FileContent::chunk_count_for_len(new_len);
            let removed_chunks = content.chunks.split_off(&new_chunks);
            let removed_reserved = content.reserved_chunks.split_off(&new_chunks);
            let released_chunks = removed_chunks.len() + removed_reserved.len();
            self.quota.release(released_chunks * CHUNK_SIZE);
        }
        content.len = new_len;
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let content = self.content.read();
        let start = content.len.min(offset as usize);
        let end = content.len.min(offset as usize + buf.len());
        let read_len = end.saturating_sub(start);
        let mut read_pos = start;
        let mut dst_pos = 0;
        while read_pos < end {
            let chunk_idx = read_pos / CHUNK_SIZE;
            let within_chunk = read_pos % CHUNK_SIZE;
            let chunk_end = ((chunk_idx + 1) * CHUNK_SIZE).min(end);
            let dst = &mut buf[dst_pos..dst_pos + (chunk_end - read_pos)];
            if let Some(chunk) = content.chunks.get(&chunk_idx) {
                dst.copy_from_slice(&chunk[within_chunk..within_chunk + dst.len()]);
            } else {
                dst.fill(0);
            }
            dst_pos += dst.len();
            read_pos = chunk_end;
        }
        Ok(read_len)
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        let offset = offset as usize;
        let mut content = self.content.write();
        let end = offset + buf.len();
        if end >= (1 << 20) && !LARGE_RAMFS_WRITE_LOGGED.swap(true, Ordering::Relaxed) {
            log::warn!(
                "ramfs large write path offset={} len={} end={} chunks={}",
                offset,
                buf.len(),
                end,
                FileContent::chunk_count_for_len(end)
            );
        }
        let start_chunk = offset / CHUNK_SIZE;
        let end_chunk = end.div_ceil(CHUNK_SIZE);
        let new_chunks = content.missing_reserved_chunks(start_chunk, end_chunk);
        self.quota.reserve(new_chunks * CHUNK_SIZE)?;
        let mut write_pos = offset;
        let mut src_pos = 0;
        while write_pos < end {
            let chunk_idx = write_pos / CHUNK_SIZE;
            let within_chunk = write_pos % CHUNK_SIZE;
            let chunk_end = ((chunk_idx + 1) * CHUNK_SIZE).min(end);
            let dst = &mut content.ensure_chunk_allocated(chunk_idx)
                [within_chunk..within_chunk + (chunk_end - write_pos)];
            dst.copy_from_slice(&buf[src_pos..src_pos + dst.len()]);
            src_pos += dst.len();
            write_pos = chunk_end;
        }
        content.len = content.len.max(end);
        Ok(buf.len())
    }

    fn fsync(&self) -> VfsResult {
        match self.ty {
            VfsNodeType::File => Ok(()),
            _ => Err(axfs_vfs::VfsError::InvalidInput),
        }
    }

    impl_vfs_non_dir_default! {}
}
