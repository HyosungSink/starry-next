use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use axfs_vfs::{impl_vfs_non_dir_default, VfsNodeAttr, VfsNodeOps, VfsResult};
use core::sync::atomic::{AtomicBool, Ordering};
use spin::RwLock;

const CHUNK_SIZE: usize = 64 * 1024;
static LARGE_RAMFS_WRITE_LOGGED: AtomicBool = AtomicBool::new(false);

struct FileContent {
    chunks: Vec<Option<Box<[u8]>>>,
    len: usize,
}

/// The file node in the RAM filesystem.
///
/// It implements [`axfs_vfs::VfsNodeOps`].
pub struct FileNode {
    content: RwLock<FileContent>,
}

impl FileContent {
    const fn new() -> Self {
        Self {
            chunks: Vec::new(),
            len: 0,
        }
    }

    fn allocated_bytes(&self) -> usize {
        self.chunks.iter().flatten().count() * CHUNK_SIZE
    }

    fn chunk_count_for_len(len: usize) -> usize {
        len.div_ceil(CHUNK_SIZE)
    }

    fn ensure_chunk_slots(&mut self, len: usize) {
        let required_chunks = Self::chunk_count_for_len(len);
        if self.chunks.len() < required_chunks {
            self.chunks.resize_with(required_chunks, || None);
        }
    }

    fn ensure_chunk_allocated(&mut self, chunk_idx: usize) -> &mut [u8] {
        self.chunks[chunk_idx]
            .get_or_insert_with(|| vec![0; CHUNK_SIZE].into_boxed_slice())
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
            if let Some(chunk) = self.chunks.get_mut(chunk_idx).and_then(Option::as_mut) {
                chunk[within_chunk..within_chunk + (chunk_end - pos)].fill(0);
            }
            pos = chunk_end;
        }
    }
}

impl FileNode {
    pub(super) const fn new() -> Self {
        Self {
            content: RwLock::new(FileContent::new()),
        }
    }
}

impl VfsNodeOps for FileNode {
    fn get_attr(&self) -> VfsResult<VfsNodeAttr> {
        let content = self.content.read();
        Ok(VfsNodeAttr::new_file(
            content.len as _,
            content.allocated_bytes().div_ceil(512) as _,
        ))
    }

    fn truncate(&self, size: u64) -> VfsResult {
        let mut content = self.content.write();
        let new_len = size as usize;
        if new_len < content.len {
            content.zero_range(new_len, content.len);
            content.chunks.truncate(FileContent::chunk_count_for_len(new_len));
        } else {
            content.ensure_chunk_slots(new_len);
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
            if let Some(chunk) = content.chunks.get(chunk_idx).and_then(Option::as_ref) {
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
        if end > content.len {
            content.ensure_chunk_slots(end);
        }
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

    impl_vfs_non_dir_default! {}
}
