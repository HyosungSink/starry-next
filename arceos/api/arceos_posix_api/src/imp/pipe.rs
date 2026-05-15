use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_int;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use axsync::Mutex;
use axtask::WaitQueue;

use super::fd_ops::{FD_CLOEXEC_FLAG, FileLike, add_file_like_with_fd_flags, close_file_like};
use crate::ctypes;

#[derive(Copy, Clone, PartialEq)]
enum RingBufferStatus {
    Full,
    Empty,
    Normal,
}

const DEFAULT_PIPE_SIZE: usize = 16 * 4096;
const PIPE_BUF_SIZE: usize = 4096;
static PIPE_MAX_SIZE: AtomicUsize = AtomicUsize::new(DEFAULT_PIPE_SIZE);

pub struct PipeRingBuffer {
    arr: Vec<u8>,
    head: usize,
    tail: usize,
    status: RingBufferStatus,
}

impl PipeRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            arr: vec![0; capacity.max(PIPE_BUF_SIZE)],
            head: 0,
            tail: 0,
            status: RingBufferStatus::Empty,
        }
    }

    fn capacity(&self) -> usize {
        self.arr.len()
    }

    pub fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::Normal;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % self.capacity();
        if self.tail == self.head {
            self.status = RingBufferStatus::Full;
        }
    }

    pub fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::Normal;
        let c = self.arr[self.head];
        self.head = (self.head + 1) % self.capacity();
        if self.head == self.tail {
            self.status = RingBufferStatus::Empty;
        }
        c
    }

    /// Get the length of remaining data in the buffer
    pub fn available_read(&self) -> usize {
        if matches!(self.status, RingBufferStatus::Empty) {
            0
        } else if self.tail > self.head {
            self.tail - self.head
        } else {
            self.tail + self.capacity() - self.head
        }
    }

    /// Get the length of remaining space in the buffer
    pub fn available_write(&self) -> usize {
        if matches!(self.status, RingBufferStatus::Full) {
            0
        } else {
            self.capacity() - self.available_read()
        }
    }

    fn resize(&mut self, new_capacity: usize) -> LinuxResult<usize> {
        let used = self.available_read();
        let new_capacity = new_capacity.max(PIPE_BUF_SIZE);
        if new_capacity < used {
            return Err(LinuxError::EBUSY);
        }
        if new_capacity == self.capacity() {
            return Ok(new_capacity);
        }

        let old_capacity = self.capacity();
        let mut next = vec![0; new_capacity];
        for (index, slot) in next.iter_mut().enumerate().take(used) {
            *slot = self.arr[(self.head + index) % old_capacity];
        }
        self.arr = next;
        self.head = 0;
        self.tail = used;
        self.status = if used == 0 {
            RingBufferStatus::Empty
        } else if used == new_capacity {
            RingBufferStatus::Full
        } else {
            RingBufferStatus::Normal
        };
        Ok(new_capacity)
    }
}

struct PipeShared {
    buffer: Mutex<PipeRingBuffer>,
    capacity: AtomicUsize,
    readers: AtomicUsize,
    writers: AtomicUsize,
    readable_wait: WaitQueue,
    writable_wait: WaitQueue,
}

pub struct Pipe {
    readable: bool,
    shared: Arc<PipeShared>,
    nonblocking: AtomicBool,
}

impl PipeShared {
    fn new(initial_capacity: usize) -> Self {
        Self {
            buffer: Mutex::new(PipeRingBuffer::new(initial_capacity)),
            capacity: AtomicUsize::new(initial_capacity.max(PIPE_BUF_SIZE)),
            readers: AtomicUsize::new(1),
            writers: AtomicUsize::new(1),
            readable_wait: WaitQueue::new(),
            writable_wait: WaitQueue::new(),
        }
    }
}

impl Pipe {
    pub fn new() -> (Pipe, Pipe) {
        let initial_capacity = if axfs::api::current_uid() == 0 {
            DEFAULT_PIPE_SIZE
        } else {
            PIPE_MAX_SIZE
                .load(Ordering::Acquire)
                .min(DEFAULT_PIPE_SIZE)
                .max(PIPE_BUF_SIZE)
        };
        let shared = Arc::new(PipeShared::new(initial_capacity));
        let read_end = Pipe {
            readable: true,
            shared: shared.clone(),
            nonblocking: AtomicBool::new(false),
        };
        let write_end = Pipe {
            readable: false,
            shared,
            nonblocking: AtomicBool::new(false),
        };
        (read_end, write_end)
    }

    pub const fn readable(&self) -> bool {
        self.readable
    }

    pub const fn writable(&self) -> bool {
        !self.readable
    }

    pub fn write_end_close(&self) -> bool {
        self.shared.writers.load(Ordering::Acquire) == 0
    }

    pub fn read_end_close(&self) -> bool {
        self.shared.readers.load(Ordering::Acquire) == 0
    }

    fn is_nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.shared.capacity.load(Ordering::Acquire)
    }

    pub fn resize_capacity(&self, new_capacity: usize) -> LinuxResult<usize> {
        let mut buffer = self.shared.buffer.lock();
        let resized = buffer.resize(new_capacity)?;
        self.shared.capacity.store(resized, Ordering::Release);
        Ok(resized)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        if self.readable {
            self.shared.readers.fetch_sub(1, Ordering::AcqRel);
            self.shared.writable_wait.notify_all(true);
        } else {
            self.shared.writers.fetch_sub(1, Ordering::AcqRel);
            self.shared.readable_wait.notify_all(true);
        }
    }
}

impl FileLike for Pipe {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if !self.readable() {
            return Err(LinuxError::EPERM);
        }
        let max_len = buf.len();
        if max_len == 0 {
            return Ok(0);
        }
        loop {
            let mut ring_buffer = self.shared.buffer.lock();
            let available = ring_buffer.available_read();
            if available == 0 {
                if self.write_end_close() {
                    return Ok(0);
                }
                if self.is_nonblocking() {
                    return Err(LinuxError::EAGAIN);
                }
                drop(ring_buffer);
                if axtask::current_wait_should_interrupt() {
                    return Err(LinuxError::EINTR);
                }
                self.shared.readable_wait.wait_until(|| {
                    self.write_end_close()
                        || self.shared.buffer.lock().available_read() > 0
                        || axtask::current_wait_should_interrupt()
                });
                if axtask::current_wait_should_interrupt() {
                    return Err(LinuxError::EINTR);
                }
                continue;
            }
            let read_size = available.min(max_len);
            for i in 0..read_size {
                buf[i] = ring_buffer.read_byte();
            }
            drop(ring_buffer);
            self.shared.writable_wait.notify_all(true);
            return Ok(read_size);
        }
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if !self.writable() {
            return Err(LinuxError::EPERM);
        }
        let mut write_size = 0usize;
        let max_len = buf.len();
        if max_len == 0 {
            return Ok(0);
        }
        loop {
            if write_size == max_len {
                return Ok(write_size);
            }
            if self.read_end_close() {
                if write_size == 0 {
                    return Err(LinuxError::EPIPE);
                }
                return Ok(write_size);
            }
            let mut ring_buffer = self.shared.buffer.lock();
            let loop_write = ring_buffer.available_write();
            if loop_write == 0 {
                if self.is_nonblocking() {
                    if write_size == 0 {
                        return Err(LinuxError::EAGAIN);
                    }
                    return Ok(write_size);
                }
                drop(ring_buffer);
                if axtask::current_wait_should_interrupt() {
                    if write_size == 0 {
                        return Err(LinuxError::EINTR);
                    }
                    return Ok(write_size);
                }
                self.shared.writable_wait.wait_until(|| {
                    self.read_end_close()
                        || self.shared.buffer.lock().available_write() > 0
                        || axtask::current_wait_should_interrupt()
                });
                if axtask::current_wait_should_interrupt() {
                    if write_size == 0 {
                        return Err(LinuxError::EINTR);
                    }
                    return Ok(write_size);
                }
                continue;
            }
            for _ in 0..loop_write {
                if write_size == max_len {
                    drop(ring_buffer);
                    self.shared.readable_wait.notify_all(true);
                    return Ok(write_size);
                }
                ring_buffer.write_byte(buf[write_size]);
                write_size += 1;
            }
            drop(ring_buffer);
            self.shared.readable_wait.notify_all(true);
        }
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let st_mode = 0o10000 | 0o600u32; // S_IFIFO | rw-------
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            st_uid: 0,
            st_gid: 0,
            st_blksize: self.capacity() as i64,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let buf = self.shared.buffer.lock();
        let writable_threshold = PIPE_BUF_SIZE.min(self.capacity());
        Ok(PollState {
            readable: self.readable() && (buf.available_read() > 0 || self.write_end_close()),
            writable: self.writable()
                && buf.available_write() >= writable_threshold
                && !self.read_end_close(),
        })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(_nonblocking, Ordering::Release);
        Ok(())
    }

    fn status_flags(&self) -> usize {
        if self.is_nonblocking() {
            ctypes::O_NONBLOCK as usize
        } else {
            0
        }
    }

    fn fcntl_identity(&self) -> usize {
        Arc::as_ptr(&self.shared) as usize
    }
}

pub fn pipe_max_size() -> usize {
    PIPE_MAX_SIZE.load(Ordering::Acquire)
}

pub fn set_pipe_max_size(value: usize) -> LinuxResult<()> {
    if value < PIPE_BUF_SIZE {
        return Err(LinuxError::EINVAL);
    }
    PIPE_MAX_SIZE.store(value, Ordering::Release);
    Ok(())
}

/// Create a pipe
///
/// Return 0 if succeed
pub fn sys_pipe(fds: &mut [c_int]) -> c_int {
    debug!("sys_pipe <= {:#x}", fds.as_ptr() as usize);
    sys_pipe2(fds, 0)
}

pub fn sys_pipe2(fds: &mut [c_int], flags: c_int) -> c_int {
    syscall_body!(sys_pipe, {
        if fds.len() != 2 {
            return Err(LinuxError::EFAULT);
        }
        let flags = flags as u32;
        let supported = ctypes::O_CLOEXEC | ctypes::O_NONBLOCK;
        if flags & !supported != 0 {
            return Err(LinuxError::EINVAL);
        }

        let (read_end, write_end) = Pipe::new();
        if flags & ctypes::O_NONBLOCK != 0 {
            read_end.set_nonblocking(true)?;
            write_end.set_nonblocking(true)?;
        }
        let fd_flags = if flags & ctypes::O_CLOEXEC != 0 {
            FD_CLOEXEC_FLAG
        } else {
            0
        };
        let read_fd = add_file_like_with_fd_flags(Arc::new(read_end), fd_flags)?;
        let write_fd =
            add_file_like_with_fd_flags(Arc::new(write_end), fd_flags).inspect_err(|_| {
                close_file_like(read_fd).ok();
            })?;

        fds[0] = read_fd as c_int;
        fds[1] = write_fd as c_int;

        Ok(0)
    })
}
