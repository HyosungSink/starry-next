use alloc::{
    collections::{BTreeMap, VecDeque},
    format,
    sync::Arc,
    vec,
};
use core::{
    ffi::{c_int, c_void},
    mem::size_of,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use arceos_posix_api::{self as api, get_file_like, FileLike};
use axerrno::{LinuxError, LinuxResult};
use axhal::{paging::MappingFlags, time::wall_time};
use axsync::Mutex;
use axtask::WaitQueue;
use memory_addr::{VirtAddr, PAGE_SIZE_4K};
use spin::Once;

use crate::{
    signal::{current_blocked_mask, read_user_sigset_mask, set_current_blocked_mask},
    syscall_body,
    usercopy::{
        copy_from_user, copy_to_user, ensure_user_range, read_value_from_user, write_value_to_user,
    },
};

const AIO_MAX_NR: usize = 65_536;
const IOCB_CMD_PREAD: u16 = 0;
const IOCB_CMD_PWRITE: u16 = 1;
const IOCB_FLAG_RESFD: u32 = 1;

static NEXT_AIO_CONTEXT_ID: AtomicU64 = AtomicU64::new(1);
static AIO_NR: AtomicUsize = AtomicUsize::new(0);

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct IoEvent {
    data: u64,
    obj: u64,
    res: i64,
    res2: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub(crate) struct Iocb {
    aio_data: u64,
    aio_key: u32,
    aio_rw_flags: u32,
    aio_lio_opcode: u16,
    aio_reqprio: i16,
    aio_fildes: u32,
    aio_buf: u64,
    aio_nbytes: u64,
    aio_offset: i64,
    aio_reserved2: u64,
    aio_flags: u32,
    aio_resfd: u32,
}

struct AioContext {
    max_events: usize,
    completions: Mutex<VecDeque<IoEvent>>,
    wait_queue: WaitQueue,
}

impl AioContext {
    fn new(max_events: usize) -> Self {
        Self {
            max_events,
            completions: Mutex::new(VecDeque::new()),
            wait_queue: WaitQueue::new(),
        }
    }

    fn queued_events(&self) -> usize {
        self.completions.lock().len()
    }

    fn push_completion(&self, event: IoEvent) -> LinuxResult<()> {
        let mut completions = self.completions.lock();
        if completions.len() >= self.max_events {
            return Err(LinuxError::EAGAIN);
        }
        completions.push_back(event);
        drop(completions);
        self.wait_queue.notify_all(true);
        Ok(())
    }

    fn pop_events(&self, events: *mut IoEvent, max_nr: usize) -> LinuxResult<usize> {
        if max_nr == 0 {
            return Ok(0);
        }
        ensure_user_range(
            VirtAddr::from(events as usize),
            max_nr * size_of::<IoEvent>(),
            MappingFlags::WRITE,
        )?;
        let mut completions = self.completions.lock();
        let mut produced = 0usize;
        while produced < max_nr {
            let Some(event) = completions.pop_front() else {
                break;
            };
            write_value_to_user(unsafe { events.add(produced) }, event)?;
            produced += 1;
        }
        Ok(produced)
    }
}

fn aio_contexts() -> &'static Mutex<BTreeMap<u64, Arc<AioContext>>> {
    static AIO_CONTEXTS: Once<Mutex<BTreeMap<u64, Arc<AioContext>>>> = Once::new();
    AIO_CONTEXTS.call_once(|| Mutex::new(BTreeMap::new()))
}

fn refresh_aio_proc_files() {
    if !axfs::api::absolute_path_exists("/proc/sys/fs") {
        let _ = axfs::api::create_dir("/proc/sys/fs");
    }
    let _ = axfs::api::write("/proc/sys/fs/aio-max-nr", format!("{AIO_MAX_NR}\n"));
    let _ = axfs::api::write(
        "/proc/sys/fs/aio-nr",
        format!("{}\n", AIO_NR.load(Ordering::Acquire)),
    );
}

fn get_aio_context(ctx: u64) -> LinuxResult<Arc<AioContext>> {
    aio_contexts()
        .lock()
        .get(&ctx)
        .cloned()
        .ok_or(LinuxError::EINVAL)
}

fn timespec_to_duration(ts: api::ctypes::timespec) -> LinuxResult<Duration> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn lseek_errno(ret: i64) -> LinuxResult<i64> {
    if ret < 0 {
        Err(LinuxError::try_from((-ret) as i32).unwrap_or(LinuxError::EINVAL))
    } else {
        Ok(ret)
    }
}

fn current_file_offset(fd: c_int) -> LinuxResult<i64> {
    lseek_errno(api::sys_lseek(fd, 0, 1))
}

fn positioned_read(
    fd: c_int,
    file: &Arc<dyn FileLike>,
    buf: *mut u8,
    count: usize,
    offset: i64,
) -> LinuxResult<usize> {
    if count == 0 {
        return Ok(0);
    }
    if buf.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if offset < 0 {
        return Err(LinuxError::EINVAL);
    }

    let previous = current_file_offset(fd)?;
    lseek_errno(api::sys_lseek(fd, offset, 0))?;
    let result = (|| {
        let mut total = 0usize;
        let mut kbuf = vec![0u8; count.min(PAGE_SIZE_4K)];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            let read_len = file.read(&mut kbuf[..chunk])?;
            if read_len == 0 {
                break;
            }
            copy_to_user(
                unsafe { buf.add(total) }.cast::<c_void>(),
                &kbuf[..read_len],
            )?;
            total += read_len;
            if read_len < chunk {
                break;
            }
        }
        Ok(total)
    })();
    let _ = api::sys_lseek(fd, previous, 0);
    result
}

fn positioned_write(
    fd: c_int,
    file: &Arc<dyn FileLike>,
    buf: *const u8,
    count: usize,
    offset: i64,
) -> LinuxResult<usize> {
    if count == 0 {
        return Ok(0);
    }
    if buf.is_null() {
        return Err(LinuxError::EFAULT);
    }
    if offset < 0 {
        return Err(LinuxError::EINVAL);
    }

    let previous = current_file_offset(fd)?;
    lseek_errno(api::sys_lseek(fd, offset, 0))?;
    let result = (|| {
        let mut total = 0usize;
        let mut kbuf = vec![0u8; count.min(PAGE_SIZE_4K)];
        while total < count {
            let chunk = (count - total).min(kbuf.len());
            copy_from_user(
                &mut kbuf[..chunk],
                unsafe { buf.add(total) }.cast::<c_void>(),
            )?;
            let written = file.write(&kbuf[..chunk])?;
            total += written;
            if written < chunk {
                break;
            }
        }
        Ok(total)
    })();
    let _ = api::sys_lseek(fd, previous, 0);
    result
}

fn execute_iocb(iocb_ptr: *const Iocb, iocb: &Iocb) -> LinuxResult<IoEvent> {
    let fd = iocb.aio_fildes as c_int;
    let file = get_file_like(fd)?;
    let status_flags = file.status_flags() as u32;
    let access_mode = status_flags & 0b11;
    if (status_flags & api::ctypes::O_PATH) != 0 {
        return Err(LinuxError::EBADF);
    }
    if (iocb.aio_flags & IOCB_FLAG_RESFD) != 0 {
        api::signal_eventfd(iocb.aio_resfd as c_int, 0)?;
    }

    let result = match iocb.aio_lio_opcode {
        IOCB_CMD_PREAD => {
            if access_mode == api::ctypes::O_WRONLY {
                return Err(LinuxError::EBADF);
            }
            positioned_read(
                fd,
                &file,
                iocb.aio_buf as usize as *mut u8,
                iocb.aio_nbytes as usize,
                iocb.aio_offset,
            )
            .map(|len| len as i64)
            .unwrap_or_else(|err| -(err.code() as i64))
        }
        IOCB_CMD_PWRITE => {
            if access_mode == api::ctypes::O_RDONLY {
                return Err(LinuxError::EBADF);
            }
            positioned_write(
                fd,
                &file,
                iocb.aio_buf as usize as *const u8,
                iocb.aio_nbytes as usize,
                iocb.aio_offset,
            )
            .map(|len| len as i64)
            .unwrap_or_else(|err| -(err.code() as i64))
        }
        _ => return Err(LinuxError::EINVAL),
    };

    if (iocb.aio_flags & IOCB_FLAG_RESFD) != 0 {
        api::signal_eventfd(iocb.aio_resfd as c_int, 1)?;
    }

    Ok(IoEvent {
        data: iocb.aio_data,
        obj: iocb_ptr as usize as u64,
        res: result,
        res2: 0,
    })
}

fn wait_for_events(
    ctx: &Arc<AioContext>,
    min_nr: usize,
    max_nr: usize,
    events: *mut IoEvent,
    timeout: Option<Duration>,
) -> LinuxResult<usize> {
    if max_nr == 0 || min_nr > max_nr {
        return Err(LinuxError::EINVAL);
    }
    if events.is_null() {
        return Err(LinuxError::EFAULT);
    }

    let deadline = timeout.map(|dur| wall_time() + dur);
    loop {
        let queued = ctx.queued_events();
        if queued >= min_nr || (queued > 0 && min_nr == 0) {
            return ctx.pop_events(events, max_nr);
        }
        if deadline.is_some_and(|ddl| wall_time() >= ddl) {
            return ctx.pop_events(events, max_nr);
        }
        if axtask::current_wait_should_interrupt() {
            return Err(LinuxError::EINTR);
        }
        let wait_for = deadline
            .and_then(|ddl| ddl.checked_sub(wall_time()))
            .unwrap_or(Duration::from_millis(10))
            .min(Duration::from_millis(10));
        ctx.wait_queue.wait_timeout(wait_for);
    }
}

pub(crate) fn sys_io_setup(nr_events: u32, ctxp: *mut u64) -> isize {
    syscall_body!(sys_io_setup, {
        if ctxp.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if nr_events == 0 {
            return Err(LinuxError::EINVAL);
        }
        if nr_events > i32::MAX as u32 {
            return Err(LinuxError::EINVAL);
        }
        if read_value_from_user(ctxp as *const u64)? != 0 {
            return Err(LinuxError::EINVAL);
        }

        let requested = nr_events as usize;
        AIO_NR
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                (current + requested <= AIO_MAX_NR).then_some(current + requested)
            })
            .map_err(|_| LinuxError::EAGAIN)?;

        let ctx_id = NEXT_AIO_CONTEXT_ID.fetch_add(1, Ordering::Relaxed);
        let ctx = Arc::new(AioContext::new(requested));
        aio_contexts().lock().insert(ctx_id, ctx);
        if let Err(err) = write_value_to_user(ctxp, ctx_id) {
            aio_contexts().lock().remove(&ctx_id);
            AIO_NR.fetch_sub(requested, Ordering::AcqRel);
            refresh_aio_proc_files();
            return Err(err);
        }

        refresh_aio_proc_files();
        Ok(0)
    })
}

pub(crate) fn sys_io_destroy(ctx: u64) -> isize {
    syscall_body!(sys_io_destroy, {
        let removed = aio_contexts()
            .lock()
            .remove(&ctx)
            .ok_or(LinuxError::EINVAL)?;
        AIO_NR.fetch_sub(removed.max_events, Ordering::AcqRel);
        refresh_aio_proc_files();
        Ok(0)
    })
}

pub(crate) fn sys_io_submit(ctx: u64, nr: isize, iocbpp: *const *const Iocb) -> isize {
    syscall_body!(sys_io_submit, {
        let ctx = get_aio_context(ctx)?;
        if nr < 0 {
            return Err(LinuxError::EINVAL);
        }
        if nr == 0 {
            return Ok(0);
        }
        if iocbpp.is_null() {
            return Err(LinuxError::EFAULT);
        }
        if ctx.queued_events() + nr as usize > ctx.max_events {
            return Err(LinuxError::EAGAIN);
        }

        let mut completions = VecDeque::with_capacity(nr as usize);
        for index in 0..nr as usize {
            let iocb_ptr = read_value_from_user(unsafe { iocbpp.add(index) })?;
            if iocb_ptr.is_null() {
                return Err(LinuxError::EFAULT);
            }
            let iocb = read_value_from_user(iocb_ptr)?;
            completions.push_back(execute_iocb(iocb_ptr, &iocb)?);
        }

        while let Some(event) = completions.pop_front() {
            ctx.push_completion(event)?;
        }
        Ok(nr)
    })
}

pub(crate) fn sys_io_getevents(
    ctx: u64,
    min_nr: isize,
    max_nr: isize,
    events: *mut IoEvent,
    timeout: *const api::ctypes::timespec,
) -> isize {
    syscall_body!(sys_io_getevents, {
        let ctx = get_aio_context(ctx)?;
        if min_nr < 0 || max_nr < 0 {
            return Err(LinuxError::EINVAL);
        }
        let timeout = if timeout.is_null() {
            None
        } else {
            Some(timespec_to_duration(read_value_from_user(timeout)?)?)
        };
        wait_for_events(&ctx, min_nr as usize, max_nr as usize, events, timeout)
    })
}

pub(crate) fn sys_io_pgetevents(
    ctx: u64,
    min_nr: isize,
    max_nr: isize,
    events: *mut IoEvent,
    timeout: *const api::ctypes::timespec,
    sigmask: *const c_void,
) -> isize {
    syscall_body!(sys_io_pgetevents, {
        if min_nr < 0 || max_nr < 0 {
            return Err(LinuxError::EINVAL);
        }
        let timeout = if timeout.is_null() {
            None
        } else {
            Some(timespec_to_duration(read_value_from_user(timeout)?)?)
        };

        let saved_mask = current_blocked_mask();
        if !sigmask.is_null() {
            let requested_mask = read_user_sigset_mask(sigmask)?;
            set_current_blocked_mask(requested_mask);
        }
        let result = wait_for_events(
            &get_aio_context(ctx)?,
            min_nr as usize,
            max_nr as usize,
            events,
            timeout,
        );
        if !sigmask.is_null() {
            set_current_blocked_mask(saved_mask);
        }
        result
    })
}

pub(crate) fn sys_io_cancel(ctx: u64, iocb: *mut Iocb, result: *mut IoEvent) -> isize {
    syscall_body!(sys_io_cancel, {
        let ret: LinuxResult<isize> = if iocb.is_null() || result.is_null() {
            Err(LinuxError::EFAULT)
        } else {
            let _ = get_aio_context(ctx)?;
            Err(LinuxError::EINVAL)
        };
        ret
    })
}
