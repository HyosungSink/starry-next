use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::ops::Deref;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use core::{alloc::Layout, cell::UnsafeCell, fmt, ptr::NonNull};

use axalloc::global_allocator;
use kspin::SpinNoIrq;
use memory_addr::{PAGE_SIZE_4K, VirtAddr, align_up_4k};

use axhal::arch::TaskContext;
#[cfg(feature = "tls")]
use axhal::tls::TlsArea;

use crate::task_ext::AxTaskExt;
use crate::{AxCpuMask, AxTask, AxTaskRef, WaitQueue};

/// A unique identifier for a thread.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TaskId(u64);

/// The possible states of a task.
#[repr(u8)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TaskState {
    /// Task is running on some CPU.
    Running = 1,
    /// Task is ready to run on some scheduler's ready queue.
    Ready = 2,
    /// Task is blocked (in the wait queue or timer list),
    /// and it has finished its scheduling process, it can be wake up by `notify()` on any run queue safely.
    Blocked = 3,
    /// Task is exited and waiting for being dropped.
    Exited = 4,
}

/// The inner task structure.
pub struct TaskInner {
    id: TaskId,
    name: UnsafeCell<String>,
    is_idle: bool,
    is_init: bool,

    entry: Option<*mut dyn FnOnce()>,
    state: AtomicU8,

    /// CPU affinity mask.
    cpumask: SpinNoIrq<AxCpuMask>,

    /// Mark whether the task is in the wait queue.
    in_wait_queue: AtomicBool,

    /// Used to indicate whether the task is running on a CPU.
    #[cfg(feature = "smp")]
    on_cpu: AtomicBool,

    /// A ticket ID used to identify the timer event.
    /// Set by `set_timer_ticket()` when creating a timer event in `set_alarm_wakeup()`,
    /// expired by setting it as zero in `timer_ticket_expired()`, which is called by `cancel_events()`.
    #[cfg(feature = "irq")]
    timer_ticket_id: AtomicU64,

    #[cfg(feature = "preempt")]
    need_resched: AtomicBool,
    #[cfg(feature = "preempt")]
    preempt_disable_count: AtomicUsize,

    exit_code: AtomicI32,
    wait_for_exit: WaitQueue,

    kstack: Option<TaskStack>,
    ctx: UnsafeCell<TaskContext>,
    task_ext: AxTaskExt,

    #[cfg(feature = "tls")]
    tls: TlsArea,
}

impl TaskId {
    fn new() -> Self {
        static ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(ID_COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Convert the task ID to a `u64`.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u8> for TaskState {
    #[inline]
    fn from(state: u8) -> Self {
        match state {
            1 => Self::Running,
            2 => Self::Ready,
            3 => Self::Blocked,
            4 => Self::Exited,
            _ => unreachable!(),
        }
    }
}

unsafe impl Send for TaskInner {}
unsafe impl Sync for TaskInner {}

impl TaskInner {
    /// Create a new task with the given entry function and stack size.
    pub fn new<F>(entry: F, name: String, stack_size: usize) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self::try_new(entry, name, stack_size)
            .unwrap_or_else(|| panic!("TaskInner::new failed to allocate task resources"))
    }

    /// Try to create a new task with the given entry function and stack size.
    pub fn try_new<F>(entry: F, name: String, stack_size: usize) -> Option<Self>
    where
        F: FnOnce() + Send + 'static,
    {
        let available_bytes = global_allocator().available_bytes();
        if available_bytes < 4096 {
            warn!(
                "TaskInner::new low byte allocator space: name={} stack_size={} available_bytes={} available_pages={}",
                name,
                stack_size,
                available_bytes,
                global_allocator().available_pages()
            );
        }
        let mut t = Self::new_common(TaskId::new(), name);
        debug!("new task: {}", t.id_name());
        let kstack = TaskStack::try_alloc(align_up_4k(stack_size))?;

        #[cfg(feature = "tls")]
        let tls = VirtAddr::from(t.tls.tls_ptr() as usize);
        #[cfg(not(feature = "tls"))]
        let tls = VirtAddr::from(0);

        t.entry = Some(Box::into_raw(Box::new(entry)));
        t.ctx_mut().init(task_entry as usize, kstack.top(), tls);
        t.kstack = Some(kstack);
        if t.name() == "idle" {
            t.is_idle = true;
        }
        Some(t)
    }

    /// Gets the ID of the task.
    pub const fn id(&self) -> TaskId {
        self.id
    }

    /// Gets the name of the task.
    pub fn name(&self) -> &str {
        unsafe { (*self.name.get()).as_str() }
    }

    /// Set the name of the task.
    pub fn set_name(&self, name: &str) {
        unsafe {
            *self.name.get() = String::from(name);
        }
    }

    /// Get a combined string of the task ID and name.
    pub fn id_name(&self) -> alloc::string::String {
        alloc::format!("Task({}, {:?})", self.id.as_u64(), self.name())
    }

    /// Wait for the task to exit, and return the exit code.
    ///
    /// It will return immediately if the task has already exited (but not dropped).
    pub fn join(&self) -> Option<i32> {
        self.wait_for_exit
            .wait_until(|| self.state() == TaskState::Exited);
        Some(self.exit_code.load(Ordering::Acquire))
    }

    /// Returns the pointer to the user-defined task extended data.
    ///
    /// # Safety
    ///
    /// The caller should not access the pointer directly, use [`TaskExtRef::task_ext`]
    /// or [`TaskExtMut::task_ext_mut`] instead.
    ///
    /// [`TaskExtRef::task_ext`]: crate::task_ext::TaskExtRef::task_ext
    /// [`TaskExtMut::task_ext_mut`]: crate::task_ext::TaskExtMut::task_ext_mut
    pub unsafe fn task_ext_ptr(&self) -> *mut u8 {
        self.task_ext.as_ptr()
    }

    /// Initialize the user-defined task extended data.
    ///
    /// Returns a reference to the task extended data if it has not been
    /// initialized yet (empty), otherwise returns [`None`].
    pub fn init_task_ext<T: Sized>(&mut self, data: T) -> Option<&T> {
        if self.task_ext.is_empty() {
            self.task_ext.write(data).map(|data| &*data)
        } else {
            None
        }
    }

    /// Returns a mutable reference to the task context.
    #[inline]
    pub const fn ctx_mut(&mut self) -> &mut TaskContext {
        self.ctx.get_mut()
    }

    /// Returns the top address of the kernel stack.
    #[inline]
    pub const fn kernel_stack_top(&self) -> Option<VirtAddr> {
        match &self.kstack {
            Some(s) => Some(s.top()),
            None => None,
        }
    }

    /// Gets the cpu affinity mask of the task.
    ///
    /// Returns the cpu affinity mask of the task in type [`AxCpuMask`].
    #[inline]
    pub fn cpumask(&self) -> AxCpuMask {
        *self.cpumask.lock()
    }

    /// Sets the cpu affinity mask of the task.
    ///
    /// # Arguments
    /// `cpumask` - The cpu affinity mask to be set in type [`AxCpuMask`].
    #[inline]
    pub fn set_cpumask(&self, cpumask: AxCpuMask) {
        *self.cpumask.lock() = cpumask
    }

    /// Read the top address of the kernel stack for the task.
    #[inline]
    pub fn get_kernel_stack_top(&self) -> Option<usize> {
        if let Some(kstack) = &self.kstack {
            return Some(kstack.top().as_usize());
        }
        None
    }

    /// Returns the exit code of the task.
    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }
}

// private methods
impl TaskInner {
    fn new_common(id: TaskId, name: String) -> Self {
        Self {
            id,
            name: UnsafeCell::new(name),
            is_idle: false,
            is_init: false,
            entry: None,
            state: AtomicU8::new(TaskState::Ready as u8),
            // By default, the task is allowed to run on all CPUs.
            cpumask: SpinNoIrq::new(AxCpuMask::full()),
            in_wait_queue: AtomicBool::new(false),
            #[cfg(feature = "irq")]
            timer_ticket_id: AtomicU64::new(0),
            #[cfg(feature = "smp")]
            on_cpu: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            need_resched: AtomicBool::new(false),
            #[cfg(feature = "preempt")]
            preempt_disable_count: AtomicUsize::new(0),
            exit_code: AtomicI32::new(0),
            wait_for_exit: WaitQueue::new(),
            kstack: None,
            ctx: UnsafeCell::new(TaskContext::new()),
            task_ext: AxTaskExt::empty(),
            #[cfg(feature = "tls")]
            tls: TlsArea::alloc(),
        }
    }

    /// Creates an "init task" using the current CPU states, to use as the
    /// current task.
    ///
    /// As it is the current task, no other task can switch to it until it
    /// switches out.
    ///
    /// And there is no need to set the `entry`, `kstack` or `tls` fields, as
    /// they will be filled automatically when the task is switches out.
    pub(crate) fn new_init(name: String) -> Self {
        let mut t = Self::new_common(TaskId::new(), name);
        t.is_init = true;
        #[cfg(feature = "smp")]
        t.set_on_cpu(true);
        if t.name() == "idle" {
            t.is_idle = true;
        }
        t
    }

    pub(crate) fn into_arc(self) -> AxTaskRef {
        Arc::new(AxTask::new(self))
    }

    /// Returns the task's current state.
    #[inline]
    pub fn state(&self) -> TaskState {
        self.state.load(Ordering::Acquire).into()
    }

    /// Set the task's state.
    #[inline]
    pub fn set_state(&self, state: TaskState) {
        self.state.store(state as u8, Ordering::Release)
    }

    /// Transition the task state from `current_state` to `new_state`,
    /// Returns `true` if the current state is `current_state` and the state is successfully set to `new_state`,
    /// otherwise returns `false`.
    #[inline]
    pub(crate) fn transition_state(&self, current_state: TaskState, new_state: TaskState) -> bool {
        self.state
            .compare_exchange(
                current_state as u8,
                new_state as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    #[inline]
    pub(crate) fn is_running(&self) -> bool {
        matches!(self.state(), TaskState::Running)
    }

    #[inline]
    pub(crate) fn is_ready(&self) -> bool {
        matches!(self.state(), TaskState::Ready)
    }

    #[inline]
    pub(crate) const fn is_init(&self) -> bool {
        self.is_init
    }

    #[inline]
    pub(crate) const fn is_idle(&self) -> bool {
        self.is_idle
    }

    #[inline]
    pub(crate) fn in_wait_queue(&self) -> bool {
        self.in_wait_queue.load(Ordering::Acquire)
    }

    #[inline]
    pub(crate) fn set_in_wait_queue(&self, in_wait_queue: bool) {
        self.in_wait_queue.store(in_wait_queue, Ordering::Release);
    }

    /// Returns task's current timer ticket ID.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn timer_ticket(&self) -> u64 {
        self.timer_ticket_id.load(Ordering::Acquire)
    }

    /// Set the timer ticket ID.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn set_timer_ticket(&self, timer_ticket_id: u64) {
        // CAN NOT set timer_ticket_id to 0,
        // because 0 is used to indicate the timer event is expired.
        assert!(timer_ticket_id != 0);
        self.timer_ticket_id
            .store(timer_ticket_id, Ordering::Release);
    }

    /// Expire timer ticket ID by setting it to 0,
    /// it can be used to identify one timer event is triggered or expired.
    #[inline]
    #[cfg(feature = "irq")]
    pub(crate) fn timer_ticket_expired(&self) {
        self.timer_ticket_id.store(0, Ordering::Release);
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn set_preempt_pending(&self, pending: bool) {
        self.need_resched.store(pending, Ordering::Release)
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn can_preempt(&self, current_disable_count: usize) -> bool {
        self.preempt_disable_count.load(Ordering::Acquire) == current_disable_count
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn disable_preempt(&self) {
        self.preempt_disable_count.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    #[cfg(feature = "preempt")]
    pub(crate) fn enable_preempt(&self, resched: bool) {
        if self.preempt_disable_count.fetch_sub(1, Ordering::Relaxed) == 1 && resched {
            // If current task is pending to be preempted, do rescheduling.
            Self::current_check_preempt_pending();
        }
    }

    #[cfg(feature = "preempt")]
    fn current_check_preempt_pending() {
        use kernel_guard::NoPreemptIrqSave;
        let curr = crate::current();
        if curr.need_resched.load(Ordering::Acquire) && curr.can_preempt(0) {
            // Note: if we want to print log msg during `preempt_resched`, we have to
            // disable preemption here, because the axlog may cause preemption.
            let mut rq = crate::current_run_queue::<NoPreemptIrqSave>();
            if curr.need_resched.load(Ordering::Acquire) {
                rq.preempt_resched()
            }
        }
    }

    /// Notify all tasks that join on this task.
    pub(crate) fn notify_exit(&self, exit_code: i32) {
        self.exit_code.store(exit_code, Ordering::Release);
        self.wait_for_exit.notify_all(false);
    }

    #[inline]
    pub(crate) const unsafe fn ctx_mut_ptr(&self) -> *mut TaskContext {
        self.ctx.get()
    }

    /// Returns whether the task is running on a CPU.
    ///
    /// It is used to protect the task from being moved to a different run queue
    /// while it has not finished its scheduling process.
    /// The `on_cpu field is set to `true` when the task is preparing to run on a CPU,
    /// and it is set to `false` when the task has finished its scheduling process in `clear_prev_task_on_cpu()`.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn on_cpu(&self) -> bool {
        self.on_cpu.load(Ordering::Acquire)
    }

    /// Sets whether the task is running on a CPU.
    #[cfg(feature = "smp")]
    #[inline]
    pub(crate) fn set_on_cpu(&self, on_cpu: bool) {
        self.on_cpu.store(on_cpu, Ordering::Release)
    }
}

impl fmt::Debug for TaskInner {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TaskInner")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("state", &self.state())
            .finish()
    }
}

impl Drop for TaskInner {
    fn drop(&mut self) {
        debug!("task drop: {}", self.id_name());
    }
}

struct TaskStack {
    ptr: NonNull<u8>,
    layout: Layout,
}

fn task_stack_cache() -> &'static SpinNoIrq<BTreeMap<(usize, usize), Vec<usize>>> {
    static CACHE: lazyinit::LazyInit<SpinNoIrq<BTreeMap<(usize, usize), Vec<usize>>>> =
        lazyinit::LazyInit::new();
    if let Some(cache) = CACHE.get() {
        cache
    } else {
        CACHE.init_once(SpinNoIrq::new(BTreeMap::new()))
    }
}

const TASK_STACK_CACHE_LIMIT_PER_LAYOUT: usize = 32;
static TASK_STACK_ALLOC_FAIL_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);

fn should_log_task_stack_alloc_failure() -> bool {
    let slot = TASK_STACK_ALLOC_FAIL_LOG_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    slot <= 4 || slot.is_power_of_two()
}

pub fn reclaim_task_stack_cache(keep_per_layout: usize) -> usize {
    let mut reclaimed = Vec::new();
    {
        let mut cache = task_stack_cache().lock();
        for (&(size, _align), entries) in cache.iter_mut() {
            let pages = size / PAGE_SIZE_4K;
            while entries.len() > keep_per_layout {
                let Some(ptr) = entries.pop() else {
                    break;
                };
                reclaimed.push((ptr, pages));
            }
        }
    }

    let mut reclaimed_pages = 0;
    for (ptr, pages) in reclaimed {
        global_allocator().dealloc_pages(ptr, pages);
        reclaimed_pages += pages;
    }
    reclaimed_pages
}

impl TaskStack {
    pub fn alloc(size: usize) -> Self {
        Self::try_alloc(size).unwrap_or_else(|| panic!("TaskStack::alloc failed"))
    }

    pub fn try_alloc(size: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size, PAGE_SIZE_4K).unwrap();
        let cache_key = (layout.size(), layout.align());
        if let Some(ptr) = task_stack_cache()
            .lock()
            .get_mut(&cache_key)
            .and_then(|cached| cached.pop())
        {
            return Some(Self {
                ptr: NonNull::new(ptr as *mut u8).expect("cached task stack pointer should be non-null"),
                layout,
            });
        }
        let num_pages = layout.size() / PAGE_SIZE_4K;
        match global_allocator().alloc_pages(num_pages, PAGE_SIZE_4K) {
            Ok(vaddr) => Some(Self {
                ptr: NonNull::new(vaddr as *mut u8)
                    .expect("allocated task stack pointer should be non-null"),
                layout,
            }),
            Err(err) => {
                let reclaimed_pages = reclaim_task_stack_cache(0);
                if reclaimed_pages > 0 {
                    if let Ok(vaddr) = global_allocator().alloc_pages(num_pages, PAGE_SIZE_4K) {
                        return Some(Self {
                            ptr: NonNull::new(vaddr as *mut u8)
                                .expect("allocated task stack pointer should be non-null"),
                            layout,
                        });
                    }
                }
                if should_log_task_stack_alloc_failure() {
                    warn!(
                        "TaskStack::alloc failed size={} available_bytes={} available_pages={} reclaimed_stack_pages={} err={:?}",
                        size,
                        global_allocator().available_bytes(),
                        global_allocator().available_pages(),
                        reclaimed_pages,
                        err
                    );
                }
                None
            }
        }
    }

    pub const fn top(&self) -> VirtAddr {
        unsafe { core::mem::transmute(self.ptr.as_ptr().add(self.layout.size())) }
    }
}

impl Drop for TaskStack {
    fn drop(&mut self) {
        let cache_key = (self.layout.size(), self.layout.align());
        let mut cache = task_stack_cache().lock();
        let entry = cache.entry(cache_key).or_default();
        if entry.len() < TASK_STACK_CACHE_LIMIT_PER_LAYOUT {
            entry.push(self.ptr.as_ptr() as usize);
        } else {
            drop(cache);
            global_allocator()
                .dealloc_pages(self.ptr.as_ptr() as usize, self.layout.size() / PAGE_SIZE_4K);
        }
    }
}

use core::mem::ManuallyDrop;

/// A wrapper of [`AxTaskRef`] as the current task.
///
/// It won't change the reference count of the task when created or dropped.
pub struct CurrentTask(ManuallyDrop<AxTaskRef>);

impl CurrentTask {
    pub(crate) fn try_get() -> Option<Self> {
        let ptr: *const super::AxTask = axhal::cpu::current_task_ptr();
        if !ptr.is_null() {
            Some(Self(unsafe { ManuallyDrop::new(AxTaskRef::from_raw(ptr)) }))
        } else {
            None
        }
    }

    pub(crate) fn get() -> Self {
        Self::try_get().expect("current task is uninitialized")
    }

    /// Converts [`CurrentTask`] to [`AxTaskRef`].
    pub fn as_task_ref(&self) -> &AxTaskRef {
        &self.0
    }

    pub(crate) fn clone(&self) -> AxTaskRef {
        self.0.deref().clone()
    }

    pub(crate) fn ptr_eq(&self, other: &AxTaskRef) -> bool {
        Arc::ptr_eq(&self.0, other)
    }

    pub(crate) unsafe fn init_current(init_task: AxTaskRef) {
        assert!(init_task.is_init());
        #[cfg(feature = "tls")]
        axhal::arch::write_thread_pointer(init_task.tls.tls_ptr() as usize);
        let ptr = Arc::into_raw(init_task);
        unsafe {
            axhal::cpu::set_current_task_ptr(ptr);
        }
    }

    pub(crate) unsafe fn set_current(prev: Self, next: AxTaskRef) {
        let Self(arc) = prev;
        ManuallyDrop::into_inner(arc); // `call Arc::drop()` to decrease prev task reference count.
        let ptr = Arc::into_raw(next);
        unsafe {
            axhal::cpu::set_current_task_ptr(ptr);
        }
    }
}

impl Deref for CurrentTask {
    type Target = TaskInner;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

extern "C" fn task_entry() -> ! {
    #[cfg(feature = "smp")]
    unsafe {
        // Clear the prev task on CPU before running the task entry function.
        crate::run_queue::clear_prev_task_on_cpu();
    }
    // Enable irq (if feature "irq" is enabled) before running the task entry function.
    #[cfg(feature = "irq")]
    axhal::arch::enable_irqs();
    let task = crate::current();
    if let Some(entry) = task.entry {
        unsafe { Box::from_raw(entry)() };
    }
    crate::exit(0);
}
