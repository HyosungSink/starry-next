//! Task APIs for multi-task configuration.

use alloc::{
    string::String,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicUsize, Ordering};

use kernel_guard::NoPreemptIrqSave;

pub(crate) use crate::run_queue::{current_run_queue, select_run_queue};

static WAIT_INTERRUPT_HOOK: AtomicUsize = AtomicUsize::new(0);
static TASK_SWITCH_HOOK: AtomicUsize = AtomicUsize::new(0);

#[doc(cfg(feature = "multitask"))]
pub use crate::task::{reclaim_task_stack_cache, CurrentTask, TaskId, TaskInner};
#[doc(cfg(feature = "multitask"))]
pub use crate::task_ext::{TaskExtMut, TaskExtRef};
#[doc(cfg(feature = "multitask"))]
pub use crate::wait_queue::WaitQueue;

/// The reference type of a task.
pub type AxTaskRef = Arc<AxTask>;

/// The weak reference type of a task.
pub type WeakAxTaskRef = Weak<AxTask>;

pub use crate::task::TaskState;

pub fn reclaim_exited_tasks(max_scan: usize) -> usize {
    crate::run_queue::reclaim_exited_tasks(max_scan)
}

/// The wrapper type for [`cpumask::CpuMask`] with SMP configuration.
pub type AxCpuMask = cpumask::CpuMask<{ axconfig::SMP }>;

cfg_if::cfg_if! {
    if #[cfg(feature = "sched_rr")] {
        const MAX_TIME_SLICE: usize = 5;
        pub(crate) type AxTask = scheduler::RRTask<TaskInner, MAX_TIME_SLICE>;
        pub(crate) type Scheduler = scheduler::RRScheduler<TaskInner, MAX_TIME_SLICE>;
    } else if #[cfg(feature = "sched_cfs")] {
        pub(crate) type AxTask = scheduler::CFSTask<TaskInner>;
        pub(crate) type Scheduler = scheduler::CFScheduler<TaskInner>;
    } else {
        // If no scheduler features are set, use FIFO as the default.
        pub(crate) type AxTask = scheduler::FifoTask<TaskInner>;
        pub(crate) type Scheduler = scheduler::FifoScheduler<TaskInner>;
    }
}

#[cfg(feature = "preempt")]
struct KernelGuardIfImpl;

#[cfg(feature = "preempt")]
#[crate_interface::impl_interface]
impl kernel_guard::KernelGuardIf for KernelGuardIfImpl {
    fn disable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.disable_preempt();
        }
    }

    fn enable_preempt() {
        if let Some(curr) = current_may_uninit() {
            curr.enable_preempt(true);
        }
    }
}

/// Gets the current task, or returns [`None`] if the current task is not
/// initialized.
pub fn current_may_uninit() -> Option<CurrentTask> {
    CurrentTask::try_get()
}

/// Gets the current task.
///
/// # Panics
///
/// Panics if the current task is not initialized.
pub fn current() -> CurrentTask {
    CurrentTask::get()
}

/// Forces a non-current task into the exited state and wakes any joiners.
pub fn force_exit_task(task: &AxTaskRef, exit_code: i32) -> bool {
    if task.state() == TaskState::Exited {
        return false;
    }
    task.set_in_wait_queue(false);
    task.set_state(TaskState::Exited);
    task.notify_exit(exit_code);
    true
}

/// Wakes a blocked task so it can observe asynchronous events such as signals.
pub fn wake_task(task: &AxTaskRef) -> bool {
    if task.state() == TaskState::Blocked {
        select_run_queue::<NoPreemptIrqSave>(task).unblock_task(task.clone(), true);
        return true;
    }
    #[cfg(feature = "preempt")]
    {
        let curr = current();
        if !curr.ptr_eq(task) && task.state() == TaskState::Ready {
            curr.set_preempt_pending(true);
            return true;
        }
    }
    false
}

pub fn set_wait_interrupt_hook(hook: fn() -> bool) {
    WAIT_INTERRUPT_HOOK.store(hook as usize, Ordering::Release);
}

pub fn current_wait_should_interrupt() -> bool {
    let hook = WAIT_INTERRUPT_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return false;
    }
    let hook: fn() -> bool = unsafe { core::mem::transmute(hook) };
    hook()
}

pub fn set_task_switch_hook(hook: fn(*mut u8, *mut u8, usize)) {
    TASK_SWITCH_HOOK.store(hook as usize, Ordering::Release);
}

pub(crate) fn notify_task_switch(prev_task_ext: *mut u8, next_task_ext: *mut u8, now: usize) {
    let hook = TASK_SWITCH_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return;
    }
    let hook: fn(*mut u8, *mut u8, usize) = unsafe { core::mem::transmute(hook) };
    hook(prev_task_ext, next_task_ext, now);
}

/// Initializes the task scheduler (for the primary CPU).
pub fn init_scheduler() {
    info!("Initialize scheduling...");

    crate::run_queue::init();
    #[cfg(feature = "irq")]
    crate::timers::init();

    info!("  use {} scheduler.", Scheduler::scheduler_name());
}

/// Initializes the task scheduler for secondary CPUs.
pub fn init_scheduler_secondary() {
    crate::run_queue::init_secondary();
    #[cfg(feature = "irq")]
    crate::timers::init();
}

/// Handles periodic timer ticks for the task manager.
///
/// For example, advance scheduler states, checks timed events, etc.
#[cfg(feature = "irq")]
#[doc(cfg(feature = "irq"))]
pub fn on_timer_tick() {
    use kernel_guard::NoOp;
    crate::timers::check_events();
    // Since irq and preemption are both disabled here,
    // we can get current run queue with the default `kernel_guard::NoOp`.
    current_run_queue::<NoOp>().scheduler_timer_tick();
}

/// Adds the given task to the run queue, returns the task reference.
pub fn spawn_task(task: TaskInner) -> AxTaskRef {
    let task_ref = task.into_arc();
    select_run_queue::<NoPreemptIrqSave>(&task_ref).add_task(task_ref.clone());
    task_ref
}

/// Spawns a new task with the given parameters.
///
/// Returns the task reference.
pub fn spawn_raw<F>(f: F, name: String, stack_size: usize) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    spawn_task(TaskInner::new(f, name, stack_size))
}

/// Spawns a new task with the default parameters.
///
/// The default task name is an empty string. The default task stack size is
/// [`axconfig::TASK_STACK_SIZE`].
///
/// Returns the task reference.
pub fn spawn<F>(f: F) -> AxTaskRef
where
    F: FnOnce() + Send + 'static,
{
    spawn_raw(f, "".into(), axconfig::TASK_STACK_SIZE)
}

/// Set the priority for current task.
///
/// The range of the priority is dependent on the underlying scheduler. For
/// example, in the [CFS] scheduler, the priority is the nice value, ranging from
/// -20 to 19.
///
/// Returns `true` if the priority is set successfully.
///
/// [CFS]: https://en.wikipedia.org/wiki/Completely_Fair_Scheduler
pub fn set_priority(prio: isize) -> bool {
    current_run_queue::<NoPreemptIrqSave>().set_current_priority(prio)
}

/// Set the priority for a specific task.
///
/// The exact priority range depends on the active scheduler implementation.
/// Returns `true` if the scheduler accepted the new priority.
pub fn set_task_priority(task: &AxTaskRef, prio: isize) -> bool {
    select_run_queue::<NoPreemptIrqSave>(task).set_task_priority(task, prio)
}

/// Set the time slice for a specific task when the RR scheduler is active.
pub fn set_task_time_slice(task: &AxTaskRef, time_slice: usize) -> bool {
    #[cfg(feature = "sched_rr")]
    {
        task.set_time_slice_value(time_slice as isize);
        true
    }
    #[cfg(not(feature = "sched_rr"))]
    {
        let _ = (task, time_slice);
        false
    }
}

/// Set the affinity for the current task.
/// [`AxCpuMask`] is used to specify the CPU affinity.
/// Returns `true` if the affinity is set successfully.
///
/// TODO: support set the affinity for other tasks.
pub fn set_current_affinity(cpumask: AxCpuMask) -> bool {
    if cpumask.is_empty() {
        false
    } else {
        let curr = current().clone();

        curr.set_cpumask(cpumask);
        // After setting the affinity, we need to check if current cpu matches
        // the affinity. If not, we need to migrate the task to the correct CPU.
        #[cfg(feature = "smp")]
        if !cpumask.get(axhal::cpu::this_cpu_id()) {
            const MIGRATION_TASK_STACK_SIZE: usize = 4096;
            // Spawn a new migration task for migrating.
            let migration_task = TaskInner::new(
                move || crate::run_queue::migrate_entry(curr),
                "migration-task".into(),
                MIGRATION_TASK_STACK_SIZE,
            )
            .into_arc();

            // Migrate the current task to the correct CPU using the migration task.
            current_run_queue::<NoPreemptIrqSave>().migrate_current(migration_task);

            assert!(cpumask.get(axhal::cpu::this_cpu_id()), "Migration failed");
        }
        true
    }
}

/// Current task gives up the CPU time voluntarily, and switches to another
/// ready task.
pub fn yield_now() {
    current_run_queue::<NoPreemptIrqSave>().yield_current()
}

/// Current task is going to sleep for the given duration.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep(dur: core::time::Duration) {
    sleep_until(axhal::time::wall_time() + dur);
}

/// Current task is going to sleep, it will be woken up at the given deadline.
///
/// If the feature `irq` is not enabled, it uses busy-wait instead.
pub fn sleep_until(deadline: axhal::time::TimeValue) {
    #[cfg(feature = "irq")]
    current_run_queue::<NoPreemptIrqSave>().sleep_until(deadline);
    #[cfg(not(feature = "irq"))]
    axhal::time::busy_wait_until(deadline);
}

/// Exits the current task.
pub fn exit(exit_code: i32) -> ! {
    current_run_queue::<NoPreemptIrqSave>().exit_current(exit_code)
}

/// The idle task routine.
///
/// It runs an infinite loop that keeps calling [`yield_now()`].
pub fn run_idle() -> ! {
    loop {
        yield_now();
        debug!("idle task: waiting for IRQs...");
        #[cfg(feature = "irq")]
        axhal::arch::wait_for_irqs();
    }
}
