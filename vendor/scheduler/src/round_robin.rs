use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicIsize, Ordering};

use crate::BaseScheduler;

/// A task wrapper for the [`RRScheduler`].
///
/// It add a time slice counter to use in round-robin scheduling.
pub struct RRTask<T, const MAX_TIME_SLICE: usize> {
    inner: T,
    time_slice: AtomicIsize,
    priority: AtomicIsize,
}

impl<T, const S: usize> RRTask<T, S> {
    /// Creates a new [`RRTask`] from the inner task struct.
    pub const fn new(inner: T) -> Self {
        Self {
            inner,
            time_slice: AtomicIsize::new(S as isize),
            priority: AtomicIsize::new(0),
        }
    }

    fn time_slice(&self) -> isize {
        self.time_slice.load(Ordering::Acquire)
    }

    fn reset_time_slice(&self) {
        self.time_slice.store(S as isize, Ordering::Release);
    }

    fn priority(&self) -> isize {
        self.priority.load(Ordering::Acquire)
    }

    fn set_priority_value(&self, priority: isize) {
        self.priority.store(priority, Ordering::Release);
    }

    /// Returns a reference to the inner task struct.
    pub const fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T, const S: usize> Deref for RRTask<T, S> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A simple [Round-Robin] (RR) preemptive scheduler.
///
/// It's very similar to the [`FifoScheduler`], but every task has a time slice
/// counter that is decremented each time a timer tick occurs. When the current
/// task's time slice counter reaches zero, the task is preempted and needs to
/// be rescheduled.
///
/// Unlike [`FifoScheduler`], it uses [`VecDeque`] as the ready queue. So it may
/// take O(n) time to remove a task from the ready queue.
///
/// [Round-Robin]: https://en.wikipedia.org/wiki/Round-robin_scheduling
/// [`FifoScheduler`]: crate::FifoScheduler
pub struct RRScheduler<T, const MAX_TIME_SLICE: usize> {
    ready_queues: BTreeMap<isize, VecDeque<Arc<RRTask<T, MAX_TIME_SLICE>>>>,
}

impl<T, const S: usize> RRScheduler<T, S> {
    /// Creates a new empty [`RRScheduler`].
    pub const fn new() -> Self {
        Self {
            ready_queues: BTreeMap::new(),
        }
    }

    fn push_back_task(&mut self, task: Arc<RRTask<T, S>>) {
        self.ready_queues
            .entry(task.priority())
            .or_default()
            .push_back(task);
    }

    fn push_front_task(&mut self, task: Arc<RRTask<T, S>>) {
        self.ready_queues
            .entry(task.priority())
            .or_default()
            .push_front(task);
    }

    fn pop_highest_priority_task(&mut self) -> Option<Arc<RRTask<T, S>>> {
        let priority = self.ready_queues.keys().next_back().copied()?;
        let (task, remove_queue) = {
            let queue = self.ready_queues.get_mut(&priority)?;
            (queue.pop_front(), queue.is_empty())
        };
        if remove_queue {
            self.ready_queues.remove(&priority);
        }
        task
    }

    fn remove_queued_task(&mut self, task: &Arc<RRTask<T, S>>) -> Option<Arc<RRTask<T, S>>> {
        let priorities: alloc::vec::Vec<_> = self.ready_queues.keys().copied().collect();
        for priority in priorities {
            let (removed, remove_queue) = {
                let queue = self.ready_queues.get_mut(&priority)?;
                if let Some(index) = queue.iter().position(|queued| Arc::ptr_eq(queued, task)) {
                    (queue.remove(index), queue.is_empty())
                } else {
                    (None, false)
                }
            };
            if removed.is_some() {
                if remove_queue {
                    self.ready_queues.remove(&priority);
                }
                return removed;
            }
        }
        None
    }

    /// get the name of scheduler
    pub fn scheduler_name() -> &'static str {
        "Round-robin"
    }
}

impl<T, const S: usize> BaseScheduler for RRScheduler<T, S> {
    type SchedItem = Arc<RRTask<T, S>>;

    fn init(&mut self) {}

    fn add_task(&mut self, task: Self::SchedItem) {
        self.push_back_task(task);
    }

    fn remove_task(&mut self, task: &Self::SchedItem) -> Option<Self::SchedItem> {
        self.remove_queued_task(task)
    }

    fn pick_next_task(&mut self) -> Option<Self::SchedItem> {
        self.pop_highest_priority_task()
    }

    fn put_prev_task(&mut self, prev: Self::SchedItem, preempt: bool) {
        if prev.time_slice() > 0 && preempt {
            self.push_front_task(prev)
        } else {
            prev.reset_time_slice();
            self.push_back_task(prev)
        }
    }

    fn task_tick(&mut self, current: &Self::SchedItem) -> bool {
        let old_slice = current.time_slice.fetch_sub(1, Ordering::Release);
        old_slice <= 1
    }

    fn set_priority(&mut self, task: &Self::SchedItem, prio: isize) -> bool {
        if let Some(queued) = self.remove_queued_task(task) {
            queued.set_priority_value(prio);
            self.push_back_task(queued);
        } else {
            task.set_priority_value(prio);
        }
        true
    }
}
