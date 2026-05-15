use alloc::string::ToString;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel_guard::NoOp;
use lazyinit::LazyInit;
use timer_list::{TimeValue, TimerEvent, TimerList};

use axhal::time::wall_time;

use crate::{AxTaskRef, select_run_queue};

static TIMER_TICKET_ID: AtomicU64 = AtomicU64::new(1);
static NICE05_TIMER_DIAG_COUNT: AtomicU64 = AtomicU64::new(0);

percpu_static! {
    TIMER_LIST: LazyInit<TimerList<TaskWakeupEvent>> = LazyInit::new(),
}

struct TaskWakeupEvent {
    ticket_id: u64,
    task: AxTaskRef,
}

fn take_nice05_timer_diag_slot(task: &AxTaskRef) -> Option<u64> {
    if !task.name().contains("nice05") {
        return None;
    }
    let slot = NICE05_TIMER_DIAG_COUNT.fetch_add(1, Ordering::Relaxed);
    (slot < 64).then_some(slot + 1)
}

impl TimerEvent for TaskWakeupEvent {
    fn callback(self, _now: TimeValue) {
        let diag_slot = take_nice05_timer_diag_slot(&self.task);
        if let Some(slot) = diag_slot {
            warn!(
                "[nice05-timer:{}] callback enter tid={} name={} ticket={} current_ticket={} state={:?}",
                slot,
                self.task.id().as_u64(),
                self.task.name(),
                self.ticket_id,
                self.task.timer_ticket(),
                self.task.state(),
            );
        }
        // Ignore the timer event if timeout was set but not triggered
        // (wake up by `WaitQueue::notify()`).
        // Judge if this timer event is still valid by checking the ticket ID.
        if self.task.timer_ticket() != self.ticket_id {
            if let Some(slot) = diag_slot {
                warn!(
                    "[nice05-timer:{}] callback ignore tid={} name={} reason=ticket-mismatch",
                    slot,
                    self.task.id().as_u64(),
                    self.task.name(),
                );
            }
            // Timer ticket ID is not matched.
            // Just ignore this timer event and return.
            return;
        }

        // Timer ticket match.
        let diag_task = diag_slot.map(|_| self.task.clone());
        select_run_queue::<NoOp>(&self.task).unblock_task(self.task, true);
        if let Some(slot) = diag_slot {
            let diag_task = diag_task.as_ref().unwrap();
            warn!(
                "[nice05-timer:{}] callback exit tid={} name={} new_state={:?}",
                slot,
                diag_task.id().as_u64(),
                diag_task.name(),
                diag_task.state(),
            );
        }
    }
}

pub fn set_alarm_wakeup(deadline: TimeValue, task: AxTaskRef) {
    TIMER_LIST.with_current(|timer_list| {
        let ticket_id = TIMER_TICKET_ID.fetch_add(1, Ordering::AcqRel);
        let diag_slot = take_nice05_timer_diag_slot(&task);
        let tid = task.id().as_u64();
        let name = task.name().to_string();
        task.set_timer_ticket(ticket_id);
        timer_list.set(deadline, TaskWakeupEvent { ticket_id, task });
        if let Some(slot) = diag_slot {
            warn!(
                "[nice05-timer:{}] arm tid={} name={} ticket={} deadline={:?}",
                slot,
                tid,
                name,
                ticket_id,
                deadline,
            );
        }
    })
}

pub fn check_events() {
    loop {
        let now = wall_time();
        let event = unsafe {
            // Safety: IRQs are disabled at this time.
            TIMER_LIST.current_ref_mut_raw()
        }
        .expire_one(now);
        if let Some((_deadline, event)) = event {
            event.callback(now);
        } else {
            break;
        }
    }
}

pub fn init() {
    TIMER_LIST.with_current(|timer_list| {
        timer_list.init_once(TimerList::new());
    });
}
