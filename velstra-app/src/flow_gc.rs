//! Bounded maintenance of the coherent flow table, independent of diagnostics.
//! Only versioned snapshots and conditional control operations may remove state.
//! No live map values or allocator words are read/overwritten from userspace.
use std::{
    sync::{Arc, Mutex, TryLockError},
    time::{Duration, Instant},
};

use anyhow::Result;
use velstra_common::{FirewallFlowRecord, FlowControlStatus as Status, FlowRecordKind as Kind};

use crate::flow_store::{FlowStore, SharedFlowStore, monotonic_ms, status};

const INTERVAL: Duration = Duration::from_millis(100);
const SLOT_BUDGET: u32 = 1024;
// Cooperative budget: a kernel syscall already in progress cannot be preempted.
const TIME_BUDGET: Duration = Duration::from_millis(5);

pub type SharedGcStatus = Arc<Mutex<GcStatus>>;

#[derive(Clone, Debug, Default)]
pub struct GcStatus {
    pub scanned: u64,
    pub expired: u64,
    pub orphaned: u64,
    pub reclaimed: u64,
    pub contention: u64,
    pub conflicts: u64,
    pub errors: u64,
    pub completed_sweeps: u64,
    pub allocated_slots: u32,
    pub next_slot: u32,
    pub last_run_ms: Option<u64>,
    pub last_clean_sweep_ms: Option<u64>,
    pub last_error: Option<String>,
    degraded: bool,
}
impl GcStatus {
    pub fn render(&self) -> String {
        let state = if self.degraded {
            "Degraded"
        } else if self.last_clean_sweep_ms.is_some() {
            "Ready"
        } else {
            "Starting"
        };
        serde_json::json!({
            "state":state,"scannedSlots":self.scanned,"expiredEntries":self.expired,
            "orphanedAliases":self.orphaned,"reclaimedRetiredSlots":self.reclaimed,
            "contention":self.contention,"conflicts":self.conflicts,"errors":self.errors,
            "completedSweeps":self.completed_sweeps,"allocatedSlots":self.allocated_slots,
            "nextSlot":self.next_slot,"lastRunMs":self.last_run_ms,
            "lastCleanSweepMs":self.last_clean_sweep_ms,"lastError":self.last_error,
        })
        .to_string()
            + "\n"
    }
    fn record(&mut self, batch: &GcBatch) {
        self.scanned = self.scanned.saturating_add(batch.scanned as u64);
        self.expired = self.expired.saturating_add(batch.expired as u64);
        self.orphaned = self.orphaned.saturating_add(batch.orphaned as u64);
        self.reclaimed = self.reclaimed.saturating_add(batch.reclaimed as u64);
        self.contention = self.contention.saturating_add(batch.contention as u64);
        self.conflicts = self.conflicts.saturating_add(batch.conflicts as u64);
        self.errors = self.errors.saturating_add(batch.errors as u64);
        if let Some(allocated) = batch.allocated_slots {
            self.allocated_slots = allocated;
        }
        self.next_slot = batch.next_slot;
        if batch.now_ms.is_some() {
            self.last_run_ms = batch.now_ms;
        }
        if batch.completed_sweep {
            self.completed_sweeps = self.completed_sweeps.saturating_add(1);
        }
        if batch.clean_sweep {
            self.last_clean_sweep_ms = batch.now_ms;
            self.degraded = false;
        }
        if let Some(error) = &batch.error {
            self.last_error = Some(error.clone());
            self.degraded = true;
        }
    }
}

#[derive(Default, Debug)]
pub struct GcBatch {
    pub scanned: u32,
    pub expired: u32,
    pub orphaned: u32,
    pub reclaimed: u32,
    pub contention: u32,
    pub conflicts: u32,
    pub errors: u32,
    pub allocated_slots: Option<u32>,
    pub next_slot: u32,
    pub completed_sweep: bool,
    pub clean_sweep: bool,
    pub now_ms: Option<u64>,
    pub error: Option<String>,
}
impl GcBatch {
    fn failure(&mut self, error: anyhow::Error) {
        match status(&error) {
            Some(Status::BUSY) => self.contention += 1,
            Some(Status::CONFLICT | Status::MISSING) => self.conflicts += 1,
            _ => {
                self.errors += 1;
                if self.error.is_none() {
                    self.error = Some(format!("{error:#}"));
                }
            }
        }
    }
}

trait Backend {
    fn allocated(&mut self) -> Result<u32>;
    fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>>;
    fn remove(&mut self, record: &FirewallFlowRecord) -> Result<()>;
    fn reclaim(&mut self, slot: u32) -> Result<bool>;
}
impl Backend for FlowStore {
    fn allocated(&mut self) -> Result<u32> {
        self.allocated_slots()
    }
    fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>> {
        self.snapshot_slot(slot)
    }
    fn remove(&mut self, record: &FirewallFlowRecord) -> Result<()> {
        self.remove_if_unchanged(record)
    }
    fn reclaim(&mut self, slot: u32) -> Result<bool> {
        self.reclaim_retired(slot)
    }
}

#[derive(Default)]
pub struct Collector {
    next_slot: u32,
    cycle_failed: bool,
}
impl Collector {
    pub fn collect(&mut self, store: &mut FlowStore) -> GcBatch {
        self.collect_with(store, SLOT_BUDGET, TIME_BUDGET)
    }
    fn collect_with(
        &mut self,
        store: &mut impl Backend,
        limit: u32,
        duration: Duration,
    ) -> GcBatch {
        let mut out = GcBatch {
            next_slot: self.next_slot,
            ..GcBatch::default()
        };
        let now_ms = match monotonic_ms() {
            Ok(now) => now,
            Err(error) => {
                out.failure(error);
                self.cycle_failed = true;
                return out;
            }
        };
        out.now_ms = Some(now_ms);
        let end = Instant::now() + duration;
        let high_water = match store.allocated() {
            Ok(n) => n,
            Err(error) => {
                out.failure(error);
                self.cycle_failed |= out.errors != 0;
                return out;
            }
        };
        out.allocated_slots = Some(high_water);
        if high_water == 0 {
            self.next_slot = 0;
            self.cycle_failed = false;
            out.next_slot = 0;
            out.clean_sweep = true;
            return out;
        }
        if self.next_slot >= high_water {
            self.next_slot = 0;
        }
        for _ in 0..limit {
            if Instant::now() >= end {
                break;
            }
            let slot = self.next_slot;
            out.scanned += 1;
            match store.snapshot(slot) {
                Ok(Some(record)) => {
                    if !matches!(
                        record.kind,
                        Kind::PRIMARY | Kind::ALIAS | Kind::ORPHAN_ALIAS
                    ) {
                        out.failure(anyhow::anyhow!(
                            "unknown coherent flow record kind {}",
                            record.kind
                        ));
                    }
                    let orphan = record.kind == Kind::ORPHAN_ALIAS;
                    // Alias snapshots carry their PRIMARY's state/deadline.
                    // Config reconciliation durably clips these deadlines before
                    // publishing shorter policy timeouts. Never infer expiry from
                    // an alias scope or an unrelated policy's default timeout.
                    let expired = matches!(record.kind, Kind::PRIMARY | Kind::ALIAS)
                        && record.state.last_seen_ms <= now_ms
                        && record.state.expires_at_ms <= now_ms;
                    if orphan || expired {
                        match store.remove(&record) {
                            Ok(()) => {
                                if orphan {
                                    out.orphaned += 1;
                                } else {
                                    out.expired += 1;
                                }
                            }
                            Err(error) => out.failure(error),
                        }
                    }
                }
                Ok(None) => match store.reclaim(slot) {
                    Ok(true) => out.reclaimed += 1,
                    Ok(false) => {}
                    Err(error) => out.failure(error),
                },
                Err(error) => out.failure(error),
            }
            self.cycle_failed |= out.errors != 0 || out.contention != 0 || out.conflicts != 0;
            self.next_slot += 1;
            if self.next_slot == high_water {
                self.next_slot = 0;
                out.completed_sweep = true;
                out.clean_sweep = !self.cycle_failed;
                self.cycle_failed = false;
                break;
            }
        }
        out.next_slot = self.next_slot;
        out
    }
}

/// Starts unconditionally in the agent. Socket availability and stats options
/// do not control maintenance. Each batch yields to policy writers and runs its
/// syscalls on a blocking worker, never on the async runtime's socket threads.
pub async fn run(store: SharedFlowStore, health: SharedGcStatus) {
    let mut tick = tokio::time::interval(INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut collector = Collector::default();
    loop {
        tick.tick().await;
        let handle = store.clone();
        let mut current = std::mem::take(&mut collector);
        let result = tokio::task::spawn_blocking(move || {
            let batch = match handle.try_lock() {
                Ok(mut store) => current.collect(&mut store),
                Err(TryLockError::WouldBlock) => GcBatch {
                    contention: 1,
                    next_slot: current.next_slot,
                    now_ms: monotonic_ms().ok(),
                    ..GcBatch::default()
                },
                Err(TryLockError::Poisoned(_)) => GcBatch {
                    errors: 1,
                    error: Some("firewall state control lock poisoned".into()),
                    next_slot: current.next_slot,
                    now_ms: monotonic_ms().ok(),
                    ..GcBatch::default()
                },
            };
            (current, batch)
        })
        .await;
        let mut batch = match result {
            Ok((next, batch)) => {
                collector = next;
                batch
            }
            Err(error) => GcBatch {
                errors: 1,
                error: Some(format!("firewall state collector worker failed: {error}")),
                now_ms: monotonic_ms().ok(),
                ..GcBatch::default()
            },
        };
        if batch.now_ms.is_none() {
            batch.failure(anyhow::anyhow!(
                "reading monotonic clock for firewall state maintenance failed"
            ));
        }
        if let Ok(mut state) = health.lock() {
            if let Some(error) = &batch.error
                && (state.last_error.as_ref() != Some(error) || !state.degraded)
            {
                log::warn!("firewall state maintenance: {error}");
            }
            state.record(&batch);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::flow_store::FlowControlError;

    #[derive(Default)]
    struct Store {
        high_water: u32,
        rows: BTreeMap<u32, FirewallFlowRecord>,
        visited: Vec<u32>,
        removed: Vec<u32>,
        retired: BTreeSet<u32>,
        faults: BTreeMap<u32, u32>,
        refresh_on_remove: bool,
    }
    impl Backend for Store {
        fn allocated(&mut self) -> Result<u32> {
            Ok(self.high_water)
        }
        fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>> {
            self.visited.push(slot);
            if let Some(status) = self.faults.get(&slot) {
                return Err(FlowControlError { status: *status }.into());
            }
            Ok(self.rows.get(&slot).copied())
        }
        fn remove(&mut self, record: &FirewallFlowRecord) -> Result<()> {
            if self.refresh_on_remove {
                self.rows.get_mut(&record.entry.slot).unwrap().revision += 1;
                return Err(FlowControlError {
                    status: Status::CONFLICT,
                }
                .into());
            }
            self.rows.remove(&record.entry.slot);
            self.removed.push(record.entry.slot);
            Ok(())
        }
        fn reclaim(&mut self, slot: u32) -> Result<bool> {
            Ok(self.retired.remove(&slot))
        }
    }
    fn record(slot: u32, kind: u32, deadline: u64) -> FirewallFlowRecord {
        let mut record = FirewallFlowRecord::EMPTY;
        record.kind = kind;
        record.entry.slot = slot;
        record.state.last_seen_ms = 0;
        record.state.expires_at_ms = deadline;
        record
    }
    fn collect(cursor: &mut Collector, store: &mut Store, limit: u32) -> GcBatch {
        cursor.collect_with(store, limit, Duration::from_secs(1))
    }

    #[test]
    fn only_initialized_prefix_is_scanned_with_bounded_progress_and_wrap() {
        let mut store = Store {
            high_water: 5,
            ..Store::default()
        };
        let mut cursor = Collector::default();
        let first = collect(&mut cursor, &mut store, 2);
        assert_eq!(store.visited, [0, 1]);
        assert_eq!(first.next_slot, 2);
        assert!(!first.completed_sweep);
        let second = collect(&mut cursor, &mut store, 2);
        assert_eq!(second.next_slot, 4);
        let third = collect(&mut cursor, &mut store, 2);
        assert_eq!(store.visited, [0, 1, 2, 3, 4]);
        assert_eq!(third.next_slot, 0);
        assert!(third.clean_sweep);
        store.high_water = 0;
        store.visited.clear();
        assert!(collect(&mut cursor, &mut store, 2).clean_sweep);
        assert!(store.visited.is_empty());
    }
    #[test]
    fn expiry_uses_primary_deadline_for_aliases_and_removes_orphans() {
        let mut store = Store {
            high_water: 5,
            ..Store::default()
        };
        store.rows.insert(0, record(0, Kind::PRIMARY, 0));
        store.rows.insert(1, record(1, Kind::ALIAS, u64::MAX));
        store.rows.insert(2, record(2, Kind::ALIAS, 0));
        store
            .rows
            .insert(3, record(3, Kind::ORPHAN_ALIAS, u64::MAX));
        store.retired.insert(4);
        let batch = collect(&mut Collector::default(), &mut store, 10);
        assert_eq!(store.removed, [0, 2, 3]);
        assert!(store.rows.contains_key(&1));
        assert_eq!(batch.expired, 2);
        assert_eq!(batch.orphaned, 1);
        assert_eq!(batch.reclaimed, 1);
    }
    #[test]
    fn corrupt_record_kind_is_reported_and_not_removed() {
        let mut store = Store {
            high_water: 1,
            ..Store::default()
        };
        store.rows.insert(0, record(0, u32::MAX, 0));
        let batch = collect(&mut Collector::default(), &mut store, 1);
        assert_eq!(batch.errors, 1);
        assert!(!batch.clean_sweep);
        assert!(store.rows.contains_key(&0));
    }
    #[test]
    fn missing_clock_does_not_replace_last_known_timestamp() {
        let mut state = GcStatus::default();
        state.record(&GcBatch {
            now_ms: Some(42),
            clean_sweep: true,
            ..GcBatch::default()
        });
        state.record(&GcBatch {
            error: Some("clock unavailable".into()),
            errors: 1,
            ..GcBatch::default()
        });
        assert_eq!(state.last_run_ms, Some(42));
        assert_eq!(state.last_clean_sweep_ms, Some(42));
        assert!(state.degraded);
    }
    #[test]
    fn concurrent_refresh_is_not_deleted_and_incomplete_sweep_is_explicit() {
        let mut store = Store {
            high_water: 1,
            refresh_on_remove: true,
            ..Store::default()
        };
        store.rows.insert(0, record(0, Kind::PRIMARY, 0));
        let batch = collect(&mut Collector::default(), &mut store, 10);
        assert_eq!(batch.conflicts, 1);
        assert_eq!(batch.errors, 0);
        assert_eq!(batch.expired, 0);
        assert!(!batch.clean_sweep);
        assert_eq!(store.rows[&0].revision, 1);
    }
    #[test]
    fn busy_and_broken_slots_do_not_starve_later_slots_and_recovery_is_observed() {
        let mut store = Store {
            high_water: 3,
            ..Store::default()
        };
        store.faults.insert(0, Status::BUSY);
        store.faults.insert(1, Status::CORRUPT);
        store.rows.insert(2, record(2, Kind::PRIMARY, 0));
        let mut collector = Collector::default();
        let mut state = GcStatus::default();
        let first = collect(&mut collector, &mut store, 2);
        assert_eq!(first.errors, 1);
        assert_eq!(first.contention, 1);
        state.record(&first);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&state.render()).unwrap()["state"],
            "Degraded"
        );
        store.faults.clear();
        let partial = collect(&mut collector, &mut store, 2);
        assert!(!partial.clean_sweep);
        assert_eq!(partial.expired, 1);
        state.record(&partial);
        let complete = collect(&mut collector, &mut store, 3);
        assert!(complete.clean_sweep);
        state.record(&complete);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&state.render()).unwrap()["state"],
            "Ready"
        );
        assert!(state.last_error.is_some());
    }
    #[test]
    fn time_budget_can_yield_without_advancing_or_claiming_a_clean_sweep() {
        let mut store = Store {
            high_water: 5,
            ..Store::default()
        };
        let mut cursor = Collector::default();
        let batch = cursor.collect_with(&mut store, 10, Duration::ZERO);
        assert_eq!(batch.scanned, 0);
        assert_eq!(batch.next_slot, 0);
        assert!(!batch.completed_sweep);
        assert!(store.visited.is_empty());
    }
    #[test]
    fn contention_does_not_replace_last_known_allocator_extent() {
        let mut state = GcStatus::default();
        state.record(&GcBatch {
            allocated_slots: Some(9),
            clean_sweep: true,
            ..GcBatch::default()
        });
        state.record(&GcBatch {
            contention: 1,
            ..GcBatch::default()
        });
        assert_eq!(state.allocated_slots, 9);
        assert_eq!(state.contention, 1);
    }
}
