use std::{
    collections::HashMap,
    sync::{
        Arc, Barrier, Mutex,
        atomic::{AtomicBool, Ordering as StdOrdering},
    },
    thread,
};

use super::*;
use crate::{FlowScope, ip_proto};
struct Storage {
    allocator: FirewallFlowAllocator,
    slots: Vec<FirewallFlowSlot>,
    index: Mutex<HashMap<FirewallFlowKey, FirewallFlowRef>>,
    fail_insert: AtomicBool,
    fail_remove: AtomicBool,
    block_allocator_on_insert: AtomicBool,
}
impl Storage {
    fn new(capacity: u32) -> Self {
        Self {
            allocator: FirewallFlowAllocator::empty(),
            slots: (0..capacity).map(|_| FirewallFlowSlot::empty()).collect(),
            index: Mutex::new(HashMap::new()),
            fail_insert: AtomicBool::new(false),
            fail_remove: AtomicBool::new(false),
            block_allocator_on_insert: AtomicBool::new(false),
        }
    }
    fn check_accounting(&self) {
        // Quiescent test inspection only, never a live runtime reader.
        let allocator = self.allocator.lock().unwrap();
        let mut free = std::collections::HashSet::new();
        let mut cursor = allocator.free_head;
        while cursor != NONE {
            assert!(free.insert(cursor - 1), "duplicate free-list entry");
            let slot = &self.slots[(cursor - 1) as usize];
            assert_eq!(slot.lock().unwrap().state, VACANT);
            cursor = unsafe { *slot.next_free.get() };
        }
        let index = self.index.lock().unwrap();
        let mut live = 0;
        for i in 0..allocator.next_unused {
            let guard = self.slots[i as usize].lock().unwrap();
            match guard.state {
                VACANT => assert!(free.contains(&i), "unreachable free slot"),
                PRIMARY | ALIAS => {
                    let reference = index.get(&guard.key).unwrap();
                    assert_eq!(reference.slot, i);
                    assert_eq!(reference.incarnation, guard.incarnation);
                    live += 1;
                }
                RETIRED => assert!(!free.contains(&i)),
                _ => panic!("unfinished reservation"),
            }
        }
        assert_eq!(live, index.len());
    }
}
// Addresses fixed before sharing; all live accesses go through the table.
unsafe impl FirewallFlowStorage for Storage {
    fn capacity(&self) -> u32 {
        self.slots.len() as u32
    }
    fn allocator(&self) -> Option<&FirewallFlowAllocator> {
        Some(&self.allocator)
    }
    fn slot(&self, index: u32) -> Option<&FirewallFlowSlot> {
        self.slots.get(index as usize)
    }
    fn index(&self, key: &FirewallFlowKey) -> Option<FirewallFlowRef> {
        self.index.lock().unwrap().get(key).copied()
    }
    fn insert(
        &self,
        key: &FirewallFlowKey,
        value: FirewallFlowRef,
    ) -> Result<bool, FlowTableError> {
        if self.block_allocator_on_insert.load(StdOrdering::Relaxed) {
            self.allocator.busy.store(1, Ordering::Relaxed);
        }
        if self.fail_insert.load(StdOrdering::Relaxed) {
            return Err(FlowTableError::Storage);
        }
        let mut index = self.index.lock().unwrap();
        if index.contains_key(key) {
            return Ok(false);
        }
        index.insert(*key, value);
        Ok(true)
    }
    fn remove(&self, key: &FirewallFlowKey) -> Result<(), FlowTableError> {
        if self.fail_remove.load(StdOrdering::Relaxed) {
            return Err(FlowTableError::Storage);
        }
        self.index
            .lock()
            .unwrap()
            .remove(key)
            .ok_or(FlowTableError::Storage)?;
        Ok(())
    }
}
const T: FlowTimeouts = FlowTimeouts::DEFAULT;
fn key(port: u16) -> (FirewallFlowKey, FlowDirection) {
    FirewallFlowKey::transport_v4(
        FlowScope {
            identity: 7,
            generation: 9,
        },
        [10, 0, 0, 1],
        [198, 51, 100, 2],
        port,
        443,
        ip_proto::UDP,
    )
    .unwrap()
}
fn admit(
    table: &FirewallFlowTable<'_, Storage>,
    port: u16,
    now: u64,
) -> Result<FirewallFlowRef, FlowTableError> {
    let (key, direction) = key(port);
    table.admit(&key, FlowPacket::Udp, direction, now, T)
}
#[test]
fn exact_capacity_expiry_reuse_and_stale_reference() {
    let s = Storage::new(3);
    let table = FirewallFlowTable::new(&s);
    let old = admit(&table, 1, 100).unwrap();
    admit(&table, 2, 100).unwrap();
    admit(&table, 3, 100).unwrap();
    assert_eq!(admit(&table, 4, 100), Err(FlowTableError::Full));
    assert!(!table.sweep_slot(old.slot, 30_099, T).unwrap());
    assert!(table.sweep_slot(old.slot, 30_100, T).unwrap());
    let new = admit(&table, 4, 30_100).unwrap();
    assert_eq!(new.slot, old.slot);
    assert_ne!(new.incarnation, old.incarnation);
    assert_eq!(table.retire(&key(1).0, old), Err(FlowTableError::Conflict));
    assert!(table.export(&key(4).0, new, 30_100, T).unwrap().is_some());
    s.check_accounting();
}
#[test]
fn failed_publication_and_deferred_reclaim_recover() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    s.fail_insert.store(true, StdOrdering::Relaxed);
    s.block_allocator_on_insert
        .store(true, StdOrdering::Relaxed);
    assert_eq!(admit(&table, 1, 100), Err(FlowTableError::Storage));
    assert_eq!(s.allocator.busy.load(Ordering::Relaxed), 1);
    assert_eq!(s.slots[0].lock().unwrap().state, RETIRED);
    s.block_allocator_on_insert
        .store(false, StdOrdering::Relaxed);
    s.allocator.busy.store(0, Ordering::Release);
    s.fail_insert.store(false, StdOrdering::Relaxed);
    assert!(table.sweep_slot(0, 100, T).unwrap());
    admit(&table, 2, 100).unwrap();
    s.check_accounting();
}
#[test]
fn busy_locks_never_release_other_owners_or_lose_slots() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let a = s.allocator.lock().unwrap();
    assert_eq!(admit(&table, 1, 100), Err(FlowTableError::Busy));
    assert_eq!(s.allocator.busy.load(Ordering::Relaxed), 1);
    drop(a);
    let slot = s.slots[0].lock().unwrap();
    assert_eq!(admit(&table, 1, 100), Err(FlowTableError::Busy));
    assert_eq!(s.slots[0].busy.load(Ordering::Relaxed), 1);
    drop(slot);
    let reference = admit(&table, 1, 100).unwrap();
    let slot = s.slots[0].lock().unwrap();
    assert_eq!(
        table.export(&key(1).0, reference, 100, T),
        Err(FlowTableError::Busy)
    );
    assert_eq!(s.slots[0].busy.load(Ordering::Relaxed), 1);
    drop(slot);
    s.check_accounting();
}
#[test]
fn failed_removal_keeps_ownership_and_retry_removes_once() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let reference = admit(&table, 1, 100).unwrap();
    s.fail_remove.store(true, StdOrdering::Relaxed);
    assert_eq!(
        table.retire(&key(1).0, reference),
        Err(FlowTableError::Storage)
    );
    assert!(
        table
            .export(&key(1).0, reference, 100, T)
            .unwrap()
            .is_some()
    );
    s.fail_remove.store(false, StdOrdering::Relaxed);
    table.retire(&key(1).0, reference).unwrap();
    assert_eq!(
        table.retire(&key(1).0, reference),
        Err(FlowTableError::Conflict)
    );
    admit(&table, 2, 100).unwrap();
    s.check_accounting();
}
#[test]
fn mismatched_index_cannot_grant_another_tuple() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let reference = admit(&table, 1, 100).unwrap();
    s.index.lock().unwrap().insert(key(2).0, reference);
    let (k, d) = key(2);
    assert_eq!(
        table.observe(&k, FlowPacket::Udp, d, 100, T),
        Err(FlowTableError::Conflict)
    );
    s.index.lock().unwrap().remove(&k);
    s.check_accounting();
}
#[test]
fn aliases_share_timer_direction_and_cannot_survive_primary_reuse() {
    let s = Storage::new(3);
    let table = FirewallFlowTable::new(&s);
    let (k, d) = key(1);
    let (a, ad) = key(2);
    let reference = admit(&table, 1, 100).unwrap();
    let alias = table
        .alias(&a, &k, reference, (ad, FlowDirection::Reverse), 100, T)
        .unwrap();
    assert_eq!(
        table.observe(&a, FlowPacket::Udp, ad, 200, T),
        Ok(FlowLookup::Tracked(reference))
    );
    assert_eq!(
        table
            .export(&k, reference, 200, T)
            .unwrap()
            .unwrap()
            .remaining_ms,
        T.udp_replied_ms
    );
    assert_eq!(
        table.export(&a, alias, 200, T),
        Err(FlowTableError::Invalid)
    );
    table.retire(&k, reference).unwrap();
    let replacement = admit(&table, 1, 300).unwrap();
    assert_eq!(replacement.slot, reference.slot);
    assert_eq!(
        table.observe(&a, FlowPacket::Udp, ad, 300, T),
        Err(FlowTableError::Conflict)
    );
    assert!(table.sweep_slot(alias.slot, 300, T).unwrap());
    assert!(table.export(&k, replacement, 300, T).unwrap().is_some());
    let _ = d;
    s.check_accounting();
}
#[test]
fn reduced_timeout_applies_to_alias_and_primary_gc() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let reference = admit(&table, 1, 100).unwrap();
    let alias = table
        .alias(
            &key(2).0,
            &key(1).0,
            reference,
            (FlowDirection::Forward, FlowDirection::Forward),
            100,
            T,
        )
        .unwrap();
    let short = FlowTimeouts {
        udp_unreplied_ms: 10,
        ..T
    };
    assert!(table.sweep_slot(alias.slot, 110, short).unwrap());
    assert!(table.sweep_slot(reference.slot, 110, short).unwrap());
    s.check_accounting();
}
#[test]
fn incarnation_exhaustion_never_wraps_or_consumes_capacity() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    s.allocator.lock().unwrap().incarnation = u64::MAX;
    assert_eq!(admit(&table, 1, 100), Err(FlowTableError::Exhausted));
    assert_eq!(s.allocator.lock().unwrap().next_unused, 0);
    s.check_accounting();
}
#[test]
fn parallel_duplicate_admissions_have_one_owner_and_no_leaks() {
    let s = Arc::new(Storage::new(64));
    let barrier = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|_| {
            let s = s.clone();
            let barrier = barrier.clone();
            thread::spawn(move || {
                barrier.wait();
                admit(&FirewallFlowTable::new(&*s), 1, 100)
            })
        })
        .collect();
    let mut successes = Vec::new();
    for h in handles {
        match h.join().unwrap() {
            Ok(r) => successes.push(r),
            Err(e) => assert!(matches!(e, FlowTableError::Busy | FlowTableError::Conflict)),
        }
    }
    assert!(!successes.is_empty());
    assert!(successes.iter().all(|r| *r == successes[0]));
    let table = FirewallFlowTable::new(&*s);
    for i in 0..64 {
        table.sweep_slot(i, 100, T).unwrap();
    }
    assert_eq!(s.index.lock().unwrap().len(), 1);
    s.check_accounting();
    for port in 2..=64 {
        admit(&table, port, 100).unwrap();
    }
    assert_eq!(admit(&table, 65, 100), Err(FlowTableError::Full));
    s.check_accounting();
}
#[test]
fn old_retirement_racing_recreation_cannot_delete_fresh_index() {
    let s = Arc::new(Storage::new(8));
    let table = FirewallFlowTable::new(&*s);
    let old = admit(&table, 1, 100).unwrap();
    table.retire(&key(1).0, old).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let other = {
        let s = s.clone();
        let b = barrier.clone();
        thread::spawn(move || {
            let table = FirewallFlowTable::new(&*s);
            b.wait();
            for _ in 0..10_000 {
                assert!(matches!(
                    table.retire(&key(1).0, old),
                    Err(FlowTableError::Conflict | FlowTableError::Busy)
                ));
            }
        })
    };
    barrier.wait();
    for _ in 0..1000 {
        let fresh = loop {
            match admit(&table, 1, 100) {
                Ok(r) => break r,
                Err(FlowTableError::Busy) => thread::yield_now(),
                result => panic!("{result:?}"),
            }
        };
        loop {
            match table.export(&key(1).0, fresh, 100, T) {
                Ok(Some(_)) => break,
                Err(FlowTableError::Busy) => thread::yield_now(),
                result => panic!("{result:?}"),
            }
        }
        loop {
            match table.retire(&key(1).0, fresh) {
                Ok(()) => break,
                Err(FlowTableError::Busy) => thread::yield_now(),
                result => panic!("{result:?}"),
            }
        }
        for i in 0..8 {
            let _ = table.sweep_slot(i, 100, T);
        }
    }
    other.join().unwrap();
    for i in 0..8 {
        table.sweep_slot(i, 100, T).unwrap();
    }
    s.check_accounting();
}

#[test]
fn zero_filled_array_layout_is_ready_without_warmup_writes() {
    assert_eq!(core::mem::size_of::<FirewallFlowSlot>(), 168);
    assert_eq!(core::mem::size_of::<FirewallFlowAllocator>(), 24);
    // Every field accepts zero, including atomics and the integer-only union.
    let mut s = Storage::new(2);
    s.allocator = unsafe { core::mem::zeroed() };
    for slot in &mut s.slots {
        *slot = unsafe { core::mem::zeroed() };
    }
    let table = FirewallFlowTable::new(&s);
    let old = admit(&table, 1, 100).unwrap();
    admit(&table, 2, 100).unwrap();
    assert_eq!(admit(&table, 3, 100), Err(FlowTableError::Full));
    table.retire(&key(1).0, old).unwrap();
    admit(&table, 3, 100).unwrap();
    s.check_accounting();
}
#[test]
fn invalid_openers_do_not_retire_good_state_or_consume_slots() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let good = admit(&table, 1, 100).unwrap();
    let (mut k, d) = key(1);
    assert_eq!(
        table.admit(&k, FlowPacket::EchoReply, d, 100, T),
        Err(FlowTableError::Invalid)
    );
    k.protocol = ip_proto::TCP;
    assert_eq!(
        table.admit(&k, FlowPacket::Udp, d, 100, T),
        Err(FlowTableError::Invalid)
    );
    k = key(1).0;
    k.scope.generation = 0;
    assert_eq!(
        table.admit(&k, FlowPacket::Udp, d, 100, T),
        Err(FlowTableError::Invalid)
    );
    assert!(table.export(&key(1).0, good, 100, T).unwrap().is_some());
    s.check_accounting();
}

#[test]
fn gc_clock_sample_preceding_concurrent_observation_preserves_flow_and_alias() {
    let s = Storage::new(3);
    let table = FirewallFlowTable::new(&s);
    let reference = admit(&table, 1, 100).unwrap();
    let (k, d) = key(1);
    let (a, ad) = key(2);
    let alias = table.alias(&a, &k, reference, (ad, d), 100, T).unwrap();
    assert_eq!(
        table.observe(&k, FlowPacket::Udp, d, 200, T),
        Ok(FlowLookup::Tracked(reference))
    );
    assert!(!table.sweep_slot(reference.slot, 150, T).unwrap());
    assert!(!table.sweep_slot(alias.slot, 150, T).unwrap());
    assert_eq!(
        table.export(&k, reference, 150, T),
        Err(FlowTableError::Conflict)
    );
    assert!(table.export(&k, reference, 200, T).unwrap().is_some());
    // Creating an alias after a newer observation must also remain safe.
    table
        .alias(&key(3).0, &k, reference, (ad, d), 150, T)
        .unwrap();
    s.check_accounting();
}
#[test]
fn invalid_gc_configuration_cannot_purge_working_flows() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let reference = admit(&table, 1, 100).unwrap();
    let invalid = FlowTimeouts {
        udp_unreplied_ms: 0,
        ..T
    };
    assert_eq!(
        table.sweep_slot(reference.slot, 100, invalid),
        Err(FlowTableError::Invalid)
    );
    assert_eq!(
        table.export(&key(1).0, reference, 100, invalid),
        Err(FlowTableError::Invalid)
    );
    assert!(
        table
            .export(&key(1).0, reference, 100, T)
            .unwrap()
            .is_some()
    );
    s.check_accounting();
}

fn snapshot(
    table: &FirewallFlowTable<'_, Storage>,
    key: &FirewallFlowKey,
) -> crate::FirewallFlowRecord {
    let mut out = crate::FirewallFlowRecord::EMPTY;
    table.snapshot_into(key, &mut out).unwrap();
    out
}
fn imported_flow(incarnation: u64) -> FirewallFlow {
    FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 100, incarnation, T).unwrap()
}
#[test]
fn coherent_snapshot_and_revision_guard_prevent_stale_gc_and_import() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let (k, d) = key(1);
    let reference = admit(&table, 1, 100).unwrap();
    let before = snapshot(&table, &k);
    assert_eq!(before.revision, 1);
    assert_eq!(before.primary_revision, 1);
    assert_eq!(before.entry, reference);
    assert_eq!(before.primary_key, k);
    assert_eq!(before.primary, reference);
    assert_eq!(
        table.observe(&k, FlowPacket::Udp, d, 200, T),
        Ok(FlowLookup::Tracked(reference))
    );
    let current = snapshot(&table, &k);
    assert_eq!(current.revision, 2);
    assert_eq!(current.state.last_seen_ms, 200);
    assert_eq!(
        table.remove_snapshot(&before, false),
        Err(FlowTableError::Conflict)
    );
    assert_eq!(
        table.import_primary(&k, &before.state, Some(before.version()), 200),
        Err(FlowTableError::Conflict)
    );
    table.remove_snapshot(&current, false).unwrap();
    s.check_accounting();
}
#[test]
fn alias_gc_checks_primary_revision_but_explicit_revocation_can_remove_it() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let (p, d) = key(1);
    let (a, ad) = key(2);
    let reference = admit(&table, 1, 100).unwrap();
    table.alias(&a, &p, reference, (ad, d), 100, T).unwrap();
    let alias = snapshot(&table, &a);
    assert_eq!(alias.kind, crate::FlowRecordKind::ALIAS);
    assert_eq!(alias.primary, reference);
    assert_eq!(alias.primary_revision, 1);
    table.observe(&p, FlowPacket::Udp, d, 200, T).unwrap();
    assert_eq!(
        table.remove_snapshot(&alias, false),
        Err(FlowTableError::Conflict)
    );
    table.remove_snapshot(&alias, true).unwrap();
    assert!(snapshot(&table, &p).state.valid_for(ip_proto::UDP));
    s.check_accounting();
}
#[test]
fn orphan_snapshot_keeps_original_target_and_cannot_delete_rebound_alias() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let (p, d) = key(1);
    let (a, ad) = key(2);
    let reference = admit(&table, 1, 100).unwrap();
    table.alias(&a, &p, reference, (ad, d), 100, T).unwrap();
    table.retire(&p, reference).unwrap();
    let replacement = admit(&table, 1, 200).unwrap();
    let orphan = snapshot(&table, &a);
    assert_eq!(orphan.kind, crate::FlowRecordKind::ORPHAN_ALIAS);
    assert_eq!(orphan.primary_key, p);
    assert_eq!(orphan.primary, reference);
    assert_eq!(orphan.state, FirewallFlow::ZERO);
    table
        .import_alias(&orphan, replacement.incarnation, 200)
        .unwrap();
    assert_eq!(
        table.remove_snapshot(&orphan, false),
        Err(FlowTableError::Conflict)
    );
    assert_eq!(
        table.remove_snapshot(&orphan, true),
        Err(FlowTableError::Conflict)
    );
    let rebound = snapshot(&table, &a);
    assert_eq!(rebound.primary, replacement);
    assert_eq!(rebound.revision, orphan.revision + 1);
    s.check_accounting();
}
#[test]
fn imported_wire_identity_is_distinct_from_local_slot_identity_and_versions() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let (k, _) = key(1);
    let flow = imported_flow(42);
    let v = table.import_primary(&k, &flow, None, 100).unwrap();
    assert_ne!(v.entry.incarnation, flow.incarnation);
    assert_eq!(v.revision, 1);
    assert_eq!(
        table.import_primary(&k, &flow, None, 100),
        Err(FlowTableError::Conflict)
    );
    let before = snapshot(&table, &k);
    let next = table
        .import_primary(&k, &flow, Some(before.version()), 100)
        .unwrap();
    assert_eq!(next.entry, before.entry);
    assert_eq!(next.revision, 2);
    assert_eq!(
        table.import_primary(&k, &imported_flow(43), Some(next), 100),
        Err(FlowTableError::Conflict)
    );
    table.remove_snapshot(&snapshot(&table, &k), true).unwrap();
    let replacement = table
        .import_primary(&k, &imported_flow(43), None, 100)
        .unwrap();
    assert_ne!(replacement.entry.incarnation, v.entry.incarnation);
    assert_eq!(snapshot(&table, &k).state.incarnation, 43);
    s.check_accounting();
}
#[test]
fn imported_alias_requires_matching_primary_and_never_seeds_or_renews_state() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    let (p, _) = key(1);
    let (a, _) = key(2);
    let mut record = crate::FirewallFlowRecord {
        kind: crate::FlowRecordKind::ALIAS,
        key: a,
        primary_key: p,
        flip: 1,
        ..crate::FirewallFlowRecord::EMPTY
    };
    assert_eq!(
        table.import_alias(&record, 42, 100),
        Err(FlowTableError::Missing)
    );
    table
        .import_primary(&p, &imported_flow(42), None, 100)
        .unwrap();
    assert_eq!(
        table.import_alias(&record, 43, 100),
        Err(FlowTableError::Conflict)
    );
    table.import_alias(&record, 42, 100).unwrap();
    let before = snapshot(&table, &p);
    assert_eq!(snapshot(&table, &a).flip, 1);
    assert_eq!(
        table.import_alias(&record, 42, 100),
        Err(FlowTableError::Conflict)
    );
    record = snapshot(&table, &a);
    record.flip = 0;
    table.import_alias(&record, 42, 100).unwrap();
    assert_eq!(snapshot(&table, &p), before);
    assert_eq!(snapshot(&table, &a).revision, 2);
    s.check_accounting();
}
#[test]
fn ordered_alias_snapshot_lock_failure_preserves_other_owner() {
    let s = Storage::new(3);
    let table = FirewallFlowTable::new(&s);
    let filler = admit(&table, 99, 100).unwrap();
    let (p, d) = key(1);
    let (a, ad) = key(2);
    let primary = admit(&table, 1, 100).unwrap();
    table.retire(&key(99).0, filler).unwrap();
    let alias = table.alias(&a, &p, primary, (ad, d), 100, T).unwrap();
    assert!(alias.slot < primary.slot);
    let held = s.slots[primary.slot as usize].lock().unwrap();
    let mut output = crate::FirewallFlowRecord::EMPTY;
    assert_eq!(
        table.snapshot_into(&a, &mut output),
        Err(FlowTableError::Busy)
    );
    assert_eq!(
        s.slots[primary.slot as usize].busy.load(Ordering::Relaxed),
        1
    );
    assert_eq!(s.slots[alias.slot as usize].busy.load(Ordering::Relaxed), 0);
    drop(held);
    assert_eq!(snapshot(&table, &a).primary, primary);
    s.check_accounting();
}
#[test]
fn revision_exhaustion_fails_closed_without_wrap_and_revocation_still_works() {
    let s = Storage::new(1);
    let table = FirewallFlowTable::new(&s);
    let (k, d) = key(1);
    let reference = admit(&table, 1, 100).unwrap();
    s.slots[reference.slot as usize].lock().unwrap().revision = u64::MAX;
    let before = snapshot(&table, &k);
    assert_eq!(
        table.observe(&k, FlowPacket::Udp, d, 200, T),
        Err(FlowTableError::Exhausted)
    );
    assert_eq!(
        table.import_primary(&k, &before.state, Some(before.version()), 200),
        Err(FlowTableError::Exhausted)
    );
    assert_eq!(snapshot(&table, &k), before);
    table.remove_snapshot(&before, true).unwrap();
    s.check_accounting();
}
#[test]
fn concurrent_snapshots_and_packet_updates_keep_coherent_state_and_exact_revision() {
    use std::sync::atomic::AtomicU64;
    let s = Arc::new(Storage::new(1));
    let table = FirewallFlowTable::new(&*s);
    let (k, d) = key(1);
    admit(&table, 1, 100).unwrap();
    let changed = Arc::new(AtomicU64::new(0));
    let gate = Arc::new(Barrier::new(5));
    let writers: Vec<_> = (0..4)
        .map(|_| {
            let s = s.clone();
            let changed = changed.clone();
            let gate = gate.clone();
            thread::spawn(move || {
                let table = FirewallFlowTable::new(&*s);
                gate.wait();
                for tick in 101..1101 {
                    match table.observe(&k, FlowPacket::Udp, d, tick, T) {
                        Ok(FlowLookup::Tracked(_)) => {
                            changed.fetch_add(1, StdOrdering::Relaxed);
                        }
                        Err(FlowTableError::Busy) => {}
                        result => panic!("{result:?}"),
                    }
                }
            })
        })
        .collect();
    gate.wait();
    let mut captured = 0;
    for _ in 0..1000 {
        let mut record = crate::FirewallFlowRecord::EMPTY;
        match table.snapshot_into(&k, &mut record) {
            Ok(()) => {
                assert!(record.state.valid_for(ip_proto::UDP));
                assert_eq!(record.revision, record.primary_revision);
                assert_eq!(record.entry, record.primary);
                captured += 1;
            }
            Err(FlowTableError::Busy) => {}
            result => panic!("{result:?}"),
        }
    }
    for writer in writers {
        writer.join().unwrap();
    }
    assert!(captured > 0);
    let final_record = snapshot(&table, &k);
    assert_eq!(
        final_record.revision,
        1 + changed.load(StdOrdering::Relaxed)
    );
    s.check_accounting();
}

#[test]
fn allocator_high_water_is_bounded_monotonic_and_lock_safe() {
    let s = Storage::new(2);
    let table = FirewallFlowTable::new(&s);
    assert_eq!(table.allocated_slots(), Ok(0));
    let first = admit(&table, 1, 100).unwrap();
    assert_eq!(table.allocated_slots(), Ok(1));
    table.retire(&key(1).0, first).unwrap();
    admit(&table, 2, 100).unwrap();
    assert_eq!(table.allocated_slots(), Ok(1));
    admit(&table, 3, 100).unwrap();
    assert_eq!(table.allocated_slots(), Ok(2));
    {
        let mut guard = s.allocator.lock().unwrap();
        assert_eq!(table.allocated_slots(), Err(FlowTableError::Busy));
        assert_eq!(s.allocator.busy.load(Ordering::Relaxed), 1);
        guard.next_unused = 3;
    }
    assert_eq!(table.allocated_slots(), Err(FlowTableError::Corrupt));
    s.allocator.lock().unwrap().next_unused = 2;
    s.check_accounting();
}

#[test]
fn scoped_observation_uses_locked_primary_authority_and_cannot_renew_removed_scopes() {
    let s = Storage::new(3);
    let table = FirewallFlowTable::new(&s);
    let (k, d) = key(1);
    let (mut a, ad) = key(2);
    a.scope.identity += 1;
    let reference = admit(&table, 1, 100).unwrap();
    table.alias(&a, &k, reference, (ad, d), 100, T).unwrap();
    let short = FlowTimeouts {
        udp_unreplied_ms: 100,
        ..T
    };
    let mut resolved = None;
    assert_eq!(
        table.observe_scoped(&a, FlowPacket::Udp, ad, 201, |scope| {
            resolved = Some(*scope);
            Some(short)
        }),
        Ok(FlowLookup::PolicyRequired(s.index(&a).unwrap()))
    );
    assert_eq!(resolved, Some(k.scope));
    // Missing authority fails before touching timestamps or protocol state.
    let mut before = crate::FirewallFlowRecord::EMPTY;
    table.snapshot_into(&k, &mut before).unwrap();
    assert_eq!(
        table.observe_scoped(&a, FlowPacket::Udp, ad, 150, |_| None),
        Err(FlowTableError::Missing)
    );
    assert_eq!(
        table.admit_scoped(&a, FlowPacket::Udp, ad, 150, T, |_| None),
        Err(FlowTableError::Missing)
    );
    let mut after = crate::FirewallFlowRecord::EMPTY;
    table.snapshot_into(&k, &mut after).unwrap();
    assert_eq!(before.revision, after.revision);
    assert_eq!(before.state, after.state);
    // Even when the alias zone allows longer timeouts, duplicate admission
    // observes the existing primary using its own, shorter timeout policy.
    assert!(
        table
            .admit_scoped(&a, FlowPacket::Udp, ad, 201, T, |scope| {
                assert_eq!(*scope, k.scope);
                Some(short)
            })
            .is_ok()
    );
    s.check_accounting();
}
