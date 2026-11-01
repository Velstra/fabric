//! Bounded, stable-address storage for firewall protocol state.
//!
//! Hash maps contain index records only. An index read is never permission:
//! the complete source key and globally unique local incarnation are checked
//! under the stable slot's lock. Reused hash element addresses are harmless.
//! A slot is published with NOEXIST, removed by its owner, then reclaimed.
//! No userspace writer may overwrite these arrays while packet hooks run.

use core::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicU32, Ordering},
};

use crate::{
    FirewallFlow, FirewallFlowKey, FirewallFlowTransfer, FlowDirection, FlowObservation,
    FlowPacket, FlowTimeouts,
};

// Free links encode index + 1; zero-filled Linux Array maps match empty().
const NONE: u32 = 0;
const VACANT: u32 = 0;
const RESERVED: u32 = 1;
const PRIMARY: u32 = 2;
const ALIAS: u32 = 3;
const RETIRED: u32 = 4;
const ATTEMPTS: usize = 8;

/// Local index token. Incarnations are never reused, even across different slots.
/// It is safe to copy a possibly concurrently replaced index only because the
/// slot validates both fields, its full key, and its publication state.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallFlowRef {
    pub slot: u32,
    pub _pad: u32,
    pub incarnation: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct AliasTarget {
    primary: FirewallFlowRef,
    key: FirewallFlowKey,
    flip: u32,
    _pad: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
union Value {
    flow: FirewallFlow,
    alias: AliasTarget,
    bytes: [u8; 80],
}
#[repr(C)]
struct SlotData {
    state: u32,
    _pad: u32,
    incarnation: u64,
    revision: u64,
    key: FirewallFlowKey,
    value: Value,
}

/// Stable Array element. Never place this type in a HashMap or LRU map.
#[repr(C)]
pub struct FirewallFlowSlot {
    busy: AtomicU32,
    // Only accessed with the allocator lock. Separate from protocol data so a
    // free-list read never creates an aliasing reference to live flow state.
    next_free: UnsafeCell<u32>,
    data: UnsafeCell<SlotData>,
}
// All data accesses use either the slot lock or (for next_free) allocator lock.
unsafe impl Sync for FirewallFlowSlot {}
impl FirewallFlowSlot {
    pub const fn empty() -> Self {
        Self {
            busy: AtomicU32::new(0),
            next_free: UnsafeCell::new(NONE),
            data: UnsafeCell::new(SlotData {
                state: VACANT,
                _pad: 0,
                incarnation: 0,
                revision: 0,
                key: FirewallFlowKey {
                    scope: crate::FlowScope {
                        identity: 0,
                        generation: 0,
                    },
                    low_addr: [0; 16],
                    high_addr: [0; 16],
                    low_port: 0,
                    high_port: 0,
                    protocol: 0,
                    family: 0,
                    query_type: 0,
                    _pad: 0,
                },
                value: Value { bytes: [0; 80] },
            }),
        }
    }
    #[inline(always)]
    fn lock(&self) -> Option<SlotGuard<'_>> {
        acquire(&self.busy).then(|| SlotGuard { slot: self })
    }
}
struct SlotGuard<'a> {
    slot: &'a FirewallFlowSlot,
}
impl Deref for SlotGuard<'_> {
    type Target = SlotData;
    #[inline(always)]
    fn deref(&self) -> &SlotData {
        unsafe { &*self.slot.data.get() }
    }
}
impl DerefMut for SlotGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut SlotData {
        unsafe { &mut *self.slot.data.get() }
    }
}
impl Drop for SlotGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.slot.busy.swap(0, Ordering::Release);
    }
}

#[repr(C)]
struct AllocatorData {
    next_unused: u32,
    free_head: u32,
    incarnation: u64,
}
/// A single Array element, initialized once before hooks are attached. The
/// unused tail makes the initial free list O(1), without a userspace fill loop.
#[repr(C)]
pub struct FirewallFlowAllocator {
    busy: AtomicU32,
    _pad: u32,
    data: UnsafeCell<AllocatorData>,
}
unsafe impl Sync for FirewallFlowAllocator {}
impl FirewallFlowAllocator {
    pub const fn empty() -> Self {
        Self {
            busy: AtomicU32::new(0),
            _pad: 0,
            data: UnsafeCell::new(AllocatorData {
                next_unused: 0,
                free_head: NONE,
                incarnation: 0,
            }),
        }
    }
    #[inline(always)]
    fn lock(&self) -> Option<AllocatorGuard<'_>> {
        acquire(&self.busy).then(|| AllocatorGuard { allocator: self })
    }
}
struct AllocatorGuard<'a> {
    allocator: &'a FirewallFlowAllocator,
}
impl Deref for AllocatorGuard<'_> {
    type Target = AllocatorData;
    #[inline(always)]
    fn deref(&self) -> &AllocatorData {
        unsafe { &*self.allocator.data.get() }
    }
}
impl DerefMut for AllocatorGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut AllocatorData {
        unsafe { &mut *self.allocator.data.get() }
    }
}
impl Drop for AllocatorGuard<'_> {
    #[inline(always)]
    fn drop(&mut self) {
        self.allocator.busy.swap(0, Ordering::Release);
    }
}
#[inline(always)]
fn acquire(lock: &AtomicU32) -> bool {
    for _ in 0..ATTEMPTS {
        if lock
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowTableError {
    Busy,
    Full,
    Exhausted,
    Corrupt,
    Storage,
    Conflict,
    Missing,
    Invalid,
}

/// Storage contract used by the actual BPF Array/HashMap adapter and host tests.
///
/// # Safety
/// Slots and allocator must retain their addresses and exclusive initialization
/// for the entire lifetime of this storage, including concurrent calls. Never
/// expose mutable references or raw multi-field userspace updates to them.
/// Index insertion must use NOEXIST; errors must leave the index unchanged.
/// Removal must be reliable and only invoked
/// by this table. Different storage views of one table must share all three
/// maps and the same capacity. A controller may inspect coherent exports only.
pub unsafe trait FirewallFlowStorage {
    fn capacity(&self) -> u32;
    fn allocator(&self) -> Option<&FirewallFlowAllocator>;
    fn slot(&self, index: u32) -> Option<&FirewallFlowSlot>;
    fn index(&self, key: &FirewallFlowKey) -> Option<FirewallFlowRef>;
    /// Return false for an existing key, never overwrite it.
    fn insert(&self, key: &FirewallFlowKey, value: FirewallFlowRef)
    -> Result<bool, FlowTableError>;
    fn remove(&self, key: &FirewallFlowKey) -> Result<(), FlowTableError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowLookup {
    Missing,
    Tracked(FirewallFlowRef),
    Unchanged(FirewallFlowRef),
    PolicyRequired(FirewallFlowRef),
    Invalid,
}

pub struct FirewallFlowTable<'a, S: FirewallFlowStorage> {
    storage: &'a S,
}
impl<'a, S: FirewallFlowStorage> FirewallFlowTable<'a, S> {
    pub const fn new(storage: &'a S) -> Self {
        Self { storage }
    }

    /// The initialized prefix is monotonic. Readers may skip the unused tail,
    /// but must still inspect holes and retired slots in this prefix.
    #[inline(always)]
    pub fn allocated_slots(&self) -> Result<u32, FlowTableError> {
        let guard = self
            .storage
            .allocator()
            .ok_or(FlowTableError::Corrupt)?
            .lock()
            .ok_or(FlowTableError::Busy)?;
        if guard.next_unused > self.storage.capacity() {
            return Err(FlowTableError::Corrupt);
        }
        Ok(guard.next_unused)
    }

    #[inline(always)]
    fn owned(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
    ) -> Result<SlotGuard<'a>, FlowTableError> {
        let slot = self
            .storage
            .slot(reference.slot)
            .ok_or(FlowTableError::Corrupt)?;
        let guard = slot.lock().ok_or(FlowTableError::Busy)?;
        if guard.incarnation != reference.incarnation
            || reference.incarnation == 0
            || !same_key(&guard.key, key)
            || (guard.state != PRIMARY && guard.state != ALIAS)
        {
            return Err(FlowTableError::Conflict);
        }
        Ok(guard)
    }

    /// Resolve alias once, then validate the target incarnation under its own
    /// lock. An alias can never point to an alias or grant an independent TTL.
    #[inline(always)]
    fn primary(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
        direction: FlowDirection,
    ) -> Result<(SlotGuard<'a>, FirewallFlowRef, FlowDirection), FlowTableError> {
        let guard = self.owned(key, reference)?;
        if guard.state == PRIMARY {
            return Ok((guard, reference, direction));
        }
        let (target, flip) = unsafe { (guard.value.alias.primary, guard.value.alias.flip) };
        drop(guard);
        if flip > 1 || target.incarnation == 0 {
            return Err(FlowTableError::Corrupt);
        }
        let slot = self
            .storage
            .slot(target.slot)
            .ok_or(FlowTableError::Corrupt)?;
        let guard = slot.lock().ok_or(FlowTableError::Busy)?;
        // A local incarnation is never reused in ANY slot. The bound target
        // key is immutable for that incarnation; no large metadata copy needed.
        if guard.state != PRIMARY || guard.incarnation != target.incarnation {
            return Err(FlowTableError::Conflict);
        }
        let direction = if direction.index() as u32 ^ flip == 0 {
            FlowDirection::Forward
        } else {
            FlowDirection::Reverse
        };
        Ok((guard, target, direction))
    }

    #[inline(always)]
    pub fn observe(
        &self,
        key: &FirewallFlowKey,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Result<FlowLookup, FlowTableError> {
        self.observe_scoped(key, packet, direction, now_ms, |_| Some(timeouts))
    }

    /// Resolve the primary's timeout authority while holding its slot lock.
    /// An alias's zone must never supply a longer lifetime for another zone's
    /// flow, and a removed primary scope cannot retain return permission.
    #[inline(always)]
    pub fn observe_scoped(
        &self,
        key: &FirewallFlowKey,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        timeouts: impl FnOnce(&crate::FlowScope) -> Option<FlowTimeouts>,
    ) -> Result<FlowLookup, FlowTableError> {
        let Some(reference) = self.storage.index(key) else {
            return Ok(FlowLookup::Missing);
        };
        let (mut guard, primary, direction) = self.primary(key, reference, direction)?;
        let timeouts = timeouts(&guard.key.scope).ok_or(FlowTableError::Missing)?;
        if !timeouts.valid() {
            return Err(FlowTableError::Invalid);
        }
        let revision = guard
            .revision
            .checked_add(1)
            .ok_or(FlowTableError::Exhausted)?;
        let proto = guard.key.protocol;
        let flow = unsafe { &mut guard.value.flow };
        Ok(
            match flow.observe(proto, packet, direction, now_ms, timeouts) {
                FlowObservation::Tracked => {
                    guard.revision = revision;
                    FlowLookup::Tracked(primary)
                }
                FlowObservation::Unchanged => FlowLookup::Unchanged(primary),
                FlowObservation::PolicyRequired => FlowLookup::PolicyRequired(reference),
                FlowObservation::Invalid => FlowLookup::Invalid,
            },
        )
    }

    /// Call only after an explicit policy admission, never just on index miss.
    /// Existing usable state is preserved (including concurrent duplicate SYN).
    /// An opener requiring new admission retires the old local key first, so
    /// translation aliases referring to its old incarnation cannot grant it.
    #[inline(always)]
    pub fn admit(
        &self,
        key: &FirewallFlowKey,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Result<FirewallFlowRef, FlowTableError> {
        self.admit_scoped(key, packet, direction, now_ms, timeouts, |_| Some(timeouts))
    }

    /// Admission uses this key's policy for new state and the primary's policy
    /// for any concurrently existing state (including translation aliases).
    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    pub fn admit_scoped(
        &self,
        key: &FirewallFlowKey,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        timeouts: FlowTimeouts,
        primary_timeouts: impl FnOnce(&crate::FlowScope) -> Option<FlowTimeouts>,
    ) -> Result<FirewallFlowRef, FlowTableError> {
        // Validate without keeping an80-byte initial state alive across the
        // existing-flow lookup. Invalid openers may not retire working state.
        if !key.valid() || !timeouts.valid() || !packet.eligible_opener(key.protocol) {
            return Err(FlowTableError::Invalid);
        }
        match self.observe_scoped(key, packet, direction, now_ms, primary_timeouts)? {
            FlowLookup::Tracked(reference) | FlowLookup::Unchanged(reference) => {
                return Ok(reference);
            }
            FlowLookup::Invalid => return Err(FlowTableError::Invalid),
            FlowLookup::Missing => {}
            FlowLookup::PolicyRequired(reference) => {
                self.retire(key, reference)?;
            }
        }
        let (reference, mut slot) = self.reserve()?;
        slot.key = *key;
        if !unsafe { &mut slot.value.flow }.begin_into(
            packet,
            direction,
            now_ms,
            reference.incarnation,
            timeouts,
        ) {
            slot.state = RETIRED;
            drop(slot);
            let _ = self.reclaim(reference.slot);
            return Err(FlowTableError::Invalid);
        }
        slot.state = PRIMARY;
        self.publish(key, reference, slot)
    }

    /// Copy protocol and alias metadata while all relevant stable slots are
    /// locked. The caller owns output and must not serialize local timestamps
    /// onto a network link. Alias snapshots include the target's revision.
    #[inline(always)]
    pub fn snapshot_into(
        &self,
        key: &FirewallFlowKey,
        out: &mut crate::FirewallFlowRecord,
    ) -> Result<(), FlowTableError> {
        let reference = self.storage.index(key).ok_or(FlowTableError::Missing)?;
        self.snapshot_reference_into(key, reference, out)
    }

    #[inline(always)]
    pub fn snapshot_slot_into(
        &self,
        index: u32,
        out: &mut crate::FirewallFlowRecord,
    ) -> Result<(), FlowTableError> {
        let node = self.storage.slot(index).ok_or(FlowTableError::Invalid)?;
        let guard = node.lock().ok_or(FlowTableError::Busy)?;
        if guard.state == VACANT || guard.state == RETIRED {
            return Err(FlowTableError::Missing);
        }
        if guard.state != PRIMARY && guard.state != ALIAS {
            return Err(FlowTableError::Corrupt);
        }
        let reference = FirewallFlowRef {
            slot: index,
            _pad: 0,
            incarnation: guard.incarnation,
        };
        self.snapshot_guard_into(guard, reference, out)
    }

    #[inline(always)]
    fn snapshot_reference_into(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
        out: &mut crate::FirewallFlowRecord,
    ) -> Result<(), FlowTableError> {
        let guard = self.owned(key, reference)?;
        self.snapshot_guard_into(guard, reference, out)
    }

    #[inline(always)]
    fn snapshot_guard_into(
        &self,
        guard: SlotGuard<'a>,
        reference: FirewallFlowRef,
        out: &mut crate::FirewallFlowRecord,
    ) -> Result<(), FlowTableError> {
        use crate::FlowRecordKind as K;
        out.key = guard.key;
        out.entry = reference;
        out.revision = guard.revision;
        out.reserved = 0;
        if guard.state == PRIMARY {
            if !unsafe { guard.value.flow.valid_for(out.key.protocol) } {
                return Err(FlowTableError::Corrupt);
            }
            out.kind = K::PRIMARY;
            out.flip = 0;
            out.primary_key = out.key;
            out.primary = reference;
            out.primary_revision = guard.revision;
            out.state = unsafe { guard.value.flow };
            return Ok(());
        }
        out.kind = K::ORPHAN_ALIAS;
        out.primary_revision = 0;
        out.state = FirewallFlow::ZERO;
        unsafe {
            out.primary = guard.value.alias.primary;
            out.primary_key = guard.value.alias.key;
            out.flip = guard.value.alias.flip;
        }
        drop(guard);
        let (_alias, primary) = self.alias_pair(out)?;
        let live = primary.state == PRIMARY
            && primary.incarnation == out.primary.incarnation
            && same_key(&primary.key, &out.primary_key);
        if live {
            if !unsafe { primary.value.flow.valid_for(out.primary_key.protocol) } {
                return Err(FlowTableError::Corrupt);
            }
            out.kind = K::ALIAS;
            out.primary_revision = primary.revision;
            out.state = unsafe { primary.value.flow };
        }
        Ok(())
    }

    /// Ordered locks plus revalidation of metadata staged in the caller's
    /// snapshot/control buffer, avoiding a large on-stack alias copy.
    #[inline(always)]
    fn alias_pair(
        &self,
        expected: &crate::FirewallFlowRecord,
    ) -> Result<(SlotGuard<'a>, SlotGuard<'a>), FlowTableError> {
        if expected.entry.slot == expected.primary.slot || expected.flip > 1 {
            return Err(FlowTableError::Corrupt);
        }
        let a = self
            .storage
            .slot(expected.entry.slot)
            .ok_or(FlowTableError::Corrupt)?;
        let p = self
            .storage
            .slot(expected.primary.slot)
            .ok_or(FlowTableError::Corrupt)?;
        let (alias, primary) = if expected.entry.slot < expected.primary.slot {
            let alias = a.lock().ok_or(FlowTableError::Busy)?;
            let primary = p.lock().ok_or(FlowTableError::Busy)?;
            (alias, primary)
        } else {
            let primary = p.lock().ok_or(FlowTableError::Busy)?;
            let alias = a.lock().ok_or(FlowTableError::Busy)?;
            (alias, primary)
        };
        if alias.state != ALIAS
            || alias.incarnation != expected.entry.incarnation
            || alias.revision != expected.revision
            || !same_key(&alias.key, &expected.key)
        {
            return Err(FlowTableError::Conflict);
        }
        let actual = unsafe { &alias.value.alias };
        if actual.primary != expected.primary
            || actual.flip != expected.flip
            || !same_key(&actual.key, &expected.primary_key)
        {
            return Err(FlowTableError::Conflict);
        }
        Ok((alias, primary))
    }

    /// Conditional GC removal protects a newer packet update in either the
    /// primary or an alias target. Explicit revocation checks the entry version
    /// only, because the current policy requires the grant to be removed.
    #[inline(always)]
    pub fn remove_snapshot(
        &self,
        expected: &crate::FirewallFlowRecord,
        explicit: bool,
    ) -> Result<(), FlowTableError> {
        use crate::FlowRecordKind as K;
        if expected.revision == 0 || expected.entry._pad != 0 || expected.reserved != 0 {
            return Err(FlowTableError::Invalid);
        }
        let mut guard = self.owned(&expected.key, expected.entry)?;
        if guard.revision != expected.revision {
            return Err(FlowTableError::Conflict);
        }
        if guard.state == PRIMARY {
            if expected.kind != K::PRIMARY {
                return Err(FlowTableError::Conflict);
            }
        } else {
            drop(guard);
            let (alias, primary) = self.alias_pair(expected)?;
            guard = alias;
            if !explicit {
                let live = primary.state == PRIMARY
                    && primary.incarnation == expected.primary.incarnation
                    && same_key(&primary.key, &expected.primary_key);
                let matches = if expected.kind == K::ALIAS {
                    live && primary.revision == expected.primary_revision
                } else if expected.kind == K::ORPHAN_ALIAS {
                    !live
                } else {
                    false
                };
                if !matches {
                    return Err(FlowTableError::Conflict);
                }
            }
            // Keep the primary lock through index removal, so its revision
            // cannot change after the conditional check.
            self.storage.remove(&expected.key)?;
            guard.state = RETIRED;
            drop(primary);
            drop(guard);
            let _ = self.reclaim(expected.entry.slot);
            return Ok(());
        }
        self.storage.remove(&expected.key)?;
        guard.state = RETIRED;
        drop(guard);
        let _ = self.reclaim(expected.entry.slot);
        Ok(())
    }

    /// Import a validated LOCAL-clock state. The userspace controller must
    /// validate and sequence peer messages, derive state with FirewallFlow::import
    /// and current canonical timeouts, then pass the expected local version.
    /// Different wire incarnations require an explicit conditional revocation
    /// followed by creation; aliases may never inherit a replacement session.
    #[inline(always)]
    pub fn import_primary(
        &self,
        key: &FirewallFlowKey,
        flow: &FirewallFlow,
        expected: Option<crate::FlowVersion>,
        now_ms: u64,
    ) -> Result<crate::FlowVersion, FlowTableError> {
        if !key.valid()
            || !flow.valid_for(key.protocol)
            || flow.last_seen_ms > now_ms
            || flow.expires_at_ms <= now_ms
        {
            return Err(FlowTableError::Invalid);
        }
        if let Some(expected) = expected {
            let mut guard = self.owned(key, expected.entry)?;
            if expected.revision == 0
                || guard.state != PRIMARY
                || guard.revision != expected.revision
                || unsafe { guard.value.flow.incarnation } != flow.incarnation
            {
                return Err(FlowTableError::Conflict);
            }
            let revision = guard
                .revision
                .checked_add(1)
                .ok_or(FlowTableError::Exhausted)?;
            guard.value.flow = *flow;
            guard.revision = revision;
            return Ok(crate::FlowVersion {
                entry: expected.entry,
                revision,
            });
        }
        if self.storage.index(key).is_some() {
            return Err(FlowTableError::Conflict);
        }
        let (reference, mut guard) = self.reserve()?;
        guard.key = *key;
        guard.value.flow = *flow;
        guard.state = PRIMARY;
        self.publish(key, reference, guard)?;
        Ok(crate::FlowVersion {
            entry: reference,
            revision: 1,
        })
    }

    /// Bind a peer alias to a locally resolved primary with the SAME wire
    /// incarnation. No alias can seed state or refresh a primary's lifetime.
    #[inline(always)]
    pub fn import_alias(
        &self,
        record: &crate::FirewallFlowRecord,
        wire_incarnation: u64,
        now_ms: u64,
    ) -> Result<crate::FlowVersion, FlowTableError> {
        if !record.key.valid()
            || !record.primary_key.valid()
            || record.flip > 1
            || record.key.protocol != record.primary_key.protocol
            || wire_incarnation == 0
        {
            return Err(FlowTableError::Invalid);
        }
        let reference = self
            .storage
            .index(&record.primary_key)
            .ok_or(FlowTableError::Missing)?;
        {
            let guard = self.owned(&record.primary_key, reference)?;
            if guard.state != PRIMARY
                || unsafe { guard.value.flow.incarnation } != wire_incarnation
                || unsafe { guard.value.flow.expires_at_ms } <= now_ms
            {
                return Err(FlowTableError::Conflict);
            }
        }
        if record.entry.incarnation != 0 {
            let mut guard = self.owned(&record.key, record.entry)?;
            if guard.state != ALIAS || record.revision == 0 || guard.revision != record.revision {
                return Err(FlowTableError::Conflict);
            }
            let revision = guard
                .revision
                .checked_add(1)
                .ok_or(FlowTableError::Exhausted)?;
            unsafe {
                let target = &mut guard.value.alias;
                target.primary = reference;
                target.key = record.primary_key;
                target.flip = record.flip;
                target._pad = 0;
            }
            guard.revision = revision;
            return Ok(crate::FlowVersion {
                entry: record.entry,
                revision,
            });
        }
        if record.revision != 0 {
            return Err(FlowTableError::Invalid);
        }
        if self.storage.index(&record.key).is_some() {
            return Err(FlowTableError::Conflict);
        }
        let (alias, mut guard) = self.reserve()?;
        guard.key = record.key;
        unsafe {
            let target = &mut guard.value.alias;
            target.primary = reference;
            target.key = record.primary_key;
            target.flip = record.flip;
            target._pad = 0;
        }
        guard.state = ALIAS;
        self.publish(&record.key, alias, guard)?;
        Ok(crate::FlowVersion {
            entry: alias,
            revision: 1,
        })
    }

    /// Retry reclamation of unpublished/retired entries without interpreting a
    /// potentially reused slot's active lifetime under another policy's config.
    #[inline(always)]
    pub fn reclaim_retired(&self, index: u32) -> Result<bool, FlowTableError> {
        self.reclaim(index)
    }

    #[inline(always)]
    fn reserve(&self) -> Result<(FirewallFlowRef, SlotGuard<'a>), FlowTableError> {
        // Consistent lock order: allocator -> slot. Packet observations never
        // acquire allocator while holding a slot. Reclamation is a second step.
        let mut allocator = self
            .storage
            .allocator()
            .ok_or(FlowTableError::Corrupt)?
            .lock()
            .ok_or(FlowTableError::Busy)?;
        let from_free = allocator.free_head != NONE;
        let index = if from_free {
            allocator.free_head - 1
        } else {
            allocator.next_unused
        };
        if index >= self.storage.capacity() {
            return Err(if from_free {
                FlowTableError::Corrupt
            } else {
                FlowTableError::Full
            });
        }
        let node = self.storage.slot(index).ok_or(FlowTableError::Corrupt)?;
        let mut slot = node.lock().ok_or(FlowTableError::Busy)?;
        if slot.state != VACANT {
            return Err(FlowTableError::Corrupt);
        }
        let incarnation = allocator
            .incarnation
            .checked_add(1)
            .ok_or(FlowTableError::Exhausted)?;
        if from_free {
            allocator.free_head = unsafe { *node.next_free.get() };
        } else {
            allocator.next_unused += 1;
        }
        allocator.incarnation = incarnation;
        slot.incarnation = incarnation;
        slot.revision = 1;
        slot.state = RESERVED;
        Ok((
            FirewallFlowRef {
                slot: index,
                _pad: 0,
                incarnation,
            },
            slot,
        ))
    }

    #[inline(always)]
    fn publish(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
        mut slot: SlotGuard<'a>,
    ) -> Result<FirewallFlowRef, FlowTableError> {
        let inserted = self.storage.insert(key, reference);
        if inserted == Ok(true) {
            return Ok(reference);
        }
        slot.state = RETIRED;
        drop(slot);
        // If contended this remains RETIRED; sweep_slot retries reclamation.
        let _ = self.reclaim(reference.slot);
        match inserted {
            Ok(false) => Err(FlowTableError::Conflict),
            Err(error) => Err(error),
            Ok(true) => Err(FlowTableError::Conflict),
        }
    }

    /// Install an alias only while its primary is alive. Target revalidation on
    /// every lookup prevents grants after concurrent retirement/replacement.
    #[inline(always)]
    pub fn alias(
        &self,
        key: &FirewallFlowKey,
        primary_key: &FirewallFlowKey,
        reference: FirewallFlowRef,
        directions: (FlowDirection, FlowDirection),
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Result<FirewallFlowRef, FlowTableError> {
        {
            let guard = self.owned(primary_key, reference)?;
            if guard.state != PRIMARY
                || !key.valid()
                || key.protocol != primary_key.protocol
                || unsafe {
                    guard.value.flow.export(
                        primary_key.protocol,
                        now_ms.max(guard.value.flow.last_seen_ms),
                        timeouts,
                    )
                }
                .is_none()
            {
                return Err(FlowTableError::Invalid);
            }
        }
        let (alias_ref, mut slot) = self.reserve()?;
        slot.key = *key;
        slot.value.alias = AliasTarget {
            primary: reference,
            key: *primary_key,
            flip: (directions.0 != directions.1) as u32,
            _pad: 0,
        };
        slot.state = ALIAS;
        self.publish(key, alias_ref, slot)
    }

    /// Coherent, relative-time snapshot, never a raw concurrent map-value dump.
    #[inline(always)]
    pub fn export(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Result<Option<FirewallFlowTransfer>, FlowTableError> {
        if !timeouts.valid() {
            return Err(FlowTableError::Invalid);
        }
        let guard = self.owned(key, reference)?;
        if guard.state != PRIMARY {
            return Err(FlowTableError::Invalid);
        }
        let flow = unsafe { &guard.value.flow };
        if now_ms < flow.last_seen_ms {
            return Err(FlowTableError::Conflict);
        }
        Ok(flow.export(key.protocol, now_ms, timeouts))
    }

    #[inline(always)]
    pub fn retire(
        &self,
        key: &FirewallFlowKey,
        reference: FirewallFlowRef,
    ) -> Result<(), FlowTableError> {
        let mut guard = self.owned(key, reference)?;
        self.storage.remove(key)?;
        guard.state = RETIRED;
        drop(guard);
        // Retirement is complete even if reclamation needs a later GC pass.
        let _ = self.reclaim(reference.slot);
        Ok(())
    }

    #[inline(always)]
    fn reclaim(&self, index: u32) -> Result<bool, FlowTableError> {
        let mut allocator = self
            .storage
            .allocator()
            .ok_or(FlowTableError::Corrupt)?
            .lock()
            .ok_or(FlowTableError::Busy)?;
        let node = self.storage.slot(index).ok_or(FlowTableError::Corrupt)?;
        let mut guard = node.lock().ok_or(FlowTableError::Busy)?;
        if guard.state != RETIRED {
            return Ok(false);
        }
        unsafe {
            *node.next_free.get() = allocator.free_head;
        }
        guard.state = VACANT;
        allocator.free_head = index + 1;
        Ok(true)
    }

    /// Sweep one deterministically chosen slot. Caller cycles through the whole
    /// capacity with a bounded budget; it must supply current policy timeouts.
    /// Returning false means no change; contention/error is explicit and retried.
    #[inline(always)]
    pub fn sweep_slot(
        &self,
        index: u32,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Result<bool, FlowTableError> {
        if !timeouts.valid() {
            return Err(FlowTableError::Invalid);
        }
        let node = self.storage.slot(index).ok_or(FlowTableError::Corrupt)?;
        let guard = node.lock().ok_or(FlowTableError::Busy)?;
        if guard.state == RETIRED {
            drop(guard);
            return self.reclaim(index);
        }
        if guard.state == VACANT {
            return Ok(false);
        }
        let key = guard.key;
        let reference = FirewallFlowRef {
            slot: index,
            _pad: 0,
            incarnation: guard.incarnation,
        };
        let expired = if guard.state == PRIMARY {
            let flow = unsafe { &guard.value.flow };
            if now_ms < flow.last_seen_ms {
                return Ok(false);
            }
            flow.export(key.protocol, now_ms, timeouts).is_none()
        } else if guard.state == ALIAS {
            let target = unsafe { guard.value.alias };
            drop(guard);
            let node = self
                .storage
                .slot(target.primary.slot)
                .ok_or(FlowTableError::Corrupt)?;
            let guard = node.lock().ok_or(FlowTableError::Busy)?;
            let expired =
                if guard.state != PRIMARY || guard.incarnation != target.primary.incarnation {
                    true
                } else {
                    let flow = unsafe { &guard.value.flow };
                    if now_ms < flow.last_seen_ms {
                        return Ok(false);
                    }
                    flow.export(guard.key.protocol, now_ms, timeouts).is_none()
                };
            drop(guard);
            if expired {
                self.retire(&key, reference)?;
            }
            return Ok(expired);
        } else {
            return Err(FlowTableError::Corrupt);
        };
        // Keep ownership while deciding and removing: a stale GC decision may
        // not remove a newly refreshed/replaced flow with the same tuple.
        if !expired {
            return Ok(false);
        }
        self.storage.remove(&key)?;
        let mut guard = guard;
        guard.state = RETIRED;
        drop(guard);
        let _ = self.reclaim(index);
        Ok(true)
    }
}

#[inline(always)]
fn same_key(a: &FirewallFlowKey, b: &FirewallFlowKey) -> bool {
    const {
        assert!(core::mem::size_of::<FirewallFlowKey>() == 56);
    }
    for i in 0..7 {
        // repr(C), explicit fields, no implicit padding; all56 bytes initialized.
        // Unaligned reads also cover legitimate key storage with lesser alignment.
        let left = unsafe {
            core::ptr::read_unaligned((a as *const FirewallFlowKey).cast::<u64>().add(i))
        };
        let right = unsafe {
            core::ptr::read_unaligned((b as *const FirewallFlowKey).cast::<u64>().add(i))
        };
        if left != right {
            return false;
        }
    }
    true
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallFlowRef {}

#[cfg(test)]
#[path = "firewall_table_tests.rs"]
mod tests;
