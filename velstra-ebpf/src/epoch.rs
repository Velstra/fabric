//! Configuration generations fence packet decisions during live map updates.
//! Odd generations are being written. A packet spanning any generation change
//! is dropped, so it cannot combine an old interface binding with new rules.
use aya_ebpf::{
    macros::map,
    maps::{Array, PerCpuArray},
};

#[map]
static CONFIG_EPOCH: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static PACKET_EPOCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub(super) fn current() -> u64 {
    CONFIG_EPOCH.get(0).copied().unwrap_or(1)
}

#[inline(always)]
pub(super) fn enter() -> bool {
    let epoch = current();
    if epoch & 1 != 0 {
        return false;
    }
    let Some(slot) = PACKET_EPOCH.get_ptr_mut(0) else {
        return false;
    };
    unsafe {
        *slot = epoch;
    }
    true
}

#[inline(always)]
pub(super) fn snapshot() -> u64 {
    PACKET_EPOCH.get(0).copied().unwrap_or(1)
}

#[inline(always)]
pub(super) fn unchanged(before: u64) -> bool {
    before & 1 == 0 && before == current()
}

#[map]
static BUM_EPOCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[inline(always)]
pub(super) fn enter_bum() -> bool {
    let epoch = current();
    if epoch & 1 != 0 {
        return false;
    }
    let Some(slot) = BUM_EPOCH.get_ptr_mut(0) else {
        return false;
    };
    unsafe {
        *slot = epoch;
    }
    true
}
#[inline(always)]
pub(super) fn bum_unchanged() -> bool {
    unchanged(BUM_EPOCH.get(0).copied().unwrap_or(1))
}

#[map]
static EGRESS_EPOCH: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[inline(always)]
pub(super) fn enter_egress() -> bool {
    let epoch = current();
    if epoch & 1 != 0 {
        return false;
    }
    let Some(slot) = EGRESS_EPOCH.get_ptr_mut(0) else {
        return false;
    };
    unsafe {
        *slot = epoch;
    }
    true
}
#[inline(always)]
pub(super) fn egress_snapshot() -> u64 {
    EGRESS_EPOCH.get(0).copied().unwrap_or(1)
}
