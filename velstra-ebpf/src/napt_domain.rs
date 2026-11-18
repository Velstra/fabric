//! Standalone TCP/UDP NAT discovery. Reverse CONNTRACK is authoritative: scan
//! every possibly occupied candidate for existing state BEFORE reserving a vacancy.
//! No cache/index whose eviction could silently change an established tuple.
//! Replicated configurations retain the legacy allocator until peers negotiate
//! complete-domain discovery. This does not repair LRU eviction/publication.

use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_loop},
    macros::map,
    maps::Array,
};
use velstra_common::{
    CgnatLayout, ConntrackTimeouts, FlowKey, FlowState, NaptClaim, NaptDomain, NaptSlot,
    napt_binding_matches, napt_claim, napt_search_count, napt_seed, napt_slot,
};

use crate::{
    CONNTRACK, NAPT_MODE, account_masquerade_binding, claim_marked_masquerade_nat, conntrack,
};

// A monotonic upper bound, NOT a binding cache or allocator authority. OR-ing
// each candidate index before publication can only overestimate the largest
// published displacement. Never clear it, including on deletion/expiry/reset.
// Any non-domain writer invalidates it before writing; non-default domains use
// complete discovery. Replication never enables this allocator. Fresh unpinned
// maps start together, so zero covers the only initially possible index (0).
#[map]
static NAPT_SEARCH: Array<u64> = Array::with_max_entries(1, 0);

// The pinned BPF target does not expose target_has_atomic=64 through std's
// AtomicU64 methods. LLVM still supports the native BPF atomic OR instruction.
// Keep this single intrinsic behind the BPF cfg; kernel verifier tests must
// load the emitted instruction on every supported kernel.
#[inline(always)]
unsafe fn atomic_merge(ptr: *mut u64, value: u64) -> u64 {
    #[cfg(all(target_arch = "bpf", not(velstra_atomic_or_two_types)))]
    unsafe {
        core::intrinsics::atomic_or::<u64, { core::intrinsics::AtomicOrdering::SeqCst }>(ptr, value)
    }
    #[cfg(all(target_arch = "bpf", velstra_atomic_or_two_types))]
    unsafe {
        core::intrinsics::atomic_or::<u64, u64, { core::intrinsics::AtomicOrdering::SeqCst }>(
            ptr, value,
        )
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        (&*ptr.cast::<core::sync::atomic::AtomicU64>())
            .fetch_or(value, core::sync::atomic::Ordering::SeqCst)
    }
}

#[inline(always)]
fn note(index: u64) -> bool {
    let Some(ptr) = NAPT_SEARCH.get_ptr_mut(0) else {
        return false;
    };
    // Array u64 values are aligned and stable for this program's lifetime. All
    // dataplane accesses use this atomic type, never mixed non-atomic writes.
    unsafe { atomic_merge(ptr, index) };
    true
}

#[inline(always)]
pub(super) fn unbounded() -> bool {
    note(65535)
}

#[inline(always)]
fn bound() -> u64 {
    let Some(ptr) = NAPT_SEARCH.get_ptr_mut(0) else {
        return 65535;
    };
    unsafe { atomic_merge(ptr, 0) }
}

pub const INSERTED: u32 = 1 << 16;
pub const FAILED: u32 = 1 << 17;

#[inline(always)]
pub fn enabled() -> bool {
    NAPT_MODE.get(0).copied() == Some(1)
}

struct Search {
    reverse: FlowKey,
    origin: [u8; 4],
    private_port: u16,
    domain: NaptDomain,
    timeouts: ConntrackTimeouts,
    now: u64,
    bytes: u64,
    result: u32,
}

impl Search {
    #[inline(always)]
    fn new(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout, bytes: u64) -> Self {
        Self {
            reverse: FlowKey::new(
                flow.policy,
                flow.dst_ip,
                public,
                flow.dst_port,
                0,
                flow.proto,
            ),
            origin: flow.src_ip,
            private_port: flow.src_port,
            domain: NaptDomain::new(
                flow.src_ip,
                napt_seed(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port),
                layout,
            ),
            timeouts: conntrack::timeouts(),
            now: unsafe { bpf_ktime_get_ns() },
            bytes,
            result: 0,
        }
    }
}

#[inline(never)]
unsafe extern "C" fn find_owned(index: u32, opaque: *mut c_void) -> i64 {
    let s = unsafe { &mut *opaque.cast::<Search>() };
    if index >= s.domain.count || s.domain.count == 0 {
        return 1;
    }
    s.reverse.dst_port = s.domain.candidate(index);
    if let Some(entry) = unsafe { CONNTRACK.get(&s.reverse) }
        && napt_binding_matches(entry, s.origin, s.private_port)
        && !entry.expired(s.reverse.proto, s.now, s.timeouts)
    {
        s.result = s.reverse.dst_port as u32;
        return 1;
    }
    0
}

#[inline(never)]
unsafe extern "C" fn reserve(index: u32, opaque: *mut c_void) -> i64 {
    let s = unsafe { &mut *opaque.cast::<Search>() };
    if index >= s.domain.count || s.domain.count == 0 {
        return 1;
    }
    s.reverse.dst_port = s.domain.candidate(index);
    let observed = napt_slot(
        unsafe { CONNTRACK.get(&s.reverse) },
        s.origin,
        s.private_port,
    );
    let claim = napt_claim(
        observed,
        || {
            // A different port layout changes the meaning of displacement.
            // Invalidate permanently before publishing such a binding.
            let marker = if s.domain.first == 32768 && s.domain.count == 32768 {
                index as u64
            } else {
                65535
            };
            if !note(marker) {
                return Err(-12);
            }
            let state = FlowState::masquerade(s.origin, s.private_port);
            match claim_marked_masquerade_nat(&s.reverse, &state, s.bytes) {
                0 => Ok(()),
                error => Err(error),
            }
        },
        || {
            matches!(
                napt_slot(
                    unsafe { CONNTRACK.get(&s.reverse) },
                    s.origin,
                    s.private_port
                ),
                NaptSlot::Owned
            )
        },
    );
    match claim {
        NaptClaim::Existing => {
            if account_masquerade_binding(&s.reverse, s.origin, s.private_port, s.bytes) {
                s.result = s.reverse.dst_port as u32;
            } else {
                s.result = FAILED;
            }
        }
        NaptClaim::Inserted => s.result = s.reverse.dst_port as u32 | INSERTED,
        NaptClaim::Busy => return 0,
        NaptClaim::Failed => s.result = FAILED,
    }
    1
}

#[inline(always)]
fn search(s: &mut Search) -> bool {
    let before = bound();
    let count = napt_search_count(s.domain, before);
    let ok = unsafe {
        bpf_loop(
            count,
            find_owned as *mut c_void,
            (s as *mut Search).cast(),
            0,
        ) >= 0
    };
    if !ok || s.result != 0 {
        return ok;
    }
    // A concurrent publication may have expanded the bound during the scan.
    // Fall back to the original whole-domain search, not an unbounded retry.
    if bound() != before {
        return unsafe {
            bpf_loop(
                s.domain.count,
                find_owned as *mut c_void,
                (s as *mut Search).cast(),
                0,
            ) >= 0
        };
    }
    true
}

/// Read-only companion for ICMP errors quoting a TCP/UDP NAT connection.
#[inline(never)]
pub fn existing(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout) -> u16 {
    let mut s = Search::new(flow, public, layout, 0);
    if search(&mut s) { s.result as u16 } else { 0 }
}

#[inline(never)]
pub fn allocate(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout, bytes: u64) -> u32 {
    let mut s = Search::new(flow, public, layout, bytes);
    if !search(&mut s) {
        return FAILED;
    }
    if s.result != 0 {
        if account_masquerade_binding(&s.reverse, s.origin, s.private_port, bytes) {
            return s.result;
        }
        return FAILED;
    }
    let count = s.domain.count;
    if unsafe {
        bpf_loop(
            count,
            reserve as *mut c_void,
            (&mut s as *mut Search).cast(),
            0,
        )
    } < 0
    {
        return FAILED;
    }
    s.result
}
