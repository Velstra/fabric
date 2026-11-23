//! Standalone TCP/UDP NAT port allocation and discovery (PERF-02).
//!
//! Reverse CONNTRACK is authoritative: a flow's binding is the reverse entry
//! that names it, and nothing caches or indexes it, so no eviction can
//! silently change an established tuple. The allocator only ever claims one
//! of the flow's own [`NaptDomain::probe`] window, so discovery scans exactly
//! that window — a fixed, small number of lookups decided by the flow tuple
//! alone. It used to scan as far as a global "largest displacement ever
//! published" bound; any NAT write outside the allocator (an ICMP echo, a
//! port-forward, a hairpin claim) pinned that bound at the whole domain, so
//! every new connection did 32768 lookups in softirq, forever, and the bound
//! was not even adopted with the persisted tables across an agent restart.
//! Replicated configurations keep the legacy allocator plus the linear HA
//! window below, for mixed-version peers.

use core::ffi::c_void;

use aya_ebpf::helpers::{bpf_ktime_get_ns, bpf_loop};
use velstra_common::{
    CgnatLayout, ConntrackTimeouts, FlowKey, FlowState, NaptClaim, NaptDomain, NaptSlot,
    napt_binding_matches, napt_claim, napt_seed, napt_slot,
};

use crate::{
    CONNTRACK, NAPT_MODE, account_masquerade_binding, conntrack, insert_masquerade_binding,
};

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
    /// Standalone scattered window (`probe`) or the replicated linear one
    /// (`candidate`).
    scattered: bool,
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
            scattered: true,
        }
    }

    #[inline(always)]
    fn port(&self, index: u32) -> u16 {
        if self.scattered {
            self.domain.probe(index)
        } else {
            self.domain.candidate(index)
        }
    }
}

#[inline(never)]
unsafe extern "C" fn find_owned(index: u32, opaque: *mut c_void) -> i64 {
    let s = unsafe { &mut *opaque.cast::<Search>() };
    let port = s.port(index);
    if port == 0 {
        return 1;
    }
    s.reverse.dst_port = port;
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
    let port = s.port(index);
    if port == 0 {
        return 1;
    }
    s.reverse.dst_port = port;
    let observed = napt_slot(
        unsafe { CONNTRACK.get(&s.reverse) },
        s.origin,
        s.private_port,
    );
    let claim = napt_claim(
        observed,
        || {
            let state = FlowState::masquerade(s.origin, s.private_port);
            match insert_masquerade_binding(&s.reverse, &state, s.bytes) {
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

/// Scan `count` candidates for this flow's live binding (`s.result`).
#[inline(always)]
fn find(s: &mut Search, count: u32) -> bool {
    unsafe {
        bpf_loop(
            count,
            find_owned as *mut c_void,
            (s as *mut Search).cast(),
            0,
        ) >= 0
    }
}

/// Claim the first vacant of `count` candidates, or reuse this flow's own
/// binding met on the way. Zero result: every candidate is foreign.
#[inline(always)]
fn claim(s: &mut Search, count: u32) -> u32 {
    if unsafe { bpf_loop(count, reserve as *mut c_void, (s as *mut Search).cast(), 0) } < 0 {
        return FAILED;
    }
    s.result
}

/// This flow's live standalone binding, or 0: at most `window()` lookups,
/// fewer the earlier the binding sits. Also the read-only companion for ICMP
/// errors quoting a TCP/UDP NAT connection.
#[inline(never)]
pub fn existing(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout) -> u16 {
    let mut s = Search::new(flow, public, layout, 0);
    let count = s.domain.window();
    if find(&mut s, count) {
        s.result as u16
    } else {
        0
    }
}

/// Claim a standalone binding for a flow [`existing`] has just found none
/// for. A binding another CPU publishes for the same flow in between is met
/// by the claim itself (`NaptClaim::Existing`) when it sits no later than the
/// first vacancy; NOEXIST insertion never replaces another endpoint's state.
#[inline(never)]
pub fn allocate(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout, bytes: u64) -> u32 {
    let mut s = Search::new(flow, public, layout, bytes);
    let count = s.domain.window();
    claim(&mut s, count)
}

/// Candidates an HA (replicated) allocator examines (DP-26): a fixed linear
/// window of the cyclic domain, whose first eight candidates are exactly the
/// legacy eight, so an older peer still finds every binding it could have
/// made, and a binding beyond them is one the older allocator would have
/// refused outright.
pub const HA_WINDOW: u32 = 64;

#[inline(always)]
fn linear(
    flow: &FlowKey,
    public: [u8; 4],
    layout: &CgnatLayout,
    bytes: u64,
    window: u32,
) -> (Search, u32) {
    let mut s = Search::new(flow, public, layout, bytes);
    s.scattered = false;
    let count = if window < s.domain.count {
        window
    } else {
        s.domain.count
    };
    (s, count)
}

/// Existing live binding of `flow` within the first `window` linear
/// candidates (the replicated allocator's window).
#[inline(never)]
pub fn existing_window(flow: &FlowKey, public: [u8; 4], layout: &CgnatLayout, window: u32) -> u16 {
    let (mut s, count) = linear(flow, public, layout, 0, window);
    if find(&mut s, count) {
        s.result as u16
    } else {
        0
    }
}

/// The replicated allocator restricted to the first `window` linear
/// candidates: reuse this flow's live binding there, else claim the first
/// free candidate.
#[inline(never)]
pub fn allocate_window(
    flow: &FlowKey,
    public: [u8; 4],
    layout: &CgnatLayout,
    bytes: u64,
    window: u32,
) -> u32 {
    let (mut s, count) = linear(flow, public, layout, bytes, window);
    if !find(&mut s, count) {
        return FAILED;
    }
    if s.result != 0 {
        if account_masquerade_binding(&s.reverse, s.origin, s.private_port, bytes) {
            return s.result;
        }
        return FAILED;
    }
    claim(&mut s, count)
}
