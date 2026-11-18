use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{Array, PerCpuArray},
};
use velstra_common::{
    ConntrackTimeouts, FirewallKey, FirewallState, FlowKey, StatePublication, ip_proto,
    publish_state_pair,
};

use super::{CONNTRACK, FW_FLOWS, ROUTER_NAT_POLICY};

#[map]
static CT_TIMEOUTS: Array<ConntrackTimeouts> = Array::with_max_entries(1, 0);

#[inline(always)]
pub(super) fn timeouts() -> ConntrackTimeouts {
    CT_TIMEOUTS
        .get(0)
        .copied()
        .unwrap_or(ConntrackTimeouts::DEFAULT)
}

#[inline(always)]
pub(super) fn ct_control(data: usize, end: usize, off: usize, proto: u8) -> u8 {
    if proto == ip_proto::UDP {
        return 0;
    }
    let pos = if proto == ip_proto::TCP {
        off + 12
    } else {
        off
    };
    let head = read_head4(data, end, pos);
    if head == u64::MAX {
        return 255;
    }
    if proto == ip_proto::TCP {
        (head >> 8) as u8
    } else {
        head as u8
    }
}

/// Keep a variable-offset packet read and its range proof in one small frame.
/// Returning a scalar avoids pointer merges and memcpy loops in callers.
#[inline(never)]
pub(super) fn read_head4(data: usize, end: usize, off: usize) -> u64 {
    // Leave headroom below the verifier's 65535-byte packet-offset limit
    // for the four-byte range proof. The bounded IPv6 walk needs < 17 KiB.
    if off > 32767 {
        return u64::MAX;
    }
    let ptr = (data + off) as *const [u8; 4];
    if ptr as usize + 4 > end {
        return u64::MAX;
    }
    let head = unsafe { core::ptr::read_volatile(ptr) };
    u32::from_le_bytes(head) as u64
}

#[inline(always)]
pub(super) fn ct_key4(mut flow: FlowKey, data: usize, end: usize, off: usize) -> FirewallKey {
    if flow.proto == ip_proto::ICMP {
        let id = read_head4(data, end, off + 4);
        let head = read_head4(data, end, off);
        if id != u64::MAX && head != u64::MAX {
            flow.src_port = (id as u16).swap_bytes();
            flow.dst_port = head as u8 as u16;
        }
    }
    FirewallKey::ipv4(flow)
}

/// Keep NAT lookup state out of the main firewall's near-full stack frame.
/// Explicit rules still use the real on-wire packet; only the TCP/UDP state
/// machine uses this canonical identity, so an invalid ACK remains invalid.
#[inline(never)]
pub(super) fn ct_router_normalize(key: &mut FirewallKey) {
    if key.family != 4 || !matches!(key.proto, ip_proto::TCP | ip_proto::UDP) {
        return;
    }
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    // The firewall key already exists on the caller's stack. Keep the separate
    // NAT lookup key in per-CPU scratch: forcing another FlowKey onto TC's
    // frame exceeds its cumulative stack budget with the NAPT port search.
    unsafe {
        (*scratch).flow = FlowKey::new(
            key.policy,
            [key.src[0], key.src[1], key.src[2], key.src[3]],
            [key.dst[0], key.dst[1], key.dst[2], key.dst[3]],
            key.src_port,
            key.dst_port,
            key.proto,
        );
        let flow = &mut (*scratch).flow;
        // A retained expired tenant binding must not shadow a live router-NAT
        // identity. As below, this is only a read, never expiry reclamation.
        if flow.policy != ROUTER_NAT_POLICY && super::nat_binding_live(flow) {
            return;
        }
        flow.policy = ROUTER_NAT_POLICY;
        let Some(state) = CONNTRACK.get(&*flow) else {
            return;
        };
        if state.expired(flow.proto, bpf_ktime_get_ns(), timeouts())
            || !state.router_firewall_flow(flow)
        {
            return;
        }
        key.policy = ROUTER_NAT_POLICY;
        key.src[..4].copy_from_slice(&flow.src_ip);
        key.dst[..4].copy_from_slice(&flow.dst_ip);
        key.src_port = flow.src_port;
        key.dst_port = flow.dst_port;
    }
}

#[inline(always)]
pub(super) fn ct_key6(key: &mut FirewallKey, data: usize, end: usize, off: usize) {
    if key.proto == 58 {
        let id = read_head4(data, end, off + 4);
        let head = read_head4(data, end, off);
        if id != u64::MAX && head != u64::MAX {
            key.src_port = (id as u16).swap_bytes();
            key.dst_port = head as u8 as u16;
        }
    }
}

#[inline(always)]
pub(super) fn write_key4(
    key: &mut FirewallKey,
    flow: FlowKey,
    data: usize,
    end: usize,
    off: usize,
) {
    key.policy = flow.policy;
    key.src = [
        flow.src_ip[0],
        flow.src_ip[1],
        flow.src_ip[2],
        flow.src_ip[3],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    key.dst = [
        flow.dst_ip[0],
        flow.dst_ip[1],
        flow.dst_ip[2],
        flow.dst_ip[3],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    key.src_port = flow.src_port;
    key.dst_port = flow.dst_port;
    key.proto = flow.proto;
    key.family = 4;
    key._pad = [0; 2];
    if flow.proto == ip_proto::ICMP {
        let id = read_head4(data, end, off + 4);
        let head = read_head4(data, end, off);
        if id != u64::MAX && head != u64::MAX {
            key.src_port = (id as u16).swap_bytes();
            key.dst_port = head as u8 as u16;
        }
    }
}

// A caller in the NAT forward tail already needs most of a 512-byte BPF
// stack. Keep full IPv6 keys and paired state out of the cumulative call stack.
#[repr(C)]
struct Scratch {
    key: FirewallKey,
    reverse: FirewallKey,
    state: FirewallState,
    reverse_state: FirewallState,
    flow: FlowKey,
}
#[map]
static CT_SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

/// Initialize an IPv4 key directly in per-CPU storage. Volatile scalar tail
/// stores prevent LLVM from introducing out-of-line memset calls: those extra
/// BPF frames exceed the forwarding tail's cumulative stack budget.
#[inline(always)]
fn scratch_key4(key: &mut FirewallKey, flow: &FlowKey) {
    const _: () = {
        assert!(core::mem::align_of::<FirewallKey>() >= 4);
        assert!(core::mem::offset_of!(FirewallKey, src) % 4 == 0);
        assert!(core::mem::offset_of!(FirewallKey, dst) % 4 == 0);
    };
    key.policy = flow.policy;
    key.src[..4].copy_from_slice(&flow.src_ip);
    key.dst[..4].copy_from_slice(&flow.dst_ip);
    // SAFETY: repr(C) and the assertions above align each address to u32;
    // offsets 4, 8 and 12 are entirely inside its initialized 16-byte array.
    unsafe {
        for offset in [4, 8, 12] {
            core::ptr::write_volatile(key.src.as_mut_ptr().add(offset).cast::<u32>(), 0);
            core::ptr::write_volatile(key.dst.as_mut_ptr().add(offset).cast::<u32>(), 0);
        }
    }
    key.src_port = flow.src_port;
    key.dst_port = flow.dst_port;
    key.proto = flow.proto;
    key.family = 4;
    key._pad = [0; 2];
}

/// 0 = untracked/expired, 1 = valid tracked packet, 2 = invalid transition.
/// A denied packet never refreshes a connection's idle timeout.
/// Classification is read-only: observing one expired direction does not own
/// either map key. The reverse direction can be newer, and another CPU may
/// refresh the observed entry before a delete-by-key would execute. Logical
/// expiry still denies stale state; physical reclamation needs a writer fence.
#[inline(never)]
pub(super) fn ct_classify(key: &FirewallKey, control: u8) -> u8 {
    let Some(state) = (unsafe { FW_FLOWS.get(key) }) else {
        return 0;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = timeouts();
    state.classify(key.proto, control, now, timeouts)
}

/// Preserve an admitted WAN-initiated connection's routed response. This reads
/// existing direction/phase/age metadata, never creates an exemption or changes
/// map layout. The caller records activity only after receiving true.
#[inline(never)]
pub(super) fn ct_is_routed_reply(key: &FirewallKey, control: u8) -> bool {
    let Some(state) = (unsafe { FW_FLOWS.get(key) }) else {
        return false;
    };
    state.is_routed_reply(
        key.proto,
        control,
        unsafe { bpf_ktime_get_ns() },
        timeouts(),
    )
}

#[inline(never)]
pub(super) fn ct_record(key: &FirewallKey, control: u8) -> StatePublication {
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return StatePublication::Failed;
    };
    unsafe {
        (*scratch).key = *key;
        record_scratch(scratch, control)
    }
}

/// Keep the physical ingress/reverse-egress handshake current as well as its
/// canonical NAT identity. Only called after the real ingress verdict admits
/// the packet; it cannot create state from an untracked non-opener.
#[inline(never)]
pub(super) fn ct_record_wire4(flow: &FlowKey, control: u8) -> StatePublication {
    if !matches!(flow.proto, ip_proto::TCP | ip_proto::UDP) {
        return StatePublication::NoChange;
    }
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return StatePublication::Failed;
    };
    unsafe {
        scratch_key4(&mut (*scratch).key, flow);
        record_scratch(scratch, control)
    }
}

#[inline(always)]
unsafe fn record_scratch(scratch: *mut Scratch, control: u8) -> StatePublication {
    // The two callers own this CPU's scratch slot and initialize its key first.
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        (*scratch).reverse = (*scratch).key.reverse();
        let proto = (*scratch).key.proto;
        let phase = if let Some(old) = FW_FLOWS.get(&(*scratch).key) {
            (*scratch).state = *old;
            if !(*scratch).state.expired(proto, now, timeouts()) {
                (*scratch).state.next_phase(proto, control)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(phase) = phase {
            (*scratch).state.phase = phase;
        } else if FirewallState::is_opener(proto, control) {
            (*scratch).state.phase = FirewallState::NEW;
            (*scratch).state.reply = 0;
        } else {
            return StatePublication::NoChange;
        }
        (*scratch).state.last_seen_ns = now;
        (*scratch).state.age_ns = 0;
        (*scratch).reverse_state = (*scratch).state.reverse();
        if (*scratch).state.phase == FirewallState::RESET {
            // Reset deletion ownership is a separate unresolved boundary. Do
            // not present this historical best-effort cleanup as publication.
            let _ = FW_FLOWS.remove(&(*scratch).key);
            let _ = FW_FLOWS.remove(&(*scratch).reverse);
            StatePublication::NoChange
        } else {
            publish_scratch(scratch)
        }
    }
}

/// NAT knows the policy on which a reply will arrive. Seed that direction as
/// waiting for a response, never as an already established TCP connection.
#[inline(never)]
pub(super) fn ct_seed_reply(flow: &FlowKey, control: u8) -> StatePublication {
    if FirewallState::new(flow.proto, control, 0).is_none() {
        return StatePublication::NoChange;
    }
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return StatePublication::Failed;
    };
    unsafe {
        scratch_key4(&mut (*scratch).key, flow);
        if FW_FLOWS.get(&(*scratch).key).is_some() {
            // This is not proof that the reverse key exists. Preserve the
            // existing seed semantics without claiming paired publication.
            return StatePublication::NoChange;
        }
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::NEW,
            reply: 1,
        };
        (*scratch).reverse_state = (*scratch).state.reverse();
        publish_scratch(scratch)
    }
}

/// Seed an admitted router-NAT opener without materializing a full IPv6-sized
/// firewall key on the forwarding tail's nearly full 512-byte stack.
#[inline(never)]
pub(super) fn ct_router_open(flow: &FlowKey, control: u8) -> StatePublication {
    if !FirewallState::is_opener(flow.proto, control) {
        return StatePublication::NoChange;
    }
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return StatePublication::Failed;
    };
    unsafe {
        scratch_key4(&mut (*scratch).key, flow);
        (*scratch).key.policy = ROUTER_NAT_POLICY;
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::NEW,
            reply: 0,
        };
        (*scratch).reverse_state = (*scratch).state.reverse();
        publish_scratch(scratch)
    }
}

/// The SYN-cookie engine has authenticated and completed the client handshake.
#[inline(never)]
pub(super) fn ct_cookie_admitted(flow: &FlowKey) -> StatePublication {
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return StatePublication::Failed;
    };
    unsafe {
        scratch_key4(&mut (*scratch).key, flow);
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::ESTABLISHED,
            reply: 0,
        };
        (*scratch).reverse_state = (*scratch).state.reverse();
        publish_scratch(scratch)
    }
}

/// Helper success is not an atomic pair transaction or an LRU-retention proof.
/// In particular, never undo the first insert by key after the second fails:
/// another CPU may already have advanced that key. Callers must drop the packet
/// and report the error, while any partial state remains for fenced recovery.
#[inline(always)]
unsafe fn publish_scratch(scratch: *mut Scratch) -> StatePublication {
    publish_state_pair(
        || unsafe {
            FW_FLOWS
                .insert(&(*scratch).key, &(*scratch).state, 0)
                .is_ok()
        },
        || unsafe {
            FW_FLOWS
                .insert(&(*scratch).reverse, &(*scratch).reverse_state, 0)
                .is_ok()
        },
    )
}
