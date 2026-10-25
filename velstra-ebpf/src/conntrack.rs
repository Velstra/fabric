use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{Array, PerCpuArray},
};
use velstra_common::{ConntrackTimeouts, FirewallKey, FirewallState, FlowKey, ip_proto};

use super::FW_FLOWS;

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
}
#[map]
static CT_SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

/// 0 = untracked/expired, 1 = valid tracked packet, 2 = invalid transition.
/// A denied packet never refreshes a connection's idle timeout.
#[inline(never)]
pub(super) fn ct_classify(key: &FirewallKey, control: u8) -> u8 {
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return 2;
    };
    let Some(state) = (unsafe { FW_FLOWS.get(key) }) else {
        return 0;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = timeouts();
    if state.expired(key.proto, now, timeouts) {
        unsafe {
            (*scratch).reverse = key.reverse();
        }
        let _ = FW_FLOWS.remove(key);
        let _ = unsafe { FW_FLOWS.remove(&(*scratch).reverse) };
        return 0;
    }
    if state.next_phase(key.proto, control).is_some() {
        1
    } else {
        2
    }
}

#[inline(never)]
pub(super) fn ct_record(key: &FirewallKey, control: u8) {
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    unsafe {
        (*scratch).key = *key;
        (*scratch).reverse = key.reverse();
        let phase = if let Some(old) = FW_FLOWS.get(key) {
            (*scratch).state = *old;
            if !(*scratch).state.expired(key.proto, now, timeouts()) {
                (*scratch).state.next_phase(key.proto, control)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(phase) = phase {
            (*scratch).state.phase = phase;
        } else if FirewallState::is_opener(key.proto, control) {
            (*scratch).state.phase = FirewallState::NEW;
            (*scratch).state.reply = 0;
        } else {
            return;
        }
        (*scratch).state.last_seen_ns = now;
        (*scratch).state.age_ns = 0;
        (*scratch).reverse_state = (*scratch).state.reverse();
        if (*scratch).state.phase == FirewallState::RESET {
            let _ = FW_FLOWS.remove(&(*scratch).key);
            let _ = FW_FLOWS.remove(&(*scratch).reverse);
        } else {
            let _ = FW_FLOWS.insert(&(*scratch).key, &(*scratch).state, 0);
            let _ = FW_FLOWS.insert(&(*scratch).reverse, &(*scratch).reverse_state, 0);
        }
    }
}

/// NAT knows the policy on which a reply will arrive. Seed that direction as
/// waiting for a response, never as an already established TCP connection.
#[inline(never)]
pub(super) fn ct_seed_reply(flow: &FlowKey, control: u8) {
    if FirewallState::new(flow.proto, control, 0).is_none() {
        return;
    }
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        (*scratch).key = FirewallKey::ipv4(*flow);
        if FW_FLOWS.get(&(*scratch).key).is_some() {
            return;
        }
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::NEW,
            reply: 1,
        };
        (*scratch).reverse_state = (*scratch).state.reverse();
        let _ = FW_FLOWS.insert(&(*scratch).key, &(*scratch).state, 0);
        let _ = FW_FLOWS.insert(&(*scratch).reverse, &(*scratch).reverse_state, 0);
    }
}

/// The SYN-cookie engine has authenticated and completed the client handshake.
#[inline(never)]
pub(super) fn ct_cookie_admitted(flow: &FlowKey) {
    let Some(scratch) = CT_SCRATCH.get_ptr_mut(0) else {
        return;
    };
    unsafe {
        (*scratch).key = FirewallKey::ipv4(*flow);
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::ESTABLISHED,
            reply: 0,
        };
        (*scratch).reverse_state = (*scratch).state.reverse();
        let _ = FW_FLOWS.insert(&(*scratch).key, &(*scratch).state, 0);
        let _ = FW_FLOWS.insert(&(*scratch).reverse, &(*scratch).reverse_state, 0);
    }
}
