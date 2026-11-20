use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{Array, PerCpuArray},
};
use velstra_common::{
    ConntrackTimeouts, Counter, FirewallKey, FirewallState, FlowKey, ResetCheck, StatePublication,
    ip_proto, publish_state_pair, tcp_flags,
};

use super::{CONNTRACK, FW_FLOWS, ROUTER_NAT_POLICY, bump};

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
    if proto == ip_proto::TCP {
        // Also captures this segment's sequence evidence for the state
        // machine below; every classify/record caller computes control first.
        return capture_tcp(data, end, off);
    }
    let head = read_head4(data, end, off);
    if head == u64::MAX {
        return 255;
    }
    head as u8
}

/// The TCP header fields of the packet whose `control` was computed last on
/// this CPU. A per-CPU slot rather than arguments: every classify/record call
/// site already passes the control byte, and the TC/XDP frames calling them
/// have no stack left for a sequence tuple. Consumers require `flags` to equal
/// the control byte they were given.
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSegment {
    seq: u32,
    ack: u32,
    window: u16,
    flags: u8,
    /// `CSUM_*`, computed only for resets.
    checksum: u8,
    valid: u32,
}
const CSUM_UNKNOWN: u8 = 0;
const CSUM_GOOD: u8 = 1;
const CSUM_BAD: u8 = 2;

#[map]
static CT_SEGMENT: PerCpuArray<TcpSegment> = PerCpuArray::with_max_entries(1, 0);

/// Read flags, sequence, acknowledgement and window. Returns the flags byte,
/// or 255 for a truncated header (exactly the historical `ct_control` value).
#[inline(never)]
fn capture_tcp(data: usize, end: usize, off: usize) -> u8 {
    let head = read_head4(data, end, off + 12);
    if head == u64::MAX {
        return 255;
    }
    let flags = (head >> 8) as u8;
    let Some(segment) = CT_SEGMENT.get_ptr_mut(0) else {
        return flags;
    };
    let seq = read_head4(data, end, off + 4);
    let ack = read_head4(data, end, off + 8);
    // read_head4 returns the four wire bytes as a little-endian integer.
    unsafe {
        (*segment).seq = (seq as u32).swap_bytes();
        (*segment).ack = (ack as u32).swap_bytes();
        (*segment).window = ((head >> 16) as u16).swap_bytes();
        (*segment).flags = flags;
        (*segment).checksum = CSUM_UNKNOWN;
        (*segment).valid = (seq != u64::MAX && ack != u64::MAX) as u32;
    }
    flags
}

/// Record whether this packet's TCP checksum is valid when it is a reset.
/// Called at XDP ingress only: there wire checksums are always complete, and
/// the call site has the verifier budget for the bounded sum. TC egress keeps
/// `CSUM_UNKNOWN`; sequence validation still applies there.
#[inline(never)]
pub(super) fn ct_verify_reset(data: usize, end: usize, off: usize, control: u8) {
    if control == 255 || control & tcp_flags::RST == 0 {
        return;
    }
    let checksum = tcp_checksum(data, end, off);
    if let Some(segment) = CT_SEGMENT.get_ptr_mut(0) {
        unsafe {
            if (*segment).flags == control {
                (*segment).checksum = checksum;
            }
        }
    }
}

/// Verify an IPv4 TCP segment's checksum (only resets pay for this). The sum
/// runs over at most 64 bytes in a constant-bound loop; a longer segment, one
/// whose length is not a multiple of four, or IPv6 is `CSUM_UNKNOWN` and keeps
/// sequence validation as its only gate. XDP receive-side checksums are
/// complete (virtio-net disables guest checksum offload under XDP), so no
/// CHECKSUM_PARTIAL form is accepted.
#[inline(never)]
fn tcp_checksum(data: usize, end: usize, off: usize) -> u8 {
    let ip = read_head4(data, end, 14);
    if ip == u64::MAX || (ip as u8) >> 4 != 4 {
        return CSUM_UNKNOWN;
    }
    let ihl = ((ip as u8) & 0x0f) as usize * 4;
    let total = ((ip >> 16) as u16).swap_bytes() as usize;
    if off != 14 + ihl || total < ihl + 20 {
        return CSUM_UNKNOWN;
    }
    let length = total - ihl;
    if length > 64 || length % 4 != 0 {
        return CSUM_UNKNOWN;
    }
    let src = read_head4(data, end, 26);
    let dst = read_head4(data, end, 30);
    if src == u64::MAX || dst == u64::MAX {
        return CSUM_UNKNOWN;
    }
    // One's-complement sums are byte-order independent: add the wire words as
    // read (byte-swapped) and the pseudo-header constants byte-swapped too.
    let pseudo: u64 = (src & 0xffff)
        + (src >> 16)
        + (dst & 0xffff)
        + (dst >> 16)
        + (ip_proto::TCP as u16).swap_bytes() as u64
        + (length as u16).swap_bytes() as u64;
    let mut sum = pseudo;
    let mut i = 0usize;
    while i < 16 {
        if i * 4 >= length {
            break;
        }
        let word = read_head4(data, end, off + i * 4);
        if word == u64::MAX {
            return CSUM_UNKNOWN;
        }
        sum += (word & 0xffff) + (word >> 16);
        i += 1;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    if sum == 0xffff { CSUM_GOOD } else { CSUM_BAD }
}

/// This packet's captured segment, if it is the one `control` was read from.
#[inline(always)]
fn segment(control: u8) -> Option<TcpSegment> {
    let segment = CT_SEGMENT.get(0).copied()?;
    if segment.flags != control || segment.valid == 0 {
        return None;
    }
    Some(segment)
}

/// RFC 5961 admission of a reset that matches live state: 1 forwards it, 2
/// refuses it. Exact and in-window resets are forwarded; only an exact one
/// will tear state down (see `reset_tears_down`).
#[inline(never)]
fn reset_verdict(state: &FirewallState, control: u8) -> u8 {
    let Some(segment) = segment(control) else {
        return 1;
    };
    if segment.checksum == CSUM_BAD || state.reset_check(segment.seq) == ResetCheck::Invalid {
        bump(Counter::TcpInvalidReset);
        return 2;
    }
    1
}

/// Whether an admitted reset ends the connection. Without sequence evidence
/// (imported/legacy state, or a capture mismatch) the historical behaviour
/// stands; a reset with a wrong checksum never ends one.
#[inline(always)]
fn reset_tears_down(state: &FirewallState, control: u8) -> bool {
    let Some(segment) = segment(control) else {
        return true;
    };
    segment.checksum != CSUM_BAD
        && matches!(
            state.reset_check(segment.seq),
            ResetCheck::Exact | ResetCheck::Unknown
        )
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
        // DP-37: scans and malformed flag combinations never belong to a
        // connection. Port zero marks a non-first fragment (no TCP header).
        if key.proto == ip_proto::TCP
            && key.src_port != 0
            && key.dst_port != 0
            && !FirewallState::tcp_flags_plausible(control)
        {
            bump(Counter::TcpInvalidFlags);
            return 2;
        }
        return 0;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = timeouts();
    let verdict = state.classify(key.proto, control, now, timeouts);
    if verdict == 1 && key.proto == ip_proto::TCP && control & tcp_flags::RST != 0 {
        return reset_verdict(state, control);
    }
    verdict
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

/// Whether the packet is live traffic in the responder's direction of its
/// connection, i.e. one opened towards its source (DP-15: what an ingress-only
/// blocklist lets a listed address send). Read-only, like [`ct_classify`].
#[inline(never)]
pub(super) fn ct_is_answer(key: &FirewallKey, control: u8) -> bool {
    let Some(state) = (unsafe { FW_FLOWS.get(key) }) else {
        return false;
    };
    state.is_answer(
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
            // Keep this fixed-size map-to-scratch copy as scalar stores. The
            // aggregate assignment becomes an overlap-checking byte loop with
            // some BPF backends, multiplying verifier paths in this caller.
            // Volatile stores constrain code generation, not synchronization:
            // this is still the same non-atomic snapshot of the four fields.
            core::ptr::write_volatile(&raw mut (*scratch).state.last_seen_ns, old.last_seen_ns);
            core::ptr::write_volatile(&raw mut (*scratch).state.age_ns, old.age_ns);
            core::ptr::write_volatile(&raw mut (*scratch).state.phase, old.phase);
            core::ptr::write_volatile(&raw mut (*scratch).state.reply, old.reply);
            core::ptr::write_volatile(&raw mut (*scratch).state.acks[0], old.acks[0]);
            core::ptr::write_volatile(&raw mut (*scratch).state.acks[1], old.acks[1]);
            core::ptr::write_volatile(&raw mut (*scratch).state.windows[0], old.windows[0]);
            core::ptr::write_volatile(&raw mut (*scratch).state.windows[1], old.windows[1]);
            core::ptr::write_volatile(&raw mut (*scratch).state.track, old.track);
            if !(*scratch).state.expired(proto, now, timeouts()) {
                (*scratch).state.next_phase(proto, control)
            } else {
                None
            }
        } else {
            None
        };
        let old_phase = (*scratch).state.phase;
        if let Some(phase) = phase {
            if phase == FirewallState::RESET && !reset_tears_down(&(*scratch).state, control) {
                // In-window but not exact (RFC 5961 challenge-ACK case), or a
                // bad checksum: forwarded at most, and no state is touched.
                return StatePublication::NoChange;
            }
            (*scratch).state.phase = phase;
        } else if FirewallState::is_opener(proto, control) {
            (*scratch).state.phase = FirewallState::NEW;
            (*scratch).state.reply = 0;
            (*scratch).state.acks = [0; 2];
            (*scratch).state.windows = [0; 2];
            (*scratch).state.track = 0;
        } else {
            return StatePublication::NoChange;
        }
        if proto == ip_proto::TCP
            && let Some(segment) = segment(control)
        {
            (*scratch)
                .state
                .track_segment(old_phase, control, segment.ack, segment.window);
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
        if let Some(old) = FW_FLOWS.get(&(*scratch).key)
            && !old.expired(flow.proto, bpf_ktime_get_ns(), timeouts())
        {
            // This is not proof that the reverse key exists. Preserve the
            // existing seed semantics without claiming paired publication.
            return StatePublication::NoChange;
        }
        // An EXPIRED entry for this reply tuple is a previous connection on a
        // reused public port (bindings now expire with their connection). It
        // must not suppress the new connection's seed: its reply would meet
        // dead state and the zone's default drop.
        (*scratch).reverse = (*scratch).key.reverse();
        (*scratch).state = FirewallState {
            last_seen_ns: bpf_ktime_get_ns(),
            age_ns: 0,
            phase: FirewallState::NEW,
            reply: 1,
            ..FirewallState::UNTRACKED
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
            ..FirewallState::UNTRACKED
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
            ..FirewallState::UNTRACKED
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
