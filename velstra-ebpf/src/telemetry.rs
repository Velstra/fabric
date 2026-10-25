use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{PerCpuArray, PerCpuHashMap, RingBuf},
};
use velstra_common::{Action, FirewallKey, PacketEvent, RuleCounterKey, RuleCounters};

#[map]
static RULE_COUNTERS: PerCpuHashMap<RuleCounterKey, RuleCounters> =
    PerCpuHashMap::with_max_entries(65536, 0);
#[map]
static PACKET_EVENTS: RingBuf = RingBuf::with_byte_size(262144, 0);
#[map]
static PACKET_EVENTS_LOST: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// The lower word retains the existing rule ABI. The upper word is its stable
// identity, carried through every lookup and ranking decision as one scalar.
#[inline(always)]
pub(super) fn port_rule_present(v: u64) -> bool {
    velstra_common::port_rule_present(v as u32)
}
#[inline(always)]
pub(super) fn port_rule_action(v: u64) -> Action {
    velstra_common::port_rule_action(v as u32)
}
#[inline(always)]
pub(super) fn port_rule_logs(v: u64) -> bool {
    velstra_common::port_rule_logs(v as u32)
}
#[inline(always)]
pub(super) fn port_rule_limit(v: u64) -> u32 {
    velstra_common::port_rule_limit(v as u32)
}
#[inline(always)]
pub(super) fn port_rule_excluded(v: u64, mask: u32) -> bool {
    velstra_common::port_rule_excluded(v as u32, mask)
}
#[inline(always)]
pub(super) fn port_rule_winner(a: u64, b: u64) -> u64 {
    velstra_common::winning_tagged_rule(a, b)
}

/// Four arguments keep the BPF calling convention bounded. `link` packs
/// ifindex/length; `flags` packs action/log/direction/reason. Build events in
/// reserved ring memory rather than placing a 72-byte event on the BPF stack.
#[inline(never)]
pub(super) fn observe(key: &FirewallKey, link: u64, rule: u64, flags: u64) {
    let length = (link as u32).saturating_sub(if crate::link_layer::raw_ip((link >> 32) as u32) {
        14
    } else {
        0
    });
    let counter_key = RuleCounterKey {
        policy: key.policy,
        rule_id: (rule >> 32) as u32,
    };
    if RULE_COUNTERS.get_ptr_mut(&counter_key).is_none() {
        let zero = RuleCounters::default();
        let _ = RULE_COUNTERS.insert(&counter_key, &zero, 0);
    }
    if let Some(c) = RULE_COUNTERS.get_ptr_mut(&counter_key) {
        unsafe {
            (*c).packets = (*c).packets.wrapping_add(1);
            (*c).bytes = (*c).bytes.wrapping_add(length as u64);
            if flags & 3 == 0 {
                (*c).accepted = (*c).accepted.wrapping_add(1);
            } else {
                (*c).dropped = (*c).dropped.wrapping_add(1);
            }
        }
    }
    if flags & (1 << 8) == 0 {
        return;
    }
    let Some(mut entry) = PACKET_EVENTS.reserve::<PacketEvent>(0) else {
        if let Some(lost) = PACKET_EVENTS_LOST.get_ptr_mut(0) {
            unsafe {
                *lost = (*lost).wrapping_add(1);
            }
        }
        return;
    };
    let event = unsafe { &mut *entry.as_mut_ptr() };
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.policy = key.policy;
    event.rule_id = counter_key.rule_id;
    event.ifindex = (link >> 32) as u32;
    event.length = length;
    event.src = key.src;
    event.dst = key.dst;
    event.src_port = key.src_port;
    event.dst_port = key.dst_port;
    event.proto = key.proto;
    event.family = key.family;
    event.action = flags as u8;
    event.direction = ((flags >> 9) & 1) as u8;
    event.reason = (flags >> 16) as u32;
    event._pad = 0;
    entry.submit(0);
}
