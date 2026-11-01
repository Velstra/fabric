//! Native IPv6 protocol-state authorization after explicit policy prohibitions.
//! New permissions require policy admission; table/index errors fail closed.
use core::sync::atomic::{AtomicU32, Ordering};

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_loop},
    macros::map,
    maps::PerCpuArray,
    programs::{TcContext, XdpContext},
};
use velstra_common::{
    Counter, FirewallPacketFlow, FlowDirection, FlowLookup, FlowPacket, FlowScope, FlowTimeouts,
    ip_proto, port_rule_limit,
};

use crate::{
    flow_table::{FW_POLICY, FW_TIMEOUT, table},
    packet_validation,
};

pub const POLICY_ALLOW: u32 = 1;
pub const STATEFUL: u32 = 2;
pub const NPT_INGRESS: u32 = 4;
pub const LOG: u32 = 8;
#[repr(C)]
struct Scratch {
    busy: u32,
    policy: u32,
    rule: u32,
    flags: u32,
    target: u32,
    counter: u32,
    parsed: FirewallPacketFlow,
}
#[map]
static FW_FLOW_BUF: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);
struct Guard(*mut Scratch);
impl Drop for Guard {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe {
            (&*core::ptr::addr_of!((*self.0).busy).cast::<AtomicU32>()).swap(0, Ordering::Release);
        }
    }
}
#[inline(always)]
fn acquire() -> Option<Guard> {
    let ptr = FW_FLOW_BUF.get_ptr_mut(0)?;
    unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() }
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .ok()?;
    Some(Guard(ptr))
}
#[inline(always)]
fn timeouts(scope: &FlowScope) -> Option<FlowTimeouts> {
    unsafe { FW_TIMEOUT.get(scope) }.copied()
}
#[inline(always)]
fn limited(rule: u32) -> bool {
    let slot = port_rule_limit(rule);
    if slot == 0 || crate::rate_limits_allow(slot) {
        return false;
    }
    crate::bump(Counter::DroppedRateLimit);
    true
}
/// Return 0 for deny, 1 for explicit/default policy admission, 2 for live state.
/// The caller has already excluded explicit denies, blocklists and ICMP bans.
#[inline(always)]
fn apply(parsed: &FirewallPacketFlow, packet: FlowPacket, rule: u32, flags: u32) -> u32 {
    if parsed.direction > 1 {
        return 0;
    }
    let direction = if parsed.direction == 0 {
        FlowDirection::Forward
    } else {
        FlowDirection::Reverse
    };
    let now = unsafe { bpf_ktime_get_ns() } / 1_000_000;
    match table().observe_scoped(&parsed.key, packet, direction, now, timeouts) {
        Ok(FlowLookup::Tracked(_) | FlowLookup::Unchanged(_)) => return 2,
        Ok(FlowLookup::Invalid) | Err(_) => return 0,
        Ok(FlowLookup::Missing | FlowLookup::PolicyRequired(_)) => {}
    }
    if flags & POLICY_ALLOW == 0 || limited(rule) {
        return 0;
    }
    // An explicitly allowed midstream packet may pass, but never seeds return
    // permission. Only SYN, UDP and echo requests can establish new state.
    if !packet.eligible_opener(parsed.key.protocol) {
        return 1;
    }
    let Some(policy_timeouts) = timeouts(&parsed.key.scope) else {
        return 0;
    };
    match table().admit_scoped(
        &parsed.key,
        packet,
        direction,
        now,
        policy_timeouts,
        timeouts,
    ) {
        Ok(_) => 1,
        Err(_) => 0,
    }
}
#[repr(C)]
struct ApplyContext {
    parsed: *const FirewallPacketFlow,
    rule: u32,
    flags: u32,
    result: u32,
}
#[inline(never)]
unsafe extern "C" fn apply_tcp(_index: u64, context: *mut ApplyContext) -> i64 {
    let context = unsafe { &mut *context };
    let parsed = unsafe { &*context.parsed };
    if parsed.key.family == 6 && parsed.key.protocol == ip_proto::TCP {
        if let FlowPacket::Tcp(packet) = parsed.packet {
            context.result = apply(parsed, FlowPacket::Tcp(packet), context.rule, context.flags);
        }
    }
    1
}
#[inline(never)]
unsafe extern "C" fn apply_udp(_index: u64, context: *mut ApplyContext) -> i64 {
    let context = unsafe { &mut *context };
    let parsed = unsafe { &*context.parsed };
    if parsed.key.family == 6
        && parsed.key.protocol == ip_proto::UDP
        && parsed.packet == FlowPacket::Udp
    {
        context.result = apply(parsed, FlowPacket::Udp, context.rule, context.flags);
    }
    1
}
#[inline(never)]
unsafe extern "C" fn apply_echo(_index: u64, context: *mut ApplyContext) -> i64 {
    let context = unsafe { &mut *context };
    let parsed = unsafe { &*context.parsed };
    if parsed.key.family == 6 && parsed.key.protocol == ip_proto::ICMPV6 {
        match parsed.packet {
            FlowPacket::EchoRequest => {
                context.result = apply(parsed, FlowPacket::EchoRequest, context.rule, context.flags)
            }
            FlowPacket::EchoReply => {
                context.result = apply(parsed, FlowPacket::EchoReply, context.rule, context.flags)
            }
            _ => {}
        }
    }
    1
}
// One synchronous bounded callback separates packet parser paths from the
// protocol-state transaction for the verifier. It does not retry or weaken
// state checks, and the parsed buffer remains guarded until it returns.
#[inline(always)]
fn apply_once(parsed: &FirewallPacketFlow, rule: u32, flags: u32) -> u32 {
    let mut context = ApplyContext {
        parsed,
        rule,
        flags,
        result: 0,
    };
    let ptr = (&mut context as *mut ApplyContext).cast();
    let result = unsafe {
        match parsed.key.protocol {
            ip_proto::TCP => bpf_loop(1, apply_tcp as *mut _, ptr, 0),
            ip_proto::UDP => bpf_loop(1, apply_udp as *mut _, ptr, 0),
            ip_proto::ICMPV6 => bpf_loop(1, apply_echo as *mut _, ptr, 0),
            _ => -1,
        }
    };
    if result == 1 { context.result } else { 0 }
}
#[inline(always)]
fn without_state(rule: u32, flags: u32) -> u32 {
    u32::from(flags & POLICY_ALLOW != 0 && !limited(rule))
}
/// Transfer exclusive ownership of the per-CPU buffer to the next XDP stage.
/// A nested packet cannot overwrite the request: it fails the same CAS guard.
#[inline(always)]
pub fn queue(policy: u32, rule: u32, flags: u32, target: u32, counter: u32) -> bool {
    let Some(guard) = acquire() else {
        return false;
    };
    unsafe {
        (*guard.0).policy = policy;
        (*guard.0).rule = rule;
        (*guard.0).flags = flags;
        (*guard.0).target = target;
        (*guard.0).counter = counter;
    }
    core::mem::forget(guard);
    true
}
#[inline(always)]
pub fn cancel() {
    if let Some(ptr) = FW_FLOW_BUF.get_ptr_mut(0) {
        drop(Guard(ptr));
    }
}
#[inline(never)]
fn log_denied(ctx: &XdpContext, policy: u32, rule: u32) {
    aya_log_ebpf::info!(
        ctx,
        "DROP6 policy={} rule={} reason=native state or rule limit",
        policy,
        rule
    );
}
#[inline(always)]
pub fn complete_xdp(ctx: &XdpContext) -> u32 {
    let Some(ptr) = FW_FLOW_BUF.get_ptr_mut(0) else {
        return 1;
    };
    let lock = unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() };
    if lock
        .compare_exchange(1, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return 1;
    }
    let guard = Guard(ptr);
    let work = unsafe { &mut *guard.0 };
    let admitted = xdp_v6(ctx, work);
    if admitted == 0 {
        if work.flags & LOG != 0 {
            log_denied(ctx, work.policy, work.rule);
        }
        crate::bump(if work.target != 0 {
            Counter::EgressDropped
        } else {
            Counter::DroppedDefault
        });
        return 1;
    }
    crate::bump(if admitted == 2 {
        Counter::EstablishedAllowed
    } else {
        Counter::from_u32(work.counter).unwrap_or(Counter::DroppedDefault)
    });
    if work.target != 0 {
        return crate::TX_PORTS.redirect(work.target, 0).unwrap_or(1);
    }
    if work.flags & NPT_INGRESS != 0
        && crate::npt66_ingress_v6(ctx, ctx.ingress_ifindex() as u32).is_err()
    {
        return 1;
    }
    2
}
#[inline(never)]
fn xdp_v6(ctx: &XdpContext, work: &mut Scratch) -> u32 {
    let flags = work.flags;
    let rule = work.rule;
    if flags & STATEFUL == 0 {
        return without_state(rule, flags);
    }
    let Some(scope) = (unsafe { FW_POLICY.get(&work.policy) }).copied() else {
        return 0;
    };
    let boundary = if flags & NPT_INGRESS != 0 {
        ctx.ingress_ifindex() as u32
    } else {
        0
    };
    match packet_validation::xdp_flow_v6(ctx, scope, boundary, &mut work.parsed) {
        Some(true) => apply_once(&work.parsed, rule, flags),
        Some(false) => without_state(rule, flags),
        None => 0,
    }
}
#[inline(never)]
fn log_tc_denied(ctx: &TcContext, policy: u32, rule: u32) {
    aya_log_ebpf::info!(
        ctx,
        "EGRESS DROP6 policy={} rule={} reason=native state or rule limit",
        policy,
        rule
    );
}
#[inline(always)]
pub fn complete_tc(ctx: &TcContext) -> i32 {
    let Some(ptr) = FW_FLOW_BUF.get_ptr_mut(0) else {
        return 2;
    };
    let lock = unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() };
    if lock
        .compare_exchange(1, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return 2;
    }
    let guard = Guard(ptr);
    let work = unsafe { &mut *guard.0 };
    let admitted = tc_v6(ctx, work);
    if admitted == 0 {
        if work.flags & LOG != 0 {
            log_tc_denied(ctx, work.policy, work.rule);
        }
        crate::bump(Counter::EgressDropped);
        return 2;
    }
    crate::bump(if admitted == 2 {
        Counter::EstablishedAllowed
    } else {
        Counter::from_u32(work.counter).unwrap_or(Counter::PassedRule)
    });
    crate::npt66_egress_v6(ctx).unwrap_or(2)
}
#[inline(never)]
fn tc_v6(ctx: &TcContext, work: &mut Scratch) -> u32 {
    let flags = work.flags;
    let rule = work.rule;
    if flags & STATEFUL == 0 {
        return without_state(rule, flags);
    }
    let Some(scope) = (unsafe { FW_POLICY.get(&work.policy) }).copied() else {
        return 0;
    };
    match packet_validation::tc_flow_v6(ctx, scope, &mut work.parsed) {
        Some(true) => apply_once(&work.parsed, rule, flags),
        Some(false) => without_state(rule, flags),
        None => 0,
    }
}
