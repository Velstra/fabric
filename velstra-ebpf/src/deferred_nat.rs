//! Router SNAT must happen after the kernel has validated the original source.
//! The XDP NAT decision leaves a short-lived, generation-fenced rewrite for TC.
//! This is derived per-host transit state, not HA connection state: each packet
//! recreates it from the replicated CONNTRACK entry before entering the kernel.
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map},
    maps::LruHashMap,
    programs::TcContext,
};
use velstra_common::{FlowKey, ip_proto};

use super::{epoch, link_layer, snat_tc};

#[repr(C)]
#[derive(Clone, Copy)]
struct Pending {
    generation: u64,
    created_ns: u64,
    source: [u8; 4],
    port: u16,
    _pad: u16,
}

#[map]
static DEFERRED_SNAT: LruHashMap<FlowKey, Pending> = LruHashMap::with_max_entries(65536, 0);

#[inline(always)]
pub(super) fn queue(key: &FlowKey, source: [u8; 4], port: u16) -> bool {
    let pending = Pending {
        generation: epoch::snapshot(),
        created_ns: unsafe { bpf_ktime_get_ns() },
        source,
        port,
        _pad: 0,
    };
    DEFERRED_SNAT.insert(key, &pending, 0).is_ok()
}

#[inline(always)]
pub(super) fn contains(key: &FlowKey) -> bool {
    unsafe { DEFERRED_SNAT.get(key) }.is_some_and(|entry| {
        entry.generation == epoch::egress_snapshot()
            && unsafe { bpf_ktime_get_ns() }.saturating_sub(entry.created_ns) < 5_000_000_000
    })
}

#[classifier]
pub fn velstra_deferred_snat(ctx: TcContext) -> i32 {
    let before = epoch::egress_snapshot();
    let action = rewrite(&ctx).unwrap_or(TC_ACT_SHOT as i32);
    if epoch::unchanged(before) {
        link_layer::finish_tc(&ctx, action)
    } else {
        TC_ACT_SHOT as i32
    }
}

#[inline(always)]
fn rewrite(ctx: &TcContext) -> Result<i32, ()> {
    let ip: [u8; 20] = ctx.load(14).map_err(|_| ())?;
    if ip[0] != 0x45 || !matches!(ip[9], ip_proto::TCP | ip_proto::UDP) {
        return Err(());
    }
    let ports: [u8; 4] = ctx.load(34).map_err(|_| ())?;
    let source = [ip[12], ip[13], ip[14], ip[15]];
    let sport = u16::from_be_bytes([ports[0], ports[1]]);
    let key = FlowKey::new(
        0,
        source,
        [ip[16], ip[17], ip[18], ip[19]],
        sport,
        u16::from_be_bytes([ports[2], ports[3]]),
        ip[9],
    );
    let pending = unsafe { DEFERRED_SNAT.get(&key) }.copied().ok_or(())?;
    if !contains(&key) {
        return Err(());
    }
    snat_tc(ctx, source, pending.source, sport, pending.port, ip[9])?;
    Ok(TC_ACT_OK as i32)
}
