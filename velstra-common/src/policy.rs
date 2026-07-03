//! The firewall policy: actions, statistics counters and the pure [`decide`]
//! verdict function.
//!
//! Keeping the decision logic in one small, allocation-free, `no_std` function
//! means the **kernel data plane and the user-space test suite execute the very
//! same code**. There is no second implementation that can drift out of sync.

use crate::{
    config::{ConfigFlags, GlobalConfig},
    packet::{PacketMeta, ip_proto},
};

/// The verdict applied to a packet.
///
/// The numeric representation is part of the on-the-wire map ABI: it is what
/// the control plane writes into [`crate::PortKey`]-keyed rule maps and what the
/// data plane reads back. Do **not** renumber the variants.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    /// Let the packet continue up the kernel network stack (`XDP_PASS`).
    Pass = 0,
    /// Drop the packet immediately at the driver (`XDP_DROP`).
    Drop = 1,
    /// **Actively** refuse the packet: send a TCP RST (for TCP) or an ICMP
    /// destination-unreachable (for everything else) back to the sender, then
    /// `XDP_TX`. Unlike [`Action::Drop`], the peer learns the connection was
    /// refused immediately instead of timing out.
    Reject = 2,
}

impl Action {
    /// Decode an [`Action`] from its map representation. Unknown values decode
    /// to [`Action::Pass`] (fail-open) so a corrupt map entry can never silently
    /// black-hole traffic.
    #[inline]
    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Action::Drop,
            2 => Action::Reject,
            _ => Action::Pass,
        }
    }

    /// Encode an [`Action`] into its `u32` map representation.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Bit set in a `PORT_RULES` map value, above the [`Action`] byte, to request
/// **per-rule logging**: a packet matching this rule is logged regardless of the
/// policy-wide [`ConfigFlags::LOG`] flag. Packing it into the existing `u32`
/// value keeps the map ABI (and key/value sizes) unchanged.
pub const PORT_RULE_LOG: u32 = 1 << 8;

/// Pack a port rule's `(action, log)` into its `PORT_RULES` map value.
#[inline]
pub const fn port_rule_value(action: Action, log: bool) -> u32 {
    action.as_u32() | if log { PORT_RULE_LOG } else { 0 }
}

/// The [`Action`] of a packed `PORT_RULES` value (its low byte; unknown values
/// fail open to [`Action::Pass`] like [`Action::from_u32`]).
#[inline]
pub const fn port_rule_action(value: u32) -> Action {
    Action::from_u32(value & 0xff)
}

/// Whether a packed `PORT_RULES` value asks for this rule's matches to be logged.
#[inline]
pub const fn port_rule_logs(value: u32) -> bool {
    value & PORT_RULE_LOG != 0
}

/// Statistics counters, one per slot in the per-CPU `STATS` array map.
///
/// The discriminant is the array index, so the order is part of the map ABI.
/// Append new counters at the end and bump nothing else.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Counter {
    /// Every packet seen by the XDP hook.
    RxPackets = 0,
    /// Total bytes seen by the XDP hook.
    RxBytes = 1,
    /// Passed because the default policy is `pass` and nothing matched.
    PassedDefault = 2,
    /// Passed because an explicit `pass` port rule matched.
    PassedRule = 3,
    /// Dropped because the default policy is `drop` and nothing matched.
    DroppedDefault = 4,
    /// Dropped because the source address is on the CIDR blocklist.
    DroppedBlocklist = 5,
    /// Dropped because an explicit `drop` port rule matched.
    DroppedRule = 6,
    /// Dropped because ICMP filtering is enabled.
    DroppedIcmp = 7,
    /// Could not be parsed (truncated / inconsistent header). Passed, but counted.
    Malformed = 8,
    /// Not IPv4 (ARP, IPv6, …). Passed without further inspection.
    NonIpv4 = 9,
    /// Forwarded to another interface by a matching route (Phase 2).
    Forwarded = 10,
    /// Dropped while forwarding because the TTL reached zero (Phase 2).
    ForwardTtlExceeded = 11,
    /// DNAT-rewritten as a **new** load-balanced connection (Phase 3).
    LoadBalanced = 12,
    /// Matched a service whose backend pool was empty — passed unchanged (Phase 3).
    LbNoBackend = 13,
    /// DNAT-rewritten using an **existing** conntrack entry (Phase 3).
    LbEstablished = 14,
    /// SNAT-rewritten on the reply path via conntrack (reverse NAT, Phase 3).
    LbReverse = 15,
    /// Allowed because it matched a tracked connection (stateful firewall).
    EstablishedAllowed = 16,
    /// Encapsulated into a VXLAN/Geneve tunnel to a remote host (Phase 4).
    OverlayEncap = 17,
    /// Decapsulated from a VXLAN/Geneve tunnel and handed to the stack (Phase 4).
    OverlayDecap = 18,
    /// Dropped before encap because the frame would exceed the underlay MTU.
    OverlayTooBig = 19,
    /// Answered locally from the ARP table (overlay ARP suppression).
    ArpSuppressed = 20,
    /// Every packet seen by the TC **egress** hook (Phase B).
    TxPackets = 21,
    /// Dropped by the egress firewall (Phase B).
    EgressDropped = 22,
    /// SNAT-masqueraded on egress through a masquerade (WAN) interface (Phase 4b).
    EgressMasqueraded = 23,
    /// Actively rejected — a TCP RST or ICMP unreachable was sent (Phase 3).
    Rejected = 24,
    /// A tunnel packet was dropped before decap because it was not addressed to
    /// our VTEP or not sourced from a known peer VTEP (overlay decap auth, C2).
    OverlayDropUntrusted = 25,
    /// Answered locally from the ND table (overlay IPv6 Neighbor-Discovery
    /// suppression, B3 — the IPv6 mirror of [`Counter::ArpSuppressed`]).
    NdSuppressed = 26,
}

impl Counter {
    /// Number of distinct counters — the `max_entries` of the `STATS` map.
    pub const COUNT: u32 = 27;

    /// The array index of this counter.
    #[inline]
    pub const fn index(self) -> u32 {
        self as u32
    }

    /// Decode a counter from its array index, if in range.
    #[inline]
    pub const fn from_u32(value: u32) -> Option<Self> {
        let counter = match value {
            0 => Counter::RxPackets,
            1 => Counter::RxBytes,
            2 => Counter::PassedDefault,
            3 => Counter::PassedRule,
            4 => Counter::DroppedDefault,
            5 => Counter::DroppedBlocklist,
            6 => Counter::DroppedRule,
            7 => Counter::DroppedIcmp,
            8 => Counter::Malformed,
            9 => Counter::NonIpv4,
            10 => Counter::Forwarded,
            11 => Counter::ForwardTtlExceeded,
            12 => Counter::LoadBalanced,
            13 => Counter::LbNoBackend,
            14 => Counter::LbEstablished,
            15 => Counter::LbReverse,
            16 => Counter::EstablishedAllowed,
            17 => Counter::OverlayEncap,
            18 => Counter::OverlayDecap,
            19 => Counter::OverlayTooBig,
            20 => Counter::ArpSuppressed,
            21 => Counter::TxPackets,
            22 => Counter::EgressDropped,
            23 => Counter::EgressMasqueraded,
            24 => Counter::Rejected,
            25 => Counter::OverlayDropUntrusted,
            26 => Counter::NdSuppressed,
            _ => return None,
        };
        Some(counter)
    }

    /// A short, stable, human-readable label (used by the CLI and in eBPF logs).
    ///
    /// `inline(always)`: a `&str` return is a `{ptr, len}` aggregate, which the
    /// BPF target cannot return from a standalone function. The eBPF program
    /// calls this inside its `info!` log lines, so it must always be inlined into
    /// the caller (where the result is constant-folded) and never emitted as a
    /// real function. Plain `#[inline]` is only a hint and LLVM dropped it once
    /// the callers grew, breaking the BPF link.
    #[inline(always)]
    pub const fn label(self) -> &'static str {
        match self {
            Counter::RxPackets => "rx_packets",
            Counter::RxBytes => "rx_bytes",
            Counter::PassedDefault => "passed_default",
            Counter::PassedRule => "passed_rule",
            Counter::DroppedDefault => "dropped_default",
            Counter::DroppedBlocklist => "dropped_blocklist",
            Counter::DroppedRule => "dropped_rule",
            Counter::DroppedIcmp => "dropped_icmp",
            Counter::Malformed => "malformed",
            Counter::NonIpv4 => "non_ipv4",
            Counter::Forwarded => "forwarded",
            Counter::ForwardTtlExceeded => "forward_ttl_exceeded",
            Counter::LoadBalanced => "load_balanced",
            Counter::LbNoBackend => "lb_no_backend",
            Counter::LbEstablished => "lb_established",
            Counter::LbReverse => "lb_reverse",
            Counter::EstablishedAllowed => "established_allowed",
            Counter::OverlayEncap => "overlay_encap",
            Counter::OverlayDecap => "overlay_decap",
            Counter::OverlayTooBig => "overlay_too_big",
            Counter::ArpSuppressed => "arp_suppressed",
            Counter::TxPackets => "tx_packets",
            Counter::EgressDropped => "egress_dropped",
            Counter::EgressMasqueraded => "egress_masqueraded",
            Counter::Rejected => "rejected",
            Counter::OverlayDropUntrusted => "overlay_drop_untrusted",
            Counter::NdSuppressed => "nd_suppressed",
        }
    }
}

/// The outcome of [`decide`]: what to do with a packet and which [`Counter`]
/// explains why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Verdict {
    /// The action to apply.
    pub action: Action,
    /// The counter to increment, recording the reason for the action.
    pub counter: Counter,
}

impl Verdict {
    #[inline]
    const fn new(action: Action, counter: Counter) -> Self {
        Self { action, counter }
    }
}

/// Decide the fate of a single packet.
///
/// This is the heart of the Phase 1 firewall. It is intentionally a pure
/// function of its inputs so the kernel and the test suite share one
/// implementation. The caller (the data plane, or a test) is responsible for
/// the side-effecting map lookups and feeds the results in:
///
/// * `blocklisted` — did the packet's **source** address match the CIDR
///   blocklist (LPM trie)?
/// * `rule` — the [`Action`] of the matching `(proto, dst_port)` rule, if any.
///
/// ## Precedence (highest first)
///
/// 1. **Blocklist** — a blocklisted source is dropped unconditionally. This is
///    the DDoS / abuse mitigation lever and must win over everything else.
/// 2. **ICMP filter** — when [`ConfigFlags::DROP_ICMP`] is set, ICMP is dropped.
/// 3. **Port rule** — an explicit `(proto, dst_port)` rule, allow or deny.
/// 4. **Default policy** — `default_action` from the [`GlobalConfig`].
///
/// ```
/// use velstra_common::{decide, Action, Counter, GlobalConfig, PacketMeta, ip_proto};
///
/// let cfg = GlobalConfig::new(Action::Pass, 0);
/// let pkt = PacketMeta::new([198, 51, 100, 7], [10, 0, 0, 1], ip_proto::TCP, 4000, 443, 40);
///
/// // Nothing matches -> default pass.
/// assert_eq!(decide(&pkt, &cfg, false, None).action, Action::Pass);
/// // A drop rule on the destination port wins over the default.
/// let v = decide(&pkt, &cfg, false, Some(Action::Drop));
/// assert_eq!(v.action, Action::Drop);
/// assert_eq!(v.counter, Counter::DroppedRule);
/// // A blocklisted source beats an explicit allow rule.
/// assert_eq!(decide(&pkt, &cfg, true, Some(Action::Pass)).counter, Counter::DroppedBlocklist);
/// ```
#[inline]
pub fn decide(
    meta: &PacketMeta,
    cfg: &GlobalConfig,
    blocklisted: bool,
    rule: Option<Action>,
) -> Verdict {
    if blocklisted {
        return Verdict::new(Action::Drop, Counter::DroppedBlocklist);
    }

    let is_icmp = meta.proto == ip_proto::ICMP || meta.proto == ip_proto::ICMPV6;
    if is_icmp && cfg.has_flag(ConfigFlags::DROP_ICMP) {
        return Verdict::new(Action::Drop, Counter::DroppedIcmp);
    }

    match rule {
        Some(Action::Drop) => Verdict::new(Action::Drop, Counter::DroppedRule),
        Some(Action::Reject) => Verdict::new(Action::Reject, Counter::Rejected),
        Some(Action::Pass) => Verdict::new(Action::Pass, Counter::PassedRule),
        None => match cfg.default_action() {
            Action::Pass => Verdict::new(Action::Pass, Counter::PassedDefault),
            Action::Drop => Verdict::new(Action::Drop, Counter::DroppedDefault),
            Action::Reject => Verdict::new(Action::Reject, Counter::Rejected),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(proto: u8, dst_port: u16) -> PacketMeta {
        PacketMeta::new([203, 0, 113, 5], [10, 0, 0, 1], proto, 1234, dst_port, 60)
    }

    #[test]
    fn action_roundtrips_and_fails_open() {
        assert_eq!(Action::from_u32(Action::Pass.as_u32()), Action::Pass);
        assert_eq!(Action::from_u32(Action::Drop.as_u32()), Action::Drop);
        // Unknown / corrupt values must never drop traffic.
        assert_eq!(Action::from_u32(42), Action::Pass);
    }

    #[test]
    fn port_rule_value_packs_action_and_log() {
        for action in [Action::Pass, Action::Drop, Action::Reject] {
            for log in [false, true] {
                let v = port_rule_value(action, log);
                assert_eq!(port_rule_action(v), action);
                assert_eq!(port_rule_logs(v), log);
            }
        }
        // A bare action value (no log bit) decodes as log-off — backward
        // compatible with values written before per-rule logging existed.
        assert_eq!(port_rule_action(Action::Drop.as_u32()), Action::Drop);
        assert!(!port_rule_logs(Action::Drop.as_u32()));
    }

    #[test]
    fn counter_index_roundtrips_for_every_variant() {
        for i in 0..Counter::COUNT {
            let c = Counter::from_u32(i).expect("in range");
            assert_eq!(c.index(), i);
            assert!(!c.label().is_empty());
        }
        assert_eq!(Counter::from_u32(Counter::COUNT), None);
    }

    #[test]
    fn default_pass_when_nothing_matches() {
        let cfg = GlobalConfig::new(Action::Pass, 0);
        let v = decide(&pkt(ip_proto::TCP, 80), &cfg, false, None);
        assert_eq!(
            v,
            Verdict {
                action: Action::Pass,
                counter: Counter::PassedDefault
            }
        );
    }

    #[test]
    fn default_drop_when_nothing_matches() {
        let cfg = GlobalConfig::new(Action::Drop, 0);
        let v = decide(&pkt(ip_proto::TCP, 80), &cfg, false, None);
        assert_eq!(
            v,
            Verdict {
                action: Action::Drop,
                counter: Counter::DroppedDefault
            }
        );
    }

    #[test]
    fn blocklist_beats_everything() {
        let cfg = GlobalConfig::new(Action::Pass, ConfigFlags::DROP_ICMP);
        // Even with an explicit allow rule and ICMP, the blocklist wins.
        let v = decide(&pkt(ip_proto::ICMP, 0), &cfg, true, Some(Action::Pass));
        assert_eq!(v.action, Action::Drop);
        assert_eq!(v.counter, Counter::DroppedBlocklist);
    }

    #[test]
    fn icmp_filter_beats_port_rule_but_not_blocklist() {
        let cfg = GlobalConfig::new(Action::Pass, ConfigFlags::DROP_ICMP);
        let v = decide(&pkt(ip_proto::ICMP, 0), &cfg, false, Some(Action::Pass));
        assert_eq!(v.action, Action::Drop);
        assert_eq!(v.counter, Counter::DroppedIcmp);
    }

    #[test]
    fn icmpv6_is_dropped_by_the_icmp_filter() {
        let cfg = GlobalConfig::new(Action::Pass, ConfigFlags::DROP_ICMP);
        let v = decide(&pkt(ip_proto::ICMPV6, 0), &cfg, false, None);
        assert_eq!(v.action, Action::Drop);
        assert_eq!(v.counter, Counter::DroppedIcmp);
    }

    #[test]
    fn icmp_passes_when_filter_disabled() {
        let cfg = GlobalConfig::new(Action::Pass, 0);
        let v = decide(&pkt(ip_proto::ICMP, 0), &cfg, false, None);
        assert_eq!(v.action, Action::Pass);
    }

    #[test]
    fn explicit_rule_overrides_default() {
        let cfg = GlobalConfig::new(Action::Drop, 0);
        let v = decide(&pkt(ip_proto::TCP, 443), &cfg, false, Some(Action::Pass));
        assert_eq!(
            v,
            Verdict {
                action: Action::Pass,
                counter: Counter::PassedRule
            }
        );
    }
}
