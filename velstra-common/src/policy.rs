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

/// Set on **every** value a writer stores, so a read-back of `0` unambiguously
/// means "no rule". [`Action::Pass`] encodes as `0` itself, so the action bits
/// cannot carry that distinction — and the data plane needs it as a plain scalar,
/// because carrying an `Option` out of a map lookup is what the verifier rejects
/// (see `lookup_port_forward`).
pub const PORT_RULE_PRESENT: u32 = 1 << 31;

/// Bits 9-12 of a packed value: which address family and which direction a rule
/// applies to. Neither bit of a pair set means "both", which is what every rule
/// written before these existed means — so an old value keeps its meaning and no
/// map had to change shape.
///
/// They are read off a value the datapath has already loaded, so scoping a rule
/// this way costs no second lookup. That is the whole reason the distinction
/// lives here rather than in the key: a fifth trie on the hot path is what the
/// verifier has repeatedly refused.
pub const PORT_RULE_V4_ONLY: u32 = 1 << 9;
/// See [`PORT_RULE_V4_ONLY`].
pub const PORT_RULE_V6_ONLY: u32 = 1 << 10;
/// Set when a rule applies only to traffic **arriving** on the policy's
/// interface. See [`PORT_RULE_V4_ONLY`].
pub const PORT_RULE_IN_ONLY: u32 = 1 << 11;
/// Set when a rule applies only to traffic **leaving** the policy's interface —
/// including traffic this box originated, which is the case an ingress-only
/// firewall cannot describe at all. See [`PORT_RULE_V4_ONLY`].
pub const PORT_RULE_OUT_ONLY: u32 = 1 << 12;

/// Whether a packed value is disqualified by any of `mask`\'s bits.
///
/// The caller passes the bits that exclude a rule *here* — on the IPv6 path,
/// [`PORT_RULE_V4_ONLY`]; at the egress hook, [`PORT_RULE_IN_ONLY`] — and a
/// disqualified value is treated as a miss. There is nothing to fall back to: two
/// rules with the same key are the same trie entry, so an excluded entry means no
/// rule matched rather than a lesser one.
#[inline]
pub const fn port_rule_excluded(value: u32, mask: u32) -> bool {
    value & mask != 0
}

/// Where the matched prefix length lives in a packed value.
const PORT_RULE_BITS_SHIFT: u32 = 16;

/// Where a rule's rate-limit slot lives in a packed value: a 1-based index into
/// the `RULE_LIMITS` array, or `0` for a rule with no limit. Packed into the value
/// rather than looked up separately so an unlimited rule — the overwhelming
/// majority — costs no map access at all.
const PORT_RULE_LIMIT_SHIFT: u32 = 24;

/// Highest rate-limit slot the 7 bits at [`PORT_RULE_LIMIT_SHIFT`] can name.
/// Slot `0` means "no limit", so a config may carry this many limited rules.
pub const MAX_RULE_LIMITS: u32 = 127;

/// How many CIDRs the source blocklist holds, per address family, across **all**
/// policies together (`BLOCKLIST` / `BLOCKLIST6` are one map each, scoped by
/// policy id in the key).
///
/// The number is set by whole-country blocking and threat feeds rather than by
/// hand-typed addresses: one country is thousands of prefixes, so a ceiling in
/// the hundreds would rule the feature out instead of bounding it. An LPM trie
/// allocates nodes on insert, so this costs nothing until it is used.
///
/// This is the source of truth. A product that refuses an over-large config at
/// commit time — Sentinel does — has to carry the same number, because the
/// alternative is discovering the ceiling as a partially-programmed firewall.
pub const MAX_BLOCKLIST: u32 = 262_144;

/// Pack a port rule's `(action, log, prefix bits)` into its map value.
///
/// `cidr_bits` is the length of the address prefix this rule constrains (`0` for
/// an unconstrained rule). Within one map the LPM trie already ranks rules by it;
/// it is stored because a **source**-scoped and a **destination**-scoped rule live
/// in *different* tries and still have to be ranked against each other.
#[inline]
pub const fn port_rule_value(action: Action, log: bool, cidr_bits: u8) -> u32 {
    action.as_u32()
        | if log { PORT_RULE_LOG } else { 0 }
        | ((cidr_bits as u32) << PORT_RULE_BITS_SHIFT)
        | PORT_RULE_PRESENT
}

/// The same value with a rate-limit slot attached (1-based; `0` leaves it
/// unlimited). Slots past [`MAX_RULE_LIMITS`] are dropped rather than wrapped into
/// another rule's bucket.
#[inline]
pub const fn port_rule_with_limit(value: u32, slot: u32) -> u32 {
    if slot == 0 || slot > MAX_RULE_LIMITS {
        value
    } else {
        value | (slot << PORT_RULE_LIMIT_SHIFT)
    }
}

/// The rate-limit slot a packed rule carries, or `0` when it is unlimited.
#[inline]
pub const fn port_rule_limit(value: u32) -> u32 {
    (value >> PORT_RULE_LIMIT_SHIFT) & 0x7f
}

/// Whether a packed value came from a real rule rather than from a lookup miss.
#[inline]
pub const fn port_rule_present(value: u32) -> bool {
    value & PORT_RULE_PRESENT != 0
}

/// The prefix length a packed rule matched on — how specific it is. `0` for a rule
/// with no address constraint.
#[inline]
pub const fn port_rule_bits(value: u32) -> u32 {
    (value >> PORT_RULE_BITS_SHIFT) & 0xff
}

/// Pick the effective rule when a **source**-scoped and a **destination**-scoped
/// rule both match the same packet. Each argument is a packed value or `0` for a
/// miss; the result is one of them (or `0` if neither matched).
///
/// The rule is the one an LPM trie already applies within a dimension — **the more
/// specific match wins** — extended across the two tries using the prefix length
/// stored in the value. On an equal prefix the denying rule wins, and between two
/// denials the explicit refusal does, so the outcome never depends on which trie
/// happened to be consulted first. Without that last step a `dst 10.0.0.0/8 drop`
/// and a `src 10.0.0.0/8 pass` would resolve by map layout, i.e. unpredictably.
#[inline]
pub const fn port_rule_winner(src_value: u32, dst_value: u32) -> u32 {
    if !port_rule_present(src_value) {
        return dst_value;
    }
    if !port_rule_present(dst_value) {
        return src_value;
    }
    let (sb, db) = (port_rule_bits(src_value), port_rule_bits(dst_value));
    // More specific wins; on an equal prefix the stricter action does
    // (pass < drop < reject), which is what makes the result independent of which
    // trie was consulted.
    if sb > db || (sb == db && (src_value & 0xff) >= (dst_value & 0xff)) {
        src_value
    } else {
        dst_value
    }
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
    /// Dropped while routing because the TTL could not survive another hop —
    /// both in local forwarding (Phase 2) and at the B7 anycast gateway, which
    /// decrements the TTL exactly like any other router.
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
    /// A copy of a BUM (broadcast/unknown-unicast/multicast) frame was head-end
    /// replicated (VXLAN/Geneve encapsulated + `clone_redirect`ed) to a remote
    /// VTEP in the ingress VNI's flood set (B2). Counted once per emitted copy,
    /// so a BUM frame flooded to N VTEPs bumps this N times.
    BumReplicated = 27,
    /// Encapsulated into an SRv6 tunnel to a remote host — reduced encap, a
    /// single `End.DT2U` service SID (B9).
    Srv6Encap = 28,
    /// Decapsulated an SRv6 packet whose IPv6 destination is a locally
    /// instantiated `End.DT2U` service SID; the inner Ethernet frame is handed to
    /// the kernel bridge (B9).
    Srv6Decap = 29,
    /// A tunnel packet was dropped after VTEP authentication because its inner VNI
    /// is not one this host serves — a (trusted-or-spoofed) peer VTEP may only
    /// inject into a locally-hosted segment, never an arbitrary one (decap VNI
    /// enforcement / tenant isolation at the ingress boundary).
    OverlayDropVni = 30,
    /// A tenant port claimed a `(vni, MAC)` another port already owns, so the
    /// local-MAC binding was **not** learned (B4b anti-spoof). The frame itself is
    /// forwarded normally — only the binding is refused, which is what keeps a
    /// tenant from having its neighbour's MAC advertised into EVPN on its behalf.
    /// A non-zero count is either an attempted hijack or a workload that moved
    /// ports while the old binding was still live.
    MacLearnSpoof = 31,
    /// An SRv6 `End.DT2U` decap was refused because the packet's outer IPv6 source
    /// was not a trusted peer (`SRV6_PEERS`). Without this the frame would be
    /// decapsulated and its inner Ethernet frame bridged into a tenant — the SRv6
    /// analogue of `OverlayDropUntrusted`. A non-zero count is a forged/misrouted
    /// underlay packet aimed at one of our service SIDs, or a peer whose source is
    /// missing from the trusted set.
    Srv6DropUntrusted = 32,
    /// **Routed** onto the overlay by a B7 symmetric-IRB entry instead of bridged:
    /// the frame was addressed to the tenant's anycast gateway MAC, its inner
    /// Ethernet header was rewritten toward the remote PE's Router's MAC and it
    /// was encapsulated with the tenant's **L3** VNI. Also bumps
    /// [`Counter::OverlayEncap`], which counts every encapsulated frame; the
    /// difference between the two is inter-subnet traffic.
    IrbRouted = 33,
    /// Dropped for exceeding its rule's **rate limit** (C15). Distinct from
    /// [`Counter::DroppedRule`]: the rule matched and would have passed the packet,
    /// so a rising count here means a limit is biting, not that a rule denies.
    DroppedRateLimit = 34,
    /// Dropped because the packet's **source address** failed validation (uRPF,
    /// RFC 3704): either no route back to it exists at all, or — under strict
    /// validation — the route back leaves by a different interface than the one
    /// it arrived on. Also counts the sources that can never be legitimate
    /// (loopback, multicast, broadcast).
    ///
    /// A rising count on an edge interface is someone spoofing; a rising count
    /// on an internal one is usually asymmetric routing meeting strict mode, and
    /// the answer there is loose.
    DroppedSpoofed = 35,

    /// A SYN answered with a cookie instead of being forwarded (C15 SYN proxy).
    ///
    /// This is the cost of a flood: one reply packet and no state. A high rate
    /// here with a low [`Counter::SynproxyAdmitted`] beside it *is* the attack
    /// being absorbed — the two read together, never alone.
    SynproxyChallenged = 36,

    /// A client returned a valid cookie, so the connection was opened to the
    /// real server. The only path on which the proxy allocates memory.
    SynproxyAdmitted = 37,

    /// An ACK carrying no cookie this appliance minted for that connection.
    /// Ordinary during a spoofed-ACK flood; also what a cookie that expired
    /// between the SYN and the ACK looks like.
    SynproxyRejected = 38,

    /// A protected server answered, and its sequence space was joined to the
    /// one the client was given. One per proxied connection.
    SynproxySpliced = 39,

    /// Dropped by the **captive portal gate** (C20): the sender has not been
    /// admitted, and what it was sending was not one of the things an unadmitted
    /// client may still do.
    ///
    /// This is the normal, expected reading on a guest zone — every device that
    /// has not logged in yet is counted here, continuously, by whatever it
    /// retries. It is only a fault when it rises for a device that *has* logged
    /// in, which means the session went and the portal did not say so.
    DroppedPortal = 40,

    /// A departing SYN's Maximum Segment Size option was lowered to fit the link
    /// (`mss` on an interface).
    ///
    /// Worth counting because the fault it prevents is invisible: a connection
    /// whose MSS is too large carries small traffic perfectly and hangs on
    /// anything big. A zero here on a tunnel that was configured to clamp says
    /// the clamp is not running; a non-zero one says it is doing something.
    MssClamped = 41,
}

impl Counter {
    /// Number of distinct counters — the `max_entries` of the `STATS` map.
    pub const COUNT: u32 = 42;

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
            27 => Counter::BumReplicated,
            28 => Counter::Srv6Encap,
            29 => Counter::Srv6Decap,
            30 => Counter::OverlayDropVni,
            31 => Counter::MacLearnSpoof,
            32 => Counter::Srv6DropUntrusted,
            33 => Counter::IrbRouted,
            34 => Counter::DroppedRateLimit,
            35 => Counter::DroppedSpoofed,
            36 => Counter::SynproxyChallenged,
            37 => Counter::SynproxyAdmitted,
            38 => Counter::SynproxyRejected,
            39 => Counter::SynproxySpliced,
            40 => Counter::DroppedPortal,
            41 => Counter::MssClamped,
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
            Counter::BumReplicated => "bum_replicated",
            Counter::Srv6Encap => "srv6_encap",
            Counter::Srv6Decap => "srv6_decap",
            Counter::OverlayDropVni => "overlay_drop_vni",
            Counter::MacLearnSpoof => "mac_learn_spoof",
            Counter::Srv6DropUntrusted => "srv6_drop_untrusted",
            Counter::IrbRouted => "irb_routed",
            Counter::DroppedRateLimit => "dropped_rate_limit",
            Counter::DroppedSpoofed => "dropped_spoofed",
            Counter::SynproxyChallenged => "synproxy_challenged",
            Counter::SynproxyAdmitted => "synproxy_admitted",
            Counter::SynproxyRejected => "synproxy_rejected",
            Counter::SynproxySpliced => "synproxy_spliced",
            Counter::MssClamped => "mss_clamped",
            Counter::DroppedPortal => "dropped_portal",
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
    fn port_rule_value_packs_action_log_and_specificity() {
        for action in [Action::Pass, Action::Drop, Action::Reject] {
            for log in [false, true] {
                for bits in [0u8, 8, 24, 32] {
                    let v = port_rule_value(action, log, bits);
                    assert_eq!(port_rule_action(v), action);
                    assert_eq!(port_rule_logs(v), log);
                    assert_eq!(port_rule_bits(v), u32::from(bits));
                    // Every stored value is marked present, including the one whose
                    // every other field is zero — `pass, no log, no prefix` packs to
                    // the same bits a lookup miss returns unless the flag says so.
                    assert!(port_rule_present(v));
                }
            }
        }
        // …and a miss is the only value that is absent.
        assert!(!port_rule_present(0));
        assert_eq!(
            port_rule_value(Action::Pass, false, 0) & !PORT_RULE_PRESENT,
            0,
            "the all-zero rule must be distinguishable from a miss by the flag alone"
        );
    }

    #[test]
    fn the_more_specific_of_a_source_and_destination_rule_wins() {
        let miss = 0;
        let src_any = port_rule_value(Action::Pass, false, 0);
        let src_24 = port_rule_value(Action::Pass, false, 24);
        let dst_8 = port_rule_value(Action::Drop, false, 8);
        let dst_24 = port_rule_value(Action::Drop, false, 24);

        // One-sided matches pass through untouched, including a miss on both.
        assert_eq!(port_rule_winner(src_24, miss), src_24);
        assert_eq!(port_rule_winner(miss, dst_8), dst_8);
        assert_eq!(port_rule_winner(miss, miss), miss);

        // A /24 source beats a /8 destination and vice versa: specificity decides,
        // not which dimension the rule constrains.
        assert_eq!(port_rule_winner(src_24, dst_8), src_24);
        assert_eq!(port_rule_winner(src_any, dst_8), dst_8);

        // Equal specificity: the denial wins, whichever side it is on — so the
        // result cannot depend on trie layout.
        assert_eq!(port_rule_winner(src_24, dst_24), dst_24);
        assert_eq!(
            port_rule_action(port_rule_winner(src_24, dst_24)),
            Action::Drop
        );
        // …and between two denials the explicit refusal, again symmetrically.
        let src_reject = port_rule_value(Action::Reject, false, 24);
        assert_eq!(
            port_rule_action(port_rule_winner(src_reject, dst_24)),
            Action::Reject
        );
        let dst_reject = port_rule_value(Action::Reject, false, 24);
        let src_drop = port_rule_value(Action::Drop, false, 24);
        assert_eq!(
            port_rule_action(port_rule_winner(src_drop, dst_reject)),
            Action::Reject
        );
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
