//! Declarative firewall configuration.
//!
//! Operators describe the desired policy in a small TOML file; this module
//! parses it ([`FileConfig`]) and resolves it into the concrete map contents
//! the data plane consumes ([`RuntimeConfig`]). Keeping parsing and validation
//! here means the `run` and `validate` subcommands share exactly one code path,
//! and a bad config is rejected *before* we touch the kernel.
//!
//! ## Example
//!
//! ```toml
//! default_action = "pass"   # "pass" or "drop"
//! drop_icmp      = true      # block all ping traffic
//! log      = false     # emit an aya-log line per drop (costly)
//! source_validation = "strict"  # uRPF: "disable" (default), "loose", "strict"
//!
//! # Dual-stack: IPv4 and IPv6 CIDRs share one list (`:` ⇒ IPv6).
//! blocklist = ["10.0.0.0/8", "203.0.113.7", "2001:db8::/32"]
//!
//! [[port_rule]]
//! proto  = "tcp"
//! port   = 22
//! action = "drop"
//! ```

use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use velstra_common::{
    Action, Backend, CgnatLayout, Cidr4, Cidr6, ConfigFlags, GENEVE_PORT, GlobalConfig,
    MAX_BLOCKLIST, Npt66, PORT_RULE_IN_ONLY, PORT_RULE_OUT_ONLY, PORT_RULE_V4_ONLY,
    PORT_RULE_V6_ONLY, PolicyId, PortKey, PortalGate, RouteEntry, ServiceKey, SourceValidation,
    VXLAN_PORT, encap_kind, ip_proto, parse_cidr_v4, parse_cidr_v6, parse_mac,
};

/// A firewall verdict as written in TOML (`"pass"` / `"drop"`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ActionName {
    /// Allow the packet (`XDP_PASS`).
    #[default]
    Pass,
    /// Drop the packet (`XDP_DROP`).
    Drop,
    /// Actively refuse the packet — TCP RST / ICMP unreachable (`XDP_TX`).
    Reject,
}

impl From<ActionName> for Action {
    fn from(value: ActionName) -> Self {
        match value {
            ActionName::Pass => Action::Pass,
            ActionName::Drop => Action::Drop,
            ActionName::Reject => Action::Reject,
        }
    }
}

/// Source-address validation (uRPF, RFC 3704) as written in TOML.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceValidationName {
    /// Accept any source address — the default. uRPF drops traffic, and *which*
    /// traffic depends on the routing table, so it is never enabled implicitly.
    #[default]
    Disable,
    /// The source must be routable somewhere. Survives asymmetric routing.
    Loose,
    /// The route back to the source must leave by the interface it arrived on
    /// (BCP 38). Drops legitimate traffic wherever routing is asymmetric.
    Strict,
}

impl SourceValidationName {
    /// The [`ConfigFlags`] bits this mode sets.
    fn flags(self) -> u32 {
        match self {
            Self::Disable => 0,
            Self::Loose => ConfigFlags::RPF_LOOSE,
            Self::Strict => ConfigFlags::RPF_STRICT,
        }
    }
}

/// A protocol name as written in TOML.
///
/// Not only the two that carry ports. The data plane keys a rule on
/// `(policy, protocol, destination port)` and passes port `0` for anything that
/// is not TCP or UDP, so a rule naming one of the port-less protocols below
/// matches on the protocol alone — which is what "allow ICMP between these two
/// zones" has always needed and what the per-zone `drop_icmp` switch could only
/// answer for a whole zone at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtoName {
    Tcp,
    Udp,
    /// ICMP for IPv4. Carries no port: a rule naming it matches every ICMP
    /// packet under its policy, subject to the rule's address constraints.
    Icmp,
    /// ICMPv6 (IANA 58). A separate protocol from ICMP, not a variant of it —
    /// and the one that carries neighbour discovery, so a v6 network without it
    /// does not work at all.
    #[serde(rename = "icmpv6", alias = "ipv6-icmp", alias = "icmp6")]
    Icmpv6,
    /// VRRP (IANA 112) — the advertisements a redundant pair exchanges.
    Vrrp,
    /// ESP (IANA 50) — the payload half of IPsec.
    Esp,
    /// AH (IANA 51) — the authentication half of IPsec.
    Ah,
    /// GRE (IANA 47).
    Gre,
}

impl ProtoName {
    /// The IANA protocol number.
    fn number(self) -> u8 {
        match self {
            ProtoName::Tcp => ip_proto::TCP,
            ProtoName::Udp => ip_proto::UDP,
            ProtoName::Icmp => ip_proto::ICMP,
            ProtoName::Icmpv6 => 58,
            ProtoName::Vrrp => 112,
            ProtoName::Esp => 50,
            ProtoName::Ah => 51,
            ProtoName::Gre => 47,
        }
    }

    /// Whether this protocol has ports at all. Everything else is matched on the
    /// protocol alone, with the port field left at `0`.
    pub fn has_ports(self) -> bool {
        matches!(self, ProtoName::Tcp | ProtoName::Udp)
    }
}

/// A single `(protocol, port) -> action` rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PortRule {
    /// Transport protocol.
    pub proto: ProtoName,
    /// Destination port to match.
    pub port: u16,
    /// The ICMP (or ICMPv6) type this rule matches. Absent means every type,
    /// which is what a rule naming only the protocol has always meant.
    ///
    /// Only for protocols that carry a type. A typed rule outranks an untyped
    /// one on the same protocol, the way a specific source outranks `from any`.
    #[serde(default, rename = "icmp-type", skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,
    /// Restrict this rule to one address family (`"ipv4"` / `"ipv6"`). Absent
    /// means both, which is what a rule with no address constraint has always
    /// meant — the same rule is found from either family's path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Restrict this rule to one direction (`"in"` / `"out"`). Absent means both.
    ///
    /// `out` is the only way to describe traffic this box **originates**: the
    /// egress hook is where a locally-generated packet is seen, and an
    /// ingress-only firewall cannot say anything about it at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// What to do on a match. Defaults to `drop` — the common "block this
    /// service" case.
    #[serde(default = "default_rule_action")]
    pub action: ActionName,
    /// Log packets matching this rule, regardless of the policy-wide `log` flag.
    /// Off by default.
    #[serde(default)]
    pub log: bool,
    /// Optional source-address constraint (an IPv4 CIDR like `"10.0.0.0/24"` or a
    /// bare `"198.51.100.7"` host). Absent means "from any source". A rule with a
    /// more specific source wins over a `from any` rule on the same port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// Optional **destination**-address constraint, same forms as `src`. Absent
    /// means "to any destination", and a more specific destination wins over a
    /// less specific rule on the same port — across both dimensions, so a `/24`
    /// destination outranks a `/8` source.
    ///
    /// Mutually exclusive with `src`: the data plane ranks each dimension in its
    /// own longest-prefix trie, and a prefix is contiguous from the front of the
    /// key, so no single entry can constrain both. Refused rather than honouring
    /// one silently — a rule that matches more than it says is worse than no rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst: Option<String>,
    /// Rate limit for **new** flows this rule admits, in packets per second. Absent
    /// (or `0`) leaves the rule unlimited. Only meaningful on a rule that passes —
    /// a limit on a drop rule would throttle nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// How much idle time the limit may bank, in packets. Defaults to one second's
    /// worth of `limit`, which is what makes a burst-less limit behave the way an
    /// operator expects rather than admitting exactly one packet at a time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

fn default_rule_action() -> ActionName {
    ActionName::Drop
}

/// How a [`RouteCfg`] forwards matching packets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    /// L3 router: decrement the IPv4 TTL and repair the checksum.
    #[default]
    Route,
    /// L2 switch: re-address the frame and forward it unchanged.
    Switch,
}

impl ForwardMode {
    /// The [`RouteEntry`] flag bits this mode implies.
    fn flags(self) -> u16 {
        match self {
            ForwardMode::Route => RouteEntry::DECREMENT_TTL,
            ForwardMode::Switch => 0,
        }
    }
}

/// A forwarding rule: packets to `dest` leave via `out_iface`, re-addressed to
/// the `via_mac` next hop (Phase 2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCfg {
    /// Policy (tenant) this route belongs to; `0` (the default) is the top-level
    /// routing table. Scoping the FIB by policy lets two tenants with
    /// overlapping prefixes each keep their own next hop (C3).
    #[serde(default)]
    pub policy: PolicyId,
    /// Destination prefix to match, e.g. `"10.0.0.0/24"`.
    pub dest: String,
    /// Egress interface name.
    pub out_iface: String,
    /// Next-hop (destination) MAC address.
    pub via_mac: String,
    /// Source MAC to stamp on the frame. Defaults to the egress interface's own
    /// MAC (read from the system at load time).
    #[serde(default)]
    pub src_mac: Option<String>,
    /// Router (default) or pure L2 switch.
    #[serde(default)]
    pub mode: ForwardMode,
}

/// One real backend behind a [`ServiceCfg`]. `Clone` because the orchestrator
/// now *builds* these (one service per policy id in play on the segment), not
/// only parses them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendCfg {
    /// Backend IP address.
    pub ip: String,
    /// Backend port, or omitted to keep the packet's original destination port.
    #[serde(default)]
    pub port: Option<u16>,
}

/// A Phase 3 load-balancer service: a virtual endpoint fronting a backend pool.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    /// Policy (tenant) this service belongs to; `0` (the default) is the
    /// top-level service table. Scoping the LB by policy lets two tenants front
    /// the same VIP:port without their conntrack/service entries colliding (C3).
    #[serde(default)]
    pub policy: PolicyId,
    /// Virtual IP clients connect to.
    pub vip: String,
    /// Virtual service port.
    pub port: u16,
    /// Transport protocol (`tcp` or `udp`).
    pub proto: ProtoName,
    /// The pool of backends to spread connections across.
    pub backends: Vec<BackendCfg>,
    /// Track this service's flows in the policy-independent (router-NAT)
    /// namespace instead of the ingress policy's.
    ///
    /// Set this on a **router/firewall** service, where the VIP is reached from one
    /// zone and the pool lives in another: the reply then arrives under a different
    /// policy than the request, and a policy-scoped conntrack entry would never
    /// match it, so the backend's address is never rewritten back to the VIP.
    /// Leave it off for a **multi-tenant** service whose pool is on the tenant's own
    /// network — there the per-policy scoping is what keeps two tenants' identical
    /// 5-tuples apart.
    #[serde(default)]
    pub router_nat: bool,
    /// Policy id the pool's replies arrive under — the zone owning the backends'
    /// segment. Only meaningful together with `router_nat`. Omitted (`0`) means the
    /// emitter could not derive it, and the reply then depends on that zone's own
    /// outbound firewall posture instead of on a state entry.
    #[serde(default)]
    pub reply_policy: PolicyId,
}

/// Tunnel encapsulation as written in TOML (`"vxlan"` / `"geneve"`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EncapName {
    /// VXLAN (RFC 7348), UDP/4789. The default.
    #[default]
    Vxlan,
    /// Geneve (RFC 8926), UDP/6081.
    Geneve,
}

impl EncapName {
    /// The [`encap_kind`] code.
    fn kind(self) -> u8 {
        match self {
            EncapName::Vxlan => encap_kind::VXLAN,
            EncapName::Geneve => encap_kind::GENEVE,
        }
    }

    /// The default UDP destination port for this encapsulation.
    fn default_port(self) -> u16 {
        match self {
            EncapName::Vxlan => VXLAN_PORT,
            EncapName::Geneve => GENEVE_PORT,
        }
    }
}

/// This host's overlay tunnel endpoint (`[overlay]`). Present only on hosts that
/// participate in the VXLAN/Geneve fabric.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverlayCfg {
    /// This host's VTEP underlay IPv4 (the outer source address).
    pub local_vtep: String,
    /// The underlay interface encapsulated traffic egresses (its MAC becomes the
    /// outer source MAC unless `local_mac` overrides it).
    pub underlay_iface: String,
    /// Encapsulation format. Defaults to `vxlan`.
    #[serde(default)]
    pub encap: EncapName,
    /// UDP destination port. Defaults to the encapsulation's standard port
    /// (4789 for VXLAN, 6081 for Geneve).
    #[serde(default)]
    pub udp_port: Option<u16>,
    /// Override the outer source MAC. Defaults to the `underlay_iface`'s own MAC.
    #[serde(default)]
    pub local_mac: Option<String>,
    /// Underlay path MTU. Defaults to 1500 — inner frames must then be ≤ 1464
    /// bytes (the 50-byte outer headers, minus the inner's own 14-byte L2).
    #[serde(default)]
    pub underlay_mtu: Option<u16>,
}

/// A tenant neighbour (`[[neighbor]]`): the MAC that answers for a tenant IP, so
/// the host can suppress (locally answer) ARP for it instead of flooding the
/// overlay. The controller pushes one per known tenant address.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeighborCfg {
    /// Tenant VNI this address lives on.
    pub vni: u32,
    /// The tenant IPv4 address.
    pub ip: String,
    /// Its hardware (MAC) address.
    pub mac: String,
}

/// A tenant IPv6 neighbour (`[[nd_neighbor]]`): the MAC that answers for a
/// tenant IPv6, so the host can suppress (locally answer) IPv6 Neighbor
/// Discovery for it instead of flooding the overlay. The IPv6 mirror of
/// [`NeighborCfg`]; the controller pushes one per known tenant IPv6 address.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nd6Cfg {
    /// Tenant VNI this address lives on.
    pub vni: u32,
    /// The tenant IPv6 address.
    pub ip: String,
    /// Its hardware (MAC) address.
    pub mac: String,
}

/// One overlay forwarding entry (`[[tunnel]]`): which remote VTEP hosts a given
/// tenant IP. The controller pushes one per remote tenant address.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelCfg {
    /// Tenant VXLAN Network Identifier (24-bit; also the firewall `policy_id`).
    pub vni: u32,
    /// Inner destination IPv4 this entry matches (a tenant VM address).
    pub inner_dst: String,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep: String,
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub via_mac: String,
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// One symmetric-IRB route (`[[irb_route]]`, B7): a remote tenant subnet reached by
/// **routing** rather than bridging.
///
/// Keyed on the **ingress** VNI, not the tenant's L3 VNI, because that is what the
/// datapath knows when the packet arrives — it sees the segment the frame came from.
/// The controller therefore emits one entry per L2 VNI in the tenant, and `l3_vni`
/// travels in the value as the VNI to encapsulate with.
///
/// Unlike a `[[tunnel]]`, which forwards the inner frame untouched, this entry says
/// the packet is routed: the inner Ethernet header is rewritten (destination
/// `router_mac`, source the tenant's anycast `gateway_mac`) and its TTL decremented.
/// That is why it is a separate table rather than two more optional fields on
/// `TunnelCfg` — a consumer that ignored those fields would silently bridge a packet
/// that must be routed.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IrbRouteCfg {
    /// The tenant segment a packet must arrive on for this route to apply.
    pub vni: u32,
    /// Remote tenant subnet this entry matches (longest-prefix, so a whole subnet
    /// is one entry).
    pub inner_dst: String,
    /// The tenant's routed VNI, stamped on the encapsulated packet.
    pub l3_vni: u32,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep: String,
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub via_mac: String,
    /// Underlay egress interface name.
    pub out_iface: String,
    /// The egress router's IRB MAC (RFC 9135) — the rewritten inner destination.
    pub router_mac: String,
    /// This tenant's anycast gateway MAC — the rewritten inner source, and the
    /// destination a local VM addresses to have its packet routed at all.
    pub gateway_mac: String,
}

/// One L2 forwarding entry (`[[mac_route]]`, B1): which remote VTEP hosts a
/// given tenant destination MAC. Consulted before the L3 `[[tunnel]]` table, so
/// a true L2 overlay bridges by MAC. The controller pushes one per remote MAC.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MacRouteCfg {
    /// Tenant VXLAN Network Identifier (24-bit; also the firewall `policy_id`).
    pub vni: u32,
    /// Inner destination MAC this entry bridges (a tenant VM's hardware address).
    pub mac: String,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep: String,
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub via_mac: String,
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// One BUM head-end replication entry (`[[flood_vtep]]`, B2): a remote VTEP that
/// broadcast/unknown-unicast/multicast traffic on `vni` must be flooded to. One
/// row per (vni, remote_vtep); the agent groups all rows sharing a `vni` into a
/// single per-VNI flood set. Fields mirror [`MacRouteCfg`] exactly (they resolve
/// to the same `TunnelEndpoint` triple), minus the per-destination MAC — the
/// flood is by VNI, not by inner MAC.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FloodVtepCfg {
    /// Tenant VXLAN Network Identifier (24-bit) whose BUM traffic floods here.
    pub vni: u32,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep: String,
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub via_mac: String,
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// This host's SRv6 tunnel-source identity (`[srv6]`, B9): the modern, SID-based
/// overlay wire format (RFC 8986). Mutually exclusive with `[overlay]` (one
/// overlay format per host). The SRv6 analogue of [`OverlayCfg`] — but the outer
/// source is a 128-bit IPv6 address out of this node's locator, and there is no
/// UDP port or encap choice (reduced encap, a single service SID).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Srv6Cfg {
    /// This host's SRv6 source address (the outer IPv6 source), an address from
    /// its own locator.
    pub local_src: String,
    /// The underlay interface encapsulated traffic egresses (its MAC becomes the
    /// outer source MAC unless `local_mac` overrides it).
    pub underlay_iface: String,
    /// Override the outer source MAC. Defaults to the `underlay_iface`'s own MAC.
    #[serde(default)]
    pub local_mac: Option<String>,
    /// Underlay path MTU. Defaults to 1500 — inner frames must then be ≤ 1460
    /// bytes (the 40-byte outer IPv6 header, over the inner's own 14-byte L2).
    #[serde(default)]
    pub underlay_mtu: Option<u16>,
    /// Trusted decap peers: the outer IPv6 **source** addresses this node accepts
    /// an SRv6 `End.DT2U` decap from (each peer's own `local_src`). A packet to one
    /// of our local SIDs is decapsulated only when its outer source is in this set
    /// — the SRv6 analogue of the VXLAN trusted-VTEP set, closing the same
    /// forge-a-frame-past-the-firewall hole on the underlay. Empty ⇒ no source is
    /// trusted and decap is refused (fail-closed). The remote SID we send *toward*
    /// (`[[srv6_route]].remote_sid`) is a function-bearing SID and is generally not
    /// a peer's source, so trust cannot be derived from routes — list it here.
    #[serde(default)]
    pub peers: Vec<String>,
}

/// One SRv6 L2 forwarding entry (`[[srv6_route]]`, B9): which remote `End.DT2U`
/// service SID hosts a given tenant destination MAC. The SRv6 analogue of
/// [`MacRouteCfg`] — the remote endpoint is a 128-bit service SID (the outer IPv6
/// destination) rather than a 4-byte VTEP IPv4.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Srv6RouteCfg {
    /// Tenant VXLAN Network Identifier (24-bit; also the firewall `policy_id`).
    pub vni: u32,
    /// Inner destination MAC this entry bridges (a tenant VM's hardware address).
    pub mac: String,
    /// Remote `End.DT2U` service SID (the outer IPv6 destination address).
    pub remote_sid: String,
    /// Next-hop MAC on the underlay toward the remote SID.
    pub via_mac: String,
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// One SRv6 local-SID this node instantiates (`[[srv6_local_sid]]`, B9): a
/// 128-bit service SID it advertises and terminates. An arriving packet whose
/// outer IPv6 destination matches `sid` is decapsulated and bridged into `vni`
/// per `behavior`. The decap counterpart of a peer's `[[srv6_route]]`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Srv6LocalSidCfg {
    /// The instantiated service SID (an IPv6 address out of this node's locator).
    pub sid: String,
    /// Tenant VNI this SID terminates into.
    pub vni: u32,
    /// Endpoint behaviour: `end.dt2u` (L2 unicast, default) or `end.dt2m` (L2
    /// flood). Only `end.dt2u` is decapsulated by the datapath today.
    #[serde(default)]
    pub behavior: Option<String>,
}

/// A named tenant policy (`[[policy]]`): the same firewall fields as the
/// top-level config, but with an explicit non-zero `id` that interfaces map to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Policy id (must be non-zero; `0` is the default top-level policy).
    pub id: PolicyId,
    /// C20 captive portal: gate this policy's clients until each is admitted at
    /// run time. Absent ⇒ no portal, and no cost.
    #[serde(default)]
    pub portal: Option<PortalCfg>,
    /// Optional human-readable name (for logs only).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub default_action: ActionName,
    #[serde(default)]
    pub drop_icmp: bool,
    #[serde(default)]
    pub log: bool,
    #[serde(default)]
    pub stateful: bool,
    /// Source-address validation (uRPF) for this policy's interfaces.
    #[serde(default)]
    pub source_validation: SourceValidationName,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default, rename = "port_rule")]
    pub port_rules: Vec<PortRule>,
}

/// C20 captive portal settings for one policy (`portal = { address = … }`).
///
/// The addresses named here are **the appliance's own**, in the gated zone: they
/// are what a client that has not logged in is still allowed to reach, and
/// therefore where the portal page and the resolver live. They are not a filter
/// on what is admitted afterwards — that is the ordinary ruleset's job, and it
/// still runs.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortalCfg {
    /// The appliance's IPv4 address in the gated zone.
    #[serde(default)]
    pub address: Option<String>,
    /// The appliance's IPv6 address in the gated zone. A dual-stacked zone wants
    /// both: the gate closes IPv6 as well, and a client with no v6 address to
    /// reach cannot load the portal over v6 at all.
    #[serde(default)]
    pub address6: Option<String>,
}

/// Maps an interface to a policy and (optionally) an overlay segment
/// (`[[interface]]`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceFile {
    /// Interface name (resolved to an ifindex at load time).
    pub name: String,
    /// Policy id this interface's traffic is evaluated against (its firewall
    /// ruleset).
    pub policy: PolicyId,
    /// Overlay segment (VXLAN Network Identifier) this interface belongs to.
    /// **Decoupled from `policy`**: many ports can share one ruleset on
    /// different segments, or one segment can host ports with different rules
    /// (security groups). Omitted ⇒ defaults to `policy` (the convenient
    /// single-tenant case); `0` ⇒ the interface is local-only (never tunneled).
    #[serde(default)]
    pub vni: Option<u32>,
    /// Clamp the TCP MSS a departing SYN advertises to at most this, in bytes.
    ///
    /// For a link that takes bytes out of every packet — a tunnel, a PPPoE
    /// session. Path MTU discovery is supposed to make this unnecessary; on a
    /// path where the ICMP carrying that news is filtered, a connection carries
    /// small traffic perfectly and hangs on anything large. Omitted ⇒ no clamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mss: Option<u16>,
    /// Masquerade (source NAT) traffic **leaving** this interface to its own
    /// public IPv4 — the classic WAN uplink. Off by default. The control plane
    /// reads the live address and programs the `MASQUERADE` map + the TC egress
    /// hook; the reply is un-NAT'd on ingress via connection tracking.
    #[serde(default)]
    pub masquerade: bool,
    /// Deterministic CGNAT (roadmap C16): the first WAN port handed out and how
    /// many each internal address gets. Both set ⇒ every masqueraded flow from one
    /// address takes a port from that address's fixed block, so a WAN port can be
    /// attributed to a subscriber by arithmetic instead of by logging every
    /// translation. Unset (or `0`) keeps the plain hash-spread NAPT.
    #[serde(default)]
    pub cgnat_base_port: u16,
    /// Ports per internal address. See `cgnat_base_port`.
    #[serde(default)]
    pub cgnat_block_size: u16,
}

/// The raw, deserialised TOML document. The top-level firewall fields define
/// policy `0` (the default); `[[policy]]`/`[[interface]]` add tenant policies.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FileConfig {
    /// Verdict for traffic that matches no rule. Defaults to `pass`.
    pub default_action: ActionName,
    /// Drop all ICMP traffic.
    pub drop_icmp: bool,
    /// Log every dropped packet via `aya-log` (debugging aid; costly).
    pub log: bool,
    /// Track connections and allow established flows (stateful firewall).
    pub stateful: bool,
    /// C20 captive portal for the default policy. See [`PortalCfg`].
    pub portal: Option<PortalCfg>,
    /// Source-address validation (uRPF, RFC 3704): `disable` (default), `loose`
    /// or `strict`. Applies to the default policy; `[[policy]]` blocks set their
    /// own.
    pub source_validation: SourceValidationName,
    /// Drop a packet the data plane cannot parse instead of passing it. Off by
    /// default: a firewall should not black-hole traffic because of its own
    /// parsing limits. Turn it on under a deny-by-default posture, where a packet
    /// the filter cannot understand is exactly the one it must not admit. Host-wide
    /// (the parse fails before any policy is known), covering the XDP ingress and
    /// the TC egress hook alike.
    pub fail_closed: bool,
    /// Source-IP CIDR blocks to drop unconditionally.
    pub blocklist: Vec<String>,
    /// Per-`(proto, port)` rules. Spelled `[[port_rule]]` in TOML.
    #[serde(rename = "port_rule")]
    pub port_rules: Vec<PortRule>,
    /// Additional tenant policies. Spelled `[[policy]]` in TOML.
    #[serde(rename = "policy")]
    pub policies: Vec<PolicyFile>,
    /// Interface-to-policy assignments. Spelled `[[interface]]` in TOML.
    #[serde(rename = "interface")]
    pub interfaces: Vec<InterfaceFile>,
    /// Phase 2 forwarding rules. Spelled `[[route]]` in TOML.
    #[serde(rename = "route")]
    pub routes: Vec<RouteCfg>,
    /// Phase 3 load-balancer services. Spelled `[[service]]` in TOML.
    #[serde(rename = "service")]
    pub services: Vec<ServiceCfg>,
    /// Phase 4 1:1 DNAT port-forwards. Spelled `[[port_forward]]` in TOML.
    #[serde(default, rename = "port_forward")]
    pub port_forwards: Vec<PortForwardCfg>,
    /// C15 SYN-proxy: the TCP ports a proxy stands in front of.
    #[serde(default, rename = "synproxy")]
    pub synproxy: Vec<SynProxyPortCfg>,
    /// Phase 4 overlay endpoint for this host. Spelled `[overlay]` in TOML.
    #[serde(default)]
    pub overlay: Option<OverlayCfg>,
    /// Phase 4 overlay forwarding entries. Spelled `[[tunnel]]` in TOML.
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<TunnelCfg>,
    /// B1 per-MAC L2 forwarding entries. Spelled `[[mac_route]]` in TOML.
    #[serde(rename = "mac_route")]
    pub mac_routes: Vec<MacRouteCfg>,
    /// B7 symmetric-IRB routes: remote tenant subnets reached by routing.
    #[serde(default, rename = "irb_route")]
    pub irb_routes: Vec<IrbRouteCfg>,
    /// Phase 4 ARP-suppression neighbours. Spelled `[[neighbor]]` in TOML.
    #[serde(rename = "neighbor")]
    pub neighbors: Vec<NeighborCfg>,
    /// B3 IPv6 ND-suppression neighbours. Spelled `[[nd_neighbor]]` in TOML.
    #[serde(rename = "nd_neighbor")]
    pub nd_neighbors: Vec<Nd6Cfg>,
    /// B2 BUM head-end replication flood entries. Spelled `[[flood_vtep]]` in
    /// TOML.
    #[serde(rename = "flood_vtep")]
    pub flood_vteps: Vec<FloodVtepCfg>,
    /// C16 NPTv6 (RFC 6296) stateless prefix translations. Spelled `[[npt66]]`.
    #[serde(default, rename = "npt66")]
    pub npt66: Vec<Npt66Cfg>,
    /// C9 stateful-HA conntrack sync. Spelled `[conntrack_sync]` in TOML.
    #[serde(default)]
    pub conntrack_sync: Option<ConntrackSyncCfg>,
    /// C12 IPFIX flow export. Spelled `[flow_export]` in TOML.
    #[serde(default, rename = "flow_export")]
    pub flow_export: Option<FlowExportCfg>,
    /// B9 SRv6 overlay endpoint for this host. Spelled `[srv6]` in TOML.
    #[serde(default)]
    pub srv6: Option<Srv6Cfg>,
    /// B9 SRv6 per-MAC L2 forwarding entries. Spelled `[[srv6_route]]` in TOML.
    #[serde(default, rename = "srv6_route")]
    pub srv6_routes: Vec<Srv6RouteCfg>,
    /// B9 SRv6 local-SID instantiations. Spelled `[[srv6_local_sid]]` in TOML.
    #[serde(default, rename = "srv6_local_sid")]
    pub srv6_local_sids: Vec<Srv6LocalSidCfg>,
}

/// A NPTv6 (RFC 6296) prefix-translation rule: on the boundary `interface`, an
/// internal source leaving is rewritten to the external prefix, and an external
/// destination arriving is rewritten back — stateless and checksum-neutral.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Npt66Cfg {
    /// The boundary (external/WAN) interface this rule is applied on.
    pub interface: String,
    /// Internal IPv6 prefix, e.g. `"fd00:1::/48"`.
    pub internal: String,
    /// External (provider-delegated) IPv6 prefix, e.g. `"2001:db8:1::/48"`.
    pub external: String,
}

/// A resolved NPTv6 rule, ready for the `NPTV6` map. The agent resolves
/// `interface` to an ifindex at program time (the live index the box has now).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNpt66 {
    /// Boundary interface name (resolved to an ifindex by the agent).
    pub interface: String,
    /// The precomputed translation (prefixes + checksum-neutral adjustment).
    pub npt: Npt66,
}

/// C12 IPFIX flow export (`[flow_export]`). When present, the agent ships the
/// conntrack table's per-flow deltas to a collector as IPFIX (RFC 7011).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FlowExportCfg {
    /// Where the collector listens, `host:port`.
    pub collector: String,
    /// Seconds between exports. Defaults to 30 — often enough that a graph has
    /// shape, rarely enough that the export is not itself the traffic.
    #[serde(default = "default_export_interval_secs")]
    pub interval_secs: u64,
    /// IPFIX observation domain. Distinguishes this appliance's records from
    /// another's at a collector that receives both; defaults to 1.
    #[serde(default = "default_observation_domain")]
    pub observation_domain: u32,
}

/// Default flow-export interval (seconds).
fn default_export_interval_secs() -> u64 {
    30
}

/// Default IPFIX observation domain.
fn default_observation_domain() -> u32 {
    1
}

/// A resolved `[flow_export]` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFlowExport {
    /// Collector endpoint, as written (resolved when the exporter starts, so a
    /// name that is not yet resolvable at boot does not fail the config).
    pub collector: String,
    /// Seconds between exports.
    pub interval_secs: u64,
    /// IPFIX observation domain.
    pub observation_domain: u32,
}

/// C9 stateful-HA conntrack-state sync (a pfsync-analog for the eBPF `CONNTRACK`
/// map). Spelled `[conntrack_sync]` in TOML. When present, the agent binds a UDP
/// socket on `listen`, periodically pushes its live conntrack entries to each
/// `peer`, and applies entries received from peers into its own `CONNTRACK` map —
/// so a VRRP failover onto the backup keeps established (NAT'd) flows alive
/// instead of dropping every connection.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConntrackSyncCfg {
    /// UDP endpoint to bind for receiving peer state, e.g. `"0.0.0.0:5429"`.
    pub listen: String,
    /// Peer endpoints to push local conntrack state to, e.g. `"10.0.0.2:5429"`.
    #[serde(default)]
    pub peer: Vec<String>,
    /// Seconds between pushes. Defaults to 1.
    #[serde(default = "default_ct_interval_secs")]
    pub interval_secs: u64,
}

/// Default conntrack-sync push interval (seconds).
fn default_ct_interval_secs() -> u64 {
    1
}

/// A resolved conntrack-sync config: the `listen`/`peer` endpoints parsed to
/// `SocketAddr` so binding and sending cannot fail on a malformed address at
/// runtime — the failure surfaces at config-load time instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConntrackSync {
    /// Local UDP bind endpoint.
    pub listen: SocketAddr,
    /// Peer endpoints pushed to each interval.
    pub peers: Vec<SocketAddr>,
    /// Seconds between pushes (at least 1).
    pub interval_secs: u64,
}

/// A resolved load-balancer service: a service key and its (validated) backends.
#[derive(Debug, Clone)]
pub struct ResolvedService {
    /// The `(VIP, port, proto)` lookup key.
    pub key: ServiceKey,
    /// The backend pool (at least one entry).
    pub backends: Vec<Backend>,
    /// Track flows in the policy-independent namespace, for a pool reached from
    /// another zone than the VIP. See [`ServiceCfg::router_nat`].
    pub router_nat: bool,
    /// Policy a backend's reply arrives under; `0` ⇒ not derived.
    pub reply_policy: PolicyId,
}

/// A resolved forwarding rule. The egress interface is kept as a name here and
/// turned into an ifindex (plus, if needed, its MAC) at load time by the control
/// plane, since that requires touching the OS.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Owning policy (tenant); `0` is the default routing table (C3).
    pub policy: PolicyId,
    /// Destination prefix to match.
    pub dest: Cidr4,
    /// Egress interface name.
    pub out_iface: String,
    /// Source MAC, or `None` to use the egress interface's own MAC.
    pub src_mac: Option<[u8; 6]>,
    /// Next-hop MAC.
    pub dst_mac: [u8; 6],
    /// [`RouteEntry`] flag bits (e.g. decrement TTL).
    pub flags: u16,
}

/// A TCP port a SYN proxy stands in front of (TOML `[[synproxy]]`).
///
/// Named by port rather than by zone: what is protected is a *service*, and a
/// service answers on its port whichever zone a client reaches it from. Scoping
/// this by zone would mean a flood arriving on a zone nobody listed reaches the
/// server — the failure the feature exists to prevent, reintroduced as a
/// configuration mistake.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SynProxyPortCfg {
    /// TCP port to protect. The proxy answers every SYN to it.
    pub port: u16,
    /// MSS the synthesised SYN-ACK advertises to clients. Defaults to the
    /// largest value an untunnelled Ethernet path carries.
    #[serde(default = "default_synproxy_mss")]
    pub mss: u16,
}

/// The MSS a proxy advertises when the config does not say: a 1500-byte
/// Ethernet MTU less the IPv4 and TCP headers.
fn default_synproxy_mss() -> u16 {
    1460
}

/// A resolved SYN-proxy port, ready for the `SYNPROXY` map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSynProxy {
    /// Protected TCP port.
    pub port: u16,
    /// MSS advertised to clients.
    pub mss: u16,
}

/// A 1:1 inbound DNAT port-forward (TOML `[[port_forward]]`): rewrite a
/// `(policy, proto, port)` arriving on a zone to an internal `dst_ip:dst_port`.
/// The reply is SNAT'd back automatically (conntrack), and the rule implicitly
/// opens the firewall for that port.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortForwardCfg {
    /// Policy (zone) the forward applies to — the public/ingress side.
    pub policy: PolicyId,
    /// Matched L4 protocol (tcp or udp).
    pub proto: ProtoName,
    /// Public destination port matched inbound.
    pub port: u16,
    /// Internal host the connection is rewritten to.
    pub dst_ip: String,
    /// Internal port (`0` keeps the public port).
    #[serde(default)]
    pub dst_port: u16,
    /// Hairpin (NAT reflection): only DNAT when the packet's destination equals
    /// this address (the box's public IP). Unset ⇒ match any destination — the
    /// plain WAN forward. Set on the internal-zone reflection entries so they never
    /// hijack internal-to-internal traffic to the same port.
    #[serde(default)]
    pub match_dst: Option<String>,
    /// Hairpin (NAT reflection): also SNAT the source to this address (the box's IP
    /// on the client's segment) so the internal server's reply routes back through
    /// the box. Unset ⇒ plain DNAT, no source rewrite.
    #[serde(default)]
    pub snat_ip: Option<String>,
    /// Policy id the internal host's replies arrive under — the zone owning
    /// `dst_ip`'s segment. Omitted (`0`) means the emitter could not derive it, and
    /// the reply then depends on that zone's own outbound firewall posture instead
    /// of on a state entry.
    #[serde(default)]
    pub reply_policy: PolicyId,
}

/// A resolved port-forward, ready for the `PORT_FORWARDS` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPortForward {
    /// Policy (zone) id on the public side.
    pub policy: PolicyId,
    /// L4 protocol number.
    pub proto: u8,
    /// Public destination port.
    pub port: u16,
    /// Internal host (network-order octets).
    pub dst_ip: [u8; 4],
    /// Internal port (`0` keeps the public port).
    pub dst_port: u16,
    /// Hairpin match guard (network-order octets); `[0; 4]` ⇒ match any.
    pub match_dst: [u8; 4],
    /// Hairpin source-NAT address (network-order octets); `[0; 4]` ⇒ no SNAT.
    pub snat_ip: [u8; 4],
    /// Policy the internal host's reply arrives under; `0` ⇒ not derived.
    pub reply_policy: PolicyId,
}

/// A resolved tenant policy: the firewall map contents for one `policy_id`.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Policy id (`0` is the default).
    pub id: PolicyId,
    /// The `CONFIG` map entry for this policy.
    pub global: GlobalConfig,
    /// Normalised IPv4 CIDR blocks for this policy's `BLOCKLIST` entries.
    pub blocklist: Vec<Cidr4>,
    /// Normalised IPv6 CIDR blocks for this policy's `BLOCKLIST6` entries.
    /// Filled from the same TOML `blocklist` list — entries containing a `:` are
    /// parsed as IPv6.
    pub blocklist6: Vec<Cidr6>,
    /// This policy's resolved firewall rules, for the `PORT_RULES` and `DST_RULES`
    /// tries.
    pub port_rules: Vec<ResolvedRule>,
    /// C20: the `PORTAL_GATES` entry for this policy, or `None` when it is not
    /// gated. Always `Some` exactly when `global` carries [`ConfigFlags::PORTAL`]
    /// — the two are written by the same apply and read together.
    pub portal: Option<PortalGate>,
}

/// One resolved firewall rule. `src` and `dst` are the optional address
/// constraints (`None` == any) and are mutually exclusive — the parser refuses a
/// rule carrying both, since the two live in different longest-prefix tries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    /// `(proto, destination port)`.
    pub key: PortKey,
    /// The ICMP type, or `0` for "any type" — which is also every protocol that
    /// has no types. It rides in the trie key's formerly-padding byte, so a
    /// typed rule is a separate entry rather than a wider key.
    pub icmp_type: u8,
    /// Scope bits — family and direction — packed into the rule's map value, so
    /// the datapath reads them off a value it has already loaded rather than
    /// paying for another lookup. `0` means "every family, both directions".
    pub scope: u32,
    /// Source-CIDR constraint, or `None` for "from any".
    pub src: Option<Cidr4>,
    /// Destination-CIDR constraint, or `None` for "to any".
    pub dst: Option<Cidr4>,
    /// The IPv6 source constraint, when the rule names one. A rule constrains
    /// one end in one family: the four fields are mutually exclusive, because
    /// each lives in a different longest-prefix trie and a prefix is contiguous
    /// from the front of its key.
    pub src6: Option<Cidr6>,
    /// The IPv6 destination constraint.
    pub dst6: Option<Cidr6>,
    /// What to do on a match.
    pub action: Action,
    /// Log packets this rule matches, regardless of the policy-wide flag.
    pub log: bool,
    /// `(rate, burst)` in packets per second and packets, or `None` when the rule
    /// is unlimited.
    pub limit: Option<(u32, u32)>,
}

/// This host's resolved overlay endpoint. The underlay MAC and egress ifindex
/// are resolved from the OS at load time by the control plane (like
/// [`ResolvedRoute`]), so only the names/overrides are kept here.
#[derive(Debug, Clone)]
pub struct ResolvedOverlay {
    /// This host's VTEP underlay IPv4 (outer source address).
    pub local_vtep_ip: [u8; 4],
    /// Underlay interface whose MAC stamps the outer source (unless overridden).
    pub underlay_iface: String,
    /// Explicit outer source MAC, or `None` to use the underlay interface's MAC.
    pub local_mac: Option<[u8; 6]>,
    /// UDP destination port (host byte order).
    pub udp_port: u16,
    /// Encapsulation code ([`encap_kind`]).
    pub encap: u8,
    /// Underlay path MTU in bytes.
    pub underlay_mtu: u16,
}

/// A resolved ARP-suppression neighbour: a tenant address and the MAC that
/// answers for it (for the `ARP_TABLE` map).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNeighbor {
    /// Tenant VNI the address lives on.
    pub vni: u32,
    /// The tenant IPv4 address (network-order octets).
    pub ip: [u8; 4],
    /// The MAC that answers for it.
    pub mac: [u8; 6],
}

/// A resolved IPv6 ND-suppression neighbour (B3): a tenant IPv6 and the MAC that
/// answers for it (for the `ND_TABLE` map). The IPv6 mirror of
/// [`ResolvedNeighbor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNd6 {
    /// Tenant VNI the address lives on.
    pub vni: u32,
    /// The tenant IPv6 address (network-order octets).
    pub ip: [u8; 16],
    /// The MAC that answers for it.
    pub mac: [u8; 6],
}

/// A resolved interface assignment: which firewall policy *and* which overlay
/// segment (VNI) an interface's traffic belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedInterface {
    /// Interface name (resolved to an ifindex at load time).
    pub name: String,
    /// Firewall policy id (`IFACE_POLICY`).
    pub policy: PolicyId,
    /// Overlay segment / VNI (`IFACE_VNI`). `0` means local-only (no overlay).
    pub vni: u32,
    /// Masquerade (source NAT) traffic leaving this interface (`MASQUERADE`).
    pub masquerade: bool,
    /// The MSS ceiling for SYNs leaving this interface (`MSS_CLAMP`), or `0` for
    /// no clamp.
    pub mss: u16,
    /// Deterministic CGNAT port-block layout for this egress, or a disabled layout.
    pub cgnat: CgnatLayout,
}

/// A resolved overlay forwarding entry: the tenant segment, the inner-destination
/// **prefix** it matches, and the remote endpoint it points at. The egress
/// interface stays a name (resolved to an ifindex at load time).
#[derive(Debug, Clone)]
pub struct ResolvedTunnel {
    /// Tenant VNI this entry belongs to (matched exactly in the LPM trie).
    pub vni: u32,
    /// Inner-destination IPv4 prefix this entry matches (e.g. a whole remote
    /// subnet, or a single `/32` host).
    pub inner_dst: Cidr4,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep_ip: [u8; 4],
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub outer_dst_mac: [u8; 6],
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// A resolved L2 forwarding entry (B1): the tenant segment, the inner
/// destination MAC it matches exactly, and the remote endpoint it points at.
/// The egress interface stays a name (resolved to an ifindex at load time).
#[derive(Debug, Clone)]
pub struct ResolvedMacRoute {
    /// Tenant VNI this entry belongs to (matched exactly in the MAC-FDB).
    pub vni: u32,
    /// Inner destination MAC this entry bridges toward.
    pub mac: [u8; 6],
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep_ip: [u8; 4],
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub outer_dst_mac: [u8; 6],
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// A resolved symmetric-IRB route (B7). See [`IrbRouteCfg`] for why it is keyed on
/// the ingress VNI and separate from a tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIrbRoute {
    /// Tenant segment a packet must arrive on.
    pub vni: u32,
    /// Remote tenant subnet, as a longest-prefix match key.
    pub inner_dst: Cidr4,
    /// The routed VNI to encapsulate with.
    pub l3_vni: u32,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep_ip: [u8; 4],
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub outer_dst_mac: [u8; 6],
    /// Underlay egress interface name.
    pub out_iface: String,
    /// Rewritten inner destination MAC (the egress router).
    pub router_mac: [u8; 6],
    /// Rewritten inner source MAC (this tenant's anycast gateway).
    pub gateway_mac: [u8; 6],
}

/// A resolved BUM head-end replication entry (B2): the tenant segment and the
/// remote endpoint a broadcast/unknown-unicast/multicast frame on it must be
/// flooded to. The agent groups every entry sharing a `vni` into one `FloodSet`
/// for the `FLOOD_LIST` map. The egress interface stays a name (resolved to an
/// ifindex at load time, like [`ResolvedMacRoute`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFloodVtep {
    /// Tenant VNI whose BUM traffic floods to this endpoint.
    pub vni: u32,
    /// Remote VTEP underlay IPv4 (outer destination address).
    pub remote_vtep_ip: [u8; 4],
    /// Next-hop MAC on the underlay toward the remote VTEP.
    pub outer_dst_mac: [u8; 6],
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// This host's resolved SRv6 endpoint (B9). The egress interface stays a name
/// (resolved to an ifindex at load time). The SRv6 analogue of
/// [`ResolvedOverlay`].
#[derive(Debug, Clone)]
pub struct ResolvedSrv6 {
    /// This host's SRv6 source address (outer IPv6 source, network-order octets).
    pub local_src: [u8; 16],
    /// Underlay interface whose MAC stamps the outer source (unless overridden).
    pub underlay_iface: String,
    /// Explicit outer source MAC, or `None` to use the underlay interface's MAC.
    pub local_mac: Option<[u8; 6]>,
    /// Underlay path MTU in bytes.
    pub underlay_mtu: u16,
    /// Trusted decap-peer outer IPv6 sources (network-order octets). A packet to
    /// one of our local SIDs is SRv6-decapsulated only when its outer source is in
    /// this set. Empty ⇒ fail-closed (no decap). Programmed into the `SRV6_PEERS`
    /// map, the SRv6 analogue of `VTEP_PEERS`.
    pub peers: Vec<[u8; 16]>,
}

/// A resolved SRv6 L2 forwarding entry (B9): the tenant segment, the inner
/// destination MAC it matches exactly, and the remote service SID it points at.
/// The egress interface stays a name (resolved to an ifindex at load time). The
/// SRv6 analogue of [`ResolvedMacRoute`].
#[derive(Debug, Clone)]
pub struct ResolvedSrv6Route {
    /// Tenant VNI this entry belongs to (matched exactly in the SRv6 FDB).
    pub vni: u32,
    /// Inner destination MAC this entry bridges toward.
    pub mac: [u8; 6],
    /// Remote `End.DT2U` service SID (outer IPv6 destination, network-order).
    pub remote_sid: [u8; 16],
    /// Next-hop MAC on the underlay toward the remote SID.
    pub outer_dst_mac: [u8; 6],
    /// Underlay egress interface name.
    pub out_iface: String,
}

/// A resolved SRv6 local-SID (B9): the parsed 128-bit SID, the tenant it
/// terminates into, and its endpoint-behaviour code ([`velstra_common::srv6::behavior`]).
#[derive(Debug, Clone)]
pub struct ResolvedSrv6LocalSid {
    /// The instantiated service SID (network-order octets, IPv6 wire form).
    pub sid: [u8; 16],
    /// Tenant VNI this SID terminates into.
    pub vni: u32,
    /// Endpoint-behaviour code point (`END_DT2U` / `END_DT2M`).
    pub behavior: u16,
}

/// Fully-resolved, validated configuration ready to be written into BPF maps.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Per-policy firewall config. Always contains policy `0` (the default).
    pub policies: Vec<PolicyConfig>,
    /// Interface → (policy, vni) assignments (for `IFACE_POLICY` / `IFACE_VNI`).
    pub interfaces: Vec<ResolvedInterface>,
    /// Forwarding rules for the `ROUTES` trie (Phase 2). Currently global.
    pub routes: Vec<ResolvedRoute>,
    /// Load-balancer services for the `SERVICES`/`BACKENDS` maps (Phase 3).
    /// Currently global.
    pub services: Vec<ResolvedService>,
    /// 1:1 DNAT port-forwards for the `PORT_FORWARDS` map (Phase 4).
    pub port_forwards: Vec<ResolvedPortForward>,
    /// C15 SYN-proxy ports.
    pub synproxy: Vec<ResolvedSynProxy>,
    /// This host's overlay endpoint (Phase 4), or `None` if not participating.
    pub overlay: Option<ResolvedOverlay>,
    /// Overlay forwarding entries for the `OVERLAY_FDB` map (Phase 4).
    pub tunnels: Vec<ResolvedTunnel>,
    /// Per-MAC L2 forwarding entries for the `MAC_FDB` map (B1).
    pub mac_routes: Vec<ResolvedMacRoute>,
    /// B7 resolved symmetric-IRB routes.
    pub irb_routes: Vec<ResolvedIrbRoute>,
    /// ARP-suppression neighbours for the `ARP_TABLE` map (Phase 4).
    pub neighbors: Vec<ResolvedNeighbor>,
    /// IPv6 ND-suppression neighbours for the `ND_TABLE` map (B3).
    pub nd_neighbors: Vec<ResolvedNd6>,
    /// BUM head-end replication flood entries for the `FLOOD_LIST` map (B2). The
    /// agent groups these by `vni` into one `FloodSet` per segment.
    pub flood_vteps: Vec<ResolvedFloodVtep>,
    /// NPTv6 (RFC 6296) prefix translations for the `NPTV6` map (C16).
    pub npt66: Vec<ResolvedNpt66>,
    /// C9 stateful-HA conntrack sync, or `None` if this node is not in an HA pair.
    pub conntrack_sync: Option<ResolvedConntrackSync>,
    /// C12 IPFIX flow export.
    pub flow_export: Option<ResolvedFlowExport>,
    /// This host's SRv6 endpoint (B9), or `None` if not running the SRv6 overlay.
    pub srv6: Option<ResolvedSrv6>,
    /// SRv6 per-MAC L2 forwarding entries for the `SRV6_FDB` map (B9).
    pub srv6_routes: Vec<ResolvedSrv6Route>,
    /// SRv6 local-SID instantiations for the `SRV6_LOCAL_SIDS` map (B9 decap).
    pub srv6_local_sids: Vec<ResolvedSrv6LocalSid>,
    /// Host-wide fail-closed switch for the `FAIL_CLOSED` map: drop a packet the
    /// data plane cannot parse instead of passing it. `false` (the default) keeps
    /// the historical fail-open behaviour.
    pub fail_closed: bool,
}

impl RuntimeConfig {
    /// A do-nothing, fail-open config (pass everything). Used when `run` is
    /// invoked without a `--config` file.
    pub fn passthrough() -> Self {
        Self {
            // Pass-everything means pass-everything: an unparseable packet is
            // passed too, matching this config's whole premise.
            fail_closed: false,
            policies: vec![PolicyConfig {
                id: 0,
                global: GlobalConfig::new(Action::Pass, 0),
                portal: None,
                blocklist: Vec::new(),
                blocklist6: Vec::new(),
                port_rules: Vec::new(),
            }],
            interfaces: Vec::new(),
            routes: Vec::new(),
            services: Vec::new(),
            port_forwards: Vec::new(),
            synproxy: Vec::new(),
            overlay: None,
            tunnels: Vec::new(),
            mac_routes: Vec::new(),
            irb_routes: Vec::new(),
            neighbors: Vec::new(),
            nd_neighbors: Vec::new(),
            flood_vteps: Vec::new(),
            npt66: Vec::new(),
            conntrack_sync: None,
            flow_export: None,
            srv6: None,
            srv6_routes: Vec::new(),
            srv6_local_sids: Vec::new(),
        }
    }
}

/// Parse and validate a `[conntrack_sync]` block into its resolved form.
fn resolve_conntrack_sync(cfg: &ConntrackSyncCfg) -> Result<ResolvedConntrackSync> {
    let listen: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("conntrack_sync.listen `{}` is not an ip:port", cfg.listen))?;
    let mut peers = Vec::with_capacity(cfg.peer.len());
    for p in &cfg.peer {
        let addr: SocketAddr = p
            .parse()
            .with_context(|| format!("conntrack_sync.peer `{p}` is not an ip:port"))?;
        peers.push(addr);
    }
    Ok(ResolvedConntrackSync {
        listen,
        peers,
        // Never sleep zero seconds — a `0` in TOML would spin the push loop.
        interval_secs: cfg.interval_secs.max(1),
    })
}

/// Resolve one policy's firewall fields into map contents.
#[allow(clippy::too_many_arguments)]
fn resolve_firewall(
    id: PolicyId,
    default_action: ActionName,
    drop_icmp: bool,
    log: bool,
    stateful: bool,
    source_validation: SourceValidationName,
    blocklist: &[String],
    port_rules: &[PortRule],
    portal: Option<&PortalCfg>,
) -> Result<PolicyConfig> {
    let mut flags = source_validation.flags();
    if drop_icmp {
        flags |= ConfigFlags::DROP_ICMP;
    }
    if log {
        flags |= ConfigFlags::LOG;
    }
    if stateful {
        flags |= ConfigFlags::STATEFUL;
    }
    let portal = resolve_portal(id, portal)?;
    if portal.is_some() {
        flags |= ConfigFlags::PORTAL;
    }
    let global = GlobalConfig::new(default_action.into(), flags);

    // One TOML `blocklist` list holds both address families; an entry with a `:`
    // is IPv6, everything else IPv4. They land in separate maps but share the
    // policy.
    let mut cidrs = Vec::new();
    let mut cidrs6 = Vec::new();
    for entry in blocklist {
        if entry.contains(':') {
            let cidr = parse_cidr_v6(entry).map_err(|e| {
                anyhow::anyhow!("policy {id}: invalid IPv6 blocklist entry {entry:?}: {e}")
            })?;
            cidrs6.push(cidr);
        } else {
            let cidr = parse_cidr_v4(entry).map_err(|e| {
                anyhow::anyhow!("policy {id}: invalid blocklist entry {entry:?}: {e}")
            })?;
            cidrs.push(cidr);
        }
    }

    let mut rules = Vec::with_capacity(port_rules.len());
    for rule in port_rules {
        // A protocol with no ports is keyed at port 0 — that is what "matches
        // every packet of this protocol the rule scopes" compiles to, and the
        // data plane reads 0 off a packet that carries no ports. What is still
        // wrong is a *port* on such a protocol: it would silently match nothing.
        //
        // This used to refuse every ICMP rule outright, from before a rule could
        // name a port-less protocol at all. The schema was updated when that
        // landed and this check was not, so the control plane emitted rules the
        // data plane's own loader then rejected — the feature never worked end
        // to end.
        // A type belongs to ICMP the way a port belongs to TCP. Silently
        // ignoring it on anything else would produce a rule that reads as
        // narrow and matches everything of that protocol.
        if rule.icmp_type.is_some()
            && !matches!(rule.proto.number(), ip_proto::ICMP | ip_proto::ICMPV6)
        {
            bail!(
                "policy {id}: icmp-type is only for icmp and icmpv6, not protocol {}",
                rule.proto.number()
            );
        }
        if !rule.proto.has_ports() && rule.port != 0 {
            bail!(
                "policy {id}: {} carries no ports, so port {} cannot match; drop the port",
                rule.proto.number(),
                rule.port
            );
        }
        if rule.src.is_some() && rule.dst.is_some() {
            bail!(
                "policy {id}: rule on {}/{} sets both src and dst; the data plane \
                 ranks one address dimension per rule, so split it into two rules",
                rule.proto.number(),
                rule.port
            );
        }
        // One field, either family: a rule's `src`/`dst` is a string, and which
        // trie it belongs to follows from what it says. An operator writing
        // `fd12::/64` means the same thing they mean by `10.0.0.0/8`, and having
        // to remember a second field name for it is a distinction the
        // configuration should not have.
        let (src, src6) = match &rule.src {
            Some(cidr) if cidr.contains(':') => (
                None,
                Some(parse_cidr_v6(cidr).map_err(|e| {
                    anyhow::anyhow!("policy {id}: invalid rule source {cidr:?}: {e}")
                })?),
            ),
            Some(cidr) => (
                Some(parse_cidr_v4(cidr).map_err(|e| {
                    anyhow::anyhow!("policy {id}: invalid rule source {cidr:?}: {e}")
                })?),
                None,
            ),
            None => (None, None),
        };
        let (dst, dst6) = match &rule.dst {
            Some(cidr) if cidr.contains(':') => (
                None,
                Some(parse_cidr_v6(cidr).map_err(|e| {
                    anyhow::anyhow!("policy {id}: invalid rule destination {cidr:?}: {e}")
                })?),
            ),
            Some(cidr) => (
                Some(parse_cidr_v4(cidr).map_err(|e| {
                    anyhow::anyhow!("policy {id}: invalid rule destination {cidr:?}: {e}")
                })?),
                None,
            ),
            None => (None, None),
        };
        // A limit is only meaningful where the rule would let traffic through;
        // attaching one to a drop rule reads as "throttle these" and does nothing,
        // so refuse it rather than accept a rule that cannot behave as written.
        let limit = match rule.limit.filter(|r| *r > 0) {
            Some(rate) => {
                if rule.action != ActionName::Pass {
                    bail!(
                        "policy {id}: rule on {}/{} sets a rate limit on a non-pass action; \
                         a limit throttles traffic a rule admits",
                        rule.proto.number(),
                        rule.port
                    );
                }
                // Default the burst to one second of the rate: a bucket of one
                // would admit a single packet and then meter every following one,
                // which no operator means by "limit 100/s".
                Some((rate, rule.burst.filter(|b| *b > 0).unwrap_or(rate)))
            }
            None => None,
        };
        // Family and direction, resolved to the two bit pairs the data plane
        // reads off the value. An unset field contributes nothing, which is how
        // "both" stays the default without a third state to carry.
        let mut scope = 0u32;
        match rule.family.as_deref() {
            None => {}
            Some("ipv4") => scope |= PORT_RULE_V4_ONLY,
            Some("ipv6") => scope |= PORT_RULE_V6_ONLY,
            Some(other) => bail!("policy {id}: family {other:?} is not ipv4 or ipv6"),
        }
        match rule.direction.as_deref() {
            None => {}
            Some("in") => scope |= PORT_RULE_IN_ONLY,
            Some("out") => scope |= PORT_RULE_OUT_ONLY,
            Some(other) => bail!("policy {id}: direction {other:?} is not in or out"),
        }
        // The egress hook is IPv4 only, so an IPv6 rule scoped to `out` would be
        // written and never consulted. Refusing beats enforcing nothing quietly.
        if scope & PORT_RULE_V6_ONLY != 0 && scope & PORT_RULE_OUT_ONLY != 0 {
            bail!(
                "policy {id}: direction \"out\" is IPv4 only — an ipv6 rule on the \
                 egress hook would never be consulted"
            );
        }
        rules.push(ResolvedRule {
            key: PortKey::new(rule.proto.number(), rule.port),
            icmp_type: rule.icmp_type.unwrap_or(0),
            scope,
            src,
            dst,
            src6,
            dst6,
            action: rule.action.into(),
            log: rule.log,
            limit,
        });
    }

    Ok(PolicyConfig {
        id,
        global,
        blocklist: cidrs,
        blocklist6: cidrs6,
        port_rules: rules,
        portal,
    })
}

/// Resolve a policy's `portal = { … }` block into its `PORTAL_GATES` entry.
///
/// A portal with no address at all is **refused**. It would parse, and it would
/// gate the zone — closing it to everything but DHCP and Neighbor Discovery,
/// with nowhere for a client to go and no way to be admitted. That is not a
/// portal, it is a zone that is off, and an operator who meant that would have
/// said `default_action = "drop"`.
fn resolve_portal(id: PolicyId, portal: Option<&PortalCfg>) -> Result<Option<PortalGate>> {
    let Some(cfg) = portal else {
        return Ok(None);
    };
    let portal4 = match &cfg.address {
        Some(addr) => addr
            .parse::<std::net::Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("policy {id}: invalid portal address {addr:?}: {e}"))?
            .octets(),
        None => [0; 4],
    };
    let portal6 = match &cfg.address6 {
        Some(addr) => addr
            .parse::<std::net::Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("policy {id}: invalid portal address {addr:?}: {e}"))?
            .octets(),
        None => [0; 16],
    };
    if portal4 == [0; 4] && portal6 == [0; 16] {
        bail!(
            "policy {id}: a captive portal needs an address for clients to reach; \
             without one the zone is simply closed"
        );
    }
    Ok(Some(PortalGate::new(portal4, portal6)))
}

impl FileConfig {
    /// Validate the document and resolve it into a [`RuntimeConfig`].
    ///
    /// Fails if a CIDR is malformed, a port-less protocol carries a port, or two
    /// policies share an id.
    pub fn resolve(&self) -> Result<RuntimeConfig> {
        // Policy 0 is the top-level config; `[[policy]]` blocks add tenants.
        let mut policies = vec![resolve_firewall(
            0,
            self.default_action,
            self.drop_icmp,
            self.log,
            self.stateful,
            self.source_validation,
            &self.blocklist,
            &self.port_rules,
            self.portal.as_ref(),
        )?];
        for policy in &self.policies {
            if policy.id == 0 {
                bail!("`[[policy]]` id 0 is reserved for the top-level config");
            }
            if policies.iter().any(|p| p.id == policy.id) {
                bail!("duplicate policy id {}", policy.id);
            }
            policies.push(resolve_firewall(
                policy.id,
                policy.default_action,
                policy.drop_icmp,
                policy.log,
                policy.stateful,
                policy.source_validation,
                &policy.blocklist,
                &policy.port_rules,
                policy.portal.as_ref(),
            )?);
        }

        // The blocklist tries are one map each across every policy, so the limit
        // is a total. Refusing here beats discovering it as a half-programmed
        // firewall: the insert that hits the ceiling fails, and the entries after
        // it are simply never written.
        for (family, count) in [
            (
                "IPv4",
                policies.iter().map(|p| p.blocklist.len()).sum::<usize>(),
            ),
            (
                "IPv6",
                policies.iter().map(|p| p.blocklist6.len()).sum::<usize>(),
            ),
        ] {
            if count > MAX_BLOCKLIST as usize {
                bail!(
                    "blocklist: {count} {family} entries across all policies exceeds the \
                     data plane's {MAX_BLOCKLIST}"
                );
            }
        }

        let overlay_present = self.overlay.is_some();
        let mut interfaces = Vec::with_capacity(self.interfaces.len());
        for iface in &self.interfaces {
            if !policies.iter().any(|p| p.id == iface.policy) {
                bail!(
                    "interface {:?} references unknown policy id {}",
                    iface.name,
                    iface.policy
                );
            }
            // The VNI is independent of the policy, but defaults to it for the
            // common single-tenant case where one number names both.
            let vni = iface.vni.unwrap_or(iface.policy);
            if overlay_present && vni > 0xFF_FFFF {
                bail!("interface {:?} vni {vni} exceeds 24 bits", iface.name);
            }
            interfaces.push(ResolvedInterface {
                name: iface.name.clone(),
                policy: iface.policy,
                vni,
                masquerade: iface.masquerade,
                // 536 is the smallest MSS a sender may be asked for (RFC 1122's
                // floor for IPv4); below it the clamp would be refusing to carry
                // ordinary traffic rather than making it fit.
                mss: match iface.mss {
                    Some(m) if m < 536 => {
                        bail!(
                            "interface {:?}: mss {m} is below the RFC 1122 floor of 536",
                            iface.name
                        )
                    }
                    Some(m) => m,
                    None => 0,
                },
                cgnat: CgnatLayout::new(iface.cgnat_base_port, iface.cgnat_block_size),
            });
        }

        let mut routes = Vec::with_capacity(self.routes.len());
        for route in &self.routes {
            if !policies.iter().any(|p| p.id == route.policy) {
                bail!(
                    "route {:?} references unknown policy id {}",
                    route.dest,
                    route.policy
                );
            }
            let dest = parse_cidr_v4(&route.dest)
                .map_err(|e| anyhow::anyhow!("invalid route dest {:?}: {e}", route.dest))?;
            let dst_mac = parse_mac(&route.via_mac)
                .map_err(|e| anyhow::anyhow!("invalid via_mac {:?}: {e}", route.via_mac))?;
            let src_mac = match &route.src_mac {
                Some(mac) => Some(
                    parse_mac(mac).map_err(|e| anyhow::anyhow!("invalid src_mac {mac:?}: {e}"))?,
                ),
                None => None,
            };
            routes.push(ResolvedRoute {
                policy: route.policy,
                dest,
                out_iface: route.out_iface.clone(),
                src_mac,
                dst_mac,
                flags: route.mode.flags(),
            });
        }

        let mut services = Vec::with_capacity(self.services.len());
        for service in &self.services {
            if !policies.iter().any(|p| p.id == service.policy) {
                bail!(
                    "service {}:{} references unknown policy id {}",
                    service.vip,
                    service.port,
                    service.policy
                );
            }
            let proto = match service.proto {
                ProtoName::Tcp => ip_proto::TCP,
                ProtoName::Udp => ip_proto::UDP,
                // Everything else has no ports, so it cannot front a service.
                _ => bail!("load-balancer service protocol must be tcp or udp"),
            };
            let vip: Ipv4Addr = service
                .vip
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid service vip {:?}", service.vip))?;
            if service.backends.is_empty() {
                bail!("service {}:{} has no backends", service.vip, service.port);
            }
            let mut backends = Vec::with_capacity(service.backends.len());
            for backend in &service.backends {
                let ip: Ipv4Addr = backend
                    .ip
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid backend ip {:?}", backend.ip))?;
                backends.push(Backend::new(ip.octets(), backend.port.unwrap_or(0)));
            }
            services.push(ResolvedService {
                key: ServiceKey::new(service.policy, vip.octets(), service.port, proto),
                backends,
                router_nat: service.router_nat,
                reply_policy: service.reply_policy,
            });
        }

        // Phase 4: 1:1 DNAT port-forwards.
        // C15 SYN proxy. Refused rather than clamped on a bad MSS: a proxy that
        // silently advertises something other than what was written would be
        // discovered as a throughput mystery months later. 536 is the IPv4
        // minimum every implementation must accept; 1460 the untunnelled
        // Ethernet maximum, and offering more than the path carries is the one
        // direction that breaks.
        let mut synproxy = Vec::with_capacity(self.synproxy.len());
        for sp in &self.synproxy {
            if sp.port == 0 {
                bail!("synproxy port must not be 0");
            }
            if sp.mss < 536 || sp.mss > 1460 {
                bail!(
                    "synproxy port {} mss {} is outside 536..=1460",
                    sp.port,
                    sp.mss
                );
            }
            if synproxy
                .iter()
                .any(|s: &ResolvedSynProxy| s.port == sp.port)
            {
                bail!("synproxy port {} is configured twice", sp.port);
            }
            synproxy.push(ResolvedSynProxy {
                port: sp.port,
                mss: sp.mss,
            });
        }

        let mut port_forwards = Vec::with_capacity(self.port_forwards.len());
        for pf in &self.port_forwards {
            let proto = match pf.proto {
                ProtoName::Tcp => ip_proto::TCP,
                ProtoName::Udp => ip_proto::UDP,
                // Everything else has no ports, so there is nothing to forward.
                _ => bail!("port-forward protocol must be tcp or udp"),
            };
            if !policies.iter().any(|p| p.id == pf.policy) {
                bail!("port-forward references unknown policy id {}", pf.policy);
            }
            let dst_ip: Ipv4Addr = pf
                .dst_ip
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port-forward dst_ip {:?}", pf.dst_ip))?;
            // Optional hairpin (NAT reflection) fields; each defaults to the zero
            // address (match-any / no-SNAT) when unset.
            let parse_opt_v4 = |field: &str, v: &Option<String>| -> Result<[u8; 4]> {
                match v {
                    Some(s) => {
                        let a: Ipv4Addr = s
                            .parse()
                            .map_err(|_| anyhow::anyhow!("invalid port-forward {field} {s:?}"))?;
                        Ok(a.octets())
                    }
                    None => Ok([0; 4]),
                }
            };
            let match_dst = parse_opt_v4("match_dst", &pf.match_dst)?;
            let snat_ip = parse_opt_v4("snat_ip", &pf.snat_ip)?;
            port_forwards.push(ResolvedPortForward {
                policy: pf.policy,
                proto,
                port: pf.port,
                dst_ip: dst_ip.octets(),
                dst_port: pf.dst_port,
                match_dst,
                snat_ip,
                reply_policy: pf.reply_policy,
            });
        }

        // C16: NPTv6 (RFC 6296) prefix translations. Both prefixes must parse as
        // v6 CIDRs of equal length, and (v1) a non-zero multiple of 16 bits ≤ /64.
        let mut npt66 = Vec::with_capacity(self.npt66.len());
        for rule in &self.npt66 {
            let int = parse_cidr_v6(&rule.internal).map_err(|e| {
                anyhow::anyhow!(
                    "npt66 {}: invalid internal prefix {:?}: {e}",
                    rule.interface,
                    rule.internal
                )
            })?;
            let ext = parse_cidr_v6(&rule.external).map_err(|e| {
                anyhow::anyhow!(
                    "npt66 {}: invalid external prefix {:?}: {e}",
                    rule.interface,
                    rule.external
                )
            })?;
            if int.prefix != ext.prefix {
                bail!(
                    "npt66 {}: internal /{} and external /{} prefix lengths must match",
                    rule.interface,
                    int.prefix,
                    ext.prefix
                );
            }
            if int.prefix == 0 || int.prefix > 64 || int.prefix % 16 != 0 {
                bail!(
                    "npt66 {}: prefix /{} must be a non-zero multiple of 16 bits, ≤ /64 (v1)",
                    rule.interface,
                    int.prefix
                );
            }
            npt66.push(ResolvedNpt66 {
                interface: rule.interface.clone(),
                npt: Npt66::new(int.octets, ext.octets, (int.prefix / 16) as u8),
            });
        }

        // Phase 4: overlay endpoint + forwarding entries.
        let overlay = match &self.overlay {
            Some(o) => {
                let local_vtep_ip: Ipv4Addr = o.local_vtep.parse().map_err(|_| {
                    anyhow::anyhow!("invalid overlay local_vtep {:?}", o.local_vtep)
                })?;
                let local_mac =
                    match &o.local_mac {
                        Some(mac) => Some(parse_mac(mac).map_err(|e| {
                            anyhow::anyhow!("invalid overlay local_mac {mac:?}: {e}")
                        })?),
                        None => None,
                    };
                Some(ResolvedOverlay {
                    local_vtep_ip: local_vtep_ip.octets(),
                    underlay_iface: o.underlay_iface.clone(),
                    local_mac,
                    udp_port: o.udp_port.unwrap_or_else(|| o.encap.default_port()),
                    encap: o.encap.kind(),
                    underlay_mtu: o.underlay_mtu.unwrap_or(1500),
                })
            }
            None => None,
        };

        if !self.tunnels.is_empty() && overlay.is_none() {
            bail!("`[[tunnel]]` entries require an `[overlay]` section");
        }
        let mut tunnels = Vec::with_capacity(self.tunnels.len());
        for tunnel in &self.tunnels {
            if tunnel.vni > 0xFF_FFFF {
                bail!("tunnel vni {} exceeds 24 bits", tunnel.vni);
            }
            // `inner_dst` is a CIDR: a whole remote subnet (one LPM entry) or a
            // bare host (`/32`).
            let inner_dst = parse_cidr_v4(&tunnel.inner_dst).map_err(|e| {
                anyhow::anyhow!("invalid tunnel inner_dst {:?}: {e}", tunnel.inner_dst)
            })?;
            let remote_vtep: Ipv4Addr = tunnel.remote_vtep.parse().map_err(|_| {
                anyhow::anyhow!("invalid tunnel remote_vtep {:?}", tunnel.remote_vtep)
            })?;
            let outer_dst_mac = parse_mac(&tunnel.via_mac)
                .map_err(|e| anyhow::anyhow!("invalid tunnel via_mac {:?}: {e}", tunnel.via_mac))?;
            tunnels.push(ResolvedTunnel {
                vni: tunnel.vni,
                inner_dst,
                remote_vtep_ip: remote_vtep.octets(),
                outer_dst_mac,
                out_iface: tunnel.out_iface.clone(),
            });
        }

        if !self.mac_routes.is_empty() && overlay.is_none() {
            bail!("`[[mac_route]]` entries require an `[overlay]` section");
        }
        let mut mac_routes = Vec::with_capacity(self.mac_routes.len());
        for mr in &self.mac_routes {
            if mr.vni > 0xFF_FFFF {
                bail!("mac_route vni {} exceeds 24 bits", mr.vni);
            }
            let mac = parse_mac(&mr.mac)
                .map_err(|e| anyhow::anyhow!("invalid mac_route mac {:?}: {e}", mr.mac))?;
            let remote_vtep: Ipv4Addr = mr.remote_vtep.parse().map_err(|_| {
                anyhow::anyhow!("invalid mac_route remote_vtep {:?}", mr.remote_vtep)
            })?;
            let outer_dst_mac = parse_mac(&mr.via_mac)
                .map_err(|e| anyhow::anyhow!("invalid mac_route via_mac {:?}: {e}", mr.via_mac))?;
            mac_routes.push(ResolvedMacRoute {
                vni: mr.vni,
                mac,
                remote_vtep_ip: remote_vtep.octets(),
                outer_dst_mac,
                out_iface: mr.out_iface.clone(),
            });
        }

        if !self.irb_routes.is_empty() && overlay.is_none() {
            bail!("`[[irb_route]]` entries require an `[overlay]` section");
        }
        let mut irb_routes = Vec::with_capacity(self.irb_routes.len());
        for r in &self.irb_routes {
            for (label, vni) in [("vni", r.vni), ("l3_vni", r.l3_vni)] {
                if vni > 0xFF_FFFF {
                    bail!("irb_route {label} {vni} exceeds 24 bits");
                }
            }
            let inner_dst = parse_cidr_v4(&r.inner_dst).map_err(|e| {
                anyhow::anyhow!("invalid irb_route inner_dst {:?}: {e}", r.inner_dst)
            })?;
            let remote_vtep: Ipv4Addr = r.remote_vtep.parse().map_err(|_| {
                anyhow::anyhow!("invalid irb_route remote_vtep {:?}", r.remote_vtep)
            })?;
            let mut macs = [[0u8; 6]; 3];
            for (slot, (label, text)) in macs.iter_mut().zip([
                ("via_mac", &r.via_mac),
                ("router_mac", &r.router_mac),
                ("gateway_mac", &r.gateway_mac),
            ]) {
                *slot = parse_mac(text)
                    .map_err(|e| anyhow::anyhow!("invalid irb_route {label} {text:?}: {e}"))?;
            }
            irb_routes.push(ResolvedIrbRoute {
                vni: r.vni,
                inner_dst,
                l3_vni: r.l3_vni,
                remote_vtep_ip: remote_vtep.octets(),
                outer_dst_mac: macs[0],
                out_iface: r.out_iface.clone(),
                router_mac: macs[1],
                gateway_mac: macs[2],
            });
        }

        if !self.neighbors.is_empty() && overlay.is_none() {
            bail!("`[[neighbor]]` entries require an `[overlay]` section");
        }
        let mut neighbors = Vec::with_capacity(self.neighbors.len());
        for n in &self.neighbors {
            if n.vni > 0xFF_FFFF {
                bail!("neighbor vni {} exceeds 24 bits", n.vni);
            }
            let ip: Ipv4Addr =
                n.ip.parse()
                    .map_err(|_| anyhow::anyhow!("invalid neighbor ip {:?}", n.ip))?;
            let mac = parse_mac(&n.mac)
                .map_err(|e| anyhow::anyhow!("invalid neighbor mac {:?}: {e}", n.mac))?;
            neighbors.push(ResolvedNeighbor {
                vni: n.vni,
                ip: ip.octets(),
                mac,
            });
        }

        if !self.nd_neighbors.is_empty() && overlay.is_none() {
            bail!("`[[nd_neighbor]]` entries require an `[overlay]` section");
        }
        let mut nd_neighbors = Vec::with_capacity(self.nd_neighbors.len());
        for n in &self.nd_neighbors {
            if n.vni > 0xFF_FFFF {
                bail!("nd_neighbor vni {} exceeds 24 bits", n.vni);
            }
            let ip: Ipv6Addr =
                n.ip.parse()
                    .map_err(|_| anyhow::anyhow!("invalid nd_neighbor ip {:?}", n.ip))?;
            let mac = parse_mac(&n.mac)
                .map_err(|e| anyhow::anyhow!("invalid nd_neighbor mac {:?}: {e}", n.mac))?;
            nd_neighbors.push(ResolvedNd6 {
                vni: n.vni,
                ip: ip.octets(),
                mac,
            });
        }

        if !self.flood_vteps.is_empty() && overlay.is_none() {
            bail!("`[[flood_vtep]]` entries require an `[overlay]` section");
        }
        let mut flood_vteps = Vec::with_capacity(self.flood_vteps.len());
        for fv in &self.flood_vteps {
            if fv.vni > 0xFF_FFFF {
                bail!("flood_vtep vni {} exceeds 24 bits", fv.vni);
            }
            let remote_vtep: Ipv4Addr = fv.remote_vtep.parse().map_err(|_| {
                anyhow::anyhow!("invalid flood_vtep remote_vtep {:?}", fv.remote_vtep)
            })?;
            let outer_dst_mac = parse_mac(&fv.via_mac)
                .map_err(|e| anyhow::anyhow!("invalid flood_vtep via_mac {:?}: {e}", fv.via_mac))?;
            flood_vteps.push(ResolvedFloodVtep {
                vni: fv.vni,
                remote_vtep_ip: remote_vtep.octets(),
                outer_dst_mac,
                out_iface: fv.out_iface.clone(),
            });
        }

        // Phase 4 (B9): SRv6 endpoint + forwarding entries. SRv6 and VXLAN/Geneve
        // are mutually exclusive per host (one overlay wire format at a time).
        if self.srv6.is_some() && overlay.is_some() {
            bail!("`[srv6]` and `[overlay]` are mutually exclusive (one overlay format per host)");
        }
        let srv6 = match &self.srv6 {
            Some(s) => {
                let local_src: Ipv6Addr = s
                    .local_src
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid srv6 local_src {:?}", s.local_src))?;
                let local_mac = match &s.local_mac {
                    Some(mac) => Some(
                        parse_mac(mac)
                            .map_err(|e| anyhow::anyhow!("invalid srv6 local_mac {mac:?}: {e}"))?,
                    ),
                    None => None,
                };
                let mut peers = Vec::with_capacity(s.peers.len());
                for p in &s.peers {
                    let ip: Ipv6Addr = p
                        .parse()
                        .map_err(|_| anyhow::anyhow!("invalid srv6 peer {p:?}"))?;
                    peers.push(ip.octets());
                }
                Some(ResolvedSrv6 {
                    local_src: local_src.octets(),
                    underlay_iface: s.underlay_iface.clone(),
                    local_mac,
                    underlay_mtu: s.underlay_mtu.unwrap_or(1500),
                    peers,
                })
            }
            None => None,
        };

        if !self.srv6_routes.is_empty() && srv6.is_none() {
            bail!("`[[srv6_route]]` entries require an `[srv6]` section");
        }
        let mut srv6_routes = Vec::with_capacity(self.srv6_routes.len());
        for sr in &self.srv6_routes {
            if sr.vni > 0xFF_FFFF {
                bail!("srv6_route vni {} exceeds 24 bits", sr.vni);
            }
            let mac = parse_mac(&sr.mac)
                .map_err(|e| anyhow::anyhow!("invalid srv6_route mac {:?}: {e}", sr.mac))?;
            let remote_sid: Ipv6Addr = sr.remote_sid.parse().map_err(|_| {
                anyhow::anyhow!("invalid srv6_route remote_sid {:?}", sr.remote_sid)
            })?;
            let outer_dst_mac = parse_mac(&sr.via_mac)
                .map_err(|e| anyhow::anyhow!("invalid srv6_route via_mac {:?}: {e}", sr.via_mac))?;
            srv6_routes.push(ResolvedSrv6Route {
                vni: sr.vni,
                mac,
                remote_sid: remote_sid.octets(),
                outer_dst_mac,
                out_iface: sr.out_iface.clone(),
            });
        }

        if !self.srv6_local_sids.is_empty() && srv6.is_none() {
            bail!("`[[srv6_local_sid]]` entries require an `[srv6]` section");
        }
        let mut srv6_local_sids = Vec::with_capacity(self.srv6_local_sids.len());
        for ls in &self.srv6_local_sids {
            if ls.vni > 0xFF_FFFF {
                bail!("srv6_local_sid vni {} exceeds 24 bits", ls.vni);
            }
            let sid: Ipv6Addr = ls
                .sid
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid srv6_local_sid sid {:?}", ls.sid))?;
            let behavior = match ls.behavior.as_deref().unwrap_or("end.dt2u") {
                "end.dt2u" => velstra_common::srv6::behavior::END_DT2U,
                "end.dt2m" => velstra_common::srv6::behavior::END_DT2M,
                other => bail!(
                    "invalid srv6_local_sid behavior {other:?} (expected end.dt2u or end.dt2m)"
                ),
            };
            srv6_local_sids.push(ResolvedSrv6LocalSid {
                sid: sid.octets(),
                vni: ls.vni,
                behavior,
            });
        }

        Ok(RuntimeConfig {
            fail_closed: self.fail_closed,
            policies,
            interfaces,
            routes,
            services,
            port_forwards,
            synproxy,
            overlay,
            tunnels,
            mac_routes,
            irb_routes,
            neighbors,
            nd_neighbors,
            flood_vteps,
            npt66,
            conntrack_sync: self
                .conntrack_sync
                .as_ref()
                .map(resolve_conntrack_sync)
                .transpose()?,
            flow_export: self
                .flow_export
                .as_ref()
                .map(|f| {
                    if f.collector.trim().is_empty() {
                        anyhow::bail!("flow_export.collector must not be empty");
                    }
                    // The address is NOT resolved here. A collector named by
                    // hostname may well not resolve at boot — the appliance is
                    // often what its DNS depends on — and refusing the whole
                    // config for that would take the firewall down to lose a
                    // graph. The exporter resolves when it starts instead.
                    Ok(ResolvedFlowExport {
                        collector: f.collector.trim().to_string(),
                        interval_secs: f.interval_secs.max(1),
                        observation_domain: f.observation_domain,
                    })
                })
                .transpose()?,
            srv6,
            srv6_routes,
            srv6_local_sids,
        })
    }
}

/// Read, parse and resolve a config file in one step.
pub fn load_file(path: &Path) -> Result<RuntimeConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let file: FileConfig =
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))?;
    file.resolve()
}

impl fmt::Display for RuntimeConfig {
    /// Human-readable summary, used by `velstra validate`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "policies       : {}", self.policies.len())?;
        for policy in &self.policies {
            let default = match policy.global.default_action() {
                Action::Pass => "pass",
                Action::Drop => "drop",
                Action::Reject => "reject",
            };
            writeln!(
                f,
                "  policy {} : default={default}, drop_icmp={}, stateful={}, log={}, \
                 source_validation={}",
                policy.id,
                policy.global.has_flag(ConfigFlags::DROP_ICMP),
                policy.global.has_flag(ConfigFlags::STATEFUL),
                policy.global.has_flag(ConfigFlags::LOG),
                match policy.global.source_validation() {
                    SourceValidation::Disabled => "disable",
                    SourceValidation::Loose => "loose",
                    SourceValidation::Strict => "strict",
                },
            )?;
            for cidr in &policy.blocklist {
                writeln!(f, "      block {cidr}")?;
            }
            for cidr in &policy.blocklist6 {
                writeln!(f, "      block6 {cidr}")?;
            }
            for rule in &policy.port_rules {
                let (key, action) = (rule.key, rule.action);
                let show = |c: &Cidr4| {
                    format!("{}/{}", c.octets.map(|o| o.to_string()).join("."), c.prefix)
                };
                let from = match (&rule.src, &rule.dst) {
                    (Some(c), _) => format!(" from {}", show(c)),
                    (_, Some(c)) => format!(" to {}", show(c)),
                    _ => String::new(),
                };
                // A rule that names an ICMP type has to say so here. A summary
                // that shows two identical lines for a typed rule and an untyped
                // one is a summary that cannot be used to check either.
                let typed = if rule.icmp_type == 0 {
                    String::new()
                } else {
                    format!(" type {}", rule.icmp_type)
                };
                // Family and direction, for the same reason: a rule scoped to
                // one of them and one scoped to neither must not print alike.
                let mut scope = String::new();
                if rule.scope & PORT_RULE_V4_ONLY != 0 {
                    scope.push_str(" ipv4");
                }
                if rule.scope & PORT_RULE_V6_ONLY != 0 {
                    scope.push_str(" ipv6");
                }
                if rule.scope & PORT_RULE_IN_ONLY != 0 {
                    scope.push_str(" in");
                }
                if rule.scope & PORT_RULE_OUT_ONLY != 0 {
                    scope.push_str(" out");
                }
                let proto = match key.proto {
                    ip_proto::TCP => "tcp",
                    ip_proto::UDP => "udp",
                    other => {
                        writeln!(
                            f,
                            "      proto {other}{typed} port {} ->{from}{scope} {action:?}",
                            key.port
                        )?;
                        continue;
                    }
                };
                let verdict = match action {
                    Action::Pass => "pass",
                    Action::Drop => "drop",
                    Action::Reject => "reject",
                };
                writeln!(f, "      {proto}/{} ->{from}{scope} {verdict}", key.port)?;
            }
        }

        writeln!(f, "interfaces     : {}", self.interfaces.len())?;
        for iface in &self.interfaces {
            if iface.vni != 0 && iface.vni != iface.policy {
                writeln!(
                    f,
                    "  - {} -> policy {} (vni {})",
                    iface.name, iface.policy, iface.vni
                )?;
            } else {
                writeln!(f, "  - {} -> policy {}", iface.name, iface.policy)?;
            }
        }

        writeln!(f, "routes         : {} route(s)", self.routes.len())?;
        for route in &self.routes {
            let mode = if route.flags & RouteEntry::DECREMENT_TTL != 0 {
                "route"
            } else {
                "switch"
            };
            let [a, b, c, d, e, ff] = route.dst_mac;
            let src = match route.src_mac {
                Some(m) => {
                    let [a, b, c, d, e, ff] = m;
                    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x}")
                }
                None => format!("<{}'s mac>", route.out_iface),
            };
            writeln!(
                f,
                "  - {} via {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x} dev {} ({mode}, src {src})",
                route.dest, route.out_iface,
            )?;
        }

        writeln!(f, "services       : {} service(s)", self.services.len())?;
        for service in &self.services {
            let [a, b, c, d] = service.key.vip;
            let proto = match service.key.proto {
                ip_proto::TCP => "tcp",
                ip_proto::UDP => "udp",
                other => {
                    writeln!(f, "  - proto {other} (unknown)")?;
                    continue;
                }
            };
            writeln!(
                f,
                "  - {proto} {a}.{b}.{c}.{d}:{} -> {} backend(s)",
                service.key.port,
                service.backends.len()
            )?;
            for backend in &service.backends {
                let [w, x, y, z] = backend.ip;
                if backend.port == 0 {
                    writeln!(f, "      {w}.{x}.{y}.{z} (keep port)")?;
                } else {
                    writeln!(f, "      {w}.{x}.{y}.{z}:{}", backend.port)?;
                }
            }
        }

        match &self.overlay {
            Some(o) => {
                let [a, b, c, d] = o.local_vtep_ip;
                let encap = if o.encap == encap_kind::GENEVE {
                    "geneve"
                } else {
                    "vxlan"
                };
                writeln!(
                    f,
                    "overlay        : {encap} vtep {a}.{b}.{c}.{d} dev {} udp/{}",
                    o.underlay_iface, o.udp_port,
                )?;
            }
            None => writeln!(f, "overlay        : disabled")?,
        }
        writeln!(f, "tunnels        : {} entry(ies)", self.tunnels.len())?;
        for tunnel in &self.tunnels {
            let [r0, r1, r2, r3] = tunnel.remote_vtep_ip;
            let [a, b, c, d, e, ff] = tunnel.outer_dst_mac;
            writeln!(
                f,
                "  - vni {} {} -> vtep {r0}.{r1}.{r2}.{r3} via {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x} dev {}",
                tunnel.vni, tunnel.inner_dst, tunnel.out_iface,
            )?;
        }
        if !self.mac_routes.is_empty() {
            writeln!(f, "mac_routes     : {} entry(ies)", self.mac_routes.len())?;
            for mr in &self.mac_routes {
                let [r0, r1, r2, r3] = mr.remote_vtep_ip;
                let [m0, m1, m2, m3, m4, m5] = mr.mac;
                let [a, b, c, d, e, ff] = mr.outer_dst_mac;
                writeln!(
                    f,
                    "  - vni {} {m0:02x}:{m1:02x}:{m2:02x}:{m3:02x}:{m4:02x}:{m5:02x} -> vtep {r0}.{r1}.{r2}.{r3} via {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x} dev {}",
                    mr.vni, mr.out_iface,
                )?;
            }
        }
        match &self.srv6 {
            Some(s) => writeln!(
                f,
                "srv6           : src {} dev {} (End.DT2U, {} trusted decap peer(s))",
                Ipv6Addr::from(s.local_src),
                s.underlay_iface,
                s.peers.len(),
            )?,
            None => writeln!(f, "srv6           : disabled")?,
        }
        if !self.srv6_routes.is_empty() {
            writeln!(f, "srv6_routes    : {} entry(ies)", self.srv6_routes.len())?;
            for sr in &self.srv6_routes {
                let [m0, m1, m2, m3, m4, m5] = sr.mac;
                let [a, b, c, d, e, ff] = sr.outer_dst_mac;
                writeln!(
                    f,
                    "  - vni {} {m0:02x}:{m1:02x}:{m2:02x}:{m3:02x}:{m4:02x}:{m5:02x} -> sid {} via {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x} dev {}",
                    sr.vni,
                    Ipv6Addr::from(sr.remote_sid),
                    sr.out_iface,
                )?;
            }
        }
        if !self.srv6_local_sids.is_empty() {
            writeln!(
                f,
                "srv6_local_sids: {} entry(ies)",
                self.srv6_local_sids.len()
            )?;
            for ls in &self.srv6_local_sids {
                let beh = if ls.behavior == velstra_common::srv6::behavior::END_DT2M {
                    "End.DT2M"
                } else {
                    "End.DT2U"
                };
                writeln!(
                    f,
                    "  - sid {} -> vni {} ({beh})",
                    Ipv6Addr::from(ls.sid),
                    ls.vni,
                )?;
            }
        }
        if !self.neighbors.is_empty() {
            writeln!(
                f,
                "neighbors      : {} (arp suppression)",
                self.neighbors.len()
            )?;
            for n in &self.neighbors {
                let [i0, i1, i2, i3] = n.ip;
                let [a, b, c, d, e, ff] = n.mac;
                writeln!(
                    f,
                    "  - vni {} {i0}.{i1}.{i2}.{i3} is at {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x}",
                    n.vni,
                )?;
            }
        }
        if !self.nd_neighbors.is_empty() {
            writeln!(
                f,
                "nd_neighbors   : {} (ipv6 nd suppression)",
                self.nd_neighbors.len()
            )?;
            for n in &self.nd_neighbors {
                let ip = Ipv6Addr::from(n.ip);
                let [a, b, c, d, e, ff] = n.mac;
                writeln!(
                    f,
                    "  - vni {} {ip} is at {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x}",
                    n.vni,
                )?;
            }
        }
        if !self.flood_vteps.is_empty() {
            writeln!(
                f,
                "flood_vteps    : {} (bum head-end replication)",
                self.flood_vteps.len()
            )?;
            for fv in &self.flood_vteps {
                let [r0, r1, r2, r3] = fv.remote_vtep_ip;
                let [a, b, c, d, e, ff] = fv.outer_dst_mac;
                writeln!(
                    f,
                    "  - vni {} flood -> vtep {r0}.{r1}.{r2}.{r3} via {a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{ff:02x} dev {}",
                    fv.vni, fv.out_iface,
                )?;
            }
        }

        if let Some(cts) = &self.conntrack_sync {
            writeln!(
                f,
                "conntrack-sync : listen {}, {} peer(s), every {}s",
                cts.listen,
                cts.peers.len(),
                cts.interval_secs,
            )?;
            for p in &cts.peers {
                writeln!(f, "  - peer {p}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    /// A protocol with no ports is keyed at port 0 — that is what "match every
    /// packet of this protocol" compiles to. Refusing such a rule outright, as
    /// this used to for ICMP, meant the control plane emitted rules this loader
    /// then rejected: the feature that let a rule name a port-less protocol had
    /// a schema that accepted it and a validator that did not, so it never
    /// worked end to end.
    #[test]
    fn a_port_less_protocol_is_accepted_at_port_zero_and_refused_with_one() {
        let cfg = |proto: &str, port: u16| {
            format!(
                "default_action = \"drop\"\n\
                 [[policy]]\nid = 1\nname = \"wan\"\ndefault_action = \"drop\"\n\
                 [[policy.port_rule]]\nproto = \"{proto}\"\nport = {port}\naction = \"pass\"\n"
            )
        };
        for proto in ["icmp", "icmpv6", "vrrp", "esp", "ah", "gre"] {
            let good: FileConfig = toml::from_str(&cfg(proto, 0)).expect("parses");
            assert!(
                good.resolve().is_ok(),
                "{proto} at port 0 was refused, so a rule naming it cannot be loaded"
            );
            let bad: FileConfig = toml::from_str(&cfg(proto, 443)).expect("parses");
            assert!(
                bad.resolve().is_err(),
                "{proto} with a port was accepted, and would silently match nothing"
            );
        }
        // …and tcp/udp are unaffected in both directions.
        let tcp: FileConfig = toml::from_str(&cfg("tcp", 443)).expect("parses");
        assert!(tcp.resolve().is_ok());
    }
    use super::*;

    #[test]
    fn resolves_conntrack_sync() {
        let toml = r#"
            [conntrack_sync]
            listen = "0.0.0.0:5429"
            peer = ["10.0.0.2:5429", "10.0.0.3:5429"]
            interval_secs = 2
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let cts = cfg.conntrack_sync.expect("conntrack_sync present");
        assert_eq!(cts.listen, "0.0.0.0:5429".parse().unwrap());
        assert_eq!(cts.peers.len(), 2);
        assert_eq!(cts.peers[1], "10.0.0.3:5429".parse().unwrap());
        assert_eq!(cts.interval_secs, 2);
    }

    #[test]
    fn conntrack_sync_defaults_interval_and_clamps_zero() {
        // No `interval_secs` → default 1; an explicit `0` is clamped up to 1 so
        // the push loop never busy-spins.
        let cfg = toml::from_str::<FileConfig>(
            "[conntrack_sync]\nlisten = \"0.0.0.0:5429\"\ninterval_secs = 0\n",
        )
        .unwrap()
        .resolve()
        .unwrap();
        assert_eq!(cfg.conntrack_sync.unwrap().interval_secs, 1);

        let cfg = toml::from_str::<FileConfig>("[conntrack_sync]\nlisten = \"0.0.0.0:5429\"\n")
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.conntrack_sync.unwrap().interval_secs, 1);
    }

    #[test]
    fn conntrack_sync_rejects_bad_listen() {
        let err = toml::from_str::<FileConfig>("[conntrack_sync]\nlisten = \"not-an-addr\"\n")
            .unwrap()
            .resolve()
            .unwrap_err();
        assert!(err.to_string().contains("conntrack_sync.listen"));
    }

    #[test]
    fn no_conntrack_sync_is_none() {
        let cfg = toml::from_str::<FileConfig>("default_action = \"drop\"\n")
            .unwrap()
            .resolve()
            .unwrap();
        assert!(cfg.conntrack_sync.is_none());
    }

    #[test]
    fn parses_full_config() {
        let toml = r#"
            default_action = "drop"
            drop_icmp = true
            log = true
            blocklist = ["10.0.0.0/8", "203.0.113.7"]

            [[port_rule]]
            proto = "tcp"
            port = 443
            action = "pass"

            [[port_rule]]
            proto = "udp"
            port = 53
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        let cfg = file.resolve().unwrap();

        // The top-level config is policy 0.
        let p0 = &cfg.policies[0];
        assert_eq!(p0.id, 0);
        assert_eq!(p0.global.default_action(), Action::Drop);
        assert!(p0.global.has_flag(ConfigFlags::DROP_ICMP));
        assert!(p0.global.has_flag(ConfigFlags::LOG));
        assert_eq!(p0.blocklist.len(), 2);
        assert_eq!(p0.blocklist[0].octets, [10, 0, 0, 0]);

        // Explicit pass rule on tcp/443.
        assert_eq!(
            p0.port_rules[0],
            ResolvedRule {
                icmp_type: 0,
                scope: 0,
                key: PortKey::new(ip_proto::TCP, 443),
                src6: None,
                dst6: None,
                src: None,
                dst: None,
                action: Action::Pass,
                log: false,
                limit: None,
            }
        );
        // udp/53 defaults to drop.
        assert_eq!(
            p0.port_rules[1],
            ResolvedRule {
                icmp_type: 0,
                scope: 0,
                key: PortKey::new(ip_proto::UDP, 53),
                src6: None,
                dst6: None,
                src: None,
                dst: None,
                action: Action::Drop,
                log: false,
                limit: None,
            }
        );
    }

    /// A rule constraining both ends is refused, not half-enforced. The data plane
    /// ranks one address dimension per rule (an LPM prefix is contiguous from the
    /// front of the key), so honouring whichever one happened to be programmed
    /// would give a rule that matches more traffic than it says it does.
    #[test]
    fn a_rule_cannot_constrain_both_ends() {
        let toml = r#"
            [[policy]]
            id = 7
            [[policy.port_rule]]
            proto = "tcp"
            port = 22
            action = "drop"
            src = "10.0.0.0/8"
            dst = "192.168.0.0/16"
        "#;
        let err = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .expect_err("a rule with both ends must be refused");
        let msg = err.to_string();
        assert!(msg.contains("both src and dst"), "{msg}");
        // The message has to say what to do instead, or the operator is stuck.
        assert!(msg.contains("two rules"), "{msg}");
    }

    /// Each constraint lands in the trie for its own dimension, and the resolver
    /// keeps them apart so the agent can route them there.
    #[test]
    fn a_destination_constraint_resolves_alongside_a_source_one() {
        let toml = r#"
            [[policy]]
            id = 7
            [[policy.port_rule]]
            proto = "tcp"
            port = 443
            action = "pass"
            src = "10.0.0.0/8"
            [[policy.port_rule]]
            proto = "tcp"
            port = 443
            action = "drop"
            dst = "192.168.4.0/24"
        "#;
        let rt = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let rules = &rt.policies.iter().find(|p| p.id == 7).unwrap().port_rules;
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].src.unwrap().prefix, 8);
        assert!(rules[0].dst.is_none());
        assert!(rules[1].src.is_none());
        assert_eq!(rules[1].dst.unwrap().prefix, 24);
    }

    #[test]
    fn splits_dual_stack_blocklist_by_family() {
        let toml = r#"
            blocklist = ["10.0.0.0/8", "2001:db8::/32", "203.0.113.7", "fe80::1"]
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let p0 = &cfg.policies[0];
        // IPv4 entries go to `blocklist`, IPv6 entries to `blocklist6`.
        assert_eq!(p0.blocklist.len(), 2);
        assert_eq!(p0.blocklist[0].octets, [10, 0, 0, 0]);
        assert_eq!(p0.blocklist6.len(), 2);
        assert_eq!(p0.blocklist6[0].prefix, 32);
        assert_eq!(&p0.blocklist6[0].octets[..4], &[0x20, 0x01, 0x0d, 0xb8]);
        // A bare IPv6 address is a /128 host route.
        assert_eq!(p0.blocklist6[1].prefix, 128);
    }

    #[test]
    fn rejects_bad_ipv6_blocklist() {
        let toml = r#"blocklist = ["2001:db8::/200"]"#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    /// The portal flag and the gate entry are two halves of one thing: the data
    /// plane reads the flag to decide whether to look the gate up, so a config
    /// that set one without the other would gate a zone against an address that
    /// is not there, or carry an address nothing consults.
    #[test]
    fn a_portal_sets_both_the_flag_and_the_gate() {
        let toml = r#"
            default_action = "drop"
            [[policy]]
            id = 4
            default_action = "drop"
            portal = { address = "192.168.50.1", address6 = "2001:db8:50::1" }
            [[policy]]
            id = 5
            default_action = "drop"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();

        let gated = cfg.policies.iter().find(|p| p.id == 4).unwrap();
        assert!(gated.global.has_flag(ConfigFlags::PORTAL));
        let gate = gated.portal.expect("policy 4 carries no gate");
        assert!(gate.is_portal4([192, 168, 50, 1]));
        assert!(
            gate.is_portal6(
                "2001:db8:50::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            )
        );

        // …and a zone without a portal pays for none of it.
        let plain = cfg.policies.iter().find(|p| p.id == 5).unwrap();
        assert!(!plain.global.has_flag(ConfigFlags::PORTAL));
        assert!(plain.portal.is_none());
    }

    /// A portal with no address would gate the zone with nowhere for a client to
    /// go — a zone that is off, written the long way round.
    #[test]
    fn a_portal_without_an_address_is_refused() {
        let toml = r#"
            [[policy]]
            id = 4
            portal = {}
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    /// One family is enough — a v4-only guest zone is an ordinary thing — but
    /// what is written has to parse.
    #[test]
    fn one_family_is_enough_and_a_typo_is_not() {
        let ok = r#"
            [[policy]]
            id = 4
            portal = { address = "192.168.50.1" }
        "#;
        let cfg = toml::from_str::<FileConfig>(ok).unwrap().resolve().unwrap();
        let gate = cfg
            .policies
            .iter()
            .find(|p| p.id == 4)
            .unwrap()
            .portal
            .unwrap();
        assert!(gate.is_portal4([192, 168, 50, 1]));
        // No v6 address ⇒ the v6 gate matches nothing, rather than everything.
        assert!(!gate.is_portal6([0; 16]));

        let typo = r#"
            [[policy]]
            id = 4
            portal = { address = "192.168.50" }
        "#;
        assert!(
            toml::from_str::<FileConfig>(typo)
                .unwrap()
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn stateful_flag_sets_per_policy() {
        let toml = r#"
            default_action = "drop"
            stateful = true
            [[policy]]
            id = 1
            default_action = "drop"
            stateful = false
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert!(cfg.policies[0].global.has_flag(ConfigFlags::STATEFUL));
        let p1 = cfg.policies.iter().find(|p| p.id == 1).unwrap();
        assert!(!p1.global.has_flag(ConfigFlags::STATEFUL));
    }

    #[test]
    fn empty_config_is_fail_open() {
        let cfg = FileConfig::default().resolve().unwrap();
        assert_eq!(cfg.policies.len(), 1);
        assert_eq!(cfg.policies[0].global.default_action(), Action::Pass);
        assert!(cfg.policies[0].blocklist.is_empty());
        assert!(cfg.policies[0].port_rules.is_empty());
        assert!(cfg.interfaces.is_empty());
    }

    #[test]
    fn parses_tenant_policies_and_interface_assignments() {
        let toml = r#"
            default_action = "pass"

            [[policy]]
            id = 7
            name = "tenant-a"
            default_action = "drop"
            blocklist = ["192.0.2.0/24"]
            [[policy.port_rule]]
            proto = "tcp"
            port = 22
            action = "drop"

            [[interface]]
            name = "tap0"
            policy = 7

            [[interface]]
            name = "tap1"
            policy = 0
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.policies.len(), 2);
        assert_eq!(cfg.policies[0].id, 0);
        let t = cfg.policies.iter().find(|p| p.id == 7).unwrap();
        assert_eq!(t.global.default_action(), Action::Drop);
        assert_eq!(t.blocklist[0].octets, [192, 0, 2, 0]);
        assert_eq!(
            cfg.interfaces,
            vec![
                ResolvedInterface {
                    name: "tap0".into(),
                    policy: 7,
                    vni: 7, // defaults to the policy id
                    masquerade: false,
                    mss: 0,
                    cgnat: CgnatLayout::default(),
                },
                ResolvedInterface {
                    name: "tap1".into(),
                    policy: 0,
                    vni: 0,
                    masquerade: false,
                    mss: 0,
                    cgnat: CgnatLayout::default(),
                },
            ]
        );
    }

    #[test]
    fn rejects_duplicate_policy_and_unknown_interface_policy() {
        let dup = r#"
            [[policy]]
            id = 5
            [[policy]]
            id = 5
        "#;
        assert!(
            toml::from_str::<FileConfig>(dup)
                .unwrap()
                .resolve()
                .is_err()
        );

        let unknown = r#"
            [[interface]]
            name = "tap0"
            policy = 9
        "#;
        assert!(
            toml::from_str::<FileConfig>(unknown)
                .unwrap()
                .resolve()
                .is_err()
        );
    }

    /// A rule may name ICMP, and then it matches every ICMP packet — which is
    /// what `port = 0` says. What is still refused is a *port* on it.
    ///
    /// This test used to assert the opposite, from before a rule could name a
    /// port-less protocol at all.
    #[test]
    fn an_icmp_rule_matches_the_protocol_and_a_port_on_it_does_not() {
        let toml = r#"
            [[port_rule]]
            proto = "icmp"
            port = 0
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        file.resolve().expect("an ICMP rule with no port is valid");

        let with_port = r#"
            [[port_rule]]
            proto = "icmp"
            port = 443
        "#;
        let file: FileConfig = toml::from_str(with_port).unwrap();
        let err = file.resolve().unwrap_err().to_string();
        assert!(err.contains("carries no ports"), "unexpected error: {err}");
    }

    /// A type is only meaningful where the protocol has types. Accepting it on
    /// TCP would read as a narrow rule and match every TCP packet.
    #[test]
    fn an_icmp_type_belongs_to_icmp() {
        let ok = r#"
            [[port_rule]]
            proto = "icmp"
            port = 0
            icmp-type = 8
        "#;
        let file: FileConfig = toml::from_str(ok).unwrap();
        let cfg = file.resolve().expect("a typed ICMP rule is valid");
        assert_eq!(cfg.policies[0].port_rules[0].icmp_type, 8);

        let bad = r#"
            [[port_rule]]
            proto = "tcp"
            port = 443
            icmp-type = 8
        "#;
        let file: FileConfig = toml::from_str(bad).unwrap();
        let err = file.resolve().unwrap_err().to_string();
        assert!(err.contains("only for icmp"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_bad_cidr() {
        let toml = r#"blocklist = ["not-an-ip"]"#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    #[test]
    fn resolves_srv6_endpoint_and_routes() {
        let toml = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"
            underlay_mtu = 9000
            peers = ["fc00:0:2::1", "fc00:0:3::1"]

            [[srv6_route]]
            vni = 10000
            mac = "02:00:00:00:00:0a"
            remote_sid = "fc00:0:2:2710::"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let s = cfg.srv6.expect("srv6 endpoint");
        assert_eq!(s.local_src[0..2], [0xfc, 0x00]);
        assert_eq!(s.local_src[15], 1);
        assert_eq!(s.underlay_iface, "eth0");
        assert_eq!(s.local_mac, None);
        assert_eq!(s.underlay_mtu, 9000);
        // The trusted decap peers resolve to their outer IPv6 source octets — and
        // are the peers' `local_src`, NOT the function-bearing `remote_sid` route.
        assert_eq!(s.peers.len(), 2);
        assert_eq!(
            s.peers[0],
            "fc00:0:2::1".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            s.peers[1],
            "fc00:0:3::1".parse::<Ipv6Addr>().unwrap().octets()
        );

        assert_eq!(cfg.srv6_routes.len(), 1);
        let r = &cfg.srv6_routes[0];
        assert_eq!(r.vni, 10000);
        assert_eq!(r.mac, [2, 0, 0, 0, 0, 0x0a]);
        assert_eq!(r.remote_sid[0..2], [0xfc, 0x00]);
        assert_eq!(r.outer_dst_mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(r.out_iface, "eth0");
    }

    #[test]
    fn srv6_peers_default_empty_and_reject_bad_address() {
        // Omitting `peers` leaves the trusted set empty (fail-closed at the datapath).
        let ok = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"
        "#;
        let cfg = toml::from_str::<FileConfig>(ok).unwrap().resolve().unwrap();
        assert!(cfg.srv6.expect("srv6").peers.is_empty());

        // A malformed peer address is rejected at resolve, not silently dropped.
        let bad = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"
            peers = ["not-an-ipv6"]
        "#;
        let err = toml::from_str::<FileConfig>(bad).unwrap().resolve();
        assert!(err.is_err());
    }

    #[test]
    fn source_validation_is_off_unless_asked_for() {
        let cfg = toml::from_str::<FileConfig>("").unwrap().resolve().unwrap();
        assert_eq!(
            cfg.policies[0].global.source_validation(),
            SourceValidation::Disabled,
            "uRPF drops traffic; a config that never mentions it must not get it"
        );
    }

    #[test]
    fn each_policy_carries_its_own_source_validation() {
        // The realistic shape: strict at the untrusted edge, off inside, where a
        // second path in or out would make strict drop legitimate traffic.
        let toml = r#"
            source_validation = "strict"

            [[policy]]
            id = 7
            source_validation = "loose"

            [[policy]]
            id = 8
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let mode = |id| {
            cfg.policies
                .iter()
                .find(|p| p.id == id)
                .unwrap()
                .global
                .source_validation()
        };
        assert_eq!(mode(0), SourceValidation::Strict);
        assert_eq!(mode(7), SourceValidation::Loose);
        assert_eq!(mode(8), SourceValidation::Disabled);
    }

    #[test]
    fn source_validation_leaves_the_other_flags_alone() {
        let toml = r#"
            source_validation = "loose"
            stateful = true
            drop_icmp = true
        "#;
        let global = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap()
            .policies[0]
            .global;
        assert!(global.has_flag(ConfigFlags::STATEFUL));
        assert!(global.has_flag(ConfigFlags::DROP_ICMP));
        assert_eq!(global.source_validation(), SourceValidation::Loose);
    }

    #[test]
    fn an_unknown_source_validation_mode_is_refused() {
        // Silently falling back to `disable` would leave an operator believing a
        // typo'd config validates sources when it does not.
        let err = toml::from_str::<FileConfig>(r#"source_validation = "rpf""#).unwrap_err();
        assert!(err.to_string().contains("source_validation"), "{err}");
    }

    #[test]
    fn resolves_srv6_local_sids_with_behavior() {
        let toml = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"

            [[srv6_local_sid]]
            sid = "fc00:0:1:2710::"
            vni = 10000

            [[srv6_local_sid]]
            sid = "fc00:0:1:2711::"
            vni = 10000
            behavior = "end.dt2m"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.srv6_local_sids.len(), 2);
        // Default behaviour is End.DT2U.
        assert_eq!(
            cfg.srv6_local_sids[0].behavior,
            velstra_common::srv6::behavior::END_DT2U
        );
        assert_eq!(cfg.srv6_local_sids[0].vni, 10000);
        assert_eq!(cfg.srv6_local_sids[0].sid[0..2], [0xfc, 0x00]);
        // Explicit end.dt2m maps to the flood behaviour.
        assert_eq!(
            cfg.srv6_local_sids[1].behavior,
            velstra_common::srv6::behavior::END_DT2M
        );
    }

    #[test]
    fn srv6_local_sid_rejects_bad_behavior() {
        let toml = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"
            [[srv6_local_sid]]
            sid = "fc00:0:1:2710::"
            vni = 1
            behavior = "end.dx2"
        "#;
        let err = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(err.contains("behavior"), "unexpected error: {err}");
    }

    #[test]
    fn srv6_route_requires_srv6_section() {
        let toml = r#"
            [[srv6_route]]
            vni = 1
            mac = "02:00:00:00:00:0a"
            remote_sid = "fc00:0:2::1"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        let err = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(err.contains("[srv6]"), "unexpected error: {err}");
    }

    #[test]
    fn srv6_and_overlay_are_mutually_exclusive() {
        let toml = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"

            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
        "#;
        let err = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("mutually exclusive"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parses_routes_with_modes_and_defaults() {
        let toml = r#"
            [[route]]
            dest = "10.0.0.0/24"
            out_iface = "eth1"
            via_mac = "02:00:00:00:00:01"

            [[route]]
            dest = "192.168.0.0/16"
            out_iface = "eth2"
            via_mac = "02:00:00:00:00:02"
            src_mac = "02:00:00:00:00:99"
            mode = "switch"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.routes.len(), 2);

        // First route: default mode = router (decrement TTL), src from iface.
        assert_eq!(cfg.routes[0].dest.prefix, 24);
        assert_eq!(cfg.routes[0].dst_mac, [2, 0, 0, 0, 0, 1]);
        assert_eq!(cfg.routes[0].src_mac, None);
        assert_eq!(cfg.routes[0].flags, RouteEntry::DECREMENT_TTL);

        // Second route: explicit switch mode + explicit src MAC.
        assert_eq!(cfg.routes[1].flags, 0);
        assert_eq!(cfg.routes[1].src_mac, Some([2, 0, 0, 0, 0, 0x99]));
    }

    #[test]
    fn parses_services_with_backends() {
        let toml = r#"
            [[service]]
            vip = "10.0.0.100"
            port = 80
            proto = "tcp"
            backends = [
                { ip = "10.0.0.7", port = 8080 },
                { ip = "10.0.0.8" },
            ]
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.services.len(), 1);
        let svc = &cfg.services[0];
        assert_eq!(svc.key.vip, [10, 0, 0, 100]);
        assert_eq!(svc.key.port, 80);
        assert_eq!(svc.key.proto, ip_proto::TCP);
        assert_eq!(svc.backends.len(), 2);
        assert_eq!(svc.backends[0].port, 8080);
        assert_eq!(svc.backends[1].port, 0); // omitted -> keep original
    }

    #[test]
    fn rejects_service_without_backends() {
        let toml = r#"
            [[service]]
            vip = "10.0.0.100"
            port = 80
            proto = "tcp"
            backends = []
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    #[test]
    fn parses_overlay_and_tunnels() {
        let toml = r#"
            [overlay]
            local_vtep = "10.10.0.1"
            underlay_iface = "eth0"
            encap = "geneve"

            [[tunnel]]
            vni = 100
            inner_dst = "192.168.50.7"
            remote_vtep = "10.10.0.2"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let o = cfg.overlay.expect("overlay present");
        assert_eq!(o.local_vtep_ip, [10, 10, 0, 1]);
        assert_eq!(o.encap, encap_kind::GENEVE);
        assert_eq!(o.udp_port, GENEVE_PORT); // defaulted from encap
        assert_eq!(cfg.tunnels.len(), 1);
        let t = &cfg.tunnels[0];
        assert_eq!(t.vni, 100);
        assert_eq!(t.inner_dst.octets, [192, 168, 50, 7]);
        assert_eq!(t.inner_dst.prefix, 32); // bare host -> /32
        assert_eq!(t.remote_vtep_ip, [10, 10, 0, 2]);
        assert_eq!(t.outer_dst_mac, [2, 0, 0, 0, 0, 2]);
        assert_eq!(t.out_iface, "eth0");
    }

    #[test]
    fn interface_vni_decouples_from_policy() {
        // Two ports share firewall policy 7 but live on different overlay
        // segments — the security-group-vs-network distinction the coupling broke.
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"

            [[policy]]
            id = 7
            default_action = "drop"

            [[interface]]
            name = "tapA"
            policy = 7
            vni = 5000

            [[interface]]
            name = "tapB"
            policy = 7
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        // tapA: explicit VNI distinct from the policy.
        assert_eq!(cfg.interfaces[0].policy, 7);
        assert_eq!(cfg.interfaces[0].vni, 5000);
        // tapB: VNI defaults to the policy id.
        assert_eq!(cfg.interfaces[1].policy, 7);
        assert_eq!(cfg.interfaces[1].vni, 7);
    }

    #[test]
    fn parses_neighbors_and_mtu() {
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
            underlay_mtu = 9000

            [[neighbor]]
            vni = 5000
            ip = "192.168.100.2"
            mac = "02:00:00:00:00:22"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.overlay.unwrap().underlay_mtu, 9000);
        assert_eq!(cfg.neighbors.len(), 1);
        assert_eq!(cfg.neighbors[0].vni, 5000);
        assert_eq!(cfg.neighbors[0].ip, [192, 168, 100, 2]);
        assert_eq!(cfg.neighbors[0].mac, [2, 0, 0, 0, 0, 0x22]);
    }

    #[test]
    fn overlay_mtu_defaults_to_1500() {
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.overlay.unwrap().underlay_mtu, 1500);
    }

    #[test]
    fn rejects_neighbor_without_overlay() {
        let toml = r#"
            [[neighbor]]
            vni = 1
            ip = "10.0.0.5"
            mac = "02:00:00:00:00:01"
        "#;
        assert!(
            toml::from_str::<FileConfig>(toml)
                .unwrap()
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn tunnel_inner_dst_accepts_a_subnet() {
        // A whole remote subnet is one LPM entry, not one per host.
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
            [[tunnel]]
            vni = 100
            inner_dst = "192.168.0.0/16"
            remote_vtep = "10.0.0.2"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(cfg.tunnels[0].inner_dst.octets, [192, 168, 0, 0]);
        assert_eq!(cfg.tunnels[0].inner_dst.prefix, 16);
    }

    #[test]
    fn rejects_interface_vni_over_24_bits_with_overlay() {
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
            [[interface]]
            name = "tap0"
            policy = 0
            vni = 16777216
        "#;
        assert!(
            toml::from_str::<FileConfig>(toml)
                .unwrap()
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn overlay_defaults_vxlan_port_and_keeps_explicit_override() {
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
            udp_port = 9999
        "#;
        let cfg = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap();
        let o = cfg.overlay.unwrap();
        assert_eq!(o.encap, encap_kind::VXLAN); // default encap
        assert_eq!(o.udp_port, 9999); // explicit override wins
    }

    #[test]
    fn rejects_tunnel_without_overlay() {
        let toml = r#"
            [[tunnel]]
            vni = 1
            inner_dst = "10.0.0.5"
            remote_vtep = "10.10.0.2"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        let err = toml::from_str::<FileConfig>(toml)
            .unwrap()
            .resolve()
            .unwrap_err()
            .to_string();
        assert!(err.contains("overlay"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_vni_over_24_bits() {
        let toml = r#"
            [overlay]
            local_vtep = "10.0.0.1"
            underlay_iface = "eth0"
            [[tunnel]]
            vni = 16777216
            inner_dst = "10.0.0.5"
            remote_vtep = "10.10.0.2"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
        "#;
        assert!(
            toml::from_str::<FileConfig>(toml)
                .unwrap()
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn rejects_icmp_service() {
        let toml = r#"
            [[service]]
            vip = "10.0.0.100"
            port = 0
            proto = "icmp"
            backends = [{ ip = "10.0.0.7" }]
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    #[test]
    fn rejects_bad_route_mac() {
        let toml = r#"
            [[route]]
            dest = "10.0.0.0/24"
            out_iface = "eth1"
            via_mac = "not-a-mac"
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = r#"defaultaction = "drop""#; // typo: should be deny_unknown_fields
        assert!(toml::from_str::<FileConfig>(toml).is_err());
    }
}
