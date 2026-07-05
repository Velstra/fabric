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
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use velstra_common::{
    Action, Backend, Cidr4, Cidr6, ConfigFlags, GENEVE_PORT, GlobalConfig, PolicyId, PortKey,
    RouteEntry, ServiceKey, VXLAN_PORT, encap_kind, ip_proto, parse_cidr_v4, parse_cidr_v6,
    parse_mac,
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

/// A transport protocol name as written in TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtoName {
    Tcp,
    Udp,
    /// ICMP (cannot carry a port rule — use `drop_icmp` instead).
    Icmp,
}

impl ProtoName {
    /// The IANA protocol number.
    fn number(self) -> u8 {
        match self {
            ProtoName::Tcp => ip_proto::TCP,
            ProtoName::Udp => ip_proto::UDP,
            ProtoName::Icmp => ip_proto::ICMP,
        }
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

/// One real backend behind a [`ServiceCfg`].
#[derive(Debug, Deserialize)]
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

/// A named tenant policy (`[[policy]]`): the same firewall fields as the
/// top-level config, but with an explicit non-zero `id` that interfaces map to.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    /// Policy id (must be non-zero; `0` is the default top-level policy).
    pub id: PolicyId,
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
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default, rename = "port_rule")]
    pub port_rules: Vec<PortRule>,
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
    /// Masquerade (source NAT) traffic **leaving** this interface to its own
    /// public IPv4 — the classic WAN uplink. Off by default. The control plane
    /// reads the live address and programs the `MASQUERADE` map + the TC egress
    /// hook; the reply is un-NAT'd on ingress via connection tracking.
    #[serde(default)]
    pub masquerade: bool,
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
    /// Phase 4 overlay endpoint for this host. Spelled `[overlay]` in TOML.
    #[serde(default)]
    pub overlay: Option<OverlayCfg>,
    /// Phase 4 overlay forwarding entries. Spelled `[[tunnel]]` in TOML.
    #[serde(rename = "tunnel")]
    pub tunnels: Vec<TunnelCfg>,
    /// B1 per-MAC L2 forwarding entries. Spelled `[[mac_route]]` in TOML.
    #[serde(rename = "mac_route")]
    pub mac_routes: Vec<MacRouteCfg>,
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
}

/// A resolved load-balancer service: a service key and its (validated) backends.
#[derive(Debug, Clone)]
pub struct ResolvedService {
    /// The `(VIP, port, proto)` lookup key.
    pub key: ServiceKey,
    /// The backend pool (at least one entry).
    pub backends: Vec<Backend>,
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
    /// `(key, src, action, log)` entries for this policy's `PORT_RULES`. `src` is
    /// the optional source-CIDR constraint (`None` == from any); `log` asks the
    /// data plane to log packets matching this rule.
    pub port_rules: Vec<(PortKey, Option<Cidr4>, Action, bool)>,
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
    /// This host's overlay endpoint (Phase 4), or `None` if not participating.
    pub overlay: Option<ResolvedOverlay>,
    /// Overlay forwarding entries for the `OVERLAY_FDB` map (Phase 4).
    pub tunnels: Vec<ResolvedTunnel>,
    /// Per-MAC L2 forwarding entries for the `MAC_FDB` map (B1).
    pub mac_routes: Vec<ResolvedMacRoute>,
    /// ARP-suppression neighbours for the `ARP_TABLE` map (Phase 4).
    pub neighbors: Vec<ResolvedNeighbor>,
    /// IPv6 ND-suppression neighbours for the `ND_TABLE` map (B3).
    pub nd_neighbors: Vec<ResolvedNd6>,
    /// BUM head-end replication flood entries for the `FLOOD_LIST` map (B2). The
    /// agent groups these by `vni` into one `FloodSet` per segment.
    pub flood_vteps: Vec<ResolvedFloodVtep>,
}

impl RuntimeConfig {
    /// A do-nothing, fail-open config (pass everything). Used when `run` is
    /// invoked without a `--config` file.
    pub fn passthrough() -> Self {
        Self {
            policies: vec![PolicyConfig {
                id: 0,
                global: GlobalConfig::new(Action::Pass, 0),
                blocklist: Vec::new(),
                blocklist6: Vec::new(),
                port_rules: Vec::new(),
            }],
            interfaces: Vec::new(),
            routes: Vec::new(),
            services: Vec::new(),
            port_forwards: Vec::new(),
            overlay: None,
            tunnels: Vec::new(),
            mac_routes: Vec::new(),
            neighbors: Vec::new(),
            nd_neighbors: Vec::new(),
            flood_vteps: Vec::new(),
        }
    }
}

/// Resolve one policy's firewall fields into map contents.
#[allow(clippy::too_many_arguments)]
fn resolve_firewall(
    id: PolicyId,
    default_action: ActionName,
    drop_icmp: bool,
    log: bool,
    stateful: bool,
    blocklist: &[String],
    port_rules: &[PortRule],
) -> Result<PolicyConfig> {
    let mut flags = 0;
    if drop_icmp {
        flags |= ConfigFlags::DROP_ICMP;
    }
    if log {
        flags |= ConfigFlags::LOG;
    }
    if stateful {
        flags |= ConfigFlags::STATEFUL;
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
        if rule.proto == ProtoName::Icmp {
            bail!(
                "policy {id}: port rule on ICMP is invalid (ICMP has no ports); use `drop_icmp = true`"
            );
        }
        let src =
            match &rule.src {
                Some(cidr) => Some(parse_cidr_v4(cidr).map_err(|e| {
                    anyhow::anyhow!("policy {id}: invalid rule source {cidr:?}: {e}")
                })?),
                None => None,
            };
        rules.push((
            PortKey::new(rule.proto.number(), rule.port),
            src,
            rule.action.into(),
            rule.log,
        ));
    }

    Ok(PolicyConfig {
        id,
        global,
        blocklist: cidrs,
        blocklist6: cidrs6,
        port_rules: rules,
    })
}

impl FileConfig {
    /// Validate the document and resolve it into a [`RuntimeConfig`].
    ///
    /// Fails if a CIDR is malformed, a port rule targets ICMP, or two policies
    /// share an id.
    pub fn resolve(&self) -> Result<RuntimeConfig> {
        // Policy 0 is the top-level config; `[[policy]]` blocks add tenants.
        let mut policies = vec![resolve_firewall(
            0,
            self.default_action,
            self.drop_icmp,
            self.log,
            self.stateful,
            &self.blocklist,
            &self.port_rules,
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
                &policy.blocklist,
                &policy.port_rules,
            )?);
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
                ProtoName::Icmp => bail!("load-balancer service protocol must be tcp or udp"),
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
            });
        }

        // Phase 4: 1:1 DNAT port-forwards.
        let mut port_forwards = Vec::with_capacity(self.port_forwards.len());
        for pf in &self.port_forwards {
            let proto = match pf.proto {
                ProtoName::Tcp => ip_proto::TCP,
                ProtoName::Udp => ip_proto::UDP,
                ProtoName::Icmp => bail!("port-forward protocol must be tcp or udp"),
            };
            if !policies.iter().any(|p| p.id == pf.policy) {
                bail!("port-forward references unknown policy id {}", pf.policy);
            }
            let dst_ip: Ipv4Addr = pf
                .dst_ip
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port-forward dst_ip {:?}", pf.dst_ip))?;
            port_forwards.push(ResolvedPortForward {
                policy: pf.policy,
                proto,
                port: pf.port,
                dst_ip: dst_ip.octets(),
                dst_port: pf.dst_port,
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

        Ok(RuntimeConfig {
            policies,
            interfaces,
            routes,
            services,
            port_forwards,
            overlay,
            tunnels,
            mac_routes,
            neighbors,
            nd_neighbors,
            flood_vteps,
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
                "  policy {} : default={default}, drop_icmp={}, stateful={}, log={}",
                policy.id,
                policy.global.has_flag(ConfigFlags::DROP_ICMP),
                policy.global.has_flag(ConfigFlags::STATEFUL),
                policy.global.has_flag(ConfigFlags::LOG),
            )?;
            for cidr in &policy.blocklist {
                writeln!(f, "      block {cidr}")?;
            }
            for cidr in &policy.blocklist6 {
                writeln!(f, "      block6 {cidr}")?;
            }
            for (key, src, action, _log) in &policy.port_rules {
                let from = match src {
                    Some(c) => format!(
                        " from {}/{}",
                        c.octets.map(|o| o.to_string()).join("."),
                        c.prefix
                    ),
                    None => String::new(),
                };
                let proto = match key.proto {
                    ip_proto::TCP => "tcp",
                    ip_proto::UDP => "udp",
                    other => {
                        writeln!(
                            f,
                            "      proto {other} port {} ->{from} {action:?}",
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
                writeln!(f, "      {proto}/{} ->{from} {verdict}", key.port)?;
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            (PortKey::new(ip_proto::TCP, 443), None, Action::Pass, false)
        );
        // udp/53 defaults to drop.
        assert_eq!(
            p0.port_rules[1],
            (PortKey::new(ip_proto::UDP, 53), None, Action::Drop, false)
        );
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
                },
                ResolvedInterface {
                    name: "tap1".into(),
                    policy: 0,
                    vni: 0,
                    masquerade: false,
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

    #[test]
    fn rejects_icmp_port_rule() {
        let toml = r#"
            [[port_rule]]
            proto = "icmp"
            port = 0
        "#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        let err = file.resolve().unwrap_err().to_string();
        assert!(err.contains("ICMP"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_bad_cidr() {
        let toml = r#"blocklist = ["not-an-ip"]"#;
        let file: FileConfig = toml::from_str(toml).unwrap();
        assert!(file.resolve().is_err());
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
