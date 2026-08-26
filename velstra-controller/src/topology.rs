//! Declarative fabric topology — the Track C front-end.
//!
//! One TOML file describes the whole virtual fabric: its `[[host]]`s (VTEPs),
//! `[[network]]`s (tenants), and `[[port]]`s (VM NICs). The controller feeds it
//! to [`velstra_orchestrator`], which **derives** each host's concrete config,
//! and serves those alongside (and above) any static per-node files. So instead
//! of hand-writing tunnels and ARP entries on every host, you declare *intent*
//! once and the controller computes — and pushes — the per-host reality.
//!
//! ```toml
//! [[host]]
//! id = "host-1"
//! vtep = "10.10.0.1"
//! underlay_iface = "eth0"
//! underlay_mac = "02:00:00:00:00:11"
//!
//! [[network]]
//! vni = 5000
//! name = "blue"
//! subnet = "192.168.100.0/24"
//!
//! [[port]]
//! network = 5000
//! host = "host-1"
//! tap = "tap0"
//! # ip = "192.168.100.10"   # optional; auto-allocated from the subnet if omitted
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use velstra_common::{parse_cidr_v4, parse_cidr_v6, parse_mac, srv6::locator_src_from_service_sid};
use velstra_config::{
    ActionName, EncapName, FileConfig, FloodVtepCfg, IrbRouteCfg, MacRouteCfg, Nd6Cfg, NeighborCfg,
    PortRule, ProtoName, Srv6FloodCfg, Srv6IrbRouteCfg, Srv6LocalSidCfg, Srv6RouteCfg, TunnelCfg,
    file_config_to_proto,
};
use velstra_orchestrator::{
    AllocRange, Host, IpVrf, LbMember, LoadBalancer, Network, SecurityGroup, Subnet, SubnetCidr,
    Topology, srv6_disc, srv6_service_sid,
};
use velstra_proto::NodeConfig;

use crate::evpn::EvpnLearned;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TopologyFile {
    #[serde(rename = "host", default)]
    hosts: Vec<HostFile>,
    #[serde(rename = "network", default)]
    networks: Vec<NetworkFile>,
    /// First-class subnets (D2). Declarative subnet definitions only; runtime
    /// IPAM allocations and port-subnet bindings are durable via the Raft
    /// snapshot (cluster mode), not this file.
    #[serde(rename = "subnet", default, skip_serializing_if = "Vec::is_empty")]
    subnets: Vec<SubnetFile>,
    /// Named security groups (B5). Ports reference one by name (see [`PortFile`]).
    #[serde(
        rename = "security_group",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    security_groups: Vec<SecurityGroupFile>,
    /// Tenant IP-VRFs (B7): the routed contexts L2 segments are grouped into.
    #[serde(rename = "ip_vrf", default, skip_serializing_if = "Vec::is_empty")]
    ip_vrfs: Vec<IpVrfFile>,
    /// Load-balanced services (D2 LBaaS). Declared after ports, since a member
    /// names a port.
    #[serde(
        rename = "load_balancer",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    load_balancers: Vec<LoadBalancerFile>,
    #[serde(rename = "port", default)]
    ports: Vec<PortFile>,
}

/// One `[[load_balancer]]` block: a VIP fronting a pool of fabric ports.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoadBalancerFile {
    id: String,
    vni: u32,
    vip: String,
    port: u16,
    /// `tcp` (default) or `udp`.
    #[serde(default = "default_lb_proto")]
    proto: ProtoName,
    /// Pool members, each naming a port declared in this file.
    #[serde(default, rename = "member", skip_serializing_if = "Vec::is_empty")]
    members: Vec<LbMemberFile>,
}

/// One `[[load_balancer.member]]` entry. A member names its port the way the
/// file names ports — by `host` + `tap` — not by the generated port id, which an
/// author cannot know when the address is auto-allocated.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LbMemberFile {
    host: String,
    tap: String,
    /// Backend port, or omitted to keep the client's original destination port.
    #[serde(default, skip_serializing_if = "is_zero_port")]
    port: u16,
}

fn is_zero_port(p: &u16) -> bool {
    *p == 0
}

/// A load balancer with no `proto` is TCP. Deliberately local rather than a
/// `Default` on `ProtoName`: an omitted protocol means different things in
/// different blocks, and a blanket default would quietly pick one everywhere.
fn default_lb_proto() -> ProtoName {
    ProtoName::Tcp
}

/// One `[[ip_vrf]]` block: a tenant's routed context. Deliberately the same shape
/// as wren's `[[bgp.evpn.ip-vrf]]`, since an operator configures the two sides of
/// the same tenant.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IpVrfFile {
    l3_vni: u32,
    name: String,
    /// The anycast gateway MAC, identical on every host.
    gateway_mac: String,
    /// The L2 VNIs routed in this context.
    #[serde(default)]
    networks: Vec<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    id: String,
    vtep: String,
    underlay_iface: String,
    underlay_mac: String,
    #[serde(default, skip_serializing_if = "is_default_encap")]
    encap: EncapName,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    udp_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    underlay_mtu: Option<u16>,
    /// B9 SRv6 locator as `prefix/len`. Absent on a non-SRv6 host; the topology
    /// refuses the mismatch in either direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    srv6_locator: Option<String>,
}

fn is_default_encap(e: &EncapName) -> bool {
    *e == EncapName::default()
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkFile {
    vni: u32,
    name: String,
    subnet: String,
    #[serde(default)]
    default_action: ActionName,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    drop_icmp: bool,
}

/// A first-class subnet (D2). The CIDR may be IPv4 or IPv6; a network can hold
/// several (e.g. a v4 and a v6 subnet for a dual-stack tenant).
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SubnetFile {
    id: String,
    vni: u32,
    cidr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool_start: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool_end: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    enable_dhcp: bool,
}

/// A named security group (B5): a reusable firewall rule set, spelled
/// `[[security_group]]` with inline `[[security_group.rule]]`s.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SecurityGroupFile {
    name: String,
    #[serde(default)]
    default_action: ActionName,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    drop_icmp: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stateful: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    blocklist: Vec<String>,
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    rules: Vec<PortRule>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortFile {
    network: u32,
    host: String,
    tap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    /// Security-group policy id, decoupled from the VNI (M4). Omitted ⇒ default
    /// to the network VNI (single-tenant). Mutually redundant with
    /// `security_group` (a name); the name form is preferred on serialize.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<u32>,
    /// Bind this port to a named security group (B5). Takes precedence over
    /// `policy`; resolved to the group's deterministic policy id at build time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    security_group: Option<String>,
    /// The workload's hardware address. Omitted ⇒ derived from the address,
    /// which is right for a port this file declares: nothing above a topology
    /// file has already chosen one. It is settable so a file can describe a
    /// workload whose address was fixed elsewhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

/// Resolve a `[[load_balancer]]` block against the ports already built.
fn build_load_balancer(topo: &Topology, lb: &LoadBalancerFile) -> Result<LoadBalancer> {
    let mut members = Vec::with_capacity(lb.members.len());
    for m in &lb.members {
        let port = topo
            .ports()
            .iter()
            .find(|p| p.host == m.host && p.tap == m.tap)
            .ok_or_else(|| anyhow!("member {}/{} names no declared port", m.host, m.tap))?;
        members.push(LbMember {
            port_id: port.id.clone(),
            port: m.port,
        });
    }
    Ok(LoadBalancer {
        id: lb.id.clone(),
        vni: lb.vni,
        vip: lb
            .vip
            .parse()
            .map_err(|_| anyhow!("invalid vip {:?}", lb.vip))?,
        port: lb.port,
        proto: lb.proto,
        members,
    })
}

/// Build the orchestrator [`Topology`] from a parsed file (validating addresses,
/// MACs, subnets, and references as it goes).
fn build(tf: &TopologyFile) -> Result<Topology> {
    let mut topo = Topology::new();
    for h in &tf.hosts {
        let vtep_ip: Ipv4Addr = h
            .vtep
            .parse()
            .with_context(|| format!("host {:?}: invalid vtep {:?}", h.id, h.vtep))?;
        let underlay_mac = parse_mac(&h.underlay_mac).map_err(|e| {
            anyhow!(
                "host {:?}: invalid underlay_mac {:?}: {e}",
                h.id,
                h.underlay_mac
            )
        })?;
        topo.add_host(Host {
            id: h.id.clone(),
            vtep_ip,
            underlay_iface: h.underlay_iface.clone(),
            underlay_mac,
            encap: h.encap,
            udp_port: h.udp_port,
            underlay_mtu: h.underlay_mtu,
            srv6_locator: match &h.srv6_locator {
                None => None,
                Some(text) => {
                    let (addr, len) = text.split_once('/').ok_or_else(|| {
                        anyhow!(
                            "host {:?}: srv6_locator {text:?} must be written as prefix/len",
                            h.id
                        )
                    })?;
                    let addr: std::net::Ipv6Addr = addr.parse().map_err(|_| {
                        anyhow!("host {:?}: invalid srv6_locator prefix in {text:?}", h.id)
                    })?;
                    let len: u8 = len.parse().map_err(|_| {
                        anyhow!("host {:?}: invalid srv6_locator length in {text:?}", h.id)
                    })?;
                    Some((addr, len))
                }
            },
        })?;
    }
    for n in &tf.networks {
        let subnet = parse_cidr_v4(&n.subnet)
            .map_err(|e| anyhow!("network {}: invalid subnet {:?}: {e}", n.vni, n.subnet))?;
        topo.add_network(Network {
            vni: n.vni,
            name: n.name.clone(),
            subnet,
            default_action: n.default_action,
            drop_icmp: n.drop_icmp,
        })?;
    }
    // Subnets (D2) reference a network by VNI, so add them after networks.
    for s in &tf.subnets {
        topo.add_subnet(subnet_from_file(s)?)?;
    }
    // Security groups (B5) must exist before ports can bind them by name.
    for g in &tf.security_groups {
        topo.add_security_group(SecurityGroup {
            name: g.name.clone(),
            default_action: g.default_action,
            drop_icmp: g.drop_icmp,
            stateful: g.stateful,
            blocklist: g.blocklist.clone(),
            rules: g.rules.clone(),
        })?;
    }
    // IP-VRFs (B7). After networks, so a membership list can only name a VNI that
    // exists.
    for v in &tf.ip_vrfs {
        let gateway_mac = parse_mac(&v.gateway_mac).map_err(|e| {
            anyhow!(
                "ip_vrf {}: invalid gateway_mac {:?}: {e}",
                v.name,
                v.gateway_mac
            )
        })?;
        // Membership, VNI range and the gateway MAC are all validated by
        // `add_ip_vrf` — the single gate every driver goes through, file or API.
        topo.add_ip_vrf(IpVrf {
            l3_vni: v.l3_vni,
            name: v.name.clone(),
            gateway_mac,
            networks: v.networks.clone(),
        })
        .with_context(|| format!("ip_vrf {}", v.name))?;
    }
    for p in &tf.ports {
        let ip = match &p.ip {
            Some(s) => Some(
                s.parse::<Ipv4Addr>()
                    .with_context(|| format!("port {}/{}: invalid ip {s:?}", p.host, p.tap))?,
            ),
            None => None,
        };
        // A named security group sets the policy via its deterministic id, so
        // create the port policy-less then bind by name; otherwise honour the
        // raw M4 policy id (if any).
        let policy = if p.security_group.is_some() {
            None
        } else {
            p.policy
        };
        // A MAC the caller chose, or one derived from the address. See
        // `CreatePortRequest.mac` for why the caller sometimes has to be the
        // one to say.
        let mac = match &p.mac {
            Some(mac) => Some(
                velstra_common::parse_mac(mac).map_err(|e| anyhow::anyhow!("mac {mac:?}: {e}"))?,
            ),
            None => None,
        };
        let created = topo.create_port(p.network, &p.host, &p.tap, ip, policy, mac)?;
        if let Some(group) = &p.security_group {
            topo.set_port_security_group(&created.id, Some(group))?;
        }
    }
    // Load balancers last: a member names a port, so every port must exist.
    for lb in &tf.load_balancers {
        let built =
            build_load_balancer(&topo, lb).with_context(|| format!("load_balancer {}", lb.id))?;
        topo.add_load_balancer(built)
            .with_context(|| format!("load_balancer {}", lb.id))?;
    }
    Ok(topo)
}

/// Build a [`Subnet`] from its file form (validating the CIDR family, gateway,
/// and pool endpoints).
fn subnet_from_file(s: &SubnetFile) -> Result<Subnet> {
    let cidr = if s.cidr.contains(':') {
        SubnetCidr::V6(
            parse_cidr_v6(&s.cidr)
                .map_err(|e| anyhow!("subnet {:?}: invalid cidr {:?}: {e}", s.id, s.cidr))?,
        )
    } else {
        SubnetCidr::V4(
            parse_cidr_v4(&s.cidr)
                .map_err(|e| anyhow!("subnet {:?}: invalid cidr {:?}: {e}", s.id, s.cidr))?,
        )
    };
    let gateway = match &s.gateway {
        Some(g) => Some(
            g.parse::<IpAddr>()
                .with_context(|| format!("subnet {:?}: invalid gateway {g:?}", s.id))?,
        ),
        None => None,
    };
    let pool = match (&s.pool_start, &s.pool_end) {
        (Some(a), Some(b)) => Some(AllocRange {
            start: a
                .parse::<IpAddr>()
                .with_context(|| format!("subnet {:?}: invalid pool_start {a:?}", s.id))?,
            end: b
                .parse::<IpAddr>()
                .with_context(|| format!("subnet {:?}: invalid pool_end {b:?}", s.id))?,
        }),
        (None, None) => None,
        _ => bail!(
            "subnet {:?}: pool requires both pool_start and pool_end",
            s.id
        ),
    };
    Ok(Subnet {
        id: s.id.clone(),
        vni: s.vni,
        cidr,
        gateway,
        pool,
        enable_dhcp: s.enable_dhcp,
    })
}

/// Derive every host's `NodeConfig` from the topology, validating each (via
/// `resolve`) before it can be served. Returns `node_id -> config` (version 0;
/// the controller stamps a real version on serve).
///
/// When `evpn` is `Some`, EVPN-learned type-2 MAC/IP routes are folded into each
/// host's config on top of the topology-derived entries (roadmap B4a); pass
/// `None` to derive from the topology alone.
pub fn derive_configs(
    topo: &Topology,
    evpn: Option<&EvpnLearned>,
) -> Result<HashMap<String, NodeConfig>> {
    let mut out = HashMap::new();
    for host in topo.hosts() {
        let mut file = topo
            .derive(&host.id)
            .ok_or_else(|| anyhow!("host {:?} vanished mid-derive", host.id))?;
        if let Some(evpn) = evpn {
            append_evpn_entries(&mut file, host, topo, evpn);
        }
        file.resolve()
            .with_context(|| format!("derived config for host {:?} is invalid", host.id))?;
        out.insert(host.id.clone(), file_config_to_proto(&file, 0));
    }
    Ok(out)
}

/// The `End.DT2U` (unicast) service SID this fabric *would* derive for `remote`'s
/// `vni` from its topology locator, or `None` when `remote` runs no SRv6 locator.
///
/// Shared by [`append_evpn_entries`] (the bring-up fallback when a peer advertised
/// no SID) and [`srv6_divergences`] (the reference a learned SID is compared
/// against), so the "what we would derive" answer is computed one way in both.
fn derived_unicast_sid(remote: &Host, vni: u32) -> Option<Ipv6Addr> {
    let (loc, len) = remote.srv6_locator?;
    srv6_service_sid(loc, len, srv6_disc::UNICAST, vni)
}

/// The `End.DT2M` (BUM flood) service SID this fabric would derive for `remote`'s
/// `vni`. The flood twin of [`derived_unicast_sid`] — a distinct discriminator, so
/// one VNI's two behaviours never share a SID (RFC 9252).
fn derived_multicast_sid(remote: &Host, vni: u32) -> Option<Ipv6Addr> {
    let (loc, len) = remote.srv6_locator?;
    srv6_service_sid(loc, len, srv6_disc::MULTICAST, vni)
}

/// The trusted decap source of an **external** (non-topology) SRv6 peer, recovered
/// from the service SID it advertised over EVPN.
///
/// A learned VTEP that is not a configured fabric host has no topology entry to
/// borrow a next-hop `via_mac` from, so this host cannot *encapsulate toward* it —
/// that needs underlay next-hop resolution EVPN does not carry (a routed-underlay
/// concern deferred with the rest of external-peer *forwarding*). But it can still
/// **accept** that peer's frames on decap: the datapath source-auth (`SRV6_PEERS`)
/// is keyed on the peer's zero-filled locator, which [`locator_src_from_service_sid`]
/// recovers from the learned SID alone when the peer follows the standard
/// locator-derived layout (the layout wren originates, so a federated wren / RFC
/// 9252 speaker with its own locator matches). A foreign-layout SID recovers
/// nothing and is left untrusted — its decap-auth needs the SID structure on the
/// wire, a later interop-gated chunk. `disc` is the behaviour the SID was learned
/// under: `UNICAST` for an RT-2 MAC, `MULTICAST` for an RT-3 flood.
fn external_peer_decap_src(learned_sid: Ipv6Addr, disc: u8, vni: u32) -> Option<Ipv6Addr> {
    locator_src_from_service_sid(&learned_sid.octets(), disc, vni).map(Ipv6Addr::from)
}

/// A learned L2 SRv6 SID that disagrees with what this fabric's locator math would
/// derive for the same `(peer, vni, behaviour)`.
///
/// This is the operator's early warning that a peer **allocates** SIDs rather than
/// deriving them — an external RFC 9252 PE (FRR/Cisco) that assigns SIDs from its
/// own pool. It is *not* an error: EVPN-learned SIDs are authoritative (see
/// [`append_evpn_entries`]), so a divergent SID is programmed as advertised. The
/// divergence is surfaced only so a heterogeneous fleet is visible instead of
/// silently masked by derivation — the exact failure Stage 1 of the
/// EVPN-over-SRv6 convergence plan closes (gap G1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Srv6Divergence {
    /// The (L2) VNI the SID serves.
    pub vni: u32,
    /// `"end.dt2u"` (RT-2 unicast) or `"end.dt2m"` (RT-3 flood) — the two L2
    /// behaviours this fabric derives and can therefore compare against.
    pub behavior: &'static str,
    /// The advertising peer's VTEP.
    pub vtep: IpAddr,
    /// The SID the peer advertised over EVPN (the one actually programmed).
    pub learned_sid: Ipv6Addr,
    /// The SID this fabric's locator math would have produced.
    pub derived_sid: Ipv6Addr,
}

/// Scan learned EVPN state against the topology and return every learned L2 SRv6
/// SID that diverges from the one this fabric would derive.
///
/// **Pure**: a function of `(topology, learned)` only, so it unit-tests directly
/// and is recomputed on each re-derive with no side effects. Only the L2
/// behaviours are compared — RT-2 `End.DT2U` and RT-3 `End.DT2M` — because those
/// are the SIDs the fabric both derives and programs. RT-5 (`End.DT4`/`End.DT6`)
/// is deliberately re-derived today (Stage 3 of the convergence plan owns learning
/// it), so there is no learned-vs-derived L2 SID to compare for a type-5 route.
///
/// A peer that is not a known fabric host, or a known host with no SRv6 locator,
/// yields no derived SID to compare against and is therefore never reported — it
/// is not "divergent", it is simply outside what this fabric derives.
pub fn srv6_divergences(topo: &Topology, evpn: &EvpnLearned) -> Vec<Srv6Divergence> {
    let mut out = Vec::new();
    // RT-2 End.DT2U: every learned MAC that carries a SID and lives behind a known
    // fabric host we can derive a reference SID for.
    for (vni, _mac, learned) in evpn.iter_macs() {
        let (Some(learned_sid), IpAddr::V4(v4)) = (learned.srv6_sid, learned.vtep) else {
            continue;
        };
        let Some(remote) = topo.hosts().find(|h| h.vtep_ip == v4) else {
            continue;
        };
        if let Some(derived_sid) = derived_unicast_sid(remote, vni)
            && derived_sid != learned_sid
        {
            out.push(Srv6Divergence {
                vni,
                behavior: "end.dt2u",
                vtep: learned.vtep,
                learned_sid,
                derived_sid,
            });
        }
    }
    // RT-3 End.DT2M: the flood SID a peer advertised for a VNI.
    for (&vni, vtep_set) in evpn.floods() {
        for (vtep, learned_sid) in vtep_set {
            let (Some(learned_sid), IpAddr::V4(v4)) = (*learned_sid, *vtep) else {
                continue;
            };
            let Some(remote) = topo.hosts().find(|h| h.vtep_ip == v4) else {
                continue;
            };
            if let Some(derived_sid) = derived_multicast_sid(remote, vni)
                && derived_sid != learned_sid
            {
                out.push(Srv6Divergence {
                    vni,
                    behavior: "end.dt2m",
                    vtep: *vtep,
                    learned_sid,
                    derived_sid,
                });
            }
        }
    }
    out.sort();
    out
}

/// A learned type-5 (`End.DT4`/`End.DT6`) SRv6 SID this fabric **cannot make
/// authoritative** because the datapath terminates only the L2 behaviours
/// (`End.DT2U`/`End.DT2M`).
///
/// This is the Stage-3 counterpart of [`Srv6Divergence`], and the two are
/// deliberately *not* the same signal. A Stage-1 divergence is "the peer allocated
/// a different SID than we would derive for the **same** behaviour, and we programmed
/// the peer's" — authority inverted, learned wins. An IRB gate is the opposite
/// outcome: the peer advertised an L3 SID (a bare-IP `End.DT4`/`End.DT6` payload,
/// RFC 9252 §6) whose behaviour class this host model has no way to terminate — it
/// has a single shared kernel bridge, not the per-tenant L3 device an L3 decap needs
/// (see `velstra_common::srv6::Srv6IrbEndpoint` and `try_srv6_decap`). So the learned
/// SID is **refused as authoritative** and the L3-VNI's derived `End.DT2U` SID is
/// programmed instead (the RFC 9136 symmetric-IRB-over-DT2U path B9 shipped), exactly
/// as [`append_evpn_entries`] does at the type-5 fold.
///
/// Surfacing it is the honest half of that gate: without this, an operator pointing a
/// third-party RFC 9252 PE at the fabric sees inter-subnet interop silently fall back
/// to the derived SID with no indication that the advertised L3 SID was dropped on the
/// floor. Making these SIDs authoritative (true `End.DT4`/`End.DT6` decap + L3 encap in
/// XDP) is the remaining Stage-3 datapath work; until it lands, this is the "refuse the
/// rest, and say so" the convergence plan's gate calls for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Srv6IrbGatedSid {
    /// The tenant's L3 VNI the type-5 route names.
    pub l3_vni: u32,
    /// The routed prefix (CIDR text, as learned off the wire).
    pub prefix: String,
    /// The advertising peer's VTEP.
    pub vtep: IpAddr,
    /// The `End.DT4`/`End.DT6` SID the peer advertised — refused as authoritative.
    pub learned_sid: Ipv6Addr,
    /// `"end.dt4"` (a v4 prefix) or `"end.dt6"` (a v6 prefix) — the L3 behaviour the
    /// learned SID carries by RFC 9252 §6, inferred from the prefix family.
    pub behavior: &'static str,
    /// The derived L3-VNI `End.DT2U` SID actually programmed toward this peer in the
    /// learned one's place (the symmetric-IRB-over-DT2U fallback).
    pub programmed_sid: Ipv6Addr,
}

/// Scan learned EVPN state and return every type-5 SRv6 SID the datapath cannot yet
/// honour — the Stage-3 gate surface (a peer advertised an `End.DT4`/`End.DT6` L3 SID
/// this host model cannot terminate).
///
/// **Pure**: a function of `(topology, learned)` only, recomputed on each re-derive
/// with no side effects, so it unit-tests directly — the same contract as
/// [`srv6_divergences`]. It reports exactly the routes [`append_evpn_entries`] would
/// install an SRv6 IRB entry for (a known SRv6 fabric-host peer, a v4 prefix — the
/// datapath's IRB path is v4-only) that additionally advertised a SID: those are the
/// ones where a learned L3 SID was present and dropped in favour of the derived DT2U
/// SID. An external (non-topology) peer, or one that advertised no SID, yields nothing
/// — there is no learned L3 SID being refused.
pub fn srv6_irb_gated_sids(topo: &Topology, evpn: &EvpnLearned) -> Vec<Srv6IrbGatedSid> {
    let mut out = Vec::new();
    for (l3_vni, prefix, learned) in evpn.iter_prefixes() {
        // Only a route this fabric actually processes: a hosted VRF for the L3 VNI…
        if !topo.ip_vrfs().any(|v| v.l3_vni == l3_vni) {
            continue;
        }
        // …that advertised an L3 SID (the thing being gated)…
        let (Some(learned_sid), IpAddr::V4(v4)) = (learned.srv6_sid, learned.vtep) else {
            continue;
        };
        // …behind a known SRv6 fabric host we derive the DT2U fallback for.
        let Some(remote) = topo.hosts().find(|h| h.vtep_ip == v4) else {
            continue;
        };
        let Some(programmed_sid) = derived_unicast_sid(remote, l3_vni) else {
            continue;
        };
        // The IRB datapath is v4-only (a v6 prefix has no L3 map to go in), matching
        // `append_evpn_entries`' `prefix.contains('.')` gate; label the behaviour by
        // the family so a future v6 route reads honestly.
        let behavior = if prefix.contains('.') {
            "end.dt4"
        } else {
            "end.dt6"
        };
        if behavior == "end.dt6" {
            // No v6 IRB route is programmed today, so there is no DT2U fallback in
            // its place — nothing was gated in the "refused in favour of" sense.
            continue;
        }
        out.push(Srv6IrbGatedSid {
            l3_vni,
            prefix: prefix.to_string(),
            vtep: learned.vtep,
            learned_sid,
            behavior,
            programmed_sid,
        });
    }
    out.sort();
    out
}

/// Fold EVPN-learned type-2 MAC/IP routes into `host`'s derived `file`, on top
/// of (and after) the topology-derived overlay entries (roadmap B4a).
///
/// Every type-2 MAC (MAC-only **and** MAC/IP) becomes an L2 [`MacRouteCfg`] for
/// the B1 MAC-FDB datapath, so the overlay bridges by destination MAC. Routes
/// that additionally carry a bound IP are programmable through the v4
/// `OVERLAY_FDB` + `ARP_TABLE` maps too: each such entry also emits an
/// ARP-suppression [`NeighborCfg`] plus an L3 [`TunnelCfg`] with
/// `inner_dst = ip/32`. A **v6** bound IP instead emits a B3 IPv6
/// ND-suppression [`Nd6Cfg`] (the L3 `OVERLAY_FDB` stays v4-only). So a MAC-only
/// entry yields one `MacRouteCfg`; a v4 MAC/IP entry yields `MacRouteCfg` +
/// `NeighborCfg` + `TunnelCfg`; a v6 MAC/IP entry yields `MacRouteCfg` +
/// `Nd6Cfg`.
///
/// **Type-5 IP Prefix routes** (`evpn.iter_prefixes()`, B7) become `IrbRouteCfg`
/// entries — see that type for why they are keyed on the ingress VNI and kept
/// separate from a bridged tunnel.
///
/// **Type-3 IMET flood VTEPs** (`evpn.floods()`) are now folded too (roadmap
/// B2): each v4 flood VTEP that is a known fabric host becomes a `FloodVtepCfg`
/// programming that VNI's `FLOOD_LIST` head-end replication set, and the agent
/// derives its `VTEP_PEERS` trusted-decap entry from it. We still defer:
/// * v6 VTEPs — the maps are v4-only today (`remote_vtep` an `Ipv4Addr`), and
///   v6 inner IPs in the L3 `OVERLAY_FDB` (`inner_dst` is a `Cidr4`), which drop
///   the L3 tunnel for a v6 entry but keep its MAC route and ND neighbour.
///
/// `via_mac`/`out_iface` mirror `Topology::derive` exactly (see `Host::underlay_mac`):
/// the next-hop `via_mac` is the remote VTEP host's underlay MAC, and `out_iface`
/// is this host's underlay iface. That means we can only program a VTEP that is a
/// **known fabric host** (we borrow its underlay MAC); an unknown/external VTEP is
/// held in [`EvpnLearned`] but not programmed (a routed underlay would resolve the
/// gateway MAC — a later chunk).
///
/// EVPN-managed and orchestrator-managed VNIs are expected disjoint (the
/// `EVPN_RESERVED_VNI_BASE` convention). Entries are appended after the
/// topology-derived ones, so on a key collision the agent's last-write-wins map
/// programming lets the EVPN entry win.
fn append_evpn_entries(file: &mut FileConfig, host: &Host, topo: &Topology, evpn: &EvpnLearned) {
    // Which set of tables this host's learned entries land in. Decided once, from
    // the host's declared wire family, so a learned route can never end up in the
    // table the *other* overlay reads — where it would validate, load, and carry
    // nothing.
    let is_srv6 = host.encap.is_srv6();

    // Trusted decap peers accumulated from the EVPN-learned SRv6 entries below.
    // A host known only through EVPN shares no topology port with this host, so
    // the port-derived peer set (`velstra-orchestrator`'s `derive`) never lists
    // it — yet we are about to encap toward its service SIDs. Without also
    // trusting its outer source, the datapath's `srv6_drop_untrusted` check drops
    // that host's return traffic fail-closed: a one-way blackhole that reads like
    // a routing bug. Each peer's identity is its `srv6_src()` (the zero-filled
    // locator), exactly the form both the port-derived path and the `SRV6_PEERS`
    // datapath check use. Merged into `file.srv6.peers` at the end.
    let mut evpn_peers: Vec<String> = Vec::new();

    for (vni, mac, learned) in evpn.iter_macs() {
        // v4-only datapath today: skip v6 VTEPs (these gates apply to the L2 MAC
        // route as well as the L3 tunnel below).
        let IpAddr::V4(vtep) = learned.vtep else {
            continue;
        };
        // Never tunnel to ourselves.
        if vtep == host.vtep_ip {
            continue;
        }
        // Borrow the remote VTEP host's underlay MAC as the next hop (mirrors
        // the topology derive). An external VTEP we don't know cannot be
        // encapsulated toward (no next-hop MAC) — but if it advertised a
        // standard-layout End.DT2U SID we still trust it as a decap source, so
        // its BUM/return traffic is accepted instead of dropped fail-closed.
        let remote = match topo.hosts().find(|h| h.vtep_ip == vtep) {
            Some(r) => r,
            None => {
                if is_srv6
                    && let Some(sid) = learned.srv6_sid
                    && let Some(src) = external_peer_decap_src(sid, srv6_disc::UNICAST, vni)
                {
                    evpn_peers.push(src.to_string());
                }
                continue;
            }
        };
        // B1: every type-2 MAC (MAC-only AND MAC/IP) gets an L2 bridging entry so
        // the datapath can bridge by destination MAC, independent of the L3 FDB.
        // Which table it lands in follows *this* host's wire family, and the SRv6
        // one needs a service SID rather than a VTEP address.
        if is_srv6 {
            // EVPN-learned SID is authoritative (convergence plan Stage 1, gap G1).
            // When the advertising PE put a SID in its Prefix-SID attribute we
            // program *that* SID verbatim — even when it diverges from what our
            // locator math would derive, because an external RFC 9252 PE allocates
            // SIDs from its own pool and its SID is the only thing that reaches it.
            // The divergence itself is counted and surfaced separately
            // (`srv6_divergences`) so a heterogeneous fleet is visible, not masked.
            //
            // Derivation is only the bring-up fallback: a learned SID is present
            // just once the BGP session is up and the route has arrived, whereas
            // the derived SID holds from the moment the peer exists in the topology
            // — so a fabric whose control plane is still converging still bridges.
            let sid = learned
                .srv6_sid
                .or_else(|| derived_unicast_sid(remote, vni));
            match sid {
                Some(sid) => {
                    file.srv6_routes.push(Srv6RouteCfg {
                        vni,
                        mac: fmt_mac(mac),
                        remote_sid: sid.to_string(),
                        via_mac: fmt_mac(remote.underlay_mac),
                        out_iface: host.underlay_iface.clone(),
                    });
                    // The peer's outer source becomes a trusted decap source, or
                    // its return frames hit `srv6_drop_untrusted` and are refused.
                    if let Some(src) = remote.srv6_src() {
                        evpn_peers.push(src.to_string());
                    }
                }
                // No learned SID and no locator: a pure-VXLAN peer. An SRv6 host
                // carries no `[overlay]` (the two are mutually exclusive per host),
                // so it cannot bridge VXLAN to reach this peer at all — the config
                // model has no mixed-transport host (that coexistence is a later
                // stage). Held, not programmed; logged so a genuinely unreachable
                // peer is visible rather than a silent blackhole.
                None => log::warn!(
                    "evpn: srv6 host {:?} learned mac {} on vni {vni} behind vxlan-only \
                     peer {vtep} (no advertised or derivable SID); held, not programmed",
                    host.id,
                    fmt_mac(mac),
                ),
            }
        } else {
            file.mac_routes.push(MacRouteCfg {
                vni,
                mac: fmt_mac(mac),
                remote_vtep: vtep.to_string(),
                via_mac: fmt_mac(remote.underlay_mac),
                out_iface: host.underlay_iface.clone(),
            });
        }
        // A bound IP additionally gets neighbour suppression. A v4 IP also gets
        // L3 `OVERLAY_FDB` forwarding; a v6 IP is programmable as an `ND_TABLE`
        // entry (B3) but the L3 FDB stays v4-only, so it emits only the ND
        // neighbour. A MAC-only entry stops above with just its MAC route.
        match learned.ip {
            Some(IpAddr::V4(ip)) => {
                file.neighbors.push(NeighborCfg {
                    vni,
                    ip: ip.to_string(),
                    mac: fmt_mac(mac),
                });
                // The L3 (inner-IP) FDB is a VXLAN-only shortcut; SRv6 bridges
                // by MAC and has no equivalent table, which costs it nothing —
                // the MAC entry above already reaches the same workload.
                if !is_srv6 {
                    file.tunnels.push(TunnelCfg {
                        vni,
                        inner_dst: format!("{ip}/32"),
                        remote_vtep: vtep.to_string(),
                        via_mac: fmt_mac(remote.underlay_mac),
                        out_iface: host.underlay_iface.clone(),
                    });
                }
            }
            // B3: a learned v6 bound IP becomes an IPv6 ND-suppression neighbour.
            Some(IpAddr::V6(ip6)) => {
                file.nd_neighbors.push(Nd6Cfg {
                    vni,
                    ip: ip6.to_string(),
                    mac: fmt_mac(mac),
                });
            }
            None => {}
        }
    }

    // B7: fold type-5 IP Prefix routes into symmetric-IRB routes. A learned route
    // names the tenant only by its L3 VNI, so it is joined to the IP-VRF holding
    // that VNI and then expanded across the tenant's L2 segments — one entry per
    // ingress VNI, since the datapath keys on the segment a packet arrives from.
    for (l3_vni, prefix, learned) in evpn.iter_prefixes() {
        let Some(vrf) = topo.ip_vrfs().find(|v| v.l3_vni == l3_vni) else {
            // A route for a tenant this fabric does not host. Held, not programmed:
            // without the IP-VRF we know neither which segments may reach it nor
            // which gateway MAC to route it from.
            continue;
        };
        // Without the Router's MAC there is no inner destination to encapsulate
        // toward, so the route is unusable over VXLAN (RFC 9136 §4.4.1 requires it
        // for exactly this reason).
        let Some(router_mac) = learned.router_mac else {
            continue;
        };
        let IpAddr::V4(vtep) = learned.vtep else {
            continue;
        };
        if vtep == host.vtep_ip {
            continue;
        }
        let Some(remote) = topo.hosts().find(|h| h.vtep_ip == vtep) else {
            continue;
        };
        // The L3 overlay FDB is v4-only, so a v6 tenant prefix has no map to go in.
        if !prefix.contains('.') {
            continue;
        }
        // On SRv6 the routed frame goes to the peer's End.DT2U SID for the
        // tenant's **L3** VNI — RFC 9136 symmetric IRB puts a rewritten Ethernet
        // frame on the wire under the L3 VNI, and that is an L2 SID.
        //
        // Note this deliberately does NOT use `learned.srv6_sid`. A type-5 route
        // carries an End.DT4/DT6 SID (RFC 9252 §6), which is a *different*
        // behaviour: its payload is a bare IP packet, and terminating one needs a
        // per-tenant L3 device this host model does not have. Programming the
        // advertised SID would build an encapsulation the far end refuses. So the
        // L3-VNI L2 SID is derived from the peer's locator instead.
        //
        // Making the learned End.DT4/DT6 SID authoritative here (the L3 half of
        // the unified plane) is **Stage 3** of the EVPN-over-SRv6 convergence plan
        // (gap G3): it needs DT4/DT6 decap in the XDP datapath, which does not
        // exist yet. Stage 1 inverts authority for L2 only; leaving this derivation
        // in place is deliberate, not an oversight. Stage 3's first slice does not
        // change this line — it makes the refusal *visible*: every learned L3 SID
        // dropped here is reported by [`srv6_irb_gated_sids`] and surfaced at
        // `/v1/srv6/irb-gated`, so an operator sees the advertised End.DT4/DT6 SID
        // was gated rather than silently ignored.
        let srv6_sid = is_srv6
            .then(|| derived_unicast_sid(remote, l3_vni))
            .flatten();
        if is_srv6 && srv6_sid.is_none() {
            // A VXLAN peer cannot route for an SRv6 host. Held, not programmed.
            continue;
        }
        // Symmetric IRB is symmetric: whatever we encapsulate into a tenant's L3
        // VNI, the peer sends back into the same one — addressed to *our* End.DT2U
        // SID for it. So a host that routes into an L3 VNI must also instantiate
        // that VNI's SID, or the return traffic hits `SRV6_LOCAL_SIDS`, misses,
        // and falls through to the firewall.
        //
        // This is the SRv6 twin of the `LOCAL_VNIS` registration the VXLAN path
        // does for the same reason, and it is easy to miss for the same reason: an
        // L3 VNI belongs to no local tenant port, so nothing else ever registers
        // it. The failure is one-way reachability, which reads like a routing
        // problem rather than a missing table entry.
        if is_srv6 && let Some(own) = derived_unicast_sid(host, l3_vni) {
            let sid = own.to_string();
            if !file.srv6_local_sids.iter().any(|ls| ls.sid == sid) {
                file.srv6_local_sids.push(Srv6LocalSidCfg {
                    sid,
                    vni: l3_vni,
                    behavior: Some("end.dt2u".to_string()),
                });
            }
        }
        if is_srv6 && let Some(src) = remote.srv6_src() {
            evpn_peers.push(src.to_string());
        }
        for &vni in &vrf.networks {
            match srv6_sid {
                Some(sid) => file.srv6_irb_routes.push(Srv6IrbRouteCfg {
                    vni,
                    inner_dst: prefix.to_string(),
                    l3_vni,
                    remote_sid: sid.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                    router_mac: fmt_mac(router_mac),
                    gateway_mac: fmt_mac(vrf.gateway_mac),
                }),
                None => file.irb_routes.push(IrbRouteCfg {
                    vni,
                    inner_dst: prefix.to_string(),
                    l3_vni,
                    remote_vtep: vtep.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                    router_mac: fmt_mac(router_mac),
                    gateway_mac: fmt_mac(vrf.gateway_mac),
                }),
            }
        }
    }

    // B2: fold type-3 IMET flood VTEPs into this host's per-VNI flood set. Each
    // remote v4 flood VTEP that is a known fabric host becomes a `FloodVtepCfg`,
    // mirroring the same next-hop convention as the MAC/tunnel entries above:
    // `via_mac` is the remote VTEP host's underlay MAC, `out_iface` this host's
    // underlay iface. Skip self, skip v6, and skip an unknown/external VTEP we
    // can't borrow a next-hop MAC for (a routed underlay is a later chunk).
    for (&vni, vtep_set) in evpn.floods() {
        for (vtep, learned_sid) in vtep_set {
            let IpAddr::V4(vtep) = vtep else {
                continue;
            };
            if *vtep == host.vtep_ip {
                continue;
            }
            let remote = match topo.hosts().find(|h| h.vtep_ip == *vtep) {
                Some(r) => r,
                None => {
                    // External flood peer: cannot be replicated toward (no
                    // next-hop MAC), but a standard-layout End.DT2M SID makes it a
                    // trusted decap source for the flood copies it sends us.
                    if is_srv6
                        && let Some(sid) = *learned_sid
                        && let Some(src) = external_peer_decap_src(sid, srv6_disc::MULTICAST, vni)
                    {
                        evpn_peers.push(src.to_string());
                    }
                    continue;
                }
            };
            if is_srv6 {
                // The peer's **End.DT2M** SID. Learned is authoritative (Stage 1,
                // gap G1): an advertised flood SID is programmed verbatim, derived
                // from the peer's locator only as the bring-up fallback. It is a
                // different SID from the unicast one: RFC 9252 binds a SID to one
                // behaviour, so a flood copy sent to the unicast SID is bridged to
                // a single MAC and every other workload on the segment misses it.
                let sid = learned_sid.or_else(|| derived_multicast_sid(remote, vni));
                if let Some(sid) = sid {
                    file.srv6_floods.push(Srv6FloodCfg {
                        vni,
                        remote_sid: sid.to_string(),
                        via_mac: fmt_mac(remote.underlay_mac),
                        out_iface: host.underlay_iface.clone(),
                    });
                    if let Some(src) = remote.srv6_src() {
                        evpn_peers.push(src.to_string());
                    }
                }
            } else {
                file.flood_vteps.push(FloodVtepCfg {
                    vni,
                    remote_vtep: vtep.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                });
            }
        }
    }

    // Merge the EVPN-learned peers into the trusted decap set, deduped against the
    // port-derived entries already present (and against themselves). Only an SRv6
    // host has a `file.srv6`; a VXLAN host accumulated nothing above, so this is a
    // no-op there. Without this, the encap entries pushed above point at hosts
    // whose return traffic `srv6_drop_untrusted` would refuse — see `evpn_peers`.
    if let Some(srv6) = file.srv6.as_mut() {
        for src in evpn_peers {
            if !srv6.peers.contains(&src) {
                srv6.peers.push(src);
            }
        }
    }
}

/// Read, parse, and build the live [`Topology`] model from a file (the seed /
/// persistent store for the orchestrator; runtime changes go through the gRPC
/// API and are written back via [`save_model`]).
pub fn load_model(path: &Path) -> Result<Topology> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading topology {}", path.display()))?;
    let tf: TopologyFile =
        toml::from_str(&text).with_context(|| format!("parsing topology {}", path.display()))?;
    build(&tf)
}

fn fmt_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// Serialise the live model back into the file schema. Ports pin their allocated
/// IP so a reload reproduces the exact same addresses (and thus ids/MACs).
fn to_file(topo: &Topology) -> TopologyFile {
    let mut hosts: Vec<HostFile> = topo
        .hosts()
        .map(|h| HostFile {
            id: h.id.clone(),
            vtep: h.vtep_ip.to_string(),
            underlay_iface: h.underlay_iface.clone(),
            underlay_mac: fmt_mac(h.underlay_mac),
            encap: h.encap,
            udp_port: h.udp_port,
            underlay_mtu: h.underlay_mtu,
            srv6_locator: h.srv6_locator.map(|(a, l)| format!("{a}/{l}")),
        })
        .collect();
    hosts.sort_by(|a, b| a.id.cmp(&b.id)); // stable on-disk order

    let mut networks: Vec<NetworkFile> = topo
        .networks()
        .map(|n| NetworkFile {
            vni: n.vni,
            name: n.name.clone(),
            subnet: n.subnet.to_string(),
            default_action: n.default_action,
            drop_icmp: n.drop_icmp,
        })
        .collect();
    networks.sort_by_key(|n| n.vni);

    let mut subnets: Vec<SubnetFile> = topo.subnets().map(subnet_to_file).collect();
    subnets.sort_by(|a, b| a.id.cmp(&b.id));

    let mut security_groups: Vec<SecurityGroupFile> = topo
        .security_groups()
        .map(|g| SecurityGroupFile {
            name: g.name.clone(),
            default_action: g.default_action,
            drop_icmp: g.drop_icmp,
            stateful: g.stateful,
            blocklist: g.blocklist.clone(),
            rules: g.rules.clone(),
        })
        .collect();
    security_groups.sort_by(|a, b| a.name.cmp(&b.name));

    // Reverse-map a port's policy id back to its security-group name (if it
    // names one) so a bound port round-trips by name rather than raw id.
    let pid_to_name: HashMap<u32, String> = topo
        .security_groups()
        .map(|g| (g.policy_id(), g.name.clone()))
        .collect();
    let ports: Vec<PortFile> = topo
        .ports()
        .iter()
        .map(|p| {
            let security_group = p.policy.and_then(|pid| pid_to_name.get(&pid).cloned());
            PortFile {
                network: p.vni,
                host: p.host.clone(),
                tap: p.tap.clone(),
                ip: Some(p.ip.to_string()),
                // Written out only when it is not what this orchestrator would
                // derive: a file that repeats a derived value invites somebody
                // to change the address and wonder why the MAC did not follow.
                mac: (p.mac != velstra_orchestrator::mac_for(p.ip))
                    .then(|| velstra_orchestrator::fmt_mac(p.mac)),
                // A group-bound port serialises by name; an unnamed raw policy
                // keeps its numeric id.
                policy: if security_group.is_some() {
                    None
                } else {
                    p.policy
                },
                security_group,
            }
        })
        .collect();

    let mut ip_vrfs: Vec<IpVrfFile> = topo
        .ip_vrfs()
        .map(|v| IpVrfFile {
            l3_vni: v.l3_vni,
            name: v.name.clone(),
            gateway_mac: fmt_mac(v.gateway_mac),
            networks: v.networks.clone(),
        })
        .collect();
    ip_vrfs.sort_by_key(|v| v.l3_vni);

    let mut load_balancers: Vec<LoadBalancerFile> = topo
        .load_balancers()
        .map(|lb| LoadBalancerFile {
            id: lb.id.clone(),
            vni: lb.vni,
            vip: lb.vip.to_string(),
            port: lb.port,
            proto: lb.proto,
            members: lb
                .members
                .iter()
                .filter_map(|m| {
                    // Serialise a member back in file terms. A member whose port
                    // vanished is dropped rather than written as an unresolvable
                    // reference the next load would reject.
                    let port = topo.ports().iter().find(|p| p.id == m.port_id)?;
                    Some(LbMemberFile {
                        host: port.host.clone(),
                        tap: port.tap.clone(),
                        port: m.port,
                    })
                })
                .collect(),
        })
        .collect();
    load_balancers.sort_by(|a, b| a.id.cmp(&b.id));

    TopologyFile {
        hosts,
        networks,
        subnets,
        security_groups,
        ip_vrfs,
        load_balancers,
        ports,
    }
}

/// Serialise a live [`Subnet`] back into its file form.
fn subnet_to_file(s: &Subnet) -> SubnetFile {
    let (pool_start, pool_end) = match s.pool {
        Some(r) => (Some(r.start.to_string()), Some(r.end.to_string())),
        None => (None, None),
    };
    SubnetFile {
        id: s.id.clone(),
        vni: s.vni,
        cidr: match s.cidr {
            SubnetCidr::V4(c) => c.to_string(),
            SubnetCidr::V6(c) => c.to_string(),
        },
        gateway: s.gateway.map(|g| g.to_string()),
        pool_start,
        pool_end,
        enable_dhcp: s.enable_dhcp,
    }
}

/// Persist the live model to `path` **atomically** (write a sibling temp file,
/// then rename) so a crash mid-write never leaves a truncated topology.
pub fn save_model(topo: &Topology, path: &Path) -> Result<()> {
    let text = toml::to_string_pretty(&to_file(topo)).context("serialising topology")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_two_host_fabric_from_a_file() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[port]]
            network = 5000
            host = "h1"
            tap = "tapA"

            [[port]]
            network = 5000
            host = "h2"
            tap = "tapB"
        "#;
        let tf: TopologyFile = toml::from_str(toml).unwrap();
        let topo = build(&tf).unwrap();
        let configs = derive_configs(&topo, None).unwrap();

        assert_eq!(configs.len(), 2);
        // h1's derived config: a local interface tapA and a tunnel toward h2.
        let h1 = &configs["h1"];
        assert!(h1.interfaces.iter().any(|i| i.name == "tapA"));
        assert_eq!(h1.tunnels.len(), 1);
        assert_eq!(h1.tunnels[0].remote_vtep, "10.10.0.2");
        assert_eq!(h1.neighbors.len(), 1);
        assert!(h1.overlay.is_some());
    }

    #[test]
    fn save_then_load_reproduces_the_model() {
        // Build a model with an auto-allocated port, serialise it, parse it back,
        // and confirm the derived configs are identical (ids/IPs/MACs stable).
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
            [[port]]
            network = 5000
            host = "h1"
            tap = "tapA"
        "#;
        let original = build(&toml::from_str(toml).unwrap()).unwrap();

        // Round-trip through the on-disk schema.
        let serialised = toml::to_string_pretty(&to_file(&original)).unwrap();
        let reloaded = build(&toml::from_str(&serialised).unwrap()).unwrap();

        // The auto-allocated port survived with the same id/ip.
        assert_eq!(reloaded.ports().len(), 1);
        assert_eq!(reloaded.ports()[0].id, original.ports()[0].id);
        assert_eq!(reloaded.ports()[0].ip, original.ports()[0].ip);
        // And the derived config is byte-identical.
        let a = derive_configs(&original, None).unwrap();
        let b = derive_configs(&reloaded, None).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn folds_evpn_learned_type2_routes_into_derived_config() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        // h1 has a local port (participates); h2 is a known host (its vtep/MAC
        // are the next hop) but has no port, so h1's *base* config has no
        // tunnels/neighbors — anything below is purely EVPN-contributed.
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
            [[port]]
            network = 5000
            host = "h1"
            tap = "tapA"
        "#;
        let topo = build(&toml::from_str(toml).unwrap()).unwrap();

        // Baseline (no EVPN): h1 has no overlay peers.
        let base = derive_configs(&topo, None).unwrap();
        assert!(base["h1"].tunnels.is_empty());
        assert!(base["h1"].neighbors.is_empty());

        // Learn: a type-2 MAC/IP behind h2's VTEP (programmable), plus a
        // MAC-only entry (must NOT be programmed) on the reserved EVPN VNI.
        let evpn_vni = velstra_orchestrator::EVPN_RESERVED_VNI_BASE;
        let mut learned = EvpnLearned::default();
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: evpn_vni,
            mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            ip: Some("192.168.100.50".parse().unwrap()),
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        }));
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: evpn_vni,
            mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ip: None, // MAC-only: held, not programmed
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        }));
        // B3: a type-2 MAC/**IPv6** behind h2 — programmable as an ND neighbour
        // (but NOT as a v4 tunnel/neighbor, since the L3 FDB stays v4-only).
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: evpn_vni,
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x06],
            ip: Some("2001:db8::50".parse().unwrap()),
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        }));
        // B2: a type-3 IMET flood VTEP behind h2 (a known fabric host) — folds
        // into h1's per-VNI flood set. An unknown/external VTEP flood is held,
        // not programmed (no fabric host to borrow a next-hop MAC from).
        assert!(learned.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: evpn_vni,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        }));
        assert!(learned.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: evpn_vni,
            vtep: "203.0.113.9".parse().unwrap(),
            srv6_sid: None,
        }));

        let cfg = derive_configs(&topo, Some(&learned)).unwrap();
        let h1 = &cfg["h1"];

        // Exactly the one v4 MAC/IP entry became a tunnel + neighbor (MAC-only and
        // the v6 entry are both skipped for the v4 L3 path).
        assert_eq!(h1.tunnels.len(), 1);
        assert_eq!(h1.neighbors.len(), 1);

        // B3: the v6 MAC/IP entry became exactly one ND neighbour (correct
        // vni/ip/mac) and NO v4 tunnel or neighbor.
        assert_eq!(h1.nd_neighbors.len(), 1);
        let nd = &h1.nd_neighbors[0];
        assert_eq!(nd.vni, evpn_vni);
        assert_eq!(nd.ip, "2001:db8::50");
        assert_eq!(nd.mac, "de:ad:be:ef:00:06");
        assert!(
            !h1.neighbors.iter().any(|n| n.mac == "de:ad:be:ef:00:06"),
            "v6 entry must not produce a v4 ARP neighbor"
        );
        assert!(
            !h1.tunnels.iter().any(|t| t.inner_dst.contains(':')),
            "v6 entry must not produce a v4 L3 tunnel"
        );

        let t = &h1.tunnels[0];
        assert_eq!(t.vni, evpn_vni);
        assert_eq!(t.inner_dst, "192.168.100.50/32");
        assert_eq!(t.remote_vtep, "10.10.0.2");
        // via_mac mirrors the topology convention: the remote VTEP host's MAC.
        assert_eq!(t.via_mac, "02:00:00:00:00:22");
        assert_eq!(t.out_iface, "eth0");

        let n = &h1.neighbors[0];
        assert_eq!(n.vni, evpn_vni);
        assert_eq!(n.ip, "192.168.100.50");
        assert_eq!(n.mac, "aa:bb:cc:dd:ee:ff");

        // B1: EVERY type-2 MAC (v4 MAC/IP + MAC-only + v6 MAC/IP) yields a MAC-FDB
        // route. Order is map-iteration dependent, so look each up by its MAC.
        assert_eq!(h1.mac_routes.len(), 3);
        let mac_ip = h1
            .mac_routes
            .iter()
            .find(|m| m.mac == "aa:bb:cc:dd:ee:ff")
            .expect("MAC/IP entry has a mac route");
        assert_eq!(mac_ip.vni, evpn_vni);
        assert_eq!(mac_ip.remote_vtep, "10.10.0.2");
        assert_eq!(mac_ip.via_mac, "02:00:00:00:00:22");
        assert_eq!(mac_ip.out_iface, "eth0");

        let mac_only = h1
            .mac_routes
            .iter()
            .find(|m| m.mac == "11:22:33:44:55:66")
            .expect("MAC-only entry has a mac route");
        assert_eq!(mac_only.vni, evpn_vni);
        assert_eq!(mac_only.remote_vtep, "10.10.0.2");
        assert_eq!(mac_only.via_mac, "02:00:00:00:00:22");
        assert_eq!(mac_only.out_iface, "eth0");

        // The MAC-only entry contributed *exactly* its one mac route: no tunnel,
        // no neighbor references it.
        assert!(
            !h1.tunnels
                .iter()
                .any(|t| t.inner_dst.starts_with("0.0.0.0"))
        );
        assert!(
            !h1.neighbors.iter().any(|n| n.mac == "11:22:33:44:55:66"),
            "MAC-only entry must not produce a neighbor"
        );
        assert_eq!(
            h1.mac_routes
                .iter()
                .filter(|m| m.mac == "11:22:33:44:55:66")
                .count(),
            1,
            "MAC-only entry produces exactly one mac route"
        );

        // B2: the type-3 flood VTEP behind the known host h2 became exactly one
        // flood_vtep row (next-hop convention mirrors the tunnel/mac routes); the
        // unknown external VTEP (203.0.113.9) was held, not programmed.
        assert_eq!(h1.flood_vteps.len(), 1);
        let fv = &h1.flood_vteps[0];
        assert_eq!(fv.vni, evpn_vni);
        assert_eq!(fv.remote_vtep, "10.10.0.2");
        assert_eq!(fv.via_mac, "02:00:00:00:00:22");
        assert_eq!(fv.out_iface, "eth0");
    }

    /// One type-5 route becomes one entry per L2 segment of its tenant, because the
    /// datapath keys on the segment a packet arrives from. Routes for an unhosted
    /// tenant, or without a Router's MAC to address the inner frame to, are held
    /// but never programmed.
    #[test]
    fn derives_irb_routes_from_type5_across_the_tenants_segments() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[network]]
            vni = 5001
            name = "green"
            subnet = "192.168.101.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000, 5001]
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        let mut evpn = EvpnLearned::default();
        let learn = |vni, prefix: &str, mac| EvpnMonitorEvent::PrefixUpdate {
            l3_vni: vni,
            prefix: prefix.into(),
            vtep: "10.10.0.2".parse().unwrap(),
            router_mac: mac,
            gw: None,
            srv6_sid: None,
        };
        let rmac = [0x02, 0x00, 0x5e, 0x00, 0x00, 0xbb];
        evpn.apply(&learn(50100, "10.20.0.0/24", Some(rmac)));
        // No Router's MAC: nothing to write as the inner destination.
        evpn.apply(&learn(50100, "10.21.0.0/24", None));
        // A tenant this fabric does not host.
        evpn.apply(&learn(50999, "10.22.0.0/24", Some(rmac)));

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];
        let mut got: Vec<_> = h1
            .irb_routes
            .iter()
            .map(|r| (r.vni, r.inner_dst.as_str(), r.l3_vni))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![(5000, "10.20.0.0/24", 50100), (5001, "10.20.0.0/24", 50100)]
        );
        let r = &h1.irb_routes[0];
        // The inner rewrite: destination the egress router, source our anycast
        // gateway. Getting these backwards would send the frame back to us.
        assert_eq!(r.router_mac, "02:00:5e:00:00:bb");
        assert_eq!(r.gateway_mac, "02:00:5e:00:00:aa");
        // The underlay next hop is the remote VTEP host's MAC, our own egress iface.
        assert_eq!(r.remote_vtep, "10.10.0.2");
        assert_eq!(r.via_mac, "02:00:00:00:00:22");
        assert_eq!(r.out_iface, "eth0");

        // h2 originates that subnet, so it must not tunnel to itself.
        assert!(cfgs["h2"].irb_routes.is_empty());
    }

    /// Everything EVPN learns lands in the tables *this host's* overlay actually
    /// reads — and for an SRv6 host that is a different set of tables entirely.
    ///
    /// This is the half that was missing after the SRv6 datapath was written: the
    /// maps, the config types, the wire messages and the agent's map programming
    /// all existed, and nothing in the controller ever produced an
    /// `Srv6IrbRouteCfg` or an SRv6 flood entry. The result would have loaded
    /// clean and carried nothing — the exact failure this codebase keeps meeting,
    /// so it gets a producer *and* a test that fails without one.
    ///
    /// The type-5 assertion is the subtle one. A type-5 route advertises an
    /// `End.DT4`/`End.DT6` SID (RFC 9252 §6), whose payload is a bare IP packet.
    /// This datapath cannot terminate one — that needs a per-tenant L3 device it
    /// does not have — so the advertised SID must be *ignored* and the L3 VNI's
    /// `End.DT2U` SID derived instead. Programming what was advertised would build
    /// an encapsulation the far end refuses.
    #[test]
    fn an_srv6_host_learns_into_the_srv6_tables() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000]
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        let mut evpn = EvpnLearned::default();
        // A type-2 MAC whose advertised End.DT2U SID we take verbatim.
        let advertised: std::net::Ipv6Addr = "fc00:0:2:0:aaaa::".parse().unwrap();
        evpn.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 5000,
            mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01],
            ip: Some("192.168.100.5".parse().unwrap()),
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: Some(advertised),
        });
        // A flood peer that advertised no SID: derived from its locator instead,
        // so a fabric whose BGP has not converged still floods.
        evpn.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: 5000,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        });
        // A type-5 route carrying an End.DT4 SID, which this datapath cannot
        // terminate.
        evpn.apply(&EvpnMonitorEvent::PrefixUpdate {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
            vtep: "10.10.0.2".parse().unwrap(),
            router_mac: Some([0x02, 0x00, 0x5e, 0x00, 0x00, 0xbb]),
            gw: None,
            srv6_sid: Some("fc00:0:2:2:c3b4::".parse().unwrap()),
        });

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];

        // Nothing landed in a VXLAN table. If it had, it would have validated,
        // loaded, and moved no traffic at all.
        assert!(h1.mac_routes.is_empty(), "{:?}", h1.mac_routes);
        assert!(h1.tunnels.is_empty(), "{:?}", h1.tunnels);
        assert!(h1.flood_vteps.is_empty(), "{:?}", h1.flood_vteps);
        assert!(h1.irb_routes.is_empty(), "{:?}", h1.irb_routes);

        // The advertised unicast SID is used as advertised.
        let learned: Vec<_> = h1
            .srv6_routes
            .iter()
            .filter(|r| r.mac == "02:00:5e:00:00:01")
            .collect();
        assert_eq!(learned.len(), 1, "{:?}", h1.srv6_routes);
        assert_eq!(learned[0].remote_sid, advertised.to_string());
        assert_eq!(learned[0].via_mac, "02:00:00:00:00:22");

        // ARP suppression still happens: it belongs to the segment.
        assert!(h1.neighbors.iter().any(|n| n.ip == "192.168.100.5"));

        // The flood SID was derived from h2's locator, with discriminator 1.
        assert_eq!(h1.srv6_floods.len(), 1, "{:?}", h1.srv6_floods);
        assert_eq!(h1.srv6_floods[0].remote_sid, "fc00:0:2:0:100:1388::");
        assert_eq!(h1.srv6_floods[0].vni, 5000);

        // The type-5 route became an SRv6 IRB entry pointing at the L3 VNI's
        // *unicast* SID — derived, not the advertised End.DT4 one.
        assert_eq!(h1.srv6_irb_routes.len(), 1, "{:?}", h1.srv6_irb_routes);
        let irb = &h1.srv6_irb_routes[0];
        assert_eq!((irb.vni, irb.l3_vni), (5000, 50100));
        assert_eq!(irb.inner_dst, "10.20.0.0/24");
        assert_ne!(
            irb.remote_sid, "fc00:0:2:2:c3b4::",
            "the advertised End.DT4 SID must not be programmed: its payload is a bare IP \
             packet and this decap path refuses it"
        );
        assert_eq!(irb.router_mac, "02:00:5e:00:00:bb");
        assert_eq!(irb.gateway_mac, "02:00:5e:00:00:aa");

        // ...and h1 instantiates its OWN End.DT2U SID for that L3 VNI, because
        // symmetric IRB is symmetric: h2 encapsulates the return traffic to it.
        // An L3 VNI belongs to no local tenant port, so nothing else registers it
        // and the failure would be one-way reachability — which reads like a
        // routing problem rather than a missing decap entry.
        let own_l3: Vec<_> = h1
            .srv6_local_sids
            .iter()
            .filter(|ls| ls.vni == 50100)
            .collect();
        assert_eq!(own_l3.len(), 1, "{:?}", h1.srv6_local_sids);
        assert_eq!(own_l3[0].sid, "fc00:0:1::c3b4:0:0");
        assert_eq!(own_l3[0].behavior, "end.dt2u");
        // It is ours, not h2's — pointing at the peer's SID would terminate
        // nothing and leave the tenant's return path dark.
        assert_ne!(own_l3[0].sid, irb.remote_sid);

        // `derive_configs` already resolved every host's config on the way out, so
        // reaching this point at all means the SRv6 tables validated.
    }

    /// Stage 3 gate: a learned type-5 `End.DT4` SID is **refused** as authoritative
    /// (the datapath terminates only L2 behaviours) — the derived L3-VNI `End.DT2U`
    /// SID is programmed in its place — *and* the refusal is surfaced by
    /// [`srv6_irb_gated_sids`], so it is visible rather than silently dropped.
    #[test]
    fn a_learned_type5_l3_sid_is_gated_not_authoritative() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000]
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        // An End.DT4 SID under a locator that is NOT h2's — an external-style
        // allocation derivation could never produce, pinning "the learned L3 SID was
        // gated" beyond doubt.
        let advertised_dt4: Ipv6Addr = "fc00:dead:beef:4::c3b4".parse().unwrap();
        let mut evpn = EvpnLearned::default();
        evpn.apply(&EvpnMonitorEvent::PrefixUpdate {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
            vtep: "10.10.0.2".parse().unwrap(),
            router_mac: Some([0x02, 0x00, 0x5e, 0x00, 0x00, 0xbb]),
            gw: None,
            srv6_sid: Some(advertised_dt4),
        });

        // The derived L3-VNI unicast SID this fabric programs in the learned one's
        // place (End.DT2U under h2's own locator, discriminator 0).
        let programmed = derived_unicast_sid(topo.hosts().find(|h| h.id == "h2").unwrap(), 50100)
            .expect("h2 has a locator");
        assert_ne!(
            programmed, advertised_dt4,
            "the fabric must not derive the DT4 SID"
        );

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];

        // The IRB route carries the derived DT2U SID, never the advertised DT4 one.
        assert_eq!(h1.srv6_irb_routes.len(), 1, "{:?}", h1.srv6_irb_routes);
        assert_eq!(h1.srv6_irb_routes[0].remote_sid, programmed.to_string());
        assert_ne!(h1.srv6_irb_routes[0].remote_sid, advertised_dt4.to_string());

        // And the gate is visible: exactly one gated learned L3 SID, naming the
        // advertised SID that was refused and the DT2U SID programmed instead.
        let gated = srv6_irb_gated_sids(&topo, &evpn);
        assert_eq!(gated.len(), 1, "{gated:?}");
        assert_eq!(gated[0].l3_vni, 50100);
        assert_eq!(gated[0].prefix, "10.20.0.0/24");
        assert_eq!(gated[0].behavior, "end.dt4");
        assert_eq!(gated[0].learned_sid, advertised_dt4);
        assert_eq!(gated[0].programmed_sid, programmed);
    }

    /// The gate reports only a genuinely refused learned L3 SID: a type-5 route that
    /// advertised no SID (a fabric whose BGP has not converged) is derived from the
    /// locator with nothing gated, and a route for a VRF this fabric does not host is
    /// outside what it processes.
    #[test]
    fn srv6_irb_gated_reports_only_refused_learned_l3_sids() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000]
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        let mut evpn = EvpnLearned::default();
        // A type-5 route that advertised no SID: derived, nothing refused.
        evpn.apply(&EvpnMonitorEvent::PrefixUpdate {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
            vtep: "10.10.0.2".parse().unwrap(),
            router_mac: Some([0x02, 0x00, 0x5e, 0x00, 0x00, 0xbb]),
            gw: None,
            srv6_sid: None,
        });
        // A type-5 route carrying a SID but for a VRF this fabric does not host: not
        // a route it processes, so not gated (it is simply held elsewhere).
        evpn.apply(&EvpnMonitorEvent::PrefixUpdate {
            l3_vni: 60600,
            prefix: "10.30.0.0/24".into(),
            vtep: "10.10.0.2".parse().unwrap(),
            router_mac: Some([0x02, 0x00, 0x5e, 0x00, 0x00, 0xcc]),
            gw: None,
            srv6_sid: Some("fc00:0:2:6::c3b4".parse().unwrap()),
        });

        assert!(
            srv6_irb_gated_sids(&topo, &evpn).is_empty(),
            "neither a no-SID route nor an unhosted-VRF route is a gated learned L3 SID"
        );
    }

    /// The two ends of an SRv6 fabric agree, with nothing exchanged between them.
    ///
    /// Every other test here checks one host's config in isolation, and a config
    /// can be internally perfect and still point at a SID the far end does not
    /// terminate — at which point the fabric loads clean and drops everything.
    /// The property that matters is a *join*: every SID one host encapsulates
    /// toward must be a SID the other host instantiates.
    ///
    /// It holds because both sides compute SIDs from the same function of the
    /// same locator, so it would survive a controller failover, a restart, or two
    /// controllers deriving concurrently. That is the whole argument for deriving
    /// rather than allocating, and this is the assertion that argument cashes out
    /// as.
    #[test]
    fn two_srv6_hosts_agree_on_every_sid_between_them() {
        let toml = r#"
            [[host]]
            id = "n1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "n2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[port]]
            network = 5000
            host = "n1"
            tap = "tap0"
            ip = "192.168.100.10"

            [[port]]
            network = 5000
            host = "n2"
            tap = "tap0"
            ip = "192.168.100.11"
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();
        let cfgs = derive_configs(&topo, None).unwrap();
        let (n1, n2) = (&cfgs["n1"], &cfgs["n2"]);

        let instantiated = |c: &NodeConfig| -> Vec<String> {
            c.srv6_local_sids.iter().map(|ls| ls.sid.clone()).collect()
        };

        // Unicast: n1 bridges toward a SID n2 terminates, and the other way round.
        for (from, to, name) in [(n1, n2, "n1 -> n2"), (n2, n1, "n2 -> n1")] {
            assert_eq!(from.srv6_routes.len(), 1, "{name}: {:?}", from.srv6_routes);
            let sid = &from.srv6_routes[0].remote_sid;
            assert!(
                instantiated(to).contains(sid),
                "{name}: encapsulates toward {sid}, which the far end does not \
                 instantiate: {:?}",
                instantiated(to)
            );
            // Flood goes to a *different* SID, and that one is instantiated too.
            assert_eq!(from.srv6_floods.len(), 1, "{name}: {:?}", from.srv6_floods);
            let flood = &from.srv6_floods[0].remote_sid;
            assert_ne!(flood, sid, "{name}: one SID cannot carry both behaviours");
            assert!(
                instantiated(to).contains(flood),
                "{name}: floods toward {flood}, which the far end does not instantiate"
            );
            // And each trusts the other's tunnel source, which is what lets the
            // far end decapsulate at all.
            let src = &to.srv6.as_ref().expect("endpoint").local_src;
            assert!(
                from.srv6.as_ref().expect("endpoint").peers.contains(src),
                "{name}: does not trust {src}, so every frame it sends is refused"
            );
        }

        // The next hop is the far host's underlay MAC, not our own: getting this
        // backwards builds a frame that never leaves the box.
        assert_eq!(n1.srv6_routes[0].via_mac, "02:00:00:00:00:22");
        assert_eq!(n2.srv6_routes[0].via_mac, "02:00:00:00:00:11");

        // Neither host talks to itself.
        for (c, own) in [(n1, "fc00:0:1:"), (n2, "fc00:0:2:")] {
            for sid in c
                .srv6_routes
                .iter()
                .map(|r| &r.remote_sid)
                .chain(c.srv6_floods.iter().map(|f| &f.remote_sid))
            {
                assert!(
                    !sid.starts_with(own),
                    "encapsulates toward its own locator: {sid}"
                );
            }
        }
    }

    /// Stage 1 authority inversion: a learned End.DT2U SID is programmed
    /// **verbatim**, even one this fabric's locator math could never have derived
    /// (a foreign locator, as an external RFC 9252 PE that *allocates* SIDs would
    /// advertise). Derivation must not mask it — and the divergence must be
    /// reported so a heterogeneous fleet is visible, plus the peer's outer source
    /// must land in the trusted-decap set in the exact form the datapath checks.
    #[test]
    fn a_learned_l2_sid_is_authoritative_over_derivation() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        // A SID under a locator that is NOT h2's — derivation from fc00:0:2::/64
        // cannot produce a fc00:dead:beef:: SID, so this pins "learned, not
        // derived" beyond doubt.
        let allocated: Ipv6Addr = "fc00:dead:beef:0:1234::".parse().unwrap();
        let derived = derived_unicast_sid(topo.hosts().find(|h| h.id == "h2").unwrap(), 5000)
            .expect("h2 has a locator");
        assert_ne!(
            allocated, derived,
            "test SID must be one derive cannot produce"
        );

        let mut evpn = EvpnLearned::default();
        evpn.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 5000,
            mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01],
            ip: None,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: Some(allocated),
        });

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];

        // The advertised SID is programmed verbatim — not the derived one.
        assert_eq!(h1.srv6_routes.len(), 1, "{:?}", h1.srv6_routes);
        assert_eq!(h1.srv6_routes[0].remote_sid, allocated.to_string());
        assert_ne!(h1.srv6_routes[0].remote_sid, derived.to_string());

        // The peer's outer source is trusted for decap, in the `srv6_src`
        // (zero-filled locator) form `srv6_drop_untrusted` checks against.
        let src = topo
            .hosts()
            .find(|h| h.id == "h2")
            .unwrap()
            .srv6_src()
            .unwrap()
            .to_string();
        assert!(
            h1.srv6
                .as_ref()
                .expect("srv6 endpoint")
                .peers
                .contains(&src),
            "learned peer {src} must be a trusted decap source: {:?}",
            h1.srv6.as_ref().map(|s| &s.peers)
        );

        // And the divergence is reported (learned ≠ derived).
        let div = srv6_divergences(&topo, &evpn);
        assert_eq!(div.len(), 1, "{div:?}");
        assert_eq!(div[0].behavior, "end.dt2u");
        assert_eq!(div[0].vni, 5000);
        assert_eq!(div[0].learned_sid, allocated);
        assert_eq!(div[0].derived_sid, derived);
    }

    /// External (non-topology) EVPN peer decap-auth: a federated SRv6 speaker that
    /// is *not* a configured fabric host advertises standard-layout service SIDs.
    /// This host cannot encapsulate toward it (no next-hop MAC in the topology), so
    /// no `srv6_route`/`srv6_flood` is programmed — but its zero-filled locator must
    /// still land in the trusted-decap set, recovered from the SID alone, so the
    /// unicast return and BUM flood copies it sends us are accepted instead of
    /// dropped fail-closed. Encapsulating *toward* it (a routed underlay's next-hop
    /// resolution) is a separate, later chunk.
    #[test]
    fn an_external_peer_is_trusted_for_decap_from_its_learned_sid() {
        use velstra_common::srv6::{build_service_sid, sid_disc};

        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        // A federated speaker at a VTEP no host in the topology owns, advertising
        // standard-layout SIDs under its own /64 locator.
        let ext_loc = [0xfc, 0, 0, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ext_dt2u =
            Ipv6Addr::from(build_service_sid(&ext_loc, 64, sid_disc::UNICAST, 5000).unwrap());
        let ext_dt2m =
            Ipv6Addr::from(build_service_sid(&ext_loc, 64, sid_disc::MULTICAST, 5000).unwrap());
        let ext_src = Ipv6Addr::from(build_service_sid(&ext_loc, 64, 0, 0).unwrap());

        let mut evpn = EvpnLearned::default();
        evpn.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 5000,
            mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x09],
            ip: None,
            vtep: "10.10.0.9".parse().unwrap(),
            srv6_sid: Some(ext_dt2u),
        });
        evpn.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: 5000,
            vtep: "10.10.0.9".parse().unwrap(),
            srv6_sid: Some(ext_dt2m),
        });

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];

        // Nothing is programmed toward the external peer: no forward unicast route
        // and no flood target (we have no next-hop MAC for it).
        assert!(
            h1.srv6_routes
                .iter()
                .all(|r| r.remote_sid != ext_dt2u.to_string()),
            "no forward route to an external peer: {:?}",
            h1.srv6_routes
        );
        assert!(
            h1.srv6_floods
                .iter()
                .all(|f| f.remote_sid != ext_dt2m.to_string()),
            "no flood target toward an external peer: {:?}",
            h1.srv6_floods
        );

        // But both of its SIDs recover the same zero-filled-locator source, which
        // is trusted for decap so its unicast return and BUM flood copies land.
        let peers = &h1.srv6.as_ref().expect("srv6 endpoint").peers;
        assert!(
            peers.contains(&ext_src.to_string()),
            "external peer source {ext_src} must be trusted for decap: {peers:?}"
        );

        // It is not a divergence: divergence compares against a *derivable*
        // reference, and an external peer is not a known host, so nothing to
        // compare — it is outside what this fabric derives, not disagreeing with it.
        assert!(
            srv6_divergences(&topo, &evpn).is_empty(),
            "an external (non-topology) peer yields no divergence"
        );
    }

    /// The transport is chosen per peer by what EVPN advertised. A peer that is a
    /// VXLAN-only host (no SRv6 locator) advertises no SID and cannot be reached
    /// over SRv6 by an SRv6 host — which carries no `[overlay]` and so cannot
    /// bridge VXLAN either. Such an entry is *held, not programmed*: it must not
    /// land in the SRv6 tables (there is no SID for it) and must not silently
    /// invent one. The full VXLAN-on-an-SRv6-host coexistence is a later stage.
    #[test]
    fn a_vxlan_only_peer_is_held_on_an_srv6_host_not_given_a_derived_sid() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();

        let mut evpn = EvpnLearned::default();
        // h2 is a VXLAN host (no locator) and advertised no SID.
        evpn.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 5000,
            mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x02],
            ip: None,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: None,
        });

        let cfgs = derive_configs(&topo, Some(&evpn)).unwrap();
        let h1 = &cfgs["h1"];

        // No SRv6 route (no SID to reach it) and no VXLAN mac_route (an SRv6 host
        // has no overlay). Held, not programmed — and no divergence (nothing to
        // compare: the peer runs no SRv6).
        assert!(h1.srv6_routes.is_empty(), "{:?}", h1.srv6_routes);
        assert!(h1.mac_routes.is_empty(), "{:?}", h1.mac_routes);
        assert!(srv6_divergences(&topo, &evpn).is_empty());
    }

    /// A learned SID that *matches* derivation is not a divergence, and a flood
    /// (End.DT2M) SID diverges independently of the unicast one. Pins that the
    /// gauge counts real heterogeneity, not every learned SID.
    #[test]
    fn srv6_divergences_reports_only_genuine_mismatches() {
        use crate::evpn::{EvpnLearned, EvpnMonitorEvent};

        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            encap = "srv6"
            srv6_locator = "fc00:0:1::/64"

            [[host]]
            id = "h2"
            vtep = "10.10.0.2"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:22"
            encap = "srv6"
            srv6_locator = "fc00:0:2::/64"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();
        let h2 = topo.hosts().find(|h| h.id == "h2").unwrap();

        // A MAC advertising exactly the derived SID: no divergence.
        let matching = derived_unicast_sid(h2, 5000).unwrap();
        let mut evpn = EvpnLearned::default();
        evpn.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 5000,
            mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x03],
            ip: None,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: Some(matching),
        });
        assert!(
            srv6_divergences(&topo, &evpn).is_empty(),
            "a SID equal to the derived one is not a divergence"
        );

        // A flood advertising a foreign End.DT2M SID: exactly one divergence,
        // tagged as the flood behaviour.
        let foreign_flood: Ipv6Addr = "fc00:aaaa:bbbb:1:5678::".parse().unwrap();
        evpn.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: 5000,
            vtep: "10.10.0.2".parse().unwrap(),
            srv6_sid: Some(foreign_flood),
        });
        let div = srv6_divergences(&topo, &evpn);
        assert_eq!(div.len(), 1, "{div:?}");
        assert_eq!(div[0].behavior, "end.dt2m");
        assert_eq!(div[0].learned_sid, foreign_flood);
        assert_eq!(div[0].derived_sid, derived_multicast_sid(h2, 5000).unwrap());
    }

    #[test]
    fn parses_ip_vrfs_and_round_trips_them() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[network]]
            vni = 5001
            name = "green"
            subnet = "192.168.101.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000, 5001]
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();
        let vrf = topo.ip_vrfs().next().unwrap();
        assert_eq!(vrf.l3_vni, 50100);
        assert_eq!(vrf.gateway_mac, [0x02, 0x00, 0x5e, 0x00, 0x00, 0xaa]);
        // Several bridged segments share one routed context — the reason this is
        // its own entity and not a field on each network.
        assert_eq!(vrf.networks, vec![5000, 5001]);
        assert_eq!(topo.ip_vrf_of_network(5001).unwrap().l3_vni, 50100);
        assert!(topo.ip_vrf_of_network(9999).is_none());

        // Serialising back and re-reading yields the same tenant, so a controller
        // that rewrites the topology file does not drop it.
        let reloaded = build(&to_file(&topo)).unwrap();
        assert_eq!(reloaded.ip_vrfs().next().unwrap(), vrf);
    }

    /// The membership list is the only thing that says which tenant a segment
    /// belongs to, so a typo in it must fail the load rather than leave a segment
    /// quietly unrouted while everything else comes up.
    /// The shipped example is the first thing a new operator copies, so it has
    /// to load — and to derive — rather than merely look plausible.
    #[test]
    fn the_shipped_example_topology_loads_and_derives() {
        let path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../examples/topology.toml");
        let topo = load_model(&path).expect("examples/topology.toml must load");

        assert_eq!(topo.hosts().count(), 2);
        assert_eq!(topo.networks().count(), 2);
        assert_eq!(topo.security_groups().count(), 1);
        assert_eq!(topo.ip_vrfs().count(), 1);
        assert_eq!(topo.load_balancers().count(), 1);

        // Every host's derived config must be *valid*, not just present: resolve()
        // is what the agent applies, so an example that derives garbage would fail
        // on a real node instead of here.
        for host in topo.hosts() {
            let cfg = topo.derive(&host.id).expect("derives");
            cfg.resolve()
                .unwrap_or_else(|e| panic!("host {} derives an invalid config: {e}", host.id));
        }
    }

    /// A file-declared VIP must survive the round-trip through the model, and a
    /// member has to name a port the file actually declares — the file speaks in
    /// host/tap, the model in generated port ids.
    #[test]
    fn parses_load_balancers_and_round_trips_them() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[port]]
            network = 5000
            host = "h1"
            tap = "tap0"
            ip = "192.168.100.10"

            [[load_balancer]]
            id = "web"
            vni = 5000
            vip = "192.168.100.200"
            port = 80
            proto = "tcp"
            [[load_balancer.member]]
            host = "h1"
            tap = "tap0"
            port = 8080
        "#;
        let topo = build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap();
        let lb = topo.load_balancers().next().unwrap();
        assert_eq!(lb.id, "web");
        assert_eq!(lb.vip.to_string(), "192.168.100.200");
        assert_eq!(lb.members.len(), 1);
        assert_eq!(lb.members[0].port, 8080);

        // The derived host config carries the service with its member resolved
        // to that port's address.
        let cfg = topo.derive("h1").unwrap();
        assert_eq!(cfg.services.len(), 1);
        assert_eq!(cfg.services[0].backends[0].ip, "192.168.100.10");

        let reloaded = build(&to_file(&topo)).unwrap();
        assert_eq!(reloaded.load_balancers().next().unwrap(), lb);
    }

    #[test]
    fn rejects_load_balancer_member_naming_no_port() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[load_balancer]]
            id = "web"
            vni = 5000
            vip = "192.168.100.200"
            port = 80
            [[load_balancer.member]]
            host = "h1"
            tap = "ghost"
        "#;
        let err = format!(
            "{:#}",
            build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap_err()
        );
        assert!(err.contains("load_balancer web"), "{err}");
        assert!(err.contains("ghost"), "{err}");
    }

    #[test]
    fn rejects_ip_vrf_naming_an_undeclared_network() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[ip_vrf]]
            l3_vni = 50100
            name = "tenant-a"
            gateway_mac = "02:00:5e:00:00:aa"
            networks = [5000, 5002]
        "#;
        // `{:#}` renders anyhow's whole chain, which is what the operator sees:
        // the file block that is wrong, then why.
        let err = format!(
            "{:#}",
            build(&toml::from_str::<TopologyFile>(toml).unwrap()).unwrap_err()
        );
        assert!(err.contains("ip_vrf tenant-a"), "{err}");
        assert!(err.contains("5002"), "{err}");
    }

    #[test]
    fn parses_subnets_and_security_groups_and_binds_ports_by_name() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"

            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"

            [[subnet]]
            id = "s4"
            vni = 5000
            cidr = "192.168.100.0/24"
            gateway = "192.168.100.1"

            [[subnet]]
            id = "s6"
            vni = 5000
            cidr = "2001:db8::/64"
            pool_start = "2001:db8::100"
            pool_end = "2001:db8::200"

            [[security_group]]
            name = "web"
            default_action = "drop"
            stateful = true
            [[security_group.rule]]
            proto = "tcp"
            port = 80
            action = "pass"

            [[port]]
            network = 5000
            host = "h1"
            tap = "tapA"
            security_group = "web"
        "#;
        let tf: TopologyFile = toml::from_str(toml).unwrap();
        let topo = build(&tf).unwrap();

        // Both subnets landed, tagged with their VNI.
        assert_eq!(topo.subnets().count(), 2);
        assert!(topo.subnet("s6").unwrap().cidr.is_v6());
        // The security group landed, and the port bound to it (its policy is the
        // group's deterministic id).
        assert_eq!(topo.security_groups().count(), 1);
        let pid = velstra_orchestrator::security_group_policy_id("web");
        assert_eq!(topo.ports()[0].policy, Some(pid));
        // The derived config resolves (the bound group emits a [[policy]] block).
        let cfg = derive_configs(&topo, None).unwrap();
        assert!(cfg["h1"].policies.iter().any(|p| p.id == pid));
    }

    #[test]
    fn subnets_and_group_bindings_survive_a_file_roundtrip() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            [[network]]
            vni = 5000
            name = "blue"
            subnet = "192.168.100.0/24"
            [[subnet]]
            id = "s4"
            vni = 5000
            cidr = "192.168.100.0/24"
            gateway = "192.168.100.1"
            [[security_group]]
            name = "web"
            default_action = "drop"
            [[port]]
            network = 5000
            host = "h1"
            tap = "tapA"
            security_group = "web"
        "#;
        let original = build(&toml::from_str(toml).unwrap()).unwrap();

        // Round-trip through the on-disk schema.
        let serialised = toml::to_string_pretty(&to_file(&original)).unwrap();
        let reloaded = build(&toml::from_str(&serialised).unwrap()).unwrap();

        // Subnet, security group, and the port's group binding all survived; the
        // port serialised by group *name* (not raw id) and re-bound identically.
        assert_eq!(reloaded.subnets().count(), 1);
        assert_eq!(reloaded.security_groups().count(), 1);
        let pid = velstra_orchestrator::security_group_policy_id("web");
        assert_eq!(reloaded.ports()[0].policy, Some(pid));
        assert!(serialised.contains("security_group = \"web\""));
        assert_eq!(
            derive_configs(&original, None).unwrap(),
            derive_configs(&reloaded, None).unwrap()
        );
    }

    #[test]
    fn rejects_port_on_unknown_network() {
        let toml = r#"
            [[host]]
            id = "h1"
            vtep = "10.10.0.1"
            underlay_iface = "eth0"
            underlay_mac = "02:00:00:00:00:11"
            [[port]]
            network = 999
            host = "h1"
            tap = "tapA"
        "#;
        let tf: TopologyFile = toml::from_str(toml).unwrap();
        assert!(build(&tf).is_err());
    }
}
