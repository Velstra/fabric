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
    net::{IpAddr, Ipv4Addr},
    path::Path,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use velstra_common::{parse_cidr_v4, parse_cidr_v6, parse_mac};
use velstra_config::{
    ActionName, EncapName, FileConfig, FloodVtepCfg, MacRouteCfg, Nd6Cfg, NeighborCfg, PortRule,
    TunnelCfg, file_config_to_proto,
};
use velstra_orchestrator::{
    AllocRange, Host, Network, SecurityGroup, Subnet, SubnetCidr, Topology,
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
    #[serde(rename = "port", default)]
    ports: Vec<PortFile>,
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
        });
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
        let created = topo.create_port(p.network, &p.host, &p.tap, ip, policy)?;
        if let Some(group) = &p.security_group {
            topo.set_port_security_group(&created.id, Some(group))?;
        }
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
        // the topology derive). An external VTEP we don't know is held, not
        // programmed.
        let Some(remote) = topo.hosts().find(|h| h.vtep_ip == vtep) else {
            continue;
        };
        // B1: every type-2 MAC (MAC-only AND MAC/IP) gets an L2 MAC-FDB entry so
        // the datapath can bridge by destination MAC, independent of the L3 FDB.
        file.mac_routes.push(MacRouteCfg {
            vni,
            mac: fmt_mac(mac),
            remote_vtep: vtep.to_string(),
            via_mac: fmt_mac(remote.underlay_mac),
            out_iface: host.underlay_iface.clone(),
        });
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
                file.tunnels.push(TunnelCfg {
                    vni,
                    inner_dst: format!("{ip}/32"),
                    remote_vtep: vtep.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                });
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

    // B2: fold type-3 IMET flood VTEPs into this host's per-VNI flood set. Each
    // remote v4 flood VTEP that is a known fabric host becomes a `FloodVtepCfg`,
    // mirroring the same next-hop convention as the MAC/tunnel entries above:
    // `via_mac` is the remote VTEP host's underlay MAC, `out_iface` this host's
    // underlay iface. Skip self, skip v6, and skip an unknown/external VTEP we
    // can't borrow a next-hop MAC for (a routed underlay is a later chunk).
    for (&vni, vtep_set) in evpn.floods() {
        for vtep in vtep_set {
            let IpAddr::V4(vtep) = vtep else {
                continue;
            };
            if *vtep == host.vtep_ip {
                continue;
            }
            let Some(remote) = topo.hosts().find(|h| h.vtep_ip == *vtep) else {
                continue;
            };
            file.flood_vteps.push(FloodVtepCfg {
                vni,
                remote_vtep: vtep.to_string(),
                via_mac: fmt_mac(remote.underlay_mac),
                out_iface: host.underlay_iface.clone(),
            });
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

    TopologyFile {
        hosts,
        networks,
        subnets,
        security_groups,
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
        }));
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: evpn_vni,
            mac: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            ip: None, // MAC-only: held, not programmed
            vtep: "10.10.0.2".parse().unwrap(),
        }));
        // B3: a type-2 MAC/**IPv6** behind h2 — programmable as an ND neighbour
        // (but NOT as a v4 tunnel/neighbor, since the L3 FDB stays v4-only).
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: evpn_vni,
            mac: [0xde, 0xad, 0xbe, 0xef, 0x00, 0x06],
            ip: Some("2001:db8::50".parse().unwrap()),
            vtep: "10.10.0.2".parse().unwrap(),
        }));
        // B2: a type-3 IMET flood VTEP behind h2 (a known fabric host) — folds
        // into h1's per-VNI flood set. An unknown/external VTEP flood is held,
        // not programmed (no fabric host to borrow a next-hop MAC from).
        assert!(learned.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: evpn_vni,
            vtep: "10.10.0.2".parse().unwrap(),
        }));
        assert!(learned.apply(&EvpnMonitorEvent::FloodUpdate {
            vni: evpn_vni,
            vtep: "203.0.113.9".parse().unwrap(),
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
