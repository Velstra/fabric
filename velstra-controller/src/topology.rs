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

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use velstra_common::{parse_cidr_v4, parse_mac};
use velstra_config::{
    ActionName, EncapName, FileConfig, MacRouteCfg, NeighborCfg, TunnelCfg, file_config_to_proto,
};
use velstra_orchestrator::{Host, Network, Topology};
use velstra_proto::NodeConfig;

use crate::evpn::EvpnLearned;

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TopologyFile {
    #[serde(rename = "host", default)]
    hosts: Vec<HostFile>,
    #[serde(rename = "network", default)]
    networks: Vec<NetworkFile>,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PortFile {
    network: u32,
    host: String,
    tap: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    /// Security-group policy id, decoupled from the VNI (M4). Omitted ⇒ default
    /// to the network VNI (single-tenant).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<u32>,
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
    for p in &tf.ports {
        let ip = match &p.ip {
            Some(s) => Some(
                s.parse::<Ipv4Addr>()
                    .with_context(|| format!("port {}/{}: invalid ip {s:?}", p.host, p.tap))?,
            ),
            None => None,
        };
        topo.create_port(p.network, &p.host, &p.tap, ip, p.policy)?;
    }
    Ok(topo)
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
/// `inner_dst = ip/32`. So a MAC-only entry ⇒ one `MacRouteCfg`; a MAC/IP entry
/// ⇒ `MacRouteCfg` + `NeighborCfg` + `TunnelCfg`. We deliberately defer:
/// * type-3 flood VTEPs (`evpn.floods()`) — need the BUM datapath (B2), and
///   have no `NodeConfig` representation yet (the agent's `VTEP_PEERS` trusted-
///   decap set is derived from the emitted tunnels/MAC routes, so a flood-only
///   VTEP has nowhere to land);
/// * v6 VTEPs — the maps are v4-only today (`remote_vtep` an `Ipv4Addr`), and
///   v6 inner IPs (`inner_dst` is a `Cidr4`), which drop the L3 tunnel/neighbor
///   for that entry but keep its MAC route.
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
        // A bound IP additionally gets L3 forwarding + ARP suppression. A
        // MAC-only entry (or a v6 inner IP) stops here — it has only a MAC route.
        let Some(IpAddr::V4(ip)) = learned.ip else {
            continue;
        };
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

    let ports: Vec<PortFile> = topo
        .ports()
        .iter()
        .map(|p| PortFile {
            network: p.vni,
            host: p.host.clone(),
            tap: p.tap.clone(),
            ip: Some(p.ip.to_string()),
            policy: p.policy,
        })
        .collect();

    TopologyFile {
        hosts,
        networks,
        ports,
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

        let cfg = derive_configs(&topo, Some(&learned)).unwrap();
        let h1 = &cfg["h1"];

        // Exactly the one MAC/IP entry became a tunnel + neighbor (MAC-only skipped
        // for the L3 path).
        assert_eq!(h1.tunnels.len(), 1);
        assert_eq!(h1.neighbors.len(), 1);

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

        // B1: BOTH type-2 MACs (MAC/IP + MAC-only) yield a MAC-FDB route. Order is
        // map-iteration dependent, so look each up by its MAC.
        assert_eq!(h1.mac_routes.len(), 2);
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
