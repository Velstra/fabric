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

use std::{collections::HashMap, net::Ipv4Addr, path::Path};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use velstra_common::{parse_cidr_v4, parse_mac};
use velstra_config::{ActionName, EncapName, file_config_to_proto};
use velstra_orchestrator::{Host, Network, Topology};
use velstra_proto::NodeConfig;

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
pub fn derive_configs(topo: &Topology) -> Result<HashMap<String, NodeConfig>> {
    let mut out = HashMap::new();
    for host in topo.hosts() {
        let file = topo
            .derive(&host.id)
            .ok_or_else(|| anyhow!("host {:?} vanished mid-derive", host.id))?;
        file.resolve()
            .with_context(|| format!("derived config for host {:?} is invalid", host.id))?;
        out.insert(host.id.clone(), file_config_to_proto(&file, 0));
    }
    Ok(out)
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
        let configs = derive_configs(&topo).unwrap();

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
        let a = derive_configs(&original).unwrap();
        let b = derive_configs(&reloaded).unwrap();
        assert_eq!(a, b);
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
