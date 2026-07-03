//! # velstra-orchestrator
//!
//! The control plane's **brain**: a high-level model of the virtual fabric —
//! *networks*, *hosts*, and *ports* — from which it **derives** each host's
//! concrete Velstra config.
//!
//! This is the leap from "a powerful data plane you configure by hand" to "a
//! platform you declare intent to". Instead of writing per-host TOML (which tap
//! is on which VNI, which remote IPs need a tunnel + ARP entry, …), an operator
//! says *"create a port for VM-B on network blue, on host-2"* and the
//! orchestrator:
//!
//! * allocates the port an IP (IPAM) and a MAC,
//! * records it against its network and host,
//! * and recomputes every host's config — the host running the port gets a tap
//!   binding; every *other* host with a port on that network gets a tunnel
//!   ([`OVERLAY_FDB`]) and an ARP entry ([`ARP_TABLE`]) pointing at it.
//!
//! Crucially this layer emits the **exact same** [`FileConfig`] the agent
//! already consumes (via `file_config_to_proto`), so neither the data plane nor
//! the agent changes — the Andromeda model, where a central brain holds the
//! topology and pushes each host only what it needs. The whole module is pure,
//! synchronous, and unit-tested; the controller wraps it with gRPC + storage.
//!
//! [`OVERLAY_FDB`]: velstra_common::TunnelKey
//! [`ARP_TABLE`]: velstra_common::ArpKey

use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use anyhow::{Result, bail};
use velstra_common::Cidr4;
use velstra_config::{
    ActionName, EncapName, FileConfig, InterfaceFile, NeighborCfg, OverlayCfg, PolicyFile,
    TunnelCfg,
};

/// A physical host that terminates tunnels (a VTEP).
#[derive(Debug, Clone)]
pub struct Host {
    /// Node id — matches the agent's `--node-id` and its served-config key.
    pub id: String,
    /// Underlay VTEP IPv4 (the outer source address for tunnels to this host).
    pub vtep_ip: Ipv4Addr,
    /// Underlay egress interface name on this host.
    pub underlay_iface: String,
    /// Underlay MAC — used as the next-hop `via_mac` when *other* hosts tunnel
    /// to this one (assumes a flat L2 underlay; a routed underlay would resolve
    /// the gateway MAC instead).
    pub underlay_mac: [u8; 6],
    /// Encapsulation this host uses.
    pub encap: EncapName,
    /// Override UDP port, or `None` for the encap default.
    pub udp_port: Option<u16>,
    /// Underlay MTU, or `None` for the default (1500).
    pub underlay_mtu: Option<u16>,
}

/// Map-ownership convention between the two writers of `OVERLAY_FDB` /
/// `ARP_TABLE` (M5), fixed **before** an EVPN/FPM path exists so the ranges can
/// never be retrofitted after callers depend on them:
///
/// * **Orchestrator ("controller-FDB")** — statically derived tunnel/neighbour
///   entries — owns VNIs `1 .. EVPN_RESERVED_VNI_BASE`.
/// * **Reserved** — VNIs `>= EVPN_RESERVED_VNI_BASE` (the top 64K of the 24-bit
///   space) are reserved for a future EVPN/FPM control-plane that learns FDB/ARP
///   entries dynamically. Reserving them now guarantees a learned entry can
///   never collide with a controller-derived one on the same map key.
///
/// The orchestrator therefore refuses to define a network in the reserved range
/// (see [`Topology::add_network`]).
pub const EVPN_RESERVED_VNI_BASE: u32 = 0xFF_0000;

/// A virtual network (a tenant L2 segment), identified by its VNI.
#[derive(Debug, Clone)]
pub struct Network {
    /// VXLAN Network Identifier (also the firewall policy id the orchestrator
    /// assigns to the network's ports). Must be non-zero and ≤ 24 bits.
    pub vni: u32,
    /// Human-readable name (becomes the policy name).
    pub name: String,
    /// Tenant subnet that IPAM allocates port addresses from.
    pub subnet: Cidr4,
    /// Default firewall action for the network's policy.
    pub default_action: ActionName,
    /// Whether the network's policy drops ICMP.
    pub drop_icmp: bool,
}

/// A workload's virtual NIC, attached to a [`Network`] and bound to a [`Host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// Stable port id.
    pub id: String,
    /// The network (VNI) this port lives on.
    pub vni: u32,
    /// The host id this port currently runs on.
    pub host: String,
    /// Allocated inner IPv4 address.
    pub ip: Ipv4Addr,
    /// Allocated MAC address.
    pub mac: [u8; 6],
    /// The tap/veth interface name on the host that carries this port.
    pub tap: String,
}

/// The whole virtual fabric: networks, hosts, and the ports binding them.
/// Holds no I/O — the controller owns persistence and distribution.
#[derive(Debug, Default, Clone)]
pub struct Topology {
    networks: HashMap<u32, Network>,
    hosts: HashMap<String, Host>,
    ports: Vec<Port>,
}

/// Derive a locally-administered, deterministic MAC for an inner IPv4: `02:00`
/// then the four address octets. Unique per address, stable across recomputes.
fn mac_for(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

fn fmt_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

impl Topology {
    /// An empty fabric.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a host (VTEP). Replaces any existing host with the same id.
    pub fn add_host(&mut self, host: Host) {
        self.hosts.insert(host.id.clone(), host);
    }

    /// Define a network. Fails for a zero VNI, a VNI in the reserved EVPN range
    /// (see [`EVPN_RESERVED_VNI_BASE`]), or a duplicate.
    pub fn add_network(&mut self, network: Network) -> Result<()> {
        if network.vni == 0 {
            bail!("network vni must be non-zero");
        }
        if network.vni >= EVPN_RESERVED_VNI_BASE {
            bail!(
                "network vni {:#x} is reserved for the EVPN/FPM control-plane path \
                 (>= {:#x}); orchestrator-managed networks must use 1..{:#x}",
                network.vni,
                EVPN_RESERVED_VNI_BASE,
                EVPN_RESERVED_VNI_BASE
            );
        }
        if self.networks.contains_key(&network.vni) {
            bail!("network vni {} already exists", network.vni);
        }
        self.networks.insert(network.vni, network);
        Ok(())
    }

    /// Retire a host. Fails while any port is still bound to it, so a caller
    /// must migrate or remove those ports first — otherwise `derive()` would keep
    /// generating dead tunnels/ARP entries toward a gone VTEP. Returns whether
    /// the host existed.
    pub fn remove_host(&mut self, id: &str) -> Result<bool> {
        if let Some(p) = self.ports.iter().find(|p| p.host == id) {
            bail!("host {id:?} still has port {:?}; migrate or remove it first", p.id);
        }
        Ok(self.hosts.remove(id).is_some())
    }

    /// Decommission a network. Fails while any port is still on it. Returns
    /// whether the network existed.
    pub fn remove_network(&mut self, vni: u32) -> Result<bool> {
        if let Some(p) = self.ports.iter().find(|p| p.vni == vni) {
            bail!("network {vni} still has port {:?}; remove it first", p.id);
        }
        Ok(self.networks.remove(&vni).is_some())
    }

    /// All hosts, in no particular order.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// All networks, in no particular order.
    pub fn networks(&self) -> impl Iterator<Item = &Network> {
        self.networks.values()
    }

    /// All ports.
    pub fn ports(&self) -> &[Port] {
        &self.ports
    }

    /// Create a port on `vni`/`host`, allocating an IP (the next free address in
    /// the network's subnet unless `requested_ip` is given) and a MAC.
    pub fn create_port(
        &mut self,
        vni: u32,
        host: &str,
        tap: &str,
        requested_ip: Option<Ipv4Addr>,
    ) -> Result<Port> {
        if !self.networks.contains_key(&vni) {
            bail!("unknown network vni {vni}");
        }
        if !self.hosts.contains_key(host) {
            bail!("unknown host {host:?}");
        }
        // A (host, tap) pair maps to exactly one host interface. Two ports bound
        // to the same tap would resolve to the same ifindex on the agent, where
        // the second silently overwrites the first's IFACE_POLICY/IFACE_VNI — one
        // port left unfirewalled/mis-VNI'd with no error. Reject it here.
        if self.ports.iter().any(|p| p.host == host && p.tap == tap) {
            bail!("tap {tap:?} on host {host:?} is already bound to another port");
        }
        let ip = match requested_ip {
            Some(ip) => {
                if !self.subnet_contains(vni, ip) {
                    bail!("ip {ip} is outside network {vni}'s subnet");
                }
                if self.ports.iter().any(|p| p.vni == vni && p.ip == ip) {
                    bail!("ip {ip} is already allocated on network {vni}");
                }
                ip
            }
            None => self.alloc_ip(vni)?,
        };
        let port = Port {
            id: format!("port-{vni}-{ip}"),
            vni,
            host: host.to_string(),
            ip,
            mac: mac_for(ip),
            tap: tap.to_string(),
        };
        self.ports.push(port.clone());
        Ok(port)
    }

    /// Remove a port by id. Returns whether it existed.
    pub fn remove_port(&mut self, id: &str) -> bool {
        let before = self.ports.len();
        self.ports.retain(|p| p.id != id);
        self.ports.len() != before
    }

    /// Move an existing port to `new_host`, binding it to `new_tap` there. The
    /// port keeps its identity — id, VNI, IP, and MAC — so a live-migrated
    /// workload stays reachable at the same address. `derive()` then re-points
    /// every peer's tunnel/ARP entry at the new host's VTEP, the old host loses
    /// the local interface binding (and gains a tunnel back to the port), and the
    /// new host gains it. A no-op host move still updates the tap.
    pub fn migrate_port(&mut self, id: &str, new_host: &str, new_tap: &str) -> Result<Port> {
        if !self.hosts.contains_key(new_host) {
            bail!("unknown host {new_host:?}");
        }
        // The destination tap must be free (ignoring this port itself), for the
        // same ifindex-collision reason as create_port.
        if self
            .ports
            .iter()
            .any(|p| p.id != id && p.host == new_host && p.tap == new_tap)
        {
            bail!("tap {new_tap:?} on host {new_host:?} is already bound to another port");
        }
        let port = self
            .ports
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown port {id:?}"))?;
        port.host = new_host.to_string();
        port.tap = new_tap.to_string();
        Ok(port.clone())
    }

    fn subnet_contains(&self, vni: u32, ip: Ipv4Addr) -> bool {
        let Some(net) = self.networks.get(&vni) else {
            return false;
        };
        let base = u32::from_be_bytes(net.subnet.octets);
        let host_bits = 32 - net.subnet.prefix as u32;
        let mask = if host_bits >= 32 {
            0
        } else {
            u32::MAX << host_bits
        };
        (u32::from(ip) & mask) == base
    }

    /// Allocate the lowest free host address in a network's subnet (skipping the
    /// network and broadcast addresses).
    fn alloc_ip(&self, vni: u32) -> Result<Ipv4Addr> {
        let net = &self.networks[&vni];
        let base = u32::from_be_bytes(net.subnet.octets);
        let host_bits = 32 - net.subnet.prefix as u32;
        // /31 and /32 have no usable host range under this scheme.
        let span = if host_bits >= 32 {
            u32::MAX
        } else {
            1u32 << host_bits
        };
        if span < 3 {
            bail!("network {vni} subnet is too small for a host address");
        }
        let taken: HashSet<u32> = self
            .ports
            .iter()
            .filter(|p| p.vni == vni)
            .map(|p| u32::from(p.ip))
            .collect();
        for off in 1..(span - 1) {
            let cand = base + off;
            if !taken.contains(&cand) {
                return Ok(Ipv4Addr::from(cand));
            }
        }
        bail!("network {vni} has no free addresses");
    }

    /// Derive host `host_id`'s complete [`FileConfig`] from the model, or `None`
    /// if the host is unknown.
    ///
    /// The host gets:
    /// * its `[overlay]` endpoint,
    /// * a `[[policy]]` for every network it has at least one local port on,
    /// * an `[[interface]]` binding (tap → policy/vni) for each **local** port,
    /// * a `[[tunnel]]` + `[[neighbor]]` for every **remote** port on a network
    ///   this host participates in — so its VMs can reach, and ARP-resolve,
    ///   their peers on other hosts.
    pub fn derive(&self, host_id: &str) -> Option<FileConfig> {
        let host = self.hosts.get(host_id)?;

        // VNIs this host participates in (has ≥1 local port on).
        let local_vnis: HashSet<u32> = self
            .ports
            .iter()
            .filter(|p| p.host == host_id)
            .map(|p| p.vni)
            .collect();

        let mut cfg = FileConfig {
            default_action: ActionName::Pass,
            overlay: Some(OverlayCfg {
                local_vtep: host.vtep_ip.to_string(),
                underlay_iface: host.underlay_iface.clone(),
                encap: host.encap,
                udp_port: host.udp_port,
                local_mac: None,
                underlay_mtu: host.underlay_mtu,
            }),
            ..FileConfig::default()
        };

        // One policy per participating network (id == vni).
        let mut vnis: Vec<u32> = local_vnis.iter().copied().collect();
        vnis.sort_unstable(); // deterministic output
        for vni in &vnis {
            let net = &self.networks[vni];
            cfg.policies.push(PolicyFile {
                id: *vni,
                name: Some(net.name.clone()),
                default_action: net.default_action,
                drop_icmp: net.drop_icmp,
                log: false,
                stateful: false,
                blocklist: Vec::new(),
                port_rules: Vec::new(),
            });
        }

        // Ports: local → interface; remote on a hosted VNI → tunnel + neighbour.
        for port in &self.ports {
            if port.host == host_id {
                cfg.interfaces.push(InterfaceFile {
                    name: port.tap.clone(),
                    policy: port.vni,
                    vni: Some(port.vni),
                    // Orchestrator-managed tap ports are tenant overlay endpoints,
                    // never a WAN uplink, so they are not masqueraded.
                    masquerade: false,
                });
            } else if local_vnis.contains(&port.vni) {
                let remote = &self.hosts[&port.host];
                cfg.tunnels.push(TunnelCfg {
                    vni: port.vni,
                    inner_dst: format!("{}/32", port.ip),
                    remote_vtep: remote.vtep_ip.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                });
                cfg.neighbors.push(NeighborCfg {
                    vni: port.vni,
                    ip: port.ip.to_string(),
                    mac: fmt_mac(port.mac),
                });
            }
        }

        Some(cfg)
    }
}

// === Serializable snapshot ==================================================
//
// The model's durable form, used by the Raft state machine (and any other
// snapshotter). Built from / restored into a [`Topology`] losslessly, with
// primitive fields so it serialises with plain `serde` (no foreign impls).

/// A serializable point-in-time copy of the whole fabric.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FabricSnapshot {
    /// All hosts.
    pub hosts: Vec<HostRec>,
    /// All networks.
    pub networks: Vec<NetworkRec>,
    /// All ports.
    pub ports: Vec<PortRec>,
}

/// Serializable mirror of a [`Host`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostRec {
    pub id: String,
    pub vtep_ip: [u8; 4],
    pub underlay_iface: String,
    pub underlay_mac: [u8; 6],
    pub encap: EncapName,
    pub udp_port: Option<u16>,
    pub underlay_mtu: Option<u16>,
}

/// Serializable mirror of a [`Network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkRec {
    pub vni: u32,
    pub name: String,
    pub subnet_octets: [u8; 4],
    pub subnet_prefix: u8,
    pub default_action: ActionName,
    pub drop_icmp: bool,
}

/// Serializable mirror of a [`Port`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortRec {
    pub id: String,
    pub vni: u32,
    pub host: String,
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub tap: String,
}

impl Topology {
    /// Capture the whole fabric as a serializable [`FabricSnapshot`].
    pub fn to_snapshot(&self) -> FabricSnapshot {
        FabricSnapshot {
            hosts: self
                .hosts
                .values()
                .map(|h| HostRec {
                    id: h.id.clone(),
                    vtep_ip: h.vtep_ip.octets(),
                    underlay_iface: h.underlay_iface.clone(),
                    underlay_mac: h.underlay_mac,
                    encap: h.encap,
                    udp_port: h.udp_port,
                    underlay_mtu: h.underlay_mtu,
                })
                .collect(),
            networks: self
                .networks
                .values()
                .map(|n| NetworkRec {
                    vni: n.vni,
                    name: n.name.clone(),
                    subnet_octets: n.subnet.octets,
                    subnet_prefix: n.subnet.prefix,
                    default_action: n.default_action,
                    drop_icmp: n.drop_icmp,
                })
                .collect(),
            ports: self
                .ports
                .iter()
                .map(|p| PortRec {
                    id: p.id.clone(),
                    vni: p.vni,
                    host: p.host.clone(),
                    ip: p.ip.octets(),
                    mac: p.mac,
                    tap: p.tap.clone(),
                })
                .collect(),
        }
    }

    /// Rebuild a [`Topology`] from a snapshot (verbatim — ports keep their stored
    /// id/ip/mac, no re-allocation).
    pub fn from_snapshot(snap: &FabricSnapshot) -> Self {
        let mut t = Topology::new();
        for h in &snap.hosts {
            t.hosts.insert(
                h.id.clone(),
                Host {
                    id: h.id.clone(),
                    vtep_ip: Ipv4Addr::from(h.vtep_ip),
                    underlay_iface: h.underlay_iface.clone(),
                    underlay_mac: h.underlay_mac,
                    encap: h.encap,
                    udp_port: h.udp_port,
                    underlay_mtu: h.underlay_mtu,
                },
            );
        }
        for n in &snap.networks {
            t.networks.insert(
                n.vni,
                Network {
                    vni: n.vni,
                    name: n.name.clone(),
                    subnet: Cidr4 {
                        octets: n.subnet_octets,
                        prefix: n.subnet_prefix,
                    },
                    default_action: n.default_action,
                    drop_icmp: n.drop_icmp,
                },
            );
        }
        for p in &snap.ports {
            t.ports.push(Port {
                id: p.id.clone(),
                vni: p.vni,
                host: p.host.clone(),
                ip: Ipv4Addr::from(p.ip),
                mac: p.mac,
                tap: p.tap.clone(),
            });
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use velstra_common::parse_cidr_v4;

    use super::*;

    fn host(id: &str, vtep: &str, last_mac: u8) -> Host {
        Host {
            id: id.to_string(),
            vtep_ip: vtep.parse::<Ipv4Addr>().unwrap(),
            underlay_iface: "eth0".to_string(),
            underlay_mac: [0x02, 0, 0, 0, 0, last_mac],
            encap: EncapName::Vxlan,
            udp_port: None,
            underlay_mtu: None,
        }
    }

    fn network(vni: u32, name: &str, subnet: &str) -> Network {
        Network {
            vni,
            name: name.to_string(),
            subnet: parse_cidr_v4(subnet).unwrap(),
            default_action: ActionName::Pass,
            drop_icmp: false,
        }
    }

    #[test]
    fn rejects_duplicate_tap_binding() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24")).unwrap();
        t.create_port(100, "h1", "tap0", None).unwrap();
        // Same (host, tap) → rejected, even on a different IP/allocation.
        assert!(t.create_port(100, "h1", "tap0", None).is_err());
        // A different tap on the same host is fine.
        assert!(t.create_port(100, "h1", "tap1", None).is_ok());
    }

    #[test]
    fn remove_host_and_network_require_no_ports() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24")).unwrap();
        let p = t.create_port(100, "h1", "tap0", None).unwrap();
        // Both are blocked while the port exists.
        assert!(t.remove_host("h1").is_err());
        assert!(t.remove_network(100).is_err());
        // After removing the port, both succeed and report existence.
        assert!(t.remove_port(&p.id));
        assert!(t.remove_network(100).unwrap());
        assert!(t.remove_host("h1").unwrap());
        // Removing again reports "did not exist".
        assert!(!t.remove_host("h1").unwrap());
    }

    #[test]
    fn ipam_allocates_sequentially_and_skips_taken() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();

        let p1 = t.create_port(100, "h1", "tap0", None).unwrap();
        let p2 = t.create_port(100, "h1", "tap1", None).unwrap();
        assert_eq!(p1.ip, "192.168.50.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(p2.ip, "192.168.50.2".parse::<Ipv4Addr>().unwrap());
        // MAC is locally-administered + the address octets.
        assert_eq!(p1.mac, [0x02, 0x00, 192, 168, 50, 1]);

        // An explicit IP is honoured and then excluded from future allocations.
        let p3 = t
            .create_port(
                100,
                "h1",
                "tap2",
                Some("192.168.50.9".parse::<Ipv4Addr>().unwrap()),
            )
            .unwrap();
        assert_eq!(p3.ip, "192.168.50.9".parse::<Ipv4Addr>().unwrap());
        let p4 = t.create_port(100, "h1", "tap3", None).unwrap();
        assert_eq!(p4.ip, "192.168.50.3".parse::<Ipv4Addr>().unwrap()); // skips .9
    }

    #[test]
    fn rejects_duplicate_and_out_of_subnet_ips() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.create_port(
            100,
            "h1",
            "tap0",
            Some("192.168.50.5".parse::<Ipv4Addr>().unwrap()),
        )
        .unwrap();
        assert!(
            t.create_port(
                100,
                "h1",
                "tap1",
                Some("192.168.50.5".parse::<Ipv4Addr>().unwrap())
            )
            .is_err()
        );
        assert!(
            t.create_port(
                100,
                "h1",
                "tap2",
                Some("10.0.0.5".parse::<Ipv4Addr>().unwrap())
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_network_or_host_and_bad_vni() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        assert!(t.create_port(100, "h1", "tap0", None).is_err()); // no network
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        assert!(t.create_port(100, "ghost", "tap0", None).is_err()); // no host
        assert!(t.add_network(network(0, "bad", "10.0.0.0/24")).is_err()); // vni 0
    }

    #[test]
    fn rejects_networks_in_the_reserved_evpn_vni_range() {
        let mut t = Topology::new();
        // The reserved base itself and anything above it are refused so a future
        // EVPN/FPM learning path owns them exclusively (M5 map-ownership).
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE, "evpn", "10.1.0.0/24"))
                .is_err()
        );
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE + 42, "evpn2", "10.2.0.0/24"))
                .is_err()
        );
        // The last orchestrator-owned VNI just below the reserved base is fine.
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE - 1, "ok", "10.3.0.0/24"))
                .is_ok()
        );
    }

    #[test]
    fn derives_local_interface_and_remote_tunnel_neighbor() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();

        let pa = t.create_port(5000, "h1", "tapA", None).unwrap(); // .1 on h1
        let pb = t.create_port(5000, "h2", "tapB", None).unwrap(); // .2 on h2

        // --- h1's derived config ---
        let cfg = t.derive("h1").unwrap();
        let rt = cfg.resolve().expect("derived config must be valid");

        // Overlay endpoint is h1's.
        let ov = rt.overlay.as_ref().unwrap();
        assert_eq!(ov.local_vtep_ip, [10, 10, 0, 1]);

        // One policy for the participating network (id == vni).
        assert!(rt.policies.iter().any(|p| p.id == 5000));

        // Local port pa → an interface binding on tapA, vni 5000.
        let iface = rt.interfaces.iter().find(|i| i.name == "tapA").unwrap();
        assert_eq!(iface.policy, 5000);
        assert_eq!(iface.vni, 5000);
        // The remote port (pb on h2) is NOT a local interface here.
        assert!(!rt.interfaces.iter().any(|i| i.name == "tapB"));

        // Remote port pb → a tunnel to h2's VTEP + an ARP neighbour.
        assert_eq!(rt.tunnels.len(), 1);
        let tun = &rt.tunnels[0];
        assert_eq!(tun.vni, 5000);
        assert_eq!(tun.inner_dst.octets, pb.ip.octets());
        assert_eq!(tun.inner_dst.prefix, 32);
        assert_eq!(tun.remote_vtep_ip, [10, 10, 0, 2]);
        assert_eq!(tun.outer_dst_mac, [0x02, 0, 0, 0, 0, 0x22]); // h2's underlay MAC

        assert_eq!(rt.neighbors.len(), 1);
        assert_eq!(rt.neighbors[0].ip, pb.ip.octets());
        assert_eq!(rt.neighbors[0].mac, [0x02, 0x00, 192, 168, 100, 2]);

        // Symmetry: h2 sees pa as the remote tunnel/neighbour, pb as local.
        let cfg2 = t.derive("h2").unwrap().resolve().unwrap();
        assert!(cfg2.interfaces.iter().any(|i| i.name == "tapB"));
        assert_eq!(cfg2.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(cfg2.tunnels[0].remote_vtep_ip, [10, 10, 0, 1]);
    }

    #[test]
    fn host_without_ports_on_a_network_gets_no_tunnel_to_it() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_host(host("h3", "10.10.0.3", 0x33));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        t.create_port(5000, "h1", "tapA", None).unwrap();
        t.create_port(5000, "h2", "tapB", None).unwrap();

        // h3 has no port on network 5000 → it gets no policy, no tunnels.
        let cfg3 = t.derive("h3").unwrap().resolve().unwrap();
        assert!(cfg3.tunnels.is_empty());
        assert!(cfg3.neighbors.is_empty());
        assert!(cfg3.interfaces.is_empty());
        // Only the implicit default policy 0 remains.
        assert_eq!(cfg3.policies.len(), 1);
        assert_eq!(cfg3.policies[0].id, 0);
    }

    #[test]
    fn snapshot_roundtrip_is_lossless() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        let p = t.create_port(5000, "h1", "tapA", None).unwrap();

        let snap = t.to_snapshot();
        let restored = Topology::from_snapshot(&snap);
        // Same derived config and same port identity after a round-trip.
        assert_eq!(derive_configs_str(&t), derive_configs_str(&restored));
        assert_eq!(restored.ports(), &[p]);
    }

    // Small helper: a stable string view of a host's derived config for equality.
    fn derive_configs_str(t: &Topology) -> Vec<String> {
        let mut hosts: Vec<_> = t.hosts().map(|h| h.id.clone()).collect();
        hosts.sort();
        hosts
            .iter()
            .map(|id| format!("{:?}", t.derive(id)))
            .collect()
    }

    #[test]
    fn removing_a_port_withdraws_it_from_peer_configs() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        t.create_port(5000, "h1", "tapA", None).unwrap();
        let pb = t.create_port(5000, "h2", "tapB", None).unwrap();

        assert_eq!(t.derive("h1").unwrap().resolve().unwrap().tunnels.len(), 1);
        assert!(t.remove_port(&pb.id));
        // h1 no longer tunnels to the removed peer.
        let cfg = t.derive("h1").unwrap().resolve().unwrap();
        assert!(cfg.tunnels.is_empty());
        assert!(cfg.neighbors.is_empty());
    }

    #[test]
    fn migrating_a_port_preserves_identity_and_repoints_peers() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_host(host("h3", "10.10.0.3", 0x33));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        // pa lives on h1; pc gives h3 a port on the network so it tunnels to pa.
        let pa = t.create_port(5000, "h1", "tapA", None).unwrap();
        t.create_port(5000, "h3", "tapC", None).unwrap();

        // Before: h3 tunnels to pa via h1's VTEP.
        let h3 = t.derive("h3").unwrap().resolve().unwrap();
        assert_eq!(h3.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(h3.tunnels[0].remote_vtep_ip, [10, 10, 0, 1]); // h1

        // Migrate pa from h1 to h2 with a new tap.
        let moved = t.migrate_port(&pa.id, "h2", "tapA2").unwrap();
        // Identity preserved: same id, ip, mac, vni.
        assert_eq!(moved.id, pa.id);
        assert_eq!(moved.ip, pa.ip);
        assert_eq!(moved.mac, pa.mac);
        assert_eq!(moved.host, "h2");
        assert_eq!(moved.tap, "tapA2");

        // After: the port is local on h2 (interface tapA2), and h3's tunnel to it
        // now points at h2's VTEP — same inner IP/MAC.
        let h2 = t.derive("h2").unwrap().resolve().unwrap();
        assert!(h2.interfaces.iter().any(|i| i.name == "tapA2"));
        let h3 = t.derive("h3").unwrap().resolve().unwrap();
        assert_eq!(h3.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(h3.tunnels[0].remote_vtep_ip, [10, 10, 0, 2]); // now h2
        // h1 no longer hosts it locally.
        let h1 = t.derive("h1").unwrap().resolve().unwrap();
        assert!(!h1.interfaces.iter().any(|i| i.name == "tapA"));

        // Unknown host / port are errors.
        assert!(t.migrate_port(&pa.id, "ghost", "tap").is_err());
        assert!(t.migrate_port("port-nope", "h2", "tap").is_err());
    }
}
