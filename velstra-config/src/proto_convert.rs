//! Conversions between the TOML config ([`FileConfig`]) and the gRPC wire format
//! ([`velstra_proto::NodeConfig`]).
//!
//! The controller turns a node's TOML into a `NodeConfig` to serve it; the agent
//! turns a received `NodeConfig` back into a `FileConfig` and reuses
//! [`FileConfig::resolve`] so the *exact same* validation runs whether config
//! came from a file or the wire.

use anyhow::Result;
use velstra_proto as proto;

use crate::config::{
    ActionName, BackendCfg, EncapName, FileConfig, ForwardMode, InterfaceFile, NeighborCfg,
    OverlayCfg, PolicyFile, PortRule, ProtoName, RouteCfg, RuntimeConfig, ServiceCfg, TunnelCfg,
};

fn port_rule_to_proto(r: &PortRule) -> proto::PortRule {
    proto::PortRule {
        proto: proto_to_proto(r.proto) as i32,
        port: u32::from(r.port),
        action: action_to_proto(r.action) as i32,
    }
}

fn port_rule_from_proto(r: &proto::PortRule) -> PortRule {
    PortRule {
        proto: proto_from_proto(r.proto()),
        port: r.port as u16,
        action: action_from_proto(r.action()),
    }
}

fn action_to_proto(a: ActionName) -> proto::Action {
    match a {
        ActionName::Pass => proto::Action::Pass,
        ActionName::Drop => proto::Action::Drop,
    }
}

fn action_from_proto(a: proto::Action) -> ActionName {
    match a {
        proto::Action::Drop => ActionName::Drop,
        proto::Action::Pass => ActionName::Pass,
    }
}

fn proto_to_proto(p: ProtoName) -> proto::Proto {
    match p {
        ProtoName::Tcp => proto::Proto::Tcp,
        ProtoName::Udp => proto::Proto::Udp,
        ProtoName::Icmp => proto::Proto::Icmp,
    }
}

fn proto_from_proto(p: proto::Proto) -> ProtoName {
    match p {
        proto::Proto::Tcp => ProtoName::Tcp,
        proto::Proto::Udp => ProtoName::Udp,
        proto::Proto::Icmp => ProtoName::Icmp,
    }
}

fn mode_to_proto(m: ForwardMode) -> proto::ForwardMode {
    match m {
        ForwardMode::Route => proto::ForwardMode::Route,
        ForwardMode::Switch => proto::ForwardMode::Switch,
    }
}

fn mode_from_proto(m: proto::ForwardMode) -> ForwardMode {
    match m {
        proto::ForwardMode::Route => ForwardMode::Route,
        proto::ForwardMode::Switch => ForwardMode::Switch,
    }
}

fn encap_to_proto(e: EncapName) -> proto::Encap {
    match e {
        EncapName::Vxlan => proto::Encap::Vxlan,
        EncapName::Geneve => proto::Encap::Geneve,
    }
}

fn encap_from_proto(e: proto::Encap) -> EncapName {
    match e {
        proto::Encap::Vxlan => EncapName::Vxlan,
        proto::Encap::Geneve => EncapName::Geneve,
    }
}

/// Serialise a [`FileConfig`] into a [`proto::NodeConfig`] with the given
/// `version` (used by the controller to signal changes to watchers).
pub fn file_config_to_proto(cfg: &FileConfig, version: u64) -> proto::NodeConfig {
    proto::NodeConfig {
        version,
        default_action: action_to_proto(cfg.default_action) as i32,
        drop_icmp: cfg.drop_icmp,
        log: cfg.log,
        stateful: cfg.stateful,
        blocklist: cfg.blocklist.clone(),
        port_rules: cfg.port_rules.iter().map(port_rule_to_proto).collect(),
        policies: cfg
            .policies
            .iter()
            .map(|p| proto::Policy {
                id: p.id,
                name: p.name.clone().unwrap_or_default(),
                default_action: action_to_proto(p.default_action) as i32,
                drop_icmp: p.drop_icmp,
                log: p.log,
                stateful: p.stateful,
                blocklist: p.blocklist.clone(),
                port_rules: p.port_rules.iter().map(port_rule_to_proto).collect(),
            })
            .collect(),
        interfaces: cfg
            .interfaces
            .iter()
            .map(|i| proto::InterfaceAssignment {
                name: i.name.clone(),
                policy: i.policy,
                vni: i.vni,
            })
            .collect(),
        routes: cfg
            .routes
            .iter()
            .map(|r| proto::Route {
                dest: r.dest.clone(),
                out_iface: r.out_iface.clone(),
                via_mac: r.via_mac.clone(),
                src_mac: r.src_mac.clone().unwrap_or_default(),
                mode: mode_to_proto(r.mode) as i32,
            })
            .collect(),
        services: cfg
            .services
            .iter()
            .map(|s| proto::Service {
                vip: s.vip.clone(),
                port: u32::from(s.port),
                proto: proto_to_proto(s.proto) as i32,
                backends: s
                    .backends
                    .iter()
                    .map(|b| proto::Backend {
                        ip: b.ip.clone(),
                        port: u32::from(b.port.unwrap_or(0)),
                    })
                    .collect(),
            })
            .collect(),
        overlay: cfg.overlay.as_ref().map(|o| proto::Overlay {
            local_vtep: o.local_vtep.clone(),
            underlay_iface: o.underlay_iface.clone(),
            encap: encap_to_proto(o.encap) as i32,
            udp_port: u32::from(o.udp_port.unwrap_or(0)),
            local_mac: o.local_mac.clone().unwrap_or_default(),
            underlay_mtu: u32::from(o.underlay_mtu.unwrap_or(0)),
        }),
        tunnels: cfg
            .tunnels
            .iter()
            .map(|t| proto::Tunnel {
                vni: t.vni,
                inner_dst: t.inner_dst.clone(),
                remote_vtep: t.remote_vtep.clone(),
                via_mac: t.via_mac.clone(),
                out_iface: t.out_iface.clone(),
            })
            .collect(),
        neighbors: cfg
            .neighbors
            .iter()
            .map(|n| proto::Neighbor {
                vni: n.vni,
                ip: n.ip.clone(),
                mac: n.mac.clone(),
            })
            .collect(),
    }
}

/// Deserialise a [`proto::NodeConfig`] back into a [`FileConfig`]. Lossy only for
/// out-of-range port numbers (clamped to `u16`), which protobuf cannot express.
pub fn file_config_from_proto(cfg: &proto::NodeConfig) -> FileConfig {
    FileConfig {
        default_action: action_from_proto(cfg.default_action()),
        drop_icmp: cfg.drop_icmp,
        log: cfg.log,
        stateful: cfg.stateful,
        blocklist: cfg.blocklist.clone(),
        port_rules: cfg.port_rules.iter().map(port_rule_from_proto).collect(),
        policies: cfg
            .policies
            .iter()
            .map(|p| PolicyFile {
                id: p.id,
                name: if p.name.is_empty() {
                    None
                } else {
                    Some(p.name.clone())
                },
                default_action: action_from_proto(p.default_action()),
                drop_icmp: p.drop_icmp,
                log: p.log,
                stateful: p.stateful,
                blocklist: p.blocklist.clone(),
                port_rules: p.port_rules.iter().map(port_rule_from_proto).collect(),
            })
            .collect(),
        interfaces: cfg
            .interfaces
            .iter()
            .map(|i| InterfaceFile {
                name: i.name.clone(),
                policy: i.policy,
                vni: i.vni,
            })
            .collect(),
        routes: cfg
            .routes
            .iter()
            .map(|r| RouteCfg {
                dest: r.dest.clone(),
                out_iface: r.out_iface.clone(),
                via_mac: r.via_mac.clone(),
                src_mac: if r.src_mac.is_empty() {
                    None
                } else {
                    Some(r.src_mac.clone())
                },
                mode: mode_from_proto(r.mode()),
            })
            .collect(),
        services: cfg
            .services
            .iter()
            .map(|s| ServiceCfg {
                vip: s.vip.clone(),
                port: s.port as u16,
                proto: proto_from_proto(s.proto()),
                backends: s
                    .backends
                    .iter()
                    .map(|b| BackendCfg {
                        ip: b.ip.clone(),
                        port: if b.port == 0 {
                            None
                        } else {
                            Some(b.port as u16)
                        },
                    })
                    .collect(),
            })
            .collect(),
        // Port-forwards are a file-config-only (appliance) feature; the gRPC
        // NodeConfig has no equivalent message, so they convert to/from empty.
        port_forwards: Vec::new(),
        overlay: cfg.overlay.as_ref().map(|o| OverlayCfg {
            local_vtep: o.local_vtep.clone(),
            underlay_iface: o.underlay_iface.clone(),
            encap: encap_from_proto(o.encap()),
            udp_port: if o.udp_port == 0 {
                None
            } else {
                Some(o.udp_port as u16)
            },
            local_mac: if o.local_mac.is_empty() {
                None
            } else {
                Some(o.local_mac.clone())
            },
            underlay_mtu: if o.underlay_mtu == 0 {
                None
            } else {
                Some(o.underlay_mtu as u16)
            },
        }),
        tunnels: cfg
            .tunnels
            .iter()
            .map(|t| TunnelCfg {
                vni: t.vni,
                inner_dst: t.inner_dst.clone(),
                remote_vtep: t.remote_vtep.clone(),
                via_mac: t.via_mac.clone(),
                out_iface: t.out_iface.clone(),
            })
            .collect(),
        neighbors: cfg
            .neighbors
            .iter()
            .map(|n| NeighborCfg {
                vni: n.vni,
                ip: n.ip.clone(),
                mac: n.mac.clone(),
            })
            .collect(),
    }
}

/// Convert a received [`proto::NodeConfig`] straight into a validated
/// [`RuntimeConfig`], reusing [`FileConfig::resolve`].
pub fn runtime_from_proto(cfg: &proto::NodeConfig) -> Result<RuntimeConfig> {
    file_config_from_proto(cfg).resolve()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_proto_roundtrip_preserves_everything() {
        let toml = r#"
            default_action = "drop"
            drop_icmp = true
            log = true
            blocklist = ["10.0.0.0/8"]

            [[port_rule]]
            proto = "tcp"
            port = 22
            action = "drop"

            [[route]]
            dest = "10.9.0.0/16"
            out_iface = "eth1"
            via_mac = "02:00:00:00:00:01"
            mode = "switch"

            [[service]]
            vip = "10.0.0.100"
            port = 80
            proto = "tcp"
            backends = [{ ip = "10.0.1.2", port = 8080 }, { ip = "10.0.1.3" }]
        "#;
        let original: FileConfig = toml::from_str(toml).unwrap();

        // FileConfig -> proto -> FileConfig must resolve to identical map contents.
        let wire = file_config_to_proto(&original, 7);
        assert_eq!(wire.version, 7);
        let back = file_config_from_proto(&wire);

        let a = original.resolve().unwrap();
        let b = back.resolve().unwrap();
        assert_eq!(a.policies[0].global, b.policies[0].global);
        assert_eq!(a.policies[0].blocklist, b.policies[0].blocklist);
        assert_eq!(a.policies[0].port_rules, b.policies[0].port_rules);
        assert_eq!(a.services.len(), b.services.len());
        assert_eq!(a.services[0].key, b.services[0].key);
        assert_eq!(a.services[0].backends, b.services[0].backends);
        assert_eq!(a.routes.len(), b.routes.len());
        assert_eq!(a.routes[0].flags, b.routes[0].flags);
    }

    #[test]
    fn tenant_policies_and_interfaces_survive_proto_roundtrip() {
        let toml = r#"
            default_action = "pass"
            [[policy]]
            id = 3
            name = "tenant-x"
            default_action = "drop"
            blocklist = ["198.51.100.0/24"]
            [[policy.port_rule]]
            proto = "tcp"
            port = 443
            action = "pass"
            [[interface]]
            name = "tap0"
            policy = 3
        "#;
        let original: FileConfig = toml::from_str(toml).unwrap();
        let back = file_config_from_proto(&file_config_to_proto(&original, 1));

        let a = original.resolve().unwrap();
        let b = back.resolve().unwrap();
        // Both policies (0 + tenant 3) and the interface assignment survive.
        assert_eq!(a.policies.len(), 2);
        assert_eq!(a.policies.len(), b.policies.len());
        let ta = a.policies.iter().find(|p| p.id == 3).unwrap();
        let tb = b.policies.iter().find(|p| p.id == 3).unwrap();
        assert_eq!(ta.global, tb.global);
        assert_eq!(ta.blocklist, tb.blocklist);
        assert_eq!(ta.port_rules, tb.port_rules);
        assert_eq!(a.interfaces, b.interfaces);
        assert_eq!(b.interfaces.len(), 1);
        assert_eq!(b.interfaces[0].name, "tap0");
        assert_eq!(b.interfaces[0].policy, 3);
        assert_eq!(b.interfaces[0].vni, 3); // defaulted from policy, survives roundtrip
    }

    #[test]
    fn overlay_and_tunnels_survive_proto_roundtrip() {
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
        let original: FileConfig = toml::from_str(toml).unwrap();
        let back = file_config_from_proto(&file_config_to_proto(&original, 4));

        let a = original.resolve().unwrap();
        let b = back.resolve().unwrap();
        let (oa, ob) = (a.overlay.unwrap(), b.overlay.unwrap());
        assert_eq!(oa.local_vtep_ip, ob.local_vtep_ip);
        assert_eq!(oa.encap, ob.encap);
        assert_eq!(oa.udp_port, ob.udp_port);
        assert_eq!(a.tunnels.len(), b.tunnels.len());
        assert_eq!(a.tunnels[0].vni, b.tunnels[0].vni);
        assert_eq!(a.tunnels[0].inner_dst, b.tunnels[0].inner_dst);
        assert_eq!(a.tunnels[0].remote_vtep_ip, b.tunnels[0].remote_vtep_ip);
        assert_eq!(a.tunnels[0].outer_dst_mac, b.tunnels[0].outer_dst_mac);
    }

    #[test]
    fn backend_port_zero_means_keep() {
        let wire = proto::NodeConfig {
            services: vec![proto::Service {
                vip: "10.0.0.1".into(),
                port: 53,
                proto: proto::Proto::Udp as i32,
                backends: vec![proto::Backend {
                    ip: "10.0.1.9".into(),
                    port: 0,
                }],
            }],
            ..Default::default()
        };
        let file = file_config_from_proto(&wire);
        assert_eq!(file.services[0].backends[0].port, None);
    }
}
