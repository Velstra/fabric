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
    ActionName, BackendCfg, EncapName, FileConfig, FloodVtepCfg, ForwardMode, InterfaceFile,
    IrbRouteCfg, MacRouteCfg, Nd6Cfg, NeighborCfg, OverlayCfg, PolicyFile, PortRule, ProtoName,
    RouteCfg, RuntimeConfig, ServiceCfg, SourceValidationName, Srv6Cfg, Srv6FloodCfg,
    Srv6IrbRouteCfg, Srv6LocalSidCfg, Srv6RouteCfg, TunnelCfg,
};

fn port_rule_to_proto(r: &PortRule) -> proto::PortRule {
    proto::PortRule {
        proto: proto_to_proto(r.proto) as i32,
        port: u32::from(r.port),
        action: action_to_proto(r.action) as i32,
        log: r.log,
        src: r.src.clone().unwrap_or_default(),
        dst: r.dst.clone().unwrap_or_default(),
        limit: r.limit.unwrap_or(0),
        burst: r.burst.unwrap_or(0),
        icmp_type: u32::from(r.icmp_type.unwrap_or(0)),
        family: r.family.clone().unwrap_or_default(),
        direction: r.direction.clone().unwrap_or_default(),
        in_interface: r.in_interface.clone().unwrap_or_default(),
        // A verdict on the device, and it used to stop here. An operator
        // quarantining a compromised machine got a green apply and an empty
        // MAC_RULES, because the rule *validated* on the way through.
        src_mac: r.src_mac.clone().unwrap_or_default(),
    }
}

fn port_rule_from_proto(r: &proto::PortRule) -> PortRule {
    PortRule {
        src_mac: (!r.src_mac.is_empty()).then(|| r.src_mac.clone()),
        in_interface: (!r.in_interface.is_empty()).then(|| r.in_interface.clone()),
        proto: proto_from_proto(r.proto()),
        // The proto carries the port as u32; a value past 65535 is invalid. Saturate
        // rather than `as u16`-truncate, which would wrap (e.g. 65536 → 0, the
        // wildcard port) and silently open a rule the operator never wrote.
        port: r.port.min(u16::MAX as u32) as u16,
        // Same saturation reasoning as `port`: a type past 255 is not a type,
        // and truncating would turn it into a different one.
        icmp_type: (r.icmp_type != 0).then(|| r.icmp_type.min(u8::MAX as u32) as u8),
        family: (!r.family.is_empty()).then(|| r.family.clone()),
        direction: (!r.direction.is_empty()).then(|| r.direction.clone()),
        action: action_from_proto(r.action()),
        log: r.log,
        src: if r.src.is_empty() {
            None
        } else {
            Some(r.src.clone())
        },
        dst: if r.dst.is_empty() {
            None
        } else {
            Some(r.dst.clone())
        },
        limit: (r.limit != 0).then_some(r.limit),
        burst: (r.burst != 0).then_some(r.burst),
    }
}

fn action_to_proto(a: ActionName) -> proto::Action {
    match a {
        ActionName::Pass => proto::Action::Pass,
        ActionName::Drop => proto::Action::Drop,
        // The gRPC controller protocol has no `reject` (it's a file-config /
        // appliance feature); it degrades to `drop` on the wire.
        ActionName::Reject => proto::Action::Drop,
    }
}

fn action_from_proto(a: proto::Action) -> ActionName {
    match a {
        proto::Action::Drop => ActionName::Drop,
        proto::Action::Pass => ActionName::Pass,
    }
}

fn rpf_to_proto(v: SourceValidationName) -> proto::SourceValidation {
    match v {
        SourceValidationName::Disable => proto::SourceValidation::Disable,
        SourceValidationName::Loose => proto::SourceValidation::Loose,
        SourceValidationName::Strict => proto::SourceValidation::Strict,
    }
}

fn rpf_from_proto(v: proto::SourceValidation) -> SourceValidationName {
    match v {
        proto::SourceValidation::Disable => SourceValidationName::Disable,
        proto::SourceValidation::Loose => SourceValidationName::Loose,
        proto::SourceValidation::Strict => SourceValidationName::Strict,
    }
}

fn proto_to_proto(p: ProtoName) -> proto::Proto {
    match p {
        ProtoName::Tcp => proto::Proto::Tcp,
        ProtoName::Udp => proto::Proto::Udp,
        ProtoName::Icmp => proto::Proto::Icmp,
        ProtoName::Icmpv6 => proto::Proto::Icmpv6,
        ProtoName::Vrrp => proto::Proto::Vrrp,
        ProtoName::Esp => proto::Proto::Esp,
        ProtoName::Ah => proto::Proto::Ah,
        ProtoName::Gre => proto::Proto::Gre,
        ProtoName::Ospf => proto::Proto::Ospf,
        ProtoName::Pim => proto::Proto::Pim,
    }
}

fn proto_from_proto(p: proto::Proto) -> ProtoName {
    match p {
        proto::Proto::Tcp => ProtoName::Tcp,
        proto::Proto::Udp => ProtoName::Udp,
        proto::Proto::Icmp => ProtoName::Icmp,
        proto::Proto::Icmpv6 => ProtoName::Icmpv6,
        proto::Proto::Vrrp => ProtoName::Vrrp,
        proto::Proto::Esp => ProtoName::Esp,
        proto::Proto::Ah => ProtoName::Ah,
        proto::Proto::Gre => ProtoName::Gre,
        proto::Proto::Ospf => ProtoName::Ospf,
        proto::Proto::Pim => ProtoName::Pim,
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
        EncapName::Srv6 => proto::Encap::Srv6,
    }
}

fn encap_from_proto(e: proto::Encap) -> EncapName {
    match e {
        proto::Encap::Vxlan => EncapName::Vxlan,
        proto::Encap::Geneve => EncapName::Geneve,
        proto::Encap::Srv6 => EncapName::Srv6,
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
        source_validation: rpf_to_proto(cfg.source_validation) as i32,
        fail_closed: cfg.fail_closed,
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
                source_validation: rpf_to_proto(p.source_validation) as i32,
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
                mss: i.mss.map(u32::from),
                bind_mac: i.bind_mac.clone(),
                bind_addresses: i.bind_addresses.clone(),
                rate_limit_mbit: i.rate_limit_mbit,
                masquerade: i.masquerade,
                cgnat_base_port: u32::from(i.cgnat_base_port),
                cgnat_block_size: u32::from(i.cgnat_block_size),
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
                policy: r.policy,
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
                        draining: b.draining,
                    })
                    .collect(),
                policy: s.policy,
                router_nat: s.router_nat,
                reply_policy: s.reply_policy,
                client_affinity: s.client_affinity,
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
        mac_routes: cfg
            .mac_routes
            .iter()
            .map(|m| proto::MacRoute {
                vni: m.vni,
                mac: m.mac.clone(),
                remote_vtep: m.remote_vtep.clone(),
                via_mac: m.via_mac.clone(),
                out_iface: m.out_iface.clone(),
            })
            .collect(),
        irb_routes: cfg
            .irb_routes
            .iter()
            .map(|r| proto::IrbRoute {
                vni: r.vni,
                inner_dst: r.inner_dst.clone(),
                l3_vni: r.l3_vni,
                remote_vtep: r.remote_vtep.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
                router_mac: r.router_mac.clone(),
                gateway_mac: r.gateway_mac.clone(),
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
        nd_neighbors: cfg
            .nd_neighbors
            .iter()
            .map(|n| proto::Nd6 {
                vni: n.vni,
                ip: n.ip.clone(),
                mac: n.mac.clone(),
            })
            .collect(),
        flood_vteps: cfg
            .flood_vteps
            .iter()
            .map(|fv| proto::FloodVtep {
                vni: fv.vni,
                remote_vtep: fv.remote_vtep.clone(),
                via_mac: fv.via_mac.clone(),
                out_iface: fv.out_iface.clone(),
            })
            .collect(),
        srv6: cfg.srv6.as_ref().map(|s| proto::Srv6 {
            local_src: s.local_src.clone(),
            underlay_iface: s.underlay_iface.clone(),
            local_mac: s.local_mac.clone().unwrap_or_default(),
            underlay_mtu: u32::from(s.underlay_mtu.unwrap_or(0)),
            peers: s.peers.clone(),
        }),
        srv6_routes: cfg
            .srv6_routes
            .iter()
            .map(|r| proto::Srv6Route {
                vni: r.vni,
                mac: r.mac.clone(),
                remote_sid: r.remote_sid.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
            })
            .collect(),
        srv6_local_sids: cfg
            .srv6_local_sids
            .iter()
            .map(|ls| proto::Srv6LocalSid {
                sid: ls.sid.clone(),
                vni: ls.vni,
                behavior: ls.behavior.clone().unwrap_or_default(),
            })
            .collect(),
        srv6_floods: cfg
            .srv6_floods
            .iter()
            .map(|f| proto::Srv6Flood {
                vni: f.vni,
                remote_sid: f.remote_sid.clone(),
                via_mac: f.via_mac.clone(),
                out_iface: f.out_iface.clone(),
            })
            .collect(),
        srv6_irb_routes: cfg
            .srv6_irb_routes
            .iter()
            .map(|r| proto::Srv6IrbRoute {
                vni: r.vni,
                inner_dst: r.inner_dst.clone(),
                l3_vni: r.l3_vni,
                remote_sid: r.remote_sid.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
                router_mac: r.router_mac.clone(),
                gateway_mac: r.gateway_mac.clone(),
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
        // A captive portal is an appliance feature configured on the appliance
        // (C20); the fabric controller has no notion of one, and inventing an
        // empty gate here would set the portal flag on every controller-driven
        // node.
        portal: None,
        source_validation: rpf_from_proto(cfg.source_validation()),
        fail_closed: cfg.fail_closed,
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
                source_validation: rpf_from_proto(p.source_validation()),
                blocklist: p.blocklist.clone(),
                port_rules: p.port_rules.iter().map(port_rule_from_proto).collect(),
                portal: None,
            })
            .collect(),
        interfaces: cfg
            .interfaces
            .iter()
            .map(|i| InterfaceFile {
                mss: i.mss.map(|v| v as u16),
                // Port security, carried at last. This used to say the proto had
                // no field for it — true, and its consequence was never written
                // down beside it: the orchestrator derives a binding for every
                // tenant tap precisely so a guest cannot send as its neighbour,
                // and dropping it here meant every controller-managed node ran
                // with the feature off.
                bind_mac: i.bind_mac.clone(),
                bind_addresses: i.bind_addresses.clone(),
                rate_limit_mbit: i.rate_limit_mbit,
                name: i.name.clone(),
                policy: i.policy,
                vni: i.vni,
                masquerade: i.masquerade,
                cgnat_base_port: i.cgnat_base_port as u16,
                cgnat_block_size: i.cgnat_block_size as u16,
            })
            .collect(),
        routes: cfg
            .routes
            .iter()
            .map(|r| RouteCfg {
                policy: r.policy,
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
                policy: s.policy,
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
                        draining: b.draining,
                    })
                    .collect(),
                router_nat: s.router_nat,
                reply_policy: s.reply_policy,
                client_affinity: s.client_affinity,
            })
            .collect(),
        // Port-forwards and the SYN proxy are file-config-only (appliance)
        // features; the gRPC NodeConfig has no equivalent message, so they
        // convert to/from empty. Both protect a service the appliance publishes,
        // which is a firewall concern rather than a fabric one.
        port_forwards: Vec::new(),
        synproxy: Vec::new(),
        flow_export: None,
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
        mac_routes: cfg
            .mac_routes
            .iter()
            .map(|m| MacRouteCfg {
                vni: m.vni,
                mac: m.mac.clone(),
                remote_vtep: m.remote_vtep.clone(),
                via_mac: m.via_mac.clone(),
                out_iface: m.out_iface.clone(),
            })
            .collect(),
        irb_routes: cfg
            .irb_routes
            .iter()
            .map(|r| IrbRouteCfg {
                vni: r.vni,
                inner_dst: r.inner_dst.clone(),
                l3_vni: r.l3_vni,
                remote_vtep: r.remote_vtep.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
                router_mac: r.router_mac.clone(),
                gateway_mac: r.gateway_mac.clone(),
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
        nd_neighbors: cfg
            .nd_neighbors
            .iter()
            .map(|n| Nd6Cfg {
                vni: n.vni,
                ip: n.ip.clone(),
                mac: n.mac.clone(),
            })
            .collect(),
        flood_vteps: cfg
            .flood_vteps
            .iter()
            .map(|fv| FloodVtepCfg {
                vni: fv.vni,
                remote_vtep: fv.remote_vtep.clone(),
                via_mac: fv.via_mac.clone(),
                out_iface: fv.out_iface.clone(),
            })
            .collect(),
        // NPTv6 is a file-config-only (appliance) feature; the gRPC NodeConfig has
        // no equivalent message, so it converts to/from empty.
        npt66: Vec::new(),
        // Conntrack sync (C9) is a file-config-only HA-appliance feature; the
        // controller never pushes it, so it converts to/from `None`.
        conntrack_sync: None,
        srv6: cfg.srv6.as_ref().map(|s| Srv6Cfg {
            local_src: s.local_src.clone(),
            underlay_iface: s.underlay_iface.clone(),
            local_mac: (!s.local_mac.is_empty()).then(|| s.local_mac.clone()),
            // `0` is protobuf's absent-integer, and it is also not a legal MTU, so
            // the two mean the same thing here: fall back to the resolve default.
            underlay_mtu: (s.underlay_mtu != 0).then(|| s.underlay_mtu.min(u16::MAX as u32) as u16),
            peers: s.peers.clone(),
        }),
        srv6_routes: cfg
            .srv6_routes
            .iter()
            .map(|r| Srv6RouteCfg {
                vni: r.vni,
                mac: r.mac.clone(),
                remote_sid: r.remote_sid.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
            })
            .collect(),
        srv6_local_sids: cfg
            .srv6_local_sids
            .iter()
            .map(|ls| Srv6LocalSidCfg {
                sid: ls.sid.clone(),
                vni: ls.vni,
                // Empty means "unset", which resolve reads as end.dt2u. Mapping it
                // to Some("") instead would fail validation on a config nobody
                // wrote that way.
                behavior: (!ls.behavior.is_empty()).then(|| ls.behavior.clone()),
            })
            .collect(),
        srv6_floods: cfg
            .srv6_floods
            .iter()
            .map(|f| Srv6FloodCfg {
                vni: f.vni,
                remote_sid: f.remote_sid.clone(),
                via_mac: f.via_mac.clone(),
                out_iface: f.out_iface.clone(),
            })
            .collect(),
        srv6_irb_routes: cfg
            .srv6_irb_routes
            .iter()
            .map(|r| Srv6IrbRouteCfg {
                vni: r.vni,
                inner_dst: r.inner_dst.clone(),
                l3_vni: r.l3_vni,
                remote_sid: r.remote_sid.clone(),
                via_mac: r.via_mac.clone(),
                out_iface: r.out_iface.clone(),
                router_mac: r.router_mac.clone(),
                gateway_mac: r.gateway_mac.clone(),
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
    fn source_validation_survives_the_wire_per_policy() {
        // The controller pushes configs as protobuf; a mode that silently reset
        // to `disable` in transit would leave the edge unvalidated while every
        // `show` still claimed otherwise.
        let toml = r#"
            source_validation = "strict"

            [[policy]]
            id = 3
            source_validation = "loose"
        "#;
        let original: FileConfig = toml::from_str(toml).unwrap();
        let wire = file_config_to_proto(&original, 1);
        assert_eq!(wire.source_validation(), proto::SourceValidation::Strict);
        assert_eq!(
            wire.policies[0].source_validation(),
            proto::SourceValidation::Loose
        );

        let back = file_config_from_proto(&wire);
        assert_eq!(back.source_validation, SourceValidationName::Strict);
        assert_eq!(
            back.policies[0].source_validation,
            SourceValidationName::Loose
        );

        let resolved = runtime_from_proto(&wire).unwrap();
        let mode = |id| {
            resolved
                .policies
                .iter()
                .find(|p| p.id == id)
                .unwrap()
                .global
                .source_validation()
        };
        assert_eq!(mode(0), velstra_common::SourceValidation::Strict);
        assert_eq!(mode(3), velstra_common::SourceValidation::Loose);
    }

    #[test]
    fn fail_closed_survives_toml_proto_and_resolve() {
        // Absent from the TOML: fail open, the historical behaviour, all the way
        // through to the resolved map contents.
        let default: FileConfig = toml::from_str("default_action = \"drop\"").unwrap();
        assert!(!default.fail_closed);
        assert!(!file_config_to_proto(&default, 1).fail_closed);
        assert!(!default.resolve().unwrap().fail_closed);
        // A passthrough config never fails closed either.
        assert!(!RuntimeConfig::passthrough().fail_closed);

        // Set in the TOML: carried across the wire and into the RuntimeConfig the
        // agent programs into the FAIL_CLOSED map.
        let toml = r#"
            default_action = "drop"
            fail_closed = true
        "#;
        let original: FileConfig = toml::from_str(toml).unwrap();
        assert!(original.fail_closed);
        let wire = file_config_to_proto(&original, 2);
        assert!(wire.fail_closed);
        let back = file_config_from_proto(&wire);
        assert!(back.fail_closed);
        assert!(back.resolve().unwrap().fail_closed);
        assert!(runtime_from_proto(&wire).unwrap().fail_closed);
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

            [[mac_route]]
            vni = 100
            mac = "02:00:00:00:0b:07"
            remote_vtep = "10.10.0.2"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"

            [[neighbor]]
            vni = 100
            ip = "192.168.50.7"
            mac = "02:00:00:00:0b:07"

            [[nd_neighbor]]
            vni = 100
            ip = "2001:db8::7"
            mac = "02:00:00:00:0b:08"

            [[flood_vtep]]
            vni = 100
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
        // B1: MAC-FDB entries survive the wire round-trip too.
        assert_eq!(a.mac_routes.len(), b.mac_routes.len());
        assert_eq!(a.mac_routes[0].vni, b.mac_routes[0].vni);
        assert_eq!(a.mac_routes[0].mac, b.mac_routes[0].mac);
        assert_eq!(a.mac_routes[0].mac, [0x02, 0, 0, 0, 0x0b, 0x07]);
        assert_eq!(
            a.mac_routes[0].remote_vtep_ip,
            b.mac_routes[0].remote_vtep_ip
        );
        assert_eq!(a.mac_routes[0].outer_dst_mac, b.mac_routes[0].outer_dst_mac);
        // ARP + B3 IPv6 ND suppression neighbours both survive the wire round-trip.
        assert_eq!(a.neighbors.len(), b.neighbors.len());
        assert_eq!(a.neighbors[0].ip, b.neighbors[0].ip);
        assert_eq!(a.nd_neighbors.len(), b.nd_neighbors.len());
        assert_eq!(a.nd_neighbors[0].vni, b.nd_neighbors[0].vni);
        assert_eq!(a.nd_neighbors[0].ip, b.nd_neighbors[0].ip);
        assert_eq!(
            a.nd_neighbors[0].ip,
            "2001:db8::7"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(a.nd_neighbors[0].mac, b.nd_neighbors[0].mac);
        assert_eq!(a.nd_neighbors[0].mac, [0x02, 0, 0, 0, 0x0b, 0x08]);
        // B2: BUM flood entries survive the wire round-trip too.
        assert_eq!(a.flood_vteps.len(), b.flood_vteps.len());
        assert_eq!(a.flood_vteps[0].vni, b.flood_vteps[0].vni);
        assert_eq!(a.flood_vteps[0].vni, 100);
        assert_eq!(
            a.flood_vteps[0].remote_vtep_ip,
            b.flood_vteps[0].remote_vtep_ip
        );
        assert_eq!(a.flood_vteps[0].remote_vtep_ip, [10, 10, 0, 2]);
        assert_eq!(
            a.flood_vteps[0].outer_dst_mac,
            b.flood_vteps[0].outer_dst_mac
        );
        assert_eq!(a.flood_vteps[0].outer_dst_mac, [0x02, 0, 0, 0, 0, 0x02]);
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
                    draining: false,
                }],
                policy: 0,
                router_nat: false,
                reply_policy: 0,
                client_affinity: false,
            }],
            ..Default::default()
        };
        let file = file_config_from_proto(&wire);
        assert_eq!(file.services[0].backends[0].port, None);
    }
}

#[cfg(test)]
mod every_field_survives {
    //! Round trips that fail to **compile** when a field is added and forgotten.
    //!
    //! This module exists because of what was found on 2026-08-18: `InterfaceFile`
    //! carried ten fields and the wire carried three. Port security, the per-port
    //! send ceiling, MSS clamping, masquerading and CGNAT were all built, tested
    //! and inert on every controller-managed node — the VM checks drive an
    //! appliance through its own CLI, which writes the node's TOML directly, so
    //! the one path nothing exercised was the one production uses.
    //!
    //! A round-trip test that constructs a value field by field would not have
    //! caught it either: adding an eleventh field and leaving it at its default
    //! keeps such a test green. **Destructuring** is what makes it a compile
    //! error — `let Struct { a, b, .. } = x` with no `..` cannot miss a field.

    use super::*;

    fn interface() -> InterfaceFile {
        InterfaceFile {
            name: "tap0".into(),
            policy: 4711,
            vni: Some(5001),
            mss: Some(1400),
            bind_mac: Some("02:00:00:00:00:01".into()),
            rate_limit_mbit: Some(100),
            bind_addresses: vec!["10.0.0.5".into(), "fd00::5".into()],
            masquerade: true,
            cgnat_base_port: 20000,
            cgnat_block_size: 512,
        }
    }

    /// Every field of an interface reaches an agent through the controller.
    #[test]
    fn interface_round_trips_every_field() {
        let before = interface();
        let cfg = FileConfig {
            interfaces: vec![interface()],
            ..Default::default()
        };
        let there = file_config_to_proto(&cfg, 0);
        let back = file_config_from_proto(&there);
        let after = back.interfaces.first().expect("the interface vanished");

        // No `..` — adding a field to `InterfaceFile` breaks this line, which is
        // the whole point. Assert each one rather than `assert_eq!` on the
        // struct, so a failure names the field that was dropped.
        let InterfaceFile {
            name,
            policy,
            vni,
            mss,
            bind_mac,
            rate_limit_mbit,
            bind_addresses,
            masquerade,
            cgnat_base_port,
            cgnat_block_size,
        } = after;
        assert_eq!(*name, before.name, "name");
        assert_eq!(*policy, before.policy, "policy");
        assert_eq!(*vni, before.vni, "vni");
        assert_eq!(*mss, before.mss, "mss — TCP clamping is off on this node");
        assert_eq!(
            *bind_mac, before.bind_mac,
            "bind_mac — port security is off, a guest may send as its neighbour"
        );
        assert_eq!(
            *rate_limit_mbit, before.rate_limit_mbit,
            "rate_limit_mbit — the port has no send ceiling"
        );
        assert_eq!(
            *bind_addresses, before.bind_addresses,
            "bind_addresses — port security is off, a guest may claim any address"
        );
        assert_eq!(*masquerade, before.masquerade, "masquerade — NAT is off");
        assert_eq!(*cgnat_base_port, before.cgnat_base_port, "cgnat_base_port");
        assert_eq!(
            *cgnat_block_size, before.cgnat_block_size,
            "cgnat_block_size"
        );
    }

    fn rule() -> PortRule {
        PortRule {
            proto: ProtoName::Tcp,
            port: 443,
            icmp_type: Some(8),
            family: Some("ipv4".into()),
            direction: Some("in".into()),
            action: ActionName::Pass,
            log: true,
            src_mac: Some("02:de:ad:be:ef:01".into()),
            in_interface: Some("eth1".into()),
            src: Some("10.0.0.0/24".into()),
            dst: Some("10.1.0.0/24".into()),
            limit: Some(50),
            burst: Some(100),
        }
    }

    /// Every field of a firewall rule reaches an agent through the controller.
    #[test]
    fn a_rule_round_trips_every_field() {
        let before = rule();
        // A rule carrying both `src` and `dst` is refused by the data plane, so
        // the round trip is asserted on the fields rather than through a
        // `resolve()` that would rightly reject this one.
        let there = port_rule_to_proto(&before);
        let after = port_rule_from_proto(&there);

        let PortRule {
            proto,
            port,
            icmp_type,
            family,
            direction,
            action,
            log,
            src_mac,
            in_interface,
            src,
            dst,
            limit,
            burst,
        } = &after;
        assert_eq!(*proto, before.proto, "proto");
        assert_eq!(*port, before.port, "port");
        assert_eq!(*icmp_type, before.icmp_type, "icmp_type");
        assert_eq!(*family, before.family, "family");
        assert_eq!(*direction, before.direction, "direction");
        assert_eq!(*action, before.action, "action");
        assert_eq!(*log, before.log, "log");
        assert_eq!(
            *src_mac, before.src_mac,
            "src_mac — a device quarantine is silently discarded"
        );
        assert_eq!(*in_interface, before.in_interface, "in_interface");
        assert_eq!(*src, before.src, "src");
        assert_eq!(*dst, before.dst, "dst");
        assert_eq!(*limit, before.limit, "limit");
        assert_eq!(*burst, before.burst, "burst");
    }

    /// Every SRv6 table survives FileConfig → proto → FileConfig.
    ///
    /// The assertions destructure each row with **no `..`**, so adding a field to
    /// any of the five SRv6 messages without also carrying it across the wire is a
    /// compile error here rather than a silently dropped value at runtime. That
    /// guard is the whole point of the test: the SRv6 half of `NodeConfig` spent
    /// its first release hardcoded to `None` on the way back in, so a controller
    /// could serve an SRv6 config an agent would then quietly discard.
    #[test]
    fn every_srv6_table_survives_the_proto_roundtrip() {
        let toml = r#"
            [srv6]
            local_src = "fc00:0:1::1"
            underlay_iface = "eth0"
            local_mac = "02:00:00:00:00:01"
            underlay_mtu = 9000
            peers = ["fc00:0:2::1", "fc00:0:3::1"]

            [[srv6_route]]
            vni = 10100
            mac = "02:00:5e:00:00:11"
            remote_sid = "fc00:0:2:0:2774::"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"

            [[srv6_local_sid]]
            sid = "fc00:0:1:0:2774::"
            vni = 10100
            behavior = "end.dt2u"

            [[srv6_local_sid]]
            sid = "fc00:0:1:1:2774::"
            vni = 10100
            behavior = "end.dt2m"

            [[srv6_flood]]
            vni = 10100
            remote_sid = "fc00:0:2:1:2774::"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"

            [[srv6_irb_route]]
            vni = 10100
            inner_dst = "10.20.0.0/24"
            l3_vni = 50100
            remote_sid = "fc00:0:2:0:c3b4::"
            via_mac = "02:00:00:00:00:02"
            out_iface = "eth0"
            router_mac = "02:aa:bb:cc:dd:ee"
            gateway_mac = "02:00:5e:00:00:01"
        "#;
        let original: FileConfig = toml::from_str(toml).unwrap();
        let back = file_config_from_proto(&file_config_to_proto(&original, 9));

        // Destructured by reference so `back` stays whole for the resolve below;
        // the `..`-free pattern is what makes a new field a compile error.
        let Some(Srv6Cfg {
            local_src,
            underlay_iface,
            local_mac,
            underlay_mtu,
            peers,
        }) = back.srv6.as_ref()
        else {
            panic!("the endpoint must survive the wire");
        };
        assert_eq!(local_src, "fc00:0:1::1");
        assert_eq!(underlay_iface, "eth0");
        assert_eq!(local_mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(*underlay_mtu, Some(9000));
        assert_eq!(peers, &["fc00:0:2::1", "fc00:0:3::1"]);

        assert_eq!(back.srv6_routes.len(), 1);
        let Srv6RouteCfg {
            vni,
            mac,
            remote_sid,
            via_mac,
            out_iface,
        } = &back.srv6_routes[0];
        assert_eq!((*vni, mac.as_str()), (10100, "02:00:5e:00:00:11"));
        assert_eq!(remote_sid, "fc00:0:2:0:2774::");
        assert_eq!(
            (via_mac.as_str(), out_iface.as_str()),
            ("02:00:00:00:00:02", "eth0")
        );

        // Both behaviours make the trip. `end.dt2m` matters twice over: it is the
        // flood SID, and the datapath refused to decapsulate it at all until the
        // flood set existed.
        assert_eq!(back.srv6_local_sids.len(), 2);
        let behaviors: Vec<_> = back
            .srv6_local_sids
            .iter()
            .map(|ls| {
                let Srv6LocalSidCfg { sid, vni, behavior } = ls;
                assert_eq!(*vni, 10100);
                assert!(sid.starts_with("fc00:0:1:"));
                behavior.clone()
            })
            .collect();
        assert_eq!(
            behaviors,
            [Some("end.dt2u".to_string()), Some("end.dt2m".to_string())]
        );

        assert_eq!(back.srv6_floods.len(), 1);
        let Srv6FloodCfg {
            vni,
            remote_sid,
            via_mac,
            out_iface,
        } = &back.srv6_floods[0];
        assert_eq!(*vni, 10100);
        // The flood row must carry the End.DT2M SID, distinct from the unicast one
        // in srv6_routes above — swapping the two bridges every BUM frame to one
        // MAC instead of flooding it.
        assert_eq!(remote_sid, "fc00:0:2:1:2774::");
        assert_eq!(
            (via_mac.as_str(), out_iface.as_str()),
            ("02:00:00:00:00:02", "eth0")
        );

        assert_eq!(back.srv6_irb_routes.len(), 1);
        let Srv6IrbRouteCfg {
            vni,
            inner_dst,
            l3_vni,
            remote_sid,
            via_mac,
            out_iface,
            router_mac,
            gateway_mac,
        } = &back.srv6_irb_routes[0];
        assert_eq!((*vni, *l3_vni), (10100, 50100));
        assert_eq!(inner_dst, "10.20.0.0/24");
        assert_eq!(remote_sid, "fc00:0:2:0:c3b4::");
        assert_eq!(via_mac, "02:00:00:00:00:02");
        assert_eq!(out_iface, "eth0");
        assert_eq!(
            (router_mac.as_str(), gateway_mac.as_str()),
            ("02:aa:bb:cc:dd:ee", "02:00:5e:00:00:01")
        );

        // And the whole thing still resolves — the wire form is not merely
        // preserved, it is usable.
        let rt = back
            .resolve()
            .expect("a round-tripped SRv6 config must resolve");
        assert_eq!(rt.srv6_floods.len(), 1);
        assert_eq!(rt.srv6_irb_routes.len(), 1);
        assert_eq!(rt.srv6_local_sids.len(), 2);
    }
}
