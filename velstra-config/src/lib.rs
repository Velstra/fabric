//! Velstra's declarative configuration, shared by the agent and the controller.
//!
//! This crate owns the TOML schema ([`FileConfig`]), its validation/resolution
//! into the concrete BPF-map contents ([`RuntimeConfig`]), and the conversion to
//! and from the gRPC wire format ([`velstra_proto::NodeConfig`]). Pulling it out
//! of the agent binary lets the controller load and serve the *same* config
//! format without duplicating the schema or the validation rules.

mod config;
mod proto_convert;

pub use config::{
    ActionName, BackendCfg, EncapName, FileConfig, FloodVtepCfg, ForwardMode, InterfaceFile,
    MacRouteCfg, Nd6Cfg, NeighborCfg, Npt66Cfg, OverlayCfg, PolicyConfig, PolicyFile,
    PortForwardCfg, PortRule, ProtoName, ResolvedFloodVtep, ResolvedInterface, ResolvedMacRoute,
    ResolvedNd6, ResolvedNeighbor, ResolvedNpt66, ResolvedOverlay, ResolvedPortForward,
    ResolvedRoute, ResolvedService, ResolvedSrv6, ResolvedSrv6Route, ResolvedTunnel, RouteCfg,
    RuntimeConfig, ServiceCfg, Srv6Cfg, Srv6RouteCfg, TunnelCfg, load_file,
};
pub use proto_convert::{file_config_from_proto, file_config_to_proto, runtime_from_proto};
