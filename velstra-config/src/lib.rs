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
    ActionName, BackendCfg, EncapName, FileConfig, ForwardMode, InterfaceFile, MacRouteCfg, Nd6Cfg,
    NeighborCfg, OverlayCfg, PolicyConfig, PolicyFile, PortForwardCfg, PortRule, ProtoName,
    ResolvedInterface, ResolvedMacRoute, ResolvedNd6, ResolvedNeighbor, ResolvedOverlay,
    ResolvedPortForward, ResolvedRoute, ResolvedService, ResolvedTunnel, RouteCfg, RuntimeConfig,
    ServiceCfg, TunnelCfg, load_file,
};
pub use proto_convert::{file_config_from_proto, file_config_to_proto, runtime_from_proto};
