//! # Velstra controller
//!
//! A gRPC control plane for a fleet of Velstra data planes. It serves each node
//! its desired policy and pushes live updates. Config comes from two layered
//! sources:
//!
//! * **files** — one `<node_id>.toml` per node in `--config-dir`, rescanned
//!   periodically (the declarative, version-controllable baseline), and
//! * **admin overrides** — config pushed at runtime over the admin API, which
//!   takes precedence over a node's file until deleted.
//!
//! The agent-facing channel (`--listen`) can require **mTLS**; the admin channel
//! (`--admin-listen`) binds to localhost by default.
//!
//! ```text
//! velstra-controller serve --config-dir /etc/velstra/nodes \
//!     --tls-cert server.pem --tls-key server.key --client-ca ca.pem
//! velstra-controller admin set    --node web-1 --file web-1.toml
//! velstra-controller admin delete --node web-1
//! velstra-controller admin list
//! ```
//!
//! `result_large_err` is allowed: the gRPC handlers return `tonic::Status`,
//! which is a large error enum by design.
#![allow(clippy::result_large_err)]

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use log::{info, warn};
use tokio::sync::{RwLock, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{
    Request, Response, Status,
    transport::{
        Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
    },
};
use velstra_config::{
    ActionName, EncapName, FileConfig, PortRule as ConfigPortRule, ProtoName, file_config_to_proto,
};
use velstra_orchestrator::Topology;
use velstra_proto::{
    Ack, Action, BindPortSecurityGroupRequest, CreatePortRequest, Encap, HostSpec,
    ListNodesRequest, ListNodesResponse, ListPortsRequest, ListPortsResponse,
    ListSecurityGroupsRequest, ListSecurityGroupsResponse, MigratePortRequest, NetworkSpec,
    NodeConfig, NodeRequest, NodeSummary, PortInfo, PortRule, Proto, RemoveHostRequest,
    RemoveNetworkRequest, RemovePortRequest, RemoveSecurityGroupRequest, SecurityGroupInfo,
    SecurityGroupSpec, SetConfigRequest, StatsReport,
    velstra_admin_client::VelstraAdminClient,
    velstra_admin_server::{VelstraAdmin, VelstraAdminServer},
    velstra_control_server::{VelstraControl, VelstraControlServer},
    velstra_orchestrator_client::VelstraOrchestratorClient,
    velstra_orchestrator_server::{VelstraOrchestrator, VelstraOrchestratorServer},
};

mod authz;
mod evpn;
mod topology;

use authz::{Authz, caller_of};
use evpn::EvpnLearned;

/// A `permission_denied` status for a caller not authorized for `what`.
fn deny(what: &str) -> Status {
    Status::permission_denied(format!("not authorized to {what}"))
}

/// Velstra controller — serve config to a fleet, or administer it.
#[derive(Debug, Parser)]
#[command(name = "velstra-controller", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the controller server.
    Serve(ServeArgs),
    /// Administer a running controller over its admin API.
    Admin(AdminArgs),
    /// Orchestrate the fabric (hosts/networks/ports) over the admin API.
    Orch(OrchArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Agent-facing address (the fleet connects here).
    #[arg(long, default_value = "0.0.0.0:50051")]
    listen: String,

    /// Admin-facing address. Defaults to localhost so admin is local-only.
    #[arg(long, default_value = "127.0.0.1:50052")]
    admin_listen: String,

    /// Directory of per-node `<node_id>.toml` config files. Optional if a
    /// `--topology` is given.
    #[arg(long)]
    config_dir: Option<PathBuf>,

    /// Declarative fabric topology file (`[[host]]`/`[[network]]`/`[[port]]`).
    /// The orchestrator derives each host's config from it (Track C).
    #[arg(long)]
    topology: Option<PathBuf>,

    /// Seconds between rescans of the config directory / topology file.
    #[arg(long, default_value_t = 2)]
    poll_interval: u64,

    /// PEM server certificate for the agent **and** admin/orchestrator channels
    /// (enables TLS on both).
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM server private key for the agent and admin channels.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// PEM CA used to verify client certificates on both channels (enables mTLS).
    #[arg(long, requires = "tls_cert")]
    client_ca: Option<PathBuf>,

    /// Certificate CN allowed to perform ANY fabric write on the admin/
    /// orchestrator channel (operators / CI), repeatable. With mTLS enabled
    /// (`--client-ca`) authorization is enforced: an admin CN may write any
    /// host, any other client may only mutate the host whose id equals its own
    /// CN, and fleet-wide writes (networks, port migration) are admin-only.
    #[arg(long = "admin-cn")]
    admin_cn: Vec<String>,

    // --- Cluster mode (Track D, embedded Raft) ------------------------------
    /// This controller's Raft node id. Presence enables **cluster mode**: the
    /// fabric is replicated across controllers and the file/`--topology`
    /// persistence is superseded by Raft.
    #[arg(long)]
    node_id: Option<u64>,

    /// Address this controller's Raft peer service listens on (cluster mode).
    #[arg(long, default_value = "0.0.0.0:50053", requires = "node_id")]
    raft_listen: String,

    /// Cluster members as `id=host:port` (repeatable), including this node.
    /// Used with `--bootstrap` to form the cluster.
    #[arg(long = "peer", requires = "node_id")]
    peers: Vec<String>,

    /// Initialise the cluster from this node using `--peer` (run once, on one
    /// node). Other nodes just start and wait to be contacted.
    #[arg(long, requires = "node_id")]
    bootstrap: bool,

    /// Directory for persisted Raft snapshots (cluster mode). With it, the node
    /// survives a full restart by reloading the committed fabric; without it,
    /// state is in-memory only and a node comes up empty (re-replicating from a
    /// surviving peer, or losing the fabric on a full-cluster restart).
    #[arg(long, requires = "node_id")]
    raft_dir: Option<PathBuf>,

    /// Server-name to validate against a peer's certificate when dialing the
    /// Raft peer transport over TLS (cluster mode). Needed when peers are
    /// addressed by IP but the shared server cert only carries a DNS SAN.
    #[arg(long, requires = "node_id")]
    raft_tls_domain: Option<String>,

    /// Path to a Wren routing-daemon control socket to subscribe to for EVPN
    /// updates (roadmap B4a). When set, the controller runs a background task
    /// that folds EVPN-learned type-2 MAC/IP routes into every host's derived
    /// config. Unset ⇒ the feature is entirely inert.
    #[arg(long)]
    wren_socket: Option<PathBuf>,
}

/// Client TLS options for the admin/orchestrator CLIs (use an `https://`
/// endpoint when a CA is given).
#[derive(Debug, Args)]
struct ClientTls {
    /// PEM CA certificate to verify the controller (enables TLS).
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    /// Client certificate for mutual TLS.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Client private key for mutual TLS.
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Server name to validate against the controller's certificate.
    #[arg(long)]
    tls_domain: Option<String>,
}

#[derive(Debug, Args)]
struct AdminArgs {
    /// Admin endpoint of the running controller.
    #[arg(long, default_value = "http://127.0.0.1:50052")]
    endpoint: String,

    #[command(flatten)]
    tls: ClientTls,

    #[command(subcommand)]
    action: AdminAction,
}

#[derive(Debug, Args)]
struct OrchArgs {
    /// Admin endpoint of the running controller.
    #[arg(long, default_value = "http://127.0.0.1:50052")]
    endpoint: String,

    #[command(flatten)]
    tls: ClientTls,

    #[command(subcommand)]
    action: OrchAction,
}

#[derive(Debug, Subcommand)]
enum OrchAction {
    /// Register a host (VTEP).
    AddHost {
        #[arg(long)]
        id: String,
        #[arg(long)]
        vtep: String,
        #[arg(long)]
        iface: String,
        #[arg(long)]
        mac: String,
        /// `vxlan` (default) or `geneve`.
        #[arg(long, default_value = "vxlan")]
        encap: String,
    },
    /// Define a network (tenant).
    AddNetwork {
        #[arg(long)]
        vni: u32,
        #[arg(long)]
        name: String,
        #[arg(long)]
        subnet: String,
        /// Drop ICMP in this network's policy. Takes an explicit value
        /// (`--drop-icmp true` / `--drop-icmp false`); defaults to false.
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        drop_icmp: bool,
    },
    /// Create a port (VM NIC); IP/MAC auto-allocated if `--ip` is omitted.
    CreatePort {
        #[arg(long)]
        network: u32,
        #[arg(long)]
        host: String,
        #[arg(long)]
        tap: String,
        #[arg(long)]
        ip: Option<String>,
        /// Security-group policy id (M4); omitted ⇒ defaults to the network VNI.
        #[arg(long)]
        policy: Option<u32>,
    },
    /// Remove a port by id.
    RemovePort {
        #[arg(long)]
        id: String,
    },
    /// Move a port to another host, keeping its IP/MAC (live migration).
    MigratePort {
        #[arg(long)]
        id: String,
        #[arg(long)]
        host: String,
        #[arg(long)]
        tap: String,
    },
    /// List all ports in the fabric.
    ListPorts,
    /// Register a named security group (B5). Rules are given as repeated
    /// `--allow proto:port` / `--deny proto:port` (e.g. `--allow tcp:80`).
    AddSecurityGroup {
        #[arg(long)]
        name: String,
        /// Default action for unmatched traffic: `pass` (default) or `drop`.
        #[arg(long, default_value = "pass")]
        default_action: String,
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        drop_icmp: bool,
        #[arg(long, action = clap::ArgAction::Set, default_value_t = false)]
        stateful: bool,
        /// Allow a `proto:port` (e.g. `tcp:80`), repeatable.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Deny a `proto:port` (e.g. `tcp:22`), repeatable.
        #[arg(long = "deny")]
        deny: Vec<String>,
        /// Source CIDR to blocklist, repeatable.
        #[arg(long = "block")]
        block: Vec<String>,
    },
    /// Remove a security group by name.
    RemoveSecurityGroup {
        #[arg(long)]
        name: String,
    },
    /// List all security groups in the fabric.
    ListSecurityGroups,
    /// Bind a port to a security group (`--group`), or clear it (`--clear`).
    BindPort {
        #[arg(long)]
        port: String,
        #[arg(long)]
        group: Option<String>,
        /// Clear the binding (revert to the VNI default); overrides `--group`.
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Debug, Subcommand)]
enum AdminAction {
    /// Push a node's config from a TOML file (overrides its file).
    Set {
        #[arg(long)]
        node: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Remove a runtime override, reverting the node to its file.
    Delete {
        #[arg(long)]
        node: String,
    },
    /// List the nodes the controller serves.
    List,
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// The controller's config sources. `served` is the merged, versioned result the
/// gRPC handlers read; `files`, `derived`, and `overrides` are the (version-less)
/// inputs, in increasing precedence. `derived` is computed by the orchestrator
/// from the declarative topology (Track C).
#[derive(Default)]
struct State {
    files: HashMap<String, NodeConfig>,
    derived: HashMap<String, NodeConfig>,
    overrides: HashMap<String, NodeConfig>,
    served: HashMap<String, NodeConfig>,
}

struct Shared {
    state: RwLock<State>,
    /// The live fabric model in **single-controller mode** (Track C). Seeded from
    /// `--topology` and mutated by the orchestration API. In **cluster mode** the
    /// fabric lives in the Raft state machine (`raft`) instead and this is unused.
    topology: RwLock<Topology>,
    /// Where to persist the topology after each mutation (single-controller mode).
    /// `None` in cluster mode — Raft snapshots are the durability there.
    topology_path: Option<PathBuf>,
    /// The embedded Raft node in **cluster mode** (Track D); `None` for a single
    /// controller. When set, the fabric is replicated: the leader serves writes,
    /// followers redirect, and `state.derived` is recomputed on every Raft apply.
    raft: Option<Arc<velstra_raft::RaftNode>>,
    /// EVPN state learned from a Wren `monitor evpn` feed (roadmap B4a). Folded
    /// into `state.derived` by `re_derive`. Empty (and unused) unless
    /// `--wren-socket` is set.
    evpn_learned: RwLock<EvpnLearned>,
    generation: AtomicU64,
    notify: watch::Sender<u64>,
}

impl Shared {
    fn new(topology_path: Option<PathBuf>, raft: Option<Arc<velstra_raft::RaftNode>>) -> Self {
        Self {
            state: RwLock::new(State::default()),
            topology: RwLock::new(Topology::new()),
            // In cluster mode the Raft state machine owns durability, not a file.
            topology_path: if raft.is_some() { None } else { topology_path },
            raft,
            evpn_learned: RwLock::new(EvpnLearned::default()),
            generation: AtomicU64::new(0),
            notify: watch::channel(0).0,
        }
    }

    fn next_generation(&self) -> u64 {
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Recompute `served` from `overrides` layered over `files`, assigning a new
    /// version to anything that changed, and wake watchers. Caller holds the
    /// write lock.
    fn recompute(&self, state: &mut State) {
        let nodes: HashSet<String> = state
            .files
            .keys()
            .chain(state.derived.keys())
            .chain(state.overrides.keys())
            .cloned()
            .collect();

        let mut changed = false;
        for node in &nodes {
            // Precedence: a runtime admin override beats the orchestrator's
            // derived config, which beats a static per-node file.
            let desired = state
                .overrides
                .get(node)
                .or_else(|| state.derived.get(node))
                .or_else(|| state.files.get(node))
                .cloned()
                .expect("node came from files, derived, or overrides");
            let differs = state
                .served
                .get(node)
                .is_none_or(|cur| !same_except_version(cur, &desired));
            if differs {
                let mut desired = desired;
                desired.version = self.next_generation();
                info!("node {node:?}: now serving v{}", desired.version);
                state.served.insert(node.clone(), desired);
                changed = true;
            }
        }

        // A node with neither a file nor an override reverts to the default.
        let stale: Vec<String> = state
            .served
            .keys()
            .filter(|n| !nodes.contains(*n))
            .cloned()
            .collect();
        for node in stale {
            let version = self.next_generation();
            info!("node {node:?}: reverted to default (v{version})");
            state.served.insert(
                node,
                NodeConfig {
                    version,
                    ..Default::default()
                },
            );
            changed = true;
        }

        if changed {
            let _ = self.notify.send(self.generation.load(Ordering::SeqCst));
        }
    }
}

/// Re-derive every host's config from the live topology and, if anything
/// changed, swap it into `state.derived` and recompute. In single-controller mode
/// it reads (and persists) the local model; in cluster mode it reads the Raft
/// state machine's applied topology (called from the Raft apply-notification task).
async fn re_derive(shared: &Shared) -> Result<()> {
    // Fold in any EVPN-learned routes (empty/None-equivalent when the feature is
    // off, so the derived output is unchanged in that case).
    let evpn = shared.evpn_learned.read().await;
    let derived = if let Some(raft) = &shared.raft {
        // Cluster mode: derive from the replicated, committed topology.
        let topo = raft.topology().await;
        topology::derive_configs(&topo, Some(&evpn))?
    } else {
        let topo = shared.topology.read().await;
        let derived = topology::derive_configs(&topo, Some(&evpn))?;
        // Single-controller mode: persist the mutated model atomically.
        if let Some(path) = &shared.topology_path {
            topology::save_model(&topo, path).context("persisting topology")?;
        }
        derived
    };
    drop(evpn);
    let mut state = shared.state.write().await;
    if state.derived != derived {
        state.derived = derived;
        shared.recompute(&mut state);
    }
    Ok(())
}

/// Two configs are equal apart from their `version` stamp.
fn same_except_version(a: &NodeConfig, b: &NodeConfig) -> bool {
    let (mut a, mut b) = (a.clone(), b.clone());
    a.version = 0;
    b.version = 0;
    a == b
}

/// Load every `<node>.toml` in `dir` into version-less `NodeConfig`s.
fn load_dir(dir: &Path) -> Result<HashMap<String, NodeConfig>> {
    let mut out = HashMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let Some(node_id) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        match load_node_file(&path) {
            Ok(cfg) => {
                out.insert(node_id.to_string(), cfg);
            }
            Err(e) => warn!("ignoring {}: {e}", path.display()),
        }
    }
    Ok(out)
}

/// Read and validate one node TOML file into a version-less `NodeConfig`.
fn load_node_file(path: &Path) -> Result<NodeConfig> {
    let text = std::fs::read_to_string(path).context("reading file")?;
    let file: FileConfig = toml::from_str(&text).context("parse error")?;
    file.resolve().context("invalid config")?; // validate before serving
    Ok(file_config_to_proto(&file, 0))
}

/// Background task: rescan the per-node config directory and recompute on change.
/// (The topology is seeded once at startup and then owned by the orchestration
/// API, so it is not polled from disk here.)
async fn poll_loop(shared: Arc<Shared>, dir: PathBuf, interval: Duration) {
    loop {
        tokio::time::sleep(interval).await;
        match load_dir(&dir) {
            Ok(files) => {
                let mut state = shared.state.write().await;
                if state.files != files {
                    state.files = files;
                    shared.recompute(&mut state);
                }
            }
            Err(e) => warn!("config reload failed: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Agent-facing service
// ---------------------------------------------------------------------------

struct ControlSvc {
    shared: Arc<Shared>,
}

#[tonic::async_trait]
impl VelstraControl for ControlSvc {
    async fn get_config(
        &self,
        request: Request<NodeRequest>,
    ) -> Result<Response<NodeConfig>, Status> {
        let node = request.into_inner().node_id;
        let cfg = self.shared.state.read().await.served.get(&node).cloned();
        info!(
            "GetConfig({node:?}) -> {}",
            if cfg.is_some() { "config" } else { "default" }
        );
        Ok(Response::new(cfg.unwrap_or_default()))
    }

    type WatchConfigStream = ReceiverStream<Result<NodeConfig, Status>>;

    async fn watch_config(
        &self,
        request: Request<NodeRequest>,
    ) -> Result<Response<Self::WatchConfigStream>, Status> {
        let node = request.into_inner().node_id;
        info!("WatchConfig({node:?}) subscribed");
        let shared = self.shared.clone();
        let mut notify = shared.notify.subscribe();
        let (tx, rx) = mpsc::channel(8);

        tokio::spawn(async move {
            let mut last_sent = u64::MAX;
            loop {
                let cfg = shared
                    .state
                    .read()
                    .await
                    .served
                    .get(&node)
                    .cloned()
                    .unwrap_or_default();
                if cfg.version != last_sent {
                    last_sent = cfg.version;
                    if tx.send(Ok(cfg)).await.is_err() {
                        break; // agent disconnected
                    }
                }
                if notify.changed().await.is_err() {
                    break; // controller shutting down
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_stats(&self, request: Request<StatsReport>) -> Result<Response<Ack>, Status> {
        let report = request.into_inner();
        let active: Vec<String> = report
            .counters
            .iter()
            .filter(|c| c.value > 0)
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        info!("stats from {:?}: {}", report.node_id, active.join(" "));
        Ok(Response::new(Ack { ok: true }))
    }
}

// ---------------------------------------------------------------------------
// Admin service
// ---------------------------------------------------------------------------

struct AdminSvc {
    shared: Arc<Shared>,
    authz: Authz,
}

#[tonic::async_trait]
impl VelstraAdmin for AdminSvc {
    async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        let req = request.into_inner();
        // A per-node config override is a write scoped to that node.
        if !self.authz.allow_host(&caller, &req.node_id) {
            return Err(deny(&format!("set config for node {:?}", req.node_id)));
        }
        let Some(config) = req.config else {
            return Err(Status::invalid_argument("missing config"));
        };
        // Validate the pushed config the same way a file is validated.
        if let Err(e) = velstra_config::runtime_from_proto(&config) {
            return Err(Status::invalid_argument(format!("invalid config: {e}")));
        }
        info!("admin SetConfig({:?})", req.node_id);
        let mut state = self.shared.state.write().await;
        state.overrides.insert(req.node_id, config);
        self.shared.recompute(&mut state);
        Ok(Response::new(Ack { ok: true }))
    }

    async fn delete_config(&self, request: Request<NodeRequest>) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        let node = request.into_inner().node_id;
        if !self.authz.allow_host(&caller, &node) {
            return Err(deny(&format!("delete config for node {node:?}")));
        }
        info!("admin DeleteConfig({node:?})");
        let mut state = self.shared.state.write().await;
        let existed = state.overrides.remove(&node).is_some();
        if existed {
            self.shared.recompute(&mut state);
        }
        Ok(Response::new(Ack { ok: existed }))
    }

    async fn list_nodes(
        &self,
        _request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        let state = self.shared.state.read().await;
        let nodes = state
            .served
            .iter()
            .map(|(node_id, cfg)| {
                let source = if state.overrides.contains_key(node_id) {
                    "admin"
                } else if state.derived.contains_key(node_id) {
                    "derived"
                } else if state.files.contains_key(node_id) {
                    "file"
                } else {
                    "default"
                };
                NodeSummary {
                    node_id: node_id.clone(),
                    version: cfg.version,
                    from_admin: state.overrides.contains_key(node_id),
                    source: source.to_string(),
                }
            })
            .collect();
        Ok(Response::new(ListNodesResponse { nodes }))
    }
}

// ---------------------------------------------------------------------------
// Orchestration service (Track C)
// ---------------------------------------------------------------------------

struct OrchestratorSvc {
    shared: Arc<Shared>,
    authz: Authz,
}

fn fmt_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

// Convert the gRPC orchestration specs into the replicated [`velstra_raft`]
// request form. Strings/enums only — validation happens when the request is
// applied to the topology (on every replica), so it is deterministic.
fn raft_host_spec(s: HostSpec) -> velstra_raft::HostSpec {
    velstra_raft::HostSpec {
        id: s.id.clone(),
        vtep: s.vtep.clone(),
        underlay_iface: s.underlay_iface.clone(),
        underlay_mac: s.underlay_mac.clone(),
        encap: match s.encap() {
            Encap::Geneve => EncapName::Geneve,
            Encap::Vxlan => EncapName::Vxlan,
        },
        udp_port: (s.udp_port != 0).then_some(s.udp_port as u16),
        underlay_mtu: (s.underlay_mtu != 0).then_some(s.underlay_mtu as u16),
    }
}

fn raft_network_spec(s: NetworkSpec) -> velstra_raft::NetworkSpec {
    velstra_raft::NetworkSpec {
        vni: s.vni,
        name: s.name.clone(),
        subnet: s.subnet.clone(),
        default_action: match s.default_action() {
            Action::Drop => ActionName::Drop,
            Action::Pass => ActionName::Pass,
        },
        drop_icmp: s.drop_icmp,
    }
}

fn action_from_proto(a: Action) -> ActionName {
    match a {
        Action::Drop => ActionName::Drop,
        Action::Pass => ActionName::Pass,
    }
}

// The proto Action enum has no Reject variant, so a config Reject narrows to
// Drop on the wire — mirroring `velstra_config::proto_convert`.
fn action_to_proto(a: ActionName) -> Action {
    match a {
        ActionName::Pass => Action::Pass,
        ActionName::Drop | ActionName::Reject => Action::Drop,
    }
}

fn proto_from_proto(p: Proto) -> ProtoName {
    match p {
        Proto::Tcp => ProtoName::Tcp,
        Proto::Udp => ProtoName::Udp,
        Proto::Icmp => ProtoName::Icmp,
    }
}

fn proto_to_proto(p: ProtoName) -> Proto {
    match p {
        ProtoName::Tcp => Proto::Tcp,
        ProtoName::Udp => Proto::Udp,
        ProtoName::Icmp => Proto::Icmp,
    }
}

fn config_rule_from_proto(r: &PortRule) -> ConfigPortRule {
    ConfigPortRule {
        proto: proto_from_proto(r.proto()),
        port: r.port as u16,
        action: action_from_proto(r.action()),
        log: r.log,
        src: (!r.src.is_empty()).then(|| r.src.clone()),
    }
}

fn proto_rule_from_config(r: &ConfigPortRule) -> PortRule {
    PortRule {
        proto: proto_to_proto(r.proto) as i32,
        port: r.port as u32,
        action: action_to_proto(r.action) as i32,
        log: r.log,
        src: r.src.clone().unwrap_or_default(),
    }
}

// Convert a gRPC security-group spec into the replicated raft form (validation
// happens when applied to the topology, on every replica). Mirrors
// `raft_network_spec`.
fn raft_security_group_spec(s: SecurityGroupSpec) -> velstra_raft::SecurityGroupSpec {
    velstra_raft::SecurityGroupSpec {
        name: s.name.clone(),
        default_action: action_from_proto(s.default_action()),
        drop_icmp: s.drop_icmp,
        stateful: s.stateful,
        blocklist: s.blocklist.clone(),
        rules: s.rules.iter().map(config_rule_from_proto).collect(),
    }
}

fn sg_to_info(g: &velstra_orchestrator::SecurityGroup) -> SecurityGroupInfo {
    SecurityGroupInfo {
        name: g.name.clone(),
        policy_id: g.policy_id(),
        default_action: action_to_proto(g.default_action) as i32,
        drop_icmp: g.drop_icmp,
        stateful: g.stateful,
        blocklist: g.blocklist.clone(),
        rules: g.rules.iter().map(proto_rule_from_config).collect(),
    }
}

fn port_record_to_info(p: velstra_raft::PortRecord) -> PortInfo {
    PortInfo {
        id: p.id,
        vni: p.vni,
        host: p.host,
        ip: p.ip,
        mac: p.mac,
        tap: p.tap,
    }
}

/// Apply a fabric mutation, in whichever mode the controller runs:
/// - **cluster mode**: propose through Raft (leader only; a follower returns a
///   redirect to the current leader). The Raft apply-notification task re-derives.
/// - **single-controller mode**: apply to the local model and re-derive inline.
async fn propose(
    shared: &Shared,
    req: velstra_raft::TopoRequest,
) -> Result<velstra_raft::TopoResponse, Status> {
    if let Some(raft) = &shared.raft {
        if !raft.is_leader() {
            return Err(Status::failed_precondition(format!(
                "not the leader; current leader is node {:?} — send writes there",
                raft.current_leader()
            )));
        }
        raft.propose(req)
            .await
            .map_err(|e| Status::internal(e.to_string()))
    } else {
        let resp = {
            let mut topo = shared.topology.write().await;
            velstra_raft::apply(&mut topo, &req)
        };
        re_derive(shared)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(resp)
    }
}

fn port_to_info(p: &velstra_orchestrator::Port) -> PortInfo {
    PortInfo {
        id: p.id.clone(),
        vni: p.vni,
        host: p.host.clone(),
        ip: p.ip.to_string(),
        mac: fmt_mac(p.mac),
        tap: p.tap.clone(),
    }
}

#[tonic::async_trait]
impl VelstraOrchestrator for OrchestratorSvc {
    async fn add_host(&self, request: Request<HostSpec>) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        let spec = request.into_inner();
        // Registering/updating a host is a write scoped to that host id — this
        // is the VTEP-impersonation vector (idempotent AddHost), so a node may
        // only (re)register itself.
        if !self.authz.allow_host(&caller, &spec.id) {
            return Err(deny(&format!("add/update host {:?}", spec.id)));
        }
        info!("AddHost({:?})", spec.id);
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::AddHost(raft_host_spec(spec)),
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn add_network(&self, request: Request<NetworkSpec>) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        if !self.authz.allow_admin(&caller) {
            return Err(deny("define networks (admin only)"));
        }
        let spec = request.into_inner();
        info!("AddNetwork(vni {} {:?})", spec.vni, spec.name);
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::AddNetwork(raft_network_spec(spec)),
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn create_port(
        &self,
        request: Request<CreatePortRequest>,
    ) -> Result<Response<PortInfo>, Status> {
        let caller = caller_of(&request);
        let req = request.into_inner();
        // Creating a port lands a tap on a specific host — a node may only place
        // ports on itself.
        if !self.authz.allow_host(&caller, &req.host) {
            return Err(deny(&format!("create ports on host {:?}", req.host)));
        }
        info!("CreatePort(vni {} on {:?})", req.network, req.host);
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::CreatePort {
                vni: req.network,
                host: req.host,
                tap: req.tap,
                ip: (!req.ip.is_empty()).then_some(req.ip),
                policy: req.policy,
            },
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        let port = resp
            .port
            .ok_or_else(|| Status::internal("create_port returned no port"))?;
        Ok(Response::new(port_record_to_info(port)))
    }

    async fn remove_port(
        &self,
        request: Request<RemovePortRequest>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        let id = request.into_inner().id;
        // A port id doesn't name its owning host here, so removing one is
        // admin-only rather than node-scoped.
        if !self.authz.allow_admin(&caller) {
            return Err(deny("remove ports (admin only)"));
        }
        info!("RemovePort({id:?})");
        let resp = propose(&self.shared, velstra_raft::TopoRequest::RemovePort { id }).await?;
        Ok(Response::new(Ack { ok: resp.ok }))
    }

    async fn migrate_port(
        &self,
        request: Request<MigratePortRequest>,
    ) -> Result<Response<PortInfo>, Status> {
        let caller = caller_of(&request);
        // Migration moves a port between hosts (two owners), so it is admin-only.
        if !self.authz.allow_admin(&caller) {
            return Err(deny("migrate ports (admin only)"));
        }
        let req = request.into_inner();
        info!("MigratePort({:?} -> {:?})", req.id, req.host);
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::MigratePort {
                id: req.id,
                host: req.host,
                tap: req.tap,
            },
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        let port = resp
            .port
            .ok_or_else(|| Status::internal("migrate_port returned no port"))?;
        Ok(Response::new(port_record_to_info(port)))
    }

    async fn list_ports(
        &self,
        _request: Request<ListPortsRequest>,
    ) -> Result<Response<ListPortsResponse>, Status> {
        // Read from the Raft state machine in cluster mode, else the local model.
        let ports = if let Some(raft) = &self.shared.raft {
            raft.topology()
                .await
                .ports()
                .iter()
                .map(port_to_info)
                .collect()
        } else {
            self.shared
                .topology
                .read()
                .await
                .ports()
                .iter()
                .map(port_to_info)
                .collect()
        };
        Ok(Response::new(ListPortsResponse { ports }))
    }

    async fn remove_host(
        &self,
        request: Request<RemoveHostRequest>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        let id = request.into_inner().id;
        if !self.authz.allow_host(&caller, &id) {
            return Err(deny(&format!("remove host {id:?}")));
        }
        info!("RemoveHost({id:?})");
        let resp = propose(&self.shared, velstra_raft::TopoRequest::RemoveHost { id }).await?;
        if !resp.ok {
            return Err(Status::failed_precondition(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn remove_network(
        &self,
        request: Request<RemoveNetworkRequest>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        if !self.authz.allow_admin(&caller) {
            return Err(deny("remove networks (admin only)"));
        }
        let vni = request.into_inner().vni;
        info!("RemoveNetwork({vni})");
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::RemoveNetwork { vni },
        )
        .await?;
        if !resp.ok {
            return Err(Status::failed_precondition(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn add_security_group(
        &self,
        request: Request<SecurityGroupSpec>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        if !self.authz.allow_admin(&caller) {
            return Err(deny("define security groups (admin only)"));
        }
        let spec = request.into_inner();
        info!("AddSecurityGroup({:?})", spec.name);
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::AddSecurityGroup(raft_security_group_spec(spec)),
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn remove_security_group(
        &self,
        request: Request<RemoveSecurityGroupRequest>,
    ) -> Result<Response<Ack>, Status> {
        let caller = caller_of(&request);
        if !self.authz.allow_admin(&caller) {
            return Err(deny("remove security groups (admin only)"));
        }
        let name = request.into_inner().name;
        info!("RemoveSecurityGroup({name:?})");
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::RemoveSecurityGroup { name },
        )
        .await?;
        if !resp.ok {
            return Err(Status::failed_precondition(resp.error.unwrap_or_default()));
        }
        Ok(Response::new(Ack { ok: true }))
    }

    async fn bind_port_security_group(
        &self,
        request: Request<BindPortSecurityGroupRequest>,
    ) -> Result<Response<PortInfo>, Status> {
        let caller = caller_of(&request);
        // A port id doesn't name its owning host here, so binding is admin-only
        // (same rationale as RemovePort).
        if !self.authz.allow_admin(&caller) {
            return Err(deny("bind ports to security groups (admin only)"));
        }
        let req = request.into_inner();
        info!(
            "BindPortSecurityGroup({:?} -> {:?})",
            req.port_id, req.group
        );
        let resp = propose(
            &self.shared,
            velstra_raft::TopoRequest::SetPortSecurityGroup {
                port_id: req.port_id,
                group: req.group,
            },
        )
        .await?;
        if !resp.ok {
            return Err(Status::invalid_argument(resp.error.unwrap_or_default()));
        }
        let port = resp
            .port
            .ok_or_else(|| Status::internal("bind_port_security_group returned no port"))?;
        Ok(Response::new(port_record_to_info(port)))
    }

    async fn list_security_groups(
        &self,
        _request: Request<ListSecurityGroupsRequest>,
    ) -> Result<Response<ListSecurityGroupsResponse>, Status> {
        // Read from the Raft state machine in cluster mode, else the local model.
        let groups = if let Some(raft) = &self.shared.raft {
            raft.topology()
                .await
                .security_groups()
                .map(sg_to_info)
                .collect()
        } else {
            self.shared
                .topology
                .read()
                .await
                .security_groups()
                .map(sg_to_info)
                .collect()
        };
        Ok(Response::new(ListSecurityGroupsResponse { groups }))
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Admin(args) => admin(args).await,
        Command::Orch(args) => orch(args).await,
    }
}

/// Build the agent-channel TLS config from the serve args, if any.
fn server_tls(args: &ServeArgs) -> Result<Option<ServerTlsConfig>> {
    let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    let identity = Identity::from_pem(
        std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?,
        std::fs::read(key).with_context(|| format!("reading {}", key.display()))?,
    );
    let mut tls = ServerTlsConfig::new().identity(identity);
    if let Some(ca) = &args.client_ca {
        let ca = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        tls = tls.client_ca_root(Certificate::from_pem(ca));
        info!("agent channel: mTLS (client certificates required)");
    } else {
        info!("agent channel: TLS (no client-cert verification)");
    }
    Ok(Some(tls))
}

/// Build the client TLS config used to dial Raft peers, from the same cert
/// material as the agent/admin channels. TLS is enabled exactly when a server
/// cert+key are configured (so securing the agent channel secures Raft too);
/// mTLS is added when a `--client-ca` is present (all controllers share that CA
/// in this model, so it doubles as the peer-verification CA). Returns `None`
/// (plaintext, legacy) when no cert is configured — dev / single-node.
fn raft_client_tls(args: &ServeArgs) -> Result<Option<ClientTlsConfig>> {
    let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    let Some(ca) = &args.client_ca else {
        // A server cert with no shared CA can't authenticate peers to each
        // other; require --client-ca to turn on Raft TLS rather than trusting
        // the system roots for internal peers.
        return Ok(None);
    };
    let ca = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
    let identity = Identity::from_pem(
        std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?,
        std::fs::read(key).with_context(|| format!("reading {}", key.display()))?,
    );
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(identity);
    if let Some(domain) = &args.raft_tls_domain {
        tls = tls.domain_name(domain);
    }
    Ok(Some(tls))
}

/// Parse `--peer id=host:port` entries into a member map; default to a
/// single-node cluster of `self_id` at `self_addr` if none are given.
fn parse_peers(peers: &[String], self_id: u64, self_addr: &str) -> Result<BTreeMap<u64, String>> {
    let mut members = BTreeMap::new();
    for p in peers {
        let (id, addr) = p
            .split_once('=')
            .ok_or_else(|| anyhow!("--peer must be id=host:port, got {p:?}"))?;
        let id: u64 = id
            .parse()
            .with_context(|| format!("bad peer id in {p:?}"))?;
        members.insert(id, addr.to_string());
    }
    if members.is_empty() {
        members.insert(self_id, self_addr.to_string());
    }
    Ok(members)
}

async fn serve(args: ServeArgs) -> Result<()> {
    if args.config_dir.is_none() && args.topology.is_none() && args.node_id.is_none() {
        bail!("provide --config-dir, --topology, or --node-id (cluster mode)");
    }

    // Cluster mode: start the embedded Raft node and its peer service.
    let raft = if let Some(id) = args.node_id {
        // Peer transport TLS/mTLS from the same certs as the agent/admin
        // channels — never plaintext when the deployment is secured (C5).
        let client_tls = raft_client_tls(&args)?;
        let server_tls = server_tls(&args)?;
        if client_tls.is_some() {
            info!("raft peer transport: TLS (mTLS between controllers)");
        } else {
            warn!(
                "raft peer transport: PLAINTEXT (no --tls-cert/--client-ca) — secure the network"
            );
        }
        let node = Arc::new(
            velstra_raft::RaftNode::start_with_opts(id, args.raft_dir.clone(), client_tls).await?,
        );
        if let Some(dir) = &args.raft_dir {
            info!("raft snapshots persisted under {}", dir.display());
        }
        let raft_addr = args
            .raft_listen
            .parse()
            .with_context(|| format!("invalid raft address {:?}", args.raft_listen))?;
        let svc = node.service();
        tokio::spawn(async move {
            info!("raft peer service listening on {raft_addr}");
            let mut builder = Server::builder();
            if let Some(tls) = server_tls {
                match builder.tls_config(tls) {
                    Ok(b) => builder = b,
                    Err(e) => {
                        warn!("raft server TLS config failed: {e}");
                        return;
                    }
                }
            }
            if let Err(e) = builder.add_service(svc).serve(raft_addr).await {
                warn!("raft server stopped: {e}");
            }
        });
        info!("cluster mode: node {id}");
        Some(node)
    } else {
        None
    };

    let shared = Arc::new(Shared::new(args.topology.clone(), raft.clone()));

    // Single-controller mode: load the topology file (the persistent store).
    if raft.is_none()
        && let Some(path) = &args.topology
    {
        if path.exists() {
            let model = topology::load_model(path).context("loading topology")?;
            let n = model.ports().len();
            *shared.topology.write().await = model;
            info!("loaded topology from {} ({n} port(s))", path.display());
        } else {
            info!(
                "topology store {} does not exist yet; starting empty",
                path.display()
            );
        }
    }

    // Cluster mode: re-derive on every Raft apply (replicated topology changes).
    if raft.is_some() {
        let shared2 = shared.clone();
        tokio::spawn(async move {
            let mut rx = shared2.raft.as_ref().unwrap().subscribe();
            while rx.changed().await.is_ok() {
                if let Err(e) = re_derive(&shared2).await {
                    warn!("re-derive after raft apply failed: {e}");
                }
            }
        });
    }

    // Synchronous initial load so the first agent gets a real config.
    {
        let mut state = shared.state.write().await;
        if let Some(dir) = &args.config_dir {
            match load_dir(dir) {
                Ok(files) => {
                    info!(
                        "loaded {} node config(s) from {}",
                        files.len(),
                        dir.display()
                    );
                    state.files = files;
                }
                Err(e) => warn!("initial config load failed: {e}"),
            }
        }
        let evpn = shared.evpn_learned.read().await;
        state.derived = if let Some(raft) = &shared.raft {
            topology::derive_configs(&raft.topology().await, Some(&evpn))
                .context("deriving topology")?
        } else {
            let topo = shared.topology.read().await;
            topology::derive_configs(&topo, Some(&evpn)).context("deriving topology")?
        };
        drop(evpn);
        shared.recompute(&mut state);
    }

    // Bootstrap the cluster (run once, on one node). On a restart the cluster is
    // already initialised — bootstrapping again is a harmless no-op, so a failure
    // here is logged and ignored rather than crashing the controller (this is
    // what lets a StatefulSet always pass --bootstrap on ordinal 0).
    if args.bootstrap {
        let raft = raft.as_ref().expect("--bootstrap requires --node-id");
        let members = parse_peers(&args.peers, args.node_id.unwrap(), &args.raft_listen)?;
        info!("bootstrapping cluster with {} member(s)", members.len());
        if let Err(e) = raft.bootstrap(members).await {
            warn!("bootstrap skipped (cluster likely already initialised): {e:#}");
        }
    }

    if let Some(dir) = &args.config_dir {
        tokio::spawn(poll_loop(
            shared.clone(),
            dir.clone(),
            Duration::from_secs(args.poll_interval.max(1)),
        ));
    }

    // EVPN bridge (roadmap B4a): subscribe to a Wren `monitor evpn` feed and
    // fold learned type-2 routes into the derived configs. Opt-in via flag; when
    // unset the controller behaves exactly as before.
    if let Some(socket) = &args.wren_socket {
        tokio::spawn(evpn::run_evpn_monitor(socket.clone(), shared.clone()));
    }

    // Admin + orchestrator server on its own (localhost-by-default) port. It
    // carries fabric-mutating RPCs (AddHost/CreatePort/…), so in a cluster where
    // it is exposed to agents and the CNI it gets the **same** TLS/mTLS as the
    // agent channel — not plaintext.
    let admin_addr = args
        .admin_listen
        .parse()
        .with_context(|| format!("invalid admin address {:?}", args.admin_listen))?;
    let admin_tls = server_tls(&args)?;
    // Authorize writes by client-cert identity when the admin channel enforces
    // mTLS (a --client-ca is set). Without it we can't identify the caller, so
    // the localhost-only default stays open (single-operator, back-compat).
    let authz = if args.client_ca.is_some() {
        info!(
            "admin/orchestrator authorization: ENFORCED ({} admin CN(s); nodes scoped to own host)",
            args.admin_cn.len()
        );
        Authz::new(args.admin_cn.clone(), true)
    } else {
        Authz::disabled()
    };
    let admin_shared = shared.clone();
    tokio::spawn(async move {
        info!("admin/orchestrator API listening on {admin_addr}");
        let mut builder = Server::builder();
        if let Some(tls) = admin_tls {
            match builder.tls_config(tls) {
                Ok(b) => builder = b,
                Err(e) => {
                    warn!("admin TLS config failed: {e}");
                    return;
                }
            }
        }
        if let Err(e) = builder
            .add_service(VelstraAdminServer::new(AdminSvc {
                shared: admin_shared.clone(),
                authz: authz.clone(),
            }))
            .add_service(VelstraOrchestratorServer::new(OrchestratorSvc {
                shared: admin_shared,
                authz,
            }))
            .serve(admin_addr)
            .await
        {
            warn!("admin server stopped: {e}");
        }
    });

    // Agent-facing server (optionally with TLS/mTLS).
    let addr = args
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", args.listen))?;
    let mut builder = Server::builder();
    if let Some(tls) = server_tls(&args)? {
        builder = builder.tls_config(tls).context("configuring TLS")?;
    }
    info!("agent API listening on {addr}");
    builder
        .add_service(VelstraControlServer::new(ControlSvc { shared }))
        .serve_with_shutdown(addr, shutdown_signal())
        .await?;
    info!("shutting down");
    Ok(())
}

/// Complete on the first **SIGINT** (Ctrl-C) or **SIGTERM** so the controller
/// shuts the server down cleanly under a process manager (systemd / k8s), not
/// just at a terminal.
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal as unix_signal};
    let term = async {
        match unix_signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(e) => warn!("cannot install SIGTERM handler: {e}"),
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
}

/// Build a channel to the admin/orchestrator endpoint, with optional (m)TLS.
async fn client_channel(endpoint: &str, tls: &ClientTls) -> Result<Channel> {
    let mut ep: Endpoint =
        Channel::from_shared(endpoint.to_string()).context("invalid endpoint")?;
    if let Some(ca) = &tls.tls_ca {
        let ca = std::fs::read(ca).with_context(|| format!("reading {}", ca.display()))?;
        let mut cfg = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
        if let (Some(cert), Some(key)) = (&tls.tls_cert, &tls.tls_key) {
            cfg = cfg.identity(Identity::from_pem(
                std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?,
                std::fs::read(key).with_context(|| format!("reading {}", key.display()))?,
            ));
        }
        if let Some(domain) = &tls.tls_domain {
            cfg = cfg.domain_name(domain.clone());
        }
        ep = ep.tls_config(cfg).context("client TLS config")?;
    }
    ep.connect()
        .await
        .with_context(|| format!("connecting to {endpoint}"))
}

async fn admin(args: AdminArgs) -> Result<()> {
    let mut client = VelstraAdminClient::new(client_channel(&args.endpoint, &args.tls).await?);

    match args.action {
        AdminAction::Set { node, file } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let parsed: FileConfig = toml::from_str(&text).context("parsing config")?;
            parsed.resolve().context("invalid config")?;
            let config = file_config_to_proto(&parsed, 0);
            let ack = client
                .set_config(SetConfigRequest {
                    node_id: node.clone(),
                    config: Some(config),
                })
                .await?
                .into_inner();
            if !ack.ok {
                bail!("controller rejected the config");
            }
            println!("set config for node {node:?}");
        }
        AdminAction::Delete { node } => {
            let ack = client
                .delete_config(NodeRequest {
                    node_id: node.clone(),
                })
                .await?
                .into_inner();
            println!(
                "{} override for node {node:?}",
                if ack.ok { "removed" } else { "no" }
            );
        }
        AdminAction::List => {
            let resp = client.list_nodes(ListNodesRequest {}).await?.into_inner();
            println!("{:<20} {:>8}  source", "node", "version");
            for node in resp.nodes {
                println!("{:<20} {:>8}  {}", node.node_id, node.version, node.source);
            }
        }
    }
    Ok(())
}

async fn orch(args: OrchArgs) -> Result<()> {
    let mut client =
        VelstraOrchestratorClient::new(client_channel(&args.endpoint, &args.tls).await?);

    match args.action {
        OrchAction::AddHost {
            id,
            vtep,
            iface,
            mac,
            encap,
        } => {
            let encap = match encap.as_str() {
                "geneve" => Encap::Geneve,
                "vxlan" => Encap::Vxlan,
                other => bail!("unknown encap {other:?} (use vxlan or geneve)"),
            };
            client
                .add_host(HostSpec {
                    id: id.clone(),
                    vtep,
                    underlay_iface: iface,
                    underlay_mac: mac,
                    encap: encap as i32,
                    udp_port: 0,
                    underlay_mtu: 0,
                })
                .await?;
            println!("added host {id:?}");
        }
        OrchAction::AddNetwork {
            vni,
            name,
            subnet,
            drop_icmp,
        } => {
            client
                .add_network(NetworkSpec {
                    vni,
                    name,
                    subnet,
                    default_action: Action::Pass as i32,
                    drop_icmp,
                })
                .await?;
            println!("added network vni {vni}");
        }
        OrchAction::CreatePort {
            network,
            host,
            tap,
            ip,
            policy,
        } => {
            let port = client
                .create_port(CreatePortRequest {
                    network,
                    host,
                    tap,
                    ip: ip.unwrap_or_default(),
                    policy,
                })
                .await?
                .into_inner();
            println!(
                "created port {} : {} ({}) on {} via {}",
                port.id, port.ip, port.mac, port.host, port.tap
            );
        }
        OrchAction::RemovePort { id } => {
            let ack = client
                .remove_port(RemovePortRequest { id: id.clone() })
                .await?
                .into_inner();
            println!("{} port {id:?}", if ack.ok { "removed" } else { "no such" });
        }
        OrchAction::MigratePort { id, host, tap } => {
            let port = client
                .migrate_port(MigratePortRequest { id, host, tap })
                .await?
                .into_inner();
            println!(
                "migrated port {} : {} ({}) now on {} via {}",
                port.id, port.ip, port.mac, port.host, port.tap
            );
        }
        OrchAction::ListPorts => {
            let resp = client.list_ports(ListPortsRequest {}).await?.into_inner();
            println!(
                "{:<22} {:>6}  {:<15} {:<17} {:<10} host",
                "id", "vni", "ip", "mac", "tap"
            );
            for p in resp.ports {
                println!(
                    "{:<22} {:>6}  {:<15} {:<17} {:<10} {}",
                    p.id, p.vni, p.ip, p.mac, p.tap, p.host
                );
            }
        }
        OrchAction::AddSecurityGroup {
            name,
            default_action,
            drop_icmp,
            stateful,
            allow,
            deny,
            block,
        } => {
            let default_action = match default_action.as_str() {
                "pass" => Action::Pass,
                "drop" => Action::Drop,
                other => bail!("unknown default_action {other:?} (use pass or drop)"),
            };
            let mut rules = Vec::new();
            for spec in &allow {
                rules.push(parse_cli_rule(spec, Action::Pass)?);
            }
            for spec in &deny {
                rules.push(parse_cli_rule(spec, Action::Drop)?);
            }
            client
                .add_security_group(SecurityGroupSpec {
                    name: name.clone(),
                    default_action: default_action as i32,
                    drop_icmp,
                    stateful,
                    blocklist: block,
                    rules,
                })
                .await?;
            println!("added security group {name:?}");
        }
        OrchAction::RemoveSecurityGroup { name } => {
            let ack = client
                .remove_security_group(RemoveSecurityGroupRequest { name: name.clone() })
                .await?
                .into_inner();
            println!(
                "{} security group {name:?}",
                if ack.ok { "removed" } else { "no such" }
            );
        }
        OrchAction::ListSecurityGroups => {
            let resp = client
                .list_security_groups(ListSecurityGroupsRequest {})
                .await?
                .into_inner();
            println!("{:<24} {:>12}  rules", "name", "policy_id");
            for g in resp.groups {
                println!("{:<24} {:>12}  {}", g.name, g.policy_id, g.rules.len());
            }
        }
        OrchAction::BindPort { port, group, clear } => {
            let group = if clear { None } else { group };
            let info = client
                .bind_port_security_group(BindPortSecurityGroupRequest {
                    port_id: port.clone(),
                    group: group.clone(),
                })
                .await?
                .into_inner();
            match group {
                Some(g) => println!("bound port {:?} to security group {g:?}", info.id),
                None => println!("cleared security group on port {:?}", info.id),
            }
        }
    }
    Ok(())
}

/// Parse a CLI rule spec `proto:port` (e.g. `tcp:80`) into a proto [`PortRule`]
/// with the given action.
fn parse_cli_rule(spec: &str, action: Action) -> Result<PortRule> {
    let (proto, port) = spec
        .split_once(':')
        .ok_or_else(|| anyhow!("rule {spec:?} must be proto:port (e.g. tcp:80)"))?;
    let proto = match proto {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        other => bail!("unknown proto {other:?} in rule {spec:?} (use tcp/udp/icmp)"),
    };
    let port: u16 = port
        .parse()
        .with_context(|| format!("bad port in rule {spec:?}"))?;
    Ok(PortRule {
        proto: proto as i32,
        port: port as u32,
        action: action as i32,
        log: false,
        src: String::new(),
    })
}
