//! The Raft type config, the replicated request/response, and the storage —
//! an in-memory log plus a state machine whose state **is** the orchestrator
//! [`Topology`]. Applying a committed log entry mutates the fabric; a snapshot
//! is the serialized fabric. Because every replica applies the same entries in
//! the same order, IPAM allocations are deterministic across the cluster.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    io::{Cursor, Write},
    net::IpAddr,
    ops::RangeBounds,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Result, anyhow, bail};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
    Vote,
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use velstra_common::{parse_cidr_v4, parse_cidr_v6, parse_mac};
use velstra_config::{ActionName, EncapName, PortRule};
use velstra_orchestrator::{
    AllocRange, FloatingIp, Host, Network, SecurityGroup, Subnet, SubnetCidr, Topology,
};

pub type NodeId = u64;

openraft::declare_raft_types!(
    /// The Raft type configuration for the Velstra fabric.
    pub TypeConfig:
        D = TopoRequest,
        R = TopoResponse,
        NodeId = NodeId,
        Node = BasicNode,
        Entry = Entry<TypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
);

// --- Replicated request / response -----------------------------------------

/// A serializable host description carried in [`TopoRequest::AddHost`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSpec {
    pub id: String,
    pub vtep: String,
    pub underlay_iface: String,
    pub underlay_mac: String,
    pub encap: EncapName,
    pub udp_port: Option<u16>,
    pub underlay_mtu: Option<u16>,
}

/// A serializable network description carried in [`TopoRequest::AddNetwork`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub vni: u32,
    pub name: String,
    pub subnet: String,
    pub default_action: ActionName,
    pub drop_icmp: bool,
}

/// A serializable security-group description carried in
/// [`TopoRequest::AddSecurityGroup`] (B5). Mirrors [`NetworkSpec`]: a plain,
/// wire-friendly form validated when applied to the topology (on every replica).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroupSpec {
    pub name: String,
    pub default_action: ActionName,
    pub drop_icmp: bool,
    pub stateful: bool,
    pub blocklist: Vec<String>,
    pub rules: Vec<PortRule>,
}

/// A serializable subnet description carried in [`TopoRequest::AddSubnet`] (D2).
/// Wire-friendly strings validated when applied to the topology (on every
/// replica). An empty `gateway`/`pool_*` is represented as `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubnetSpec {
    pub id: String,
    pub vni: u32,
    /// CIDR, IPv4 (`192.168.50.0/24`) or IPv6 (`2001:db8::/64`).
    pub cidr: String,
    pub gateway: Option<String>,
    pub pool_start: Option<String>,
    pub pool_end: Option<String>,
    pub enable_dhcp: bool,
}

/// A serializable view of a floating IP (the result of allocate/associate/
/// disassociate, B6). `assoc_*` are `None` when the floating IP is unassociated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FloatingIpRecord {
    pub id: String,
    pub vni: u32,
    pub subnet_id: String,
    pub addr: String,
    pub assoc_port: Option<String>,
    pub assoc_fixed: Option<String>,
}

/// A fabric mutation — the unit of replication. Every committed request is
/// applied, in log order, to every replica's [`Topology`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TopoRequest {
    AddHost(HostSpec),
    AddNetwork(NetworkSpec),
    CreatePort {
        vni: u32,
        host: String,
        tap: String,
        ip: Option<String>,
        /// Explicit security-group policy, or `None` to default to the VNI (M4).
        #[serde(default)]
        policy: Option<u32>,
    },
    RemovePort {
        id: String,
    },
    MigratePort {
        id: String,
        host: String,
        tap: String,
    },
    RemoveHost {
        id: String,
    },
    RemoveNetwork {
        vni: u32,
    },
    /// Register a named security group (B5).
    AddSecurityGroup(SecurityGroupSpec),
    /// Remove a security group by name (fails while any port binds it).
    RemoveSecurityGroup {
        name: String,
    },
    /// Bind a port to a security group by name, or clear it (`group = None`).
    SetPortSecurityGroup {
        port_id: String,
        group: Option<String>,
    },
    // --- Subnets + IPAM (D2) ------------------------------------------------
    /// Define a first-class subnet under a network.
    AddSubnet(SubnetSpec),
    /// Remove a subnet by id (fails while any address is still allocated).
    RemoveSubnet {
        id: String,
    },
    /// Bind a port to a subnet, allocating (or requesting `ip`) an address.
    BindPortSubnet {
        port_id: String,
        subnet_id: String,
        ip: Option<String>,
    },
    /// Release one of a port's bound addresses back to its subnet's pool.
    UnbindPortAddress {
        port_id: String,
        subnet_id: String,
        addr: String,
    },
    /// Allocate a standalone address from a subnet's pool (or a requested one).
    AllocateAddress {
        subnet_id: String,
        ip: Option<String>,
    },
    /// Release a standalone address back to a subnet's pool.
    ReleaseAddress {
        subnet_id: String,
        addr: String,
    },
    // --- Floating IPs (B6) --------------------------------------------------
    /// Allocate a floating IP from a floating subnet via IPAM.
    AllocateFloatingIp {
        subnet_id: String,
        ip: Option<String>,
    },
    /// Associate a floating IP to a port's fixed address (1:1).
    AssociateFloatingIp {
        id: String,
        port_id: String,
        fixed_addr: String,
    },
    /// Clear a floating IP's association, leaving it allocated.
    DisassociateFloatingIp {
        id: String,
    },
    /// Release a floating IP (blocked while it is still associated).
    ReleaseFloatingIp {
        id: String,
    },
}

/// A serializable view of an allocated port (the result of `CreatePort`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortRecord {
    pub id: String,
    pub vni: u32,
    pub host: String,
    pub ip: String,
    pub mac: String,
    pub tap: String,
}

/// The result of applying a [`TopoRequest`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopoResponse {
    pub ok: bool,
    pub error: Option<String>,
    /// The created/updated port, for `CreatePort`/`MigratePort`/`SetPortSecurityGroup`.
    pub port: Option<PortRecord>,
    /// The allocated address, for `AllocateAddress`/`BindPortSubnet` (D2).
    #[serde(default)]
    pub addr: Option<String>,
    /// The affected floating IP, for the B6 allocate/associate/disassociate ops.
    #[serde(default)]
    pub floating: Option<FloatingIpRecord>,
}

impl TopoResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            ..Default::default()
        }
    }
    fn ok_port(port: PortRecord) -> Self {
        Self {
            ok: true,
            port: Some(port),
            ..Default::default()
        }
    }
    fn ok_addr(addr: String) -> Self {
        Self {
            ok: true,
            addr: Some(addr),
            ..Default::default()
        }
    }
    fn ok_floating(floating: FloatingIpRecord) -> Self {
        Self {
            ok: true,
            floating: Some(floating),
            ..Default::default()
        }
    }
    fn err(e: impl ToString) -> Self {
        Self {
            ok: false,
            error: Some(e.to_string()),
            ..Default::default()
        }
    }
}

fn fmt_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

fn host_from_spec(s: &HostSpec) -> Result<Host> {
    Ok(Host {
        id: s.id.clone(),
        vtep_ip: s
            .vtep
            .parse()
            .map_err(|_| anyhow!("invalid vtep {:?}", s.vtep))?,
        underlay_iface: s.underlay_iface.clone(),
        underlay_mac: parse_mac(&s.underlay_mac).map_err(|e| anyhow!("invalid mac: {e}"))?,
        encap: s.encap,
        udp_port: s.udp_port,
        underlay_mtu: s.underlay_mtu,
    })
}

fn network_from_spec(s: &NetworkSpec) -> Result<Network> {
    Ok(Network {
        vni: s.vni,
        name: s.name.clone(),
        subnet: parse_cidr_v4(&s.subnet).map_err(|e| anyhow!("invalid subnet: {e}"))?,
        default_action: s.default_action,
        drop_icmp: s.drop_icmp,
    })
}

fn sg_from_spec(s: &SecurityGroupSpec) -> SecurityGroup {
    SecurityGroup {
        name: s.name.clone(),
        default_action: s.default_action,
        drop_icmp: s.drop_icmp,
        stateful: s.stateful,
        blocklist: s.blocklist.clone(),
        rules: s.rules.clone(),
    }
}

/// Parse an optional address string; `None` (auto-allocate) stays `None`.
fn parse_opt_ip(s: &Option<String>) -> Result<Option<IpAddr>> {
    match s {
        Some(s) => Ok(Some(s.parse().map_err(|_| anyhow!("invalid ip {s:?}"))?)),
        None => Ok(None),
    }
}

fn subnet_from_spec(s: &SubnetSpec) -> Result<Subnet> {
    // Detect the family by the CIDR text: a ':' means IPv6.
    let cidr = if s.cidr.contains(':') {
        SubnetCidr::V6(
            parse_cidr_v6(&s.cidr).map_err(|e| anyhow!("invalid cidr {:?}: {e}", s.cidr))?,
        )
    } else {
        SubnetCidr::V4(
            parse_cidr_v4(&s.cidr).map_err(|e| anyhow!("invalid cidr {:?}: {e}", s.cidr))?,
        )
    };
    let gateway = match &s.gateway {
        Some(g) => Some(
            g.parse::<IpAddr>()
                .map_err(|_| anyhow!("invalid gateway {g:?}"))?,
        ),
        None => None,
    };
    let pool = match (&s.pool_start, &s.pool_end) {
        (Some(a), Some(b)) => Some(AllocRange {
            start: a.parse().map_err(|_| anyhow!("invalid pool start {a:?}"))?,
            end: b.parse().map_err(|_| anyhow!("invalid pool end {b:?}"))?,
        }),
        (None, None) => None,
        _ => bail!("subnet {:?}: pool requires both start and end", s.id),
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

fn port_record(p: &velstra_orchestrator::Port) -> PortRecord {
    PortRecord {
        id: p.id.clone(),
        vni: p.vni,
        host: p.host.clone(),
        ip: p.ip.to_string(),
        mac: fmt_mac(p.mac),
        tap: p.tap.clone(),
    }
}

fn fip_record(f: &FloatingIp) -> FloatingIpRecord {
    FloatingIpRecord {
        id: f.id.clone(),
        vni: f.vni,
        subnet_id: f.subnet_id.clone(),
        addr: f.addr.to_string(),
        assoc_port: f.association.as_ref().map(|a| a.port_id.clone()),
        assoc_fixed: f.association.as_ref().map(|a| a.fixed_addr.to_string()),
    }
}

/// Apply one request to the fabric, producing its response. Pure given the
/// current `topo`, so it is deterministic across replicas. Exposed so the
/// controller can run the *same* mutation logic in its non-Raft single-node mode.
pub fn apply(topo: &mut Topology, req: &TopoRequest) -> TopoResponse {
    let outcome: Result<TopoResponse> = (|| match req {
        TopoRequest::AddHost(s) => {
            topo.add_host(host_from_spec(s)?);
            Ok(TopoResponse::ok())
        }
        TopoRequest::AddNetwork(s) => {
            topo.add_network(network_from_spec(s)?)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::CreatePort {
            vni,
            host,
            tap,
            ip,
            policy,
        } => {
            let ip = match ip {
                Some(s) => Some(s.parse().map_err(|_| anyhow!("invalid ip {s:?}"))?),
                None => None,
            };
            let p = topo.create_port(*vni, host, tap, ip, *policy)?;
            Ok(TopoResponse::ok_port(port_record(&p)))
        }
        TopoRequest::RemovePort { id } => {
            topo.remove_port(id);
            Ok(TopoResponse::ok())
        }
        TopoRequest::RemoveHost { id } => {
            topo.remove_host(id)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::RemoveNetwork { vni } => {
            topo.remove_network(*vni)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::MigratePort { id, host, tap } => {
            let p = topo.migrate_port(id, host, tap)?;
            Ok(TopoResponse::ok_port(port_record(&p)))
        }
        TopoRequest::AddSecurityGroup(s) => {
            topo.add_security_group(sg_from_spec(s))?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::RemoveSecurityGroup { name } => {
            topo.remove_security_group(name)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::SetPortSecurityGroup { port_id, group } => {
            let p = topo.set_port_security_group(port_id, group.as_deref())?;
            Ok(TopoResponse::ok_port(port_record(&p)))
        }
        // --- Subnets + IPAM (D2) --------------------------------------------
        TopoRequest::AddSubnet(s) => {
            topo.add_subnet(subnet_from_spec(s)?)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::RemoveSubnet { id } => {
            topo.remove_subnet(id)?;
            Ok(TopoResponse::ok())
        }
        TopoRequest::BindPortSubnet {
            port_id,
            subnet_id,
            ip,
        } => {
            let pa = topo.bind_port_subnet(port_id, subnet_id, parse_opt_ip(ip)?)?;
            Ok(TopoResponse::ok_addr(pa.addr.to_string()))
        }
        TopoRequest::UnbindPortAddress {
            port_id,
            subnet_id,
            addr,
        } => {
            let a = addr
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("invalid addr {addr:?}"))?;
            if topo.unbind_port_address(port_id, subnet_id, a) {
                Ok(TopoResponse::ok())
            } else {
                bail!("address {addr} was not bound to port {port_id:?}")
            }
        }
        TopoRequest::AllocateAddress { subnet_id, ip } => {
            let a = topo.allocate(subnet_id, parse_opt_ip(ip)?)?;
            Ok(TopoResponse::ok_addr(a.to_string()))
        }
        TopoRequest::ReleaseAddress { subnet_id, addr } => {
            let a = addr
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("invalid addr {addr:?}"))?;
            if topo.release(subnet_id, a) {
                Ok(TopoResponse::ok())
            } else {
                bail!("address {addr} was not allocated in subnet {subnet_id:?}")
            }
        }
        // --- Floating IPs (B6) ----------------------------------------------
        TopoRequest::AllocateFloatingIp { subnet_id, ip } => {
            let f = topo.allocate_floating_ip(subnet_id, parse_opt_ip(ip)?)?;
            Ok(TopoResponse::ok_floating(fip_record(&f)))
        }
        TopoRequest::AssociateFloatingIp {
            id,
            port_id,
            fixed_addr,
        } => {
            let a = fixed_addr
                .parse::<IpAddr>()
                .map_err(|_| anyhow!("invalid fixed addr {fixed_addr:?}"))?;
            let f = topo.associate_floating_ip(id, port_id, a)?;
            Ok(TopoResponse::ok_floating(fip_record(&f)))
        }
        TopoRequest::DisassociateFloatingIp { id } => {
            let f = topo.disassociate_floating_ip(id)?;
            Ok(TopoResponse::ok_floating(fip_record(&f)))
        }
        TopoRequest::ReleaseFloatingIp { id } => {
            if topo.release_floating_ip(id)? {
                Ok(TopoResponse::ok())
            } else {
                bail!("no floating ip {id:?}")
            }
        }
    })();
    outcome.unwrap_or_else(TopoResponse::err)
}

// --- Log store --------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct LogInner {
    log: BTreeMap<u64, Entry<TypeConfig>>,
    last_purged: Option<LogId<NodeId>>,
    committed: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
}

/// The on-disk write-ahead log file inside the raft dir.
const LOG_FILE: &str = "raftlog.json";

/// Load a persisted log (write-ahead log) from `dir`, if one is present. Returns
/// `Ok(None)` when the directory holds no log yet (a fresh node, or one that only
/// ever persisted snapshots).
fn load_log(dir: &Path) -> Result<Option<LogInner>> {
    let path = dir.join(LOG_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let inner: LogInner = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("parsing {}: {e}", path.display()))?;
            Ok(Some(inner))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
    }
}

/// Raft log store with a durable write-ahead log. Every mutation — appended
/// entries, the vote, the committed marker, truncation and purge — is written
/// through to `raftlog.json` (atomic temp+rename, fsynced) before it is
/// acknowledged, so a committed+acked write survives a correlated full-cluster
/// power loss instead of vanishing when it happened <100 entries since the last
/// snapshot. With `dir == None` the log is purely in-memory (dev / single-node /
/// trusted use), matching the previous behaviour.
#[derive(Clone, Debug, Default)]
pub struct LogStore {
    inner: Arc<Mutex<LogInner>>,
    dir: Option<Arc<PathBuf>>,
}

impl LogStore {
    /// Build a log store under `dir`, resuming from the persisted write-ahead log
    /// there if one exists. With no persisted log the store starts empty but with
    /// its `last_purged` seeded from `last_purged` (the reloaded snapshot's last
    /// log id) so the reported `last_log_id` stays consistent with the state
    /// machine's `last_applied`. `dir == None` keeps the log volatile.
    pub fn new(dir: Option<PathBuf>, last_purged: Option<LogId<NodeId>>) -> Result<Self> {
        let inner = match &dir {
            Some(d) => match load_log(d)? {
                Some(loaded) => loaded,
                None => LogInner {
                    last_purged,
                    ..Default::default()
                },
            },
            None => LogInner {
                last_purged,
                ..Default::default()
            },
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            dir: dir.map(Arc::new),
        })
    }

    /// Atomically persist the current log state to `raftlog.json`, if a directory
    /// is configured. Writes a temp file, fsyncs its contents, renames it over the
    /// live file, then fsyncs the directory — so a crash at any point leaves either
    /// the old complete log or the new complete log, never a torn one, and a
    /// power-loss after the return still has the bytes on stable storage.
    fn persist(&self, inner: &LogInner) -> Result<(), StorageError<NodeId>> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(inner).map_err(io_err)?;
        let path = dir.join(LOG_FILE);
        let tmp = dir.join(format!("{LOG_FILE}.tmp"));
        let mut f = std::fs::File::create(&tmp).map_err(io_err)?;
        f.write_all(&bytes).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        drop(f);
        std::fs::rename(&tmp, &path).map_err(io_err)?;
        // fsync the directory so the rename itself is durable across a power loss.
        if let Ok(d) = std::fs::File::open(dir.as_path()) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        Ok(inner.log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        let last = inner
            .log
            .iter()
            .next_back()
            .map(|(_, e)| e.log_id)
            .or(inner.last_purged);
        Ok(LogState {
            last_purged_log_id: inner.last_purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.vote = Some(*vote);
        // The vote MUST be durable before we act on it (RFC: a granted vote may
        // never be forgotten across a restart, or two leaders could form).
        self.persist(&inner)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.committed = committed;
        self.persist(&inner)
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.committed)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut inner = self.inner.lock().await;
        for entry in entries {
            inner.log.insert(entry.log_id.index, entry);
        }
        // Flush the appended tail to stable storage before acknowledging it: the
        // callback is what lets the leader count this replica toward the commit
        // quorum, so it must not fire until the bytes are durable.
        let res = self.persist(&inner);
        drop(inner);
        match res {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(e) => {
                callback.log_io_completed(Err(std::io::Error::other("raft log persist failed")));
                Err(e)
            }
        }
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.log.split_off(&log_id.index); // drops [index, +oo)
        self.persist(&inner)
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.last_purged = Some(log_id);
        let keep = inner.log.split_off(&(log_id.index + 1)); // keep (index, +oo)
        inner.log = keep;
        self.persist(&inner)
    }
}

// --- State machine ----------------------------------------------------------

/// What a snapshot serialises to: the whole fabric.
#[derive(Serialize, Deserialize)]
struct SnapshotPayload {
    fabric: velstra_orchestrator::FabricSnapshot,
}

#[derive(Clone, Debug)]
pub struct StoredSnapshot {
    pub meta: SnapshotMeta<NodeId, BasicNode>,
    pub data: Vec<u8>,
}

/// On-disk form of a snapshot: its metadata plus the serialized fabric. Written
/// atomically so a crash mid-write never leaves a torn file.
#[derive(Serialize, Deserialize)]
struct PersistedSnapshot {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

const SNAPSHOT_FILE: &str = "snapshot.json";

/// Read the persisted snapshot from `dir`, if one exists. Returns `Ok(None)`
/// when the directory holds no snapshot yet (a fresh node).
pub fn load_snapshot(dir: &Path) -> Result<Option<StoredSnapshot>> {
    let path = dir.join(SNAPSHOT_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let p: PersistedSnapshot = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow!("parsing {}: {e}", path.display()))?;
            Ok(Some(StoredSnapshot {
                meta: p.meta,
                data: p.data,
            }))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow!("reading {}: {e}", path.display())),
    }
}

struct SmInner {
    last_applied: Option<LogId<NodeId>>,
    last_membership: StoredMembership<NodeId, BasicNode>,
    topology: Topology,
    current_snapshot: Option<StoredSnapshot>,
}

impl Default for SmInner {
    fn default() -> Self {
        Self {
            last_applied: None,
            last_membership: StoredMembership::default(),
            topology: Topology::new(),
            current_snapshot: None,
        }
    }
}

/// The replicated state machine: the fabric topology. Cloneable (Arc-backed) so
/// the controller can hold a handle to read the applied topology and subscribe
/// to change notifications.
#[derive(Clone)]
pub struct StateMachineStore {
    inner: Arc<Mutex<SmInner>>,
    snapshot_idx: Arc<AtomicU64>,
    changed: Arc<watch::Sender<u64>>,
    /// Where snapshots are persisted, if durability is enabled.
    dir: Option<Arc<PathBuf>>,
}

impl Default for StateMachineStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SmInner::default())),
            snapshot_idx: Arc::new(AtomicU64::new(0)),
            changed: Arc::new(watch::channel(0).0),
            dir: None,
        }
    }
}

impl StateMachineStore {
    /// Build a state machine, optionally persisting snapshots under `dir` and
    /// resuming from a previously persisted snapshot (`loaded`). With no `loaded`
    /// snapshot it starts empty; with one it restores the fabric, `last_applied`,
    /// and membership so the node rejoins the cluster from where it left off.
    pub fn new(dir: Option<PathBuf>, loaded: Option<StoredSnapshot>) -> Result<Self> {
        let inner = match &loaded {
            Some(s) => {
                let payload: SnapshotPayload = serde_json::from_slice(&s.data)
                    .map_err(|e| anyhow!("parsing persisted snapshot payload: {e}"))?;
                SmInner {
                    last_applied: s.meta.last_log_id,
                    last_membership: s.meta.last_membership.clone(),
                    topology: Topology::from_snapshot(&payload.fabric),
                    current_snapshot: Some(s.clone()),
                }
            }
            None => SmInner::default(),
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            snapshot_idx: Arc::new(AtomicU64::new(0)),
            changed: Arc::new(watch::channel(0).0),
            dir: dir.map(Arc::new),
        })
    }

    /// Atomically persist `snap` to the snapshot directory, if one is configured.
    /// Writes to a temp file and renames, so readers never see a partial file.
    fn persist(&self, snap: &StoredSnapshot) -> Result<(), StorageError<NodeId>> {
        let Some(dir) = &self.dir else {
            return Ok(());
        };
        let payload = PersistedSnapshot {
            meta: snap.meta.clone(),
            data: snap.data.clone(),
        };
        let bytes = serde_json::to_vec(&payload).map_err(io_err)?;
        let path = dir.join(SNAPSHOT_FILE);
        let tmp = dir.join(format!("{SNAPSHOT_FILE}.tmp"));
        std::fs::write(&tmp, &bytes)
            .and_then(|()| std::fs::rename(&tmp, &path))
            .map_err(io_err)?;
        Ok(())
    }

    /// A clone of the current applied topology (for deriving per-host configs).
    pub async fn topology(&self) -> Topology {
        self.inner.lock().await.topology.clone()
    }

    /// Subscribe to "the applied topology changed" notifications.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    fn notify(&self) {
        self.changed.send_modify(|v| *v = v.wrapping_add(1));
    }
}

fn io_err<E: std::error::Error + 'static>(e: E) -> StorageError<NodeId> {
    StorageIOError::read_state_machine(&e).into()
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachineStore {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let (data, last_applied, last_membership) = {
            let inner = self.inner.lock().await;
            let payload = SnapshotPayload {
                fabric: inner.topology.to_snapshot(),
            };
            let data = serde_json::to_vec(&payload).map_err(io_err)?;
            (data, inner.last_applied, inner.last_membership.clone())
        };

        let idx = self.snapshot_idx.fetch_add(1, Ordering::SeqCst) + 1;
        let snapshot_id = match last_applied {
            Some(l) => format!("{}-{}-{idx}", l.leader_id, l.index),
            None => format!("--{idx}"),
        };
        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        };
        self.persist(&stored)?;
        self.inner.lock().await.current_snapshot = Some(stored);
        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachineStore {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let inner = self.inner.lock().await;
        Ok((inner.last_applied, inner.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<TopoResponse>, StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        let mut responses = Vec::new();
        {
            let mut inner = self.inner.lock().await;
            for entry in entries {
                inner.last_applied = Some(entry.log_id);
                let resp = match entry.payload {
                    EntryPayload::Blank => TopoResponse::ok(),
                    EntryPayload::Normal(ref req) => apply(&mut inner.topology, req),
                    EntryPayload::Membership(mem) => {
                        inner.last_membership = StoredMembership::new(Some(entry.log_id), mem);
                        TopoResponse::ok()
                    }
                };
                responses.push(resp);
            }
        }
        self.notify();
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let payload: SnapshotPayload = serde_json::from_slice(&data).map_err(io_err)?;
        let stored = StoredSnapshot {
            meta: meta.clone(),
            data,
        };
        self.persist(&stored)?;
        {
            let mut inner = self.inner.lock().await;
            inner.topology = Topology::from_snapshot(&payload.fabric);
            inner.last_applied = meta.last_log_id;
            inner.last_membership = meta.last_membership.clone();
            inner.current_snapshot = Some(stored);
        }
        self.notify();
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        let inner = self.inner.lock().await;
        Ok(inner.current_snapshot.as_ref().map(|s| Snapshot {
            meta: s.meta.clone(),
            snapshot: Box::new(Cursor::new(s.data.clone())),
        }))
    }
}

#[cfg(test)]
mod tests {
    use velstra_config::{ActionName, EncapName};
    use velstra_orchestrator::Topology;

    use super::*;

    fn host_spec(id: &str, vtep: &str) -> HostSpec {
        HostSpec {
            id: id.into(),
            vtep: vtep.into(),
            underlay_iface: "eth0".into(),
            underlay_mac: "02:00:00:00:00:11".into(),
            encap: EncapName::Vxlan,
            udp_port: None,
            underlay_mtu: None,
        }
    }

    #[test]
    fn apply_migrate_port_moves_host_keeping_identity() {
        let mut t = Topology::new();
        assert!(apply(&mut t, &TopoRequest::AddHost(host_spec("h1", "10.0.0.1"))).ok);
        assert!(apply(&mut t, &TopoRequest::AddHost(host_spec("h2", "10.0.0.2"))).ok);
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddNetwork(NetworkSpec {
                    vni: 5000,
                    name: "blue".into(),
                    subnet: "192.168.100.0/24".into(),
                    default_action: ActionName::Pass,
                    drop_icmp: false,
                })
            )
            .ok
        );
        let port = apply(
            &mut t,
            &TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            },
        )
        .port
        .expect("create returns a port");
        assert_eq!(port.host, "h1");

        // Migrate to h2 with a new tap; identity (id/ip/mac) is preserved.
        let migrated = apply(
            &mut t,
            &TopoRequest::MigratePort {
                id: port.id.clone(),
                host: "h2".into(),
                tap: "tapA2".into(),
            },
        );
        assert!(migrated.ok, "migrate failed: {:?}", migrated.error);
        let mp = migrated.port.expect("migrate returns the port");
        assert_eq!(mp.id, port.id);
        assert_eq!(mp.ip, port.ip);
        assert_eq!(mp.mac, port.mac);
        assert_eq!(mp.host, "h2");
        assert_eq!(mp.tap, "tapA2");

        // Migrating onto an unknown host is a failed response, not a panic.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::MigratePort {
                    id: port.id,
                    host: "ghost".into(),
                    tap: "x".into(),
                },
            )
            .ok
        );
    }

    #[test]
    fn apply_security_group_add_bind_and_remove_roundtrip() {
        use velstra_config::ProtoName;

        let mut t = Topology::new();
        assert!(apply(&mut t, &TopoRequest::AddHost(host_spec("h1", "10.0.0.1"))).ok);
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddNetwork(NetworkSpec {
                    vni: 5000,
                    name: "blue".into(),
                    subnet: "192.168.100.0/24".into(),
                    default_action: ActionName::Pass,
                    drop_icmp: false,
                })
            )
            .ok
        );
        let port = apply(
            &mut t,
            &TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            },
        )
        .port
        .expect("create returns a port");

        // Add a "web" group (default-drop, allow tcp/80).
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddSecurityGroup(SecurityGroupSpec {
                    name: "web".into(),
                    default_action: ActionName::Drop,
                    drop_icmp: false,
                    stateful: true,
                    blocklist: vec![],
                    rules: vec![PortRule {
                        proto: ProtoName::Tcp,
                        port: 80,
                        action: ActionName::Pass,
                        log: false,
                        src: None,
                    }],
                })
            )
            .ok
        );
        // A duplicate name is a failed response, not a panic.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::AddSecurityGroup(SecurityGroupSpec {
                    name: "web".into(),
                    default_action: ActionName::Drop,
                    drop_icmp: false,
                    stateful: false,
                    blocklist: vec![],
                    rules: vec![],
                })
            )
            .ok
        );

        // Bind the port → its policy becomes the group's deterministic id, and
        // the derived config for h1 resolves with the group's rules.
        let bound = apply(
            &mut t,
            &TopoRequest::SetPortSecurityGroup {
                port_id: port.id.clone(),
                group: Some("web".into()),
            },
        );
        assert!(bound.ok, "bind failed: {:?}", bound.error);
        let pid = velstra_orchestrator::security_group_policy_id("web");
        let rt = t
            .derive("h1")
            .unwrap()
            .resolve()
            .expect("derived config resolves");
        assert!(rt.policies.iter().any(|p| p.id == pid));
        assert_eq!(
            rt.interfaces
                .iter()
                .find(|i| i.name == "tapA")
                .unwrap()
                .policy,
            pid
        );

        // Removing a bound group fails; clearing the binding then allows removal.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::RemoveSecurityGroup { name: "web".into() }
            )
            .ok
        );
        assert!(
            apply(
                &mut t,
                &TopoRequest::SetPortSecurityGroup {
                    port_id: port.id,
                    group: None,
                },
            )
            .ok
        );
        assert!(
            apply(
                &mut t,
                &TopoRequest::RemoveSecurityGroup { name: "web".into() }
            )
            .ok
        );
    }

    /// Seed a topology (one host + one network) via `apply`, returning it.
    fn seeded() -> Topology {
        let mut t = Topology::new();
        assert!(apply(&mut t, &TopoRequest::AddHost(host_spec("h1", "10.0.0.1"))).ok);
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddNetwork(NetworkSpec {
                    vni: 5000,
                    name: "blue".into(),
                    subnet: "192.168.100.0/24".into(),
                    default_action: ActionName::Pass,
                    drop_icmp: false,
                })
            )
            .ok
        );
        t
    }

    fn subnet_spec(id: &str, cidr: &str, gateway: Option<&str>) -> SubnetSpec {
        SubnetSpec {
            id: id.into(),
            vni: 5000,
            cidr: cidr.into(),
            gateway: gateway.map(|g| g.into()),
            pool_start: None,
            pool_end: None,
            enable_dhcp: false,
        }
    }

    #[test]
    fn apply_subnet_add_bind_allocate_and_remove_roundtrip() {
        let mut t = seeded();

        // Add a v4 and a v6 subnet (dual stack), each with a gateway.
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddSubnet(subnet_spec(
                    "s4",
                    "192.168.100.0/24",
                    Some("192.168.100.1")
                ))
            )
            .ok
        );
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddSubnet(subnet_spec("s6", "2001:db8::/64", Some("2001:db8::1")))
            )
            .ok
        );
        // An unknown-VNI subnet fails (validated on apply, deterministically).
        let bad = SubnetSpec {
            vni: 999,
            ..subnet_spec("bad", "10.9.0.0/24", None)
        };
        assert!(!apply(&mut t, &TopoRequest::AddSubnet(bad)).ok);
        assert_eq!(t.subnets().count(), 2);

        // A standalone allocation returns the address (gateway .1 reserved → .2).
        let alloc = apply(
            &mut t,
            &TopoRequest::AllocateAddress {
                subnet_id: "s4".into(),
                ip: None,
            },
        );
        assert!(alloc.ok);
        assert_eq!(alloc.addr.as_deref(), Some("192.168.100.2"));
        // Releasing it back succeeds; a double release fails.
        assert!(
            apply(
                &mut t,
                &TopoRequest::ReleaseAddress {
                    subnet_id: "s4".into(),
                    addr: "192.168.100.2".into()
                }
            )
            .ok
        );
        assert!(
            !apply(
                &mut t,
                &TopoRequest::ReleaseAddress {
                    subnet_id: "s4".into(),
                    addr: "192.168.100.2".into()
                }
            )
            .ok
        );

        // Create a port and bind it dual-stack.
        let port = apply(
            &mut t,
            &TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            },
        )
        .port
        .expect("create returns a port");
        let b4 = apply(
            &mut t,
            &TopoRequest::BindPortSubnet {
                port_id: port.id.clone(),
                subnet_id: "s4".into(),
                ip: None,
            },
        );
        assert!(b4.ok);
        assert_eq!(b4.addr.as_deref(), Some("192.168.100.2")); // .1 gw reserved, .2 free again
        let b6 = apply(
            &mut t,
            &TopoRequest::BindPortSubnet {
                port_id: port.id.clone(),
                subnet_id: "s6".into(),
                ip: None,
            },
        );
        assert!(b6.ok);
        assert_eq!(b6.addr.as_deref(), Some("2001:db8::2"));

        // Unbinding the wrong address fails; the right one succeeds.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::UnbindPortAddress {
                    port_id: port.id.clone(),
                    subnet_id: "s4".into(),
                    addr: "192.168.100.9".into()
                }
            )
            .ok
        );
        assert!(
            apply(
                &mut t,
                &TopoRequest::UnbindPortAddress {
                    port_id: port.id.clone(),
                    subnet_id: "s4".into(),
                    addr: "192.168.100.2".into()
                }
            )
            .ok
        );

        // Removing a subnet with a live binding fails; after unbinding s6, it removes.
        assert!(!apply(&mut t, &TopoRequest::RemoveSubnet { id: "s6".into() }).ok);
        assert!(
            apply(
                &mut t,
                &TopoRequest::UnbindPortAddress {
                    port_id: port.id,
                    subnet_id: "s6".into(),
                    addr: "2001:db8::2".into()
                }
            )
            .ok
        );
        assert!(apply(&mut t, &TopoRequest::RemoveSubnet { id: "s6".into() }).ok);

        // The whole thing survives a snapshot round-trip (cluster durability).
        let restored = Topology::from_snapshot(&t.to_snapshot());
        assert_eq!(restored.subnets().count(), t.subnets().count());
    }

    #[test]
    fn apply_floating_ip_allocate_associate_and_release_roundtrip() {
        let mut t = seeded();
        // A tenant subnet (for the port's fixed address) and an external/floating one.
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddSubnet(subnet_spec("tenant", "192.168.100.0/24", None))
            )
            .ok
        );
        assert!(
            apply(
                &mut t,
                &TopoRequest::AddSubnet(SubnetSpec {
                    vni: 5000,
                    ..subnet_spec("ext", "203.0.113.0/29", None)
                })
            )
            .ok
        );

        let port = apply(
            &mut t,
            &TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            },
        )
        .port
        .expect("create returns a port");
        let fixed = apply(
            &mut t,
            &TopoRequest::BindPortSubnet {
                port_id: port.id.clone(),
                subnet_id: "tenant".into(),
                ip: None,
            },
        )
        .addr
        .expect("bind returns an address"); // .1

        // Allocate a floating IP (returns the fip record, unassociated).
        let alloc = apply(
            &mut t,
            &TopoRequest::AllocateFloatingIp {
                subnet_id: "ext".into(),
                ip: None,
            },
        );
        assert!(alloc.ok);
        let fip = alloc.floating.expect("allocate returns a floating ip");
        assert_eq!(fip.addr, "203.0.113.1");
        assert!(fip.assoc_port.is_none());

        // Associating to a fixed address the port does not hold fails.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::AssociateFloatingIp {
                    id: fip.id.clone(),
                    port_id: port.id.clone(),
                    fixed_addr: "192.168.100.99".into()
                }
            )
            .ok
        );
        // Associate to the port's real fixed address.
        let assoc = apply(
            &mut t,
            &TopoRequest::AssociateFloatingIp {
                id: fip.id.clone(),
                port_id: port.id.clone(),
                fixed_addr: fixed.clone(),
            },
        );
        assert!(assoc.ok, "associate failed: {:?}", assoc.error);
        let af = assoc.floating.unwrap();
        assert_eq!(af.assoc_port.as_deref(), Some(port.id.as_str()));
        assert_eq!(af.assoc_fixed.as_deref(), Some(fixed.as_str()));

        // Release is blocked while associated; disassociate then release works.
        assert!(
            !apply(
                &mut t,
                &TopoRequest::ReleaseFloatingIp { id: fip.id.clone() }
            )
            .ok
        );
        let dis = apply(
            &mut t,
            &TopoRequest::DisassociateFloatingIp { id: fip.id.clone() },
        );
        assert!(dis.ok);
        assert!(dis.floating.unwrap().assoc_port.is_none());
        assert!(
            apply(
                &mut t,
                &TopoRequest::ReleaseFloatingIp { id: fip.id.clone() }
            )
            .ok
        );
        // Releasing again reports failure (no such floating ip).
        assert!(!apply(&mut t, &TopoRequest::ReleaseFloatingIp { id: fip.id }).ok);

        // Re-allocate + associate, then confirm it survives a snapshot round-trip.
        let f2 = apply(
            &mut t,
            &TopoRequest::AllocateFloatingIp {
                subnet_id: "ext".into(),
                ip: None,
            },
        )
        .floating
        .unwrap();
        assert!(
            apply(
                &mut t,
                &TopoRequest::AssociateFloatingIp {
                    id: f2.id.clone(),
                    port_id: port.id,
                    fixed_addr: fixed
                }
            )
            .ok
        );
        let restored = Topology::from_snapshot(&t.to_snapshot());
        let rf = restored
            .floating_ip(&f2.id)
            .expect("floating ip survives failover");
        assert!(rf.association.is_some());
    }

    #[tokio::test]
    async fn wal_recovers_committed_state_after_restart() {
        use openraft::CommittedLeaderId;

        // A unique per-run directory so parallel test runs don't collide.
        let dir =
            std::env::temp_dir().join(format!("velstra-wal-{}-{:p}", std::process::id(), &0u8));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let entry = Entry {
            log_id: LogId::new(CommittedLeaderId::new(3, 1), 7),
            payload: EntryPayload::Normal(TopoRequest::AddHost(host_spec("h1", "10.0.0.1"))),
        };
        let vote = Vote::new_committed(3, 1);

        // First "process": persist a vote, a log entry, and the committed marker —
        // then drop the store, simulating a full-cluster power loss.
        {
            let mut store = LogStore::new(Some(dir.clone()), None).unwrap();
            store.save_vote(&vote).await.unwrap();
            {
                // `append` needs an openraft-internal LogFlushed callback we cannot
                // build here, so drive the same insert+persist it performs.
                let mut inner = store.inner.lock().await;
                inner.log.insert(entry.log_id.index, entry.clone());
                store.persist(&inner).unwrap();
            }
            store.save_committed(Some(entry.log_id)).await.unwrap();
        }

        // Second "process": a fresh store over the same directory recovers the vote,
        // the committed marker and the log entry from the write-ahead log — none of
        // which a snapshot had captured yet.
        let mut store = LogStore::new(Some(dir.clone()), None).unwrap();
        assert_eq!(store.read_vote().await.unwrap(), Some(vote));
        assert_eq!(
            store.read_committed().await.unwrap().map(|l| l.index),
            Some(7)
        );
        let entries = store.try_get_log_entries(0..u64::MAX).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].log_id.index, 7);
        assert_eq!(
            store
                .get_log_state()
                .await
                .unwrap()
                .last_log_id
                .map(|l| l.index),
            Some(7)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
