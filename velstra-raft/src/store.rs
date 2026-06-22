//! The Raft type config, the replicated request/response, and the storage —
//! an in-memory log plus a state machine whose state **is** the orchestrator
//! [`Topology`]. Applying a committed log entry mutates the fabric; a snapshot
//! is the serialized fabric. Because every replica applies the same entries in
//! the same order, IPAM allocations are deterministic across the cluster.

use std::{
    collections::BTreeMap,
    fmt::Debug,
    io::Cursor,
    ops::RangeBounds,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Result, anyhow};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, LogState, OptionalSend, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StorageIOError, StoredMembership,
    Vote,
    storage::{LogFlushed, RaftLogStorage, RaftStateMachine},
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, watch};
use velstra_common::{parse_cidr_v4, parse_mac};
use velstra_config::{ActionName, EncapName};
use velstra_orchestrator::{Host, Network, Topology};

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
    },
    RemovePort {
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
    /// The created port, for `CreatePort`.
    pub port: Option<PortRecord>,
}

impl TopoResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            port: None,
        }
    }
    fn err(e: impl ToString) -> Self {
        Self {
            ok: false,
            error: Some(e.to_string()),
            port: None,
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

/// Apply one request to the fabric, producing its response. Pure given the
/// current `topo`, so it is deterministic across replicas. Exposed so the
/// controller can run the *same* mutation logic in its non-Raft single-node mode.
pub fn apply(topo: &mut Topology, req: &TopoRequest) -> TopoResponse {
    let outcome: Result<Option<PortRecord>> = (|| match req {
        TopoRequest::AddHost(s) => {
            topo.add_host(host_from_spec(s)?);
            Ok(None)
        }
        TopoRequest::AddNetwork(s) => {
            topo.add_network(network_from_spec(s)?)?;
            Ok(None)
        }
        TopoRequest::CreatePort { vni, host, tap, ip } => {
            let ip = match ip {
                Some(s) => Some(s.parse().map_err(|_| anyhow!("invalid ip {s:?}"))?),
                None => None,
            };
            let p = topo.create_port(*vni, host, tap, ip)?;
            Ok(Some(PortRecord {
                id: p.id,
                vni: p.vni,
                host: p.host,
                ip: p.ip.to_string(),
                mac: fmt_mac(p.mac),
                tap: p.tap,
            }))
        }
        TopoRequest::RemovePort { id } => {
            topo.remove_port(id);
            Ok(None)
        }
    })();
    match outcome {
        Ok(port) => TopoResponse {
            ok: true,
            error: None,
            port,
        },
        Err(e) => TopoResponse::err(e),
    }
}

// --- Log store --------------------------------------------------------------

#[derive(Debug, Default)]
struct LogInner {
    log: BTreeMap<u64, Entry<TypeConfig>>,
    last_purged: Option<LogId<NodeId>>,
    committed: Option<LogId<NodeId>>,
    vote: Option<Vote<NodeId>>,
}

/// In-memory Raft log store (durability comes from snapshots persisted by the
/// caller; the uncommitted log tail is volatile, which is acceptable for a
/// small control-plane cluster that re-replicates on restart).
#[derive(Clone, Debug, Default)]
pub struct LogStore {
    inner: Arc<Mutex<LogInner>>,
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
        self.inner.lock().await.vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(self.inner.lock().await.vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.inner.lock().await.committed = committed;
        Ok(())
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
        {
            let mut inner = self.inner.lock().await;
            for entry in entries {
                inner.log.insert(entry.log_id.index, entry);
            }
        }
        // The log is in memory, so it is "flushed" the moment it is inserted.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.log.split_off(&log_id.index); // drops [index, +oo)
        Ok(())
    }

    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let mut inner = self.inner.lock().await;
        inner.last_purged = Some(log_id);
        let keep = inner.log.split_off(&(log_id.index + 1)); // keep (index, +oo)
        inner.log = keep;
        Ok(())
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
}

impl Default for StateMachineStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SmInner::default())),
            snapshot_idx: Arc::new(AtomicU64::new(0)),
            changed: Arc::new(watch::channel(0).0),
        }
    }
}

impl StateMachineStore {
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
        self.inner.lock().await.current_snapshot = Some(StoredSnapshot {
            meta: meta.clone(),
            data: data.clone(),
        });
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
        {
            let mut inner = self.inner.lock().await;
            inner.topology = Topology::from_snapshot(&payload.fabric);
            inner.last_applied = meta.last_log_id;
            inner.last_membership = meta.last_membership.clone();
            inner.current_snapshot = Some(StoredSnapshot {
                meta: meta.clone(),
                data,
            });
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
