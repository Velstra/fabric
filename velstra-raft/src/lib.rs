//! # velstra-raft
//!
//! Embedded Raft consensus for the Velstra controllers (Track D). The replicated
//! state machine **is** the orchestrator [`Topology`] (see [`store`]): a committed
//! fabric mutation is applied, in log order, on every controller, so they all hold
//! one consistent fabric — no split brain, no external datastore, no message
//! queue. The leader accepts writes ([`RaftNode::propose`]); followers replicate
//! and apply.
//!
//! Peers talk over a tiny gRPC transport ([`network`]) that carries openraft's
//! RPCs as serialized bytes, so a controller mounts [`RaftNode::service`] on its
//! raft port and the cluster forms over normal gRPC.
//!
//! [`Topology`]: velstra_orchestrator::Topology

use std::{collections::BTreeMap, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use openraft::{BasicNode, Config, Raft, ServerState, SnapshotPolicy};
use tokio::sync::watch;
use tonic::transport::ClientTlsConfig;
use velstra_orchestrator::Topology;

pub mod network;
pub mod store;

use network::NetworkFactory;
pub use network::{RaftServiceServer, service};
pub use store::{
    HostSpec, NetworkSpec, NodeId, PortRecord, TopoRequest, TopoResponse, TypeConfig, apply,
};
use store::{LogStore, StateMachineStore};

/// A running Raft node wrapping an orchestrator topology state machine.
pub struct RaftNode {
    /// The underlying openraft instance.
    pub raft: Raft<TypeConfig>,
    sm: StateMachineStore,
    /// This node's id.
    pub id: NodeId,
}

fn raft_config() -> Result<Arc<Config>> {
    let config = Config {
        cluster_name: "velstra".to_string(),
        heartbeat_interval: 250,
        election_timeout_min: 500,
        election_timeout_max: 1000,
        // The Raft log is in-memory only; durability comes exclusively from
        // persisted snapshots. openraft's default policy snapshots every 5000
        // committed logs, so a fabric with fewer mutations than that since the
        // last snapshot would lose its ENTIRE topology on a full-cluster restart.
        // Snapshot far more eagerly, and also on graceful shutdown (see
        // RaftNode::shutdown), so `--raft-dir` actually protects the topology.
        snapshot_policy: SnapshotPolicy::LogsSinceLast(100),
        ..Default::default()
    }
    .validate()?;
    Ok(Arc::new(config))
}

impl RaftNode {
    /// Start a Raft instance with the gRPC peer network, keeping all state in
    /// memory (no snapshot durability). Not yet a member of any cluster — call
    /// [`RaftNode::bootstrap`] on exactly one node to form it.
    pub async fn start(id: NodeId) -> Result<Self> {
        Self::start_with_dir(id, None).await
    }

    /// Like [`RaftNode::start`], but persisting snapshots under `dir` (created if
    /// missing) and resuming from one already there. This gives the cluster
    /// durability across a full restart: every controller reloads the last
    /// snapshot — the committed fabric — instead of coming up empty.
    pub async fn start_with_dir(id: NodeId, dir: Option<PathBuf>) -> Result<Self> {
        Self::start_with_opts(id, dir, None).await
    }

    /// Like [`RaftNode::start_with_dir`], but dialing peers with `client_tls`
    /// (the same TLS/mTLS material as the agent/admin channels) so the Raft peer
    /// transport is encrypted+authenticated rather than plaintext (C5). `None`
    /// keeps the plaintext transport for dev / single-node / trusted networks.
    pub async fn start_with_opts(
        id: NodeId,
        dir: Option<PathBuf>,
        client_tls: Option<ClientTlsConfig>,
    ) -> Result<Self> {
        let loaded = match &dir {
            Some(d) => {
                std::fs::create_dir_all(d)
                    .map_err(|e| anyhow!("creating raft dir {}: {e}", d.display()))?;
                store::load_snapshot(d)?
            }
            None => None,
        };
        // Seed the (volatile) log's purge point so its reported last_log_id lines
        // up with the state machine's restored last_applied.
        let last_purged = loaded.as_ref().and_then(|s| s.meta.last_log_id);
        let log = LogStore::new(last_purged);
        let sm = StateMachineStore::new(dir, loaded)?;
        let raft =
            Raft::new(id, raft_config()?, NetworkFactory::new(client_tls), log, sm.clone()).await?;
        Ok(Self { raft, sm, id })
    }

    /// The gRPC service to mount on this node's raft listen address so peers can
    /// reach it.
    pub fn service(&self) -> RaftServiceServer {
        service(self.raft.clone())
    }

    /// Initialise the cluster with `members` (`id -> raft address`). Run this on
    /// exactly one node, once; all listed members must already be serving their
    /// raft service. A single-element map forms a one-node cluster.
    pub async fn bootstrap(&self, members: BTreeMap<NodeId, String>) -> Result<()> {
        let members: BTreeMap<NodeId, BasicNode> = members
            .into_iter()
            .map(|(id, addr)| (id, BasicNode::new(addr)))
            .collect();
        self.raft
            .initialize(members)
            .await
            .map_err(|e| anyhow!("initialize: {e}"))?;
        Ok(())
    }

    /// Block until this node is the leader (or `timeout` elapses).
    pub async fn wait_leader(&self, timeout: Duration) -> Result<()> {
        self.raft
            .wait(Some(timeout))
            .state(ServerState::Leader, "become leader")
            .await
            .map_err(|e| anyhow!("waiting for leadership: {e}"))?;
        Ok(())
    }

    /// The id of the node this one currently believes is leader, if any.
    pub fn current_leader(&self) -> Option<NodeId> {
        self.raft.metrics().borrow().current_leader
    }

    /// Whether this node is the current leader.
    pub fn is_leader(&self) -> bool {
        self.current_leader() == Some(self.id)
    }

    /// Propose a fabric mutation through Raft. On the leader it replicates and
    /// applies the request and returns its response; on a follower it errors with
    /// a redirect to the leader (see [`RaftNode::current_leader`]).
    pub async fn propose(&self, req: TopoRequest) -> Result<TopoResponse> {
        let resp = self
            .raft
            .client_write(req)
            .await
            .map_err(|e| anyhow!("client_write: {e}"))?;
        Ok(resp.data)
    }

    /// A clone of the current applied topology (for deriving per-host configs).
    pub async fn topology(&self) -> Topology {
        self.sm.topology().await
    }

    /// Subscribe to "the applied topology changed" notifications.
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.sm.subscribe()
    }

    /// Gracefully stop the Raft instance. Triggers a final snapshot first (best
    /// effort) so the committed topology is persisted before exit rather than
    /// relying on the periodic snapshot policy having fired recently.
    pub async fn shutdown(&self) -> Result<()> {
        // Only the leader can build a snapshot; on followers/errors this is a
        // no-op we intentionally ignore, since their state is reconstructed from
        // the leader on restart.
        let _ = self.raft.trigger().snapshot().await;
        self.raft
            .shutdown()
            .await
            .map_err(|e| anyhow!("shutdown: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use velstra_config::{ActionName, EncapName};

    use super::*;

    fn host_spec(id: &str, vtep: &str, mac: &str) -> HostSpec {
        HostSpec {
            id: id.into(),
            vtep: vtep.into(),
            underlay_iface: "eth0".into(),
            underlay_mac: mac.into(),
            encap: EncapName::Vxlan,
            udp_port: None,
            underlay_mtu: None,
        }
    }

    /// Spawn a node's gRPC raft server on `addr` and return immediately.
    async fn spawn_server(node: &RaftNode, addr: std::net::SocketAddr) {
        let svc = node.service();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(svc)
                .serve(addr)
                .await;
        });
    }

    #[tokio::test]
    async fn three_node_cluster_replicates_a_port_to_all_members() {
        // Three nodes, each with a raft gRPC server on a localhost port.
        let addrs = ["127.0.0.1:24021", "127.0.0.1:24022", "127.0.0.1:24023"];
        let mut nodes = Vec::new();
        for (i, addr) in addrs.iter().enumerate() {
            let node = RaftNode::start(i as u64 + 1).await.unwrap();
            spawn_server(&node, addr.parse().unwrap()).await;
            nodes.push(node);
        }
        // Give the servers a moment to bind.
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Form the 3-node cluster from node 1.
        let members: BTreeMap<NodeId, String> = addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (i as u64 + 1, a.to_string()))
            .collect();
        nodes[0].bootstrap(members).await.unwrap();

        // Wait for a leader to emerge.
        let mut leader = None;
        for _ in 0..50 {
            if let Some(l) = nodes[0].current_leader() {
                leader = Some(l);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let leader_id = leader.expect("a leader was elected");
        let leader = nodes.iter().find(|n| n.id == leader_id).unwrap();

        // Write a host, a network, and a port on the leader.
        assert!(
            leader
                .propose(TopoRequest::AddHost(host_spec(
                    "h1",
                    "10.10.0.1",
                    "02:00:00:00:00:11"
                )))
                .await
                .unwrap()
                .ok
        );
        assert!(
            leader
                .propose(TopoRequest::AddNetwork(NetworkSpec {
                    vni: 5000,
                    name: "blue".into(),
                    subnet: "192.168.100.0/24".into(),
                    default_action: ActionName::Pass,
                    drop_icmp: false,
                }))
                .await
                .unwrap()
                .ok
        );
        let port = leader
            .propose(TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            })
            .await
            .unwrap();
        assert!(port.ok, "create_port failed: {:?}", port.error);

        // Every node — leader and followers — must converge on the same port.
        for node in &nodes {
            let mut ok = false;
            for _ in 0..50 {
                let topo = node.topology().await;
                if topo.ports().len() == 1 && topo.ports()[0].ip.to_string() == "192.168.100.1" {
                    ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(ok, "node {} never received the replicated port", node.id);
        }
    }

    #[tokio::test]
    async fn snapshot_persists_and_reloads_across_a_restart() {
        // A unique scratch dir for this node's persisted snapshots.
        let dir =
            std::env::temp_dir().join(format!("velstra-raft-durability-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // First boot: a single-node cluster, write a fabric, snapshot it, stop.
        {
            let node = RaftNode::start_with_dir(1, Some(dir.clone()))
                .await
                .unwrap();
            let mut members = BTreeMap::new();
            members.insert(1u64, "127.0.0.1:24031".to_string());
            node.bootstrap(members).await.unwrap();
            node.wait_leader(Duration::from_secs(5)).await.unwrap();

            node.propose(TopoRequest::AddHost(host_spec(
                "h1",
                "10.10.0.1",
                "02:00:00:00:00:11",
            )))
            .await
            .unwrap();
            node.propose(TopoRequest::AddNetwork(NetworkSpec {
                vni: 5000,
                name: "blue".into(),
                subnet: "192.168.100.0/24".into(),
                default_action: ActionName::Pass,
                drop_icmp: false,
            }))
            .await
            .unwrap();
            node.propose(TopoRequest::CreatePort {
                vni: 5000,
                host: "h1".into(),
                tap: "tapA".into(),
                ip: None,
                policy: None,
            })
            .await
            .unwrap();

            // Force a snapshot and wait for it to be built and persisted.
            node.raft.trigger().snapshot().await.unwrap();
            let mut built = false;
            for _ in 0..50 {
                if node.raft.metrics().borrow().snapshot.is_some() {
                    built = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(built, "snapshot was never built");
            node.shutdown().await.unwrap();
        }

        // The snapshot file must exist on disk.
        assert!(
            dir.join("snapshot.json").exists(),
            "no snapshot file was persisted"
        );

        // Second boot from the same dir: the fabric is restored without any peer.
        let node = RaftNode::start_with_dir(1, Some(dir.clone()))
            .await
            .unwrap();
        let topo = node.topology().await;
        assert_eq!(topo.ports().len(), 1, "port did not survive the restart");
        assert_eq!(topo.ports()[0].ip.to_string(), "192.168.100.1");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
