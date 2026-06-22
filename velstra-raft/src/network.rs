//! The Raft network transport: a tiny gRPC service that carries openraft's RPCs
//! as serde-serialized bytes between controllers. The [`NetworkFactory`] is the
//! client side (openraft calls it to reach peers); [`RaftServer`] is the server
//! side (it hands incoming RPCs to the local [`Raft`]).

use anyhow::Result;
use openraft::{
    BasicNode, Raft,
    error::{InstallSnapshotError, RPCError, RaftError, Unreachable},
    network::{RPCOption, RaftNetwork, RaftNetworkFactory},
    raft::{
        AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest,
        InstallSnapshotResponse, VoteRequest, VoteResponse,
    },
};
use tonic::{Request, Response, Status, transport::Channel};

use crate::store::{NodeId, TypeConfig};

pub mod pb {
    #![allow(clippy::all)]
    tonic::include_proto!("velstra.raft.v1");
}

use pb::{RaftMsg, raft_service_client::RaftServiceClient, raft_service_server::RaftService};

/// Server side: turns incoming gRPC bytes back into openraft RPCs and applies
/// them to the local Raft instance.
pub struct RaftServer {
    raft: Raft<TypeConfig>,
}

impl RaftServer {
    pub fn new(raft: Raft<TypeConfig>) -> Self {
        Self { raft }
    }
}

fn decode<T: serde::de::DeserializeOwned>(msg: &RaftMsg) -> Result<T, Status> {
    serde_json::from_slice(&msg.data).map_err(|e| Status::invalid_argument(e.to_string()))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Response<RaftMsg>, Status> {
    let data = serde_json::to_vec(value).map_err(|e| Status::internal(e.to_string()))?;
    Ok(Response::new(RaftMsg { data }))
}

#[tonic::async_trait]
impl RaftService for RaftServer {
    async fn append(&self, req: Request<RaftMsg>) -> Result<Response<RaftMsg>, Status> {
        let rpc: AppendEntriesRequest<TypeConfig> = decode(&req.into_inner())?;
        let resp = self
            .raft
            .append_entries(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        encode(&resp)
    }

    async fn vote(&self, req: Request<RaftMsg>) -> Result<Response<RaftMsg>, Status> {
        let rpc: VoteRequest<NodeId> = decode(&req.into_inner())?;
        let resp = self
            .raft
            .vote(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        encode(&resp)
    }

    async fn snapshot(&self, req: Request<RaftMsg>) -> Result<Response<RaftMsg>, Status> {
        let rpc: InstallSnapshotRequest<TypeConfig> = decode(&req.into_inner())?;
        let resp = self
            .raft
            .install_snapshot(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        encode(&resp)
    }
}

/// The gRPC server type the controller mounts on its raft port.
pub type RaftServiceServer = pb::raft_service_server::RaftServiceServer<RaftServer>;

/// Build the tonic service for a Raft instance.
pub fn service(raft: Raft<TypeConfig>) -> RaftServiceServer {
    RaftServiceServer::new(RaftServer::new(raft))
}

// --- Client side ------------------------------------------------------------

/// Creates a [`Network`] client per peer on demand.
#[derive(Clone)]
pub struct NetworkFactory;

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = Network;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        Network {
            target,
            addr: node.addr.clone(),
            channel: None,
        }
    }
}

/// A connection to one peer. Lazily dials and caches the channel.
pub struct Network {
    target: NodeId,
    addr: String,
    channel: Option<Channel>,
}

impl Network {
    async fn client<E>(
        &mut self,
    ) -> Result<RaftServiceClient<Channel>, RPCError<NodeId, BasicNode, E>>
    where
        E: std::error::Error,
    {
        if self.channel.is_none() {
            let endpoint = format!("http://{}", self.addr);
            let channel = Channel::from_shared(endpoint)
                .map_err(unreachable)?
                .connect()
                .await
                .map_err(unreachable)?;
            self.channel = Some(channel);
        }
        Ok(RaftServiceClient::new(self.channel.clone().unwrap()))
    }
}

fn unreachable<E, RE>(e: E) -> RPCError<NodeId, BasicNode, RE>
where
    E: std::error::Error + 'static,
    RE: std::error::Error,
{
    // Drop the cached channel implicitly by reporting unreachable; openraft retries.
    RPCError::Unreachable(Unreachable::new(&e))
}

impl RaftNetwork<TypeConfig> for Network {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let data = serde_json::to_vec(&rpc).map_err(unreachable)?;
        let mut client = self.client().await?;
        let reply = client
            .append(RaftMsg { data })
            .await
            .map_err(|e| {
                self.channel = None;
                unreachable(e)
            })?
            .into_inner();
        serde_json::from_slice(&reply.data).map_err(unreachable)
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let data = serde_json::to_vec(&rpc).map_err(unreachable)?;
        let mut client = self.client().await?;
        let reply = client
            .vote(RaftMsg { data })
            .await
            .map_err(|e| {
                self.channel = None;
                unreachable(e)
            })?
            .into_inner();
        serde_json::from_slice(&reply.data).map_err(unreachable)
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let data = serde_json::to_vec(&rpc).map_err(unreachable)?;
        let mut client = self.client().await?;
        let reply = client
            .snapshot(RaftMsg { data })
            .await
            .map_err(|e| {
                self.channel = None;
                unreachable(e)
            })?
            .into_inner();
        serde_json::from_slice(&reply.data).map_err(unreachable)
    }
}

// Silence "field is never read" for `target` (kept for diagnostics/log context).
impl Network {
    #[allow(dead_code)]
    fn target(&self) -> NodeId {
        self.target
    }
}
