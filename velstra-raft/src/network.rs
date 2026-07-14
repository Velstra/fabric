//! The Raft network transport: a tiny gRPC service that carries openraft's RPCs
//! as serde-serialized bytes between controllers. The [`NetworkFactory`] is the
//! client side (openraft calls it to reach peers); [`RaftServer`] is the server
//! side (it hands incoming RPCs to the local [`Raft`]).

use std::{collections::HashSet, sync::Arc};

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
use tonic::{
    Request, Response, Status,
    transport::{Channel, ClientTlsConfig},
};

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
    /// The Common Names permitted to drive this node's Raft state (the other
    /// controllers). `None` disables the check — any peer the transport TLS already
    /// authenticated is accepted, matching the plaintext / single-CA deployments.
    /// `Some(set)` requires the caller's client-certificate CN to be listed, so a
    /// compromised agent that merely shares the cluster CA cannot inject
    /// AppendEntries/Vote and hijack consensus.
    allowed_cns: Option<Arc<HashSet<String>>>,
}

impl RaftServer {
    pub fn new(raft: Raft<TypeConfig>, allowed_cns: Option<Arc<HashSet<String>>>) -> Self {
        Self { raft, allowed_cns }
    }

    /// Reject an RPC whose client-certificate CN is not on the allowlist. A `None`
    /// allowlist accepts everyone (the check is off); a `Some` allowlist requires a
    /// peer certificate whose CN is listed.
    fn authorize<T>(&self, req: &Request<T>) -> Result<(), Status> {
        let Some(allowed) = &self.allowed_cns else {
            return Ok(());
        };
        let cn = peer_cn(req);
        if cn_permitted(allowed, cn.as_deref()) {
            Ok(())
        } else {
            Err(Status::permission_denied(match cn {
                Some(cn) => format!("raft peer CN {cn:?} is not an authorized controller"),
                None => "raft peer presented no client certificate".to_string(),
            }))
        }
    }
}

/// Whether a client CN is permitted by the allowlist: it must be present *and*
/// listed. An absent CN (no client certificate) is never permitted once an
/// allowlist is in force.
fn cn_permitted(allowed: &HashSet<String>, cn: Option<&str>) -> bool {
    cn.is_some_and(|cn| allowed.contains(cn))
}

/// The subject Common Name of the request's client (leaf) certificate, if the
/// transport carried one.
fn peer_cn<T>(req: &Request<T>) -> Option<String> {
    let certs = req.peer_certs()?;
    let leaf = certs.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_string)
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
        self.authorize(&req)?;
        let rpc: AppendEntriesRequest<TypeConfig> = decode(&req.into_inner())?;
        let resp = self
            .raft
            .append_entries(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        encode(&resp)
    }

    async fn vote(&self, req: Request<RaftMsg>) -> Result<Response<RaftMsg>, Status> {
        self.authorize(&req)?;
        let rpc: VoteRequest<NodeId> = decode(&req.into_inner())?;
        let resp = self
            .raft
            .vote(rpc)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        encode(&resp)
    }

    async fn snapshot(&self, req: Request<RaftMsg>) -> Result<Response<RaftMsg>, Status> {
        self.authorize(&req)?;
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

/// Build the tonic service for a Raft instance, restricting incoming RPCs to the
/// controller CNs in `allowed_cns` (or accepting any TLS-authenticated peer when
/// `None`).
pub fn service(
    raft: Raft<TypeConfig>,
    allowed_cns: Option<Arc<HashSet<String>>>,
) -> RaftServiceServer {
    RaftServiceServer::new(RaftServer::new(raft, allowed_cns))
}

// --- Client side ------------------------------------------------------------

/// Creates a [`Network`] client per peer on demand. Carries the optional client
/// TLS config so peer connections use the **same** TLS/mTLS as the agent/admin
/// channels instead of plaintext (C5).
#[derive(Clone, Default)]
pub struct NetworkFactory {
    tls: Option<ClientTlsConfig>,
}

impl NetworkFactory {
    /// A factory that dials peers with `tls` (mTLS when the config carries a
    /// client identity); `None` keeps the legacy plaintext transport (dev /
    /// single-node / trusted network).
    pub fn new(tls: Option<ClientTlsConfig>) -> Self {
        Self { tls }
    }
}

impl RaftNetworkFactory<TypeConfig> for NetworkFactory {
    type Network = Network;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        Network {
            target,
            addr: node.addr.clone(),
            tls: self.tls.clone(),
            channel: None,
        }
    }
}

/// A connection to one peer. Lazily dials and caches the channel.
pub struct Network {
    target: NodeId,
    addr: String,
    tls: Option<ClientTlsConfig>,
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
            // Match the scheme to the transport: https when TLS is configured so
            // AppendEntries/Vote/InstallSnapshot can't be injected in the clear.
            let scheme = if self.tls.is_some() { "https" } else { "http" };
            let endpoint = format!("{scheme}://{}", self.addr);
            let mut ep = Channel::from_shared(endpoint).map_err(unreachable)?;
            if let Some(tls) = &self.tls {
                ep = ep.tls_config(tls.clone()).map_err(unreachable)?;
            }
            let channel = ep.connect().await.map_err(unreachable)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cn_allowlist_admits_only_listed_controllers() {
        let allowed: HashSet<String> = ["ctrl-a".to_string(), "ctrl-b".to_string()]
            .into_iter()
            .collect();
        // A listed controller passes.
        assert!(cn_permitted(&allowed, Some("ctrl-a")));
        assert!(cn_permitted(&allowed, Some("ctrl-b")));
        // A compromised agent that merely shares the CA (its own CN) is rejected.
        assert!(!cn_permitted(&allowed, Some("agent-node-7")));
        // No client certificate is never admitted once an allowlist is in force.
        assert!(!cn_permitted(&allowed, None));
        // An empty allowlist admits nothing (callers use `None` to disable instead).
        assert!(!cn_permitted(&HashSet::new(), Some("ctrl-a")));
    }
}
