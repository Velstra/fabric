//! gRPC client to the controller's `VelstraOrchestrator` service: create and
//! remove the fabric port that backs a pod.
//!
//! In controller-integrated mode the controller (its Raft leader) is the source
//! of truth for IP/MAC allocation. On `ADD` we call [`create_port`]; the leader
//! allocates the address, replicates it through Raft, and on the next derive
//! pushes the agent on *this* node an `[[interface]]` binding for the pod veth —
//! which is what attaches the XDP firewall/LB. On `DEL` we call [`remove_port`].
//!
//! Writes must reach the leader. We try the configured endpoints in order;
//! followers reject a write with a redirect [`tonic::Status`], so we simply move
//! on to the next endpoint until one (the leader) accepts.

use std::{future::Future, path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use velstra_proto::{
    CreatePortRequest, PortInfo, RemovePortRequest,
    velstra_orchestrator_client::VelstraOrchestratorClient,
};

/// TLS settings for the controller (orchestrator) channel.
#[derive(Clone, Debug)]
pub struct TlsOptions {
    /// PEM CA certificate used to verify the controller.
    pub ca: PathBuf,
    /// Client certificate + key for mutual TLS (both or neither).
    pub client_cert: Option<PathBuf>,
    pub client_key: Option<PathBuf>,
    /// Server name to validate against the controller's certificate.
    pub domain: Option<String>,
}

/// The port the controller allocated for a pod.
#[derive(Debug, Clone)]
pub struct AllocatedPort {
    pub id: String,
    /// Inner IPv4 address, e.g. `"10.244.0.5"`.
    pub ip: String,
    /// MAC, e.g. `"02:00:0a:f4:00:05"` — the pod interface must wear this so the
    /// overlay's ARP suppression (which answers with this MAC) routes to it.
    pub mac: String,
}

/// Build a current-thread runtime and run `fut` to completion. The CNI is a
/// one-shot process, so a runtime per invocation is fine.
fn block_on<F: Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building tokio runtime")
        .block_on(fut)
}

/// Build an (optionally TLS-secured) channel to a controller endpoint.
async fn connect(endpoint: &str, tls: &Option<TlsOptions>) -> Result<Channel> {
    let mut ep: Endpoint = Channel::from_shared(endpoint.to_string())
        .context("invalid controller endpoint")?
        .connect_timeout(Duration::from_secs(5));

    if let Some(tls) = tls {
        let ca = std::fs::read(&tls.ca).with_context(|| format!("reading {}", tls.ca.display()))?;
        let mut cfg = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca));
        if let (Some(cert), Some(key)) = (&tls.client_cert, &tls.client_key) {
            let identity = Identity::from_pem(
                std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?,
                std::fs::read(key).with_context(|| format!("reading {}", key.display()))?,
            );
            cfg = cfg.identity(identity);
        }
        if let Some(domain) = &tls.domain {
            cfg = cfg.domain_name(domain.clone());
        }
        ep = ep.tls_config(cfg).context("client TLS config")?;
    }

    ep.connect()
        .await
        .with_context(|| format!("connecting to controller {endpoint}"))
}

/// Try each endpoint in order until one accepts; collect the last error so a
/// total failure reports why. `f` runs one attempt against a connected client.
async fn on_first_leader<T, F, Fut>(
    endpoints: &[String],
    tls: &Option<TlsOptions>,
    f: F,
) -> Result<T>
where
    F: Fn(VelstraOrchestratorClient<Channel>) -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut last_err = None;
    for endpoint in endpoints {
        match connect(endpoint, tls).await {
            Ok(channel) => match f(VelstraOrchestratorClient::new(channel)).await {
                Ok(value) => return Ok(value),
                Err(e) => last_err = Some(anyhow!("{endpoint}: {e}")),
            },
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no controller endpoints configured")))
}

/// Create the port backing a pod on the first controller that accepts the write
/// (the leader), allocating an IP/MAC (or pinning `ip` if given).
pub fn create_port(
    endpoints: &[String],
    tls: &Option<TlsOptions>,
    vni: u32,
    host: &str,
    tap: &str,
    ip: Option<&str>,
) -> Result<AllocatedPort> {
    block_on(on_first_leader(endpoints, tls, |mut client| {
        let req = CreatePortRequest {
            network: vni,
            host: host.to_string(),
            tap: tap.to_string(),
            ip: ip.unwrap_or_default().to_string(),
        };
        async move {
            let info: PortInfo = client
                .create_port(req)
                .await
                .map_err(|e| anyhow!("CreatePort: {e}"))?
                .into_inner();
            Ok(AllocatedPort {
                id: info.id,
                ip: info.ip,
                mac: info.mac,
            })
        }
    }))
}

/// Remove the port backing a pod by id. Idempotent on the controller side.
pub fn remove_port(endpoints: &[String], tls: &Option<TlsOptions>, id: &str) -> Result<()> {
    block_on(on_first_leader(endpoints, tls, |mut client| {
        let req = RemovePortRequest { id: id.to_string() };
        async move {
            client
                .remove_port(req)
                .await
                .map_err(|e| anyhow!("RemovePort: {e}"))?;
            Ok(())
        }
    }))
}
