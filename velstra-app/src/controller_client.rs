//! gRPC client: fetch this node's config from the controller, watch for live
//! updates, and report statistics back — optionally over (m)TLS.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use tonic::{
    Streaming,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
use velstra_proto::{
    Counter as ProtoCounter, HostSpec, NodeConfig, NodeRequest, StatsReport,
    velstra_control_client::VelstraControlClient,
    velstra_orchestrator_client::VelstraOrchestratorClient,
};

use crate::firewall::Stats;

/// TLS settings for the controller connection.
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

/// Build a (optionally TLS-secured) channel to the controller.
async fn connect(endpoint: &str, tls: &Option<TlsOptions>) -> Result<Channel> {
    let mut ep: Endpoint =
        Channel::from_shared(endpoint.to_string()).context("invalid controller endpoint")?;

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

/// Open a `WatchConfig` stream for `node_id` against the **first reachable**
/// controller in `endpoints`, returning the stream and which endpoint answered.
/// Config reads are served by any cluster member (leader or follower), so the
/// agent simply uses whichever controller is up — this is its HA failover.
pub async fn watch_any(
    endpoints: &[String],
    node_id: &str,
    tls: &Option<TlsOptions>,
) -> Result<(Streaming<NodeConfig>, String)> {
    let mut last_err = None;
    for endpoint in endpoints {
        match connect(endpoint, tls).await {
            Ok(channel) => {
                let mut client = VelstraControlClient::new(channel);
                match client
                    .watch_config(NodeRequest {
                        node_id: node_id.to_string(),
                    })
                    .await
                {
                    Ok(resp) => return Ok((resp.into_inner(), endpoint.clone())),
                    Err(e) => last_err = Some(anyhow!("{endpoint}: WatchConfig RPC: {e}")),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no controller endpoints configured")))
}

/// Register (or replace) this node's Host (VTEP) with the controller, trying
/// each orchestrator endpoint until the leader accepts (followers redirect, so
/// we move on). `AddHost` is replace-idempotent, so re-registration is safe.
pub async fn register_host(
    endpoints: &[String],
    tls: &Option<TlsOptions>,
    spec: &HostSpec,
) -> Result<()> {
    let mut last_err = None;
    for endpoint in endpoints {
        match connect(endpoint, tls).await {
            Ok(channel) => {
                let mut client = VelstraOrchestratorClient::new(channel);
                match client.add_host(spec.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(e) => last_err = Some(anyhow!("{endpoint}: AddHost: {e}")),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("no orchestrator endpoints configured")))
}

/// A client for pushing periodic statistics back to the controller.
pub struct Reporter {
    client: VelstraControlClient<Channel>,
    node_id: String,
}

impl Reporter {
    /// Connect a reporter to the first reachable controller in `endpoints`.
    pub async fn connect_any(
        endpoints: &[String],
        node_id: String,
        tls: &Option<TlsOptions>,
    ) -> Result<Self> {
        let mut last_err = None;
        for endpoint in endpoints {
            match connect(endpoint, tls).await {
                Ok(channel) => {
                    return Ok(Self {
                        client: VelstraControlClient::new(channel),
                        node_id,
                    });
                }
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("no controller endpoints configured")))
    }

    /// Send the current per-counter statistics to the controller.
    pub async fn report(&mut self, stats: &Stats) -> Result<()> {
        let counters = stats
            .rows
            .iter()
            .map(|(counter, value)| ProtoCounter {
                name: counter.label().to_string(),
                value: *value,
            })
            .collect();
        self.client
            .report_stats(StatsReport {
                node_id: self.node_id.clone(),
                counters,
            })
            .await
            .context("ReportStats RPC")?;
        Ok(())
    }
}
