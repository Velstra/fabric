//! gRPC client: fetch this node's config from the controller, watch for live
//! updates, and report statistics back — optionally over (m)TLS.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tonic::{
    Streaming,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity},
};
use velstra_proto::{
    Counter as ProtoCounter, NodeConfig, NodeRequest, StatsReport,
    velstra_control_client::VelstraControlClient,
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

/// Open a `WatchConfig` stream for `node_id`. The first message is the current
/// config; each subsequent message is a fresh config the controller pushed.
pub async fn watch(
    endpoint: String,
    node_id: String,
    tls: Option<TlsOptions>,
) -> Result<Streaming<NodeConfig>> {
    let mut client = VelstraControlClient::new(connect(&endpoint, &tls).await?);
    let stream = client
        .watch_config(NodeRequest { node_id })
        .await
        .context("WatchConfig RPC")?
        .into_inner();
    Ok(stream)
}

/// A client for pushing periodic statistics back to the controller.
pub struct Reporter {
    client: VelstraControlClient<Channel>,
    node_id: String,
}

impl Reporter {
    /// Connect a reporter (a separate channel from the config watch stream).
    pub async fn connect(
        endpoint: String,
        node_id: String,
        tls: Option<TlsOptions>,
    ) -> Result<Self> {
        let client = VelstraControlClient::new(connect(&endpoint, &tls).await?);
        Ok(Self { client, node_id })
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
