//! A local **query socket** for the running agent (roadmap C23).
//!
//! The agent owns the eBPF maps, so it is the only process that can answer "what
//! is this firewall doing right now". Until this existed the only way to see the
//! counters was to scrape them out of the agent's journal — which meant the answer
//! depended on `--stats-interval` having been set, on log retention, and on
//! whatever the last dump happened to contain. The flow table could not be seen at
//! all.
//!
//! A Unix socket with a one-line request/response protocol, mirroring the control
//! socket the co-located Wren daemon exposes:
//!
//! ```text
//! stats          → the per-CPU counter table, summed
//! flows [limit]  → the live NAT flow table (0 = all; default 100)
//! top [limit]    → source addresses ranked by live connection count
//! ```
//!
//! Read-only by construction: there is no command that changes anything, so
//! exposing it cannot become a way to reconfigure the data plane. It is bound
//! wherever the caller says (a root-owned `/run` directory in the appliance), and
//! the socket's directory is what governs who may ask.

use std::{path::PathBuf, sync::Arc};

use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

use crate::{
    firewall::Firewall,
    flows::{render_flows, render_top_talkers},
};

/// How many flows `flows` returns when the caller names no limit. A full table can
/// be tens of thousands of entries; a default dump should be readable, and asking
/// for `flows 0` is the explicit way to say "all of it".
const DEFAULT_FLOW_LIMIT: usize = 100;

/// Serve the query socket at `path` until the process ends.
///
/// A stale socket file from a previous run is removed first: the agent is
/// restarted far more often than the path changes, and refusing to start because
/// yesterday's socket file is still there would be a self-inflicted outage.
pub async fn serve(path: PathBuf, firewall: Arc<Mutex<Firewall>>) {
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            // Diagnostics must never take the data plane with them.
            warn!("query socket {} unavailable: {e}", path.display());
            return;
        }
    };
    info!("query socket listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let fw = firewall.clone();
                tokio::spawn(async move { handle(stream, fw).await });
            }
            Err(e) => {
                warn!("query socket accept failed: {e}");
                return;
            }
        }
    }
}

/// Answer one request. Errors are reported to the caller as text rather than
/// logged and dropped — someone is waiting on this socket for an answer.
async fn handle(stream: UnixStream, firewall: Arc<Mutex<Firewall>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let reply = respond(line.trim(), &firewall).await;
    let _ = reader.get_mut().write_all(reply.as_bytes()).await;
}

/// Dispatch one command to its rendering.
async fn respond(line: &str, firewall: &Arc<Mutex<Firewall>>) -> String {
    let mut tokens = line.split_whitespace();
    let verb = tokens.next().unwrap_or("");
    let limit = parse_limit(tokens.next());
    match verb {
        "stats" => {
            let fw = firewall.lock().await;
            match fw.read_stats() {
                Ok(stats) => stats.render(),
                Err(e) => format!("error: reading statistics: {e:#}\n"),
            }
        }
        "flows" | "top" => {
            let mut fw = firewall.lock().await;
            match fw.read_flows().await {
                Ok(flows) => {
                    if verb == "flows" {
                        render_flows(&flows, limit.unwrap_or(DEFAULT_FLOW_LIMIT))
                    } else {
                        render_top_talkers(&flows, limit.unwrap_or(10))
                    }
                }
                Err(e) => format!("error: reading the flow table: {e:#}\n"),
            }
        }
        // Deterministic CGNAT (C16): which WAN ports an internal address holds.
        // Answered by the agent rather than by the CLI so the reply comes from the
        // *same* arithmetic the data plane hands ports out with — a second
        // implementation would eventually name the wrong subscriber.
        "cgnat" => {
            let Some(addr) = tokens_addr(line) else {
                return "usage: cgnat <internal-ipv4>\n".to_string();
            };
            let fw = firewall.lock().await;
            match fw.cgnat_blocks(addr) {
                Ok(blocks) if blocks.is_empty() => {
                    "no interface is configured with cgnat port blocks\n".to_string()
                }
                Ok(blocks) => {
                    let mut out = String::new();
                    for (iface, first, last) in blocks {
                        let a = addr;
                        out.push_str(&format!(
                            "{}.{}.{}.{} -> ports {first}-{last} on {iface}\n",
                            a[0], a[1], a[2], a[3]
                        ));
                    }
                    out
                }
                Err(e) => format!("error: reading the cgnat layout: {e:#}\n"),
            }
        }
        "" => "usage: stats | flows [limit] | top [limit] | cgnat <ip>\n".to_string(),
        other => {
            format!("error: unknown query {other:?}; try: stats | flows | top | cgnat\n")
        }
    }
}

/// The IPv4 argument of a `cgnat <ip>` query, as network-order octets.
fn tokens_addr(line: &str) -> Option<[u8; 4]> {
    line.split_whitespace()
        .nth(1)?
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|ip| ip.octets())
}

/// Parse an optional limit argument. An unparseable one yields `None` (the
/// default) rather than an error: a diagnostics command should answer with
/// something useful instead of arguing about its arguments.
fn parse_limit(token: Option<&str>) -> Option<usize> {
    token.and_then(|t| t.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_is_optional_and_a_bad_one_falls_back() {
        assert_eq!(parse_limit(None), None);
        assert_eq!(parse_limit(Some("25")), Some(25));
        // Explicitly "all", which the renderers take as no cap.
        assert_eq!(parse_limit(Some("0")), Some(0));
        // Garbage means "you get the default", not an error page.
        assert_eq!(parse_limit(Some("lots")), None);
        assert_eq!(parse_limit(Some("-3")), None);
    }
}
