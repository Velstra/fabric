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
//! stats             → the per-CPU counter table, summed
//! flows [limit]     → the live NAT flow table (0 = all; default 100)
//! top [limit]       → hosts ranked by the traffic volume attributed to them
//! cgnat <ip>        → the WAN port block an internal address holds
//! blocks            → sources blocked at run time, and for how much longer
//! block <cidr> [s]  → block a source for a while (roadmap C11)
//! unblock <cidr>    → lift one early (`all` lifts every one)
//! ```
//!
//! Mostly read-only, and **nothing here can open anything**. `block` is the only
//! command that changes what the data plane does, and it can only ever add a
//! drop — there is no verb that admits traffic, lifts a configured block, or
//! alters the configuration. So the worst an unwanted caller achieves is denial
//! of service against an address, which is loud, visible in `blocks`, and expires
//! on its own; it can never be used to let something through. The socket is bound
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

/// How long a run-time block lasts when the caller names no duration.
const DEFAULT_BLOCK_SECS: u64 = 3600;

/// The longest a run-time block may last. A day is already far beyond "react to
/// what you just saw"; anything an operator wants to hold longer belongs in the
/// configuration, where it is written down and survives a restart on purpose.
const MAX_BLOCK_SECS: u64 = 86_400;

/// How often expired blocks are swept up. A block whose deadline passed must lift
/// itself without anyone asking — otherwise the deadline is only a promise kept
/// when someone happens to run `blocks`.
const BLOCK_SWEEP: std::time::Duration = std::time::Duration::from_secs(10);

/// Lift expired run-time blocks, forever. Spawned alongside [`serve`].
pub async fn expire_blocks_loop(firewall: Arc<Mutex<Firewall>>) {
    let mut tick = tokio::time::interval(BLOCK_SWEEP);
    loop {
        tick.tick().await;
        let lifted = firewall.lock().await.expire_blocks();
        if lifted > 0 {
            info!("lifted {lifted} expired run-time block(s)");
        }
    }
}

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
    // Collected rather than consumed one at a time: reading the limit off the
    // iterator here would swallow the argument every *other* verb needs, and the
    // resulting bug is silent — the command works, it just acts on the wrong
    // token.
    let args: Vec<&str> = tokens.collect();
    let limit = parse_limit(args.first().copied());
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
            let Some(addr) = args
                .first()
                .and_then(|t| t.parse::<std::net::Ipv4Addr>().ok())
                .map(|ip| ip.octets())
            else {
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
        // Run-time source blocks (roadmap C11): a detector acts on what it saw.
        // Every block carries a deadline — see `Firewall::expire_blocks` for why
        // an appliance must not be able to lock an address out indefinitely on
        // its own reading of a packet.
        "blocks" => {
            let mut fw = firewall.lock().await;
            fw.expire_blocks();
            let blocks = fw.runtime_blocks();
            if blocks.is_empty() {
                "no run-time blocks\n".to_string()
            } else {
                let mut out = String::new();
                for (cidr, secs) in blocks {
                    out.push_str(&format!("{cidr} blocked, {secs}s remaining\n"));
                }
                out
            }
        }
        "block" => {
            let Some(cidr) = args.first() else {
                return "usage: block <cidr> [seconds]\n".to_string();
            };
            let secs = args
                .get(1)
                .and_then(|t| t.parse::<u64>().ok())
                .unwrap_or(DEFAULT_BLOCK_SECS);
            if secs == 0 || secs > MAX_BLOCK_SECS {
                return format!("error: a block lasts 1..={MAX_BLOCK_SECS} seconds\n");
            }
            let mut fw = firewall.lock().await;
            match fw.block_source(cidr, std::time::Duration::from_secs(secs)) {
                Ok(true) => format!("blocked {cidr} for {secs}s\n"),
                // Not an error: the caller asked for an outcome that already
                // holds, and permanently. Saying so beats reporting success and
                // letting the expiry later switch the operator's block off.
                Ok(false) => {
                    format!("{cidr} is already blocked by the configuration; left as it is\n")
                }
                Err(e) => format!("error: blocking {cidr}: {e:#}\n"),
            }
        }
        "unblock" => {
            let Some(cidr) = args.first() else {
                return "usage: unblock <cidr|all>\n".to_string();
            };
            let mut fw = firewall.lock().await;
            // `all` exists for the false-positive storm: a rule that was too broad
            // blocks a dozen addresses in a minute, and lifting them one at a time
            // is exactly the wrong thing to be doing at that moment.
            if *cidr == "all" {
                match fw.unblock_all() {
                    Ok(0) => "no run-time blocks to lift\n".to_string(),
                    Ok(n) => format!("lifted {n} run-time block(s)\n"),
                    Err(e) => format!("error: lifting run-time blocks: {e:#}\n"),
                }
            } else {
                match fw.unblock_source(cidr) {
                    Ok(true) => format!("unblocked {cidr}\n"),
                    Ok(false) => format!("{cidr} is not blocked at run time\n"),
                    Err(e) => format!("error: unblocking {cidr}: {e:#}\n"),
                }
            }
        }
        "" => "usage: stats | flows [limit] | top [limit] | cgnat <ip> | blocks | \
               block <cidr> [seconds] | unblock <cidr>\n"
            .to_string(),
        other => {
            format!(
                "error: unknown query {other:?}; try: stats | flows | top | cgnat | \
                 blocks | block | unblock\n"
            )
        }
    }
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
