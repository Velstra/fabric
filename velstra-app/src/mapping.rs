//! C18 — the **mapping socket**: where a NAT-PMP/PCP request becomes a port
//! forward, for a while.
//!
//! The third socket, and a third blast radius. The query socket can only ever
//! add a drop; the portal socket can move a device from held-at-the-gate to
//! subject-to-the-rules; this one opens an **inbound port**. They are separate
//! files with separate permissions precisely because those are three different
//! amounts of trust, and a service that needs one should not be handed the
//! others.
//!
//! ```text
//! mappings                                → what is open, and for how long
//! map <proto> <port> <ip> <iport> <policy> [seconds]
//! unmap <proto> <port> <policy>           → close one early (`all` closes every one)
//! ```
//!
//! ## Why the policy is required here and optional at the portal
//!
//! A portal admission is scoped to whichever zones have a portal, and admitting
//! into all of them is nearly always admitting into the only one. A port mapping
//! is the opposite: it belongs to exactly one zone — the uplink the request is
//! asking to be reachable from — and opening it on every zone would open the
//! port on the LAN, the DMZ and the guest network as well. So there is no `any`
//! for `map`, and the caller has to say which.
//!
//! ## What this socket cannot do
//!
//! Take away, or take over, anything the operator configured. A `(policy, proto,
//! port)` the configuration already forwards is refused rather than replaced —
//! not only because replacing it would redirect somebody else's service, but
//! because the mapping's own expiry would then delete an entry nobody asked to
//! have removed. `unmap` likewise only ever removes a mapping this socket
//! opened.
//!
//! One thing it **cannot check** is who asked. A request arrives here as a
//! target address, not as a sender, so refusing a host mapping a port to a
//! *different* internal address — PCP calls that THIRD_PARTY, and it is how one
//! device on a LAN would expose another — has to happen in the daemon that
//! speaks the protocol and can see the source. That is stated here so the
//! division is written down rather than assumed.

use std::{net::Ipv4Addr, path::PathBuf, sync::Arc, time::Duration};

use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use velstra_common::{PolicyId, ip_proto};

use crate::firewall::Firewall;

/// How long a mapping lasts when the caller names no lifetime.
///
/// Two hours, which is what PCP suggests as a default and long enough that a
/// client renewing at half the lifetime does so rarely.
const DEFAULT_MAPPING_SECS: u64 = 7200;

/// The longest one mapping may last.
///
/// A day, the same ceiling every other run-time opening on this appliance has. A
/// client that means to keep a port open renews, and a client that has gone away
/// stops — which is exactly the distinction a ceiling exists to make.
const MAX_MAPPING_SECS: u64 = 86_400;

/// How often expired mappings are closed.
const SWEEP: Duration = Duration::from_secs(10);

/// Close expired mappings, forever. Spawned alongside [`serve`].
pub async fn expire_mappings_loop(firewall: Arc<Mutex<Firewall>>) {
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tick.tick().await;
        let closed = firewall.lock().await.expire_mappings();
        if closed > 0 {
            info!("{closed} run-time port mapping(s) expired");
        }
    }
}

/// Serve the mapping socket at `path` until the process ends.
pub async fn serve(path: PathBuf, firewall: Arc<Mutex<Firewall>>) {
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!("mapping socket {} unavailable: {e}", path.display());
            return;
        }
    };
    info!("mapping socket listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let fw = firewall.clone();
                tokio::spawn(async move { handle(stream, fw).await });
            }
            Err(e) => {
                warn!("mapping socket accept failed: {e}");
                return;
            }
        }
    }
}

/// Answer one request.
async fn handle(stream: UnixStream, firewall: Arc<Mutex<Firewall>>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let reply = respond(line.trim(), &firewall).await;
    let _ = reader.get_mut().write_all(reply.as_bytes()).await;
}

/// Parse a protocol name into its IP number. Only TCP and UDP: those are the two
/// NAT-PMP can express and the two the data plane's port key is defined over.
fn parse_proto(token: &str) -> Result<u8, String> {
    match token.to_ascii_lowercase().as_str() {
        "tcp" => Ok(ip_proto::TCP),
        "udp" => Ok(ip_proto::UDP),
        other => Err(format!("{other:?} is not tcp or udp")),
    }
}

/// Parse a port. Zero is refused rather than treated as a wildcard: NAT-PMP
/// gives port 0 a meaning this table has no way to express.
fn parse_port(token: &str, what: &str) -> Result<u16, String> {
    let port: u16 = token
        .parse()
        .map_err(|_| format!("{token:?} is not a {what}"))?;
    if port == 0 {
        return Err(format!("0 is not a {what}"));
    }
    Ok(port)
}

/// Parse the lifetime, with the default and the ceiling applied.
///
/// Out-of-range is **refused**, not clamped: a client that asked for a week and
/// was quietly given a day would renew on the schedule it asked for and lose its
/// mapping in between. The protocol has a way to say "you got less than you
/// asked for", and that belongs to the daemon speaking it.
fn parse_seconds(token: Option<&str>) -> Result<u64, String> {
    let Some(t) = token else {
        return Ok(DEFAULT_MAPPING_SECS);
    };
    let secs = t
        .parse::<u64>()
        .map_err(|_| format!("{t:?} is not a number of seconds"))?;
    if secs == 0 || secs > MAX_MAPPING_SECS {
        return Err(format!("a mapping lasts 1..={MAX_MAPPING_SECS} seconds"));
    }
    Ok(secs)
}

/// Parse a policy id. Required — see the module header for why there is no
/// `any` here.
fn parse_policy(token: Option<&str>) -> Result<PolicyId, String> {
    let Some(t) = token else {
        return Err("a mapping needs the policy (zone) it opens on".to_string());
    };
    t.parse().map_err(|_| format!("{t:?} is not a policy id"))
}

/// A protocol number as an operator reads it.
fn proto_name(proto: u8) -> &'static str {
    match proto {
        ip_proto::TCP => "tcp",
        ip_proto::UDP => "udp",
        _ => "ip",
    }
}

/// Dispatch one command.
async fn respond(line: &str, firewall: &Arc<Mutex<Firewall>>) -> String {
    let mut tokens = line.split_whitespace();
    let verb = tokens.next().unwrap_or("");
    let args: Vec<&str> = tokens.collect();

    match verb {
        "mappings" => {
            let mut fw = firewall.lock().await;
            fw.expire_mappings();
            let mappings = fw.runtime_mappings();
            if mappings.is_empty() {
                "no run-time port mappings\n".to_string()
            } else {
                let mut out = String::new();
                for (policy, proto, port, ip, iport, secs) in mappings {
                    out.push_str(&format!(
                        "{}/{port} -> {}:{iport} in policy {policy}, {secs}s remaining\n",
                        proto_name(proto),
                        Ipv4Addr::from(ip)
                    ));
                }
                out
            }
        }
        "map" => {
            if args.len() < 5 {
                return "usage: map <tcp|udp> <port> <ip> <internal-port> <policy> [seconds]\n"
                    .to_string();
            }
            let proto = match parse_proto(args[0]) {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let port = match parse_port(args[1], "port") {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let Ok(ip) = args[2].parse::<Ipv4Addr>() else {
                return format!("error: {:?} is not an IPv4 address\n", args[2]);
            };
            let internal_port = match parse_port(args[3], "port") {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let policy = match parse_policy(args.get(4).copied()) {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let secs = match parse_seconds(args.get(5).copied()) {
                Ok(s) => s,
                Err(e) => return format!("error: {e}\n"),
            };
            let mut fw = firewall.lock().await;
            match fw.map_port(
                policy,
                proto,
                port,
                ip.octets(),
                internal_port,
                Duration::from_secs(secs),
            ) {
                Ok(true) => format!(
                    "{}/{port} -> {ip}:{internal_port} for {secs}s\n",
                    proto_name(proto)
                ),
                // Not an error the caller can retry differently, and worth its
                // own sentence: the port is spoken for by the configuration, and
                // that is a refusal rather than a failure.
                Ok(false) => format!(
                    "{}/{port} is forwarded by the configuration; left as it is\n",
                    proto_name(proto)
                ),
                Err(e) => format!("error: mapping {}/{port}: {e:#}\n", proto_name(proto)),
            }
        }
        "unmap" => {
            let Some(first) = args.first() else {
                return "usage: unmap <tcp|udp> <port> <policy> | unmap all\n".to_string();
            };
            let mut fw = firewall.lock().await;
            if *first == "all" {
                return match fw.unmap_all() {
                    Ok(0) => "no run-time port mappings to close\n".to_string(),
                    Ok(n) => format!("closed {n} run-time port mapping(s)\n"),
                    Err(e) => format!("error: closing mappings: {e:#}\n"),
                };
            }
            if args.len() < 3 {
                return "usage: unmap <tcp|udp> <port> <policy> | unmap all\n".to_string();
            }
            let proto = match parse_proto(first) {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let port = match parse_port(args[1], "port") {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            let policy = match parse_policy(args.get(2).copied()) {
                Ok(p) => p,
                Err(e) => return format!("error: {e}\n"),
            };
            match fw.unmap_port(policy, proto, port) {
                Ok(true) => format!("closed {}/{port}\n", proto_name(proto)),
                Ok(false) => format!("{}/{port} is not a run-time mapping\n", proto_name(proto)),
                Err(e) => format!("error: closing {}/{port}: {e:#}\n", proto_name(proto)),
            }
        }
        "" => "usage: mappings | map <tcp|udp> <port> <ip> <internal-port> <policy> [seconds] | \
               unmap <tcp|udp> <port> <policy>\n"
            .to_string(),
        other => format!("error: unknown command {other:?}; try: mappings | map | unmap\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the two protocols the table's key is defined over, and only ports
    /// that exist.
    #[test]
    fn a_mapping_names_a_real_protocol_and_port() {
        assert_eq!(parse_proto("tcp"), Ok(ip_proto::TCP));
        assert_eq!(parse_proto("UDP"), Ok(ip_proto::UDP));
        assert!(parse_proto("sctp").is_err());
        assert!(parse_proto("47").is_err());

        assert_eq!(parse_port("443", "port"), Ok(443));
        // NAT-PMP gives port 0 a meaning this table cannot express, so it is
        // refused rather than stored as a wildcard nothing honours.
        assert!(parse_port("0", "port").is_err());
        assert!(parse_port("70000", "port").is_err());
    }

    /// A lifetime out of range is refused, not clamped — a client quietly given
    /// less than it asked for renews too late and loses the mapping.
    #[test]
    fn a_lifetime_is_bounded_and_says_so() {
        assert_eq!(parse_seconds(None), Ok(DEFAULT_MAPPING_SECS));
        assert_eq!(parse_seconds(Some("60")), Ok(60));
        assert!(parse_seconds(Some("0")).is_err());
        assert!(parse_seconds(Some(&(MAX_MAPPING_SECS + 1).to_string())).is_err());
        assert!(parse_seconds(Some("forever")).is_err());
    }

    /// There is no `any` for a mapping: opening a port on every zone would open
    /// it on the LAN and the guest network too.
    #[test]
    fn a_mapping_must_name_its_zone() {
        assert_eq!(parse_policy(Some("2")), Ok(2));
        assert!(parse_policy(None).is_err());
        assert!(parse_policy(Some("any")).is_err());
        assert!(parse_policy(Some("wan")).is_err());
    }
}
