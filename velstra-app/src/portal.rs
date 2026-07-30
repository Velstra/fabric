//! C20 — the **portal socket**: the one place where something outside the agent
//! may open the firewall.
//!
//! The query socket next door is explicit that nothing on it can admit traffic:
//! its only write verb adds a drop, so the worst an unwanted caller achieves is
//! denial of service against an address. A captive portal cannot live under that
//! rule — admitting a client is its entire purpose — so it does not live on that
//! socket. It gets its own, with its own path and its own permissions, and the
//! diagnostic socket keeps the property it was given.
//!
//! What bounds this one instead is *what an admission can reach*: the
//! `PORTAL_CLIENTS` map is consulted only by a policy that carries a portal, so
//! a caller here can move a device from "held at the gate of a guest zone" to
//! "subject to that zone's ordinary rules" — and nowhere else. It cannot open a
//! port, reach a zone that has no portal, lift a block, or alter the
//! configuration. Every session it opens carries a deadline, and the deadline is
//! enforced whether or not anyone comes back.
//!
//! ```text
//! sessions                        → who is admitted, and for how much longer
//! status <ip|mac> [policy|any]    → whether one device is, and for how long
//! allow <ip|mac> <policy|any> [s] → admit a device
//! revoke <mac|all> <policy|any>   → end a session early
//! ```
//!
//! An address is the more useful argument and the one the portal actually has:
//! an HTTP request carries a peer address and nothing else. It is resolved to a
//! MAC through what the *data plane saw* on the packets carrying that very
//! request (`PORTAL_SEEN`), never through the kernel's neighbour cache — a login
//! from an address the gate has never seen is refused rather than guessed at.

use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};

use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Mutex,
};
use velstra_common::{PolicyId, parse_mac};

use crate::firewall::{Firewall, render_mac};

/// How long a session lasts when the caller names no duration.
const DEFAULT_SESSION_SECS: u64 = 3600;

/// The longest one session may last.
///
/// A day, for the same reason a run-time block is capped at one: a portal is a
/// thing people pass through, and an admission that outlives the visit is an
/// access nobody remembers granting. A guest who is still there tomorrow logs in
/// again, which takes a moment and leaves a record.
const MAX_SESSION_SECS: u64 = 86_400;

/// How often expired sessions are swept up. The deadline has to end the session
/// on its own, or it is only a promise kept when somebody happens to look.
const SWEEP: Duration = Duration::from_secs(10);

/// End expired sessions, forever. Spawned alongside [`serve`].
pub async fn expire_sessions_loop(firewall: Arc<Mutex<Firewall>>) {
    let mut tick = tokio::time::interval(SWEEP);
    loop {
        tick.tick().await;
        let ended = firewall.lock().await.expire_portal_sessions();
        if ended > 0 {
            info!("{ended} captive-portal session(s) expired");
        }
    }
}

/// Serve the portal socket at `path` until the process ends.
///
/// A stale socket file from a previous run is removed first, for the same reason
/// the query socket does it: the agent restarts far more often than the path
/// changes, and refusing to start because yesterday's file is still there would
/// be a self-inflicted outage — here, one that leaves a guest zone with no way
/// to let anybody in.
pub async fn serve(path: PathBuf, firewall: Arc<Mutex<Firewall>>) {
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            warn!("portal socket {} unavailable: {e}", path.display());
            return;
        }
    };
    info!("portal socket listening on {}", path.display());
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let fw = firewall.clone();
                tokio::spawn(async move { handle(stream, fw).await });
            }
            Err(e) => {
                warn!("portal socket accept failed: {e}");
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

/// Which policies a command names.
///
/// `any` means "every zone that has a portal", which on the overwhelmingly
/// common single-guest-zone appliance is the only zone there is. An explicit id
/// is what a box running two portals with two different passphrases needs, so
/// that logging in to one does not admit the device to the other.
#[derive(Debug, PartialEq, Eq)]
enum Scope {
    Any,
    One(PolicyId),
}

/// Parse the policy argument. Absent ⇒ [`Scope::Any`].
fn parse_scope(token: Option<&str>) -> Result<Scope, String> {
    match token {
        None | Some("any") => Ok(Scope::Any),
        Some(t) => t
            .parse::<PolicyId>()
            .map(Scope::One)
            .map_err(|_| format!("{t:?} is not a policy id or `any`")),
    }
}

/// Parse the session length, with the default and the cap applied.
fn parse_seconds(token: Option<&str>) -> Result<u64, String> {
    let Some(t) = token else {
        return Ok(DEFAULT_SESSION_SECS);
    };
    let secs = t
        .parse::<u64>()
        .map_err(|_| format!("{t:?} is not a number of seconds"))?;
    if secs == 0 || secs > MAX_SESSION_SECS {
        return Err(format!("a session lasts 1..={MAX_SESSION_SECS} seconds"));
    }
    Ok(secs)
}

/// The device a command names: a MAC directly, or an address to be resolved
/// against what the data plane saw.
enum Device {
    Mac([u8; 6]),
    Addr(IpAddr),
}

/// Parse the device argument. A MAC is tried first — it has a shape an address
/// never takes — so a caller that already knows the device is not sent through a
/// lookup that can fail.
fn parse_device(token: &str) -> Result<Device, String> {
    if let Ok(mac) = parse_mac(token) {
        return Ok(Device::Mac(mac));
    }
    token
        .parse::<IpAddr>()
        .map(Device::Addr)
        .map_err(|_| format!("{token:?} is neither an address nor a MAC"))
}

/// Dispatch one command.
async fn respond(line: &str, firewall: &Arc<Mutex<Firewall>>) -> String {
    let mut tokens = line.split_whitespace();
    let verb = tokens.next().unwrap_or("");
    let args: Vec<&str> = tokens.collect();

    match verb {
        "sessions" => {
            let mut fw = firewall.lock().await;
            fw.expire_portal_sessions();
            let sessions = fw.portal_sessions();
            if sessions.is_empty() {
                "no captive-portal sessions\n".to_string()
            } else {
                let mut out = String::new();
                for (policy, mac, secs) in sessions {
                    out.push_str(&format!(
                        "{} admitted to policy {policy}, {secs}s remaining\n",
                        render_mac(mac)
                    ));
                }
                out
            }
        }
        // Read-only, and the one thing a portal page needs to answer RFC 8908's
        // "are you captive": the API is polled by the client's own operating
        // system, so it has to be answerable without admitting anything.
        "status" => {
            let Some(device) = args.first() else {
                return "usage: status <ip|mac> [policy|any]\n".to_string();
            };
            let device = match parse_device(device) {
                Ok(d) => d,
                Err(e) => return format!("error: {e}\n"),
            };
            let scope = match parse_scope(args.get(1).copied()) {
                Ok(s) => s,
                Err(e) => return format!("error: {e}\n"),
            };
            status(firewall, device, scope).await
        }
        "allow" => {
            let Some(device) = args.first() else {
                return "usage: allow <ip|mac> [policy|any] [seconds]\n".to_string();
            };
            let device = match parse_device(device) {
                Ok(d) => d,
                Err(e) => return format!("error: {e}\n"),
            };
            let scope = match parse_scope(args.get(1).copied()) {
                Ok(s) => s,
                Err(e) => return format!("error: {e}\n"),
            };
            let secs = match parse_seconds(args.get(2).copied()) {
                Ok(s) => s,
                Err(e) => return format!("error: {e}\n"),
            };
            admit(firewall, device, scope, secs).await
        }
        "revoke" => {
            let Some(device) = args.first() else {
                return "usage: revoke <mac|all> [policy|any]\n".to_string();
            };
            let mut fw = firewall.lock().await;
            if *device == "all" {
                return match fw.portal_revoke_all() {
                    Ok(0) => "no captive-portal sessions to end\n".to_string(),
                    Ok(n) => format!("ended {n} captive-portal session(s)\n"),
                    Err(e) => format!("error: ending sessions: {e:#}\n"),
                };
            }
            // Only a MAC here, and deliberately: an address is resolved through
            // the seen table, and a device being thrown off is exactly the one
            // whose entry may already have aged out. `sessions` lists MACs, which
            // is what an operator ending one has in front of them.
            let Ok(mac) = parse_mac(device) else {
                return format!("error: {device:?} is not a MAC; `sessions` lists them\n");
            };
            let scope = match parse_scope(args.get(1).copied()) {
                Ok(s) => s,
                Err(e) => return format!("error: {e}\n"),
            };
            let policies = match &scope {
                Scope::Any => fw.portal_policies(),
                Scope::One(id) => vec![*id],
            };
            let mut ended = 0;
            for policy in policies {
                match fw.portal_revoke(policy, mac) {
                    Ok(true) => ended += 1,
                    Ok(false) => {}
                    Err(e) => return format!("error: ending that session: {e:#}\n"),
                }
            }
            if ended == 0 {
                format!("{} is not admitted\n", render_mac(mac))
            } else {
                format!("{} is no longer admitted\n", render_mac(mac))
            }
        }
        "" => "usage: sessions | status <ip|mac> [policy|any] | \
               allow <ip|mac> [policy|any] [seconds] | revoke <mac|all> [policy|any]\n"
            .to_string(),
        other => {
            format!("error: unknown command {other:?}; try: sessions | status | allow | revoke\n")
        }
    }
}

/// Report whether one device is admitted, and for how much longer.
///
/// An address that has never reached the portal is reported as **not admitted**
/// rather than as an error: from the asking client's point of view those are the
/// same state, and a page that showed an error there would be telling a guest
/// about a table they have never heard of.
async fn status(firewall: &Arc<Mutex<Firewall>>, device: Device, scope: Scope) -> String {
    let mut fw = firewall.lock().await;
    fw.expire_portal_sessions();
    let policies: Vec<PolicyId> = match scope {
        Scope::Any => fw.portal_policies(),
        Scope::One(id) => vec![id],
    };
    for policy in policies {
        let mac = match device {
            Device::Mac(mac) => Some(mac),
            Device::Addr(addr) => match fw.portal_mac_for(policy, addr) {
                Ok(seen) => seen,
                Err(e) => return format!("error: looking up {addr}: {e:#}\n"),
            },
        };
        let Some(mac) = mac else { continue };
        if let Some((_, _, secs)) = fw
            .portal_sessions()
            .into_iter()
            .find(|(p, m, _)| *p == policy && *m == mac)
        {
            return format!(
                "{} admitted to policy {policy}, {secs}s remaining\n",
                render_mac(mac)
            );
        }
    }
    "not admitted\n".to_string()
}

/// Admit one device, resolving an address to a MAC where necessary.
async fn admit(firewall: &Arc<Mutex<Firewall>>, device: Device, scope: Scope, secs: u64) -> String {
    let mut fw = firewall.lock().await;
    let gated = fw.portal_policies();
    if gated.is_empty() {
        return "error: no zone on this appliance has a captive portal\n".to_string();
    }
    let policies: Vec<PolicyId> = match scope {
        Scope::Any => gated,
        Scope::One(id) => {
            if !gated.contains(&id) {
                return format!("error: policy {id} has no captive portal\n");
            }
            vec![id]
        }
    };

    let ttl = Duration::from_secs(secs);
    match device {
        Device::Mac(mac) => {
            for policy in &policies {
                if let Err(e) = fw.portal_admit(*policy, mac, ttl) {
                    return format!("error: admitting {}: {e:#}\n", render_mac(mac));
                }
            }
            format!(
                "{} admitted for {secs}s to {}\n",
                render_mac(mac),
                render_policies(&policies)
            )
        }
        Device::Addr(addr) => {
            // The address is resolved per policy, and the first zone that has
            // actually seen it wins. A device is on one link; asking every gated
            // zone is how the caller is spared having to know which.
            for policy in &policies {
                let seen = match fw.portal_mac_for(*policy, addr) {
                    Ok(seen) => seen,
                    Err(e) => return format!("error: looking up {addr}: {e:#}\n"),
                };
                let Some(mac) = seen else { continue };
                if let Err(e) = fw.portal_admit(*policy, mac, ttl) {
                    return format!("error: admitting {}: {e:#}\n", render_mac(mac));
                }
                return format!(
                    "{} ({addr}) admitted for {secs}s to policy {policy}\n",
                    render_mac(mac)
                );
            }
            // Not an error the caller can fix by retrying differently, so say
            // what it means: the gate has no record of this address reaching the
            // portal, and admitting a MAC we never saw would be admitting a guess.
            format!("error: {addr} has not reached the portal, so there is no device to admit\n")
        }
    }
}

/// Name the policies an admission covered, in a form that reads in one line.
fn render_policies(policies: &[PolicyId]) -> String {
    if policies.len() == 1 {
        format!("policy {}", policies[0])
    } else {
        let ids: Vec<String> = policies.iter().map(|id| id.to_string()).collect();
        format!("policies {}", ids.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope argument is what keeps two portals on one appliance apart.
    #[test]
    fn a_scope_is_a_policy_or_every_gated_one() {
        assert_eq!(parse_scope(None), Ok(Scope::Any));
        assert_eq!(parse_scope(Some("any")), Ok(Scope::Any));
        assert_eq!(parse_scope(Some("3")), Ok(Scope::One(3)));
        assert!(parse_scope(Some("guest")).is_err());
    }

    /// A session is always bounded, and unlike a diagnostic limit an unparseable
    /// duration is refused rather than defaulted: the caller asked for a length,
    /// and quietly granting a different one is how a portal ends up admitting a
    /// device for an hour when the operator wrote five minutes.
    #[test]
    fn a_session_is_always_bounded() {
        assert_eq!(parse_seconds(None), Ok(DEFAULT_SESSION_SECS));
        assert_eq!(parse_seconds(Some("900")), Ok(900));
        assert!(parse_seconds(Some("0")).is_err());
        assert!(parse_seconds(Some("a while")).is_err());
        assert!(parse_seconds(Some(&(MAX_SESSION_SECS + 1).to_string())).is_err());
        assert!(parse_seconds(Some(&MAX_SESSION_SECS.to_string())).is_ok());
    }

    /// A MAC and an address are told apart by shape, never by position.
    #[test]
    fn a_device_is_a_mac_or_an_address() {
        assert!(matches!(
            parse_device("02:00:00:00:00:11"),
            Ok(Device::Mac(_))
        ));
        assert!(matches!(
            parse_device("192.168.50.33"),
            Ok(Device::Addr(IpAddr::V4(_)))
        ));
        assert!(matches!(
            parse_device("2001:db8::1"),
            Ok(Device::Addr(IpAddr::V6(_)))
        ));
        assert!(parse_device("nobody").is_err());
    }

    /// The reply names what was actually admitted to, in both shapes.
    #[test]
    fn an_admission_says_where_it_applies() {
        assert_eq!(render_policies(&[3]), "policy 3");
        assert_eq!(render_policies(&[3, 4]), "policies 3, 4");
    }
}
