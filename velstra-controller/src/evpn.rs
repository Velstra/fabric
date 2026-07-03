//! EVPN → fabric bridge (controller side, roadmap chunk B4a).
//!
//! The sibling `wren` routing daemon exposes a streaming EVPN feed over its Unix
//! control socket: a client connects, writes `monitor evpn\n`, and reads a
//! line-based stream (like `ip monitor`). This module
//!
//! 1. [`parse_evpn_event`] — a **pure** parser of that wire format,
//! 2. [`EvpnLearned`] — the controller's in-memory view of the remote EVPN
//!    state (type-2 MAC/IP routes + type-3 BUM flood VTEPs), and
//! 3. [`run_evpn_monitor`] — a resilient async client that keeps the learned
//!    state in sync and folds it into the per-host `NodeConfig` the controller
//!    already derives and pushes to agents.
//!
//! Only type-2 MAC/IP routes **with a bound IP** are programmable through the
//! existing datapath (they become an ARP-suppression `Neighbor` + an L3
//! `Tunnel` with `inner_dst = ip/32`, see `topology::derive_configs`). MAC-only
//! entries (no IP) and type-3 flood VTEPs are learned/held but **not** yet
//! programmed — they need the MAC-FDB / BUM datapath work coming in later
//! chunks (B1/B2). Holding them now keeps the wire contract stable so those
//! chunks only add a datapath, not a new feed.
//!
//! # Wire format (stable input contract)
//! ```text
//! + evpn vni <vni> mac <mac> ip <ipaddr> vtep <ipaddr>   # remote MAC/IP learned
//! + evpn vni <vni> mac <mac> vtep <ipaddr>               # same, no bound IP
//! - evpn vni <vni> mac <mac>                             # remote MAC withdrawn
//! + evpn vni <vni> flood <ipaddr>                        # BUM flood VTEP added
//! - evpn vni <vni> flood <ipaddr>                        # BUM flood VTEP removed
//! % end-of-dump                                          # initial snapshot done
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use crate::{Shared, re_derive};

/// Backoff between reconnect attempts when the Wren socket is unavailable or the
/// stream drops. Kept short: the daemon may restart and we want to re-sync fast.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(1);

/// One decoded line of the `monitor evpn` stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvpnMonitorEvent {
    /// A remote type-2 MAC (optionally with a bound IP) reachable behind `vtep`.
    MacUpdate {
        vni: u32,
        mac: [u8; 6],
        ip: Option<IpAddr>,
        vtep: IpAddr,
    },
    /// A remote type-2 MAC was withdrawn.
    MacWithdraw { vni: u32, mac: [u8; 6] },
    /// A type-3 IMET BUM flood VTEP was added.
    FloodUpdate { vni: u32, vtep: IpAddr },
    /// A type-3 IMET BUM flood VTEP was removed.
    FloodWithdraw { vni: u32, vtep: IpAddr },
    /// The initial snapshot is complete; later lines are live updates.
    EndOfDump,
}

/// Parse a lower-case colon-hex MAC (`aa:bb:cc:dd:ee:ff`) into six octets, or
/// `None` on anything malformed.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut octets = [0u8; 6];
    let mut parts = s.split(':');
    for slot in &mut octets {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    // Reject anything with a 7th field.
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// Parse one line of the `monitor evpn` stream. **Pure**: robust to arbitrary
/// whitespace, and returns `None` on anything unrecognized (usage/error lines,
/// partial lines, unknown `%` comments, garbage).
pub fn parse_evpn_event(line: &str) -> Option<EvpnMonitorEvent> {
    let t: Vec<&str> = line.split_whitespace().collect();

    // End-of-dump sentinel — the only recognized `%` line.
    if t.len() == 2 && t[0] == "%" && t[1] == "end-of-dump" {
        return Some(EvpnMonitorEvent::EndOfDump);
    }

    // Every real event is at least `<sign> evpn vni <vni> <kind> ...`.
    if t.len() < 6 {
        return None;
    }
    let sign = t[0];
    if (sign != "+" && sign != "-") || t[1] != "evpn" || t[2] != "vni" {
        return None;
    }
    let vni: u32 = t[3].parse().ok()?;

    match t[4] {
        "flood" => {
            if t.len() != 6 {
                return None;
            }
            let vtep: IpAddr = t[5].parse().ok()?;
            match sign {
                "+" => Some(EvpnMonitorEvent::FloodUpdate { vni, vtep }),
                _ => Some(EvpnMonitorEvent::FloodWithdraw { vni, vtep }),
            }
        }
        "mac" => {
            let mac = parse_mac(t[5])?;
            if sign == "-" {
                // Withdraw is exactly `- evpn vni <vni> mac <mac>`.
                return (t.len() == 6).then_some(EvpnMonitorEvent::MacWithdraw { vni, mac });
            }
            // `+` update: with or without a bound IP.
            match t.len() {
                8 => {
                    // `+ evpn vni V mac M vtep VT`
                    if t[6] != "vtep" {
                        return None;
                    }
                    let vtep: IpAddr = t[7].parse().ok()?;
                    Some(EvpnMonitorEvent::MacUpdate {
                        vni,
                        mac,
                        ip: None,
                        vtep,
                    })
                }
                10 => {
                    // `+ evpn vni V mac M ip IP vtep VT`
                    if t[6] != "ip" || t[8] != "vtep" {
                        return None;
                    }
                    let ip: IpAddr = t[7].parse().ok()?;
                    let vtep: IpAddr = t[9].parse().ok()?;
                    Some(EvpnMonitorEvent::MacUpdate {
                        vni,
                        mac,
                        ip: Some(ip),
                        vtep,
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// A single learned type-2 MAC: which `vtep` hosts it and, optionally, the
/// tenant IP bound to it (present ⇒ programmable as ARP suppression + L3 route).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedMac {
    pub vtep: IpAddr,
    pub ip: Option<IpAddr>,
}

/// The controller's in-memory view of the remote EVPN state.
#[derive(Debug, Default, Clone)]
pub struct EvpnLearned {
    /// `(vni, mac) -> where it lives`. `BTreeMap` for deterministic derive order.
    macs: BTreeMap<(u32, [u8; 6]), LearnedMac>,
    /// `vni -> {flood VTEPs}` (type-3 IMET). Held for the future BUM datapath.
    floods: BTreeMap<u32, BTreeSet<IpAddr>>,
}

impl EvpnLearned {
    /// Fold one event into the learned state, returning whether anything changed
    /// (so the caller can skip a needless re-derive). `EndOfDump` never changes
    /// state and returns `false`.
    pub fn apply(&mut self, ev: &EvpnMonitorEvent) -> bool {
        match ev {
            EvpnMonitorEvent::MacUpdate { vni, mac, ip, vtep } => {
                let key = (*vni, *mac);
                let next = LearnedMac {
                    vtep: *vtep,
                    ip: *ip,
                };
                match self.macs.get(&key) {
                    Some(cur) if *cur == next => false,
                    _ => {
                        self.macs.insert(key, next);
                        true
                    }
                }
            }
            EvpnMonitorEvent::MacWithdraw { vni, mac } => self.macs.remove(&(*vni, *mac)).is_some(),
            EvpnMonitorEvent::FloodUpdate { vni, vtep } => {
                self.floods.entry(*vni).or_default().insert(*vtep)
            }
            EvpnMonitorEvent::FloodWithdraw { vni, vtep } => {
                let Some(set) = self.floods.get_mut(vni) else {
                    return false;
                };
                let removed = set.remove(vtep);
                if set.is_empty() {
                    self.floods.remove(vni);
                }
                removed
            }
            EvpnMonitorEvent::EndOfDump => false,
        }
    }

    /// Iterate learned type-2 MACs as `(vni, mac, &LearnedMac)`, in a
    /// deterministic order (the derive step relies on this for stable output).
    pub fn iter_macs(&self) -> impl Iterator<Item = (u32, [u8; 6], &LearnedMac)> {
        self.macs.iter().map(|((vni, mac), v)| (*vni, *mac, v))
    }

    /// The learned type-3 BUM flood VTEPs per VNI. Held for the future BUM
    /// datapath (B2); not yet programmed into any map.
    pub fn floods(&self) -> &BTreeMap<u32, BTreeSet<IpAddr>> {
        &self.floods
    }
}

/// Long-lived task: subscribe to Wren's `monitor evpn` feed and keep the
/// controller's [`EvpnLearned`] in sync, re-deriving (and thus re-pushing) node
/// configs whenever the learned state changes. Never panics the controller: on
/// any I/O error or disconnect it logs and reconnects with a bounded backoff, so
/// a Wren restart (or Wren not being up yet) is transparent.
pub async fn run_evpn_monitor(socket: PathBuf, shared: Arc<Shared>) {
    info!("evpn monitor: watching wren socket {}", socket.display());
    loop {
        match monitor_once(&socket, &shared).await {
            Ok(()) => info!("evpn monitor: stream ended; reconnecting"),
            Err(e) => warn!("evpn monitor: {e}; retry in {RECONNECT_BACKOFF:?}"),
        }
        tokio::time::sleep(RECONNECT_BACKOFF).await;
    }
}

/// One connection lifecycle: connect, request the feed, and apply lines until
/// EOF/error. During the initial dump, changes are accumulated and a single
/// re-derive is triggered at `% end-of-dump`; live changes after that trigger a
/// re-derive each.
async fn monitor_once(socket: &Path, shared: &Arc<Shared>) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(b"monitor evpn\n").await?;
    let (rd, _wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();

    let mut dumped = false;
    let mut dirty_in_dump = false;
    while let Some(line) = lines.next_line().await? {
        let Some(ev) = parse_evpn_event(&line) else {
            continue; // ignore usage/error/unknown lines
        };
        if ev == EvpnMonitorEvent::EndOfDump {
            dumped = true;
            {
                // Summarise the snapshot. Flood VTEPs are counted but not
                // programmed yet (held for the BUM datapath, B2).
                let learned = shared.evpn_learned.read().await;
                let macs = learned.iter_macs().count();
                let floods: usize = learned.floods().values().map(BTreeSet::len).sum();
                info!(
                    "evpn monitor: snapshot complete ({macs} mac(s), {floods} flood vtep(s) held)"
                );
            }
            if dirty_in_dump {
                trigger_rederive(shared).await;
            }
            continue;
        }
        let changed = shared.evpn_learned.write().await.apply(&ev);
        if !changed {
            continue;
        }
        if dumped {
            trigger_rederive(shared).await;
        } else {
            dirty_in_dump = true;
        }
    }
    Ok(())
}

/// Re-derive every node config from the topology + learned EVPN state and push
/// any changes. A derive failure is logged, not fatal — the monitor keeps
/// running so the next update can recover.
async fn trigger_rederive(shared: &Arc<Shared>) {
    if let Err(e) = re_derive(shared).await {
        warn!("evpn monitor: re-derive failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(s: &str) -> [u8; 6] {
        parse_mac(s).unwrap()
    }

    #[test]
    fn parses_mac_update_with_ip() {
        let ev = parse_evpn_event(
            "+ evpn vni 4200000 mac aa:bb:cc:dd:ee:ff ip 192.168.5.7 vtep 10.0.0.2",
        )
        .unwrap();
        assert_eq!(
            ev,
            EvpnMonitorEvent::MacUpdate {
                vni: 4_200_000,
                mac: mac("aa:bb:cc:dd:ee:ff"),
                ip: Some("192.168.5.7".parse().unwrap()),
                vtep: "10.0.0.2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parses_mac_update_without_ip() {
        let ev = parse_evpn_event("+ evpn vni 100 mac 02:00:00:00:00:11 vtep 10.0.0.9").unwrap();
        assert_eq!(
            ev,
            EvpnMonitorEvent::MacUpdate {
                vni: 100,
                mac: mac("02:00:00:00:00:11"),
                ip: None,
                vtep: "10.0.0.9".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parses_v6_vtep_and_ip() {
        let ev =
            parse_evpn_event("+ evpn vni 7 mac aa:bb:cc:dd:ee:ff ip 2001:db8::1 vtep 2001:db8::2")
                .unwrap();
        assert_eq!(
            ev,
            EvpnMonitorEvent::MacUpdate {
                vni: 7,
                mac: mac("aa:bb:cc:dd:ee:ff"),
                ip: Some("2001:db8::1".parse().unwrap()),
                vtep: "2001:db8::2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parses_mac_withdraw() {
        let ev = parse_evpn_event("- evpn vni 100 mac 02:00:00:00:00:11").unwrap();
        assert_eq!(
            ev,
            EvpnMonitorEvent::MacWithdraw {
                vni: 100,
                mac: mac("02:00:00:00:00:11"),
            }
        );
    }

    #[test]
    fn parses_flood_add_and_remove() {
        assert_eq!(
            parse_evpn_event("+ evpn vni 100 flood 10.0.0.2").unwrap(),
            EvpnMonitorEvent::FloodUpdate {
                vni: 100,
                vtep: "10.0.0.2".parse().unwrap(),
            }
        );
        assert_eq!(
            parse_evpn_event("- evpn vni 100 flood 10.0.0.2").unwrap(),
            EvpnMonitorEvent::FloodWithdraw {
                vni: 100,
                vtep: "10.0.0.2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn parses_end_of_dump() {
        assert_eq!(
            parse_evpn_event("% end-of-dump").unwrap(),
            EvpnMonitorEvent::EndOfDump
        );
    }

    #[test]
    fn tolerates_extra_whitespace() {
        let ev = parse_evpn_event("  +   evpn  vni 100   mac aa:bb:cc:dd:ee:ff   vtep  10.0.0.2 ")
            .unwrap();
        assert!(matches!(ev, EvpnMonitorEvent::MacUpdate { vni: 100, .. }));
    }

    #[test]
    fn rejects_garbage_and_partial_lines() {
        for bad in [
            "",
            "   ",
            "% something-else",
            "% end-of-dump extra",
            "garbage line",
            "+ evpn vni", // truncated
            "+ evpn vni notanumber mac aa:bb:cc:dd:ee:ff vtep 10.0.0.2",
            "+ evpn vni 100 mac zz:zz:zz:zz:zz:zz vtep 10.0.0.2", // bad mac
            "+ evpn vni 100 mac aa:bb:cc:dd:ee:ff vtep notanip",
            "+ evpn vni 100 mac aa:bb:cc:dd:ee:ff", // no vtep
            "+ evpn vni 100 mac aa:bb:cc:dd:ee:ff ip 1.2.3.4", // ip but no vtep
            "* evpn vni 100 flood 10.0.0.2",        // bad sign
            "+ bgp vni 100 flood 10.0.0.2",         // wrong keyword
            "- evpn vni 100 mac aa:bb:cc:dd:ee:ff vtep 10.0.0.2", // withdraw w/ trailer
        ] {
            assert!(parse_evpn_event(bad).is_none(), "should reject: {bad:?}");
        }
    }

    #[test]
    fn apply_add_replace_withdraw_change_detection() {
        let mut learned = EvpnLearned::default();
        let add = EvpnMonitorEvent::MacUpdate {
            vni: 100,
            mac: mac("aa:bb:cc:dd:ee:ff"),
            ip: Some("192.168.1.5".parse().unwrap()),
            vtep: "10.0.0.2".parse().unwrap(),
        };
        // First apply: state changes.
        assert!(learned.apply(&add));
        // Idempotent re-apply of the identical entry: no change.
        assert!(!learned.apply(&add));
        // Same key, different vtep: a change (replace).
        let moved = EvpnMonitorEvent::MacUpdate {
            vni: 100,
            mac: mac("aa:bb:cc:dd:ee:ff"),
            ip: Some("192.168.1.5".parse().unwrap()),
            vtep: "10.0.0.3".parse().unwrap(),
        };
        assert!(learned.apply(&moved));
        assert_eq!(learned.iter_macs().count(), 1);
        let (_, _, lm) = learned.iter_macs().next().unwrap();
        assert_eq!(lm.vtep, "10.0.0.3".parse::<IpAddr>().unwrap());

        // Withdraw removes it (change); a second withdraw is a no-op.
        let wd = EvpnMonitorEvent::MacWithdraw {
            vni: 100,
            mac: mac("aa:bb:cc:dd:ee:ff"),
        };
        assert!(learned.apply(&wd));
        assert!(!learned.apply(&wd));
        assert_eq!(learned.iter_macs().count(), 0);
    }

    #[test]
    fn apply_flood_add_remove_and_end_of_dump() {
        let mut learned = EvpnLearned::default();
        let add = EvpnMonitorEvent::FloodUpdate {
            vni: 100,
            vtep: "10.0.0.2".parse().unwrap(),
        };
        assert!(learned.apply(&add));
        assert!(!learned.apply(&add)); // duplicate flood VTEP: no change
        assert_eq!(learned.floods()[&100].len(), 1);

        let rm = EvpnMonitorEvent::FloodWithdraw {
            vni: 100,
            vtep: "10.0.0.2".parse().unwrap(),
        };
        assert!(learned.apply(&rm));
        assert!(!learned.apply(&rm)); // already gone
        assert!(learned.floods().get(&100).is_none()); // empty set pruned

        // EndOfDump is never a state change.
        assert!(!learned.apply(&EvpnMonitorEvent::EndOfDump));
    }
}
