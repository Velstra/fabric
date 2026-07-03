//! B4b part 2 — **local MAC learning → EVPN advertise**.
//!
//! The data plane learns each tenant's source MAC/IPv4 on a tenant port into the
//! `LOCAL_MACS` LRU map (see `velstra-ebpf`). This module is the user-space half
//! that closes the loop: a long-lived task [`learn_and_advertise`] reads that map
//! every couple of seconds, diffs it against what it has already told Wren, and
//! drives the co-located [Wren](https://github.com/Velstra/wren) routing daemon's
//! one-shot control commands:
//!
//! ```text
//! evpn advertise <vni> <mac> <ip>\n     # a newly-seen / changed local MAC
//! evpn withdraw  <vni> <mac> <ip>\n     # a local MAC that aged out of the LRU
//! ```
//!
//! Wren re-advertises those as type-2 EVPN routes to the remote VTEPs. The whole
//! task is **opt-in** (`--wren-socket`) and **best-effort**: any I/O error is
//! logged and retried on the next tick, never panicking the agent.
//!
//! The pure diff ([`diff_advertised`]) is kept entirely in Rust so it can be unit
//! tested without a running Wren or kernel.

use std::{
    collections::BTreeMap,
    io,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use aya::maps::{HashMap, MapData};
use log::warn;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};
use velstra_common::{LocalMac, LocalMacKey};

/// A learned local endpoint's identity: its tenant VNI and source MAC.
type MacKey = (u32, [u8; 6]);

/// The set of local `(vni, mac)` → bound IPv4 currently known — either freshly
/// read from `LOCAL_MACS` or the set already advertised to Wren.
type AdvMap = BTreeMap<MacKey, Ipv4Addr>;

/// One local MAC/IP to advertise to Wren (`evpn advertise <vni> <mac> <ip>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertise {
    /// Tenant VNI the MAC lives on.
    pub vni: u32,
    /// The learned tenant source MAC.
    pub mac: [u8; 6],
    /// The IPv4 currently bound to that MAC.
    pub ip: Ipv4Addr,
}

/// One local MAC to withdraw from Wren (`evpn withdraw <vni> <mac> <ip>`), sent
/// when a previously-advertised MAC has aged out of the learning map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Withdraw {
    /// Tenant VNI the MAC lived on.
    pub vni: u32,
    /// The tenant source MAC being withdrawn.
    pub mac: [u8; 6],
    /// The last IPv4 that was bound to it (echoed in the withdraw line).
    pub ip: Ipv4Addr,
}

/// Diff the previously-advertised set against a fresh read of the learning map.
///
/// **Pure** and allocation-only, so it is unit tested without any I/O:
/// * an entry present in `cur` but not `prev`, or whose bound IP changed, is an
///   [`Advertise`];
/// * an entry present in `prev` but gone from `cur` is a [`Withdraw`] (carrying
///   its last-known IP).
///
/// An unchanged entry produces nothing, so a steady state is silent on the wire.
pub fn diff_advertised(prev: &AdvMap, cur: &AdvMap) -> (Vec<Advertise>, Vec<Withdraw>) {
    let mut advertise = Vec::new();
    let mut withdraw = Vec::new();

    for (&(vni, mac), &ip) in cur {
        match prev.get(&(vni, mac)) {
            // Already advertised with the same IP — nothing to do.
            Some(&old_ip) if old_ip == ip => {}
            // New, or the bound IP changed — (re)advertise.
            _ => advertise.push(Advertise { vni, mac, ip }),
        }
    }
    for (&(vni, mac), &ip) in prev {
        if !cur.contains_key(&(vni, mac)) {
            withdraw.push(Withdraw { vni, mac, ip });
        }
    }

    (advertise, withdraw)
}

/// Format a MAC as lower-case colon-hex, the form Wren's control parser expects.
fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Drive one one-shot Wren EVPN control command: connect the Unix control socket,
/// write a single `evpn advertise|withdraw <vni> <mac> [ip]\n` line, read and
/// discard the status line, then close. Best-effort — the caller logs and retries.
pub async fn wren_evpn(
    socket: &Path,
    advertise: bool,
    vni: u32,
    mac: [u8; 6],
    ip: Option<Ipv4Addr>,
) -> io::Result<()> {
    let verb = if advertise { "advertise" } else { "withdraw" };
    let mac = format_mac(mac);
    let line = match ip {
        Some(ip) => format!("evpn {verb} {vni} {mac} {ip}\n"),
        None => format!("evpn {verb} {vni} {mac}\n"),
    };

    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(line.as_bytes()).await?;
    stream.flush().await?;

    // Read and discard the one-line status Wren writes back (ignore a bare EOF).
    let (rd, _wr) = stream.into_split();
    let mut lines = BufReader::new(rd).lines();
    let _ = lines.next_line().await?;
    Ok(())
}

/// Read every entry of the `LOCAL_MACS` LRU map into a fresh [`AdvMap`]. A map
/// that is empty (nothing learned yet) simply yields an empty map; a per-entry
/// read error is skipped rather than aborting the whole scan.
fn read_local_macs(map: &HashMap<MapData, LocalMacKey, LocalMac>) -> AdvMap {
    let mut out = AdvMap::new();
    for key in map.keys().flatten() {
        if let Ok(val) = map.get(&key, 0) {
            out.insert((key.vni, key.mac), Ipv4Addr::from(val.ip));
        }
    }
    out
}

/// Long-lived task: every `poll` interval, read `LOCAL_MACS`, diff it against the
/// set already advertised, and advertise/withdraw the delta to Wren. Owns the map
/// handle (taken from the loaded eBPF object) and the advertised-set state.
///
/// Best-effort per operation: a failed advertise/withdraw is logged and its entry
/// is left out of the advertised set, so the next tick retries it — the state
/// self-heals without ever blocking the loop.
pub async fn learn_and_advertise(
    map: HashMap<MapData, LocalMacKey, LocalMac>,
    socket: PathBuf,
    poll: Duration,
) {
    let mut advertised: AdvMap = AdvMap::new();
    let mut ticker = tokio::time::interval(poll);

    loop {
        ticker.tick().await;

        let cur = read_local_macs(&map);
        let (to_adv, to_wdr) = diff_advertised(&advertised, &cur);
        if to_adv.is_empty() && to_wdr.is_empty() {
            continue;
        }

        // Apply only the operations that succeed, so a failure retries next tick.
        let mut next = advertised.clone();
        for a in &to_adv {
            match wren_evpn(&socket, true, a.vni, a.mac, Some(a.ip)).await {
                Ok(()) => {
                    next.insert((a.vni, a.mac), a.ip);
                }
                Err(e) => warn!(
                    "wren advertise failed (vni {} mac {}): {e}",
                    a.vni,
                    format_mac(a.mac)
                ),
            }
        }
        for w in &to_wdr {
            match wren_evpn(&socket, false, w.vni, w.mac, Some(w.ip)).await {
                Ok(()) => {
                    next.remove(&(w.vni, w.mac));
                }
                Err(e) => warn!(
                    "wren withdraw failed (vni {} mac {}): {e}",
                    w.vni,
                    format_mac(w.mac)
                ),
            }
        }
        advertised = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    #[test]
    fn mac_is_lower_case_colon_hex() {
        assert_eq!(
            format_mac([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]),
            "aa:bb:cc:dd:ee:ff"
        );
        assert_eq!(format_mac([0x02, 0, 0, 0, 0, 0x0a]), "02:00:00:00:00:0a");
    }

    #[test]
    fn diff_flags_new_entries_to_advertise() {
        let prev = AdvMap::new();
        let mut cur = AdvMap::new();
        cur.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 5));
        let (adv, wdr) = diff_advertised(&prev, &cur);
        assert_eq!(
            adv,
            vec![Advertise {
                vni: 100,
                mac: MAC_A,
                ip: Ipv4Addr::new(10, 0, 0, 5)
            }]
        );
        assert!(wdr.is_empty());
    }

    #[test]
    fn diff_flags_changed_ip_as_advertise() {
        let mut prev = AdvMap::new();
        prev.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 5));
        let mut cur = AdvMap::new();
        cur.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 6));
        let (adv, wdr) = diff_advertised(&prev, &cur);
        // Same (vni, mac) but a new IP re-advertises with the new binding.
        assert_eq!(
            adv,
            vec![Advertise {
                vni: 100,
                mac: MAC_A,
                ip: Ipv4Addr::new(10, 0, 0, 6)
            }]
        );
        assert!(wdr.is_empty());
    }

    #[test]
    fn diff_flags_removed_entries_as_withdraw() {
        let mut prev = AdvMap::new();
        prev.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 5));
        let cur = AdvMap::new();
        let (adv, wdr) = diff_advertised(&prev, &cur);
        assert!(adv.is_empty());
        // The withdraw carries the last-known IP for the `evpn withdraw` line.
        assert_eq!(
            wdr,
            vec![Withdraw {
                vni: 100,
                mac: MAC_A,
                ip: Ipv4Addr::new(10, 0, 0, 5)
            }]
        );
    }

    #[test]
    fn diff_is_silent_when_unchanged() {
        let mut prev = AdvMap::new();
        prev.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 5));
        prev.insert((200, MAC_B), Ipv4Addr::new(10, 0, 1, 9));
        let cur = prev.clone();
        let (adv, wdr) = diff_advertised(&prev, &cur);
        assert!(adv.is_empty(), "unchanged set must not re-advertise");
        assert!(wdr.is_empty(), "unchanged set must not withdraw");
    }

    #[test]
    fn diff_handles_add_change_and_remove_together() {
        let mut prev = AdvMap::new();
        prev.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 5)); // will change IP
        prev.insert((200, MAC_B), Ipv4Addr::new(10, 0, 1, 9)); // will be removed
        let mut cur = AdvMap::new();
        cur.insert((100, MAC_A), Ipv4Addr::new(10, 0, 0, 7)); // changed
        cur.insert((300, MAC_A), Ipv4Addr::new(10, 0, 2, 2)); // new (different vni)

        let (adv, wdr) = diff_advertised(&prev, &cur);
        assert_eq!(adv.len(), 2, "one changed + one new");
        assert!(adv.contains(&Advertise {
            vni: 100,
            mac: MAC_A,
            ip: Ipv4Addr::new(10, 0, 0, 7)
        }));
        assert!(adv.contains(&Advertise {
            vni: 300,
            mac: MAC_A,
            ip: Ipv4Addr::new(10, 0, 2, 2)
        }));
        assert_eq!(
            wdr,
            vec![Withdraw {
                vni: 200,
                mac: MAC_B,
                ip: Ipv4Addr::new(10, 0, 1, 9)
            }]
        );
    }
}
