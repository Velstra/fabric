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
//! **Type-5 IP Prefix routes** (B7 symmetric IRB) become `IrbRoute` entries. A
//! route names its tenant only by L3 VNI, so `topology::derive_configs` joins it
//! against the fabric's IP-VRFs — which supply the L2 segments allowed to reach it
//! and the anycast gateway MAC to route it from — and expands it across those
//! segments. A route whose tenant this fabric does not host, or that arrived
//! without a Router's MAC, is held but not programmed.
//!
//! # Wire format (stable input contract)
//! ```text
//! + evpn vni <vni> mac <mac> ip <ipaddr> vtep <ipaddr>   # remote MAC/IP learned
//! + evpn vni <vni> mac <mac> vtep <ipaddr>               # same, no bound IP
//! - evpn vni <vni> mac <mac>                             # remote MAC withdrawn
//! + evpn vni <vni> flood <ipaddr>                        # BUM flood VTEP added
//! - evpn vni <vni> flood <ipaddr>                        # BUM flood VTEP removed
//! + evpn l3vni <vni> prefix <cidr> vtep <ipaddr> [router-mac <mac>] [gw <ipaddr>] [srv6 <sid>]
//! - evpn l3vni <vni> prefix <cidr>                       # remote subnet withdrawn
//! % end-of-dump                                          # initial snapshot done
//! ```
//!
//! The prefix lines carry `l3vni`, a distinct keyword from the `vni` of the
//! bridging lines, and name the **routed** VNI of a tenant IP-VRF — a different
//! number space from the L2 VNIs above. That distinction is load-bearing: reading
//! a type-5 route as a bridging update would program a routed prefix into an L2
//! table.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr},
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
        /// The advertising PE's `End.DT2U` service SID, when it runs an SRv6 data
        /// plane (RFC 9252). `None` on a VXLAN peer. Carried, not dropped: it is
        /// the *only* thing that says where to send an SRv6-encapsulated frame,
        /// and a fabric whose hosts run SRv6 has no VTEP IPv4 to fall back on.
        srv6_sid: Option<Ipv6Addr>,
    },
    /// A remote type-2 MAC was withdrawn.
    MacWithdraw { vni: u32, mac: [u8; 6] },
    /// A type-3 IMET BUM flood VTEP was added.
    FloodUpdate {
        vni: u32,
        vtep: IpAddr,
        /// The advertising PE's `End.DT2M` (flood) service SID on an SRv6 data
        /// plane. Distinct from the `End.DT2U` SID a [`Self::MacUpdate`] carries:
        /// RFC 9252 binds a SID to one behaviour, so a BUM copy sent to the
        /// unicast SID is bridged to a single MAC instead of flooded.
        srv6_sid: Option<Ipv6Addr>,
    },
    /// A type-3 IMET BUM flood VTEP was removed.
    FloodWithdraw { vni: u32, vtep: IpAddr },
    /// A remote tenant subnet (type-5 IP Prefix, RFC 9136) reachable by routing
    /// through `vtep` in the IP-VRF's L3 VNI. `router_mac` is the egress router's
    /// IRB MAC (RFC 9135) — the inner destination MAC symmetric IRB writes when it
    /// encapsulates toward that subnet.
    PrefixUpdate {
        l3_vni: u32,
        prefix: String,
        vtep: IpAddr,
        router_mac: Option<[u8; 6]>,
        gw: Option<IpAddr>,
        /// The advertising PE's service SID for this IP-VRF on an SRv6 data plane.
        srv6_sid: Option<Ipv6Addr>,
    },
    /// A remote tenant subnet was withdrawn.
    PrefixWithdraw { l3_vni: u32, prefix: String },
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

    // Every real event is at least `<sign> evpn <vni|l3vni> <n> <kind> ...`.
    if t.len() < 6 {
        return None;
    }
    let sign = t[0];
    if (sign != "+" && sign != "-") || t[1] != "evpn" {
        return None;
    }
    // `l3vni` introduces the routed (type-5) lines; `vni` the bridging ones. Any
    // other keyword is a format we do not know and must skip, not guess at.
    if t[2] == "l3vni" {
        return parse_prefix_event(sign, &t);
    }
    if t[2] != "vni" {
        return None;
    }
    let vni: u32 = t[3].parse().ok()?;

    match t[4] {
        "flood" => {
            // `<sign> evpn vni V flood VT [srv6 SID]`.
            let vtep: IpAddr = t[5].parse().ok()?;
            if sign == "-" {
                // Withdraw names the endpoint, nothing more.
                return (t.len() == 6).then_some(EvpnMonitorEvent::FloodWithdraw { vni, vtep });
            }
            let srv6_sid = parse_tail_srv6(&t[6..])?;
            Some(EvpnMonitorEvent::FloodUpdate {
                vni,
                vtep,
                srv6_sid,
            })
        }
        "mac" => {
            let mac = parse_mac(t[5])?;
            if sign == "-" {
                // Withdraw is exactly `- evpn vni <vni> mac <mac>`.
                return (t.len() == 6).then_some(EvpnMonitorEvent::MacWithdraw { vni, mac });
            }
            // `+ evpn vni V mac M [ip IP] vtep VT [srv6 SID]`.
            //
            // Read as keyword/value pairs, NOT by token count. Counting was the
            // original shape and it failed the moment wren gained an SRv6 locator:
            // `... vtep VT srv6 SID` is ten tokens, the same length as the
            // `... ip IP vtep VT` form, so the `t[6] == "ip"` check rejected it and
            // every type-2 route in an SRv6 fabric was silently discarded. The
            // type-5 lines below already read their tail this way and say why; the
            // bridging lines never got the lesson. An unknown keyword still rejects
            // the whole line — a line we only half understand is one we would
            // program incompletely.
            let mut ip = None;
            let mut vtep = None;
            let mut srv6_sid = None;
            let mut rest = &t[6..];
            while let [key, value, tail @ ..] = rest {
                match *key {
                    "ip" => ip = Some(value.parse::<IpAddr>().ok()?),
                    "vtep" => vtep = Some(value.parse::<IpAddr>().ok()?),
                    "srv6" => srv6_sid = Some(value.parse::<Ipv6Addr>().ok()?),
                    _ => return None,
                }
                rest = tail;
            }
            // An odd trailing token means a key without its value.
            if !rest.is_empty() {
                return None;
            }
            Some(EvpnMonitorEvent::MacUpdate {
                vni,
                mac,
                ip,
                // The endpoint is not optional: a MAC with no way to reach it is
                // not a route.
                vtep: vtep?,
                srv6_sid,
            })
        }
        _ => None,
    }
}

/// Read an optional trailing `srv6 <sid>` pair off a line's tail, rejecting
/// anything else. Shared by the flood lines, whose only extension this is.
fn parse_tail_srv6(tail: &[&str]) -> Option<Option<Ipv6Addr>> {
    match tail {
        [] => Some(None),
        ["srv6", sid] => Some(Some(sid.parse().ok()?)),
        _ => None,
    }
}

/// Parse a type-5 line, already known to start `<sign> evpn l3vni ...`.
///
/// Unlike the bridging lines this cannot be matched on token count: the tail
/// (`router-mac`, `gw`, `srv6`) is optional and, being append-only by contract,
/// will grow. So the head is fixed and the tail is read as keyword/value pairs,
/// with an unknown keyword rejecting the line rather than being skipped — a line
/// we only half understand is one we would program incompletely.
fn parse_prefix_event(sign: &str, t: &[&str]) -> Option<EvpnMonitorEvent> {
    if t[4] != "prefix" {
        return None;
    }
    let l3_vni: u32 = t[3].parse().ok()?;
    let prefix = validated_cidr(t[5])?;

    if sign == "-" {
        // Withdraw is exactly `- evpn l3vni <vni> prefix <cidr>`.
        return (t.len() == 6).then_some(EvpnMonitorEvent::PrefixWithdraw { l3_vni, prefix });
    }
    // `+ evpn l3vni V prefix P vtep VT [router-mac M] [gw G] [srv6 S]`
    if t.len() < 8 || t[6] != "vtep" {
        return None;
    }
    let vtep: IpAddr = t[7].parse().ok()?;
    let mut router_mac = None;
    let mut gw = None;
    let mut srv6_sid = None;
    let mut rest = &t[8..];
    while let [key, value, tail @ ..] = rest {
        match *key {
            "router-mac" => router_mac = Some(parse_mac(value)?),
            "gw" => gw = Some(value.parse().ok()?),
            // The SRv6 service SID is the alternative to VXLAN encapsulation. It
            // used to be validated and thrown away, on the grounds that the
            // datapath was VXLAN-only; it no longer is, and a discarded SID is a
            // routed prefix an SRv6 host cannot reach.
            "srv6" => srv6_sid = Some(value.parse::<Ipv6Addr>().ok()?),
            _ => return None,
        }
        rest = tail;
    }
    // An odd trailing token means a key without its value.
    if !rest.is_empty() {
        return None;
    }
    Some(EvpnMonitorEvent::PrefixUpdate {
        l3_vni,
        prefix,
        vtep,
        router_mac,
        gw,
        srv6_sid,
    })
}

/// Accept `addr/len` only if both halves parse and the length fits the address
/// family. The prefix is the map key a route is later programmed under, so a
/// malformed one must be rejected at the parser rather than stored as a string
/// that fails much later.
fn validated_cidr(s: &str) -> Option<String> {
    let (addr, len) = s.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    (len <= max).then(|| s.to_string())
}

/// A single learned type-2 MAC: which `vtep` hosts it and, optionally, the
/// tenant IP bound to it (present ⇒ programmable as ARP suppression + L3 route).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedMac {
    pub vtep: IpAddr,
    pub ip: Option<IpAddr>,
    /// The advertising PE's `End.DT2U` service SID when it runs SRv6. `None` on a
    /// VXLAN peer, which is also how a derive decides which overlay table this
    /// MAC belongs in.
    pub srv6_sid: Option<Ipv6Addr>,
}

/// The controller's in-memory view of the remote EVPN state.
#[derive(Debug, Default, Clone)]
pub struct EvpnLearned {
    /// `(vni, mac) -> where it lives`. `BTreeMap` for deterministic derive order.
    macs: BTreeMap<(u32, [u8; 6]), LearnedMac>,
    /// `vni -> {flood VTEP -> its End.DT2M SID, if any}` (type-3 IMET). A map
    /// rather than a set because an SRv6 peer's flood target is its `End.DT2M`
    /// SID, and the VTEP address alone cannot reach it; withdrawal still keys on
    /// the VTEP, which is what the withdraw line names.
    floods: BTreeMap<u32, BTreeMap<IpAddr, Option<Ipv6Addr>>>,
    /// `(l3_vni, prefix) -> where to route it`. Keyed on the pair, not the prefix
    /// alone: two tenants routinely use the same RFC 1918 subnet, and collapsing
    /// them onto one key would send one tenant's traffic to the other's VTEP.
    prefixes: BTreeMap<(u32, String), LearnedPrefix>,
}

/// A single learned type-5 subnet: which `vtep` routes it and the egress router's
/// IRB MAC to write as the inner destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LearnedPrefix {
    pub vtep: IpAddr,
    /// RFC 9135 Router's MAC. `None` when the advertising PE omitted it — such a
    /// route is held but not programmable over either overlay, since there is no
    /// inner destination MAC to encapsulate toward.
    pub router_mac: Option<[u8; 6]>,
    pub gw: Option<IpAddr>,
    /// The advertising PE's service SID for this IP-VRF when it runs SRv6.
    pub srv6_sid: Option<Ipv6Addr>,
}

impl EvpnLearned {
    /// Fold one event into the learned state, returning whether anything changed
    /// (so the caller can skip a needless re-derive). `EndOfDump` never changes
    /// state and returns `false`.
    pub fn apply(&mut self, ev: &EvpnMonitorEvent) -> bool {
        match ev {
            EvpnMonitorEvent::MacUpdate {
                vni,
                mac,
                ip,
                vtep,
                srv6_sid,
            } => {
                let key = (*vni, *mac);
                let next = LearnedMac {
                    vtep: *vtep,
                    ip: *ip,
                    srv6_sid: *srv6_sid,
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
            EvpnMonitorEvent::FloodUpdate {
                vni,
                vtep,
                srv6_sid,
            } => {
                // `insert` on a map returns the *previous* value, so compare rather
                // than trusting its return: re-learning the same endpoint with the
                // same SID must report "unchanged" and skip a needless re-derive.
                let set = self.floods.entry(*vni).or_default();
                match set.get(vtep) {
                    Some(cur) if cur == srv6_sid => false,
                    _ => {
                        set.insert(*vtep, *srv6_sid);
                        true
                    }
                }
            }
            EvpnMonitorEvent::FloodWithdraw { vni, vtep } => {
                let Some(set) = self.floods.get_mut(vni) else {
                    return false;
                };
                let removed = set.remove(vtep).is_some();
                if set.is_empty() {
                    self.floods.remove(vni);
                }
                removed
            }
            EvpnMonitorEvent::PrefixUpdate {
                l3_vni,
                prefix,
                vtep,
                router_mac,
                gw,
                srv6_sid,
            } => {
                let key = (*l3_vni, prefix.clone());
                let next = LearnedPrefix {
                    vtep: *vtep,
                    router_mac: *router_mac,
                    gw: *gw,
                    srv6_sid: *srv6_sid,
                };
                match self.prefixes.get(&key) {
                    Some(cur) if *cur == next => false,
                    _ => {
                        self.prefixes.insert(key, next);
                        true
                    }
                }
            }
            EvpnMonitorEvent::PrefixWithdraw { l3_vni, prefix } => {
                self.prefixes.remove(&(*l3_vni, prefix.clone())).is_some()
            }
            EvpnMonitorEvent::EndOfDump => false,
        }
    }

    /// Iterate learned type-2 MACs as `(vni, mac, &LearnedMac)`, in a
    /// deterministic order (the derive step relies on this for stable output).
    pub fn iter_macs(&self) -> impl Iterator<Item = (u32, [u8; 6], &LearnedMac)> {
        self.macs.iter().map(|((vni, mac), v)| (*vni, *mac, v))
    }

    /// The learned type-3 BUM flood endpoints per VNI, each mapped to the
    /// advertising PE's `End.DT2M` service SID when it runs SRv6 (`None` on a
    /// VXLAN peer).
    pub fn floods(&self) -> &BTreeMap<u32, BTreeMap<IpAddr, Option<Ipv6Addr>>> {
        &self.floods
    }

    /// Iterate learned type-5 subnets as `(l3_vni, prefix, &LearnedPrefix)`, in a
    /// deterministic order.
    ///
    /// Joined against the topology's IP-VRFs to derive symmetric-IRB routes: a
    /// route names its tenant only by L3 VNI, and the IP-VRF supplies the segments
    /// that may reach it plus the gateway MAC to route it from. Without that join
    /// the derive would have to guess the tenant a subnet belongs to — and guessing
    /// wrong routes one tenant's traffic into another's.
    pub fn iter_prefixes(&self) -> impl Iterator<Item = (u32, &str, &LearnedPrefix)> {
        self.prefixes
            .iter()
            .map(|((vni, p), v)| (*vni, p.as_str(), v))
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
                let floods: usize = learned.floods().values().map(BTreeMap::len).sum();
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
                srv6_sid: None,
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
                srv6_sid: None,
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
                srv6_sid: None,
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
                srv6_sid: None,
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

    /// The bridging lines wren actually emits once an `srv6-locator` is
    /// configured — and the regression that made an SRv6 fabric silently
    /// unreachable.
    ///
    /// `... vtep VT srv6 SID` is ten tokens, exactly as many as `... ip IP vtep
    /// VT`, so the old count-based parser matched the ten-token arm, found `t[6]`
    /// was `vtep` rather than `ip`, and returned `None`. Every type-2 MAC route in
    /// the fabric was dropped at the parser, with no log line and no counter: the
    /// MAC-FDB simply never filled. The twelve-token form (ip *and* srv6) fell off
    /// the end of the match entirely.
    #[test]
    fn a_mac_line_carrying_an_srv6_sid_is_not_dropped() {
        let sid: Ipv6Addr = "fc00:0:1:0:2774::".parse().unwrap();

        // Ten tokens, the shape that used to be rejected.
        assert_eq!(
            parse_evpn_event(
                "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1 srv6 fc00:0:1:0:2774::"
            )
            .unwrap(),
            EvpnMonitorEvent::MacUpdate {
                vni: 10100,
                mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01],
                ip: None,
                vtep: "10.0.0.1".parse().unwrap(),
                srv6_sid: Some(sid),
            }
        );

        // Twelve tokens: a bound IP *and* a SID.
        assert_eq!(
            parse_evpn_event(
                "+ evpn vni 10100 mac 02:00:5e:00:00:01 ip 10.100.0.5 vtep 10.0.0.1 srv6 fc00:0:1:0:2774::"
            )
            .unwrap(),
            EvpnMonitorEvent::MacUpdate {
                vni: 10100,
                mac: [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01],
                ip: Some("10.100.0.5".parse().unwrap()),
                vtep: "10.0.0.1".parse().unwrap(),
                srv6_sid: Some(sid),
            }
        );

        // A flood line carries the peer's *End.DT2M* SID — a different SID from the
        // unicast one above, and the only thing that can address a BUM copy.
        assert_eq!(
            parse_evpn_event("+ evpn vni 10100 flood 10.0.0.1 srv6 fc00:0:1:1:2774::").unwrap(),
            EvpnMonitorEvent::FloodUpdate {
                vni: 10100,
                vtep: "10.0.0.1".parse().unwrap(),
                srv6_sid: Some("fc00:0:1:1:2774::".parse().unwrap()),
            }
        );
    }

    /// Reading the tail as keyword/value pairs must not become "accept anything":
    /// an unknown keyword, a keyword without its value, or an unparsable SID still
    /// rejects the whole line. A half-understood line is one we would program
    /// incompletely, which is worse than not programming it at all.
    #[test]
    fn a_loosely_read_tail_is_still_a_strict_one() {
        for bad in [
            // unknown keyword
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1 label 17",
            // keyword with no value
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1 srv6",
            // SID that is not an address
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep 10.0.0.1 srv6 not-a-sid",
            // an SRv6 SID where an IPv4 VTEP belongs
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 vtep fc00::1 srv6 10.0.0.1",
            // no endpoint at all: a MAC with no way to reach it is not a route
            "+ evpn vni 10100 mac 02:00:5e:00:00:01 srv6 fc00:0:1:0:2774::",
            // flood lines take only the srv6 pair
            "+ evpn vni 10100 flood 10.0.0.1 gw 10.0.0.254",
        ] {
            assert_eq!(
                parse_evpn_event(bad),
                None,
                "should have been refused: {bad}"
            );
        }
    }

    /// The full type-5 line, every optional field present. The Router's MAC is the
    /// inner destination symmetric IRB encapsulates toward, and the SRv6 SID is
    /// where an SRv6 host encapsulates *to*; both must survive the parse. The SID
    /// used to be validated and thrown away here, which was defensible only while
    /// the datapath was VXLAN-only.
    #[test]
    fn parses_prefix_update_with_full_tail() {
        let ev = parse_evpn_event(
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1 \
             router-mac 02:00:5e:00:00:aa gw 10.20.0.1 srv6 fc00:0:1:200:c3b4::",
        )
        .unwrap();
        assert_eq!(
            ev,
            EvpnMonitorEvent::PrefixUpdate {
                l3_vni: 50100,
                prefix: "10.20.0.0/24".into(),
                vtep: "10.0.0.1".parse().unwrap(),
                router_mac: Some([0x02, 0x00, 0x5e, 0x00, 0x00, 0xaa]),
                gw: Some("10.20.0.1".parse().unwrap()),
                srv6_sid: Some("fc00:0:1:200:c3b4::".parse().unwrap()),
            }
        );
    }

    /// The tail is optional and order-independent — it is read as keyword/value
    /// pairs precisely so a line carrying only some of it still parses.
    #[test]
    fn parses_prefix_update_with_partial_and_reordered_tail() {
        let bare =
            parse_evpn_event("+ evpn l3vni 7 prefix 2001:db8::/64 vtep 2001:db8::9").unwrap();
        assert_eq!(
            bare,
            EvpnMonitorEvent::PrefixUpdate {
                l3_vni: 7,
                prefix: "2001:db8::/64".into(),
                vtep: "2001:db8::9".parse().unwrap(),
                router_mac: None,
                gw: None,
                srv6_sid: None,
            }
        );
        let a = parse_evpn_event(
            "+ evpn l3vni 7 prefix 10.0.0.0/8 vtep 10.0.0.1 router-mac aa:bb:cc:dd:ee:ff gw 10.0.0.1",
        );
        let b = parse_evpn_event(
            "+ evpn l3vni 7 prefix 10.0.0.0/8 vtep 10.0.0.1 gw 10.0.0.1 router-mac aa:bb:cc:dd:ee:ff",
        );
        assert_eq!(a, b);
        assert!(a.is_some());
    }

    #[test]
    fn parses_prefix_withdraw() {
        assert_eq!(
            parse_evpn_event("- evpn l3vni 50100 prefix 10.20.0.0/24").unwrap(),
            EvpnMonitorEvent::PrefixWithdraw {
                l3_vni: 50100,
                prefix: "10.20.0.0/24".into(),
            }
        );
    }

    /// An unknown tail keyword rejects the whole line. Skipping it instead would
    /// mean programming a route from a line we only half understood — and the
    /// format is append-only exactly so a future field is a reason to upgrade, not
    /// to silently misread.
    #[test]
    fn rejects_malformed_prefix_lines() {
        for bad in [
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1 encap vxlan", // unknown key
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1 router-mac",  // key, no value
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1 router-mac zz:bb:cc:dd:ee:ff",
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 vtep notanip",
            "+ evpn l3vni 50100 prefix 10.20.0.0/24 10.0.0.1", // missing `vtep`
            "+ evpn l3vni 50100 prefix 10.20.0.0 vtep 10.0.0.1", // not a cidr
            "+ evpn l3vni 50100 prefix 10.20.0.0/33 vtep 10.0.0.1", // v4 length overflow
            "+ evpn l3vni notanumber prefix 10.20.0.0/24 vtep 10.0.0.1",
            "- evpn l3vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1", // withdraw with a tail
            "+ evpn l4vni 50100 prefix 10.20.0.0/24 vtep 10.0.0.1", // unknown keyword
        ] {
            assert!(parse_evpn_event(bad).is_none(), "should reject: {bad}");
        }
    }

    /// The routed VNI is a separate number space from the bridged one: the same
    /// number as an L2 VNI must not collide, and the same prefix in two tenants
    /// must stay two routes.
    #[test]
    fn prefixes_are_keyed_per_l3_vni() {
        let mut learned = EvpnLearned::default();
        for (vni, vtep) in [(50100u32, "10.0.0.1"), (50200, "10.0.0.2")] {
            assert!(learned.apply(&EvpnMonitorEvent::PrefixUpdate {
                l3_vni: vni,
                prefix: "10.20.0.0/24".into(),
                vtep: vtep.parse().unwrap(),
                router_mac: None,
                gw: None,
                srv6_sid: None,
            }));
        }
        assert_eq!(learned.iter_prefixes().count(), 2);
        // A bridging entry on a numerically equal VNI is a different table.
        assert!(learned.apply(&EvpnMonitorEvent::MacUpdate {
            vni: 50100,
            mac: mac("aa:bb:cc:dd:ee:ff"),
            ip: None,
            vtep: "10.0.0.1".parse().unwrap(),
            srv6_sid: None,
        }));
        assert_eq!(learned.iter_prefixes().count(), 2);

        // Re-applying the identical route reports no change, so the controller
        // does not re-derive and re-push every host config for nothing.
        assert!(!learned.apply(&EvpnMonitorEvent::PrefixUpdate {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
            vtep: "10.0.0.1".parse().unwrap(),
            router_mac: None,
            gw: None,
            srv6_sid: None,
        }));
        // A withdraw removes only its own tenant's route.
        assert!(learned.apply(&EvpnMonitorEvent::PrefixWithdraw {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
        }));
        let rest: Vec<_> = learned.iter_prefixes().map(|(v, p, _)| (v, p)).collect();
        assert_eq!(rest, vec![(50200, "10.20.0.0/24")]);
        assert!(!learned.apply(&EvpnMonitorEvent::PrefixWithdraw {
            l3_vni: 50100,
            prefix: "10.20.0.0/24".into(),
        }));
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
            srv6_sid: None,
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
            srv6_sid: None,
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
            srv6_sid: None,
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
