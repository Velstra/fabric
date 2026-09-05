//! Routes from Wren into the `ROUTES` trie — the FPM half of the split.
//!
//! Wren is the brain and the fabric owns the data path: that split was chosen
//! for EVPN (this agent advertises what it learns, Wren speaks BGP) and it is
//! kept here for unicast. Wren streams its forwarding table on the control
//! socket (`monitor routes`: a snapshot, then `+`/`-` lines as the RIB moves),
//! which is exactly what FRR's zebra hands an external forwarder through the
//! Forwarding Plane Manager. This module is the subscriber: it takes that
//! feed, resolves each next hop to the MAC the XDP program has to write into
//! the frame, and programs `ROUTES`. Without it, dynamic routing converged in
//! Wren while XDP kept forwarding from static and controller state.
//!
//! ## What it does, and does not, program
//!
//! A route is programmable when it has a **gateway on a link this box has an
//! ARP entry for**: the trie entry is `(policy, prefix) → (out ifindex, src
//! MAC, gateway MAC)`, and a next hop the kernel has not resolved is a frame
//! with no destination address. An unresolved gateway is not an error — the
//! kernel is nudged (a zero-length UDP datagram is enough to make it ARP) and
//! the route is tried again on the next pass. A route with a device and no
//! gateway is on-link and is left to the kernel: every host behind it has its
//! own MAC, and a single trie entry cannot say which. IPv6 prefixes are
//! skipped with a debug line, because `ROUTES` is IPv4 (see the fabric's IPv6
//! issue). Only one table is followed, the main one unless told otherwise.
//!
//! ## Precedence
//!
//! A static route in the agent's own configuration wins over a learned one for
//! the same destination. The operator wrote the static one on purpose, and a
//! routing protocol that could override it would be a routing protocol that
//! could take a box off its management network.
//!
//! ## Best effort, like the advertiser
//!
//! Wren restarting, the socket vanishing, a line this parser does not know:
//! none of it kills the agent. The subscription is retried with backoff, and
//! until it is back the routes already in the trie stay in force — a forwarder
//! that dropped its FIB because its route source blinked would turn every Wren
//! restart into an outage.

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use log::{debug, info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::Mutex,
};
use velstra_common::{Cidr4, PolicyId, RouteEntry, parse_cidr_v4};
use velstra_config::ResolvedRoute;

use crate::firewall::Firewall;

/// One line of `monitor routes`, parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// `+ <prefix> table <t> [via <gw>] [dev <dev>] … proto <p> metric <m>`.
    Install {
        prefix: Cidr4,
        table: u32,
        gateway: Option<Ipv4Addr>,
        dev: Option<String>,
    },
    /// `- <prefix> table <t>`.
    Withdraw { prefix: Cidr4, table: u32 },
    /// `% end-of-dump` — the snapshot is complete; what follows is live.
    EndOfDump,
    /// A line this forwarder cannot use — an IPv6 prefix today — with why.
    Skipped(String),
}

/// Parse one line of the feed. A line the grammar does not cover is an error
/// with the line in it, so a Wren that grew a word is visible in the log
/// rather than silently unrouted.
pub fn parse_line(line: &str) -> Result<Line, String> {
    let line = line.trim();
    if line == "% end-of-dump" {
        return Ok(Line::EndOfDump);
    }
    let mut words = line.split_whitespace();
    let mark = words.next().ok_or_else(|| "empty line".to_string())?;
    let prefix = words
        .next()
        .ok_or_else(|| format!("no prefix in {line:?}"))?;
    if prefix.contains(':') {
        return Ok(Line::Skipped(format!(
            "{prefix} is IPv6, and the ROUTES trie is IPv4"
        )));
    }
    let prefix = parse_cidr_v4(prefix).map_err(|e| format!("prefix in {line:?}: {e:?}"))?;
    let mut table = None;
    let mut gateway = None;
    let mut dev = None;
    while let Some(word) = words.next() {
        match word {
            "table" => {
                table = Some(
                    words
                        .next()
                        .and_then(|t| t.parse::<u32>().ok())
                        .ok_or_else(|| format!("table without a number in {line:?}"))?,
                );
            }
            "via" => {
                let gw = words
                    .next()
                    .ok_or_else(|| format!("via without an address in {line:?}"))?;
                match gw.parse::<Ipv4Addr>() {
                    Ok(v4) => gateway = Some(v4),
                    Err(_) => {
                        return Ok(Line::Skipped(format!(
                            "{prefix} via {gw}: an IPv6 next hop for an IPv4 prefix (RFC 5549) \
                             needs a neighbour this forwarder does not resolve yet"
                        )));
                    }
                }
            }
            "dev" => {
                dev = Some(
                    words
                        .next()
                        .ok_or_else(|| format!("dev without a name in {line:?}"))?
                        .to_string(),
                );
            }
            // `proto <p>` and `metric <m>` carry nothing this forwarder keys on.
            "proto" | "metric" => {
                words.next();
            }
            other => return Err(format!("unknown word {other:?} in {line:?}")),
        }
    }
    let table = table.ok_or_else(|| format!("no table in {line:?}"))?;
    match mark {
        "+" => Ok(Line::Install {
            prefix,
            table,
            gateway,
            dev,
        }),
        "-" => Ok(Line::Withdraw { prefix, table }),
        other => Err(format!("line starts with {other:?}, not + or -")),
    }
}

/// What Wren said about one prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Learned {
    pub gateway: Option<Ipv4Addr>,
    pub dev: Option<String>,
}

/// The routes Wren currently has in the followed table.
#[derive(Debug, Default)]
pub struct Store {
    table: u32,
    routes: BTreeMap<(u32, u8), (Cidr4, Learned)>,
}

fn key(prefix: &Cidr4) -> (u32, u8) {
    (u32::from_be_bytes(prefix.octets), prefix.prefix)
}

impl Store {
    pub fn new(table: u32) -> Self {
        Self {
            table,
            routes: BTreeMap::new(),
        }
    }

    /// Apply one line; `true` when the set changed. Lines for other tables are
    /// not an error, they are somebody else's VRF.
    pub fn apply(&mut self, line: Line) -> bool {
        match line {
            Line::Install {
                prefix,
                table,
                gateway,
                dev,
            } if table == self.table => {
                let learned = Learned { gateway, dev };
                self.routes
                    .insert(key(&prefix), (prefix, learned.clone()))
                    .is_none_or(|(_, old)| old != learned)
            }
            Line::Withdraw { prefix, table } if table == self.table => {
                self.routes.remove(&key(&prefix)).is_some()
            }
            Line::Install { .. } | Line::Withdraw { .. } | Line::EndOfDump => false,
            Line::Skipped(why) => {
                debug!("wren routes: {why}");
                false
            }
        }
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Cidr4, &Learned)> {
        self.routes.values().map(|(p, l)| (p, l))
    }
}

/// What the kernel has resolved: address → its MAC and the link it is on.
///
/// Taken as a snapshot rather than queried per route. `/proc/net/arp` is a file
/// read, and one per route inside the loop that also reads the feed would put a
/// blocking read on the async path once per route per pass.
pub type ArpTable = BTreeMap<Ipv4Addr, ([u8; 6], String)>;

/// The kernel's ARP table, as `/proc/net/arp` prints it.
pub struct ProcArp;

impl ProcArp {
    /// Read and parse the whole table. Blocking; call it off the runtime.
    pub fn read() -> ArpTable {
        std::fs::read_to_string("/proc/net/arp")
            .map(|text| Self::parse(&text))
            .unwrap_or_default()
    }

    /// "IP address  HW type  Flags  HW address  Mask  Device"; flag 0x2 is a
    /// complete entry, and an incomplete one names no MAC worth writing.
    pub fn parse(text: &str) -> ArpTable {
        text.lines()
            .skip(1)
            .filter_map(|line| {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 6 {
                    return None;
                }
                let ip: Ipv4Addr = f[0].parse().ok()?;
                let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).ok()?;
                if flags & 0x2 == 0 {
                    return None;
                }
                let mac = velstra_common::parse_mac(f[3]).ok()?;
                Some((ip, (mac, f[5].to_string())))
            })
            .collect()
    }
}

/// Ask the kernel to resolve `ip`, so the next pass finds it. A zero-length
/// datagram to the discard port: nothing answers, and the kernel has to resolve
/// the address before it can send. Best effort.
pub fn nudge(ip: Ipv4Addr) {
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        let _ = socket.send_to(&[], (ip, 9));
    }
}

/// What one pass made of what Wren said: the routes that can be programmed, the
/// ones that cannot and why, and the gateways worth asking the kernel about.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Resolved {
    pub routes: Vec<ResolvedRoute>,
    pub waiting: Vec<(Cidr4, String)>,
    pub unresolved: Vec<Ipv4Addr>,
}

/// Turn what Wren said into what the trie takes. The second list is the
/// routes that could not be programmed this pass and why — logged once each
/// time the set changes, not every pass, because "still unresolved" is not
/// news.
pub fn resolve(store: &Store, arp: &ArpTable, policy: PolicyId) -> Resolved {
    let mut out = Resolved::default();
    for (prefix, learned) in store.iter() {
        let Some(gateway) = learned.gateway else {
            out.waiting.push((
                *prefix,
                "on-link, no gateway: every host behind it has its own MAC, left to the kernel"
                    .into(),
            ));
            continue;
        };
        match arp.get(&gateway) {
            Some((mac, dev)) => out.routes.push(ResolvedRoute {
                policy,
                dest: *prefix,
                out_iface: learned.dev.clone().unwrap_or_else(|| dev.clone()),
                src_mac: None,
                dst_mac: *mac,
                flags: RouteEntry::DECREMENT_TTL,
            }),
            None => {
                out.unresolved.push(gateway);
                out.waiting.push((
                    *prefix,
                    format!("gateway {gateway} is not in the ARP table yet"),
                ));
            }
        }
    }
    out
}

const BACKOFF_FLOOR: Duration = Duration::from_millis(500);
const BACKOFF_CEIL: Duration = Duration::from_secs(10);
/// How often unresolved next hops are tried again while nothing else moves.
const RERESOLVE: Duration = Duration::from_secs(5);

/// Follow Wren's forwarding table for as long as the agent runs.
pub async fn follow(socket: PathBuf, firewall: Arc<Mutex<Firewall>>, policy: PolicyId, table: u32) {
    let mut backoff = BACKOFF_FLOOR;
    loop {
        match subscribe(&socket, &firewall, policy, table).await {
            Ok(()) => {
                info!("wren closed the routes feed; resubscribing");
                backoff = BACKOFF_FLOOR;
            }
            Err(e) => {
                warn!(
                    "wren routes feed unavailable ({e}); retrying in {:.1}s, keeping what is programmed",
                    backoff.as_secs_f32()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_CEIL);
                continue;
            }
        }
        tokio::time::sleep(BACKOFF_FLOOR).await;
    }
}

async fn subscribe(
    socket: &Path,
    firewall: &Arc<Mutex<Firewall>>,
    policy: PolicyId,
    table: u32,
) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(b"monitor routes\n").await?;
    stream.flush().await?;
    info!(
        "subscribed to wren's routes feed at {} (table {table} → policy {policy})",
        socket.display()
    );

    let mut store = Store::new(table);
    let mut lines = BufReader::new(stream).lines();
    let mut settled = false;
    let mut last_waiting: Vec<(Cidr4, String)> = Vec::new();
    let mut tick = tokio::time::interval(RERESOLVE);
    tick.tick().await; // the first tick is immediate; the feed's snapshot comes first

    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line? else { return Ok(()) };
                if line.is_empty() {
                    continue;
                }
                if !line.starts_with(['+', '-', '%']) {
                    // An error, not a clean close: the caller's Ok arm resets
                    // the backoff and reconnects at once, which against a wren
                    // that keeps refusing is a retry every half second for ever.
                    return Err(std::io::Error::other(format!(
                        "wren refused the routes subscription: {line}"
                    )));
                }
                match parse_line(&line) {
                    Ok(Line::EndOfDump) => {
                        // Always, even for an empty snapshot with nothing
                        // dirty. A reconnect after wren lost its last route
                        // sends exactly that, and skipping it would leave the
                        // routes from the previous connection programmed for
                        // ever — the trie would be a memory of a table that no
                        // longer exists.
                        settled = true;
                        push(firewall, &store, policy, &mut last_waiting).await;
                    }
                    Ok(parsed) => {
                        // Before the snapshot ends, nothing is programmed:
                        // end-of-dump pushes whatever the store holds by then,
                        // so a half-read snapshot never reaches the trie.
                        if store.apply(parsed) && settled {
                            push(firewall, &store, policy, &mut last_waiting).await;
                        }
                    }
                    Err(why) => warn!("wren routes: {why}"),
                }
            }
            _ = tick.tick() => {
                // Nothing moved in Wren; a gateway may have been resolved since.
                if settled && !last_waiting.is_empty() {
                    push(firewall, &store, policy, &mut last_waiting).await;
                }
            }
        }
    }
}

async fn push(
    firewall: &Arc<Mutex<Firewall>>,
    store: &Store,
    policy: PolicyId,
    last_waiting: &mut Vec<(Cidr4, String)>,
) {
    // Reading /proc and sending a datagram are both blocking, and this runs on
    // the task that is also reading the feed. Off the runtime with both.
    let arp = tokio::task::spawn_blocking(ProcArp::read)
        .await
        .unwrap_or_default();
    let Resolved {
        routes,
        waiting,
        unresolved,
    } = resolve(store, &arp, policy);
    if !unresolved.is_empty() {
        let _ = tokio::task::spawn_blocking(move || unresolved.into_iter().for_each(nudge)).await;
    }
    if waiting != *last_waiting {
        for (prefix, why) in &waiting {
            info!("wren route {prefix} not programmed: {why}");
        }
        *last_waiting = waiting;
    }
    let programmed = routes.len();
    match firewall.lock().await.set_dynamic_routes(routes) {
        Ok(true) => info!(
            "wren routes: {programmed} programmed, {} waiting, {} known",
            last_waiting.len(),
            store.len()
        ),
        Ok(false) => {}
        Err(e) => warn!("wren routes could not be programmed ({e:#}); keeping the previous set"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr4 {
        parse_cidr_v4(s).unwrap()
    }

    #[test]
    fn the_three_line_shapes_parse_and_a_stranger_word_is_refused() {
        assert_eq!(
            parse_line("+ 10.20.0.0/24 table 254 via 10.0.0.2 dev eth1 proto bgp metric 1"),
            Ok(Line::Install {
                prefix: cidr("10.20.0.0/24"),
                table: 254,
                gateway: Some("10.0.0.2".parse().unwrap()),
                dev: Some("eth1".into()),
            })
        );
        assert_eq!(
            parse_line("+ 10.30.0.0/16 table 254 via 10.0.0.9 proto ospf metric 20"),
            Ok(Line::Install {
                prefix: cidr("10.30.0.0/16"),
                table: 254,
                gateway: Some("10.0.0.9".parse().unwrap()),
                dev: None,
            })
        );
        assert_eq!(
            parse_line("- 10.20.0.0/24 table 254"),
            Ok(Line::Withdraw {
                prefix: cidr("10.20.0.0/24"),
                table: 254
            })
        );
        assert_eq!(parse_line("% end-of-dump"), Ok(Line::EndOfDump));
        assert!(matches!(
            parse_line("+ 2001:db8::/32 table 254 via fe80::1 dev eth1 proto bgp metric 1"),
            Ok(Line::Skipped(_))
        ));
        assert!(matches!(
            parse_line("+ 10.0.0.0/8 table 254 via fe80::1 dev eth1 proto bgp metric 1"),
            Ok(Line::Skipped(_))
        ));
        assert!(
            parse_line("+ 10.0.0.0/8 table 254 weight 3 proto bgp metric 1")
                .unwrap_err()
                .contains("weight")
        );
        assert!(
            parse_line("+ 10.0.0.0/8 via 10.0.0.1")
                .unwrap_err()
                .contains("no table")
        );
        assert!(
            parse_line("? 10.0.0.0/8 table 254")
                .unwrap_err()
                .contains("not + or -")
        );
    }

    #[test]
    fn the_store_follows_installs_and_withdraws_in_its_table_only() {
        let mut store = Store::new(254);
        let install = |p: &str, t: u32| Line::Install {
            prefix: cidr(p),
            table: t,
            gateway: Some("10.0.0.2".parse().unwrap()),
            dev: None,
        };
        assert!(store.apply(install("10.20.0.0/24", 254)));
        assert!(
            !store.apply(install("10.20.0.0/24", 254)),
            "the same route again is not a change"
        );
        assert!(
            !store.apply(install("10.99.0.0/24", 100)),
            "another table is another VRF"
        );
        assert_eq!(store.len(), 1);
        assert!(store.apply(Line::Withdraw {
            prefix: cidr("10.20.0.0/24"),
            table: 254
        }));
        assert!(!store.apply(Line::Withdraw {
            prefix: cidr("10.20.0.0/24"),
            table: 254
        }));
        assert_eq!(store.len(), 0);
        assert!(!store.apply(Line::EndOfDump));
        assert!(!store.apply(Line::Skipped("v6".into())));
    }

    fn arp(entries: &[(&str, [u8; 6], &str)]) -> ArpTable {
        entries
            .iter()
            .map(|(ip, mac, dev)| (ip.parse().unwrap(), (*mac, dev.to_string())))
            .collect()
    }

    #[test]
    fn a_resolved_gateway_becomes_a_route_and_an_unresolved_one_waits_to_be_asked_about() {
        let mut store = Store::new(254);
        for (p, gw, dev) in [
            ("10.20.0.0/24", Some("10.0.0.2"), None),
            ("10.30.0.0/24", Some("10.0.0.3"), Some("eth9")),
            ("10.40.0.0/24", Some("10.0.0.4"), None),
            ("10.50.0.0/24", None, Some("eth1")),
        ] {
            store.apply(Line::Install {
                prefix: cidr(p),
                table: 254,
                gateway: gw.map(|g| g.parse().unwrap()),
                dev: dev.map(str::to_string),
            });
        }
        let table = arp(&[
            ("10.0.0.2", [1, 2, 3, 4, 5, 6], "eth1"),
            ("10.0.0.3", [1, 2, 3, 4, 5, 7], "eth1"),
        ]);
        let Resolved {
            routes,
            waiting,
            unresolved,
        } = resolve(&store, &table, 3);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].dest, cidr("10.20.0.0/24"));
        assert_eq!(
            routes[0].out_iface, "eth1",
            "the ARP table's device when wren names none"
        );
        assert_eq!(routes[0].dst_mac, [1, 2, 3, 4, 5, 6]);
        assert_eq!(routes[0].policy, 3);
        assert_eq!(routes[0].flags, RouteEntry::DECREMENT_TTL);
        assert_eq!(
            routes[1].out_iface, "eth9",
            "wren's device wins when it names one"
        );
        assert_eq!(waiting.len(), 2, "{waiting:?}");
        assert!(waiting[0].1.contains("not in the ARP table"));
        assert!(waiting[1].1.contains("on-link"));
        // The gateway nobody has resolved is the one to ask the kernel about,
        // and the on-link route is not — there is no single next hop to ask for.
        assert_eq!(unresolved, vec!["10.0.0.4".parse::<Ipv4Addr>().unwrap()]);
    }

    #[test]
    fn the_arp_table_is_read_as_the_kernel_prints_it() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    10.8.0.2         0x1         0x2         52:54:00:12:34:56     *        eth1\n\
                    10.8.0.3         0x1         0x0         00:00:00:00:00:00     *        eth1\n";
        let table = ProcArp::parse(text);
        assert_eq!(
            table.get(&"10.8.0.2".parse().unwrap()),
            Some(&([0x52, 0x54, 0, 0x12, 0x34, 0x56], "eth1".to_string()))
        );
        assert!(
            !table.contains_key(&"10.8.0.3".parse().unwrap()),
            "an incomplete entry names no MAC and must not be read as one"
        );
        assert_eq!(table.len(), 1, "only the complete entry: {table:?}");
    }
}
