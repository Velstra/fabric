//! Flow insight (roadmap C23): rendering and aggregation of the live NAT flow
//! table for an operator.
//!
//! The data plane already records every NAT'd connection in the `CONNTRACK` LRU
//! (`FlowKey → FlowState`). What was missing was any way to *look* at it: a
//! firewall whose state table is invisible is one you cannot debug.
//!
//! ## What this can and cannot report
//!
//! [`FlowState`] now carries per-flow packet and byte counters, so "top talkers"
//! ranks by **traffic volume** — the question an operator actually has when a
//! link is full. Two things about that ranking are not obvious from the numbers
//! themselves:
//!
//! * A talker is named by the host the traffic **belongs to**, not by the
//!   address in the key. For a masqueraded flow the key's source is the remote
//!   server (the entry describes the reply), while the internal client that
//!   caused the traffic sits in the value's NAT target — so a reverse entry is
//!   attributed to `nat_ip`. Ranking on the key would answer "which server sent
//!   us the most", never "which of my machines is eating the line".
//! * The counters are per node and are not replicated by conntrack sync, so
//!   after a failover a flow's volume restarts. `velstra_common::FlowState`
//!   says why.
//!
//! Everything here is pure so it is unit-tested without a kernel.

use std::{collections::HashMap, fmt::Write as _, net::Ipv4Addr};

use velstra_common::{FlowKey, FlowState, ip_proto};

/// A protocol number as a short name, falling back to the number itself.
fn proto_name(proto: u8) -> String {
    match proto {
        ip_proto::TCP => "tcp".to_string(),
        ip_proto::UDP => "udp".to_string(),
        ip_proto::ICMP => "icmp".to_string(),
        other => other.to_string(),
    }
}

/// Render the flow table as an aligned view, newest-first order not being
/// available (an LRU hash map has no ordering), so entries are sorted by
/// `(policy, source, destination)` for a stable, diffable dump.
///
/// `limit` caps the number of rows; `0` means all. A truncated dump says so —
/// silently showing the first N of a full table would let an operator conclude
/// the box has 50 connections when it has 50 000.
pub fn render_flows(flows: &[(FlowKey, FlowState)], limit: usize) -> String {
    let mut sorted: Vec<&(FlowKey, FlowState)> = flows.iter().collect();
    sorted.sort_by_key(|(k, _)| {
        (
            k.policy, k.src_ip, k.dst_ip, k.src_port, k.dst_port, k.proto,
        )
    });

    let mut out = String::new();
    let _ = writeln!(
        out,
        "  {:<6} {:<5} {:<21} {:<21} {:<22} {:>8} {:>8}",
        "policy", "proto", "source", "destination", "nat", "packets", "bytes"
    );
    let shown: Vec<&&(FlowKey, FlowState)> = if limit == 0 {
        sorted.iter().collect()
    } else {
        sorted.iter().take(limit).collect()
    };
    for (key, state) in shown.iter().map(|e| (&e.0, &e.1)) {
        let src = format!("{}:{}", Ipv4Addr::from(key.src_ip), key.src_port);
        let dst = format!("{}:{}", Ipv4Addr::from(key.dst_ip), key.dst_port);
        // The direction the entry rewrites is the useful part: a reverse entry
        // SNATs a reply's source, a forward one DNATs a request's destination.
        let dir = if state.flags & FlowState::REVERSE != 0 {
            "src"
        } else {
            "dst"
        };
        let nat = format!("{dir}→{}:{}", Ipv4Addr::from(state.nat_ip), state.nat_port);
        let _ = writeln!(
            out,
            "  {:<6} {:<5} {:<21} {:<21} {:<22} {:>8} {:>8}",
            key.policy,
            proto_name(key.proto),
            src,
            dst,
            nat,
            state.packets,
            human_bytes(state.bytes),
        );
    }
    if limit != 0 && sorted.len() > limit {
        let _ = writeln!(
            out,
            "  … {} more (of {} total)",
            sorted.len() - limit,
            sorted.len()
        );
    } else {
        let _ = writeln!(out, "  {} flow(s)", sorted.len());
    }
    out
}

/// The host an entry's traffic should be attributed to.
///
/// Normally that is the key's source, as one would expect. A masqueraded flow is
/// the exception: its single entry is keyed on the *reply*, so the source there
/// is the remote server, and the internal client that caused the traffic appears
/// only as the NAT target. The data plane marks those entries
/// ([`FlowState::ORIGIN`]) precisely because nothing in the addresses reveals it
/// — a load balancer's entry has the same shape and its NAT target is a backend,
/// not an originator. Guessing from the shape produces a ranking of other
/// people's servers, which is never the question being asked.
fn talker(key: &FlowKey, state: &FlowState) -> Ipv4Addr {
    if state.is_origin() {
        Ipv4Addr::from(state.nat_ip)
    } else {
        Ipv4Addr::from(key.src_ip)
    }
}

/// What one host accounts for across its live flows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Talker {
    /// Bytes across every flow attributed to this host.
    pub bytes: u64,
    /// Packets across those flows.
    pub packets: u64,
    /// How many of them are live.
    pub connections: usize,
}

/// Rank hosts by the traffic volume attributed to them, descending.
///
/// Volume rather than connection count: a host holding four hundred idle
/// keep-alives is not the reason a link is saturated, and the table can now
/// answer the question that is actually being asked. The connection count is
/// still carried alongside, because "one flow, ten gigabytes" and "ten thousand
/// flows, ten gigabytes" are very different problems.
///
/// Ties break on bytes, then packets, then the address, so the output is
/// deterministic — an operator comparing two dumps should not see rows shuffle
/// for no reason.
pub fn top_talkers(flows: &[(FlowKey, FlowState)], limit: usize) -> Vec<(Ipv4Addr, Talker)> {
    let mut totals: HashMap<Ipv4Addr, Talker> = HashMap::new();
    for (key, state) in flows {
        let entry = totals.entry(talker(key, state)).or_default();
        entry.bytes = entry.bytes.saturating_add(state.bytes);
        entry.packets = entry.packets.saturating_add(state.packets);
        entry.connections += 1;
    }
    let mut ranked: Vec<(Ipv4Addr, Talker)> = totals.into_iter().collect();
    ranked.sort_by(|a, b| {
        b.1.bytes
            .cmp(&a.1.bytes)
            .then_with(|| b.1.packets.cmp(&a.1.packets))
            .then_with(|| a.0.cmp(&b.0))
    });
    if limit != 0 {
        ranked.truncate(limit);
    }
    ranked
}

/// Render [`top_talkers`], naming every unit explicitly.
pub fn render_top_talkers(flows: &[(FlowKey, FlowState)], limit: usize) -> String {
    let ranked = top_talkers(flows, limit);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "  {:<21} {:>10} {:>12} {:>12}",
        "host", "bytes", "packets", "connections"
    );
    let _ = writeln!(out, "  {:-<21} {:->10} {:->12} {:->12}", "", "", "", "");
    for (addr, t) in &ranked {
        let _ = writeln!(
            out,
            "  {:<21} {:>10} {:>12} {:>12}",
            addr.to_string(),
            human_bytes(t.bytes),
            t.packets,
            t.connections
        );
    }
    if ranked.is_empty() {
        let _ = writeln!(out, "  (no flows)");
    }
    out
}

/// A byte count an operator can read at a glance.
///
/// Binary multiples (1 K = 1024 B), the convention every interface counter on
/// the box already uses; the exact figure is one `show firewall flows` away when
/// it matters. Under 1 K prints as a plain number — rounding 900 bytes to "0 K"
/// would hide the difference between a silent flow and an idle one.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["K", "M", "G", "T", "P"];
    if bytes < 1024 {
        return bytes.to_string();
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    // One decimal below 10 (4.7M reads better than 4M), none above it.
    if value < 10.0 {
        format!("{value:.1}{}", UNITS[unit])
    } else {
        format!("{value:.0}{}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(src: [u8; 4], dst: [u8; 4], sport: u16, proto: u8) -> (FlowKey, FlowState) {
        (
            FlowKey {
                policy: 0,
                src_ip: src,
                dst_ip: dst,
                src_port: sport,
                dst_port: 443,
                proto,
                _pad: [0; 3],
            },
            FlowState::forward([10, 0, 0, 9], 8443),
        )
    }

    /// A flow carrying `bytes` bytes over `packets` packets.
    fn busy(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        packets: u64,
        bytes: u64,
    ) -> (FlowKey, FlowState) {
        let (key, mut state) = flow(src, dst, sport, ip_proto::TCP);
        state.packets = packets;
        state.bytes = bytes;
        (key, state)
    }

    /// The whole point of the counters: the host to look at is the one moving
    /// the traffic, not the one holding the most sockets. A ranking by
    /// connection count puts a host with four hundred idle keep-alives above the
    /// one actually filling the link.
    #[test]
    fn top_talkers_ranks_by_volume_not_by_connection_count() {
        let heavy = [192, 168, 0, 5];
        let chatty = [192, 168, 0, 6];
        let mut flows = vec![busy(heavy, [1, 1, 1, 1], 1000, 900, 9_000_000)];
        // Three times the connections, a thousandth of the traffic.
        flows.extend((0..3).map(|i| busy(chatty, [1, 1, 1, 1], 2000 + i, 4, 400)));

        let ranked = top_talkers(&flows, 0);
        assert_eq!(ranked[0].0, Ipv4Addr::from(heavy));
        assert_eq!(ranked[0].1.bytes, 9_000_000);
        assert_eq!(ranked[0].1.connections, 1);
        assert_eq!(ranked[1].0, Ipv4Addr::from(chatty));
        assert_eq!(ranked[1].1.connections, 3, "connections are still reported");
        assert_eq!(ranked[1].1.bytes, 1200);

        assert_eq!(top_talkers(&flows, 1).len(), 1);
        assert!(top_talkers(&[], 0).is_empty());
    }

    /// Two dumps of one table have to look the same; hash-map order must never
    /// reach the output.
    #[test]
    fn a_tie_breaks_on_the_address_so_two_dumps_match() {
        let a_host = [192, 168, 0, 5];
        let b_host = [192, 168, 0, 6];
        let flows = vec![
            busy(b_host, [1, 1, 1, 1], 1000, 10, 5000),
            busy(a_host, [1, 1, 1, 1], 1001, 10, 5000),
        ];
        let first = top_talkers(&flows, 0);
        assert_eq!(first, top_talkers(&flows, 0));
        assert!(
            first[0].0 < first[1].0,
            "the tie broke on the address: {first:?}"
        );
    }

    /// A masqueraded flow's conntrack entry describes the *reply*, so its key's
    /// source is the remote server. Ranking on the key would answer "which
    /// server sent us the most" — never "which of my machines is eating the
    /// line", which is the question being asked.
    #[test]
    fn a_masqueraded_flow_is_attributed_to_the_internal_client() {
        let client = [10, 0, 0, 7];
        let server = [203, 0, 113, 9];
        // The reply entry: remote → our WAN address, restoring the client.
        let (key, _) = flow(server, [198, 51, 100, 1], 443, ip_proto::TCP);
        let mut state = FlowState::masquerade(client, 51000);
        state.packets = 100;
        state.bytes = 1_000_000;

        let ranked = top_talkers(&[(key, state)], 0);
        assert_eq!(
            ranked[0].0,
            Ipv4Addr::from(client),
            "the download was attributed to the server, not the host that asked for it"
        );
    }

    /// The counterexample that makes the flag necessary rather than a guess: a
    /// load balancer's forward entry has the identical shape — destination
    /// rewrite, an address in the NAT target — but that address is a *backend*.
    /// Attributing to it would credit the pool member with its clients' traffic.
    #[test]
    fn a_load_balanced_flow_is_attributed_to_its_client_not_the_backend() {
        let client = [198, 51, 100, 4];
        let backend = [10, 0, 0, 9];
        let (key, mut state) = flow(client, [203, 0, 113, 10], 40000, ip_proto::TCP);
        state = FlowState::forward(backend, 8443);
        state.bytes = 500_000;

        let ranked = top_talkers(&[(key, state)], 0);
        assert_eq!(ranked[0].0, Ipv4Addr::from(client));
    }

    /// Rounding a real number down to "0" would make a live flow look idle.
    #[test]
    fn byte_counts_stay_readable_without_hiding_small_ones() {
        assert_eq!(human_bytes(0), "0");
        assert_eq!(human_bytes(900), "900");
        assert_eq!(human_bytes(1024), "1.0K");
        assert_eq!(human_bytes(1536), "1.5K");
        assert_eq!(human_bytes(20 * 1024), "20K");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0M");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0G");
    }

    /// Showing the first N rows of a bigger table without saying so would let an
    /// operator conclude the box holds far fewer connections than it does.
    #[test]
    fn a_truncated_dump_says_how_much_it_hid() {
        let flows: Vec<(FlowKey, FlowState)> = (0..5)
            .map(|i| flow([10, 0, 0, 1], [1, 1, 1, 1], 1000 + i, ip_proto::TCP))
            .collect();

        let all = render_flows(&flows, 0);
        assert!(all.contains("5 flow(s)"), "{all}");
        assert!(!all.contains("more (of"), "{all}");

        let capped = render_flows(&flows, 2);
        assert!(capped.contains("… 3 more (of 5 total)"), "{capped}");
    }

    /// The NAT column has to say which side the entry rewrites: a reverse entry
    /// SNATs a reply, a forward one DNATs a request, and reading one as the other
    /// sends you looking for the wrong bug.
    #[test]
    fn the_nat_column_names_the_rewritten_side() {
        let (key, _) = flow([10, 0, 0, 1], [1, 1, 1, 1], 1000, ip_proto::TCP);
        let forward = vec![(key, FlowState::forward([10, 0, 0, 9], 8443))];
        let out = render_flows(&forward, 0);
        assert!(out.contains("dst→10.0.0.9:8443"), "{out}");

        let mut reverse_state = FlowState::forward([203, 0, 113, 1], 443);
        reverse_state.flags |= FlowState::REVERSE;
        let out = render_flows(&[(key, reverse_state)], 0);
        assert!(out.contains("src→203.0.113.1:443"), "{out}");
    }

    /// A flow row without its volume is a row an operator has to correlate by
    /// hand against an interface counter.
    #[test]
    fn a_flow_row_carries_its_own_counters() {
        let out = render_flows(&[busy([10, 0, 0, 1], [1, 1, 1, 1], 1000, 12, 3 * 1024)], 0);
        assert!(out.contains("packets"), "no counter column: {out}");
        assert!(out.contains("12"), "{out}");
        assert!(out.contains("3.0K"), "{out}");
    }

    #[test]
    fn protocols_render_by_name_with_a_numeric_fallback() {
        assert_eq!(proto_name(ip_proto::TCP), "tcp");
        assert_eq!(proto_name(ip_proto::UDP), "udp");
        assert_eq!(proto_name(ip_proto::ICMP), "icmp");
        assert_eq!(proto_name(89), "89");
    }
}
