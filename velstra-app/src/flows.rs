//! Flow insight (roadmap C23): rendering and aggregation of the live NAT flow
//! table for an operator.
//!
//! The data plane already records every NAT'd connection in the `CONNTRACK` LRU
//! (`FlowKey → FlowState`). What was missing was any way to *look* at it: a
//! firewall whose state table is invisible is one you cannot debug.
//!
//! ## What this can and cannot report
//!
//! [`FlowState`] holds NAT targets and flags — **no byte or packet counters**. So
//! "top talkers" here ranks hosts by their number of live connections, which is
//! what the table can actually answer. Ranking by traffic volume would need
//! per-flow counters in the map value, i.e. a data-plane change (and a new
//! conntrack-sync wire format, since C9 replicates that value). Calling a
//! connection count "top talkers by bytes" would be a lie an operator acts on,
//! so the output labels the unit it means.
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
        "  {:<8} {:<5} {:<21} {:<21} nat",
        "policy", "proto", "source", "destination"
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
            "  {:<8} {:<5} {:<21} {:<21} {}",
            key.policy,
            proto_name(key.proto),
            src,
            dst,
            nat
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

/// Rank source addresses by how many live connections they hold, descending.
///
/// Ties break on the address so the output is deterministic — an operator
/// comparing two dumps should not see rows shuffle for no reason.
pub fn top_talkers(flows: &[(FlowKey, FlowState)], limit: usize) -> Vec<(Ipv4Addr, usize)> {
    let mut counts: HashMap<Ipv4Addr, usize> = HashMap::new();
    for (key, _) in flows {
        *counts.entry(Ipv4Addr::from(key.src_ip)).or_insert(0) += 1;
    }
    let mut ranked: Vec<(Ipv4Addr, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    if limit != 0 {
        ranked.truncate(limit);
    }
    ranked
}

/// Render [`top_talkers`], naming the unit explicitly.
pub fn render_top_talkers(flows: &[(FlowKey, FlowState)], limit: usize) -> String {
    let ranked = top_talkers(flows, limit);
    let mut out = String::new();
    let _ = writeln!(out, "  {:<21} {:>12}", "source", "connections");
    let _ = writeln!(out, "  {:-<21} {:->12}", "", "");
    for (addr, count) in &ranked {
        let _ = writeln!(out, "  {:<21} {:>12}", addr.to_string(), count);
    }
    if ranked.is_empty() {
        let _ = writeln!(out, "  (no flows)");
    }
    out
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

    #[test]
    fn top_talkers_ranks_by_connection_count_and_breaks_ties_stably() {
        let noisy = [192, 168, 0, 5];
        let quiet = [192, 168, 0, 6];
        let mut flows = vec![
            flow(quiet, [1, 1, 1, 1], 1000, ip_proto::TCP),
            flow(noisy, [1, 1, 1, 1], 1001, ip_proto::TCP),
            flow(noisy, [1, 1, 1, 1], 1002, ip_proto::TCP),
            flow(noisy, [1, 1, 1, 1], 1003, ip_proto::TCP),
        ];
        let ranked = top_talkers(&flows, 0);
        assert_eq!(ranked[0], (Ipv4Addr::from(noisy), 3));
        assert_eq!(ranked[1], (Ipv4Addr::from(quiet), 1));

        // A tie must resolve on the address, not on hash-map order — two dumps of
        // the same table have to look the same.
        flows.push(flow(quiet, [2, 2, 2, 2], 1004, ip_proto::TCP));
        flows.push(flow(quiet, [2, 2, 2, 2], 1005, ip_proto::TCP));
        let a = top_talkers(&flows, 0);
        let b = top_talkers(&flows, 0);
        assert_eq!(a, b);
        assert_eq!(a[0].1, 3);
        assert_eq!(a[1].1, 3);
        assert!(a[0].0 < a[1].0, "the tie broke on the address: {a:?}");

        assert_eq!(top_talkers(&flows, 1).len(), 1);
        assert!(top_talkers(&[], 0).is_empty());
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

    #[test]
    fn protocols_render_by_name_with_a_numeric_fallback() {
        assert_eq!(proto_name(ip_proto::TCP), "tcp");
        assert_eq!(proto_name(ip_proto::UDP), "udp");
        assert_eq!(proto_name(ip_proto::ICMP), "icmp");
        assert_eq!(proto_name(89), "89");
    }
}
