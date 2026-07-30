//! C12 — **IPFIX flow export** (RFC 7011).
//!
//! The appliance knows every translated connection and, since the data plane
//! started counting, how much each one carried. That is exactly what a flow
//! collector wants, and shipping it is the difference between a firewall that
//! can answer "what happened last Tuesday" and one that can only answer "what is
//! happening now".
//!
//! ## Deltas, not totals
//!
//! The single thing a flow exporter has to get right. The map holds a running
//! total per flow; a collector adds up what it receives. Sending the total each
//! interval would therefore make every byte count again on every export — a
//! connection idle for an hour would report its whole volume sixty times.
//!
//! So the exporter remembers what it last sent for each flow and ships the
//! difference, which is what `octetDeltaCount` and `packetDeltaCount` mean. Two
//! consequences follow and both are deliberate:
//!
//! * A flow whose counters did not move is **not exported**. It carried nothing;
//!   a record saying zero is noise a collector has to store.
//! * A flow that vanished from the LRU and came back is a new flow with a
//!   smaller total, so the difference is computed saturating — a counter that
//!   went *backwards* exports nothing rather than an enormous number.
//!
//! ## What is exported, and what is not
//!
//! Only what the data plane actually knows: the five-tuple and the two counters.
//! There are no timestamps, because the map holds none — inventing "first seen"
//! from when the exporter noticed a flow would put a plausible, wrong number in
//! a record an operator later reasons about. Only NAT'd connections appear at
//! all, for the reason `flows.rs` gives.
//!
//! The encoder is pure and unit-tested; only [`run`] needs a socket.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, MapData};
use log::{info, warn};
use tokio::{net::UdpSocket, sync::Mutex};
use velstra_common::{FlowKey, FlowState};

/// IPFIX version, per RFC 7011 §3.1. Ten, not nine — nine is NetFlow.
const VERSION: u16 = 10;
/// Set ID reserved for a template set (RFC 7011 §3.3.2).
const SET_TEMPLATE: u16 = 2;
/// The template this exporter defines. Anything from 256 up is ours to choose.
const TEMPLATE_ID: u16 = 256;
/// Message header: version, length, export time, sequence, domain.
const HEADER_LEN: usize = 16;
/// One data record: the five-tuple plus the two counters.
const RECORD_LEN: usize = 4 + 4 + 2 + 2 + 1 + 8 + 8;

/// The information elements a record carries, as `(id, length)` — IANA IPFIX
/// element IDs, so a collector needs nothing from us to read them.
const FIELDS: [(u16, u16); 7] = [
    (8, 4),  // sourceIPv4Address
    (12, 4), // destinationIPv4Address
    (7, 2),  // sourceTransportPort
    (11, 2), // destinationTransportPort
    (4, 1),  // protocolIdentifier
    (1, 8),  // octetDeltaCount
    (2, 8),  // packetDeltaCount
];

/// How many records fit in one datagram without relying on IP fragmentation.
///
/// A fragmented flow export is one a firewall in the path may drop, which would
/// lose whole batches silently — the failure mode a collector cannot detect.
const MAX_RECORDS: usize = 24;

/// What was last exported for one flow, so the next export can be a difference.
#[derive(Clone, Copy, Default)]
struct Sent {
    packets: u64,
    bytes: u64,
}

/// One flow's change since the last export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowDelta {
    /// The flow this describes.
    pub key: FlowKey,
    /// Bytes since the last export.
    pub bytes: u64,
    /// Packets since the last export.
    pub packets: u64,
}

/// Compute what to export, and update the record of what has been sent.
///
/// Flows whose counters did not move are left out entirely; see the module
/// header. `seen` is updated in place, and flows absent from `flows` are
/// forgotten so a long-running exporter does not accumulate every flow the box
/// has ever had.
fn deltas(flows: &[(FlowKey, FlowState)], seen: &mut HashMap<FlowKey, Sent>) -> Vec<FlowDelta> {
    let mut out = Vec::new();
    let mut still_here = HashMap::with_capacity(flows.len());
    for (key, state) in flows {
        let before = seen.get(key).copied().unwrap_or_default();
        // Saturating: an LRU eviction and re-creation makes the total smaller
        // than what was last sent, and the honest report of that is "nothing
        // new", not a counter's worth of imaginary traffic.
        let bytes = state.bytes.saturating_sub(before.bytes);
        let packets = state.packets.saturating_sub(before.packets);
        still_here.insert(
            *key,
            Sent {
                packets: state.packets,
                bytes: state.bytes,
            },
        );
        if bytes == 0 && packets == 0 {
            continue;
        }
        out.push(FlowDelta {
            key: *key,
            bytes,
            packets,
        });
    }
    *seen = still_here;
    out
}

/// Encode one IPFIX message: the template, then up to [`MAX_RECORDS`] records.
///
/// The template is repeated in **every** message rather than sent once. A
/// collector that restarts, or that joined the multicast group late, has no way
/// to ask for it, and a data set it cannot decode is silently discarded — so
/// thirty-six bytes per message buys away a failure nobody would notice.
pub fn encode_message(
    domain: u32,
    export_time: u32,
    sequence: u32,
    records: &[FlowDelta],
) -> Vec<u8> {
    let template_len = 4 + 4 + FIELDS.len() * 4;
    let data_len = if records.is_empty() {
        0
    } else {
        4 + records.len() * RECORD_LEN
    };
    let total = HEADER_LEN + template_len + data_len;

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&VERSION.to_be_bytes());
    buf.extend_from_slice(&(total as u16).to_be_bytes());
    buf.extend_from_slice(&export_time.to_be_bytes());
    buf.extend_from_slice(&sequence.to_be_bytes());
    buf.extend_from_slice(&domain.to_be_bytes());

    // Template set.
    buf.extend_from_slice(&SET_TEMPLATE.to_be_bytes());
    buf.extend_from_slice(&(template_len as u16).to_be_bytes());
    buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
    buf.extend_from_slice(&(FIELDS.len() as u16).to_be_bytes());
    for (id, len) in FIELDS {
        buf.extend_from_slice(&id.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
    }

    // Data set.
    if !records.is_empty() {
        buf.extend_from_slice(&TEMPLATE_ID.to_be_bytes());
        buf.extend_from_slice(&(data_len as u16).to_be_bytes());
        for r in records {
            buf.extend_from_slice(&r.key.src_ip);
            buf.extend_from_slice(&r.key.dst_ip);
            buf.extend_from_slice(&r.key.src_port.to_be_bytes());
            buf.extend_from_slice(&r.key.dst_port.to_be_bytes());
            buf.push(r.key.proto);
            buf.extend_from_slice(&r.bytes.to_be_bytes());
            buf.extend_from_slice(&r.packets.to_be_bytes());
        }
    }
    buf
}

/// Export the conntrack table to a collector, forever.
///
/// Best-effort by design: a collector that is down must never hold up the data
/// plane, so a failed send warns and the next interval tries again. The
/// sequence number counts **data records**, as RFC 7011 §3.1 requires — a
/// collector uses it to notice loss, and counting messages instead would make
/// it under-report exactly when it mattered.
pub async fn run(
    conntrack: Arc<Mutex<AyaHashMap<MapData, FlowKey, FlowState>>>,
    collector: SocketAddr,
    domain: u32,
    interval_secs: u64,
) {
    let socket = match UdpSocket::bind(("0.0.0.0", 0)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("ipfix: cannot open a socket: {e}");
            return;
        }
    };
    info!("ipfix: exporting to {collector} every {interval_secs}s (domain {domain})");

    let mut seen: HashMap<FlowKey, Sent> = HashMap::new();
    let mut sequence: u32 = 0;
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;

        let flows: Vec<(FlowKey, FlowState)> = {
            let map = conntrack.lock().await;
            map.iter().filter_map(|e| e.ok()).collect()
        };
        let records = deltas(&flows, &mut seen);
        if records.is_empty() {
            continue;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        for chunk in records.chunks(MAX_RECORDS) {
            let msg = encode_message(domain, now, sequence, chunk);
            if let Err(e) = socket.send_to(&msg, collector).await {
                warn!("ipfix: send to {collector} failed: {e}");
                break; // the collector is unreachable; try again next interval
            }
            sequence = sequence.wrapping_add(chunk.len() as u32);
        }
    }
}

/// Resolve a `host:port` collector address.
pub fn parse_collector(spec: &str) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    spec.to_socket_addrs()
        .with_context(|| format!("resolving flow collector {spec:?}"))?
        .next()
        .with_context(|| format!("{spec:?} resolved to nothing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(src: [u8; 4], sport: u16) -> FlowKey {
        FlowKey::new(0, src, [203, 0, 113, 5], sport, 443, 6)
    }

    fn state(packets: u64, bytes: u64) -> FlowState {
        let mut s = FlowState::forward([10, 0, 0, 9], 8443);
        s.packets = packets;
        s.bytes = bytes;
        s
    }

    /// The one thing an exporter must get right. The map holds totals; a
    /// collector adds up what it receives, so sending totals would count every
    /// byte again on every interval.
    #[test]
    fn what_is_exported_is_the_change_not_the_total() {
        let mut seen = HashMap::new();
        let k = key([10, 0, 0, 1], 40000);

        let first = deltas(&[(k, state(10, 1000))], &mut seen);
        assert_eq!(first.len(), 1);
        assert_eq!((first[0].packets, first[0].bytes), (10, 1000));

        // The flow carried 5 more packets and 500 more bytes.
        let second = deltas(&[(k, state(15, 1500))], &mut seen);
        assert_eq!((second[0].packets, second[0].bytes), (5, 500));
    }

    /// A flow that carried nothing since the last export is not a record worth
    /// storing; a collector should not have to hold a row saying zero.
    #[test]
    fn an_idle_flow_is_not_exported() {
        let mut seen = HashMap::new();
        let k = key([10, 0, 0, 1], 40000);
        assert_eq!(deltas(&[(k, state(10, 1000))], &mut seen).len(), 1);
        assert!(deltas(&[(k, state(10, 1000))], &mut seen).is_empty());
    }

    /// An LRU eviction and re-creation makes a flow's total smaller than what
    /// was last sent. The honest report is "nothing new" — the alternative is a
    /// counter's worth of traffic that never happened.
    #[test]
    fn a_counter_that_went_backwards_exports_nothing() {
        let mut seen = HashMap::new();
        let k = key([10, 0, 0, 1], 40000);
        deltas(&[(k, state(1000, 5_000_000))], &mut seen);
        let after = deltas(&[(k, state(3, 400))], &mut seen);
        assert!(after.is_empty(), "{after:?}");
        // …and the next real growth is measured from the new, smaller total.
        let grown = deltas(&[(k, state(9, 900))], &mut seen);
        assert_eq!((grown[0].packets, grown[0].bytes), (6, 500));
    }

    /// A flow gone from the map is forgotten, or an exporter that runs for
    /// months accumulates every flow the box has ever had.
    #[test]
    fn a_vanished_flow_is_forgotten() {
        let mut seen = HashMap::new();
        let k = key([10, 0, 0, 1], 40000);
        deltas(&[(k, state(10, 1000))], &mut seen);
        deltas(&[], &mut seen);
        assert!(seen.is_empty());
        // Coming back, it is a new flow and its whole total is new traffic.
        let back = deltas(&[(k, state(4, 400))], &mut seen);
        assert_eq!((back[0].packets, back[0].bytes), (4, 400));
    }

    /// A collector decodes by the header, so the header has to be exactly what
    /// RFC 7011 §3.1 describes — including the length, which is how it finds
    /// the end of a message it may have read together with the next one.
    #[test]
    fn a_message_is_shaped_the_way_a_collector_reads_it() {
        let r = FlowDelta {
            key: key([10, 0, 0, 1], 40000),
            bytes: 1500,
            packets: 12,
        };
        let msg = encode_message(7, 0x6800_0000, 42, &[r]);

        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), 10, "not IPFIX");
        assert_eq!(
            u16::from_be_bytes([msg[2], msg[3]]) as usize,
            msg.len(),
            "the stated length is not the real one"
        );
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            0x6800_0000
        );
        assert_eq!(u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]), 42);
        assert_eq!(u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]), 7);

        // Template set, then the data set it describes.
        assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), SET_TEMPLATE);
        let tmpl_len = u16::from_be_bytes([msg[18], msg[19]]) as usize;
        let data = 16 + tmpl_len;
        assert_eq!(u16::from_be_bytes([msg[data], msg[data + 1]]), TEMPLATE_ID);
        assert_eq!(
            u16::from_be_bytes([msg[data + 2], msg[data + 3]]) as usize,
            4 + RECORD_LEN
        );
    }

    /// The template describes the record, so a field list and a record length
    /// that disagree would make a collector read the next record's bytes as
    /// this one's. They are derived from the same place; this proves it.
    #[test]
    fn the_template_describes_the_record_it_precedes() {
        let declared: usize = FIELDS.iter().map(|(_, len)| *len as usize).sum();
        assert_eq!(declared, RECORD_LEN);

        let msg = encode_message(1, 0, 0, &[]);
        // With no records there is no data set at all — a set header describing
        // zero records is a thing some collectors reject.
        assert_eq!(msg.len(), HEADER_LEN + 4 + 4 + FIELDS.len() * 4);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]) as usize, msg.len());
    }
}
