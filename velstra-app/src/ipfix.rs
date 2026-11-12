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
//! Only what the data plane actually knows: policy identity, the five-tuple and
//! the two counters. Each configured policy is a logical Observation Point;
//! IANA observationPointId (138, unsigned64) carries its exact numeric policy ID.
//! There are no timestamps, because the map holds none — inventing "first seen"
//! from when the exporter noticed a flow would put a plausible, wrong number in
//! a record an operator later reasons about. Only NAT'd connections appear at
//! all, for the reason `flows.rs` gives.
//!
//! The encoder is pure and unit-tested; only [`run`] needs a socket.

use std::{
    collections::{HashMap, VecDeque},
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
const TEMPLATE_ID: u16 = 257;
/// Message header: version, length, export time, sequence, domain.
const HEADER_LEN: usize = 16;
/// One data record: policy observation point, five-tuple and two counters.
const RECORD_LEN: usize = 8 + 4 + 4 + 2 + 2 + 1 + 8 + 8;

/// The information elements a record carries, as `(id, length)` — IANA IPFIX
/// element IDs, so a collector needs nothing from us to read them.
const FIELDS: [(u16, u16); 8] = [
    (138, 8), // observationPointId: configured firewall policy ID
    (8, 4),   // sourceIPv4Address
    (12, 4),  // destinationIPv4Address
    (7, 2),   // sourceTransportPort
    (11, 2),  // destinationTransportPort
    (4, 1),   // protocolIdentifier
    (1, 8),   // octetDeltaCount
    (2, 8),   // packetDeltaCount
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
            buf.extend_from_slice(&u64::from(r.key.policy).to_be_bytes());
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
    let socket = match collector_socket(collector).await {
        Ok(s) => s,
        Err(e) => {
            warn!("ipfix: cannot open a socket: {e}");
            return;
        }
    };
    info!("ipfix: exporting to {collector} every {interval_secs}s (domain {domain})");

    let mut seen: HashMap<FlowKey, Sent> = HashMap::new();
    let mut sequence: u32 = 0;
    // At most one map snapshot is pending. Keep locally unsent records even if
    // their flow disappears before recovery; never replace them with idle deltas.
    let mut pending = VecDeque::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    loop {
        ticker.tick().await;

        if pending.is_empty() {
            let flows: Vec<(FlowKey, FlowState)> = {
                let map = conntrack.lock().await;
                map.iter().filter_map(|e| e.ok()).collect()
            };
            pending = deltas(&flows, &mut seen).into();
        }
        if pending.is_empty() {
            continue;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        if let Err(e) = flush_pending(&mut pending, &mut sequence, domain, now, |message| {
            let socket = &socket;
            async move { socket.send(&message).await }
        })
        .await
        {
            warn!(
                "ipfix: send to {collector} failed: {e}; {} unsent records retained",
                pending.len()
            );
        }
    }
}

async fn collector_socket(collector: SocketAddr) -> std::io::Result<UdpSocket> {
    let bind = if collector.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(collector).await?;
    Ok(socket)
}

/// A successful local datagram submission commits only that chunk. UDP delivery
/// beyond the local host remains unacknowledged, as required by the transport.
async fn flush_pending<F, Fut>(
    pending: &mut VecDeque<FlowDelta>,
    sequence: &mut u32,
    domain: u32,
    now: u32,
    mut send: F,
) -> std::io::Result<()>
where
    F: FnMut(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<usize>>,
{
    while !pending.is_empty() {
        let chunk: Vec<_> = pending.iter().take(MAX_RECORDS).copied().collect();
        let message = encode_message(domain, now, *sequence, &chunk);
        let expected = message.len();
        if send(message).await? != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "partial IPFIX datagram submission",
            ));
        }
        pending.drain(..chunk.len());
        *sequence = sequence.wrapping_add(chunk.len() as u32);
    }
    Ok(())
}

/// Resolve a `host:port` collector address. Use the resolver's first result,
/// matching its IPv4/IPv6 family at bind time; no silent family downgrade.
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

    /// Decode by the wire template, without the encoder's FIELDS/RECORD_LEN.
    fn decode(message: &[u8]) -> Vec<HashMap<u16, Vec<u8>>> {
        let u16_at = |offset| u16::from_be_bytes([message[offset], message[offset + 1]]) as usize;
        let template_bytes = u16_at(18);
        let fields: Vec<_> = (0..u16_at(22))
            .map(|i| (u16_at(24 + i * 4) as u16, u16_at(26 + i * 4)))
            .collect();
        let record_bytes: usize = fields.iter().map(|(_, len)| len).sum();
        let start = 16 + template_bytes;
        let end = start + u16_at(start + 2);
        message[start + 4..end]
            .chunks_exact(record_bytes)
            .map(|record| {
                let mut offset = 0;
                fields
                    .iter()
                    .map(|(id, len)| {
                        let field = (*id, record[offset..offset + len].to_vec());
                        offset += len;
                        field
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn identical_five_tuples_in_distinct_policies_remain_distinguishable_on_wire() {
        let mut first = key([10, 0, 0, 1], 40000);
        first.policy = 100;
        let mut second = first;
        second.policy = 200;
        let records: Vec<_> = [first, second]
            .into_iter()
            .map(|key| FlowDelta {
                key,
                bytes: 1000,
                packets: 10,
            })
            .collect();
        let wire = encode_message(7, 0, 0, &records);
        let decoded = decode(&wire);
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0][&138], 100u64.to_be_bytes());
        assert_eq!(decoded[1][&138], 200u64.to_be_bytes());
        for field in [8, 12, 7, 11, 4, 1, 2] {
            assert_eq!(decoded[0][&field], decoded[1][&field]);
        }
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_collectors_receive_decodable_datagrams() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let collector = UdpSocket::bind(address).await.unwrap();
            let address = collector.local_addr().unwrap();
            assert_eq!(parse_collector(&address.to_string()).unwrap(), address);
            let socket = collector_socket(address).await.unwrap();
            assert_eq!(socket.local_addr().unwrap().is_ipv6(), address.is_ipv6());
            let message = encode_message(
                7,
                0,
                0,
                &[FlowDelta {
                    key: key([10, 0, 0, 1], 40000),
                    bytes: 42,
                    packets: 1,
                }],
            );
            socket.send(&message).await.unwrap();
            let mut received = [0; 1500];
            let (length, _) =
                tokio::time::timeout(Duration::from_secs(1), collector.recv_from(&mut received))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(&received[..length], &message);
            assert_eq!(decode(&received[..length]).len(), 1);
        }
        use std::net::ToSocketAddrs;
        let expected = "localhost:4739".to_socket_addrs().unwrap().next().unwrap();
        assert_eq!(parse_collector("localhost:4739").unwrap(), expected);
    }

    #[tokio::test]
    async fn unsent_chunks_survive_failure_without_repeating_successful_chunks() {
        let flows: Vec<_> = (0..(MAX_RECORDS * 2 + 1))
            .map(|i| (key([10, 0, 0, 1], 10000 + i as u16), state(10, 1000)))
            .collect();
        let mut seen = HashMap::new();
        let mut pending = VecDeque::from(deltas(&flows, &mut seen));
        let mut sequence = 0;
        let mut messages = Vec::new();
        let failed = flush_pending(&mut pending, &mut sequence, 7, 0, |message| {
            if messages.is_empty() {
                let length = message.len();
                messages.push(message);
                std::future::ready(Ok(length))
            } else {
                std::future::ready(Err(std::io::Error::other("injected local send failure")))
            }
        })
        .await;
        assert!(failed.is_err());
        assert_eq!(sequence, MAX_RECORDS as u32);
        assert_eq!(pending.len(), MAX_RECORDS + 1);
        flush_pending(&mut pending, &mut sequence, 7, 1, |message| {
            let length = message.len();
            messages.push(message);
            std::future::ready(Ok(length))
        })
        .await
        .unwrap();
        assert!(pending.is_empty());
        assert_eq!(sequence as usize, flows.len());
        let ports: Vec<_> = messages
            .iter()
            .flat_map(|m| decode(m))
            .map(|r| r[&7].clone())
            .collect();
        assert_eq!(ports.len(), flows.len());
        assert_eq!(
            ports
                .into_iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            flows.len()
        );
        assert!(
            deltas(&flows, &mut seen).is_empty(),
            "idle counters must not duplicate a recovered batch"
        );
    }

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
