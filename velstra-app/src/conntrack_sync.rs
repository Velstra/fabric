//! C9 — **stateful-HA conntrack sync** (a pfsync-analog for the eBPF `CONNTRACK`
//! **and** `FW_FLOWS` maps).
//!
//! VRRP moves the virtual IP to the backup on a failover, but the backup's data
//! plane has never seen the established flows, so every connection breaks. Two
//! kernel tables carry that per-flow state and both must cross over:
//!
//! * `CONNTRACK` — the NAT flow table (`FlowKey → FlowState`): without it a
//!   reply to a NAT'd connection misses conntrack and is dropped or mis-NAT'd.
//! * `FW_FLOWS` — the **stateful-firewall** table (`FlowKey → present`): the
//!   record that lets a reply back through a deny-by-default zone
//!   (`main.rs`'s `established = FW_FLOWS.get(&fkey).is_some()`). Without it,
//!   after a failover the reply of an established *stateful-firewall* flow
//!   (even one that is not NAT'd) hits the default-drop and is discarded.
//!
//! When `[conntrack_sync]` is configured, a long-lived task [`run`] binds a UDP
//! socket and, each interval, **pushes** every live entry of *both* maps to the
//! configured peer(s); symmetrically it **applies** entries received from a peer
//! into its own maps. So the backup already holds the master's flow *and*
//! firewall tables when the VIP lands on it, and established connections — NAT'd
//! or merely stateful-firewalled — survive the failover.
//!
//! ## Wire format
//!
//! A datagram is a small fixed header followed by up to [`MAX_RECORDS`] records;
//! a full push is split across as many datagrams as needed. The header's `kind`
//! field selects the record layout, so each datagram is self-describing. Every
//! field is little-endian, so the frame is explicit and endian-defined (not a
//! raw struct memcpy):
//!
//! ```text
//! header : "VCS1" (4) | count u16-le (2) | kind u16-le (2)      = 8 bytes
//! kind 0 (CONNTRACK) record : FlowKey (20) | NAT state (16)     = 36 bytes
//! kind 1 (FW_FLOWS)  record : FlowKey (20)                      = 20 bytes
//! ```
//!
//! "NAT state" rather than "`FlowState`": the value also carries this node's
//! traffic counters, which deliberately stay at home — see [`encode_val`].
//!
//! `kind == 0` is the original v1 CONNTRACK layout — the field was a reserved
//! zero before, so CONNTRACK datagrams are byte-identical to the pre-`FW_FLOWS`
//! format and interoperate with an un-upgraded peer. `FW_FLOWS` records carry no
//! value (the map value is a mere presence flag), so they are key-only.
//!
//! ## Trust model
//!
//! Like pfsync, the sync stream is **unauthenticated** and must run over a
//! trusted link — a dedicated sync interface or a protected segment between the
//! two appliances. A peer that can reach the `listen` socket can inject conntrack
//! (hence NAT) and firewall state, so do not expose it to untrusted networks. (A
//! shared-secret MAC is a later refinement; the appliance config places this on
//! the HA/sync zone.)
//!
//! The codec ([`encode_conntrack_batch`] / [`encode_fwflows_batch`] /
//! [`decode_datagram`]) is pure and allocation-only so it is unit-tested without
//! a socket or a kernel map.

use std::{net::SocketAddr, sync::Arc};

use aya::maps::{HashMap, MapData};
use log::{info, warn};
use tokio::{net::UdpSocket, sync::Mutex};
use velstra_common::{FlowKey, FlowState};

/// Datagram magic + version tag (`VCS1` = Velstra Conntrack Sync v1).
const MAGIC: [u8; 4] = *b"VCS1";
/// Header `kind` for a CONNTRACK batch (key + value). Value 0 keeps the frame
/// byte-identical to the original v1 format (the field was a reserved zero).
const KIND_CONNTRACK: u16 = 0;
/// Header `kind` for a FW_FLOWS batch (key only — the map value is a presence
/// flag, so nothing but the flow key needs to cross).
const KIND_FW_FLOWS: u16 = 1;
/// Wire size of one encoded [`FlowKey`] (field-by-field, little-endian).
const KEY_LEN: usize = 20;
/// Wire size of one encoded [`FlowState`].
const VAL_LEN: usize = 16;
/// Wire size of one CONNTRACK record (key + value).
const RECORD_LEN: usize = KEY_LEN + VAL_LEN;
/// Header size: magic (4) + count (2) + kind (2).
const HEADER_LEN: usize = 8;
/// Records per datagram, chosen so a full CONNTRACK datagram
/// (`HEADER_LEN + MAX_RECORDS * RECORD_LEN` = 1160 bytes) stays well under a
/// 1500-byte MTU without relying on IP fragmentation. A FW_FLOWS datagram uses
/// the same cap and is smaller (20-byte records), so it also fits.
const MAX_RECORDS: usize = 32;
/// Receive buffer: one maximum-size (CONNTRACK) datagram.
const RECV_BUF: usize = HEADER_LEN + MAX_RECORDS * RECORD_LEN;

/// A decoded datagram: one map's worth of records, tagged by which map it came
/// from so the receiver applies it to the right kernel table.
#[derive(Debug, PartialEq)]
pub enum Datagram {
    /// CONNTRACK entries (NAT flow key + state).
    Conntrack(Vec<(FlowKey, FlowState)>),
    /// FW_FLOWS entries (stateful-firewall flow keys; the value is presence).
    FwFlows(Vec<FlowKey>),
}

/// Encode one flow key into 20 little-endian bytes.
fn encode_key(k: &FlowKey, out: &mut Vec<u8>) {
    out.extend_from_slice(&k.policy.to_le_bytes());
    out.extend_from_slice(&k.src_ip);
    out.extend_from_slice(&k.dst_ip);
    out.extend_from_slice(&k.src_port.to_le_bytes());
    out.extend_from_slice(&k.dst_port.to_le_bytes());
    out.push(k.proto);
    out.extend_from_slice(&[0u8; 3]); // pad
}

/// Encode a [`FlowState`] into 16 little-endian bytes — the NAT fields only.
///
/// The value's traffic counters are **not** sent, and the record stays at its
/// original 16 bytes, so an appliance running this still interoperates with one
/// that predates the counters. That is a consequence rather than the reason: a
/// byte was carried by one node or the other, so replicating the number would
/// make any sum over an HA pair count it twice, and a backup that has forwarded
/// nothing has honestly forwarded nothing. What must survive a failover is the
/// NAT state — that is what keeps connections alive — and it does.
fn encode_val(v: &FlowState, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.nat_ip);
    out.extend_from_slice(&v.nat2_ip);
    out.extend_from_slice(&v.nat_port.to_le_bytes());
    out.extend_from_slice(&v.nat2_port.to_le_bytes());
    out.extend_from_slice(&v.flags.to_le_bytes());
    out.extend_from_slice(&[0u8; 2]); // pad
}

/// Decode a 20-byte key. Caller guarantees `b.len() == KEY_LEN`.
fn decode_key(b: &[u8]) -> FlowKey {
    FlowKey::new(
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        [b[4], b[5], b[6], b[7]],
        [b[8], b[9], b[10], b[11]],
        u16::from_le_bytes([b[12], b[13]]),
        u16::from_le_bytes([b[14], b[15]]),
        b[16],
    )
}

/// Decode a 16-byte value. Caller guarantees `b.len() == VAL_LEN`.
fn decode_val(b: &[u8]) -> FlowState {
    FlowState {
        nat_ip: [b[0], b[1], b[2], b[3]],
        nat2_ip: [b[4], b[5], b[6], b[7]],
        nat_port: u16::from_le_bytes([b[8], b[9]]),
        nat2_port: u16::from_le_bytes([b[10], b[11]]),
        flags: u16::from_le_bytes([b[12], b[13]]),
        _pad: 0,
        // Counters deliberately do not cross the wire; see `encode_val`.
        packets: 0,
        bytes: 0,
    }
}

/// Write the 8-byte header (magic + count + kind) into `buf`.
fn push_header(buf: &mut Vec<u8>, count: usize, kind: u16) {
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&(count as u16).to_le_bytes());
    buf.extend_from_slice(&kind.to_le_bytes());
}

/// Split CONNTRACK `entries` into one or more datagrams of at most
/// [`MAX_RECORDS`] records. An empty input yields no datagrams (nothing to send).
pub fn encode_conntrack_batch(entries: &[(FlowKey, FlowState)]) -> Vec<Vec<u8>> {
    entries
        .chunks(MAX_RECORDS)
        .map(|chunk| {
            let mut buf = Vec::with_capacity(HEADER_LEN + chunk.len() * RECORD_LEN);
            push_header(&mut buf, chunk.len(), KIND_CONNTRACK);
            for (k, v) in chunk {
                encode_key(k, &mut buf);
                encode_val(v, &mut buf);
            }
            buf
        })
        .collect()
}

/// Split FW_FLOWS `keys` into one or more key-only datagrams of at most
/// [`MAX_RECORDS`] records. An empty input yields no datagrams.
pub fn encode_fwflows_batch(keys: &[FlowKey]) -> Vec<Vec<u8>> {
    keys.chunks(MAX_RECORDS)
        .map(|chunk| {
            let mut buf = Vec::with_capacity(HEADER_LEN + chunk.len() * KEY_LEN);
            push_header(&mut buf, chunk.len(), KIND_FW_FLOWS);
            for k in chunk {
                encode_key(k, &mut buf);
            }
            buf
        })
        .collect()
}

/// Parse a received datagram into its records, or `None` if the frame is
/// malformed (bad magic, unknown kind, truncated header, or a length that does
/// not match the declared count for its kind). Untrusted input never panics or
/// over-reads — a bad datagram is simply dropped.
pub fn decode_datagram(buf: &[u8]) -> Option<Datagram> {
    if buf.len() < HEADER_LEN || buf[0..4] != MAGIC {
        return None;
    }
    let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    let kind = u16::from_le_bytes([buf[6], buf[7]]);
    if count > MAX_RECORDS {
        return None;
    }
    match kind {
        KIND_CONNTRACK => {
            if buf.len() != HEADER_LEN + count * RECORD_LEN {
                return None;
            }
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let off = HEADER_LEN + i * RECORD_LEN;
                let key = decode_key(&buf[off..off + KEY_LEN]);
                let val = decode_val(&buf[off + KEY_LEN..off + RECORD_LEN]);
                out.push((key, val));
            }
            Some(Datagram::Conntrack(out))
        }
        KIND_FW_FLOWS => {
            if buf.len() != HEADER_LEN + count * KEY_LEN {
                return None;
            }
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let off = HEADER_LEN + i * KEY_LEN;
                out.push(decode_key(&buf[off..off + KEY_LEN]));
            }
            Some(Datagram::FwFlows(out))
        }
        _ => None,
    }
}

/// Read every entry of the `CONNTRACK` LRU map into an owned vector. An empty map
/// yields an empty vector; a per-entry read error is skipped rather than aborting
/// the scan. Returning owned data ends the map borrow before the caller sends or
/// (in the same task) inserts.
fn read_conntrack(map: &HashMap<MapData, FlowKey, FlowState>) -> Vec<(FlowKey, FlowState)> {
    let mut out = Vec::new();
    for key in map.keys().flatten() {
        if let Ok(val) = map.get(&key, 0) {
            out.push((key, val));
        }
    }
    out
}

/// Read every key of the `FW_FLOWS` LRU map into an owned vector. Only the key
/// matters (the value is a presence flag), so no per-entry `get` is needed; a key
/// that was evicted concurrently is harmless (a stale re-insert on the peer).
fn read_fw_flows(map: &HashMap<MapData, FlowKey, u8>) -> Vec<FlowKey> {
    map.keys().flatten().collect()
}

/// Long-lived task: own the `CONNTRACK` and `FW_FLOWS` handles and a bound UDP
/// socket, and every `interval` **push** both full tables to each peer while
/// continuously **applying** any datagrams peers push to us.
///
/// Best-effort throughout: a send error to one peer is logged and the others
/// still get the push; a malformed inbound datagram is dropped; a per-entry map
/// insert error is logged and the rest of the batch still applies. Nothing in the
/// loop can panic the agent.
pub async fn run(
    conntrack: Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>,
    mut fw_flows: HashMap<MapData, FlowKey, u8>,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    interval_secs: u64,
) {
    let socket = match UdpSocket::bind(listen).await {
        Ok(s) => s,
        Err(e) => {
            warn!("conntrack-sync: bind {listen} failed, sync disabled: {e}");
            return;
        }
    };
    info!(
        "conntrack-sync: listening on {listen}, pushing to {} peer(s) every {interval_secs}s",
        peers.len()
    );

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    let mut rx = vec![0u8; RECV_BUF];

    loop {
        tokio::select! {
            // Push our live conntrack + firewall tables to every peer.
            _ = ticker.tick() => {
                if peers.is_empty() {
                    continue;
                }
                let ct = read_conntrack(&*conntrack.lock().await);
                let fw = read_fw_flows(&fw_flows);
                if ct.is_empty() && fw.is_empty() {
                    continue;
                }
                let mut datagrams = encode_conntrack_batch(&ct);
                datagrams.extend(encode_fwflows_batch(&fw));
                for peer in &peers {
                    for dg in &datagrams {
                        if let Err(e) = socket.send_to(dg, peer).await {
                            warn!("conntrack-sync: push to {peer} failed: {e}");
                            break; // this peer is unreachable; try it again next tick
                        }
                    }
                }
                info!(
                    "conntrack-sync: pushed {} conntrack + {} fw-flow entries to {} peer(s)",
                    ct.len(), fw.len(), peers.len()
                );
            }

            // Apply a peer's pushed state into our own tables.
            res = socket.recv_from(&mut rx) => {
                let (n, from) = match res {
                    Ok(v) => v,
                    Err(e) => { warn!("conntrack-sync: recv failed: {e}"); continue; }
                };
                match decode_datagram(&rx[..n]) {
                    Some(Datagram::Conntrack(records)) => {
                        let mut applied = 0usize;
                        for (k, v) in &records {
                            let mut map = conntrack.lock().await;
                            // A peer's record carries no counters (see `encode_val`), so
                            // applying it verbatim would zero this node's own accounting
                            // for a flow it is actively forwarding. In an N-way mesh every
                            // node pushes, so that would happen every interval — the
                            // counters would never get past one tick's worth of traffic.
                            let mut v = *v;
                            if let Ok(local) = map.get(k, 0) {
                                v.packets = local.packets;
                                v.bytes = local.bytes;
                            }
                            match map.insert(k, v, 0) {
                                Ok(()) => applied += 1,
                                Err(e) => warn!("conntrack-sync: apply conntrack entry from {from} failed: {e}"),
                            }
                        }
                        if applied > 0 {
                            info!("conntrack-sync: applied {applied} conntrack entries from {from}");
                        }
                    }
                    Some(Datagram::FwFlows(keys)) => {
                        let mut applied = 0usize;
                        for k in &keys {
                            match fw_flows.insert(k, 1u8, 0) {
                                Ok(()) => applied += 1,
                                Err(e) => warn!("conntrack-sync: apply fw-flow entry from {from} failed: {e}"),
                            }
                        }
                        if applied > 0 {
                            info!("conntrack-sync: applied {applied} fw-flow entries from {from}");
                        }
                    }
                    None => warn!("conntrack-sync: dropped malformed datagram from {from}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(seed: u8) -> (FlowKey, FlowState) {
        let key = sample_key(seed);
        let val = FlowState::reverse([10, 1, 0, seed], 8443);
        (key, val)
    }

    fn sample_key(seed: u8) -> FlowKey {
        FlowKey::new(
            7,
            [10, 0, 0, seed],
            [198, 51, 100, 1],
            40000 + seed as u16,
            443,
            6, // TCP
        )
    }

    #[test]
    fn empty_batch_yields_no_datagrams() {
        assert!(encode_conntrack_batch(&[]).is_empty());
        assert!(encode_fwflows_batch(&[]).is_empty());
    }

    #[test]
    fn single_conntrack_entry_round_trips() {
        let entries = vec![sample_entry(2)];
        let dgs = encode_conntrack_batch(&entries);
        assert_eq!(dgs.len(), 1);
        assert_eq!(dgs[0].len(), HEADER_LEN + RECORD_LEN);
        assert_eq!(decode_datagram(&dgs[0]), Some(Datagram::Conntrack(entries)));
    }

    /// Counters are per node, so they must not cross: a byte was carried here or
    /// on the peer, and a record that replicated the number would make any sum
    /// over an HA pair count it twice. Keeping the record at 16 bytes also keeps
    /// an un-upgraded peer interoperable, which is a welcome consequence.
    #[test]
    fn a_record_carries_the_nat_state_but_not_the_accounting() {
        let (key, mut state) = sample_entry(3);
        state.packets = 4242;
        state.bytes = 9_000_000;

        let dgs = encode_conntrack_batch(&[(key, state)]);
        assert_eq!(dgs[0].len(), HEADER_LEN + RECORD_LEN, "the record grew");

        let Some(Datagram::Conntrack(decoded)) = decode_datagram(&dgs[0]) else {
            panic!("did not decode as a conntrack batch");
        };
        assert_eq!(
            decoded[0].1.nat_ip, state.nat_ip,
            "the NAT state must cross"
        );
        assert_eq!(decoded[0].1.nat_port, state.nat_port);
        assert_eq!(decoded[0].1.packets, 0, "the counters must not cross");
        assert_eq!(decoded[0].1.bytes, 0);
    }

    #[test]
    fn conntrack_frame_kind_is_zero_and_wire_compatible() {
        // The kind field (bytes 6..8) is 0 for a CONNTRACK datagram, so the frame
        // is byte-identical to the pre-FW_FLOWS v1 format.
        let dg = encode_conntrack_batch(&[sample_entry(1)])[0].clone();
        assert_eq!(&dg[6..8], &[0, 0]);
    }

    #[test]
    fn conntrack_full_table_splits_across_datagrams() {
        // 70 entries → 3 datagrams (32 + 32 + 6), all decoding back exactly.
        let entries: Vec<_> = (0..70).map(|i| sample_entry(i as u8)).collect();
        let dgs = encode_conntrack_batch(&entries);
        assert_eq!(dgs.len(), 3);
        let mut back = Vec::new();
        for dg in &dgs {
            match decode_datagram(dg).expect("decodes") {
                Datagram::Conntrack(recs) => back.extend(recs),
                other => panic!("expected conntrack, got {other:?}"),
            }
        }
        assert_eq!(back, entries);
    }

    #[test]
    fn single_fwflow_key_round_trips() {
        let keys = vec![sample_key(3)];
        let dgs = encode_fwflows_batch(&keys);
        assert_eq!(dgs.len(), 1);
        // Key-only records: 20 bytes each, no 16-byte value.
        assert_eq!(dgs[0].len(), HEADER_LEN + KEY_LEN);
        assert_eq!(&dgs[0][6..8], &[1, 0]); // kind == 1
        assert_eq!(decode_datagram(&dgs[0]), Some(Datagram::FwFlows(keys)));
    }

    #[test]
    fn fwflows_full_table_splits_across_datagrams() {
        let keys: Vec<_> = (0..70).map(|i| sample_key(i as u8)).collect();
        let dgs = encode_fwflows_batch(&keys);
        assert_eq!(dgs.len(), 3);
        let mut back = Vec::new();
        for dg in &dgs {
            match decode_datagram(dg).expect("decodes") {
                Datagram::FwFlows(ks) => back.extend(ks),
                other => panic!("expected fw-flows, got {other:?}"),
            }
        }
        assert_eq!(back, keys);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut dg = encode_conntrack_batch(&[sample_entry(1)])[0].clone();
        dg[0] = b'X';
        assert!(decode_datagram(&dg).is_none());
    }

    #[test]
    fn decode_rejects_unknown_kind() {
        let mut dg = encode_conntrack_batch(&[sample_entry(1)])[0].clone();
        dg[6..8].copy_from_slice(&99u16.to_le_bytes());
        assert!(decode_datagram(&dg).is_none());
    }

    #[test]
    fn decode_rejects_truncated_and_overlong() {
        for dg in [
            encode_conntrack_batch(&[sample_entry(1)])[0].clone(),
            encode_fwflows_batch(&[sample_key(1)])[0].clone(),
        ] {
            // A datagram whose declared count does not match its byte length
            // (for its kind) is rejected, in either direction.
            assert!(decode_datagram(&dg[..dg.len() - 1]).is_none());
            let mut longer = dg.clone();
            longer.push(0);
            assert!(decode_datagram(&longer).is_none());
        }
    }

    #[test]
    fn decode_rejects_count_over_max() {
        let mut dg = encode_conntrack_batch(&[sample_entry(1)])[0].clone();
        // Forge count = MAX_RECORDS + 1 without the matching payload.
        dg[4..6].copy_from_slice(&((MAX_RECORDS as u16) + 1).to_le_bytes());
        assert!(decode_datagram(&dg).is_none());
    }

    #[test]
    fn empty_datagram_header_decodes_to_no_records() {
        // A well-formed header with count 0 is valid and yields nothing (though the
        // push path never emits one — empty tables are skipped before encoding).
        let mut ct = Vec::new();
        push_header(&mut ct, 0, KIND_CONNTRACK);
        assert_eq!(decode_datagram(&ct), Some(Datagram::Conntrack(vec![])));
        let mut fw = Vec::new();
        push_header(&mut fw, 0, KIND_FW_FLOWS);
        assert_eq!(decode_datagram(&fw), Some(Datagram::FwFlows(vec![])));
    }
}
