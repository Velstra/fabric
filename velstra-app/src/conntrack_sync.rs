//! C9 — **stateful-HA conntrack sync** (a pfsync-analog for the eBPF `CONNTRACK`
//! map).
//!
//! VRRP moves the virtual IP to the backup on a failover, but the backup's data
//! plane has never seen the established flows, so every NAT'd connection breaks:
//! the reply arrives, misses conntrack, and is dropped or mis-NAT'd. This module
//! is the fix. When `[conntrack_sync]` is configured, a long-lived task
//! [`run`] binds a UDP socket and, each interval, **pushes** every live
//! `CONNTRACK` entry to the configured peer(s); symmetrically it **applies**
//! entries received from a peer into its own `CONNTRACK` map. So the backup
//! already holds the master's flow table when the VIP lands on it, and
//! established connections survive the failover.
//!
//! ## Wire format
//!
//! A datagram is a small fixed header followed by up to [`MAX_RECORDS`] flow
//! records; a full push is split across as many datagrams as needed. Each record
//! is a `CONNTRACK` key/value pair encoded field-by-field in little-endian, so the
//! frame is explicit and endian-defined (not a raw struct memcpy):
//!
//! ```text
//! header : "VCS1" (4) | count u16-le (2) | reserved u16 (2)   = 8 bytes
//! record : FlowKey (20) | FlowState (16)                      = 36 bytes
//! ```
//!
//! ## Trust model
//!
//! Like pfsync, the sync stream is **unauthenticated** and must run over a
//! trusted link — a dedicated sync interface or a protected segment between the
//! two appliances. A peer that can reach the `listen` socket can inject conntrack
//! (hence NAT) state, so do not expose it to untrusted networks. (A shared-secret
//! MAC is a later refinement; the appliance config places this on the HA/sync
//! zone.)
//!
//! The codec ([`encode_batch`] / [`decode_datagram`]) is pure and allocation-only
//! so it is unit-tested without a socket or a kernel map.

use std::net::SocketAddr;

use aya::maps::{HashMap, MapData};
use log::{info, warn};
use tokio::net::UdpSocket;
use velstra_common::{FlowKey, FlowState};

/// Datagram magic + version tag (`VCS1` = Velstra Conntrack Sync v1).
const MAGIC: [u8; 4] = *b"VCS1";
/// Wire size of one encoded [`FlowKey`] (field-by-field, little-endian).
const KEY_LEN: usize = 20;
/// Wire size of one encoded [`FlowState`].
const VAL_LEN: usize = 16;
/// Wire size of one flow record (key + value).
const RECORD_LEN: usize = KEY_LEN + VAL_LEN;
/// Header size: magic (4) + count (2) + reserved (2).
const HEADER_LEN: usize = 8;
/// Records per datagram, chosen so a full datagram
/// (`HEADER_LEN + MAX_RECORDS * RECORD_LEN` = 1160 bytes) stays well under a
/// 1500-byte MTU without relying on IP fragmentation.
const MAX_RECORDS: usize = 32;
/// Receive buffer: one maximum-size datagram.
const RECV_BUF: usize = HEADER_LEN + MAX_RECORDS * RECORD_LEN;

/// Encode one `CONNTRACK` key into 20 little-endian bytes.
fn encode_key(k: &FlowKey, out: &mut Vec<u8>) {
    out.extend_from_slice(&k.policy.to_le_bytes());
    out.extend_from_slice(&k.src_ip);
    out.extend_from_slice(&k.dst_ip);
    out.extend_from_slice(&k.src_port.to_le_bytes());
    out.extend_from_slice(&k.dst_port.to_le_bytes());
    out.push(k.proto);
    out.extend_from_slice(&[0u8; 3]); // pad
}

/// Encode one `CONNTRACK` value into 16 little-endian bytes.
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
    }
}

/// Split `entries` into one or more datagrams of at most [`MAX_RECORDS`] records.
/// An empty input yields no datagrams (nothing to send).
pub fn encode_batch(entries: &[(FlowKey, FlowState)]) -> Vec<Vec<u8>> {
    entries
        .chunks(MAX_RECORDS)
        .map(|chunk| {
            let mut buf = Vec::with_capacity(HEADER_LEN + chunk.len() * RECORD_LEN);
            buf.extend_from_slice(&MAGIC);
            buf.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            buf.extend_from_slice(&[0u8; 2]); // reserved
            for (k, v) in chunk {
                encode_key(k, &mut buf);
                encode_val(v, &mut buf);
            }
            buf
        })
        .collect()
}

/// Parse a received datagram back into flow records, or `None` if the frame is
/// malformed (bad magic, truncated header, or a length that does not match the
/// declared count). Untrusted input never panics or over-reads — a bad datagram
/// is simply dropped.
pub fn decode_datagram(buf: &[u8]) -> Option<Vec<(FlowKey, FlowState)>> {
    if buf.len() < HEADER_LEN || buf[0..4] != MAGIC {
        return None;
    }
    let count = u16::from_le_bytes([buf[4], buf[5]]) as usize;
    if count > MAX_RECORDS || buf.len() != HEADER_LEN + count * RECORD_LEN {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = HEADER_LEN + i * RECORD_LEN;
        let key = decode_key(&buf[off..off + KEY_LEN]);
        let val = decode_val(&buf[off + KEY_LEN..off + RECORD_LEN]);
        out.push((key, val));
    }
    Some(out)
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

/// Long-lived task: own the `CONNTRACK` handle and a bound UDP socket, and every
/// `interval` **push** the full flow table to each peer while continuously
/// **applying** any datagrams peers push to us.
///
/// Best-effort throughout: a send error to one peer is logged and the others
/// still get the push; a malformed inbound datagram is dropped; a per-entry map
/// insert error is logged and the rest of the batch still applies. Nothing in the
/// loop can panic the agent.
pub async fn run(
    mut map: HashMap<MapData, FlowKey, FlowState>,
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
            // Push our live conntrack table to every peer.
            _ = ticker.tick() => {
                if peers.is_empty() {
                    continue;
                }
                let entries = read_conntrack(&map);
                if entries.is_empty() {
                    continue;
                }
                let datagrams = encode_batch(&entries);
                for peer in &peers {
                    for dg in &datagrams {
                        if let Err(e) = socket.send_to(dg, peer).await {
                            warn!("conntrack-sync: push to {peer} failed: {e}");
                            break; // this peer is unreachable; try it again next tick
                        }
                    }
                }
                info!("conntrack-sync: pushed {} entries to {} peer(s)", entries.len(), peers.len());
            }

            // Apply a peer's pushed state into our own conntrack table.
            res = socket.recv_from(&mut rx) => {
                let (n, from) = match res {
                    Ok(v) => v,
                    Err(e) => { warn!("conntrack-sync: recv failed: {e}"); continue; }
                };
                let Some(records) = decode_datagram(&rx[..n]) else {
                    warn!("conntrack-sync: dropped malformed datagram from {from}");
                    continue;
                };
                let mut applied = 0usize;
                for (k, v) in &records {
                    match map.insert(k, v, 0) {
                        Ok(()) => applied += 1,
                        Err(e) => warn!("conntrack-sync: apply entry from {from} failed: {e}"),
                    }
                }
                if applied > 0 {
                    info!("conntrack-sync: applied {applied} entries from {from}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry(seed: u8) -> (FlowKey, FlowState) {
        let key = FlowKey::new(
            7,
            [10, 0, 0, seed],
            [198, 51, 100, 1],
            40000 + seed as u16,
            443,
            6, // TCP
        );
        let val = FlowState::reverse([10, 1, 0, seed], 8443);
        (key, val)
    }

    #[test]
    fn empty_batch_yields_no_datagrams() {
        assert!(encode_batch(&[]).is_empty());
    }

    #[test]
    fn single_entry_round_trips() {
        let entries = vec![sample_entry(2)];
        let dgs = encode_batch(&entries);
        assert_eq!(dgs.len(), 1);
        assert_eq!(dgs[0].len(), HEADER_LEN + RECORD_LEN);
        let back = decode_datagram(&dgs[0]).expect("decodes");
        assert_eq!(back, entries);
    }

    #[test]
    fn full_table_splits_across_datagrams() {
        // 70 entries → 3 datagrams (32 + 32 + 6), all decoding back exactly.
        let entries: Vec<_> = (0..70).map(|i| sample_entry(i as u8)).collect();
        let dgs = encode_batch(&entries);
        assert_eq!(dgs.len(), 3);
        let mut back = Vec::new();
        for dg in &dgs {
            back.extend(decode_datagram(dg).expect("decodes"));
        }
        assert_eq!(back, entries);
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut dg = encode_batch(&[sample_entry(1)])[0].clone();
        dg[0] = b'X';
        assert!(decode_datagram(&dg).is_none());
    }

    #[test]
    fn decode_rejects_truncated_and_overlong() {
        let dg = encode_batch(&[sample_entry(1)])[0].clone();
        // A datagram whose declared count does not match its byte length is rejected.
        assert!(decode_datagram(&dg[..dg.len() - 1]).is_none());
        let mut longer = dg.clone();
        longer.push(0);
        assert!(decode_datagram(&longer).is_none());
    }

    #[test]
    fn decode_rejects_count_over_max() {
        let mut dg = encode_batch(&[sample_entry(1)])[0].clone();
        // Forge count = MAX_RECORDS + 1 without the matching payload.
        dg[4..6].copy_from_slice(&((MAX_RECORDS as u16) + 1).to_le_bytes());
        assert!(decode_datagram(&dg).is_none());
    }

    #[test]
    fn empty_datagram_header_decodes_to_no_records() {
        // A well-formed header with count 0 is valid and yields nothing (though the
        // push path never emits one — empty tables are skipped before encoding).
        let mut dg = Vec::new();
        dg.extend_from_slice(&MAGIC);
        dg.extend_from_slice(&0u16.to_le_bytes());
        dg.extend_from_slice(&[0u8; 2]);
        assert_eq!(decode_datagram(&dg), Some(vec![]));
    }
}
