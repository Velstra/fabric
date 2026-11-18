//! Portable TCP state codec primitives, deliberately NOT wired into VCS2.
//!
//! The active receiver cannot promote legacy flags-only TCP into this schema.
//! A future authenticated BEGIN must require [`TcpSchema`] before any records,
//! authority change or readiness publication. Decoding proves structure only:
//! caller still owns authentication, ordering, policy, coherent lock-aware map
//! access, local revision monotonicity and incarnation allocation/tombstones.
//! This module neither accesses maps nor establishes runtime HA compatibility.
//! Snapshot ABI1 has no TCP-MD5/TCP-AO authentication state; this codec does not
//! invent that capability or qualify authenticated TCP flows for retirement.

use std::{collections::BTreeSet, error::Error, fmt};

use velstra_common::{TCP_STATE_ABI, TcpPeer, TcpSession, TcpSessionKey, TcpSnapshot};

const MAGIC: &[u8; 4] = b"VTC1";
const SCHEMA_MAGIC: &[u8; 4] = b"VTSC";
const VERSION: u16 = 1;
const HEADER: usize = 8;
const KEY: usize = 44;
const SNAPSHOT: usize = 120;
const UPSERT: u16 = 1;
const DELETE: u16 = 2;
pub const TCP_UPSERT_BYTES: usize = HEADER + KEY + 4 + SNAPSHOT;
pub const TCP_DELETE_BYTES: usize = HEADER + KEY + 4 + 8 + 8;
/// VCS2 payload bound; its authenticated outer header/tag add another 77 bytes.
pub const TCP_FRAME_BYTES: usize = 32_768;
pub const TCP_FRAME_RECORDS: usize = 256;
pub const TCP_TABLE_RECORDS: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpCodecError {
    Header,
    Version,
    Kind,
    Length,
    Key,
    Initiator,
    Snapshot,
    Identity,
    DuplicateKey,
    FrameLimit,
    RecordLimit,
    EmptyFrame,
}

impl fmt::Display for TcpCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Header => "unknown TCP state magic or legacy state schema",
            Self::Version => "unsupported TCP state schema",
            Self::Kind => "unknown TCP state record kind",
            Self::Length => "invalid TCP state record length",
            Self::Key => "invalid or noncanonical TCP session key",
            Self::Initiator => "invalid TCP initiator side",
            Self::Snapshot => "invalid TCP snapshot",
            Self::Identity => "invalid TCP incarnation or policy admission domain",
            Self::DuplicateKey => "duplicate TCP session key in state batch",
            Self::FrameLimit => "TCP state frame exceeds byte limit",
            Self::RecordLimit => "TCP state batch exceeds record limit",
            Self::EmptyFrame => "empty TCP state record frame",
        })
    }
}

impl Error for TcpCodecError {}

/// Mandatory exact descriptor for a FUTURE authenticated schema negotiation.
/// No optional fields, legacy-empty descriptor or automatic downgrade exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSchema;

impl TcpSchema {
    pub fn encode(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[..4].copy_from_slice(SCHEMA_MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        // bytes6..8 are reserved and must remain zero.
        bytes[8..10].copy_from_slice(&(KEY as u16).to_le_bytes());
        bytes[10..12].copy_from_slice(&(SNAPSHOT as u16).to_le_bytes());
        bytes[12..16].copy_from_slice(&TCP_STATE_ABI.to_le_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TcpCodecError> {
        if bytes.len() != 16 {
            return Err(TcpCodecError::Length);
        }
        if &bytes[..4] != SCHEMA_MAGIC {
            return Err(TcpCodecError::Header);
        }
        if bytes != Self.encode() {
            return Err(TcpCodecError::Version);
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpRecord {
    pub key: TcpSessionKey,
    /// Sorted endpoint holding the admitted SYN initiator, not packet direction.
    pub initiator_side: u32,
    pub snapshot: TcpSnapshot,
}

/// Incarnation-qualified deletion. A tuple-only DELETE must never retire a
/// newer connection reusing the same canonical key. This is an identity guard,
/// NOT permission to delete without authenticated ordering and ownership.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpTombstone {
    pub key: TcpSessionKey,
    pub initiator_side: u32,
    pub incarnation: u64,
    pub policy_epoch: u64,
}

impl TcpRecord {
    pub fn tombstone(self) -> TcpTombstone {
        TcpTombstone {
            key: self.key,
            initiator_side: self.initiator_side,
            incarnation: self.snapshot.incarnation,
            policy_epoch: self.snapshot.policy_epoch,
        }
    }
}

impl TcpTombstone {
    pub fn matches(self, record: &TcpRecord) -> bool {
        validate_prefix(&self.key, self.initiator_side).is_ok()
            && self.incarnation != 0
            && self.policy_epoch != 0
            && record.snapshot.valid()
            && self == record.tombstone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpWireRecord {
    Upsert(TcpRecord),
    Delete(TcpTombstone),
}

impl TcpWireRecord {
    fn prefix(self) -> (TcpSessionKey, u32, u16) {
        match self {
            Self::Upsert(record) => (record.key, record.initiator_side, UPSERT),
            Self::Delete(record) => (record.key, record.initiator_side, DELETE),
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, TcpCodecError> {
        let (key, side, kind) = self.prefix();
        validate_prefix(&key, side)?;
        match self {
            Self::Upsert(record)
                if !record.snapshot.valid() || record.snapshot.phase == TcpSession::GC_PENDING =>
            {
                return Err(TcpCodecError::Snapshot);
            }
            Self::Delete(record) if record.incarnation == 0 || record.policy_epoch == 0 => {
                return Err(TcpCodecError::Identity);
            }
            _ => {}
        }
        let mut bytes = Vec::with_capacity(TCP_UPSERT_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        encode_key(&key, &mut bytes);
        put32(&mut bytes, side);
        match self {
            Self::Upsert(record) => encode_snapshot(&record.snapshot, &mut bytes),
            Self::Delete(record) => {
                put64(&mut bytes, record.incarnation);
                put64(&mut bytes, record.policy_epoch);
            }
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TcpCodecError> {
        if bytes.len() < HEADER {
            return Err(TcpCodecError::Length);
        }
        if &bytes[..4] != MAGIC {
            return Err(TcpCodecError::Header);
        }
        if u16::from_le_bytes(bytes[4..6].try_into().unwrap()) != VERSION {
            return Err(TcpCodecError::Version);
        }
        let kind = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let expected = match kind {
            UPSERT => TCP_UPSERT_BYTES,
            DELETE => TCP_DELETE_BYTES,
            _ => return Err(TcpCodecError::Kind),
        };
        if bytes.len() != expected {
            return Err(TcpCodecError::Length);
        }
        let mut cursor = Cursor(&bytes[HEADER..]);
        let key = decode_key(&mut cursor);
        let side = cursor.u32();
        validate_prefix(&key, side)?;
        let record = match kind {
            UPSERT => {
                let snapshot = decode_snapshot(&mut cursor);
                if !snapshot.valid() || snapshot.phase == TcpSession::GC_PENDING {
                    return Err(TcpCodecError::Snapshot);
                }
                Self::Upsert(TcpRecord {
                    key,
                    initiator_side: side,
                    snapshot,
                })
            }
            DELETE => {
                let incarnation = cursor.u64();
                let policy_epoch = cursor.u64();
                if incarnation == 0 || policy_epoch == 0 {
                    return Err(TcpCodecError::Identity);
                }
                Self::Delete(TcpTombstone {
                    key,
                    initiator_side: side,
                    incarnation,
                    policy_epoch,
                })
            }
            _ => unreachable!(),
        };
        debug_assert!(cursor.0.is_empty());
        Ok(record)
    }
}

fn validate_prefix(key: &TcpSessionKey, side: u32) -> Result<(), TcpCodecError> {
    if !key.valid() {
        return Err(TcpCodecError::Key);
    }
    if side > 1 {
        return Err(TcpCodecError::Initiator);
    }
    Ok(())
}

fn encode_key(key: &TcpSessionKey, bytes: &mut Vec<u8>) {
    put32(bytes, key.policy);
    put32(bytes, key.family);
    bytes.extend_from_slice(&key.addr0);
    bytes.extend_from_slice(&key.addr1);
    bytes.extend_from_slice(&key.port0.to_le_bytes());
    bytes.extend_from_slice(&key.port1.to_le_bytes());
}

fn decode_key(cursor: &mut Cursor<'_>) -> TcpSessionKey {
    TcpSessionKey {
        policy: cursor.u32(),
        family: cursor.u32(),
        addr0: cursor.take(),
        addr1: cursor.take(),
        port0: cursor.u16(),
        port1: cursor.u16(),
    }
}

fn encode_snapshot(state: &TcpSnapshot, bytes: &mut Vec<u8>) {
    for value in [state.incarnation, state.policy_epoch, state.age_ns] {
        put64(bytes, value);
    }
    for value in [state.abi, state.phase, state.terminal_flags, state.reserved] {
        put32(bytes, value);
    }
    for peer in &state.peers {
        for value in [
            peer.syn_seq,
            peer.end,
            peer.max_ack,
            peer.window_raw,
            peer.window_seq,
            peer.window_ack,
            peer.max_window,
            peer.fin_seq,
            peer.flags,
            peer.scale,
        ] {
            put32(bytes, value);
        }
    }
}

fn decode_snapshot(cursor: &mut Cursor<'_>) -> TcpSnapshot {
    let mut snapshot = TcpSnapshot {
        incarnation: cursor.u64(),
        policy_epoch: cursor.u64(),
        age_ns: cursor.u64(),
        abi: cursor.u32(),
        phase: cursor.u32(),
        terminal_flags: cursor.u32(),
        reserved: cursor.u32(),
        peers: [TcpPeer::default(); 2],
    };
    for peer in &mut snapshot.peers {
        *peer = TcpPeer {
            syn_seq: cursor.u32(),
            end: cursor.u32(),
            max_ack: cursor.u32(),
            window_raw: cursor.u32(),
            window_seq: cursor.u32(),
            window_ack: cursor.u32(),
            max_window: cursor.u32(),
            fin_seq: cursor.u32(),
            flags: cursor.u32(),
            scale: cursor.u32(),
        };
    }
    snapshot
}

fn put32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

/// Every call follows an EXACT record-size check, never a partial wire read.
struct Cursor<'a>(&'a [u8]);

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let (head, tail) = self.0.split_at(N);
        self.0 = tail;
        head.try_into().unwrap()
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.take())
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.take())
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take())
    }
}

fn key_bytes(key: &TcpSessionKey) -> [u8; KEY] {
    let mut bytes = Vec::with_capacity(KEY);
    encode_key(key, &mut bytes);
    bytes.try_into().unwrap()
}

/// Encode wholly validated batches: no partial result on invalid input, no
/// ambiguous duplicate key, at most256 records AND32768 payload bytes per frame.
pub fn encode_frames(records: &[TcpWireRecord]) -> Result<Vec<Vec<u8>>, TcpCodecError> {
    if records.len() > TCP_TABLE_RECORDS {
        return Err(TcpCodecError::RecordLimit);
    }
    let mut seen = BTreeSet::new();
    let mut frames = Vec::new();
    let mut frame = Vec::new();
    let mut count = 0;
    for record in records {
        let wire = record.encode()?;
        if !seen.insert(key_bytes(&record.prefix().0)) {
            return Err(TcpCodecError::DuplicateKey);
        }
        if count == TCP_FRAME_RECORDS || frame.len() + 2 + wire.len() > TCP_FRAME_BYTES {
            frames.push(std::mem::take(&mut frame));
            count = 0;
        }
        frame.extend_from_slice(&(wire.len() as u16).to_le_bytes());
        frame.extend_from_slice(&wire);
        count += 1;
    }
    if !frame.is_empty() {
        frames.push(frame);
    }
    Ok(frames)
}

/// Decode ALL records before a caller may apply any of them. This is not an
/// authenticated outer frame parser and never authorizes map side effects.
pub fn decode_frame(bytes: &[u8]) -> Result<Vec<TcpWireRecord>, TcpCodecError> {
    if bytes.is_empty() {
        return Err(TcpCodecError::EmptyFrame);
    }
    if bytes.len() > TCP_FRAME_BYTES {
        return Err(TcpCodecError::FrameLimit);
    }
    let mut remaining = bytes;
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    while !remaining.is_empty() {
        if records.len() == TCP_FRAME_RECORDS {
            return Err(TcpCodecError::RecordLimit);
        }
        if remaining.len() < 2 {
            return Err(TcpCodecError::Length);
        }
        let length = u16::from_le_bytes(remaining[..2].try_into().unwrap()) as usize;
        if !matches!(length, TCP_UPSERT_BYTES | TCP_DELETE_BYTES) || remaining.len() < 2 + length {
            return Err(TcpCodecError::Length);
        }
        let record = TcpWireRecord::decode(&remaining[2..2 + length])?;
        if !seen.insert(key_bytes(&record.prefix().0)) {
            return Err(TcpCodecError::DuplicateKey);
        }
        records.push(record);
        remaining = &remaining[2 + length..];
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use velstra_common::{
        FirewallKey, FirewallState, FlowKey, TCP_SCALE_ABSENT, TCP_SEGMENT_VALIDATED, TcpSegment,
        tcp_flags,
    };

    use super::*;

    fn sample(policy: u32) -> TcpRecord {
        let key = TcpSessionKey::new(
            policy,
            4,
            [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            [192, 0, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            12345,
            443,
        )
        .unwrap()
        .0;
        let mut snapshot = TcpSession::open_admitted(
            TcpSegment {
                seq: 256,
                ack: 0,
                payload_len: 0,
                window: 4096,
                flags: tcp_flags::SYN as u32,
                scale: TCP_SCALE_ABSENT,
                validated: TCP_SEGMENT_VALIDATED,
                reserved: 0,
            },
            0x0102030405060708,
            0x1112131415161718,
            123456,
        )
        .unwrap()
        .snapshot;
        snapshot.age_ns = 1_000_000_000;
        TcpRecord {
            key,
            initiator_side: 0,
            snapshot,
        }
    }

    fn hex(literal: &str) -> Vec<u8> {
        let compact: String = literal.chars().filter(|c| !c.is_whitespace()).collect();
        assert_eq!(compact.len() % 2, 0);
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn independent_literal_golden_snapshot_and_schema() {
        let wire = hex("56544331 0100 0100
             40302010 04000000
             0a000001000000000000000000000000 c0000202000000000000000000000000
             3930 bb01 00000000
             0807060504030201 1817161514131211 00ca9a3b00000000
             01000000 01000000 00000000 00000000
             00010000 01010000 00000000 00100000 00010000
             00000000 00100000 00000000 41010000 00000000
             00000000 00000000 00000000 00000000 00000000
             00000000 00000000 00000000 00000000 00000000");
        assert_eq!(wire.len(), 176);
        let expected = TcpWireRecord::Upsert(sample(0x10203040));
        assert_eq!(TcpWireRecord::decode(&wire), Ok(expected));
        assert_eq!(expected.encode().unwrap(), wire);
        let schema = hex("56545343 0100 0000 2c00 7800 01000000");
        assert_eq!(TcpSchema.encode().as_slice(), schema);
        assert_eq!(TcpSchema::decode(&schema), Ok(TcpSchema));
        for i in 0..schema.len() {
            let mut invalid = schema.clone();
            invalid[i] ^= 1;
            assert!(TcpSchema::decode(&invalid).is_err(), "byte{i}");
        }
        for length in 0..schema.len() {
            assert!(TcpSchema::decode(&schema[..length]).is_err());
        }
        let mut extra = schema;
        extra.push(0);
        assert!(TcpSchema::decode(&extra).is_err());
    }

    #[test]
    fn complete_directional_metadata_survives_without_local_fields() {
        let mut record = sample(7);
        record.initiator_side = 1;
        record.snapshot.phase = TcpSession::CLOSING;
        record.snapshot.peers = [
            TcpPeer {
                syn_seq: 1,
                end: 501,
                max_ack: 501,
                window_raw: 100,
                window_seq: 500,
                window_ack: 1200,
                max_window: 800,
                fin_seq: 500,
                flags: 255,
                scale: 3,
            },
            TcpPeer {
                syn_seq: 1000,
                end: 1201,
                max_ack: 1200,
                window_raw: 200,
                window_seq: 1200,
                window_ack: 501,
                max_window: 3200,
                fin_seq: 1200,
                flags: 223,
                scale: 4,
            },
        ];
        assert!(record.snapshot.valid());
        let wire = TcpWireRecord::Upsert(record).encode().unwrap();
        assert_eq!(wire.len(), TCP_UPSERT_BYTES);
        assert_eq!(
            TcpWireRecord::decode(&wire),
            Ok(TcpWireRecord::Upsert(record))
        );
        // Snapshot is the only value serialized: top-level spinlock, local
        // epoch, timestamp and revision have no field/offset in this codec.
        assert_eq!(&wire[56..64], &record.snapshot.incarnation.to_le_bytes());
        assert_eq!(&wire[72..80], &1_000_000_000u64.to_le_bytes());
        let imported =
            TcpSession::import(record.snapshot, record.snapshot.policy_epoch, 900000).unwrap();
        assert_eq!(imported.snapshot, record.snapshot);
        assert_eq!(imported.last_seen_ns, 900000);
        assert_eq!(imported.revision, 1);
    }

    #[test]
    fn tombstone_has_independent_golden_and_exact_incarnation_guard() {
        let record = sample(0x10203040);
        let identity = record.tombstone();
        let wire = hex("56544331 0100 0200
             40302010 04000000
             0a000001000000000000000000000000 c0000202000000000000000000000000
             3930 bb01 00000000 0807060504030201 1817161514131211");
        assert_eq!(wire.len(), 72);
        assert_eq!(TcpWireRecord::Delete(identity).encode().unwrap(), wire);
        assert_eq!(
            TcpWireRecord::decode(&wire),
            Ok(TcpWireRecord::Delete(identity))
        );
        assert!(identity.matches(&record));
        let mut newer = record;
        newer.snapshot.age_ns += 1;
        assert!(identity.matches(&newer)); // Activity is not identity.
        newer.snapshot.incarnation += 1;
        assert!(!identity.matches(&newer));
        newer = record;
        newer.snapshot.policy_epoch += 1;
        assert!(!identity.matches(&newer));
        newer = record;
        newer.initiator_side ^= 1;
        assert!(!identity.matches(&newer));
        newer = record;
        newer.key.policy += 1;
        assert!(!identity.matches(&newer));
    }

    #[test]
    fn all_truncations_overruns_versions_kinds_and_reserved_fields_fail_closed() {
        for record in [
            TcpWireRecord::Upsert(sample(7)),
            TcpWireRecord::Delete(sample(7).tombstone()),
        ] {
            let wire = record.encode().unwrap();
            for end in 0..wire.len() {
                assert!(TcpWireRecord::decode(&wire[..end]).is_err(), "end{end}");
            }
            for extra in 1..=4 {
                let mut invalid = wire.clone();
                invalid.resize(wire.len() + extra, 0);
                assert!(TcpWireRecord::decode(&invalid).is_err());
            }
            for (offset, value) in [(0, b'X'), (4, 0), (4, 2), (5, 1), (6, 0), (6, 3), (7, 1)] {
                let mut invalid = wire.clone();
                invalid[offset] = value;
                assert!(TcpWireRecord::decode(&invalid).is_err());
            }
        }
        let wire = TcpWireRecord::Upsert(sample(7)).encode().unwrap();
        for (offset, value) in [
            (12, 5),  // family
            (20, 1),  // nonzero IPv4 address tail
            (52, 2),  // initiator side
            (80, 2),  // snapshot ABI
            (84, 0),  // phase
            (92, 1),  // snapshot reserved
            (129, 3), // unknown peer flags bit9
        ] {
            let mut invalid = wire.clone();
            invalid[offset] = value;
            assert!(TcpWireRecord::decode(&invalid).is_err(), "offset{offset}");
        }
        for start in [56, 64] {
            let mut invalid = wire.clone();
            invalid[start..start + 8].fill(0);
            assert!(TcpWireRecord::decode(&invalid).is_err());
        }
        let mut invalid = sample(7);
        invalid.snapshot.reserved = 1;
        assert!(TcpWireRecord::Upsert(invalid).encode().is_err());
        let mut invalid = sample(7).tombstone();
        invalid.incarnation = 0;
        assert!(TcpWireRecord::Delete(invalid).encode().is_err());
    }

    #[test]
    fn canonical_ipv6_numeric_ports_zero_ports_and_equal_endpoints_are_explicit() {
        assert_eq!(std::mem::size_of::<TcpSessionKey>(), KEY);
        assert_eq!(std::mem::size_of::<TcpSnapshot>(), SNAPSHOT);
        let mut record = sample(7);
        let address = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        record.key = TcpSessionKey::new(7, 6, address, address, 256, 255)
            .unwrap()
            .0;
        assert_eq!((record.key.port0, record.key.port1), (255, 256));
        record.initiator_side = 1;
        let wire = TcpWireRecord::Upsert(record).encode().unwrap();
        assert_eq!(
            TcpWireRecord::decode(&wire),
            Ok(TcpWireRecord::Upsert(record))
        );
        record.key.port0 = 0;
        assert!(TcpWireRecord::Upsert(record).encode().is_ok());
        let mut invalid = record;
        invalid.key.port0 = invalid.key.port1;
        assert!(TcpWireRecord::Upsert(invalid).encode().is_err());
        invalid = record;
        invalid.key.port0 = 300;
        assert!(TcpWireRecord::Upsert(invalid).encode().is_err());
        invalid = record;
        invalid.initiator_side = 2;
        assert!(TcpWireRecord::Upsert(invalid).encode().is_err());
        assert!(!invalid.tombstone().matches(&invalid));
        invalid = record;
        invalid.snapshot.incarnation = 0;
        assert!(!invalid.tombstone().matches(&invalid));
        for start in [56, 64] {
            let mut invalid = TcpWireRecord::Delete(record.tombstone()).encode().unwrap();
            invalid[start..start + 8].fill(0);
            assert_eq!(
                TcpWireRecord::decode(&invalid),
                Err(TcpCodecError::Identity)
            );
        }
    }

    #[test]
    fn legacy_flags_only_tcp_cannot_be_promoted_and_empty_schema_is_not_optional() {
        let key = FirewallKey::ipv4(FlowKey::new(
            7,
            [10, 0, 0, 1],
            [192, 0, 2, 2],
            12345,
            443,
            6,
        ));
        let legacy = super::super::encode_firewall_batch(
            &[(
                key,
                FirewallState {
                    last_seen_ns: 1,
                    age_ns: 0,
                    phase: 3,
                    reply: 0,
                },
            )],
            1,
        );
        assert_eq!(legacy[0].len(), 68);
        assert_eq!(
            TcpWireRecord::decode(&legacy[0]),
            Err(TcpCodecError::Header)
        );
        assert!(TcpSchema::decode(&[]).is_err());
    }

    #[test]
    fn local_gc_in_progress_cannot_become_an_authoritative_upsert() {
        let mut record = sample(7);
        record.snapshot.phase = TcpSession::GC_PENDING;
        assert!(record.snapshot.valid()); // The LOCAL model can represent GC.
        assert_eq!(
            TcpWireRecord::Upsert(record).encode(),
            Err(TcpCodecError::Snapshot)
        );
        let mut invalid = TcpWireRecord::Upsert(sample(7)).encode().unwrap();
        invalid[84..88].copy_from_slice(&TcpSession::GC_PENDING.to_le_bytes());
        assert_eq!(
            TcpWireRecord::decode(&invalid),
            Err(TcpCodecError::Snapshot)
        );
        let deletion = TcpWireRecord::Delete(record.tombstone());
        assert_eq!(
            TcpWireRecord::decode(&deletion.encode().unwrap()),
            Ok(deletion)
        );
    }

    #[test]
    fn exact_byte_limit_and_record_limit_are_independent() {
        let records: Vec<_> = (0..185).map(|i| TcpWireRecord::Upsert(sample(i))).collect();
        let frames = encode_frames(&records).unwrap();
        assert_eq!(
            frames.iter().map(Vec::len).collect::<Vec<_>>(),
            [32752, 178]
        );
        let decoded: Vec<_> = frames
            .iter()
            .flat_map(|f| decode_frame(f).unwrap())
            .collect();
        assert_eq!(decoded, records);

        let records: Vec<_> = (0..257)
            .map(|i| TcpWireRecord::Delete(sample(i).tombstone()))
            .collect();
        let frames = encode_frames(&records).unwrap();
        assert_eq!(frames.iter().map(Vec::len).collect::<Vec<_>>(), [18944, 74]);
        let mut too_many = frames[0].clone();
        too_many.extend_from_slice(&frames[1]);
        assert_eq!(decode_frame(&too_many), Err(TcpCodecError::RecordLimit));

        // 150*(176+2)+82*(72+2) = EXACT32768, with232 records.
        let records: Vec<_> = (0..232)
            .map(|i| {
                if i < 150 {
                    TcpWireRecord::Upsert(sample(i))
                } else {
                    TcpWireRecord::Delete(sample(i).tombstone())
                }
            })
            .collect();
        let frames = encode_frames(&records).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), TCP_FRAME_BYTES);
        assert_eq!(decode_frame(&frames[0]).unwrap(), records);
        let mut over = frames[0].clone();
        over.push(0);
        assert_eq!(decode_frame(&over), Err(TcpCodecError::FrameLimit));
        assert!(encode_frames(&[]).unwrap().is_empty());
        assert_eq!(decode_frame(&[]), Err(TcpCodecError::EmptyFrame));
    }

    #[test]
    fn duplicate_keys_and_partial_batches_never_return_applicable_prefixes() {
        let record = TcpWireRecord::Upsert(sample(7));
        let delete = TcpWireRecord::Delete(sample(7).tombstone());
        assert_eq!(
            encode_frames(&[record, delete]),
            Err(TcpCodecError::DuplicateKey)
        );
        let first = encode_frames(&[record]).unwrap().remove(0);
        let second = encode_frames(&[delete]).unwrap().remove(0);
        let mut duplicate = first.clone();
        duplicate.extend_from_slice(&second);
        assert_eq!(decode_frame(&duplicate), Err(TcpCodecError::DuplicateKey));
        for tail in [vec![1], vec![0, 0], vec![176, 0, 1], vec![255, 255]] {
            let mut invalid = first.clone();
            invalid.extend_from_slice(&tail);
            assert!(decode_frame(&invalid).is_err());
        }
        let excessive = vec![record; TCP_TABLE_RECORDS + 1];
        assert_eq!(encode_frames(&excessive), Err(TcpCodecError::RecordLimit));
    }

    #[test]
    fn accepted_mutations_reencode_exactly_and_arbitrary_bytes_never_panic() {
        let mut seed = 0x93b18702u32;
        let golden = TcpWireRecord::Upsert(sample(7)).encode().unwrap();
        for trial in 0..10000 {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let mut bytes = golden.clone();
            let index = seed as usize % bytes.len();
            bytes[index] ^= ((seed >> 16) as u8) | 1;
            if trial % 3 == 0 {
                bytes.resize(seed as usize % 200, (seed >> 8) as u8);
            }
            if let Ok(record) = TcpWireRecord::decode(&bytes) {
                assert_eq!(record.encode().unwrap(), bytes);
            }
            let _ = decode_frame(&bytes);
        }
    }
}
