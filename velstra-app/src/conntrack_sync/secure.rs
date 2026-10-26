//! VCS2: mutually authenticated, ordered state replication. Fresh challenges
//! bind each connection to a session; sequence numbers and HMAC authenticate
//! every bounded frame. This provides authenticity, not confidentiality: use a
//! dedicated HA link or WireGuard when flow metadata must be encrypted.
//!
//! One producer reads all three LRU maps in kernel batches. Each peer gets an initial
//! snapshot followed by changes and deletions. Imported entries are not echoed;
//! once a local packet changes one, the local dataplane owns it. All application
//! is fenced by the firewall's configuration lock and policy fingerprint.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    io,
    net::IpAddr,
    os::fd::{AsFd, AsRawFd},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use aya::{
    Pod,
    maps::{HashMap, IterableMap, MapData},
};
use log::{info, warn};
use ring::{
    digest, hmac,
    rand::{SecureRandom, SystemRandom},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, watch},
    time::timeout,
};
use velstra_common::{FirewallKey, FirewallState, FlowKey, FlowState, SynFlow};
use velstra_config::{ResolvedConntrackSync, RuntimeConfig};

use super::{
    Datagram, decode_datagram, decode_key, encode_firewall_batch, encode_key, encode_nat_batch,
    monotonic_ns,
};
use crate::{
    firewall::Firewall,
    ha::{self, Authority},
};

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = 32_768;
// Each of CONNTRACK, FW_FLOWS and SYN_FLOWS has at most 65,536 entries.
const MAX_ENTRIES: usize = 196_608 + 4096;
const BEGIN: u8 = 0;
const UPSERT: u8 = 1;
const DELETE: u8 = 2;
const END: u8 = 3;
const HEARTBEAT: u8 = 4;
type Key = Vec<u8>;
type Entries = BTreeMap<Key, Record>;
type NatMap = Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Record {
    Nat(FlowKey, FlowState),
    Firewall(FirewallKey, FirewallState),
    SynProxy(FlowKey, SynFlow),
    Wireguard(ha::wireguard::Endpoint),
}

impl Record {
    fn key(self) -> Key {
        match self {
            Self::Wireguard(endpoint) => {
                let mut key = vec![5];
                key.extend_from_slice(&endpoint.interface);
                key.extend_from_slice(&endpoint.public_key);
                key
            }
            Self::Nat(key, _) => {
                let mut out = vec![3];
                encode_key(&key, &mut out);
                out
            }
            Self::SynProxy(key, _) => {
                let mut out = vec![4];
                encode_key(&key, &mut out);
                out
            }
            Self::Firewall(_, _) => {
                let wire = self.encode(0);
                let mut out = vec![2];
                out.extend_from_slice(&wire[8..52]);
                out
            }
        }
    }
    fn encode(self, now: u64) -> Vec<u8> {
        // The parent codec intentionally excludes ages over seven days. Such
        // entries are omitted by the producer before calling this method.
        match self {
            Self::Wireguard(endpoint) => {
                let mut wire = b"VWG1".to_vec();
                wire.extend_from_slice(&endpoint.interface);
                wire.extend_from_slice(&endpoint.public_key);
                wire.extend_from_slice(&endpoint.ip);
                wire.extend_from_slice(&endpoint.port.to_le_bytes());
                wire.push(endpoint.family);
                wire
            }
            Self::SynProxy(key, state) => {
                // Secure-stream-only record: legacy UDP never accepts SYN state.
                let mut out = b"VSP1".to_vec();
                encode_key(&key, &mut out);
                out.extend_from_slice(&state.cookie.to_le_bytes());
                out.extend_from_slice(&state.delta.to_le_bytes());
                out.extend_from_slice(&state.client_isn.to_le_bytes());
                out.extend_from_slice(&state.flags.to_le_bytes());
                out.extend_from_slice(&[0; 2]);
                out
            }
            Self::Nat(key, mut state) => {
                state.age_ns = state.idle_ns(now).min(604_800_000_000_000);
                state.last_seen_ns = 0;
                encode_nat_batch(&[(key, state)], 0).remove(0)
            }
            Self::Firewall(key, mut state) => {
                state.age_ns = state.idle_ns(now).min(604_800_000_000_000);
                state.last_seen_ns = 0;
                encode_firewall_batch(&[(key, state)], 0).remove(0)
            }
        }
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"VWG1") {
            ensure!(
                bytes.len() == 71,
                "invalid WireGuard endpoint record length"
            );
            let endpoint = ha::wireguard::Endpoint {
                interface: bytes[4..20].try_into()?,
                public_key: bytes[20..52].try_into()?,
                ip: bytes[52..68].try_into()?,
                port: u16::from_le_bytes(bytes[68..70].try_into()?),
                family: bytes[70],
            };
            endpoint.validate()?;
            return Ok(Self::Wireguard(endpoint));
        }
        if bytes.starts_with(b"VSP1") {
            ensure!(bytes.len() == 40, "invalid SYN-proxy record length");
            let key = decode_key(&bytes[4..24]);
            let state = SynFlow {
                cookie: u32::from_le_bytes(bytes[24..28].try_into()?),
                delta: u32::from_le_bytes(bytes[28..32].try_into()?),
                client_isn: u32::from_le_bytes(bytes[32..36].try_into()?),
                flags: u16::from_le_bytes(bytes[36..38].try_into()?),
                _pad: 0,
            };
            ensure!(
                key.policy == 0
                    && key.dst_ip == [0; 4]
                    && key.proto == 6
                    && key.src_port != 0
                    && key.dst_port != 0
                    && bytes[21..24] == [0; 3]
                    && bytes[38..40] == [0; 2]
                    && (state.flags == SynFlow::SPLICED || (state.flags == 0 && state.delta == 0)),
                "invalid SYN-proxy state"
            );
            return Ok(Self::SynProxy(key, state));
        }
        match decode_datagram(bytes) {
            Some(Datagram::Nat(mut entries)) if entries.len() == 1 => {
                let (key, value) = entries.remove(0);
                Ok(Self::Nat(key, value))
            }
            Some(Datagram::Firewall(mut entries)) if entries.len() == 1 => {
                let (key, value) = entries.remove(0);
                Ok(Self::Firewall(key, value))
            }
            _ => bail!("invalid VCS2 state record"),
        }
    }
    fn received(self, now: u64) -> Self {
        match self {
            Self::SynProxy(_, _) | Self::Wireguard(_) => self,
            Self::Nat(key, state) => Self::Nat(
                key,
                FlowState {
                    last_seen_ns: now,
                    ..state
                },
            ),
            Self::Firewall(key, state) => Self::Firewall(
                key,
                FirewallState {
                    last_seen_ns: now,
                    ..state
                },
            ),
        }
    }
}

#[derive(Clone)]
struct Snapshot {
    authority: Option<Authority>,
    policy: [u8; 32],
    entries: Entries,
}
struct Imported {
    peer: IpAddr,
    record: Record,
}
struct Store {
    nat: NatMap,
    firewall: HashMap<MapData, FirewallKey, FirewallState>,
    synproxy: HashMap<MapData, FlowKey, SynFlow>,
    endpoints: BTreeMap<Key, ha::wireguard::Endpoint>,
    imported: BTreeMap<Key, Imported>,
    policy: Option<[u8; 32]>,
    local_addresses: BTreeSet<IpAddr>,
}

impl Store {
    fn local_firewall(&self, key: &FirewallKey) -> bool {
        let (src, dst) = if key.family == 4 {
            (
                IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(&key.src[..4]).expect("IPv4 key width"),
                )),
                IpAddr::V4(std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(&key.dst[..4]).expect("IPv4 key width"),
                )),
            )
        } else {
            (
                IpAddr::V6(std::net::Ipv6Addr::from(key.src)),
                IpAddr::V6(std::net::Ipv6Addr::from(key.dst)),
            )
        };
        self.local_addresses.contains(&src) || self.local_addresses.contains(&dst)
    }
    fn generation(&mut self, policy: [u8; 32]) {
        if self.policy != Some(policy) {
            self.imported.clear();
            self.policy = Some(policy);
        }
    }
    async fn snapshot(&mut self, policy: [u8; 32], authoritative: bool) -> Result<Snapshot> {
        self.generation(policy);
        let nat = self.nat.lock().await;
        let mut entries = Entries::new();
        // Kernel writers continue while LOOKUP_BATCH copies the map. Sample
        // time after each dump: a timestamp refreshed during the syscall must
        // not look like a foreign-clock entry and become a false tombstone.
        let nat_entries = batch_read(&*nat)?;
        let now = monotonic_ns();
        for (key, state) in nat_entries {
            if state.idle_ns(now) <= 604_800_000_000_000 {
                let record = Record::Nat(key, state);
                entries.insert(record.key(), record);
            }
        }
        let firewall_entries = batch_read(&self.firewall)?;
        let now = monotonic_ns();
        for (key, state) in firewall_entries {
            if self.local_firewall(&key) {
                continue;
            }
            if state.idle_ns(now) <= 604_800_000_000_000 {
                let record = Record::Firewall(key, state);
                entries.insert(record.key(), record);
            }
        }
        for (key, state) in batch_read(&self.synproxy)? {
            let record = Record::SynProxy(key, state);
            entries.insert(record.key(), record);
        }
        self.imported
            .retain(|key, imported| entries.get(key) == Some(&imported.record));
        // A leased owner owns its entire complete baseline, including stable
        // SYN splices that never change after import. Standalone mesh mode
        // alone suppresses unchanged imports to prevent echo loops.
        if !authoritative {
            entries.retain(|key, _| !self.imported.contains_key(key));
        }
        Ok(Snapshot {
            authority: None,
            policy,
            entries,
        })
    }
    async fn apply(&mut self, peer: IpAddr, kind: u8, record: Record) -> Result<()> {
        self.apply_inner(peer, kind, record, false).await
    }
    async fn apply_inner(
        &mut self,
        peer: IpAddr,
        kind: u8,
        mut record: Record,
        authoritative: bool,
    ) -> Result<()> {
        let key = record.key();
        if matches!(record,Record::Firewall(key,_) if self.local_firewall(&key)) {
            self.imported.remove(&key);
            return Ok(());
        }

        if let Record::Wireguard(endpoint) = record {
            ensure!(
                authoritative,
                "WireGuard endpoint requires witness authority"
            );
            if kind == DELETE {
                self.endpoints.remove(&key);
            } else {
                ensure!(
                    self.endpoints.len() < 4096 || self.endpoints.contains_key(&key),
                    "too many WireGuard endpoints"
                );
                self.endpoints.insert(key, endpoint);
            }
            return Ok(());
        }
        let mut nat = self.nat.lock().await;
        let local = match record {
            Record::Wireguard(_) => unreachable!("handled above"),
            Record::SynProxy(k, _) => self
                .synproxy
                .get(&k, 0)
                .ok()
                .map(|v| Record::SynProxy(k, v)),
            Record::Nat(k, _) => nat.get(&k, 0).ok().map(|v| Record::Nat(k, v)),
            Record::Firewall(k, _) => self
                .firewall
                .get(&k, 0)
                .ok()
                .map(|v| Record::Firewall(k, v)),
        };
        // Never delete or overwrite locally advanced state. This also prevents
        // an old master's queued snapshot undoing a locally observed TCP RST.
        let ours = self
            .imported
            .get(&key)
            .is_some_and(|i| i.peer == peer && local == Some(i.record));
        if local.is_some() && !ours && !authoritative {
            return Ok(());
        }
        if kind == DELETE {
            if ours || authoritative && local.is_some() {
                match record {
                    Record::Wireguard(_) => unreachable!("handled above"),
                    Record::SynProxy(k, _) => self.synproxy.remove(&k)?,
                    Record::Nat(k, _) => nat.remove(&k)?,
                    Record::Firewall(k, _) => self.firewall.remove(&k)?,
                }
                self.imported.remove(&key);
            }
        } else {
            ensure!(
                self.imported.len() < MAX_ENTRIES || self.imported.contains_key(&key),
                "peer state exceeds bounded map capacity"
            );
            // A successor owns flow state, while accounting stays local even
            // when the former master rejoins with older, locally owned values.
            if let (Record::Nat(key, incoming), Some(Record::Nat(_, old))) = (&mut record, local) {
                let _ = key;
                incoming.packets = old.packets;
                incoming.bytes = old.bytes;
            }
            let record = record.received(monotonic_ns());
            match record {
                Record::Wireguard(_) => unreachable!("handled above"),
                Record::SynProxy(k, v) => self.synproxy.insert(k, v, 0)?,
                Record::Nat(k, v) => nat.insert(k, v, 0)?,
                Record::Firewall(k, v) => self.firewall.insert(k, v, 0)?,
            }
            self.imported.insert(key, Imported { peer, record });
        }
        Ok(())
    }
    /// Called only while HA's kernel lease is closed and its authority lock is
    /// held. A complete successor snapshot supersedes old locally owned state.
    async fn replace_ha(&mut self, peer: IpAddr, records: Entries) -> Result<()> {
        let absent_nat: Vec<_> = batch_read(&*self.nat.lock().await)?
            .into_iter()
            .filter(|(k, v)| !records.contains_key(&Record::Nat(*k, *v).key()))
            .collect();
        let absent_fw: Vec<_> = batch_read(&self.firewall)?
            .into_iter()
            .filter(|(k, v)| {
                !self.local_firewall(k) && !records.contains_key(&Record::Firewall(*k, *v).key())
            })
            .collect();
        let absent_syn: Vec<_> = batch_read(&self.synproxy)?
            .into_iter()
            .filter(|(k, v)| !records.contains_key(&Record::SynProxy(*k, *v).key()))
            .collect();
        {
            let mut nat = self.nat.lock().await;
            for (key, _) in absent_nat {
                nat.remove(&key)?;
            }
        }
        for (key, _) in absent_fw {
            self.firewall.remove(&key)?;
        }
        for (key, _) in absent_syn {
            self.synproxy.remove(&key)?;
        }
        self.imported.clear();
        self.endpoints.clear();
        for record in records.into_values() {
            self.apply_inner(peer, UPSERT, record, true).await?;
        }
        Ok(())
    }
    async fn finish_snapshot(&mut self, peer: IpAddr, seen: &HashSet<Key>) -> Result<()> {
        let absent: Vec<_> = self
            .imported
            .iter()
            .filter(|(key, item)| item.peer == peer && !seen.contains(*key))
            .map(|(_, item)| item.record)
            .collect();
        for record in absent {
            self.apply(peer, DELETE, record).await?;
        }
        Ok(())
    }
}

/// BPF_MAP_LOOKUP_BATCH uses one syscall per bucket batch instead of two per
/// flow. A concurrent dump is bounded; errors never become an empty snapshot
/// that could accidentally delete a peer's working state.
fn batch_read<K: Pod, V: Pod>(map: &HashMap<MapData, K, V>) -> Result<Vec<(K, V)>> {
    #[repr(C)]
    struct Attr {
        in_batch: u64,
        out_batch: u64,
        keys: u64,
        values: u64,
        count: u32,
        map_fd: u32,
        elem_flags: u64,
        flags: u64,
    }
    let mut cursor = 0u32;
    let mut first = true;
    let mut capacity = 512usize;
    let mut output = Vec::new();
    loop {
        // Aya Pod permits zero-filled values; buffers stay initialized even on
        // an error. Only the count reported by a successful/final call is read.
        let mut keys: Vec<K> = vec![unsafe { std::mem::zeroed() }; capacity];
        let mut values: Vec<V> = vec![unsafe { std::mem::zeroed() }; capacity];
        let input = cursor;
        let mut attr = Attr {
            in_batch: if first {
                0
            } else {
                &input as *const u32 as u64
            },
            out_batch: &mut cursor as *mut u32 as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: capacity as u32,
            map_fd: map.map().fd().as_fd().as_raw_fd() as u32,
            elem_flags: 0,
            flags: 0,
        };
        // Linux UAPI enum bpf_cmd: BPF_MAP_LOOKUP_BATCH = 24.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                24,
                &mut attr as *mut Attr,
                std::mem::size_of::<Attr>(),
            )
        };
        let error = io::Error::last_os_error();
        if rc < 0 && error.raw_os_error() == Some(libc::ENOSPC) {
            ensure!(
                capacity < 65_536,
                "conntrack batch bucket exceeds map capacity"
            );
            capacity *= 2;
            cursor = input;
            continue;
        }
        if rc < 0 && error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error).context("reading conntrack map batch");
        }
        let count = attr.count as usize;
        ensure!(
            count <= capacity && output.len() + count <= MAX_ENTRIES,
            "conntrack dump exceeds bounded map capacity"
        );
        output.extend(keys.into_iter().zip(values).take(count));
        if rc < 0 {
            return Ok(output);
        }
        ensure!(
            count > 0 && (first || cursor != input),
            "conntrack dump made no progress"
        );
        first = false;
    }
}

fn proof(secret: &[u8], label: &[u8], client: &[u8; 32], server: &[u8; 32]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut context = hmac::Context::with_key(&key);
    context.update(b"Velstra VCS2\0");
    context.update(label);
    context.update(client);
    context.update(server);
    context.sign().as_ref().to_vec()
}
fn verify_proof(
    secret: &[u8],
    label: &[u8],
    client: &[u8; 32],
    server: &[u8; 32],
    tag: &[u8],
) -> Result<()> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut message = b"Velstra VCS2\0".to_vec();
    message.extend_from_slice(label);
    message.extend_from_slice(client);
    message.extend_from_slice(server);
    hmac::verify(&key, &message, tag).map_err(|_| anyhow!("VCS2 authentication failed"))
}
fn nonce() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow!("HA random source unavailable"))?;
    Ok(bytes)
}

async fn handshake(stream: &mut TcpStream, secret: &[u8], client_side: bool) -> Result<hmac::Key> {
    let (client, server) = if client_side {
        let client = nonce()?;
        stream.write_all(b"VCS2").await?;
        stream.write_all(&client).await?;
        let mut server = [0; 32];
        let mut tag = [0; 32];
        stream.read_exact(&mut server).await?;
        stream.read_exact(&mut tag).await?;
        verify_proof(secret, b"server", &client, &server, &tag)?;
        stream
            .write_all(&proof(secret, b"client", &client, &server))
            .await?;
        (client, server)
    } else {
        let mut magic = [0; 4];
        let mut client = [0; 32];
        stream.read_exact(&mut magic).await?;
        ensure!(&magic == b"VCS2", "unsupported conntrack protocol");
        stream.read_exact(&mut client).await?;
        let server = nonce()?;
        stream.write_all(&server).await?;
        stream
            .write_all(&proof(secret, b"server", &client, &server))
            .await?;
        let mut tag = [0; 32];
        stream.read_exact(&mut tag).await?;
        verify_proof(secret, b"client", &client, &server, &tag)?;
        (client, server)
    };
    Ok(hmac::Key::new(
        hmac::HMAC_SHA256,
        &proof(secret, b"state", &client, &server),
    ))
}

struct Session {
    key: hmac::Key,
    sequence: u64,
}
impl Session {
    fn frame(&mut self, policy: [u8; 32], kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
        ensure!(payload.len() <= MAX_FRAME, "state frame exceeds limit");
        let mut bytes = Vec::with_capacity(77 + payload.len());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&policy);
        bytes.push(kind);
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(hmac::sign(&self.key, &bytes).as_ref());
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("state sequence exhausted")?;
        Ok(bytes)
    }
    fn verify<'a>(&mut self, bytes: &'a [u8]) -> Result<([u8; 32], u8, &'a [u8])> {
        ensure!(bytes.len() >= 77, "truncated state frame");
        let length = u32::from_le_bytes(bytes[41..45].try_into()?) as usize;
        ensure!(
            length <= MAX_FRAME && bytes.len() == 77 + length,
            "invalid state frame length"
        );
        hmac::verify(&self.key, &bytes[..45 + length], &bytes[45 + length..])
            .map_err(|_| anyhow!("state frame authentication failed"))?;
        ensure!(
            u64::from_le_bytes(bytes[..8].try_into()?) == self.sequence,
            "replayed or reordered state frame"
        );
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("state sequence exhausted")?;
        Ok((bytes[8..40].try_into()?, bytes[40], &bytes[45..45 + length]))
    }
}

async fn write_frame(
    stream: &mut TcpStream,
    session: &mut Session,
    policy: [u8; 32],
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    timeout(
        IO_TIMEOUT,
        stream.write_all(&session.frame(policy, kind, payload)?),
    )
    .await??;
    Ok(())
}
async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut header = [0; 45];
    stream.read_exact(&mut header).await?;
    let length = u32::from_le_bytes(header[41..45].try_into()?) as usize;
    ensure!(length <= MAX_FRAME, "oversized state frame");
    let mut bytes = vec![0; 77 + length];
    bytes[..45].copy_from_slice(&header);
    stream.read_exact(&mut bytes[45..]).await?;
    Ok(bytes)
}

fn pack(records: &[Record], now: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        let wire = record.encode(now);
        if wire.is_empty() {
            continue;
        }
        bytes.extend_from_slice(&(wire.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&wire);
    }
    bytes
}
fn unpack(mut bytes: &[u8]) -> Result<Vec<Record>> {
    let mut records = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 2, "truncated state record size");
        let length = u16::from_le_bytes(bytes[..2].try_into()?) as usize;
        ensure!(
            length <= 96 && bytes.len() >= 2 + length,
            "invalid state record size"
        );
        records.push(Record::decode(&bytes[2..2 + length])?);
        bytes = &bytes[2 + length..];
    }
    Ok(records)
}

async fn send_records(
    stream: &mut TcpStream,
    session: &mut Session,
    policy: [u8; 32],
    kind: u8,
    records: Vec<Record>,
) -> Result<()> {
    for batch in records.chunks(256) {
        write_frame(stream, session, policy, kind, &pack(batch, monotonic_ns())).await?;
    }
    Ok(())
}

async fn push(
    mut stream: TcpStream,
    secret: Arc<String>,
    mut snapshots: watch::Receiver<Option<Arc<Snapshot>>>,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let key = timeout(IO_TIMEOUT, handshake(&mut stream, secret.as_bytes(), true)).await??;
    let mut session = Session { key, sequence: 0 };
    let mut previous: Option<Arc<Snapshot>> = None;
    loop {
        let next = snapshots.borrow_and_update().clone();
        if let Some(next) = next {
            if previous
                .as_ref()
                .is_none_or(|old| old.policy != next.policy || old.authority != next.authority)
            {
                write_frame(
                    &mut stream,
                    &mut session,
                    next.policy,
                    BEGIN,
                    &encode_authority(&next.authority),
                )
                .await?;
                send_records(
                    &mut stream,
                    &mut session,
                    next.policy,
                    UPSERT,
                    next.entries.values().copied().collect(),
                )
                .await?;
                write_frame(&mut stream, &mut session, next.policy, END, &[]).await?;
            } else if let Some(old) = &previous {
                let changed = next
                    .entries
                    .iter()
                    .filter(|(key, record)| old.entries.get(*key) != Some(*record))
                    .map(|(_, record)| *record)
                    .collect();
                let deleted = old
                    .entries
                    .iter()
                    .filter(|(key, _)| !next.entries.contains_key(*key))
                    .map(|(_, record)| *record)
                    .collect();
                send_records(&mut stream, &mut session, next.policy, UPSERT, changed).await?;
                send_records(&mut stream, &mut session, next.policy, DELETE, deleted).await?;
            }
            write_frame(&mut stream, &mut session, next.policy, HEARTBEAT, &[]).await?;
            previous = Some(next);
        } else {
            previous = None;
        }
        snapshots.changed().await?;
    }
}

fn encode_authority(authority: &Option<Authority>) -> Vec<u8> {
    let Some(a) = authority else {
        return Vec::new();
    };
    let mut bytes = a.term.to_le_bytes().to_vec();
    bytes.push(a.owner);
    bytes.extend_from_slice(&a.boot);
    bytes
}
fn decode_authority(bytes: &[u8], policy: [u8; 32]) -> Result<Option<Authority>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    ensure!(bytes.len() == 25, "invalid HA authority length");
    let term = u64::from_le_bytes(bytes[..8].try_into()?);
    let owner = bytes[8];
    ensure!(term > 0 && (1..=2).contains(&owner), "invalid HA authority");
    Ok(Some(Authority {
        term,
        owner,
        boot: bytes[9..25].try_into()?,
        policy,
    }))
}

struct Receiver {
    firewall: Arc<Mutex<Firewall>>,
    store: Arc<Mutex<Store>>,
    ha: ha::Shared,
    generation: Arc<AtomicU64>,
    idle_timeout: Duration,
}
async fn receive(
    mut stream: TcpStream,
    peer: IpAddr,
    secret: Arc<String>,
    context: Receiver,
) -> Result<()> {
    let Receiver {
        firewall,
        store,
        ha,
        generation,
        idle_timeout,
    } = context;
    stream.set_nodelay(true)?;
    let key = timeout(IO_TIMEOUT, handshake(&mut stream, secret.as_bytes(), false)).await??;
    // A reconnect supersedes the previous authenticated stream. Its queued
    // frames cannot roll the new snapshot back, even if both sockets survive.
    let ticket = generation.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    let mut session = Session { key, sequence: 0 };
    let mut seen: Option<HashSet<Key>> = None;
    let mut initialized = false;
    let mut authority = None;
    let mut staged = Entries::new();
    loop {
        let bytes = timeout(idle_timeout, read_frame(&mut stream)).await??;
        let (policy, kind, payload) = session.verify(&bytes)?;
        let fw = firewall.lock().await;
        ensure!(
            generation.load(Ordering::SeqCst) == ticket,
            "state session superseded"
        );
        ensure!(
            initialized || kind == BEGIN,
            "state session requires an initial snapshot"
        );
        ensure!(
            fw.sync_policy()? == policy,
            "peer firewall policy differs; refusing state"
        );
        let mut ha = ha.lock().await;
        if kind == BEGIN {
            authority = decode_authority(payload, policy)?;
        }
        ha.receive_authority(&authority, policy, peer)?;
        let mut store = store.lock().await;
        store.generation(policy);
        match kind {
            BEGIN => {
                ensure!(seen.is_none(), "invalid snapshot start");
                seen = Some(HashSet::new());
                staged.clear();
                initialized = true;
            }
            UPSERT | DELETE => {
                let mut endpoints_changed = false;
                for record in unpack(payload)? {
                    if kind == DELETE && matches!(record, Record::SynProxy(..)) {
                        log::debug!(
                            "conntrack-sync: deleting SYN state term={} record={record:?}",
                            authority.as_ref().map_or(0, |a| a.term)
                        );
                    }
                    endpoints_changed |= matches!(record, Record::Wireguard(_));
                    if let Some(seen) = &mut seen {
                        ensure!(kind == UPSERT, "deletion inside snapshot");
                        seen.insert(record.key());
                        ensure!(seen.len() <= MAX_ENTRIES, "oversized peer snapshot");
                    }
                    if authority.is_some() && seen.is_some() {
                        staged.insert(record.key(), record);
                    } else {
                        store
                            .apply_inner(peer, kind, record, authority.is_some())
                            .await?;
                    }
                }
                if let Some(authority) = authority
                    .as_ref()
                    .filter(|_| seen.is_none() && endpoints_changed)
                {
                    ha::wireguard::publish(
                        &ha,
                        authority,
                        store.endpoints.values().copied().collect(),
                    )?;
                }
            }
            END => {
                ensure!(payload.is_empty(), "invalid snapshot end");
                let seen = seen.take().context("snapshot end without start")?;
                if let Some(authority) = &authority {
                    log::debug!(
                        "conntrack-sync: installing HA snapshot term={} records={} syn={}",
                        authority.term,
                        staged.len(),
                        staged
                            .values()
                            .filter(|r| matches!(r, Record::SynProxy(..)))
                            .count()
                    );
                    ha.begin_install();
                    store.replace_ha(peer, std::mem::take(&mut staged)).await?;
                    ha::wireguard::publish(
                        &ha,
                        authority,
                        store.endpoints.values().copied().collect(),
                    )?;
                    ha.snapshot_ready(authority);
                } else {
                    store.finish_snapshot(peer, &seen).await?;
                }
            }
            HEARTBEAT => {
                ensure!(payload.is_empty() && seen.is_none(), "incomplete snapshot");
                if let Some(authority) = &authority {
                    ha.heartbeat(authority);
                }
            }
            _ => bail!("unknown state frame operation"),
        }
    }
}

async fn control_scope(
    ha: &ha::Shared,
    config: &ResolvedConntrackSync,
) -> Result<BTreeSet<IpAddr>> {
    let Some(config_ha) = ha.lock().await.config.clone() else {
        return Ok(BTreeSet::new());
    };
    let mut scope = ha::control_addresses(&config_ha)?;
    if !config.listen.ip().is_unspecified() {
        scope.insert(config.listen.ip());
    }
    scope.extend(config.peers.iter().map(|peer| peer.ip()));
    Ok(scope)
}

pub async fn run(
    firewall: Arc<Mutex<Firewall>>,
    nat: NatMap,
    flows: HashMap<MapData, FirewallKey, FirewallState>,
    synproxy: HashMap<MapData, FlowKey, SynFlow>,
    ha: ha::Shared,
    config: ResolvedConntrackSync,
) {
    let secret = Arc::new(
        config
            .secret
            .clone()
            .expect("authenticated sync configuration"),
    );
    let initial_scope = loop {
        match control_scope(&ha, &config).await {
            Ok(scope) => break scope,
            Err(error) => {
                warn!("conntrack-sync: cannot determine control ownership: {error:#}; retrying");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };
    let store = Arc::new(Mutex::new(Store {
        nat,
        firewall: flows,
        synproxy,
        endpoints: BTreeMap::new(),
        imported: BTreeMap::new(),
        policy: None,
        local_addresses: initial_scope,
    }));
    let (snapshots, receiver) = watch::channel(None);
    for peer in config.peers.iter().copied() {
        let secret = secret.clone();
        let receiver = receiver.clone();
        tokio::spawn(async move {
            let mut retry = 50u64;
            loop {
                let result = match timeout(IO_TIMEOUT, TcpStream::connect(peer)).await {
                    Ok(Ok(stream)) => {
                        retry = 50;
                        push(stream, secret.clone(), receiver.clone()).await
                    }
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                };
                log::debug!("conntrack-sync: peer {peer} disconnected: {result:?}");
                tokio::time::sleep(Duration::from_millis(retry)).await;
                retry = (retry * 2).min(1000);
            }
        });
    }
    let permits = Arc::new(Semaphore::new(config.peers.len().max(1) * 2));
    let generations: BTreeMap<_, _> = config
        .peers
        .iter()
        .map(|peer| (peer.ip(), Arc::new(AtomicU64::new(0))))
        .collect();
    let idle_timeout = IO_TIMEOUT.max(Duration::from_millis(config.interval_ms.saturating_mul(3)));
    let mut ticker = tokio::time::interval(Duration::from_millis(config.interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut export_authority = None;
    loop {
        let listener = match TcpListener::bind(config.listen).await {
            Ok(listener) => listener,
            Err(error) => {
                warn!(
                    "conntrack-sync: cannot bind {}: {error}; retrying",
                    config.listen
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        info!(
            "conntrack-sync: authenticated TCP listening on {}, polling every {}ms",
            config.listen, config.interval_ms
        );
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, remote)) = accepted else { break; };
                    let Some(generation) = generations.get(&remote.ip()).cloned() else { continue; };
                    let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                    let secret = secret.clone(); let firewall = firewall.clone(); let store = store.clone(); let ha = ha.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = receive(stream, remote.ip(), secret, Receiver{firewall, store, ha, generation, idle_timeout}).await { log::debug!("conntrack-sync: rejected/closed session from {remote}: {error:#}"); }
                    });
                }
                _ = ticker.tick() => {
                    // Batch dumps can be large. Do not hold the configuration
                    // or lease-heartbeat lock while scanning kernel maps. The
                    // epoch and authority are rechecked after the bounded dump.
                    let result = async {
                        let control=control_scope(&ha,&config).await?;
                        store.lock().await.local_addresses=control;
                        let generation = firewall.lock().await.sync_generation()?;
                        let policy = generation.0;
                        let (authority,wg_interfaces) = {
                            let ha=ha.lock().await;
                            (ha.authority_for_send(policy)?,ha.config.as_ref().map(|c|c.wireguard.clone()).unwrap_or_default())
                        };
                        let endpoints = if authority.is_some(){ha::wireguard::scan(&wg_interfaces).await?}else{Vec::new()};
                        let mut snapshot = {
                            let mut store = store.lock().await;
                            store.snapshot(policy, authority.is_some()).await?
                        };
                        if let Some(a) = authority.as_ref().filter(|_| export_authority != authority) {
                            log::debug!("conntrack-sync: exporting HA snapshot term={} records={} syn={}",a.term,snapshot.entries.len(),snapshot.entries.values().filter(|r|matches!(r,Record::SynProxy(..))).count());
                        }
                        for endpoint in endpoints {let record=Record::Wireguard(endpoint);snapshot.entries.insert(record.key(),record);}
                        let fw = firewall.lock().await;
                        ensure!(fw.sync_generation()? == generation, "policy changed during state dump");
                        ensure!(ha.lock().await.authority_for_send(policy)? == authority, "HA authority changed during state dump");
                        snapshot.authority = authority.clone(); export_authority = authority;
                        Ok::<_,anyhow::Error>(snapshot)
                    }.await;
                    match result {
                        Ok(snapshot) => { snapshots.send_replace(Some(Arc::new(snapshot))); }
                        Err(error) => { export_authority = None; snapshots.send_replace(None); log::debug!("conntrack-sync: snapshot unavailable: {error:#}"); }
                    }
                }
            }
        }
    }
}

/// Canonical, versioned JSON of the shared dataplane policy. Local addresses,
/// MACs, routes and sync endpoints are excluded; policy IDs, interface bindings,
/// state lifetimes, filtering and NAT semantics must agree before state applies.
pub(crate) fn policy_fingerprint(cfg: &RuntimeConfig) -> [u8; 32] {
    use serde_json::json;
    let policies: Vec<_> = cfg.policies.iter().map(|p| json!({
        "id":p.id, "global":[p.global.default_action,p.global.flags],
        "block4":p.blocklist.iter().map(|c| (c.octets,c.prefix)).collect::<Vec<_>>(),
        "block6":p.blocklist6.iter().map(|c| (c.octets,c.prefix)).collect::<Vec<_>>(),
        "mac":p.mac_rules.iter().map(|(m,a)| (*m,a.as_u32())).collect::<Vec<_>>(),
        "portal":p.portal.map(|g| (g.portal4,g.portal6)),
        "rules":p.port_rules.iter().map(|r| json!([r.name,r.key.proto,r.key.port,r.icmp_type,r.in_interface,r.scope,
            r.src.map(|c|(c.octets,c.prefix)),r.dst.map(|c|(c.octets,c.prefix)),r.src6.map(|c|(c.octets,c.prefix)),r.dst6.map(|c|(c.octets,c.prefix)),r.action.as_u32(),r.log,r.limit])).collect::<Vec<_>>()
    })).collect();
    let interfaces: Vec<_> = cfg
        .interfaces
        .iter()
        .map(|i| {
            json!([
                i.name,
                i.policy,
                i.vni,
                i.masquerade,
                i.snat_address,
                i.mss,
                i.binding.as_ref().map(|b| json!([b.mac, b.v4, b.v6])),
                i.rate_limit_mbit,
                [i.cgnat.base_port, i.cgnat.block_size, i.cgnat.blocks]
            ])
        })
        .collect();
    let forwards: Vec<_> = cfg
        .port_forwards
        .iter()
        .map(|p| {
            json!([
                p.policy,
                p.proto,
                p.port,
                p.dst_ip,
                p.dst_port,
                p.match_dst,
                p.snat_ip,
                p.reply_policy
            ])
        })
        .collect();
    let services: Vec<_> = cfg
        .services
        .iter()
        .map(|s| {
            json!([
                s.key.policy,
                s.key.vip,
                s.key.port,
                s.key.proto,
                s.backends
                    .iter()
                    .map(|b| (b.ip, b.port))
                    .collect::<Vec<_>>(),
                s.live,
                s.router_nat,
                s.reply_policy,
                s.client_affinity
            ])
        })
        .collect();
    let bytes = json!({"version":5,"ha":cfg.ha.as_ref().map(|h|json!([h.cluster,h.interfaces,h.wireguard_ports,h.wireguard,h.wireguard_policy])),"policies":policies,"interfaces":interfaces,"forwards":forwards,"services":services,
        "timeouts":[cfg.conntrack.tcp_syn,cfg.conntrack.tcp_established,cfg.conntrack.tcp_closing,cfg.conntrack.udp,cfg.conntrack.udp_stream,cfg.conntrack.icmp],
        "synproxy":cfg.synproxy.iter().map(|s|(s.port,s.mss)).collect::<Vec<_>>(),"fail_closed":cfg.fail_closed}).to_string();
    digest::digest(&digest::SHA256, bytes.as_bytes())
        .as_ref()
        .try_into()
        .expect("SHA256 length")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel_map<K: Pod, V: Pod>() -> HashMap<MapData, K, V> {
        use std::os::fd::{FromRawFd, OwnedFd};
        #[repr(C)]
        struct Create {
            kind: u32,
            key: u32,
            value: u32,
            entries: u32,
            flags: u32,
        }
        let attr = Create {
            kind: 9,
            key: std::mem::size_of::<K>() as u32,
            value: std::mem::size_of::<V>() as u32,
            entries: 4096,
            flags: 0,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                0,
                &attr as *const Create,
                std::mem::size_of::<Create>(),
            )
        };
        assert!(
            fd >= 0,
            "creating isolated LRU map: {}",
            io::Error::last_os_error()
        );
        let data = MapData::from_fd(unsafe { OwnedFd::from_raw_fd(fd as i32) }).unwrap();
        HashMap::try_from(aya::maps::Map::LruHashMap(data)).unwrap()
    }

    fn kernel_store() -> Store {
        Store {
            nat: Arc::new(Mutex::new(kernel_map())),
            firewall: kernel_map(),
            synproxy: kernel_map(),
            endpoints: BTreeMap::new(),
            imported: BTreeMap::new(),
            policy: None,
            local_addresses: BTreeSet::new(),
        }
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_batches_replication_deletion_and_local_ownership() {
        let mut source = kernel_store();
        let mut target = kernel_store();
        let peer: IpAddr = "192.0.2.1".parse().unwrap();
        let now = monotonic_ns();
        for port in 1..=1025 {
            let key = FlowKey::new(7, [10, 0, 0, 1], [198, 51, 100, 1], port, 443, 6);
            let state = FlowState {
                last_seen_ns: now,
                age_ns: 0,
                nat_ip: [192, 0, 2, 100],
                nat2_ip: [0; 4],
                nat_port: port,
                nat2_port: 0,
                flags: 1,
                _pad: 0,
                packets: 12,
                bytes: 1200,
            };
            source.nat.lock().await.insert(key, state, 0).unwrap();
        }
        let mut key =
            FirewallKey::ipv4(FlowKey::new(7, [10, 0, 0, 1], [198, 51, 100, 1], 1, 443, 6));
        key.family = 6;
        key.src = [1; 16];
        key.dst = [2; 16];
        source
            .firewall
            .insert(
                key,
                FirewallState {
                    last_seen_ns: now,
                    age_ns: 0,
                    phase: FirewallState::ESTABLISHED,
                    reply: 1,
                },
                0,
            )
            .unwrap();
        let snapshot = source.snapshot([1; 32], false).await.unwrap();
        assert_eq!(snapshot.entries.len(), 1026);
        target.generation(snapshot.policy);
        let mut seen = HashSet::new();
        for batch in snapshot
            .entries
            .values()
            .copied()
            .collect::<Vec<_>>()
            .chunks(256)
        {
            for record in unpack(&pack(batch, monotonic_ns())).unwrap() {
                seen.insert(record.key());
                target.apply(peer, UPSERT, record).await.unwrap();
            }
        }
        target.finish_snapshot(peer, &seen).await.unwrap();
        assert_eq!(batch_read(&*target.nat.lock().await).unwrap().len(), 1025);
        assert_eq!(
            target.firewall.get(&key, 0).unwrap().phase,
            FirewallState::ESTABLISHED
        );
        // Receiving a record must not echo it or import the sender's counters.
        assert!(
            target
                .snapshot([1; 32], false)
                .await
                .unwrap()
                .entries
                .is_empty()
        );
        let record = *snapshot
            .entries
            .values()
            .find(|r| matches!(r, Record::Nat(_, _)))
            .unwrap();
        let Record::Nat(nat_key, _) = record else {
            unreachable!()
        };
        assert_eq!(target.nat.lock().await.get(&nat_key, 0).unwrap().packets, 0);
        // A real local packet changes the kernel value. A queued peer deletion
        // must not remove that newly active flow or reset its accounting.
        let mut active = target.nat.lock().await.get(&nat_key, 0).unwrap();
        active.packets = 1;
        active.bytes = 64;
        active.last_seen_ns = monotonic_ns();
        target.nat.lock().await.insert(nat_key, active, 0).unwrap();
        target.apply(peer, DELETE, record).await.unwrap();
        target.apply(peer, UPSERT, record).await.unwrap();
        assert_eq!(target.nat.lock().await.get(&nat_key, 0).unwrap(), active);
        assert_eq!(
            target.snapshot([1; 32], false).await.unwrap().entries.len(),
            1
        );
        // Reconnection with an empty full snapshot removes only this peer's
        // unchanged imports, retaining the flow already owned locally.
        target.finish_snapshot(peer, &HashSet::new()).await.unwrap();
        assert_eq!(batch_read(&*target.nat.lock().await).unwrap().len(), 1);
        assert!(batch_read(&target.firewall).unwrap().is_empty());
        let empty = kernel_store();
        assert!(batch_read(&*empty.nat.lock().await).unwrap().is_empty());
    }
    fn syn_record() -> Record {
        let key = FlowKey::new(0, [10, 2, 0, 10], [0; 4], 12345, 8443, 6);
        let mut state = SynFlow::pending(u32::MAX - 3, 42);
        state.splice(9); // The sequence adjustment wraps around u32.
        Record::SynProxy(key, state)
    }

    #[test]
    fn synproxy_wire_preserves_splice_and_rejects_malformed_state() {
        let record = syn_record();
        let wire = record.encode(0);
        assert_eq!(Record::decode(&wire).unwrap(), record);
        assert_eq!(unpack(&pack(&[record], 0)).unwrap(), vec![record]);
        assert!(
            decode_datagram(&wire).is_none(),
            "legacy UDP must not import SYN state"
        );
        for length in 0..wire.len() {
            assert!(Record::decode(&wire[..length]).is_err());
        }
        let mut extra = wire.clone();
        extra.push(0);
        assert!(Record::decode(&extra).is_err());
        for (index, value) in [
            (4, 1),
            (12, 1),
            (16, 0),
            (20, 17),
            (21, 1),
            (36, 2),
            (38, 1),
        ] {
            let mut invalid = wire.clone();
            invalid[index] = value;
            if index == 16 {
                invalid[17] = 0;
            }
            assert!(
                Record::decode(&invalid).is_err(),
                "accepted invalid field at {index}"
            );
        }
        let Record::SynProxy(key, _) = record else {
            unreachable!()
        };
        let pending = Record::SynProxy(key, SynFlow::pending(123, 456));
        assert_eq!(Record::decode(&pending.encode(0)).unwrap(), pending);
        let mut invalid = wire;
        invalid[36..38].copy_from_slice(&0u16.to_le_bytes());
        assert!(
            Record::decode(&invalid).is_err(),
            "pending state cannot carry a splice delta"
        );
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_synproxy_snapshot_splice_deletion_and_local_ownership() {
        let mut source = kernel_store();
        let mut target = kernel_store();
        target.generation([1; 32]);
        let peer = "192.0.2.1".parse().unwrap();
        let Record::SynProxy(key, spliced) = syn_record() else {
            unreachable!()
        };
        let pending = SynFlow::pending(spliced.cookie, spliced.client_isn);
        source.synproxy.insert(key, pending, 0).unwrap();
        for state in [pending, spliced] {
            source.synproxy.insert(key, state, 0).unwrap();
            let snapshot = source.snapshot([1; 32], false).await.unwrap();
            assert_eq!(snapshot.entries.len(), 1);
            let record = snapshot.entries.values().copied().next().unwrap();
            target
                .apply(peer, UPSERT, Record::decode(&record.encode(0)).unwrap())
                .await
                .unwrap();
            assert_eq!(target.synproxy.get(&key, 0).unwrap(), state);
            assert!(
                target
                    .snapshot([1; 32], false)
                    .await
                    .unwrap()
                    .entries
                    .is_empty(),
                "import echoed"
            );
        }
        // An independently completed local splice must survive a queued update
        // or deletion from the peer. Reconciliation keeps the same map FD.
        let mut local = spliced;
        local.splice(200);
        target.synproxy.insert(key, local, 0).unwrap();
        target
            .apply(peer, UPSERT, Record::SynProxy(key, pending))
            .await
            .unwrap();
        target.finish_snapshot(peer, &HashSet::new()).await.unwrap();
        assert_eq!(target.synproxy.get(&key, 0).unwrap(), local);
        assert_eq!(
            target.snapshot([1; 32], false).await.unwrap().entries.len(),
            1
        );
        let mut target = kernel_store();
        target.apply(peer, UPSERT, syn_record()).await.unwrap();
        target.finish_snapshot(peer, &HashSet::new()).await.unwrap();
        assert!(target.synproxy.get(&key, 0).is_err());
    }

    #[test]
    fn wireguard_records_roundtrip_and_reject_noncanonical_endpoints() {
        let mut endpoint = ha::wireguard::Endpoint {
            interface: [0; 16],
            public_key: [3; 32],
            ip: [0; 16],
            port: 51820,
            family: 4,
        };
        endpoint.interface[..3].copy_from_slice(b"wg0");
        endpoint.ip[..4].copy_from_slice(&[192, 0, 2, 1]);
        let record = Record::Wireguard(endpoint);
        let bytes = record.encode(0);
        assert_eq!(Record::decode(&bytes).unwrap(), record);
        assert_eq!(unpack(&pack(&[record], 0)).unwrap(), vec![record]);
        for n in 0..bytes.len() {
            assert!(Record::decode(&bytes[..n]).is_err());
        }
        let mut invalid = bytes;
        invalid[70] = 7;
        assert!(Record::decode(&invalid).is_err());
        endpoint.interface = [b'a'; 16];
        assert!(endpoint.validate().is_err());
    }
    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_ha_successor_replaces_former_master_locals_without_resetting_counters() {
        let peer = "10.0.0.2".parse().unwrap();
        let mut store = kernel_store();
        let key = FlowKey::new(0, [10, 0, 0, 1], [198, 51, 100, 1], 12345, 443, 6);
        let old = FlowState {
            packets: 31,
            bytes: 991,
            ..FlowState::forward([192, 0, 2, 1], 0)
        };
        store.nat.lock().await.insert(key, old, 0).unwrap();
        let mut successor = old;
        successor.nat_ip = [192, 0, 2, 254];
        successor.packets = 999;
        successor.bytes = 9999;
        let record = Record::Nat(key, successor);
        let mut records = Entries::new();
        records.insert(record.key(), record);
        let fw_key = FirewallKey::ipv4(key);
        let old_fw = FirewallState {
            last_seen_ns: monotonic_ns(),
            age_ns: 0,
            phase: FirewallState::ESTABLISHED,
            reply: 1,
        };
        store.firewall.insert(fw_key, old_fw, 0).unwrap();
        let successor_fw = FirewallState {
            phase: FirewallState::CLOSING,
            ..old_fw
        };
        let fw_record = Record::Firewall(fw_key, successor_fw);
        records.insert(fw_record.key(), fw_record);
        let Record::SynProxy(syn_key, successor_syn) = syn_record() else {
            unreachable!()
        };
        store
            .synproxy
            .insert(syn_key, SynFlow::pending(123, 456), 0)
            .unwrap();
        let syn_record = Record::SynProxy(syn_key, successor_syn);
        records.insert(syn_record.key(), syn_record);
        store.replace_ha(peer, records).await.unwrap();
        let imported = store.nat.lock().await.get(&key, 0).unwrap();
        assert_eq!(imported.nat_ip, [192, 0, 2, 254]);
        assert_eq!(imported.packets, 31);
        assert_eq!(imported.bytes, 991);
        assert_eq!(
            store.firewall.get(&fw_key, 0).unwrap().phase,
            FirewallState::CLOSING
        );
        assert_eq!(store.synproxy.get(&syn_key, 0).unwrap(), successor_syn);
        store.replace_ha(peer, Entries::new()).await.unwrap();
        assert!(store.nat.lock().await.get(&key, 0).is_err());
        assert!(store.firewall.get(&fw_key, 0).is_err());
        assert!(store.synproxy.get(&syn_key, 0).is_err());
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_snapshot_keeps_flows_refreshed_during_batch_dumps() {
        use std::sync::atomic::{AtomicBool, Ordering};
        fn duplicate<K: Pod, V: Pod>(map: &HashMap<MapData, K, V>) -> HashMap<MapData, K, V> {
            let data =
                MapData::from_fd(map.map().fd().as_fd().try_clone_to_owned().unwrap()).unwrap();
            HashMap::try_from(aya::maps::Map::LruHashMap(data)).unwrap()
        }
        struct Writer(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
        impl Drop for Writer {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
                self.1.take().unwrap().join().unwrap();
            }
        }
        let mut store = kernel_store();
        let keys: Vec<_> = (1..=1025)
            .map(|port| FlowKey::new(7, [10, 0, 0, 1], [198, 51, 100, 1], port, 443, 6))
            .collect();
        let mut nat = duplicate(&*store.nat.lock().await);
        let mut firewall = duplicate(&store.firewall);
        fn refresh(
            nat: &mut HashMap<MapData, FlowKey, FlowState>,
            firewall: &mut HashMap<MapData, FirewallKey, FirewallState>,
            keys: &[FlowKey],
        ) {
            for key in keys {
                nat.insert(
                    key,
                    FlowState {
                        last_seen_ns: monotonic_ns(),
                        age_ns: 0,
                        nat_ip: [192, 0, 2, 100],
                        nat2_ip: [0; 4],
                        nat_port: 47000,
                        nat2_port: 0,
                        flags: 0,
                        _pad: 0,
                        packets: 1,
                        bytes: 64,
                    },
                    0,
                )
                .unwrap();
                firewall
                    .insert(
                        FirewallKey::ipv4(*key),
                        FirewallState {
                            last_seen_ns: monotonic_ns(),
                            age_ns: 0,
                            phase: FirewallState::ESTABLISHED,
                            reply: 0,
                        },
                        0,
                    )
                    .unwrap();
            }
        }
        refresh(&mut nat, &mut firewall, &keys);
        let stop = Arc::new(AtomicBool::new(false));
        let signal = stop.clone();
        let writer = std::thread::spawn(move || {
            while !signal.load(Ordering::Relaxed) {
                refresh(&mut nat, &mut firewall, &keys);
            }
        });
        let _writer = Writer(stop, Some(writer));
        for _ in 0..32 {
            let snapshot = store.snapshot([8; 32], true).await.unwrap();
            assert_eq!(
                snapshot.entries.len(),
                2050,
                "concurrently refreshed live entries must never become deletion tombstones"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_ha_owner_reexports_unchanged_imported_splices_in_every_snapshot() {
        let mut store = kernel_store();
        let peer = "10.3.0.2".parse().unwrap();
        let record = syn_record();
        let policy = [8; 32];
        let mut entries = Entries::new();
        entries.insert(record.key(), record);
        store.generation(policy);
        store.replace_ha(peer, entries).await.unwrap();
        assert!(
            store
                .snapshot(policy, false)
                .await
                .unwrap()
                .entries
                .is_empty(),
            "standalone mesh suppresses unchanged imports"
        );
        for _ in 0..3 {
            assert_eq!(
                store
                    .snapshot(policy, true)
                    .await
                    .unwrap()
                    .entries
                    .get(&record.key()),
                Some(&record),
                "an HA owner's complete baseline must retain an unchanged imported splice"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_ha_preserves_node_local_control_connections_while_replacing_data() {
        let mut source = kernel_store();
        let mut target = kernel_store();
        let peer = "10.3.0.1".parse().unwrap();
        source.local_addresses.insert(peer);
        target.local_addresses.insert("10.3.0.2".parse().unwrap());
        target.local_addresses.insert("fd42:3::2".parse().unwrap());
        let state = FirewallState {
            last_seen_ns: monotonic_ns(),
            age_ns: 0,
            phase: FirewallState::ESTABLISHED,
            reply: 1,
        };
        let source_control =
            FirewallKey::ipv4(FlowKey::new(3, [10, 3, 0, 1], [10, 3, 0, 3], 4000, 5440, 6));
        let target_control =
            FirewallKey::ipv4(FlowKey::new(3, [10, 3, 0, 2], [10, 3, 0, 3], 4001, 5440, 6));
        let target6 = FirewallKey {
            src: "fd42:3::2".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            dst: "fd42:3::3".parse::<std::net::Ipv6Addr>().unwrap().octets(),
            family: 6,
            ..target_control
        };
        let data = FirewallKey::ipv4(FlowKey::new(
            7,
            [10, 2, 0, 10],
            [10, 1, 0, 10],
            12345,
            8443,
            6,
        ));
        source.firewall.insert(source_control, state, 0).unwrap();
        source.firewall.insert(data, state, 0).unwrap();
        target.firewall.insert(target_control, state, 0).unwrap();
        target.firewall.insert(target6, state, 0).unwrap();
        let snapshot = source.snapshot([8; 32], false).await.unwrap();
        assert!(
            !snapshot
                .entries
                .contains_key(&Record::Firewall(source_control, state).key())
        );
        assert!(
            snapshot
                .entries
                .contains_key(&Record::Firewall(data, state).key())
        );
        target.replace_ha(peer, snapshot.entries).await.unwrap();
        assert!(target.firewall.get(&data, 0).is_ok());
        assert_eq!(target.firewall.get(&target_control, 0).unwrap(), state);
        assert_eq!(target.firewall.get(&target6, 0).unwrap(), state);
        let closing = Record::Firewall(
            target_control,
            FirewallState {
                phase: FirewallState::CLOSING,
                ..state
            },
        );
        target
            .apply_inner(peer, UPSERT, closing, true)
            .await
            .unwrap();
        target
            .apply_inner(peer, DELETE, closing, true)
            .await
            .unwrap();
        assert_eq!(target.firewall.get(&target_control, 0).unwrap(), state);
        target.replace_ha(peer, Entries::new()).await.unwrap();
        assert!(target.firewall.get(&data, 0).is_err());
        assert_eq!(target.firewall.get(&target_control, 0).unwrap(), state);
        assert_eq!(target.firewall.get(&target6, 0).unwrap(), state);
        assert!(
            target
                .snapshot([8; 32], false)
                .await
                .unwrap()
                .entries
                .is_empty()
        );
    }

    fn session() -> Session {
        Session {
            key: hmac::Key::new(hmac::HMAC_SHA256, b"test-only session key"),
            sequence: 0,
        }
    }

    #[tokio::test]
    #[ignore = "requires CAP_BPF/CAP_SYS_ADMIN; runs in the HA kernel VM"]
    async fn kernel_authenticated_transport_applies_deltas_and_fences_policy_changes() {
        let initial = RuntimeConfig::passthrough();
        let mut fw =
            Firewall::load_and_attach(&[], crate::firewall::AttachMode::Skb, &initial, false)
                .unwrap();
        let nat = fw.conntrack_handle().unwrap();
        let flows = fw.fw_flows_handle().unwrap();
        let synproxy = fw.syn_flows_handle().unwrap();
        let policy = fw.sync_policy().unwrap();
        let fw = Arc::new(Mutex::new(fw));
        let store = Arc::new(Mutex::new(Store {
            nat: nat.clone(),
            firewall: flows,
            synproxy,
            endpoints: BTreeMap::new(),
            imported: BTreeMap::new(),
            policy: None,
            local_addresses: BTreeSet::new(),
        }));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let secret = Arc::new("kernel test secret with sufficient entropy".to_string());
        let receiver = {
            let secret = secret.clone();
            let fw = fw.clone();
            let store = store.clone();
            tokio::spawn(async move {
                let (stream, peer) = listener.accept().await.unwrap();
                receive(
                    stream,
                    peer.ip(),
                    secret,
                    Receiver {
                        firewall: fw,
                        store,
                        ha: ha::State::new(None).unwrap(),
                        generation: Arc::new(AtomicU64::new(0)),
                        idle_timeout: IO_TIMEOUT,
                    },
                )
                .await
            })
        };
        let now = monotonic_ns();
        let key = FlowKey::new(0, [10, 0, 0, 1], [198, 51, 100, 1], 12345, 443, 6);
        let state = FlowState {
            last_seen_ns: now,
            age_ns: 0,
            nat_ip: [192, 0, 2, 100],
            nat2_ip: [0; 4],
            nat_port: 12345,
            nat2_port: 0,
            flags: 1,
            _pad: 0,
            packets: 100,
            bytes: 10000,
        };
        let record = Record::Nat(key, state);
        let splice = syn_record();
        let Record::SynProxy(syn_key, syn_state) = splice else {
            unreachable!()
        };
        let (snapshots, watcher) = watch::channel(Some(Arc::new(Snapshot {
            authority: None,
            policy,
            entries: BTreeMap::from([(record.key(), record), (splice.key(), splice)]),
        })));
        let sender = tokio::spawn(push(
            TcpStream::connect(address).await.unwrap(),
            secret,
            watcher,
        ));
        timeout(IO_TIMEOUT, async {
            while nat.lock().await.get(&key, 0).is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            nat.lock().await.get(&key, 0).unwrap().nat_ip,
            [192, 0, 2, 100]
        );
        assert_eq!(nat.lock().await.get(&key, 0).unwrap().packets, 0);
        timeout(IO_TIMEOUT, async {
            while store.lock().await.synproxy.get(&syn_key, 0).is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            store.lock().await.synproxy.get(&syn_key, 0).unwrap(),
            syn_state
        );
        snapshots.send_replace(Some(Arc::new(Snapshot {
            authority: None,
            policy,
            entries: Entries::new(),
        })));
        timeout(IO_TIMEOUT, async {
            while nat.lock().await.get(&key, 0).is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        timeout(IO_TIMEOUT, async {
            while store.lock().await.synproxy.get(&syn_key, 0).is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        let mut changed = initial.clone();
        changed.policies[0].global.flags ^= velstra_common::ConfigFlags::STATEFUL;
        fw.lock().await.reconfigure(&changed).unwrap();
        snapshots.send_replace(Some(Arc::new(Snapshot {
            authority: None,
            policy,
            entries: BTreeMap::from([(record.key(), record), (splice.key(), splice)]),
        })));
        let error = timeout(IO_TIMEOUT, receiver)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("policy differs"), "{error:#}");
        assert!(nat.lock().await.get(&key, 0).is_err());
        assert!(store.lock().await.synproxy.get(&syn_key, 0).is_err());
        sender.abort();
    }
    #[test]
    fn authenticated_frames_reject_tampering_replay_and_other_sessions() {
        let frame = session().frame([42; 32], HEARTBEAT, &[]).unwrap();
        let mut receiver = session();
        assert!(receiver.verify(&frame).is_ok());
        assert!(receiver.verify(&frame).is_err());
        for index in 0..frame.len() {
            let mut damaged = frame.clone();
            damaged[index] ^= 1;
            assert!(session().verify(&damaged).is_err());
        }
        let mut wrong = Session {
            key: hmac::Key::new(hmac::HMAC_SHA256, b"another session"),
            sequence: 0,
        };
        assert!(wrong.verify(&frame).is_err());
    }
    #[test]
    fn mutual_challenges_are_not_reflectable_or_replayable() {
        let client = [1; 32];
        let server = [2; 32];
        let secret = b"correct test secret";
        let tag = proof(secret, b"server", &client, &server);
        assert!(verify_proof(secret, b"server", &client, &server, &tag).is_ok());
        assert!(verify_proof(secret, b"client", &client, &server, &tag).is_err());
        assert!(verify_proof(secret, b"server", &client, &[3; 32], &tag).is_err());
        assert!(verify_proof(b"wrong", b"server", &client, &server, &tag).is_err());
    }
    #[test]
    fn policy_fingerprint_fences_changed_filtering_without_node_local_routes() {
        let first = RuntimeConfig::passthrough();
        let mut second = first.clone();
        assert_eq!(policy_fingerprint(&first), policy_fingerprint(&second));
        second.policies[0].global.flags ^= velstra_common::ConfigFlags::STATEFUL;
        assert_ne!(policy_fingerprint(&first), policy_fingerprint(&second));
        second = first.clone();
        second.conntrack.tcp_established = 30;
        assert_ne!(policy_fingerprint(&first), policy_fingerprint(&second));
    }
    #[tokio::test]
    async fn tcp_handshake_and_frame_roundtrip_use_fresh_sessions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let key = handshake(&mut stream, b"test secret", false).await.unwrap();
            let mut session = Session { key, sequence: 0 };
            let bytes = read_frame(&mut stream).await.unwrap();
            let (policy, kind, payload) = session.verify(&bytes).unwrap();
            assert_eq!(policy, [7; 32]);
            assert_eq!(kind, HEARTBEAT);
            assert!(payload.is_empty());
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        let key = handshake(&mut stream, b"test secret", true).await.unwrap();
        write_frame(
            &mut stream,
            &mut Session { key, sequence: 0 },
            [7; 32],
            HEARTBEAT,
            &[],
        )
        .await
        .unwrap();
        server.await.unwrap();
    }
}
