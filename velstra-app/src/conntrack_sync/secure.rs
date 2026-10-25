//! VCS2: mutually authenticated, ordered state replication. Fresh challenges
//! bind each connection to a session; sequence numbers and HMAC authenticate
//! every bounded frame. This provides authenticity, not confidentiality: use a
//! dedicated HA link or WireGuard when flow metadata must be encrypted.
//!
//! One producer reads both LRU maps in kernel batches. Each peer gets an initial
//! snapshot followed by changes and deletions. Imported entries are not echoed;
//! once a local packet changes one, the local dataplane owns it. All application
//! is fenced by the firewall's configuration lock and policy fingerprint.

use std::{
    collections::{BTreeMap, HashSet},
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
use velstra_common::{FirewallKey, FirewallState, FlowKey, FlowState};
use velstra_config::{ResolvedConntrackSync, RuntimeConfig};

use super::{
    Datagram, decode_datagram, encode_firewall_batch, encode_key, encode_nat_batch, monotonic_ns,
};
use crate::firewall::Firewall;

const IO_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_FRAME: usize = 32_768;
const MAX_ENTRIES: usize = 131_072;
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
}

impl Record {
    fn key(self) -> Key {
        match self {
            Self::Nat(key, _) => {
                let mut out = vec![3];
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
    imported: BTreeMap<Key, Imported>,
    policy: Option<[u8; 32]>,
}

impl Store {
    fn generation(&mut self, policy: [u8; 32]) {
        if self.policy != Some(policy) {
            self.imported.clear();
            self.policy = Some(policy);
        }
    }
    async fn snapshot(&mut self, policy: [u8; 32]) -> Result<Snapshot> {
        self.generation(policy);
        let nat = self.nat.lock().await;
        let mut entries = Entries::new();
        let now = monotonic_ns();
        for (key, state) in batch_read(&*nat)? {
            if state.idle_ns(now) <= 604_800_000_000_000 {
                let record = Record::Nat(key, state);
                entries.insert(record.key(), record);
            }
        }
        for (key, state) in batch_read(&self.firewall)? {
            if state.idle_ns(now) <= 604_800_000_000_000 {
                let record = Record::Firewall(key, state);
                entries.insert(record.key(), record);
            }
        }
        self.imported
            .retain(|key, imported| entries.get(key) == Some(&imported.record));
        entries.retain(|key, _| !self.imported.contains_key(key));
        Ok(Snapshot { policy, entries })
    }
    async fn apply(&mut self, peer: IpAddr, kind: u8, record: Record) -> Result<()> {
        let key = record.key();
        let mut nat = self.nat.lock().await;
        let local = match record {
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
        if local.is_some() && !ours {
            return Ok(());
        }
        if kind == DELETE {
            if ours {
                match record {
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
            let record = record.received(monotonic_ns());
            match record {
                Record::Nat(k, v) => nat.insert(k, v, 0)?,
                Record::Firewall(k, v) => self.firewall.insert(k, v, 0)?,
            }
            self.imported.insert(key, Imported { peer, record });
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
            length <= 68 && bytes.len() >= 2 + length,
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
                .is_none_or(|old| old.policy != next.policy)
            {
                write_frame(&mut stream, &mut session, next.policy, BEGIN, &[]).await?;
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

async fn receive(
    mut stream: TcpStream,
    peer: IpAddr,
    secret: Arc<String>,
    firewall: Arc<Mutex<Firewall>>,
    store: Arc<Mutex<Store>>,
    generation: Arc<AtomicU64>,
    idle_timeout: Duration,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let key = timeout(IO_TIMEOUT, handshake(&mut stream, secret.as_bytes(), false)).await??;
    // A reconnect supersedes the previous authenticated stream. Its queued
    // frames cannot roll the new snapshot back, even if both sockets survive.
    let ticket = generation.fetch_add(1, Ordering::SeqCst).wrapping_add(1);
    let mut session = Session { key, sequence: 0 };
    let mut seen: Option<HashSet<Key>> = None;
    let mut initialized = false;
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
        let mut store = store.lock().await;
        store.generation(policy);
        match kind {
            BEGIN => {
                ensure!(
                    payload.is_empty() && seen.is_none(),
                    "invalid snapshot start"
                );
                seen = Some(HashSet::new());
                initialized = true;
            }
            UPSERT | DELETE => {
                for record in unpack(payload)? {
                    if let Some(seen) = &mut seen {
                        ensure!(kind == UPSERT, "deletion inside snapshot");
                        seen.insert(record.key());
                        ensure!(seen.len() <= MAX_ENTRIES, "oversized peer snapshot");
                    }
                    store.apply(peer, kind, record).await?;
                }
            }
            END => {
                ensure!(payload.is_empty(), "invalid snapshot end");
                store
                    .finish_snapshot(peer, &seen.take().context("snapshot end without start")?)
                    .await?;
            }
            HEARTBEAT => ensure!(payload.is_empty() && seen.is_none(), "incomplete snapshot"),
            _ => bail!("unknown state frame operation"),
        }
    }
}

pub async fn run(
    firewall: Arc<Mutex<Firewall>>,
    nat: NatMap,
    flows: HashMap<MapData, FirewallKey, FirewallState>,
    config: ResolvedConntrackSync,
) {
    let secret = Arc::new(
        config
            .secret
            .clone()
            .expect("authenticated sync configuration"),
    );
    let store = Arc::new(Mutex::new(Store {
        nat,
        firewall: flows,
        imported: BTreeMap::new(),
        policy: None,
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
                    let secret = secret.clone(); let firewall = firewall.clone(); let store = store.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Err(error) = receive(stream, remote.ip(), secret, firewall, store, generation, idle_timeout).await { log::debug!("conntrack-sync: rejected/closed session from {remote}: {error:#}"); }
                    });
                }
                _ = ticker.tick() => {
                    let fw = firewall.lock().await;
                    let result = match fw.sync_policy() { Ok(policy) => store.lock().await.snapshot(policy).await, Err(error) => Err(error) };
                    match result {
                        Ok(snapshot) => { snapshots.send_replace(Some(Arc::new(snapshot))); }
                        Err(error) => { snapshots.send_replace(None); log::debug!("conntrack-sync: snapshot unavailable: {error:#}"); }
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
    let bytes = json!({"version":2,"policies":policies,"interfaces":interfaces,"forwards":forwards,"services":services,
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
            imported: BTreeMap::new(),
            policy: None,
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
        let snapshot = source.snapshot([1; 32]).await.unwrap();
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
        assert!(target.snapshot([1; 32]).await.unwrap().entries.is_empty());
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
        assert_eq!(target.snapshot([1; 32]).await.unwrap().entries.len(), 1);
        // Reconnection with an empty full snapshot removes only this peer's
        // unchanged imports, retaining the flow already owned locally.
        target.finish_snapshot(peer, &HashSet::new()).await.unwrap();
        assert_eq!(batch_read(&*target.nat.lock().await).unwrap().len(), 1);
        assert!(batch_read(&target.firewall).unwrap().is_empty());
        let empty = kernel_store();
        assert!(batch_read(&*empty.nat.lock().await).unwrap().is_empty());
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
        let policy = fw.sync_policy().unwrap();
        let fw = Arc::new(Mutex::new(fw));
        let store = Arc::new(Mutex::new(Store {
            nat: nat.clone(),
            firewall: flows,
            imported: BTreeMap::new(),
            policy: None,
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
                    fw,
                    store,
                    Arc::new(AtomicU64::new(0)),
                    IO_TIMEOUT,
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
        let (snapshots, watcher) = watch::channel(Some(Arc::new(Snapshot {
            policy,
            entries: BTreeMap::from([(record.key(), record)]),
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
        snapshots.send_replace(Some(Arc::new(Snapshot {
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
        let mut changed = initial.clone();
        changed.policies[0].global.flags ^= velstra_common::ConfigFlags::STATEFUL;
        fw.lock().await.reconfigure(&changed).unwrap();
        snapshots.send_replace(Some(Arc::new(Snapshot {
            policy,
            entries: BTreeMap::from([(record.key(), record)]),
        })));
        let error = timeout(IO_TIMEOUT, receiver)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("policy differs"), "{error:#}");
        assert!(nat.lock().await.get(&key, 0).is_err());
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
