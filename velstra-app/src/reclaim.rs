//! Background reclamation of expired connection state (DP-07, DP-41).
//!
//! The datapath treats an expired entry as absent but never deletes it, so
//! without a collector the LRU tables sit full of dead connections and the
//! LRU — not the timeouts — decides which live ones die: an idle SSH session
//! was evicted after ~16,000 unrelated new connections. The only remedy was a
//! manual `expire-state`, which closed the datapath gate for up to 250 ms and
//! left it closed when it failed.
//!
//! This collector walks `FW_FLOWS` and `CONNTRACK` continuously, a bounded
//! slice per tick, and deletes entries that are expired by the applied
//! timeouts. It **never touches the gate**: deleting an entry the datapath
//! already ignores changes no verdict. Each candidate is re-read immediately
//! before its delete, so an entry refreshed since the walk is kept; what
//! remains is a window of microseconds in which a brand-new connection reusing
//! an expired tuple could lose its first entry, costing it one retransmission.
//!
//! The same walk counts every table's occupancy, which is what `capacity`
//! reports and what raises the high-water warning (DP-06). `SYN_FLOWS` holds
//! no timestamp; the splice sweep the firewall and NAT walks drive ends its
//! records ([`SpliceSweep`]), counted as its observation's reclaimed entries.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    io,
    os::fd::{AsFd, AsRawFd},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use aya::{
    Pod,
    maps::{HashMap, MapData},
};
use log::{info, warn};
use serde::Serialize;
use tokio::sync::Mutex;
use velstra_common::{ConntrackTimeouts, FirewallKey, FirewallState, FlowKey, FlowState, SynFlow};

use crate::{conntrack_sync::secure::ImportedSplices, firewall::Firewall, state_tables};

/// How often the collector runs.
const TICK: Duration = Duration::from_secs(1);
/// Entries examined per table per tick. At this rate a 2-million-entry table is
/// walked in about half a minute; a small one many times a second's worth.
const SLICE: usize = 65_536;
/// Entries read per kernel batch call.
const BATCH: usize = 4096;
/// An occupancy older than this is reported as unknown.
const STALE_AFTER: Duration = Duration::from_secs(120);

/// One table's latest observation.
#[derive(Debug, Clone, Serialize)]
pub struct TableObservation {
    pub name: &'static str,
    pub max_entries: u32,
    /// Entries seen in the last complete walk, expired ones included until
    /// they are reclaimed. `None` until one walk has completed.
    pub observed_entries: Option<u64>,
    /// Entries deleted since the agent started: expired ones, and for
    /// SYN_FLOWS the splices the splice sweep ended.
    pub reclaimed_expired: u64,
    /// Complete walks since the agent started.
    pub passes: u64,
    #[serde(skip)]
    pub completed_at: Option<Instant>,
    pub last_error: Option<String>,
}

impl TableObservation {
    fn new(name: &'static str, max_entries: u32) -> Self {
        Self {
            name,
            max_entries,
            observed_entries: None,
            reclaimed_expired: 0,
            passes: 0,
            completed_at: None,
            last_error: None,
        }
    }
}

fn observations() -> &'static std::sync::Mutex<Vec<TableObservation>> {
    static OBSERVED: OnceLock<std::sync::Mutex<Vec<TableObservation>>> = OnceLock::new();
    OBSERVED.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// The latest observation of every table, and how old each is.
pub fn snapshot() -> Vec<(TableObservation, Option<Duration>)> {
    let now = Instant::now();
    observations()
        .lock()
        .map(|tables| {
            tables
                .iter()
                .map(|t| {
                    let age = t.completed_at.map(|at| now.saturating_duration_since(at));
                    (t.clone(), age)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether an observation of `age` is too old to report.
pub fn is_stale(age: Option<Duration>) -> bool {
    age.is_none_or(|age| age > STALE_AFTER)
}

/// One state map, opened twice: raw for the batch walk, typed for the
/// re-read and delete of each candidate.
struct Handle<K: Pod, V: Pod> {
    raw: MapData,
    typed: HashMap<MapData, K, V>,
}

impl<K: Pod, V: Pod> Handle<K, V> {
    fn open(map: MapData) -> Result<Self> {
        let duplicate = MapData::from_fd(map.fd().as_fd().try_clone_to_owned()?)?;
        Ok(Self {
            raw: map,
            typed: HashMap::try_from(aya::maps::Map::LruHashMap(duplicate))
                .context("opening a state map")?,
        })
    }
}

/// What one table holds, and how to tell whether an entry has expired.
enum Contents {
    Firewall(Handle<FirewallKey, FirewallState>),
    Nat(Handle<FlowKey, FlowState>),
    /// No timestamp: counted here; the splice sweep ends its records.
    Syn(Handle<FlowKey, SynFlow>),
}

/// One table's walk: where it is, and what this pass has counted so far.
pub struct Table {
    contents: Contents,
    cursor: Option<u32>,
    counted: u64,
    observation: TableObservation,
    above_high_water: bool,
}

impl Table {
    pub fn firewall(map: MapData, max: u32) -> Result<Self> {
        Ok(Self::new(
            Contents::Firewall(Handle::open(map)?),
            "FW_FLOWS",
            max,
        ))
    }

    pub fn nat(map: MapData, max: u32) -> Result<Self> {
        Ok(Self::new(
            Contents::Nat(Handle::open(map)?),
            "CONNTRACK",
            max,
        ))
    }

    pub fn syn(map: MapData, max: u32) -> Result<Self> {
        Ok(Self::new(
            Contents::Syn(Handle::open(map)?),
            "SYN_FLOWS",
            max,
        ))
    }

    fn new(contents: Contents, name: &'static str, max: u32) -> Self {
        Self {
            contents,
            cursor: None,
            counted: 0,
            observation: TableObservation::new(name, max),
            above_high_water: false,
        }
    }

    /// Walk up to `slice` entries from where the last call stopped, deleting
    /// expired ones. Returns the number deleted.
    pub fn step(&mut self, timeouts: ConntrackTimeouts, slice: usize) -> Result<usize> {
        Ok(self.step_claiming(timeouts, slice, None)?.deleted)
    }

    /// [`Self::step`], also adding to `claims` the splice every live entry of
    /// a firewall or NAT walk claims (see [`SpliceSweep`]).
    fn step_claiming(
        &mut self,
        timeouts: ConntrackTimeouts,
        slice: usize,
        mut claims: Option<Claims<'_>>,
    ) -> Result<Stepped> {
        let began = self.cursor.is_none();
        let mut examined = 0;
        let mut reclaimed = 0;
        let mut completed = false;
        while examined < slice {
            let (seen, deleted, done) = match &mut self.contents {
                Contents::Firewall(map) => walk_batch(
                    map,
                    &mut self.cursor,
                    |k: &FirewallKey, v: &FirewallState, now| v.expired(k.proto, now, timeouts),
                    |k, v, expired| {
                        if let (false, Some(claims)) = (expired, claims.as_mut()) {
                            claims.claim(velstra_common::firewall_claim(k, v));
                        }
                    },
                )?,
                Contents::Nat(map) => walk_batch(
                    map,
                    &mut self.cursor,
                    |k: &FlowKey, v: &FlowState, now| v.expired(k.proto, now, timeouts),
                    |k, v, expired| {
                        if let (false, Some(claims)) = (expired, claims.as_mut()) {
                            claims.claim(velstra_common::nat_claim(k, v));
                        }
                    },
                )?,
                Contents::Syn(map) => walk_batch(
                    map,
                    &mut self.cursor,
                    |_, _: &SynFlow, _| false,
                    |_, _, _| {},
                )?,
            };
            examined += seen;
            reclaimed += deleted;
            self.counted += seen as u64;
            if done {
                self.finish_pass();
                completed = true;
                break;
            }
        }
        self.observation.reclaimed_expired += reclaimed as u64;
        Ok(Stepped {
            deleted: reclaimed,
            began,
            completed,
        })
    }

    fn kind(&self) -> Kind {
        match self.contents {
            Contents::Firewall(_) => Kind::Firewall,
            Contents::Nat(_) => Kind::Nat,
            Contents::Syn(_) => Kind::Syn,
        }
    }

    fn finish_pass(&mut self) {
        let observed = self.counted;
        self.counted = 0;
        self.cursor = None;
        self.observation.observed_entries = Some(observed);
        self.observation.passes += 1;
        self.observation.completed_at = Some(Instant::now());
        self.observation.last_error = None;
        let max = u64::from(self.observation.max_entries);
        let above = state_tables::past_high_water(observed, max);
        if above && !self.above_high_water {
            warn!(
                "{} is {}% full ({observed} of {max} entries): connections beyond its capacity \
                 evict the oldest established ones; raise [state] connections or reduce load",
                self.observation.name,
                observed * 100 / max.max(1)
            );
        } else if !above && self.above_high_water {
            info!(
                "{} is below {}% again ({observed} of {max} entries)",
                self.observation.name,
                state_tables::HIGH_WATER_PERCENT
            );
        }
        self.above_high_water = above;
    }

    fn fail(&mut self, error: &anyhow::Error) {
        // Start over next tick: a cursor from a failed walk proves nothing.
        self.cursor = None;
        self.counted = 0;
        self.observation.last_error = Some(format!("{error:#}"));
    }
}

/// What one [`Table::step_claiming`] did.
struct Stepped {
    deleted: usize,
    /// The step started a new walk of the table.
    began: bool,
    /// The step finished a walk.
    completed: bool,
}

/// Read one batch from `cursor`, delete the expired entries in it, and move the
/// cursor on; `each` sees every entry read with its expiry verdict. Returns
/// `(entries seen, entries deleted, walk complete)`.
fn walk_batch<K: Pod, V: Pod>(
    map: &mut Handle<K, V>,
    cursor: &mut Option<u32>,
    expired: impl Fn(&K, &V, u64) -> bool,
    mut each: impl FnMut(&K, &V, bool),
) -> Result<(usize, usize, bool)> {
    let batch = lookup_batch::<K, V>(&map.raw, *cursor, BATCH)?;
    let now = monotonic_ns()?;
    for (k, v) in &batch.entries {
        each(k, v, expired(k, v, now));
    }
    let candidates: Vec<K> = batch
        .entries
        .iter()
        .filter(|(k, v)| expired(k, v, now))
        .map(|(k, _)| *k)
        .collect();
    let mut deleted = 0;
    for key in candidates {
        // Re-read at the last moment: an entry refreshed since the batch was
        // read is live, and its fresh timestamp says so.
        let Ok(value) = map.typed.get(&key, 0) else {
            continue;
        };
        if expired(&key, &value, monotonic_ns()?) && map.typed.remove(&key).is_ok() {
            deleted += 1;
        }
    }
    *cursor = batch.next;
    Ok((batch.entries.len(), deleted, batch.next.is_none()))
}

struct Batch<K, V> {
    entries: Vec<(K, V)>,
    /// Where the next batch starts; `None` once the walk reached the end.
    next: Option<u32>,
}

/// Linux UAPI `BPF_MAP_LOOKUP_BATCH` (command 24) on a hash-type map. The
/// batch token is the kernel's bucket index, so a walk can resume from it on
/// the next tick even though the map changed in between.
fn lookup_batch<K: Pod, V: Pod>(
    map: &MapData,
    cursor: Option<u32>,
    count: usize,
) -> Result<Batch<K, V>> {
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
    let mut count = count;
    loop {
        // SAFETY: K and V are `Pod`: any bit pattern, including all zeroes, is
        // a valid value, and the kernel writes at most `count` of each.
        let mut keys: Vec<K> = vec![unsafe { std::mem::zeroed() }; count];
        let mut values: Vec<V> = vec![unsafe { std::mem::zeroed() }; count];
        let input = cursor.unwrap_or(0);
        let mut output = 0u32;
        let mut attr = Attr {
            in_batch: if cursor.is_some() {
                &input as *const u32 as u64
            } else {
                0
            },
            out_batch: &mut output as *mut u32 as u64,
            keys: keys.as_mut_ptr() as u64,
            values: values.as_mut_ptr() as u64,
            count: count as u32,
            map_fd: map.fd().as_fd().as_raw_fd() as u32,
            elem_flags: 0,
            flags: 0,
        };
        // SAFETY: every pointer in `attr` refers to a live, writable buffer of
        // the size the kernel is told, for the duration of the call.
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
            // One bucket holds more than `count` entries.
            ensure!(count < 1 << 20, "a state-map bucket is implausibly large");
            count *= 2;
            continue;
        }
        let end = rc < 0;
        if end && error.raw_os_error() != Some(libc::ENOENT) {
            return Err(error).context("reading connection state in a batch");
        }
        let returned = attr.count as usize;
        ensure!(returned <= count, "kernel returned an oversized batch");
        keys.truncate(returned);
        values.truncate(returned);
        return Ok(Batch {
            entries: keys.into_iter().zip(values).collect(),
            next: (!end).then_some(output),
        });
    }
}

fn monotonic_ns() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is writable; CLOCK_MONOTONIC is the clock
    // `bpf_ktime_get_ns` reads, so timestamps compare directly.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } == 0,
        "reading monotonic clock: {}",
        io::Error::last_os_error()
    );
    Ok(value.tv_sec as u64 * 1_000_000_000 + value.tv_nsec as u64)
}

/// How far one claiming table is into the current sweep round.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Round {
    /// Its walk under way began before the round: its claims do not cover
    /// the whole table for this round.
    #[default]
    Waiting,
    /// A walk that began inside the round is under way.
    Walking,
    /// A walk that began inside the round has finished.
    Covered,
}

impl Round {
    fn advance(self, stepped: &Stepped) -> Self {
        let walking = match self {
            Self::Waiting if stepped.began => Self::Walking,
            other => other,
        };
        if walking == Self::Walking && stepped.completed {
            Self::Covered
        } else {
            walking
        }
    }
}

/// Which map a [`Table`] walks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Firewall,
    Nat,
    Syn,
}

impl Kind {
    /// Whether this table's live entries claim splices.
    fn claims(self) -> bool {
        matches!(self, Self::Firewall | Self::Nat)
    }
}

/// While the sweep runs, a walk of a claiming table takes at most this many
/// ticks: the per-tick slice grows with the table ([`table_slice`]). A sweep
/// round needs a walk of FW_FLOWS and of CONNTRACK that began inside it, so it
/// lasts at most twice this many ticks however large the box is sized
/// (`state_tables::SYN_ENTRIES_PER_CONNECTION` depends on it).
pub const PASS_TICKS: usize = 5;

/// The entries one tick walks in a table: the base `slice`, and while the
/// sweep runs enough of a claiming table that its walk takes at most
/// [`PASS_TICKS`] ticks. Plain expiry is content with the base slice.
fn table_slice(base: usize, kind: Kind, max_entries: u32, sweeping: bool) -> usize {
    if sweeping && kind.claims() {
        base.max((max_entries as usize).div_ceil(PASS_TICKS))
    } else {
        base
    }
}

/// The index of the SYN_FLOWS table, whose observation counts the splices
/// the sweep ends.
fn syn_table(kinds: impl IntoIterator<Item = Kind>) -> Option<usize> {
    kinds.into_iter().position(|kind| kind == Kind::Syn)
}

/// The shortest time a splice stays unclaimed before the sweep ends it, on
/// top of its two rounds.
const MIN_GRACE: Duration = Duration::from_secs(2);

/// What the agent's configuration, HA role and conntrack sync say about
/// sweeping, read each tick.
pub struct SweepInputs {
    /// The ports servers of proxied connections use (a splice's key names
    /// one); empty when no port is SYN-proxied, and the sweep is then off.
    pub ports: HashSet<u16>,
    /// Whether this node owns its connection state
    /// ([`crate::ha::State::owns_state`]).
    pub owns: bool,
    /// The splices conntrack sync holds as imported from a peer, which the
    /// sweep leaves alone; `None` on a leased HA owner, which owns everything
    /// it holds ([`crate::ha::State::leased`]).
    pub held: Option<ImportedSplices>,
    /// The HA conntrack-sync push interval, when this node is in a pair.
    pub sync_interval: Option<Duration>,
}

impl SweepInputs {
    /// The inputs of one tick. Without a lease this node cannot know it is
    /// the active member, so the splices conntrack sync holds as imported
    /// (`held`) are never judged; a leased owner judges everything it holds.
    pub fn new(
        ports: HashSet<u16>,
        owns: bool,
        leased: bool,
        held: &ImportedSplices,
        sync_interval: Option<Duration>,
    ) -> Self {
        Self {
            ports,
            owns,
            held: (!leased).then(|| held.clone()),
            sync_interval,
        }
    }

    /// Whether the sweep runs this tick: a sweep exists, this node owns its
    /// state, and some port is SYN-proxied.
    fn sweeping(&self, has_sweep: bool) -> bool {
        has_sweep && self.owns && !self.ports.is_empty()
    }

    /// How long a splice must have been unclaimed.
    fn grace(&self) -> Duration {
        self.sync_interval
            .map_or(MIN_GRACE, |interval| MIN_GRACE.max(interval * 10))
    }
}

/// Ends the SYN-proxy splices no live connection claims any more.
///
/// `SYN_FLOWS` holds no timestamp and the data plane never removes a splice,
/// so the map used to be left to its LRU — which, once as many proxied
/// connections had come and gone as it holds, evicted the least recently used
/// record: an idle live connection, which then died silently.
///
/// A proxied connection lives exactly as long as its connection state (the
/// policy it is proxied under must be stateful; the agent refuses anything
/// else): its firewall entries, and for a translated one its destination-NAT
/// binding. While the reclaim walk passes over FW_FLOWS and CONNTRACK it
/// collects the splice key every live entry claims
/// ([`velstra_common::firewall_claim`], [`velstra_common::nat_claim`], the
/// latter mapping a port-forward's public port to the inside one), keeping
/// only keys on a proxied server port. A round ends once both tables have been
/// walked completely since it began; every splice no claim names is then a
/// suspect, and a suspect still unclaimed, with the same value, at the end of
/// the next round and at least [`SweepInputs::grace`] after it was first
/// unclaimed is removed after one more read of its current value. The extra
/// round and the grace cover a handshake in flight (its splice is written an
/// instant before its connection state) and a client that reused the tuple
/// meanwhile (its record has a new value).
///
/// Only removal from evidence of absence: a forged packet can at most keep a
/// dead splice claimed. Only a node that owns its state sweeps — an HA
/// standby on a lease keeps every imported splice and receives the owner's
/// removals as conntrack-sync deletions — and without a lease (pairs that
/// fail over by VRRP alone, where the agent cannot tell which member is
/// active) a node never judges a splice conntrack sync holds as imported: a
/// peer's splice can arrive a dump before the state that claims it.
struct SpliceSweep {
    splices: Handle<FlowKey, SynFlow>,
    state: SweepState,
}

/// The sweep's bookkeeping, apart from the map it judges.
#[derive(Default)]
struct SweepState {
    claims: HashSet<FlowKey>,
    /// Splices no claim named at the end of the last round: the value they
    /// had and when they were first found unclaimed.
    suspects: StdHashMap<FlowKey, (SynFlow, Instant)>,
    firewall: Round,
    nat: Round,
}

impl SweepState {
    /// Forget everything: the next round starts from scratch, so nothing
    /// judged before counts afterwards.
    fn reset(&mut self) {
        *self = Self::default();
    }

    /// The start of a tick: a sweep that does not run this tick forgets its
    /// rounds, so a node that starts owning its state again waits two full
    /// rounds before it ends anything.
    fn begin_tick(&mut self, sweeping: bool) {
        if !sweeping {
            self.reset();
        }
    }

    /// Account one table's step to the round. A step taken while not
    /// sweeping gathered no claims, so it never counts towards a round.
    fn stepped(&mut self, kind: Kind, stepped: &Stepped, sweeping: bool) {
        if !sweeping {
            return;
        }
        match kind {
            Kind::Firewall => self.firewall = self.firewall.advance(stepped),
            Kind::Nat => self.nat = self.nat.advance(stepped),
            Kind::Syn => {}
        }
    }

    /// Whether the round is complete and may be judged this tick.
    fn round_complete(&self, sweeping: bool) -> bool {
        sweeping && self.firewall == Round::Covered && self.nat == Round::Covered
    }

    /// Judge every splice of a complete round: returns the ended ones (to be
    /// removed after a last read) and keeps the rest of the unclaimed as
    /// suspects. A splice in `held` is never judged.
    fn judge_round(
        &mut self,
        splices: impl IntoIterator<Item = (FlowKey, SynFlow)>,
        held: &HashSet<FlowKey>,
        now: Instant,
        grace: Duration,
    ) -> Vec<(FlowKey, SynFlow)> {
        let claims = std::mem::take(&mut self.claims);
        let mut suspects = StdHashMap::new();
        let mut ended = Vec::new();
        for (key, value) in splices {
            if held.contains(&key) {
                continue;
            }
            match judge(&claims, &self.suspects, &key, &value, now, grace) {
                Judgement::Claimed => {}
                Judgement::Ended => ended.push((key, value)),
                Judgement::Suspect(since) => {
                    suspects.insert(key, (value, since));
                }
            }
        }
        self.suspects = suspects;
        self.firewall = Round::Waiting;
        self.nat = Round::Waiting;
        ended
    }
}

/// What a sweep round makes of one splice.
#[derive(Debug, PartialEq, Eq)]
enum Judgement {
    /// A live connection claims it.
    Claimed,
    /// Unclaimed since the given instant (now, when first found so or changed
    /// since).
    Suspect(Instant),
    /// Unclaimed for two rounds running with the same value, for at least the
    /// grace: its connection is over.
    Ended,
}

fn judge(
    claims: &HashSet<FlowKey>,
    suspects: &StdHashMap<FlowKey, (SynFlow, Instant)>,
    key: &FlowKey,
    value: &SynFlow,
    now: Instant,
    grace: Duration,
) -> Judgement {
    if claims.contains(key) {
        return Judgement::Claimed;
    }
    match suspects.get(key) {
        Some((before, since)) if before == value => {
            if now.saturating_duration_since(*since) >= grace {
                Judgement::Ended
            } else {
                Judgement::Suspect(*since)
            }
        }
        _ => Judgement::Suspect(now),
    }
}

impl SpliceSweep {
    /// The round is complete: judge every splice and remove the ended ones.
    /// Returns how many were removed.
    fn end_round(&mut self, held: Option<&ImportedSplices>, grace: Duration) -> Result<usize> {
        let mut splices = Vec::new();
        let mut cursor = None;
        loop {
            let batch = lookup_batch::<FlowKey, SynFlow>(&self.splices.raw, cursor, BATCH)?;
            splices.extend(batch.entries);
            cursor = batch.next;
            if cursor.is_none() {
                break;
            }
        }
        let held = held
            .map(|set| set.lock().unwrap_or_else(|e| e.into_inner()).clone())
            .unwrap_or_default();
        let mut removed = 0;
        for (key, value) in self
            .state
            .judge_round(splices, &held, Instant::now(), grace)
        {
            // Re-read at the last moment: a client that reused the tuple
            // since has a new record, which is not ended.
            if self
                .splices
                .typed
                .get(&key, 0)
                .is_ok_and(|now| now == value)
                && self.splices.typed.remove(&key).is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Where a firewall or NAT walk puts the splice keys its live entries claim:
/// only those on a server port some proxied connection uses, so the set is
/// bounded by the proxied connections, not by all connection state.
struct Claims<'a> {
    into: &'a mut HashSet<FlowKey>,
    ports: &'a HashSet<u16>,
}

impl Claims<'_> {
    fn claim(&mut self, splice: Option<FlowKey>) {
        if let Some(splice) = splice
            && self.ports.contains(&splice.dst_port)
        {
            self.into.insert(splice);
        }
    }
}

/// The collector's whole state: every table it walks, and the splice sweep
/// the firewall and NAT walks drive.
pub struct Reclaimer {
    tables: Vec<Table>,
    sweep: Option<SpliceSweep>,
}

impl Reclaimer {
    pub fn new(tables: Vec<Table>) -> Self {
        publish(&tables);
        Self {
            tables,
            sweep: None,
        }
    }

    /// Also end the splices in `splices` (SYN_FLOWS) no live connection
    /// claims (see [`SpliceSweep`]). On an error the reclaimer is unchanged
    /// and keeps reclaiming expired state.
    pub fn enable_splice_sweep(&mut self, splices: MapData) -> Result<()> {
        self.sweep = Some(SpliceSweep {
            splices: Handle::open(splices)?,
            state: SweepState::default(),
        });
        Ok(())
    }

    /// One tick: a bounded slice of every table ([`table_slice`]), feeding
    /// the splice sweep while it runs. Errors are recorded per table and
    /// never stop the others, and never touch the datapath gate. The policy
    /// lives in the helpers this calls, which are tested on their own.
    pub fn tick(
        &mut self,
        timeouts: ConntrackTimeouts,
        slice: usize,
        inputs: &SweepInputs,
    ) -> usize {
        let sweeping = inputs.sweeping(self.sweep.is_some());
        if let Some(sweep) = &mut self.sweep {
            sweep.state.begin_tick(sweeping);
        }
        let mut reclaimed = 0;
        for table in &mut self.tables {
            let kind = table.kind();
            let slice = table_slice(slice, kind, table.observation.max_entries, sweeping);
            let claims = match &mut self.sweep {
                Some(sweep) if sweeping && kind.claims() => Some(Claims {
                    into: &mut sweep.state.claims,
                    ports: &inputs.ports,
                }),
                _ => None,
            };
            match table.step_claiming(timeouts, slice, claims) {
                Ok(stepped) => {
                    reclaimed += stepped.deleted;
                    if let Some(sweep) = &mut self.sweep {
                        sweep.state.stepped(kind, &stepped, sweeping);
                    }
                }
                Err(error) => {
                    warn!(
                        "reclaiming expired {} entries failed: {error:#}",
                        table.observation.name
                    );
                    table.fail(&error);
                    // A walk that failed covers nothing: start over.
                    if let Some(sweep) = &mut self.sweep {
                        sweep.state.reset();
                    }
                }
            }
        }
        if let Some(sweep) = &mut self.sweep
            && sweep.state.round_complete(sweeping)
        {
            match sweep.end_round(inputs.held.as_ref(), inputs.grace()) {
                Ok(removed) => {
                    if let Some(index) = syn_table(self.tables.iter().map(Table::kind)) {
                        self.tables[index].observation.reclaimed_expired += removed as u64;
                    }
                }
                Err(error) => {
                    warn!("ending unclaimed SYN-proxy splices failed: {error:#}");
                    sweep.state.reset();
                }
            }
        }
        publish(&self.tables);
        reclaimed
    }
}

fn publish(tables: &[Table]) {
    if let Ok(mut observed) = observations().lock() {
        *observed = tables.iter().map(|t| t.observation.clone()).collect();
    }
}

/// One immediate pass for the `expire-state` verb: a full walk of the named
/// table (or as much of it as `limit` entries allow), reported as JSON. Runs
/// on the background collector's own handles, so it cannot block traffic.
pub async fn expire_now(
    firewall: &Arc<Mutex<Firewall>>,
    table: &str,
    limit: usize,
) -> Result<serde_json::Value> {
    let (mut table, timeouts) = {
        let fw = firewall.lock().await;
        let sizing = fw.state_tables().0;
        let table = match table {
            "firewall" => Table::firewall(fw.state_map("FW_FLOWS")?, sizing.fw_flows)?,
            "nat" => Table::nat(fw.state_map("CONNTRACK")?, sizing.conntrack)?,
            other => anyhow::bail!("expiry table must be nat or firewall, not {other:?}"),
        };
        (table, fw.conntrack_timeouts())
    };
    let started = Instant::now();
    let report = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let removed = table.step(timeouts, limit)?;
        let complete = table.observation.passes > 0;
        Ok(serde_json::json!({
            "examined": table.observation.observed_entries.unwrap_or(table.counted),
            "removed": removed,
            "scan_complete": complete,
            "budget_exhausted": !complete,
            "pause_ns": 0,
        }))
    })
    .await
    .context("expiry task failed")??;
    let mut report = report;
    report["elapsed_ns"] = serde_json::json!(started.elapsed().as_nanos() as u64);
    Ok(report)
}

/// Run the collector for the life of the agent.
pub async fn run(firewall: Arc<Mutex<Firewall>>, ha: crate::ha::Shared, held: ImportedSplices) {
    let tables = {
        let fw = firewall.lock().await;
        let sizing = fw.state_tables().0;
        let tables = (|| -> Result<Vec<Table>> {
            Ok(vec![
                Table::firewall(fw.state_map("FW_FLOWS")?, sizing.fw_flows)?,
                Table::nat(fw.state_map("CONNTRACK")?, sizing.conntrack)?,
                Table::syn(fw.state_map("SYN_FLOWS")?, sizing.syn_flows)?,
            ])
        })();
        match tables {
            Ok(tables) => tables,
            Err(e) => {
                warn!("expired-state reclamation disabled: {e:#}");
                return;
            }
        }
    };
    let mut reclaimer = Reclaimer::new(tables);
    let splices = firewall.lock().await.state_map("SYN_FLOWS");
    if let Err(e) = splices.and_then(|map| reclaimer.enable_splice_sweep(map)) {
        // Expired-state reclamation goes on; only SYN-proxy records are then
        // left to their LRU.
        warn!("SYN-proxy splice sweep disabled, expired-state reclamation continues: {e:#}");
    }
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let (timeouts, ports, sync_interval) = {
            let fw = firewall.lock().await;
            (
                fw.conntrack_timeouts(),
                fw.splice_service_ports(),
                fw.sync_interval(),
            )
        };
        let (owns, leased) = {
            let ha = ha.lock().await;
            (ha.owns_state(crate::ha::now_ns()), ha.leased())
        };
        let inputs = SweepInputs::new(ports, owns, leased, &held, sync_interval);
        let joined = tokio::task::spawn_blocking(move || {
            let reclaimed = reclaimer.tick(timeouts, SLICE, &inputs);
            (reclaimer, reclaimed)
        })
        .await;
        match joined {
            Ok((back, _)) => reclaimer = back,
            Err(error) => {
                warn!("expired-state reclamation stopped: {error}");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn splice(port: u16) -> FlowKey {
        velstra_common::splice_key([198, 51, 100, 7], port, 443)
    }

    #[test]
    fn a_claimed_splice_is_never_a_suspect() {
        let now = Instant::now();
        let claims = HashSet::from([splice(1)]);
        let suspects = StdHashMap::from([(splice(1), (SynFlow::pending(1, 2), now))]);
        let verdict = judge(
            &claims,
            &suspects,
            &splice(1),
            &SynFlow::pending(1, 2),
            now,
            GRACE,
        );
        assert_eq!(verdict, Judgement::Claimed);
    }

    const GRACE: Duration = Duration::from_secs(2);

    #[test]
    fn a_splice_ends_only_unclaimed_and_unchanged_for_two_rounds_and_the_grace() {
        let none = HashSet::new();
        let value = SynFlow::pending(1, 2);
        let start = Instant::now();
        assert_eq!(
            judge(&none, &StdHashMap::new(), &splice(1), &value, start, GRACE),
            Judgement::Suspect(start)
        );
        let suspects = StdHashMap::from([(splice(1), (value, start))]);
        // Second round, inside the grace: still a suspect, since the start.
        let early = start + Duration::from_secs(1);
        assert_eq!(
            judge(&none, &suspects, &splice(1), &value, early, GRACE),
            Judgement::Suspect(start)
        );
        let late = start + GRACE;
        assert_eq!(
            judge(&none, &suspects, &splice(1), &value, late, GRACE),
            Judgement::Ended
        );
        // Replaced since (a client reused the tuple): a fresh suspect again.
        let replaced = SynFlow::pending(3, 4);
        assert_eq!(
            judge(&none, &suspects, &splice(1), &replaced, late, GRACE),
            Judgement::Suspect(late)
        );
        // Another connection's splice is judged on its own.
        assert_eq!(
            judge(&none, &suspects, &splice(2), &value, late, GRACE),
            Judgement::Suspect(late)
        );
    }

    #[test]
    fn a_round_keeps_suspects_and_returns_only_the_ended() {
        let mut state = SweepState::default();
        let start = Instant::now();
        let none = HashSet::new();
        let live = (splice(1), SynFlow::pending(1, 1));
        let dead = (splice(2), SynFlow::pending(2, 2));
        state.claims.insert(live.0);
        assert!(
            state
                .judge_round([live, dead], &none, start, GRACE)
                .is_empty()
        );
        assert!(state.claims.is_empty(), "claims are per round");
        assert_eq!(state.suspects.len(), 1);
        state.claims.insert(live.0);
        let ended = state.judge_round([live, dead], &none, start + GRACE, GRACE);
        assert_eq!(ended, vec![dead]);
        assert!(state.suspects.is_empty());
    }

    #[test]
    fn a_splice_held_for_a_peer_is_never_judged() {
        // M1: without a lease a node cannot tell whether it is active, and a
        // peer's splice can arrive a dump before its claim.
        let mut state = SweepState::default();
        let start = Instant::now();
        let imported = (splice(3), SynFlow::pending(3, 3));
        let held = HashSet::from([imported.0]);
        for round in 0..4 {
            let now = start + GRACE * round;
            assert!(state.judge_round([imported], &held, now, GRACE).is_empty());
        }
        assert!(state.suspects.is_empty());
        // No longer held: judged like any other, from scratch.
        let none = HashSet::new();
        assert!(
            state
                .judge_round([imported], &none, start + GRACE * 5, GRACE)
                .is_empty()
        );
        assert_eq!(
            state.judge_round([imported], &none, start + GRACE * 6, GRACE),
            vec![imported]
        );
    }

    #[test]
    fn a_reset_forgets_suspects_so_a_new_owner_waits_two_rounds_again() {
        let mut state = SweepState::default();
        let none = HashSet::new();
        let start = Instant::now();
        let dead = (splice(2), SynFlow::pending(2, 2));
        assert!(state.judge_round([dead], &none, start, GRACE).is_empty());
        state.reset();
        assert!(
            state
                .judge_round([dead], &none, start + GRACE, GRACE)
                .is_empty()
        );
        assert_eq!(
            state.judge_round([dead], &none, start + GRACE * 2, GRACE),
            vec![dead]
        );
    }

    #[test]
    fn a_tick_without_the_sweep_forgets_the_round() {
        // M2: the reset while inactive.
        let mut state = SweepState::default();
        state.claims.insert(splice(1));
        state
            .suspects
            .insert(splice(2), (SynFlow::pending(2, 2), Instant::now()));
        state.firewall = Round::Covered;
        state.begin_tick(true);
        assert_eq!(
            state.firewall,
            Round::Covered,
            "a running sweep keeps its round"
        );
        assert_eq!(state.claims.len(), 1);
        state.begin_tick(false);
        assert!(state.claims.is_empty() && state.suspects.is_empty());
        assert_eq!(
            (state.firewall, state.nat),
            (Round::Waiting, Round::Waiting)
        );
    }

    #[test]
    fn a_round_completes_only_both_tables_covered_and_only_while_sweeping() {
        // M2: the gate on end_round.
        let mut state = SweepState::default();
        state.stepped(Kind::Firewall, &stepped(true, true), true);
        assert!(!state.round_complete(true), "CONNTRACK not walked yet");
        state.stepped(Kind::Syn, &stepped(true, true), true);
        assert!(!state.round_complete(true), "SYN_FLOWS walks do not count");
        state.stepped(Kind::Nat, &stepped(true, true), true);
        assert!(state.round_complete(true));
        assert!(
            !state.round_complete(false),
            "never judged while not sweeping"
        );
    }

    #[test]
    fn a_step_taken_while_not_sweeping_never_counts_towards_a_round() {
        // Review A: walks before the sweep runs gathered no claims; the
        // first judged round must be one whose walks all gathered them.
        let mut state = SweepState::default();
        state.begin_tick(false);
        state.stepped(Kind::Firewall, &stepped(true, true), false);
        state.stepped(Kind::Nat, &stepped(true, true), false);
        assert_eq!(
            (state.firewall, state.nat),
            (Round::Waiting, Round::Waiting)
        );
        state.begin_tick(true);
        assert!(
            !state.round_complete(true),
            "judged on walks without claims"
        );
    }

    #[test]
    fn held_splices_are_skipped_only_without_a_lease() {
        // M1: a leased owner judges everything, a node without a lease never
        // judges what conntrack sync holds for a peer.
        let held = ImportedSplices::default();
        held.lock().unwrap().insert(splice(1));
        let unleased = SweepInputs::new(HashSet::from([443]), true, false, &held, None);
        assert!(
            unleased
                .held
                .is_some_and(|set| set.lock().unwrap().contains(&splice(1)))
        );
        let leased = SweepInputs::new(HashSet::from([443]), true, true, &held, None);
        assert!(leased.held.is_none());
    }

    #[test]
    fn the_sweep_runs_only_with_a_sweep_owning_and_a_proxied_port() {
        // M2/L2: the active gate, including a sweep that could not be set up.
        let base = inputs(&[443], true, None);
        assert!(base.sweeping(true));
        assert!(!base.sweeping(false), "no sweep set up");
        assert!(
            !inputs(&[443], false, None).sweeping(true),
            "an HA standby never sweeps"
        );
        assert!(
            !inputs(&[], true, None).sweeping(true),
            "no SYN proxy, no sweep"
        );
    }

    #[test]
    fn a_claiming_table_gets_a_larger_slice_only_while_sweeping() {
        // M2: the slice size.
        let max = 12_600_000;
        assert_eq!(table_slice(SLICE, Kind::Firewall, max, false), SLICE);
        assert_eq!(table_slice(SLICE, Kind::Firewall, max, true), 2_520_000);
        assert_eq!(table_slice(SLICE, Kind::Nat, 4_200_000, true), 840_000);
        assert_eq!(
            table_slice(SLICE, Kind::Syn, max, true),
            SLICE,
            "SYN_FLOWS claims nothing"
        );
        assert_eq!(
            table_slice(SLICE, Kind::Firewall, 6144, true),
            SLICE,
            "never below the base"
        );
    }

    #[test]
    fn removals_are_counted_on_the_syn_flows_table() {
        // M2: the removal counting goes to SYN_FLOWS, wherever it is listed.
        assert_eq!(syn_table([Kind::Firewall, Kind::Nat, Kind::Syn]), Some(2));
        assert_eq!(syn_table([Kind::Syn, Kind::Firewall]), Some(0));
        assert_eq!(syn_table([Kind::Firewall, Kind::Nat]), None);
    }

    fn inputs(ports: &[u16], owns: bool, sync: Option<Duration>) -> SweepInputs {
        SweepInputs {
            ports: ports.iter().copied().collect(),
            owns,
            held: None,
            sync_interval: sync,
        }
    }

    #[test]
    fn the_grace_covers_several_sync_pushes() {
        assert_eq!(inputs(&[443], true, None).grace(), MIN_GRACE);
        assert_eq!(
            inputs(&[443], true, Some(Duration::from_millis(50))).grace(),
            MIN_GRACE
        );
        assert_eq!(
            inputs(&[443], true, Some(Duration::from_secs(3))).grace(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn claims_keep_only_keys_on_a_proxied_server_port() {
        let ports = HashSet::from([443]);
        let mut into = HashSet::new();
        let mut claims = Claims {
            into: &mut into,
            ports: &ports,
        };
        claims.claim(Some(splice(1)));
        claims.claim(Some(velstra_common::splice_key([198, 51, 100, 7], 2, 80)));
        claims.claim(None);
        assert_eq!(into, HashSet::from([splice(1)]));
    }

    fn stepped(began: bool, completed: bool) -> Stepped {
        Stepped {
            deleted: 0,
            began,
            completed,
        }
    }

    #[test]
    fn a_round_counts_only_a_walk_that_began_inside_it() {
        // A walk already under way when the round began does not cover the
        // table for it, even when it finishes: its first part was claimed
        // before the round's claims started.
        let round = Round::Waiting.advance(&stepped(false, true));
        assert_eq!(round, Round::Waiting);
        // The next walk begins inside the round and covers it when done.
        let round = round.advance(&stepped(true, false));
        assert_eq!(round, Round::Walking);
        assert_eq!(round.advance(&stepped(false, false)), Round::Walking);
        assert_eq!(round.advance(&stepped(false, true)), Round::Covered);
        // A small table begun and finished in one step covers it at once.
        assert_eq!(Round::Waiting.advance(&stepped(true, true)), Round::Covered);
        // Covered stays covered until the round ends.
        assert_eq!(
            Round::Covered.advance(&stepped(true, false)),
            Round::Covered
        );
    }

    #[test]
    fn staleness_is_unknown_before_the_first_pass_and_after_the_bound() {
        assert!(is_stale(None));
        assert!(!is_stale(Some(Duration::from_secs(1))));
        assert!(is_stale(Some(STALE_AFTER + Duration::from_secs(1))));
    }
}
