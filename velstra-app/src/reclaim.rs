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
//! no timestamp, so it is counted but left to its LRU.

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

use crate::{firewall::Firewall, state_tables};

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
    /// Expired entries deleted since the agent started.
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
    /// No timestamp: counted, never reclaimed.
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
        mut claims: Option<&mut HashSet<FlowKey>>,
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
                        if let (false, Some(claims), Some(splice)) = (
                            expired,
                            claims.as_deref_mut(),
                            velstra_common::firewall_claim(k, v),
                        ) {
                            claims.insert(splice);
                        }
                    },
                )?,
                Contents::Nat(map) => walk_batch(
                    map,
                    &mut self.cursor,
                    |k: &FlowKey, v: &FlowState, now| v.expired(k.proto, now, timeouts),
                    |k, v, expired| {
                        if let (false, Some(claims), Some(splice)) = (
                            expired,
                            claims.as_deref_mut(),
                            velstra_common::nat_claim(k, v),
                        ) {
                            claims.insert(splice);
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

    fn claims_splices(&self) -> bool {
        matches!(self.contents, Contents::Firewall(_) | Contents::Nat(_))
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Round {
    /// Its walk under way began before the round: its claims do not cover
    /// the whole table for this round.
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

/// Ends the SYN-proxy splices no live connection claims any more.
///
/// `SYN_FLOWS` holds no timestamp and the data plane never removes a splice,
/// so the map used to be left to its LRU — which, once as many proxied
/// connections had come and gone as it holds, evicted the least recently used
/// record: an idle live connection, which then died silently.
///
/// A live proxied connection always has live connection state: its firewall
/// entries, and for a translated one its destination-NAT binding. While the
/// reclaim walk passes over FW_FLOWS and CONNTRACK it collects the splice key
/// every live entry claims ([`velstra_common::firewall_claim`],
/// [`velstra_common::nat_claim`], the latter mapping a port-forward's or load
/// balancer's public port to the inside one). A round ends once both tables
/// have been walked completely since it began; every splice no claim names is
/// then a suspect, and a suspect still unclaimed, with the same value, at the
/// end of the next round is removed after one more read of its current value.
/// The extra round is the grace for a handshake in flight, whose splice the
/// data plane writes an instant before its connection state, and for a
/// client that reused the tuple meanwhile (its record has a new value).
///
/// Only removal from evidence of absence: a forged packet can at most keep a
/// dead splice claimed. Removal is local. On an HA owner, the next snapshot
/// omits the splice and its standbys delete it through the existing
/// SYN-proxy DELETE; a standby exports nothing (the ours/authoritative gate of
/// conntrack sync), so its own sweep never deletes the owner's records.
struct SpliceSweep {
    splices: Handle<FlowKey, SynFlow>,
    claims: HashSet<FlowKey>,
    suspects: StdHashMap<FlowKey, SynFlow>,
    firewall: Round,
    nat: Round,
    ended: u64,
}

impl SpliceSweep {
    fn new(splices: MapData) -> Result<Self> {
        Ok(Self {
            splices: Handle::open(splices)?,
            claims: HashSet::new(),
            suspects: StdHashMap::new(),
            firewall: Round::Waiting,
            nat: Round::Waiting,
            ended: 0,
        })
    }

    /// The round is complete: judge every splice. Returns how many ended.
    fn end_round(&mut self) -> Result<usize> {
        let claims = std::mem::take(&mut self.claims);
        let mut suspects = StdHashMap::new();
        let mut removed = 0;
        let mut cursor = None;
        loop {
            let batch = lookup_batch::<FlowKey, SynFlow>(&self.splices.raw, cursor, BATCH)?;
            for (key, value) in batch.entries {
                match judge(&claims, &self.suspects, &key, &value) {
                    Judgement::Claimed => {}
                    Judgement::Ended
                        // Re-read at the last moment: a client that reused
                        // the tuple since has a new record, not a suspect.
                        if self.splices.typed.get(&key, 0).is_ok_and(|now| now == value)
                            && self.splices.typed.remove(&key).is_ok() =>
                    {
                        removed += 1;
                    }
                    Judgement::Ended | Judgement::Suspect => {
                        suspects.insert(key, value);
                    }
                }
            }
            cursor = batch.next;
            if cursor.is_none() {
                break;
            }
        }
        self.suspects = suspects;
        self.firewall = Round::Waiting;
        self.nat = Round::Waiting;
        self.ended += removed as u64;
        Ok(removed)
    }
}

/// What a sweep round makes of one splice.
#[derive(Debug, PartialEq, Eq)]
enum Judgement {
    /// A live connection claims it.
    Claimed,
    /// Unclaimed for the first time, or changed since it was last unclaimed.
    Suspect,
    /// Unclaimed for two rounds running with the same value: its connection
    /// is over.
    Ended,
}

fn judge(
    claims: &HashSet<FlowKey>,
    suspects: &StdHashMap<FlowKey, SynFlow>,
    key: &FlowKey,
    value: &SynFlow,
) -> Judgement {
    if claims.contains(key) {
        Judgement::Claimed
    } else if suspects.get(key) == Some(value) {
        Judgement::Ended
    } else {
        Judgement::Suspect
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
    /// claims (see [`SpliceSweep`]).
    pub fn with_splice_sweep(mut self, splices: MapData) -> Result<Self> {
        self.sweep = Some(SpliceSweep::new(splices)?);
        Ok(self)
    }

    /// One tick: a bounded slice of every table. Errors are recorded per table
    /// and never stop the others, and never touch the datapath gate.
    pub fn tick(&mut self, timeouts: ConntrackTimeouts, slice: usize) -> usize {
        let mut reclaimed = 0;
        for table in &mut self.tables {
            let claims = match (&mut self.sweep, table.claims_splices()) {
                (Some(sweep), true) => Some(&mut sweep.claims),
                _ => None,
            };
            match table.step_claiming(timeouts, slice, claims) {
                Ok(stepped) => {
                    reclaimed += stepped.deleted;
                    if let Some(sweep) = &mut self.sweep {
                        match table.contents {
                            Contents::Firewall(_) => {
                                sweep.firewall = sweep.firewall.advance(&stepped)
                            }
                            Contents::Nat(_) => sweep.nat = sweep.nat.advance(&stepped),
                            Contents::Syn(_) => {}
                        }
                    }
                }
                Err(error) => {
                    warn!(
                        "reclaiming expired {} entries failed: {error:#}",
                        table.observation.name
                    );
                    table.fail(&error);
                    // A walk that failed covers nothing: start the round over.
                    if let Some(sweep) = &mut self.sweep {
                        sweep.firewall = Round::Waiting;
                        sweep.nat = Round::Waiting;
                    }
                }
            }
        }
        if let Some(sweep) = &mut self.sweep
            && sweep.firewall == Round::Covered
            && sweep.nat == Round::Covered
            && let Err(error) = sweep.end_round()
        {
            warn!("ending unclaimed SYN-proxy splices failed: {error:#}");
            sweep.firewall = Round::Waiting;
            sweep.nat = Round::Waiting;
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
pub async fn run(firewall: Arc<Mutex<Firewall>>) {
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
    let reclaimer = Reclaimer::new(tables);
    let splices = firewall.lock().await.state_map("SYN_FLOWS");
    let mut reclaimer = match splices.and_then(|map| reclaimer.with_splice_sweep(map)) {
        Ok(reclaimer) => reclaimer,
        Err(e) => {
            warn!("SYN-proxy splice sweep disabled: {e:#}");
            return;
        }
    };
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let timeouts = firewall.lock().await.conntrack_timeouts();
        let joined = tokio::task::spawn_blocking(move || {
            let reclaimed = reclaimer.tick(timeouts, SLICE);
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
        let claims = HashSet::from([splice(1)]);
        let suspects = StdHashMap::from([(splice(1), SynFlow::pending(1, 2))]);
        let verdict = judge(&claims, &suspects, &splice(1), &SynFlow::pending(1, 2));
        assert_eq!(verdict, Judgement::Claimed);
    }

    #[test]
    fn a_splice_ends_only_when_unclaimed_and_unchanged_for_two_rounds() {
        let none = HashSet::new();
        let value = SynFlow::pending(1, 2);
        assert_eq!(
            judge(&none, &StdHashMap::new(), &splice(1), &value),
            Judgement::Suspect
        );
        let suspects = StdHashMap::from([(splice(1), value)]);
        assert_eq!(
            judge(&none, &suspects, &splice(1), &value),
            Judgement::Ended
        );
        // Replaced since (a client reused the tuple): a fresh suspect again.
        let replaced = SynFlow::pending(3, 4);
        assert_eq!(
            judge(&none, &suspects, &splice(1), &replaced),
            Judgement::Suspect
        );
        // Another connection's splice is judged on its own.
        assert_eq!(
            judge(&none, &suspects, &splice(2), &value),
            Judgement::Suspect
        );
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
