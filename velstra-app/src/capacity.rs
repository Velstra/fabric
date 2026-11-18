//! Observed physical state-map occupancy, not active sessions or eviction counts.
//!
//! The kernel offers no atomic LRU occupancy snapshot. Require two complete,
//! bounded walks with identical key sets, label the result observed/non-atomic,
//! and report unknown on churn, truncation, errors or stale samples. Expired
//! entries still consume slots and therefore deliberately remain in the count.

use std::{
    collections::BTreeSet,
    io,
    os::fd::{AsFd, AsRawFd},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use aya::maps::{MapData, MapType};
use serde_json::{Value, json};
use tokio::sync::{Mutex, oneshot};

use crate::firewall::Firewall;

const MAPS: [&str; 3] = ["CONNTRACK", "FW_FLOWS", "SYN_FLOWS"];
const THRESHOLD: u64 = 80;
const CACHE_TTL: Duration = Duration::from_secs(2);
const SAMPLE_BUDGET: Duration = Duration::from_millis(750);
const REQUEST_BUDGET: Duration = Duration::from_secs(1);
// A larger future map needs an explicitly reviewed observer budget too. This
// is an observer safety bound, never a substitute for kernel max_entries.
const MAX_MAP_ENTRIES: usize = 65_536;
const MAX_CALLS: usize = 4096;

pub struct Snapshot {
    maps: Vec<(&'static str, Result<MapData>)>,
}

impl Snapshot {
    /// Called under the short configuration lock; callers duplicate FDs only.
    pub fn new(maps: Vec<(&'static str, Result<MapData>)>) -> Self {
        Self { maps }
    }

    fn read(self) -> Value {
        let mut budget = Budget::new();
        let maps: Vec<_> = self
            .maps
            .into_iter()
            .map(|(name, map)| read_map(name, map, &mut budget))
            .collect();
        report(maps)
    }
}

struct Budget {
    deadline: Instant,
    calls_left: usize,
}

impl Budget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + SAMPLE_BUDGET,
            calls_left: MAX_CALLS,
        }
    }

    fn check(&self) -> Result<()> {
        ensure!(
            Instant::now() < self.deadline,
            "capacity sample time budget exceeded"
        );
        Ok(())
    }

    fn call(&mut self) -> Result<()> {
        self.check()?;
        ensure!(
            self.calls_left > 0,
            "capacity sample syscall budget exceeded"
        );
        self.calls_left -= 1;
        Ok(())
    }
}

enum Batch {
    Grow,
    Entries {
        cursor: u32,
        keys: Vec<Vec<u8>>,
        end: bool,
    },
}

fn walk(
    max_entries: usize,
    budget: &mut Budget,
    mut next: impl FnMut(usize, Option<u32>) -> Result<Batch>,
) -> Result<BTreeSet<Vec<u8>>> {
    ensure!(
        (1..=MAX_MAP_ENTRIES).contains(&max_entries),
        "map exceeds reviewed observer entry bound"
    );
    let mut cursor = None;
    let mut batch_size = 512.min(max_entries);
    let mut keys = BTreeSet::new();
    loop {
        budget.call()?;
        let batch = next(batch_size, cursor)?;
        budget.check()?;
        match batch {
            Batch::Grow => {
                ensure!(
                    batch_size < max_entries,
                    "map bucket exceeds observer entry bound"
                );
                batch_size = (batch_size * 2).min(max_entries);
            }
            Batch::Entries {
                cursor: output,
                keys: batch,
                end,
            } => {
                let returned = batch.len();
                ensure!(
                    batch.len() <= batch_size,
                    "kernel returned an oversized map batch"
                );
                ensure!(
                    keys.len() + batch.len() <= max_entries,
                    "map traversal exceeds kernel capacity or changed concurrently"
                );
                for key in batch {
                    ensure!(
                        keys.insert(key),
                        "map changed during traversal (duplicate key)"
                    );
                }
                if end {
                    return Ok(keys);
                }
                ensure!(
                    returned > 0 && cursor != Some(output),
                    "map traversal made no progress"
                );
                cursor = Some(output);
            }
        }
    }
}

/// Linux UAPI BPF_MAP_LOOKUP_BATCH. Initialized byte buffers are sized from
/// validated kernel metadata; no untrusted bytes become typed Rust values.
fn kernel_batch(
    map: &MapData,
    key_size: usize,
    value_size: usize,
    count: usize,
    cursor: Option<u32>,
) -> Result<Batch> {
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
    let mut keys = vec![0u8; key_size * count];
    let mut values = vec![0u8; value_size * count];
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
    // UAPI command24 is shared with the existing HA batch reader. The kernel
    // writes at most count initialized key/value slots into these live buffers.
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
        return Ok(Batch::Grow);
    }
    if rc < 0 && error.raw_os_error() != Some(libc::ENOENT) {
        return Err(error).context("reading raw state-map occupancy");
    }
    ensure!(attr.count as usize <= count, "invalid kernel batch count");
    Ok(Batch::Entries {
        cursor: output,
        keys: keys
            .chunks_exact(key_size)
            .take(attr.count as usize)
            .map(<[u8]>::to_vec)
            .collect(),
        end: rc < 0,
    })
}

fn read_map(name: &str, map: Result<MapData>, budget: &mut Budget) -> Value {
    let mut row = unknown_map(name, "capacity sample unavailable");
    let result = (|| -> Result<usize> {
        budget.check()?;
        let map = map?;
        let info = map.info().context("reading kernel map metadata")?;
        row["map_id"] = json!(info.id());
        row["max_entries"] = json!(info.max_entries());
        ensure!(
            info.map_type()? == MapType::LruHash,
            "unexpected state-map type"
        );
        let key_size = info.key_size() as usize;
        let value_size = info.value_size() as usize;
        ensure!(
            (1..=128).contains(&key_size) && (1..=128).contains(&value_size),
            "unexpected state-map key/value size"
        );
        let mut read = || {
            walk(info.max_entries() as usize, budget, |count, cursor| {
                kernel_batch(&map, key_size, value_size, count, cursor)
            })
        };
        let first = read()?;
        let second = read()?;
        consistent_count(&first, &second)
    })();
    match result {
        Ok(count) => complete_map(row, count),
        Err(error) => {
            row["error"] = json!(format!("{error:#}"));
            row
        }
    }
}

fn consistent_count(first: &BTreeSet<Vec<u8>>, second: &BTreeSet<Vec<u8>>) -> Result<usize> {
    ensure!(first == second, "map changed between occupancy walks");
    Ok(first.len())
}

fn complete_map(mut row: Value, count: usize) -> Value {
    let max = row["max_entries"]
        .as_u64()
        .expect("validated kernel capacity");
    row["observed_entries"] = json!(count);
    row["utilization_percent"] = json!(count as f64 * 100.0 / max as f64);
    row["status"] = json!(if (count as u64) * 100 >= max * THRESHOLD {
        "warning"
    } else {
        "observed-below-threshold"
    });
    row["sample_complete"] = json!(true);
    row["error"] = Value::Null;
    row
}

fn unknown_map(name: &str, error: &str) -> Value {
    json!({"name":name,"map_id":null,"max_entries":null,"observed_entries":null,
        "utilization_percent":null,"status":"unknown","sample_complete":false,"error":error})
}

fn report(maps: Vec<Value>) -> Value {
    let status = if maps.iter().any(|m| m["status"] == "unknown") {
        "unknown"
    } else if maps.iter().any(|m| m["status"] == "warning") {
        "warning"
    } else {
        "observed-below-threshold"
    };
    json!({"version":1,"threshold_percent":THRESHOLD,"measurement":"non-atomic kernel map traversal; entries include expired state",
        "atomic_snapshot":false,"active_connections":null,"evictions":null,"status":status,"maps":maps})
}

fn unknown(error: &str) -> Value {
    report(MAPS.iter().map(|name| unknown_map(name, error)).collect())
}

#[derive(Default)]
struct Cache {
    cached: Option<(Instant, Value)>,
    started: Option<Instant>,
    running: bool,
}

impl Cache {
    /// A request deadline does not release running: only the actual worker's
    /// completion can admit another scan.
    fn begin(&mut self, now: Instant) -> Option<Value> {
        if let Some((sampled, value)) = &self.cached
            && now.saturating_duration_since(*sampled) <= CACHE_TTL
        {
            return Some(decorate(value.clone(), Some(*sampled), now));
        }
        if self.running
            || self
                .started
                .is_some_and(|at| now.saturating_duration_since(at) < CACHE_TTL)
        {
            return Some(match &self.cached {
                Some((sampled, value)) => decorate(value.clone(), Some(*sampled), now),
                None => decorate(unknown("capacity sampling already in progress"), None, now),
            });
        }
        self.running = true;
        self.started = Some(now);
        None
    }
}

fn decorate(mut value: Value, sampled: Option<Instant>, now: Instant) -> Value {
    let age = sampled.map(|at| now.saturating_duration_since(at));
    let stale = age.is_none_or(|age| age > CACHE_TTL);
    value["age_ms"] = age.map_or(Value::Null, |age| json!(age.as_millis() as u64));
    value["max_age_ms"] = json!(CACHE_TTL.as_millis() as u64);
    value["stale"] = json!(stale);
    if stale {
        value["status"] = json!("unknown");
        if let Some(maps) = value["maps"].as_array_mut() {
            for map in maps {
                map["status"] = json!("unknown");
                map["sample_complete"] = json!(false);
                map["error"] = json!("capacity sample stale or not yet available");
            }
        }
    }
    value
}

/// At most one scan is in flight process-wide. Cached observations are fresh
/// for at most2s; old/busy results are explicitly unknown. The blocking task,
/// not the request timeout, owns the permit, preventing timeout-driven floods.
pub async fn query(firewall: Arc<Mutex<Firewall>>) -> Value {
    static CACHE: OnceLock<Arc<Mutex<Cache>>> = OnceLock::new();
    let cache = CACHE
        .get_or_init(|| Arc::new(Mutex::new(Cache::default())))
        .clone();
    let now = Instant::now();
    let mut state = cache.lock().await;
    if let Some(value) = state.begin(now) {
        return value;
    }
    drop(state);
    let (sender, receiver) = oneshot::channel();
    tokio::spawn(async move {
        let snapshot = firewall.lock().await.capacity_snapshot();
        let value = match tokio::task::spawn_blocking(move || snapshot.read()).await {
            Ok(value) => value,
            Err(_) => unknown("capacity observer task failed"),
        };
        // Age starts before descriptor acquisition, not at completion: lock
        // waits and a long scan must not make old observations look new.
        let sampled = now;
        let mut state = cache.lock().await;
        state.running = false;
        state.cached = Some((sampled, value.clone()));
        let _ = sender.send(decorate(value, Some(sampled), Instant::now()));
    });
    match tokio::time::timeout(REQUEST_BUDGET, receiver).await {
        Ok(Ok(value)) => value,
        _ => decorate(
            unknown("capacity sample request timed out"),
            None,
            Instant::now(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(max: u64, count: usize) -> Value {
        let mut row = unknown_map("CONNTRACK", "not sampled");
        row["max_entries"] = json!(max);
        complete_map(row, count)
    }

    #[test]
    fn threshold_counts_slots_not_sessions_and_does_not_round_up() {
        for (max, count, status) in [
            (65536, 52428, "observed-below-threshold"),
            (65536, 52429, "warning"),
            (10, 8, "warning"),
            (10, 0, "observed-below-threshold"),
            (10, 10, "warning"),
        ] {
            assert_eq!(row(max, count)["status"], status);
        }
        let report = report(vec![row(10, 8)]);
        assert!(report["active_connections"].is_null());
        assert!(report["evictions"].is_null());
        assert_eq!(report["atomic_snapshot"], false);
    }

    #[test]
    fn any_unknown_map_prevents_a_falsely_healthy_overall_status() {
        assert_eq!(
            report(vec![row(10, 0), unknown_map("FW_FLOWS", "read failed")])["status"],
            "unknown"
        );
        assert_eq!(
            report(vec![row(10, 8), unknown_map("FW_FLOWS", "read failed")])["status"],
            "unknown"
        );
    }

    #[test]
    fn expired_occupied_entries_are_never_filtered_by_the_observer() {
        let keys = walk(10, &mut Budget::new(), |_, _| {
            Ok(Batch::Entries {
                cursor: 0,
                keys: vec![vec![1], vec![2]],
                end: true,
            })
        })
        .unwrap();
        assert_eq!(keys.len(), 2);
        // No value/age/timeout is passed to walk: expired values occupy slots too.
        assert_eq!(row(10, keys.len())["observed_entries"], 2);
    }

    #[test]
    fn duplicates_overcapacity_errors_and_nonprogress_fail_closed() {
        assert!(
            walk(2, &mut Budget::new(), |_, _| Ok(Batch::Entries {
                cursor: 0,
                keys: vec![vec![1], vec![1]],
                end: true
            }))
            .is_err()
        );
        assert!(
            walk(2, &mut Budget::new(), |_, _| Ok(Batch::Entries {
                cursor: 0,
                keys: vec![vec![1], vec![2], vec![3]],
                end: true
            }))
            .is_err()
        );
        assert!(
            walk(2, &mut Budget::new(), |_, _| anyhow::bail!(
                "kernel denied read"
            ))
            .is_err()
        );
        assert!(
            walk(2, &mut Budget::new(), |_, _| Ok(Batch::Entries {
                cursor: 0,
                keys: vec![],
                end: false
            }))
            .is_err()
        );
        assert!(walk(0, &mut Budget::new(), |_, _| unreachable!()).is_err());
        assert!(
            walk(
                MAX_MAP_ENTRIES + 1,
                &mut Budget::new(),
                |_, _| unreachable!()
            )
            .is_err()
        );
    }

    #[test]
    fn time_and_syscall_budgets_stop_before_a_kernel_call() {
        let mut budget = Budget::new();
        budget.deadline = Instant::now() - Duration::from_millis(1);
        assert!(walk(1, &mut budget, |_, _| unreachable!()).is_err());
        let mut budget = Budget::new();
        budget.calls_left = 0;
        assert!(walk(1, &mut budget, |_, _| unreachable!()).is_err());
    }

    #[test]
    fn bucket_growth_is_bounded_without_inventing_an_empty_map() {
        assert!(walk(2, &mut Budget::new(), |_, _| Ok(Batch::Grow)).is_err());
        let mut calls = 0;
        let keys = walk(1024, &mut Budget::new(), |count, cursor| {
            calls += 1;
            assert_eq!(cursor, None);
            if calls == 1 {
                assert_eq!(count, 512);
                Ok(Batch::Grow)
            } else {
                assert_eq!(count, 1024);
                Ok(Batch::Entries {
                    cursor: 0,
                    keys: vec![vec![1]],
                    end: true,
                })
            }
        })
        .unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn an_empty_nonfinal_batch_after_progress_is_still_an_error() {
        let mut calls = 0;
        assert!(
            walk(10, &mut Budget::new(), |_, _| {
                calls += 1;
                Ok(Batch::Entries {
                    cursor: calls,
                    keys: if calls == 1 { vec![vec![1]] } else { vec![] },
                    end: false,
                })
            })
            .is_err()
        );
        assert_eq!(calls, 2);
    }

    #[test]
    fn a_slow_kernel_batch_cannot_be_published_as_complete() {
        let mut budget = Budget::new();
        budget.deadline = Instant::now() + Duration::from_millis(5);
        assert!(
            walk(1, &mut budget, |_, _| {
                std::thread::sleep(Duration::from_millis(10));
                Ok(Batch::Entries {
                    cursor: 0,
                    keys: vec![],
                    end: true,
                })
            })
            .is_err()
        );
    }

    #[test]
    fn old_or_unavailable_observations_are_never_presented_as_fresh_warning_or_low_pressure() {
        let now = Instant::now();
        let old = now - CACHE_TTL - Duration::from_millis(1);
        for count in [0, 8] {
            let stale = decorate(report(vec![row(10, count)]), Some(old), now);
            assert_eq!(stale["status"], "unknown");
            assert_eq!(stale["maps"][0]["status"], "unknown");
            assert_eq!(stale["stale"], true);
            assert_eq!(
                decorate(report(vec![row(10, count)]), Some(now), now)["stale"],
                false
            );
        }
        assert_eq!(decorate(unknown("busy"), None, now)["stale"], true);
    }

    #[test]
    fn equal_counts_with_different_keys_are_unknown_not_a_consistent_snapshot() {
        let first = BTreeSet::from([vec![1], vec![2]]);
        let second = BTreeSet::from([vec![1], vec![3]]);
        assert!(consistent_count(&first, &second).is_err());
        assert_eq!(consistent_count(&first, &first).unwrap(), 2);
    }

    #[test]
    fn inaccessible_maps_are_unknown_not_zero_occupied() {
        let row = read_map(
            "CONNTRACK",
            Err(anyhow::anyhow!("permission denied")),
            &mut Budget::new(),
        );
        assert_eq!(row["status"], "unknown");
        assert!(row["observed_entries"].is_null());
        assert!(row["error"].as_str().unwrap().contains("permission denied"));
    }

    #[test]
    fn one_inflight_scan_survives_request_timeouts_and_cache_rate_limits_retries() {
        let now = Instant::now();
        let mut cache = Cache::default();
        assert!(cache.begin(now).is_none());
        assert_eq!(cache.begin(now).unwrap()["status"], "unknown");
        let later = now + CACHE_TTL + Duration::from_millis(1);
        assert_eq!(cache.begin(later).unwrap()["status"], "unknown");
        assert_eq!(
            cache.started,
            Some(now),
            "a still-running worker must retain its permit"
        );
        cache.running = false;
        cache.cached = Some((now, report(vec![row(10, 8)])));
        assert_eq!(
            cache.begin(now + Duration::from_millis(1)).unwrap()["status"],
            "warning"
        );
        assert!(cache.begin(later).is_none());
        assert_eq!(cache.started, Some(later));
    }
}
