//! Explicit, bounded expiry maintenance. This is not admission control or a
//! remedy for LRU eviction. The caller owns the firewall writer lock throughout.
//! HA and standalone state replication are deliberately unsupported.

use std::{
    borrow::BorrowMut,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, ensure};
use aya::{
    Ebpf, Pod,
    maps::{Array, HashMap, MapData},
};
use serde::Serialize;
use velstra_common::{CONFIG_FAILED, CONFIG_READY, CONFIG_UPDATING};

pub const MAX_SCAN: usize = 65_536;
const WORK_BUDGET: Duration = Duration::from_millis(250);

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub examined: usize,
    pub removed: usize,
    /// False means a bounded prefix only, not that all expired state was found.
    pub scan_complete: bool,
    pub budget_exhausted: bool,
    /// Includes the reader drain. Kernel syscalls are not hard real-time bounded.
    pub pause_ns: u64,
    pub generation: u64,
}

#[derive(Clone, Copy)]
pub struct Eligibility {
    pub ha: bool,
    pub replication: bool,
    pub current_intent: bool,
}

#[derive(Debug)]
struct MutationAttempted;
impl std::fmt::Display for MutationAttempted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("expiry transaction attempted")
    }
}
impl std::error::Error for MutationAttempted {}

pub fn mutation_attempted(error: &anyhow::Error) -> bool {
    error.downcast_ref::<MutationAttempted>().is_some()
}

trait Io {
    fn state(&self) -> Result<u32>;
    fn epoch(&self) -> Result<u64>;
    fn set_state(&mut self, state: u32) -> Result<()>;
    fn set_epoch(&mut self, epoch: u64) -> Result<()>;
    fn drain(&mut self) -> Result<()>;
    fn now(&mut self) -> Result<u64>;
    fn sweep(&mut self, now: u64, limit: usize) -> Result<Report>;
}

fn execute(io: &mut impl Io, eligibility: Eligibility, limit: usize) -> Result<Report> {
    ensure!(
        !eligibility.ha && !eligibility.replication,
        "expiry maintenance requires standalone mode without state replication"
    );
    ensure!(
        eligibility.current_intent,
        "expiry maintenance requires current applied intent"
    );
    ensure!(
        (1..=MAX_SCAN).contains(&limit),
        "scan limit must be 1..={MAX_SCAN}"
    );
    ensure!(
        io.state()? == CONFIG_READY,
        "expiry maintenance requires a ready datapath"
    );
    let before = io.epoch()?;
    ensure!(
        before & 1 == 0,
        "expiry maintenance refuses an incomplete generation"
    );
    let complete = before
        .checked_add(2)
        .context("configuration generation exhausted")?;
    let started = Instant::now();
    // After attempting closure, every error is a failed transaction, including
    // close failure itself. Never use a Drop guard that unconditionally reopens.
    let result: Result<Report> = (|| {
        io.set_state(CONFIG_UPDATING)?;
        io.drain()?;
        io.set_epoch(before + 1)?;
        let now = io.now()?; // strictly after packet readers have drained
        let mut report = io.sweep(now, limit)?;
        io.set_epoch(complete)?;
        io.set_state(CONFIG_READY)?;
        report.generation = complete;
        report.pause_ns = started.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        Ok(report)
    })();
    match result {
        Ok(report) => Ok(report),
        Err(error) => match io.set_state(CONFIG_FAILED) {
            Ok(()) => Err(error).context("expiry maintenance failed; datapath blocked"),
            Err(fence) => Err(anyhow!(
                "expiry maintenance failed: {error:#}; failed-state fence also failed: {fence:#}; datapath state is uncertain"
            )),
        }.context(MutationAttempted),
    }
}

/// Uses the existing kernel reader barrier, never a delay or userspace-only
/// memory fence. Map errors are fatal under quiescence, including missing keys.
pub fn collect<T, K, V>(
    ebpf: &mut Ebpf,
    map: &mut HashMap<T, K, V>,
    eligibility: Eligibility,
    limit: usize,
    expired: impl Fn(&K, &V, u64) -> bool,
    drain: impl FnMut() -> Result<()>,
) -> Result<Report>
where
    T: BorrowMut<MapData>,
    K: Pod,
    V: Pod,
{
    struct KernelIo<'a, T, K: Pod, V: Pod, F, D> {
        ebpf: &'a mut Ebpf,
        map: &'a mut HashMap<T, K, V>,
        expired: F,
        drain: D,
    }
    impl<T, K, V, F, D> Io for KernelIo<'_, T, K, V, F, D>
    where
        T: BorrowMut<MapData>,
        K: Pod,
        V: Pod,
        F: Fn(&K, &V, u64) -> bool,
        D: FnMut() -> Result<()>,
    {
        fn state(&self) -> Result<u32> {
            Ok(Array::<_, u32>::try_from(
                self.ebpf
                    .map("APPLY_STATE")
                    .context("APPLY_STATE missing")?,
            )?
            .get(&0, 0)?)
        }
        fn epoch(&self) -> Result<u64> {
            Ok(Array::<_, u64>::try_from(
                self.ebpf
                    .map("CONFIG_EPOCH")
                    .context("CONFIG_EPOCH missing")?,
            )?
            .get(&0, 0)?)
        }
        fn set_state(&mut self, state: u32) -> Result<()> {
            Array::<_, u32>::try_from(
                self.ebpf
                    .map_mut("APPLY_STATE")
                    .context("APPLY_STATE missing")?,
            )?
            .set(0, state, 0)?;
            Ok(())
        }
        fn set_epoch(&mut self, epoch: u64) -> Result<()> {
            Array::<_, u64>::try_from(
                self.ebpf
                    .map_mut("CONFIG_EPOCH")
                    .context("CONFIG_EPOCH missing")?,
            )?
            .set(0, epoch, 0)?;
            Ok(())
        }
        fn drain(&mut self) -> Result<()> {
            (self.drain)()
        }
        fn now(&mut self) -> Result<u64> {
            monotonic_ns()
        }
        fn sweep(&mut self, now: u64, limit: usize) -> Result<Report> {
            let started = Instant::now();
            let mut report = Report::default();
            let mut candidates = Vec::new();
            // Never delete during GET_NEXT_KEY iteration: a missing iterator
            // key restarts the walk. Never flatten map errors into success.
            let mut keys = self.map.keys();
            loop {
                if started.elapsed() >= WORK_BUDGET {
                    report.budget_exhausted = true;
                    break;
                }
                let Some(key) = keys.next() else {
                    report.scan_complete = true;
                    break;
                };
                let key = key.context("enumerating state for expiry")?;
                if report.examined == limit {
                    break;
                }
                let value = self.map.get(&key, 0).context("reading quiesced state")?;
                report.examined += 1;
                if (self.expired)(&key, &value, now) {
                    candidates.push(key);
                }
            }
            for key in candidates {
                if started.elapsed() >= WORK_BUDGET {
                    report.scan_complete = false;
                    report.budget_exhausted = true;
                    break;
                }
                // Re-evaluate this exact entry, never its reverse/related key.
                // A fresh reverse or an unexpired partial publication survives.
                let value = self
                    .map
                    .get(&key, 0)
                    .context("rechecking expiry candidate")?;
                if (self.expired)(&key, &value, now) {
                    self.map.remove(&key).context("removing expired state")?;
                    report.removed += 1;
                }
            }
            Ok(report)
        }
    }
    execute(
        &mut KernelIo {
            ebpf,
            map,
            expired,
            drain,
        },
        eligibility,
        limit,
    )
}

fn monotonic_ns() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is writable and CLOCK_MONOTONIC uses no other pointers.
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut value) } == 0,
        "reading monotonic clock: {}",
        std::io::Error::last_os_error()
    );
    let seconds = u64::try_from(value.tv_sec).context("negative monotonic seconds")?;
    let nanos = u64::try_from(value.tv_nsec).context("negative monotonic nanos")?;
    ensure!(nanos < 1_000_000_000, "invalid monotonic nanos");
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|s| s.checked_add(nanos))
        .context("monotonic clock overflow")
}

#[cfg(test)]
mod tests {
    use super::*;
    const STANDALONE: Eligibility = Eligibility {
        ha: false,
        replication: false,
        current_intent: true,
    };
    struct Fake {
        state: u32,
        epoch: u64,
        fail: &'static str,
        fail_fence: bool,
        events: Vec<&'static str>,
    }
    impl Default for Fake {
        fn default() -> Self {
            Self {
                state: CONFIG_READY,
                epoch: 2,
                fail: "",
                fail_fence: false,
                events: vec![],
            }
        }
    }
    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<()> {
            self.events.push(name);
            ensure!(self.fail != name, "injected {name}");
            ensure!(
                !(self.fail_fence && name == "failed"),
                "injected failed fence"
            );
            Ok(())
        }
    }
    impl Io for Fake {
        fn state(&self) -> Result<u32> {
            ensure!(self.fail != "state-read", "injected state read");
            Ok(self.state)
        }
        fn epoch(&self) -> Result<u64> {
            ensure!(self.fail != "epoch-read", "injected epoch read");
            Ok(self.epoch)
        }
        fn set_state(&mut self, state: u32) -> Result<()> {
            self.step(match state {
                CONFIG_READY => "reopen",
                CONFIG_UPDATING => "close",
                _ => "failed",
            })?;
            self.state = state;
            Ok(())
        }
        fn set_epoch(&mut self, epoch: u64) -> Result<()> {
            self.step(if epoch & 1 == 0 { "commit" } else { "begin" })?;
            self.epoch = epoch;
            Ok(())
        }
        fn drain(&mut self) -> Result<()> {
            self.step("drain")
        }
        fn now(&mut self) -> Result<u64> {
            self.step("clock")?;
            Ok(100)
        }
        fn sweep(&mut self, now: u64, _: usize) -> Result<Report> {
            assert_eq!(now, 100);
            assert_eq!(self.state, CONFIG_UPDATING);
            self.step("sweep")?;
            Ok(Report::default())
        }
    }
    #[test]
    fn transaction_order_and_generation_are_explicit() {
        let mut io = Fake::default();
        let r = execute(&mut io, STANDALONE, 1).unwrap();
        assert_eq!(
            io.events,
            [
                "close", "drain", "begin", "clock", "sweep", "commit", "reopen"
            ]
        );
        assert_eq!(r.generation, 4);
        assert_eq!(io.state, CONFIG_READY);
    }
    #[test]
    fn every_transaction_error_blocks_without_reopening() {
        for failure in [
            "close", "drain", "begin", "clock", "sweep", "commit", "reopen",
        ] {
            let mut io = Fake {
                fail: failure,
                ..Fake::default()
            };
            let error = execute(&mut io, STANDALONE, 1).unwrap_err();
            assert!(mutation_attempted(&error));
            assert!(format!("{error:#}").contains(failure));
            assert_eq!(io.state, CONFIG_FAILED);
            assert_eq!(io.events.last(), Some(&"failed"));
            if failure != "reopen" {
                assert!(!io.events.contains(&"reopen"));
            }
        }
    }
    #[test]
    fn failure_to_establish_the_failed_fence_is_reported_as_uncertain() {
        let mut io = Fake {
            fail: "close",
            fail_fence: true,
            ..Fake::default()
        };
        let error = execute(&mut io, STANDALONE, 1).unwrap_err();
        assert!(mutation_attempted(&error));
        assert!(format!("{error:#}").contains("uncertain"));
        assert_eq!(io.events, ["close", "failed"]);
    }
    #[test]
    fn preflight_read_errors_cannot_start_maintenance() {
        for fail in ["state-read", "epoch-read"] {
            let mut io = Fake {
                fail,
                ..Fake::default()
            };
            let error = execute(&mut io, STANDALONE, 1).unwrap_err();
            assert!(!mutation_attempted(&error));
            assert!(io.events.is_empty());
        }
    }
    #[test]
    fn preconditions_do_not_mutate_or_reopen_existing_failures() {
        for mode in [
            Eligibility {
                ha: true,
                ..STANDALONE
            },
            Eligibility {
                replication: true,
                ..STANDALONE
            },
            Eligibility {
                current_intent: false,
                ..STANDALONE
            },
        ] {
            let mut io = Fake::default();
            assert!(execute(&mut io, mode, 1).is_err());
            assert!(io.events.is_empty());
        }
        for (state, epoch, limit) in [
            (CONFIG_FAILED, 2, 1),
            (CONFIG_UPDATING, 2, 1),
            (CONFIG_READY, 3, 1),
            (CONFIG_READY, u64::MAX - 1, 1),
            (CONFIG_READY, 2, 0),
            (CONFIG_READY, 2, MAX_SCAN + 1),
        ] {
            let mut io = Fake {
                state,
                epoch,
                ..Fake::default()
            };
            assert!(execute(&mut io, STANDALONE, limit).is_err());
            assert!(io.events.is_empty());
        }
    }
}
