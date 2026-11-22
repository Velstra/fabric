//! A rate budget for the data plane's own log records.
//!
//! The data plane writes a record for every packet a logging policy drops.
//! A SYN flood or a scan against a zone with `log = true` therefore offers
//! thousands of records a second; the ring buffer and the agent's
//! non-blocking writer keep that from stalling the box, but whatever does get
//! through still reaches the journal, and an appliance keeps a small one: at
//! a few hundred lines a second the security, audit and HA history rotates
//! out within the hour.
//!
//! [`Budgeted`] passes records through a token bucket (a burst, then a
//! steady rate) and counts the rest. Every [`SUMMARY_INTERVAL`] in which
//! records were held back it logs one summary line saying how many. The
//! per-reason drop counters are kept by the data plane itself and stay exact
//! — only the lines are rationed.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use log::{Log, Metadata, Record};

/// Records allowed at once before the steady rate applies, unless
/// `VELSTRA_DATAPATH_LOG_BURST` says otherwise.
pub const DEFAULT_BURST: u32 = 100;
/// Records allowed per second after the burst, unless
/// `VELSTRA_DATAPATH_LOG_RATE` says otherwise.
pub const DEFAULT_RATE: u32 = 10;
/// How often a summary of held-back records is written.
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(10);

/// Data-plane records held back since start.
static SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Data-plane log records held back by the budget since the agent started.
pub fn suppressed() -> u64 {
    SUPPRESSED.load(Ordering::Relaxed)
}

/// A non-negative count from the environment, or `default`.
pub fn setting(value: Option<&str>, default: u32) -> u32 {
    value
        .and_then(|v| v.trim().parse::<u32>().ok())
        .unwrap_or(default)
}

struct Bucket {
    tokens: f64,
    refilled: Instant,
    held_back: u64,
    summarised: Instant,
}

/// A [`Log`] that forwards at most `burst` records at once and `rate` a
/// second to `inner`, and summarises the rest. Clones share one budget.
pub struct Budgeted<L> {
    inner: Arc<L>,
    burst: f64,
    rate: f64,
    bucket: Arc<Mutex<Bucket>>,
    clock: fn() -> Instant,
}

impl<L> Clone for Budgeted<L> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            burst: self.burst,
            rate: self.rate,
            bucket: Arc::clone(&self.bucket),
            clock: self.clock,
        }
    }
}

impl<L: Log> Budgeted<L> {
    pub fn new(inner: L, burst: u32, rate: u32) -> Self {
        Self::with_clock(inner, burst, rate, Instant::now)
    }

    fn with_clock(inner: L, burst: u32, rate: u32, clock: fn() -> Instant) -> Self {
        let now = clock();
        Self {
            inner: Arc::new(inner),
            burst: f64::from(burst),
            rate: f64::from(rate),
            bucket: Arc::new(Mutex::new(Bucket {
                tokens: f64::from(burst),
                refilled: now,
                held_back: 0,
                summarised: now,
            })),
            clock,
        }
    }

    /// Whether this record may pass; a held-back one is counted.
    fn admit(&self, now: Instant) -> bool {
        let Ok(mut bucket) = self.bucket.lock() else {
            return false;
        };
        let elapsed = now.saturating_duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.refilled = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return true;
        }
        bucket.held_back += 1;
        SUPPRESSED.fetch_add(1, Ordering::Relaxed);
        false
    }

    /// Write the summary if records were held back and the interval has
    /// passed. Called on every record and by a periodic tick, so the last
    /// summary of a flood appears after it ends too.
    pub fn summarise(&self) {
        let now = (self.clock)();
        let held_back = {
            let Ok(mut bucket) = self.bucket.lock() else {
                return;
            };
            if bucket.held_back == 0
                || now.saturating_duration_since(bucket.summarised) < SUMMARY_INTERVAL
            {
                return;
            }
            bucket.summarised = now;
            std::mem::take(&mut bucket.held_back)
        };
        self.inner.log(
            &Record::builder()
                .level(log::Level::Warn)
                .target("velstra::datapath")
                .args(format_args!(
                    "suppressed {held_back} data-plane log record(s) over the log budget; \
                     the drop counters still count every packet (show firewall statistics)"
                ))
                .build(),
        );
    }
}

impl<L: Log> Log for Budgeted<L> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.inner.enabled(record.metadata()) {
            return;
        }
        if self.admit((self.clock)()) {
            self.inner.log(record);
        }
        self.summarise();
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    thread_local! {
        static NOW: Cell<Option<Instant>> = const { Cell::new(None) };
    }

    fn fake_now() -> Instant {
        NOW.with(|now| now.get().expect("test clock set"))
    }

    fn advance(by: Duration) {
        NOW.with(|now| now.set(Some(now.get().unwrap() + by)));
    }

    #[derive(Default)]
    struct Capture(Mutex<Vec<String>>);

    impl Log for Capture {
        fn enabled(&self, _: &Metadata) -> bool {
            true
        }
        fn log(&self, record: &Record) {
            self.0.lock().unwrap().push(record.args().to_string());
        }
        fn flush(&self) {}
    }

    fn drop_record(logger: &impl Log, i: u32) {
        logger.log(
            &Record::builder()
                .level(log::Level::Info)
                .target("velstra")
                .args(format_args!(
                    "DROP 198.51.100.{i} proto=6 dport=22 reason=4"
                ))
                .build(),
        );
    }

    /// A flood passes its burst, then the steady rate; everything else is
    /// counted, and one summary per interval says how much was held back.
    #[test]
    fn a_flood_is_cut_to_burst_plus_rate_and_summarised() {
        NOW.with(|now| now.set(Some(Instant::now())));
        let logger = Budgeted::with_clock(Capture::default(), 100, 10, fake_now);
        let before = suppressed();
        // 30 s of 1000 records/s.
        for _ in 0..30 {
            for i in 0..1000 {
                drop_record(&logger, i % 250);
            }
            advance(Duration::from_secs(1));
        }
        logger.summarise();
        let lines = logger.inner.0.lock().unwrap().clone();
        let drops = lines.iter().filter(|l| l.starts_with("DROP ")).count();
        let summaries: Vec<_> = lines
            .iter()
            .filter(|l| l.starts_with("suppressed "))
            .collect();
        // 100 at once, then 10 a second for the 29 seconds after.
        assert!((100..=100 + 10 * 30).contains(&drops), "{drops} drop lines");
        assert_eq!(summaries.len(), 3, "{summaries:?}");
        let held_back: u64 = summaries
            .iter()
            .map(|s| s.split_whitespace().nth(1).unwrap().parse::<u64>().unwrap())
            .sum();
        assert_eq!(held_back + drops as u64, 30_000);
        assert_eq!(suppressed() - before, held_back);
    }

    /// A quiet logger is not rationed: a few lines a second always pass, and
    /// nothing is summarised.
    #[test]
    fn ordinary_traffic_passes_unrationed() {
        NOW.with(|now| now.set(Some(Instant::now())));
        let logger = Budgeted::with_clock(Capture::default(), 100, 10, fake_now);
        for second in 0..60 {
            for i in 0..5 {
                drop_record(&logger, second * 5 + i);
            }
            advance(Duration::from_secs(1));
        }
        logger.summarise();
        let lines = logger.inner.0.lock().unwrap();
        assert_eq!(lines.len(), 300);
        assert!(lines.iter().all(|l| l.starts_with("DROP ")));
    }

    #[test]
    fn settings_parse_and_default() {
        assert_eq!(setting(None, 10), 10);
        assert_eq!(setting(Some("x"), 10), 10);
        assert_eq!(setting(Some(" 25 "), 10), 25);
        assert_eq!(setting(Some("0"), 10), 0);
    }
}
