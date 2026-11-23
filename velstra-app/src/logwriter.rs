//! Log output that never blocks the agent.
//!
//! The agent logged through `env_logger` to stderr and wrote its periodic
//! statistics table to stdout, both synchronously. Under systemd both are
//! streams to journald, and when journald stops reading (disk pressure, rate
//! limiting, a console it forwards to) every such write blocks. On a small
//! box the runtime has one worker, so one blocked write freezes the whole
//! agent — the HA heartbeat (`agent.json`) included — and the routing
//! daemon withdraws ownership although nothing failed.
//!
//! [`Lossy`] hands each record to a bounded queue drained by a dedicated
//! thread. A full queue drops the record instead of waiting; drops are
//! counted ([`dropped`], served as `log_lines_dropped` in the `stats` query)
//! and announced on the output once it drains again.

use std::{
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
        mpsc::{Receiver, SyncSender, TrySendError, sync_channel},
    },
    time::{Duration, Instant},
};

/// Records held while the output is blocked, unless
/// `VELSTRA_LOG_QUEUE_LINES` says otherwise.
pub const QUEUE_LINES: usize = 4096;

/// The accepted range of `VELSTRA_LOG_QUEUE_LINES`.
const QUEUE_LINES_RANGE: std::ops::RangeInclusive<usize> = 1..=65_536;

/// How long an agent exit waits for queued records.
pub const SHUTDOWN_FLUSH: Duration = Duration::from_millis(500);

/// Records dropped because an output was blocked, since start.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Records dropped since the agent started, on every output.
pub fn dropped() -> u64 {
    DROPPED.load(Ordering::Relaxed)
}

/// The queue size from `VELSTRA_LOG_QUEUE_LINES`, clamped; the default when
/// unset or unparsable.
pub fn queue_lines(setting: Option<&str>) -> usize {
    setting
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map_or(QUEUE_LINES, |lines| {
            lines.clamp(*QUEUE_LINES_RANGE.start(), *QUEUE_LINES_RANGE.end())
        })
}

struct Shared {
    tx: SyncSender<Vec<u8>>,
    pending: AtomicUsize,
    dropped: AtomicU64,
}

/// A writer that queues each `write` as one record and never blocks.
#[derive(Clone)]
pub struct Lossy {
    shared: Arc<Shared>,
}

impl Lossy {
    /// A writer draining into `out` on its own thread, holding at most
    /// `capacity` records while `out` blocks.
    pub fn new(out: impl Write + Send + 'static, capacity: usize) -> Self {
        let (tx, rx) = sync_channel(capacity.max(1));
        let shared = Arc::new(Shared {
            tx,
            pending: AtomicUsize::new(0),
            dropped: AtomicU64::new(0),
        });
        let drain = Arc::clone(&shared);
        // Without the thread the queue fills and every record counts as
        // dropped: logging degrades, the agent does not.
        let _ = std::thread::Builder::new()
            .name("velstra-log".into())
            .spawn(move || drain_records(out, rx, &drain));
        Self { shared }
    }

    /// Wait up to `limit` for the queued records to be written; whether the
    /// queue drained.
    pub fn flush_for(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while self.shared.pending.load(Ordering::Acquire) > 0 {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        true
    }

    fn queue(&self, record: Vec<u8>) {
        if record.is_empty() {
            return;
        }
        self.shared.pending.fetch_add(1, Ordering::AcqRel);
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.shared.tx.try_send(record)
        {
            self.shared.pending.fetch_sub(1, Ordering::AcqRel);
            self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `env_logger` writes each formatted record with one `write_all` into its
/// pipe target, so one `write` call is one record.
impl Write for Lossy {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.queue(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Write each record, first saying how many were dropped since the last
/// report.
fn drain_records(mut out: impl Write, rx: Receiver<Vec<u8>>, shared: &Shared) {
    let mut reported = 0u64;
    for record in rx {
        let dropped = shared.dropped.load(Ordering::Relaxed);
        if dropped > reported {
            let _ = writeln!(
                out,
                "velstra: {} log record(s) dropped while the log output was blocked",
                dropped - reported
            );
            reported = dropped;
        }
        let _ = out.write_all(&record);
        let _ = out.flush();
        shared.pending.fetch_sub(1, Ordering::Release);
    }
}

/// The agent's two outputs: log records (stderr) and the periodic
/// statistics table (stdout).
pub struct Outputs {
    pub log: Lossy,
    pub stats: Lossy,
}

impl Outputs {
    /// Both outputs, sized by `VELSTRA_LOG_QUEUE_LINES`.
    pub fn standard() -> Self {
        let lines = queue_lines(std::env::var("VELSTRA_LOG_QUEUE_LINES").ok().as_deref());
        Self {
            log: Lossy::new(io::stderr(), lines),
            stats: Lossy::new(io::stdout(), lines),
        }
    }
}

static INSTALLED: std::sync::OnceLock<Outputs> = std::sync::OnceLock::new();

/// The process's outputs, created on first use.
pub fn installed() -> &'static Outputs {
    INSTALLED.get_or_init(Outputs::standard)
}

/// Writes out what is still queued when dropped, bounded by
/// [`SHUTDOWN_FLUSH`]; held for the life of `main`.
pub struct FlushOnExit(pub Vec<Lossy>);

impl Drop for FlushOnExit {
    fn drop(&mut self) {
        let deadline = Instant::now() + SHUTDOWN_FLUSH;
        for output in &self.0 {
            output.flush_for(deadline.saturating_duration_since(Instant::now()));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// Output that blocks every write for `stall` — a journal that stopped
    /// reading — and records what it eventually receives.
    struct Stalled {
        stall: Duration,
        seen: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Stalled {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            std::thread::sleep(self.stall);
            self.seen.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn stalled(stall: Duration) -> (Stalled, Arc<Mutex<Vec<u8>>>) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let out = Stalled {
            stall,
            seen: Arc::clone(&seen),
        };
        (out, seen)
    }

    /// The HA heartbeat keeps its cadence while the log output is stalled: a
    /// 25 ms loop on a one-worker runtime that logs ten records per beat
    /// through the agent's logger never falls 100 ms behind. With the logger
    /// writing straight to the stalled output, every beat waited the stall
    /// out.
    #[test]
    fn heartbeat_keeps_its_cadence_while_the_log_output_is_stalled() {
        let (out, _) = stalled(Duration::from_secs(2));
        let logger = env_logger::Builder::new()
            .filter_level(log::LevelFilter::Info)
            .target(env_logger::Target::Pipe(Box::new(Lossy::new(out, 64))))
            .build();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let worst = runtime.block_on(async {
            let mut beat = tokio::time::interval(Duration::from_millis(25));
            let mut last = Instant::now();
            let mut worst = Duration::ZERO;
            for _ in 0..40 {
                beat.tick().await;
                let now = Instant::now();
                worst = worst.max(now - last);
                last = now;
                for _ in 0..10 {
                    log::Log::log(
                        &logger,
                        &log::Record::builder()
                            .level(log::Level::Info)
                            .target("velstra::ha")
                            .args(format_args!("heartbeat written"))
                            .build(),
                    );
                }
            }
            worst
        });
        assert!(
            worst < Duration::from_millis(100),
            "heartbeat gap {worst:?} under a stalled log"
        );
        assert!(
            dropped() > 0,
            "a stalled output must drop and count records"
        );
    }

    /// Dropped records are announced once the output drains, and every queued
    /// record is written whole.
    #[test]
    fn dropped_records_are_reported_when_the_output_drains() {
        let (out, seen) = stalled(Duration::from_millis(50));
        let mut writer = Lossy::new(out, 2);
        for i in 0..20 {
            writer
                .write_all(format!("record {i}\n").as_bytes())
                .unwrap();
        }
        writer.write_all(b"after the stall\n").unwrap();
        assert!(writer.flush_for(Duration::from_secs(10)));
        let text = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
        assert!(text.contains("record 0\n"), "{text}");
        assert!(
            text.contains("log record(s) dropped while the log output was blocked"),
            "{text}"
        );
    }

    #[test]
    fn the_queue_size_setting_is_clamped_and_defaults() {
        assert_eq!(queue_lines(None), QUEUE_LINES);
        assert_eq!(queue_lines(Some("nonsense")), QUEUE_LINES);
        assert_eq!(queue_lines(Some("0")), 1);
        assert_eq!(queue_lines(Some("1")), 1);
        assert_eq!(queue_lines(Some(" 100 ")), 100);
        assert_eq!(queue_lines(Some("10000000")), 65_536);
    }
}
