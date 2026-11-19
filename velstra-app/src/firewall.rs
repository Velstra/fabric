//! The control-plane side of the firewall: load the eBPF object, program the
//! maps from a [`RuntimeConfig`], attach the XDP hook, and read back per-CPU
//! statistics.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        Array, DevMap, HashMap, MapData, PerCpuArray, ProgramArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        ProgramError, Xdp, XdpMode,
        tc::{SchedClassifier, SchedClassifierLink, TcAttachType, qdisc_add_clsact},
        xdp::XdpLink,
    },
};
use clap::ValueEnum;
use log::warn;
use tokio::sync::Mutex;
use velstra_common::{
    Action, ArpEntry, ArpKey, Backend, CONFIG_FAILED, CONFIG_READY, CONFIG_UPDATING, CgnatLayout,
    Cidr4, Cidr6, ConfigFlags, Counter, FirewallKey, FirewallState, FloodSet, FlowKey, FlowState,
    GlobalConfig, IrbEndpoint, LocalMac, LocalMacKey, MAX_RULE_LIMITS, MacFdbKey, NdKey, Npt66,
    OverlayConfig, PORT_RULE_OUT_ONLY, PolicyId, PortAddr4, PortAddr6, PortBinding, PortFwd,
    PortalClientKey, PortalGate, PortalSeenKey, RateBucket, RouteEntry, ScopedAddr, ScopedAddr6,
    ScopedDstPortKey, ScopedDstPortKey6, ScopedMac, ScopedPortKey, ScopedSrcPortKey,
    ScopedSrcPortKey6, ServiceKey, ServiceValue, Srv6Config, Srv6Endpoint, Srv6FloodSet,
    Srv6IrbEndpoint, Srv6LocalSid, Srv6SidKey, SynFlow, SynProxyCfg, SynProxyKey, TunnelEndpoint,
    TunnelKey, parse_cidr_v4, parse_cidr_v6, parse_mac, port_rule_value,
};
use velstra_config::{
    PolicyConfig, PortIdentity, ResolvedFloodVtep, ResolvedInterface, ResolvedIrbRoute,
    ResolvedMacRoute, ResolvedNd6, ResolvedNeighbor, ResolvedNpt66, ResolvedPortForward,
    ResolvedRoute, ResolvedService, ResolvedSrv6, ResolvedSrv6Flood, ResolvedSrv6IrbRoute,
    ResolvedSrv6LocalSid, ResolvedSrv6Route, ResolvedSynProxy, ResolvedTunnel, RuntimeConfig,
};

/// Bounded diagnostics only: no timing sample participates in readiness,
/// authority, admission or timeout decisions. Logging happens on another
/// thread, never synchronously in a Firewall critical section.
pub(crate) mod timing {
    use std::{
        sync::{
            OnceLock,
            atomic::{AtomicU64, Ordering},
            mpsc::{SyncSender, sync_channel},
        },
        thread::ThreadId,
        time::Instant,
    };

    const SLOW_NS: u64 = 20_000_000;
    const REPORT_INTERVAL_NS: u64 = 1_000_000_000;
    const QUEUE_CAPACITY: usize = 64;
    // Diagnostic threshold only; unrelated to authority/freshness limits.
    const HEARTBEAT_REPORT_NS: u64 = 60_000_000;

    #[derive(Clone, Copy, Debug)]
    #[repr(usize)]
    pub(crate) enum Phase {
        ReconcileLockWait,
        ReconcileLockHold,
        HaLockWait,
        HaLockHold,
        HaStateLockWait,
        HaPolicy,
        HaGuards,
        HaReadRole,
        HaPublish,
        HaTickLateness,
        HaPublicationGap,
        Reload,
        HostPrepare,
        HostObserver,
        HostRevalidate,
        LocalAddressInsert,
        LocalAddressRevalidate,
        ReaderDrain,
        MapApply,
        FullTransaction,
    }
    const PHASE_COUNT: usize = Phase::FullTransaction as usize + 1;

    impl Phase {
        fn synchronous(self) -> bool {
            !matches!(
                self,
                Self::ReconcileLockWait
                    | Self::HaLockWait
                    | Self::HaLockHold
                    | Self::HaStateLockWait
                    | Self::HaTickLateness
                    | Self::HaPublicationGap
            )
        }
    }

    struct Budget {
        next: AtomicU64,
        suppressed: AtomicU64,
    }
    impl Budget {
        const fn new() -> Self {
            Self {
                next: AtomicU64::new(0),
                suppressed: AtomicU64::new(0),
            }
        }

        fn admit(&self, now: u64, elapsed: u64) -> Option<u64> {
            if elapsed < SLOW_NS || now == u64::MAX {
                return None;
            }
            let mut next = self.next.load(Ordering::Relaxed);
            loop {
                if now < next {
                    self.suppressed.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                match self.next.compare_exchange_weak(
                    next,
                    now.saturating_add(REPORT_INTERVAL_NS),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return Some(self.suppressed.swap(0, Ordering::Relaxed)),
                    Err(current) => next = current,
                }
            }
        }
    }

    static BUDGETS: [Budget; PHASE_COUNT] = [const { Budget::new() }; PHASE_COUNT];
    static REPORTER: OnceLock<Option<SyncSender<Report>>> = OnceLock::new();
    static DROPPED: AtomicU64 = AtomicU64::new(0);

    struct Report {
        phase: Phase,
        boot_start_ns: u64,
        boot_end_ns: u64,
        elapsed_ns: u64,
        thread_cpu_ns: Option<u64>,
        suppressed: u64,
        heartbeat: Option<HeartbeatReport>,
    }

    #[derive(Clone, Copy, Debug)]
    pub(crate) struct TickObservation {
        wait_entry_boot_ns: u64,
        resume_boot_before_ns: u64,
        resume_boot_after_ns: u64,
        nominal_lateness_ns: u64,
    }

    impl TickObservation {
        fn from_samples(
            wait_entry_boot_ns: u64,
            scheduled: tokio::time::Instant,
            resumed: tokio::time::Instant,
            resume_boot_before_ns: u64,
            resume_boot_after_ns: u64,
        ) -> Self {
            Self {
                wait_entry_boot_ns,
                resume_boot_before_ns,
                resume_boot_after_ns,
                nominal_lateness_ns: resumed
                    .saturating_duration_since(scheduled)
                    .as_nanos()
                    .min(u64::MAX as u128) as u64,
            }
        }

        fn valid(self) -> bool {
            self.wait_entry_boot_ns <= self.resume_boot_before_ns
                && self.resume_boot_before_ns <= self.resume_boot_after_ns
                && self.resume_boot_after_ns != u64::MAX
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct Publication {
        agent_updated_ns: u64,
        completed_observed_boot_ns: u64,
    }

    #[derive(Debug)]
    struct HeartbeatReport {
        tick: TickObservation,
        previous: Option<Publication>,
        current: Option<Publication>,
        completion_gap_ns: Option<u64>,
    }

    #[derive(Default)]
    pub(crate) struct Heartbeat {
        previous: Option<Publication>,
    }

    impl Heartbeat {
        pub(crate) fn tick(
            &self,
            wait_entry_boot_ns: u64,
            scheduled: tokio::time::Instant,
        ) -> TickObservation {
            // BOOTTIME brackets the resumed Instant sample. Do not subtract
            // different clock domains or pretend the samples are simultaneous.
            let before = crate::ha::now_ns();
            let resumed = tokio::time::Instant::now();
            let after = crate::ha::now_ns();
            let tick = TickObservation::from_samples(
                wait_entry_boot_ns,
                scheduled,
                resumed,
                before,
                after,
            );
            report_heartbeat(
                Phase::HaTickLateness,
                // Also report a long cross-clock sampling bracket: a vCPU
                // pause after the Instant read must not vanish from evidence.
                tick.nominal_lateness_ns.max(after.saturating_sub(before)),
                HeartbeatReport {
                    tick,
                    previous: self.previous,
                    current: None,
                    completion_gap_ns: None,
                },
            );
            tick
        }

        pub(crate) fn published(&mut self, tick: TickObservation, agent_updated_ns: u64) {
            self.published_at(tick, agent_updated_ns, crate::ha::now_ns());
        }

        fn published_at(&mut self, tick: TickObservation, agent_updated_ns: u64, completed: u64) {
            if !tick.valid()
                || completed == u64::MAX
                || completed < tick.resume_boot_after_ns
                || completed < agent_updated_ns
                || self.previous.is_some_and(|previous| {
                    completed < previous.completed_observed_boot_ns
                        || agent_updated_ns < previous.agent_updated_ns
                })
            {
                return;
            }
            let current = Publication {
                agent_updated_ns,
                completed_observed_boot_ns: completed,
            };
            let gap = self
                .previous
                .and_then(|previous| completed.checked_sub(previous.completed_observed_boot_ns));
            report_heartbeat(
                Phase::HaPublicationGap,
                gap.unwrap_or(0),
                HeartbeatReport {
                    tick,
                    previous: self.previous,
                    current: Some(current),
                    completion_gap_ns: gap,
                },
            );
            self.previous = Some(current);
        }
    }

    fn report_heartbeat(phase: Phase, metric: u64, heartbeat: HeartbeatReport) {
        if !heartbeat_reportable(heartbeat.tick, metric) {
            return;
        }
        let Some(Some(sender)) = REPORTER.get() else {
            return;
        };
        let end = heartbeat
            .current
            .map_or(heartbeat.tick.resume_boot_after_ns, |publication| {
                publication.completed_observed_boot_ns
            });
        let Some(suppressed) = BUDGETS[phase as usize].admit(end, metric) else {
            return;
        };
        let report = Report {
            phase,
            boot_start_ns: heartbeat.tick.wait_entry_boot_ns,
            boot_end_ns: end,
            elapsed_ns: metric,
            thread_cpu_ns: None,
            suppressed,
            heartbeat: Some(heartbeat),
        };
        if sender.try_send(report).is_err() {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn heartbeat_reportable(tick: TickObservation, metric: u64) -> bool {
        metric >= HEARTBEAT_REPORT_NS && tick.valid()
    }

    pub(crate) fn initialize() {
        REPORTER.get_or_init(|| {
            let (sender, receiver) = sync_channel::<Report>(QUEUE_CAPACITY);
            match std::thread::Builder::new()
                .name("ha-timing-log".into())
                .spawn(move || {
                    while let Ok(report) = receiver.recv() {
                        let dropped = DROPPED.swap(0, Ordering::Relaxed);
                        if let Some(heartbeat) = report.heartbeat {
                            log::info!(target: "velstra::ha_timing",
                                "heartbeat phase={:?} wait_entry_boot_ns={} resume_boot_before_ns={} resume_boot_after_ns={} nominal_lateness_ns={} previous_agent_updated_ns={:?} previous_completed_observed_boot_ns={:?} agent_updated_ns={:?} completed_observed_boot_ns={:?} completion_gap_ns={:?} suppressed={} queue_dropped={}",
                                report.phase, heartbeat.tick.wait_entry_boot_ns,
                                heartbeat.tick.resume_boot_before_ns, heartbeat.tick.resume_boot_after_ns,
                                heartbeat.tick.nominal_lateness_ns,
                                heartbeat.previous.map(|p| p.agent_updated_ns),
                                heartbeat.previous.map(|p| p.completed_observed_boot_ns),
                                heartbeat.current.map(|p| p.agent_updated_ns),
                                heartbeat.current.map(|p| p.completed_observed_boot_ns),
                                heartbeat.completion_gap_ns, report.suppressed, dropped);
                        } else {
                            log::info!(target: "velstra::ha_timing",
                            "slow phase={:?} boot_start_ns={} boot_end_ns={} elapsed_ns={} thread_cpu_ns={:?} suppressed={} queue_dropped={}",
                            report.phase, report.boot_start_ns, report.boot_end_ns,
                            report.elapsed_ns, report.thread_cpu_ns, report.suppressed, dropped);
                        }
                    }
                }) {
                Ok(_) => Some(sender),
                Err(error) => {
                    log::warn!("HA timing diagnostics unavailable: {error}");
                    None
                }
            }
        });
    }

    fn thread_cpu_ns() -> Option<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: time points to initialized, writable timespec storage.
        if unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) } != 0 {
            return None;
        }
        Some(
            (time.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(time.tv_nsec as u64),
        )
    }

    pub(crate) struct Span {
        phase: Phase,
        start: Instant,
        boot_start_ns: u64,
        cpu_start_ns: Option<u64>,
        thread: ThreadId,
    }
    impl Span {
        pub(crate) fn start(phase: Phase) -> Self {
            Self {
                phase,
                start: Instant::now(),
                boot_start_ns: crate::ha::now_ns(),
                cpu_start_ns: thread_cpu_ns(),
                thread: std::thread::current().id(),
            }
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            let elapsed_ns = self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            let Some(Some(sender)) = REPORTER.get() else {
                return;
            };
            let boot_end_ns = crate::ha::now_ns();
            if self.boot_start_ns == u64::MAX {
                return;
            }
            let Some(suppressed) = BUDGETS[self.phase as usize].admit(boot_end_ns, elapsed_ns)
            else {
                return;
            };
            // Never attribute other executor tasks' CPU time to an async
            // waiter, even if it resumes on the same worker. Synchronous
            // phases additionally require the same OS thread at both ends.
            let thread_cpu_ns = (self.phase.synchronous()
                && self.thread == std::thread::current().id())
            .then(thread_cpu_ns)
            .flatten()
            .zip(self.cpu_start_ns)
            .and_then(|(after, before)| after.checked_sub(before));
            let report = Report {
                phase: self.phase,
                boot_start_ns: self.boot_start_ns,
                boot_end_ns,
                elapsed_ns,
                thread_cpu_ns,
                suppressed,
                heartbeat: None,
            };
            if sender.try_send(report).is_err() {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn tick_sample(lateness: u64) -> TickObservation {
            let scheduled = tokio::time::Instant::now();
            TickObservation::from_samples(
                1_000,
                scheduled,
                scheduled + std::time::Duration::from_nanos(lateness),
                2_000,
                2_010,
            )
        }

        #[test]
        fn heartbeat_lateness_uses_nominal_tick_not_normal_wait_duration() {
            let on_time = tick_sample(0);
            assert_eq!(on_time.nominal_lateness_ns, 0);
            assert!(!heartbeat_reportable(on_time, on_time.nominal_lateness_ns));
            let delayed = tick_sample(60_000_000);
            assert_eq!(delayed.nominal_lateness_ns, 60_000_000);
            assert!(heartbeat_reportable(delayed, delayed.nominal_lateness_ns));
            assert!(!heartbeat_reportable(delayed, HEARTBEAT_REPORT_NS - 1));
            assert!(!Phase::HaTickLateness.synchronous());
            assert!(!Phase::HaPublicationGap.synchronous());
        }

        #[test]
        fn heartbeat_retains_cross_clock_bounds_without_inventing_exact_boot_deadline() {
            let mut tick = tick_sample(0);
            tick.resume_boot_after_ns += HEARTBEAT_REPORT_NS;
            assert_eq!(tick.nominal_lateness_ns, 0);
            assert!(heartbeat_reportable(
                tick,
                tick.resume_boot_after_ns - tick.resume_boot_before_ns
            ));
            tick.resume_boot_after_ns = u64::MAX;
            assert!(!heartbeat_reportable(tick, HEARTBEAT_REPORT_NS));
            tick.resume_boot_after_ns = tick.resume_boot_before_ns - 1;
            assert!(!heartbeat_reportable(tick, HEARTBEAT_REPORT_NS));
        }

        #[test]
        fn heartbeat_publication_tracks_only_successful_valid_completion_observations() {
            let tick = tick_sample(0);
            let mut heartbeat = Heartbeat::default();
            assert!(heartbeat.previous.is_none());
            heartbeat.published_at(tick, 2_020, 2_030);
            assert_eq!(heartbeat.previous.unwrap().agent_updated_ns, 2_020);
            // Caller does not invoke published on write failure. A failed
            // diagnostic clock also cannot overwrite the successful baseline.
            heartbeat.published_at(tick, 2_040, u64::MAX);
            assert_eq!(
                heartbeat.previous.unwrap().completed_observed_boot_ns,
                2_030
            );
            heartbeat.published_at(tick, 2_050, 2_040);
            assert_eq!(
                heartbeat.previous.unwrap().completed_observed_boot_ns,
                2_030
            );
            heartbeat.published_at(tick, 62_000_000, 62_000_010);
            let previous = heartbeat.previous.unwrap();
            assert_eq!(previous.agent_updated_ns, 62_000_000);
            assert_eq!(previous.completed_observed_boot_ns, 62_000_010);
            heartbeat.published_at(tick, 62_000_000, 62_000_009);
            assert_eq!(
                heartbeat.previous.unwrap().completed_observed_boot_ns,
                62_000_010
            );
            heartbeat.published_at(tick, 61_999_999, 62_000_020);
            assert_eq!(heartbeat.previous.unwrap().agent_updated_ns, 62_000_000);
            assert_eq!(
                heartbeat.previous.unwrap().completed_observed_boot_ns,
                62_000_010
            );
        }

        #[test]
        fn timing_threshold_does_not_spend_slow_report_budget() {
            let budget = Budget::new();
            assert_eq!(budget.admit(7, SLOW_NS - 1), None);
            assert_eq!(budget.admit(7, SLOW_NS), Some(0));
            assert_eq!(budget.admit(8, SLOW_NS), None);
            assert_eq!(budget.admit(7 + REPORT_INTERVAL_NS, SLOW_NS), Some(1));
        }

        #[test]
        fn timing_rate_limit_counts_suppressed_without_extending_window() {
            let budget = Budget::new();
            assert_eq!(budget.admit(100, SLOW_NS), Some(0));
            for tick in 101..201 {
                assert_eq!(budget.admit(tick, SLOW_NS), None);
            }
            assert_eq!(budget.admit(100 + REPORT_INTERVAL_NS, SLOW_NS), Some(100));
            assert_eq!(budget.admit(100 + 2 * REPORT_INTERVAL_NS, SLOW_NS), Some(0));
        }

        #[test]
        fn timing_failed_clock_never_consumes_or_overflows_budget() {
            let budget = Budget::new();
            assert_eq!(budget.admit(u64::MAX, SLOW_NS), None);
            assert_eq!(budget.admit(u64::MAX - 1, SLOW_NS), Some(0));
            assert_eq!(budget.admit(u64::MAX - 1, SLOW_NS), None);
        }

        #[test]
        fn timing_queue_is_bounded_and_does_not_wait_for_consumer() {
            let (sender, _receiver) = sync_channel(QUEUE_CAPACITY);
            for value in 0..QUEUE_CAPACITY {
                assert!(sender.try_send(value).is_ok());
            }
            assert!(matches!(
                sender.try_send(QUEUE_CAPACITY),
                Err(std::sync::mpsc::TrySendError::Full(_))
            ));
        }

        #[test]
        fn timing_async_phases_never_attribute_executor_cpu_to_waiter() {
            for phase in [
                Phase::ReconcileLockWait,
                Phase::HaLockWait,
                Phase::HaLockHold,
                Phase::HaStateLockWait,
            ] {
                assert!(!phase.synchronous());
            }
            for phase in [
                Phase::HostObserver,
                Phase::MapApply,
                Phase::ReaderDrain,
                Phase::ReconcileLockHold,
            ] {
                assert!(phase.synchronous());
            }
        }
    }
}

/// Duplicated diagnostic FDs and their policy names. Reading per-CPU maps can
/// be expensive at capacity; do it off the async executor and outside the HA
/// configuration mutex. The firewall retains ownership of the actual maps.
pub struct RuleCounterSnapshot {
    counters: aya::maps::PerCpuHashMap<
        MapData,
        velstra_common::RuleCounterKey,
        velstra_common::RuleCounters,
    >,
    lost: aya::maps::PerCpuArray<MapData, u64>,
    names: BTreeMap<(u32, u32), String>,
}
impl RuleCounterSnapshot {
    pub fn read(&self, limit: usize) -> Result<serde_json::Value> {
        let mut rows = Vec::new();
        let mut total = 0;
        for item in self.counters.iter() {
            let (key, per_cpu) = item?;
            total += 1;
            if rows.len() >= limit {
                continue;
            }
            let mut totals = velstra_common::RuleCounters::default();
            for counter in per_cpu.iter() {
                totals.packets = totals.packets.wrapping_add(counter.packets);
                totals.bytes = totals.bytes.wrapping_add(counter.bytes);
                totals.accepted = totals.accepted.wrapping_add(counter.accepted);
                totals.dropped = totals.dropped.wrapping_add(counter.dropped);
            }
            rows.push(serde_json::json!({"policy":key.policy,"rule_id":key.rule_id,"rule":self.names.get(&(key.policy,key.rule_id)),
                "packets":totals.packets,"bytes":totals.bytes,"accepted":totals.accepted,"dropped":totals.dropped}));
        }
        rows.sort_by_key(|row| (row["policy"].as_u64(), row["rule_id"].as_u64()));
        let lost = self.lost.get(&0, 0)?.iter().copied().sum::<u64>();
        Ok(
            serde_json::json!({"rules":rows,"events_lost":lost,"total_rules":total,"sample_limit":limit}),
        )
    }
}

/// How to attach the XDP program to the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AttachMode {
    /// Try native driver mode, then fall back to the generic SKB path.
    Auto,
    /// Native driver (`XDP_FLAGS_DRV_MODE`) — fast; needs driver support.
    Driver,
    /// Generic / SKB mode — works everywhere, slower (runs after `sk_buff`
    /// allocation). The usual choice for veth, bridges and dev laptops.
    Skb,
    /// Hardware offload (`XDP_FLAGS_HW_MODE`) — rare, SmartNIC only.
    Hw,
}

impl AttachMode {
    /// The ordered list of concrete [`XdpMode`]s to try for this preference.
    fn candidates(self) -> &'static [XdpMode] {
        match self {
            AttachMode::Auto => &[XdpMode::Driver, XdpMode::Skb],
            AttachMode::Driver => &[XdpMode::Driver],
            AttachMode::Skb => &[XdpMode::Skb],
            AttachMode::Hw => &[XdpMode::Hardware],
        }
    }
}

/// An attachment owns its kernel link instead of leaving it in Aya's program
/// collection. Removing a stale interface drops the link and closes its FD.
///
/// A **pinned** attachment (`[state] persist`) outlives the process: closing
/// the FD leaves it attached. Dropping one therefore also removes its pin —
/// that is what retiring a hook means — unless the agent is shutting down for
/// a restart, when [`Self::keep_pinned`] leaves the last policy enforcing.
struct InterfaceLink<L> {
    ifindex: u32,
    pin: Option<LinkPin>,
    _link: L,
}

/// A bpffs pin this agent owns, with the kernel id of the link behind it so a
/// newer pin at the same path is never removed by an older link's drop.
struct LinkPin {
    path: std::path::PathBuf,
    link_id: u32,
}

impl LinkPin {
    fn release(self) {
        let current = aya::programs::links::PinnedLink::from_pin(&self.path)
            .ok()
            .map(aya::programs::links::FdLink::from)
            .and_then(|link| link.info().ok())
            .map(|info| info.id());
        if current == Some(self.link_id)
            && let Err(error) = crate::persist::remove_pin(&self.path)
        {
            warn!(
                "could not detach retired hook {}: {error:#}",
                self.path.display()
            );
        }
    }
}

impl<L> Drop for InterfaceLink<L> {
    fn drop(&mut self) {
        if let Some(pin) = self.pin.take() {
            pin.release();
        }
    }
}

impl<L> InterfaceLink<L> {
    fn new(iface: &str, ifindex: u32, link: L) -> Result<Self> {
        Self::with_pin(iface, ifindex, link, None)
    }

    fn with_pin(iface: &str, ifindex: u32, link: L, pin: Option<LinkPin>) -> Result<Self> {
        // Constructed first, so a refusal below drops it and releases the pin.
        let this = Self {
            ifindex,
            pin,
            _link: link,
        };
        if if_nametoindex(iface)? != ifindex {
            bail!("interface {iface:?} changed while attaching its datapath");
        }
        Ok(this)
    }

    /// Leave this attachment in the kernel when the agent exits.
    fn keep_pinned(&mut self) {
        self.pin = None;
    }

    fn pin_path(&self) -> Option<&std::path::Path> {
        self.pin.as_ref().map(|pin| pin.path.as_path())
    }

    fn is_current(&self, iface: &str) -> bool {
        match if_nametoindex(iface) {
            Ok(index) => index == self.ifindex,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(interface_missing) =>
            {
                false
            }
            Err(error) => {
                // A failed observation is not evidence that a live firewall
                // should be detached. Retry the inventory on the next tick.
                warn!("checking datapath interface {iface} failed; retaining link: {error:#}");
                true
            }
        }
    }
}

/// A loaded-and-attached Velstra firewall.
///
/// Owns the [`Ebpf`] object and its interface links; dropping the firewall
/// detaches the programs and frees the maps. The XDP program therefore stays attached exactly as long as this value
/// (and hence the daemon) lives.
pub struct Firewall {
    ebpf: Ebpf,
    /// The interfaces the program is attached to and the [`XdpMode`] each
    /// attach succeeded with. Attaching to several interfaces from one process
    /// shares the maps (notably `CONNTRACK`) across them, which is what makes
    /// bidirectional NAT work: requests ingress one NIC, replies another.
    pub attached: Vec<(String, XdpMode)>,
    xdp_links: BTreeMap<String, InterfaceLink<XdpLink>>,
    primary: Vec<String>,
    attach_mode: AttachMode,
    /// The currently-applied config, kept so a live [`reconfigure`] can remove
    /// the entries that are no longer present before writing the new set.
    ///
    /// [`reconfigure`]: Firewall::reconfigure
    applied: RuntimeConfig,
    applied_host: PreparedHostConfig,
    applied_intent: AppliedIntent,
    last_apply_error: Option<String>,
    /// Exactly what the six policy tries hold, so a reconfigure writes only
    /// the difference (DP-28).
    tries: crate::policy_tries::PolicyTries,
    /// How the connection-state maps were sized at load (DP-06).
    sizing: crate::state_tables::Sizing,
    /// Whether those maps were adopted from the previous agent (DP-27).
    state_adopted: bool,
    /// The bpffs pin directory when `[state] persist` is on (DP-12, DP-27).
    persist: Option<crate::persist::Persist>,
    /// Where this agent's tail-call program arrays are pinned, when persisting.
    program_arrays: Option<std::path::PathBuf>,
    /// Consecutive polls whose host inventory was torn by a concurrent change
    /// even after [`crate::host_inventory::read`]'s own retries (DP-32).
    torn_inventory_polls: u32,
    /// The configuration as it arrived, before the advertised rules were merged
    /// into it.
    ///
    /// Kept apart from [`Self::applied`] because the two sources change
    /// independently: a config push must not lose the FlowSpec rules in force,
    /// and a FlowSpec update must not re-apply a config the operator has since
    /// replaced. Both paths rebuild the merge from these two, so whichever
    /// arrives last, the answer is the same.
    base: RuntimeConfig,
    /// Routes learned from Wren (`routes::follow`), merged under the static
    /// ones at every reprogram. Empty when nothing subscribes.
    dynamic_routes: Vec<velstra_config::ResolvedRoute>,
    /// The rules a BGP peer has asked this box to enforce (roadmap A3), already
    /// translated. Empty unless the FlowSpec task is running.
    flowspec: Vec<velstra_config::ResolvedRule>,
    /// What arrived over the same feed and is **not** being enforced, with the
    /// reason. Kept beside the rules rather than only logged: "a rule was
    /// advertised and is doing nothing" is the question somebody asks during an
    /// attack, and a journal that has rotated cannot answer it.
    flowspec_refused: Vec<(String, String)>,
    /// Packet events drained from the consume-once kernel ring, kept so every
    /// reader pages through them with its own cursor (see `packet_events`).
    packet_log: crate::packet_events::PacketEventLog,
    /// Tenant taps already carrying the TC BUM-replication classifier. Tracked
    /// because the attach is now re-tried on every reprogram — a tap that appears
    /// after startup has to be picked up — and attaching twice would put two
    /// classifiers on one ingress, replicating every broadcast frame twice.
    bum_attached: BTreeMap<String, InterfaceLink<SchedClassifierLink>>,
    /// TC egress classifiers installed for current interfaces. Controller-driven
    /// tenant taps appear after startup, so their firewall hook is reconciled.
    egress_attached: BTreeMap<String, InterfaceLink<SchedClassifierLink>>,
    /// Explicit --egress coverage survives interface disappearance/recreation.
    explicit_egress_ifaces: Vec<String>,
    /// Interfaces attached dynamically by auto-attach, tracked separately so they
    /// can be dropped again when the interface disappears (a VM tap going away).
    auto_attached: HashSet<String>,
    /// Interfaces attached because the **config** named them (e.g. pod veths the
    /// controller declared). Tracked separately from auto-attach so each is
    /// forgotten when its netdev disappears.
    config_attached: BTreeMap<String, u32>,
    /// Route egress devices can appear without being declared as firewall ports.
    route_ifindices: BTreeMap<String, u32>,
    /// Where the HA guard is installed: link name → the ifindex it went on.
    /// Kept here rather than in the HA monitor because a held link may come
    /// up only once the guard is on its *current* incarnation, and the one
    /// that raises it ([`Self::activate_held_links`]) has to be able to tell.
    ha_guarded: BTreeMap<String, u32>,
    /// The held links this agent raised or found up: link name → that ifindex.
    /// Once raised, that incarnation is the operator's: a `networkctl down`
    /// on it is respected by every reconcile that follows, and only an
    /// explicit hand-back ([`Self::dark_held_links`], the commit's
    /// `reconcile-links`) or a recreated link raises it again.
    raised: BTreeMap<String, u32>,
    /// The `CONNTRACK` handle once it has been moved out of [`Self::ebpf`],
    /// **shared** rather than given away: both the C9 sync task and the flow
    /// query path read it. Keeping it here is what stops enabling HA from taking
    /// the flow table away from every other reader.
    conntrack: Option<Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>>,
    /// Sources blocked at **run time** rather than by configuration, each with the
    /// moment it stops being blocked (roadmap C11: a detector acting on what it
    /// saw).
    ///
    /// Held here so `show`, expiry and the config reconcile all agree on which
    /// entries in `BLOCKLIST` the configuration did *not* put there. Deliberately
    /// **not persisted**: a block nobody wrote down must not outlive the process
    /// that decided on it, or an appliance ends up enforcing a reason no one can
    /// reconstruct. Restarting the agent is therefore always a way out.
    runtime_blocks: BTreeMap<String, Instant>,
    /// C20 captive-portal sessions: `(policy, MAC)` → the moment the device stops
    /// being admitted.
    ///
    /// Held here for the same reason as `runtime_blocks`, and deliberately not
    /// persisted for the mirror-image reason: a block that outlived the process
    /// that decided on it enforces a reason nobody can reconstruct, and an
    /// *admission* that outlived it would let a guest back onto the network after
    /// a restart nobody connected to their login. Restarting the agent ends every
    /// session, which is the correct way round.
    portal_sessions: BTreeMap<(PolicyId, [u8; 6]), Instant>,
    /// C18 port mappings opened at **run time** by a NAT-PMP/PCP request, keyed
    /// by `(policy, proto, external port)` and carrying the internal target and
    /// the moment the mapping closes.
    ///
    /// Not persisted, like the other two run-time tables — and here the reason is
    /// the sharpest of the three: a mapping is a hole a host on the inside asked
    /// for, and one that outlived the process that opened it would be an inbound
    /// port nobody can account for. A host that still wants it asks again, which
    /// is what the protocol has it do anyway.
    runtime_mappings: BTreeMap<MappingKey, MappingValue>,
}

/// Which hole: the zone policy it lives in, the protocol, and the WAN port.
type MappingKey = (PolicyId, u8, u16);

/// Where it points and until when: the inside address, its port, and the
/// deadline after which the hole closes on its own.
type MappingValue = ([u8; 4], u16, Instant);

/// The most run-time port mappings held at once.
///
/// `PORT_FORWARDS` holds 1024 entries and the operator's own forwards live in
/// the same table, so this is deliberately a small fraction of it: the failure
/// this prevents is a LAN host — a misbehaving one, or simply a busy one —
/// filling the map and leaving no room for a forward somebody configured.
const MAX_RUNTIME_MAPPINGS: usize = 256;

impl Firewall {
    /// Exercise the real kernel verifier for every shipped XDP/TC entry point.
    /// No packet hook is attached and dropping the object releases all maps.
    pub fn verify_object(object: Option<&[u8]>) -> Result<()> {
        bump_memlock_rlimit();
        let object = crate::btf::kernel_object(object.unwrap_or(aya::include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/velstra")
        )))?;
        let mut ebpf = Ebpf::load(&object).context("loading eBPF object for verification")?;
        let mut rejected = Vec::new();
        for name in [
            "velstra",
            "velstra_main",
            "velstra_v4_state",
            "velstra_guest_delivery",
            "velstra_forward",
            "velstra_v6",
            "velstra_local",
            "velstra_v6_state",
            "velstra_icmp_nat",
            "velstra_related",
        ] {
            let program: &mut Xdp = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("missing {name}"))?
                .try_into()?;
            match program.load() {
                Ok(()) => {
                    println!("verified {name}");
                    report_verified_insns(name, program.info());
                }
                Err(error) => rejected.push(format!("verifying {name}: {error:#}")),
            }
        }
        for name in [
            "velstra_egress",
            "velstra_egress_v4",
            "velstra_egress_v6",
            "velstra_egress_v6_state",
            "velstra_egress_v4_state",
            "velstra_masquerade",
            "velstra_egress_icmp",
            "velstra_deferred_snat",
            "velstra_related_egress",
            "velstra_related_egress_apply",
            "velstra_bum",
            "velstra_ha_guard",
        ] {
            let program: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("missing {name}"))?
                .try_into()?;
            match program.load() {
                Ok(()) => {
                    println!("verified {name}");
                    report_verified_insns(name, program.info());
                }
                Err(error) => rejected.push(format!("verifying {name}: {error:#}")),
            }
        }
        let exit: &mut aya::programs::RawTracePoint = ebpf
            .program_mut("velstra_ha_exit")
            .ok_or_else(|| anyhow!("missing velstra_ha_exit"))?
            .try_into()?;
        match exit.load() {
            Ok(()) => println!("verified velstra_ha_exit"),
            Err(error) => rejected.push(format!("verifying velstra_ha_exit: {error:#}")),
        }
        // Report every rejected entry point, not just the first. Never attach
        // anything, and never convert partial load success into exit status 0.
        if !rejected.is_empty() {
            bail!(
                "{} eBPF programs rejected:\n{}",
                rejected.len(),
                rejected.join("\n")
            );
        }
        Ok(())
    }

    /// Load the embedded eBPF object, program the maps from `cfg`, and attach
    /// to every interface in `ifaces`.
    ///
    /// Maps are populated **before** attaching so the very first packet already
    /// sees the full ruleset — there is no window where traffic is processed
    /// against empty maps.
    ///
    /// Requires `CAP_NET_ADMIN` / root and must run inside a Tokio runtime (it
    /// spawns the `aya-log` forwarding task).
    pub fn load_and_attach(
        ifaces: &[String],
        mode: AttachMode,
        cfg: &RuntimeConfig,
        egress: bool,
    ) -> Result<Self> {
        ensure_reader_barrier_supported()?;
        bump_memlock_rlimit();

        let object = crate::btf::kernel_object(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/velstra"
        )))?;
        let total_ram = crate::state_tables::host_memory().unwrap_or(0);
        let sizing = crate::state_tables::resolve(&cfg.state, total_ram);
        let state_maps = crate::persist::state_maps(&sizing);
        let root = std::path::Path::new(crate::persist::ROOT);
        let (persist, state_dir) = if cfg.state.persist {
            let persist = crate::persist::Persist::open(root)?;
            let identity: Vec<(String, u32)> = cfg
                .interfaces
                .iter()
                .map(|i| (i.name.clone(), i.policy))
                .collect();
            let tag = crate::persist::layout_tag(&state_maps, &identity);
            let dir = persist.prepare_state(&tag, &state_maps)?;
            (Some(persist), Some(dir))
        } else {
            // Persistence was switched off: what an earlier agent pinned would
            // keep enforcing (and refuse this agent's XDP attach) forever.
            if root.exists() {
                log::info!("releasing the datapath pinned by a previous agent");
                crate::persist::Persist::release(root)?;
            }
            (None, None)
        };
        log::info!(
            "state tables sized for {} connections ({} firewall, {} NAT, {} SYN-proxy entries; \
             {} MiB){}",
            sizing.connections,
            sizing.fw_flows,
            sizing.conntrack,
            sizing.syn_flows,
            sizing.committed_bytes() >> 20,
            if cfg.state.connections.is_none() {
                " from host memory"
            } else {
                ""
            }
        );
        let mut loader = aya::EbpfLoader::new();
        for (name, entries) in sizing.maps() {
            loader.map_max_entries(name, entries);
        }
        if let Some(dir) = &state_dir {
            crate::persist::Persist::apply(&mut loader, &dir.path, &state_maps);
        }
        if cfg.ha.is_some() {
            loader.map_pin_path("HA_DEADLINE", std::path::Path::new(crate::ha::DEADLINE_PIN));
            loader.map_pin_path("HA_OWNER", std::path::Path::new(crate::ha::OWNER_PIN));
        }
        let mut ebpf = loader
            .load(&object)
            .context("loading embedded eBPF object")?;
        // The guard goes on before anything is attached; the held links among
        // its links stay down until the firewall's own hooks are in place too.
        let mut ha_guarded = BTreeMap::new();
        if let Some(ha) = &cfg.ha {
            crate::ha::reconcile_interfaces(&mut ebpf, ha, &mut ha_guarded, |name| {
                is_held(&cfg.interfaces, name)
            })?;
        }

        spawn_log_forwarder(&mut ebpf);
        {
            let mut state: Array<_, u32> =
                Array::try_from(ebpf.map_mut("APPLY_STATE").ok_or_else(|| {
                    anyhow!("APPLY_STATE map missing; agent and datapath are incompatible")
                })?)?;
            state
                .set(0, CONFIG_UPDATING, 0)
                .context("closing the initial datapath gate")?;
        }
        let prepared = prepare_host_config(cfg)?;
        let plan = PolicyPlan::new(&ebpf, cfg, &prepared)?;
        let mut tries = crate::policy_tries::PolicyTries::default();
        // This object's ordinary packet programs have not been attached yet;
        // unlike a live rewrite, initialization has no readers to drain.
        apply_config_quiesced(
            &mut ebpf,
            cfg,
            None,
            &prepared,
            false,
            &ReaderQuiescence::Unattached,
            &plan,
            &mut tries,
        )?;

        // Load the tail-call target (`velstra_forward`) and register it in the
        // `VELSTRA_PROGS` program array, so the main program's
        // `tail_call(PROG_FORWARD)` resolves. It is loaded but never attached to
        // an interface — it only ever runs via the tail call out of `velstra`.
        // Done before the `velstra` mutable borrow below so the borrows don't
        // overlap, and before attach so the first packet already tail-calls.
        {
            let flow: &mut Xdp = ebpf
                .program_mut("velstra_forward")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_forward` program"))?
                .try_into()?;
            flow.load()
                .context("loading XDP forward program into the kernel")?;
        }
        // Clone the program fd to an owned handle so the immutable borrow on
        // `ebpf` ends before the map is borrowed mutably below.
        let flow_fd = {
            let flow: &Xdp = ebpf
                .program("velstra_forward")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_forward` program"))?
                .try_into()?;
            flow.fd()?.try_clone()?
        };
        // Same again for `velstra_main`, the datapath itself. Only the small
        // port-security gate (`velstra`) is attached to an interface; it tail-
        // calls straight into this one. The split exists because a call chain's
        // stack frames are summed against a single 512-byte limit and the two
        // together came to 528 — a tail call starts a fresh frame.
        {
            let main: &mut Xdp = ebpf
                .program_mut("velstra_main")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_main` program"))?
                .try_into()?;
            main.load()
                .context("loading XDP datapath program into the kernel")?;
        }
        let main_fd = {
            let main: &Xdp = ebpf
                .program("velstra_main")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_main` program"))?
                .try_into()?;
            main.fd()?.try_clone()?
        };
        {
            let delivery: &mut Xdp = ebpf
                .program_mut("velstra_guest_delivery")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_guest_delivery` program"))?
                .try_into()?;
            delivery
                .load()
                .context("loading XDP guest delivery program into the kernel")?;
        }
        let delivery_fd = {
            let delivery: &Xdp = ebpf
                .program("velstra_guest_delivery")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_guest_delivery` program"))?
                .try_into()?;
            delivery.fd()?.try_clone()?
        };
        {
            let mut prog_array = ProgramArray::try_from(
                ebpf.map_mut("VELSTRA_PROGS")
                    .ok_or_else(|| anyhow!("VELSTRA_PROGS map missing"))?,
            )?;
            prog_array
                .set(0, &flow_fd, 0)
                .context("registering velstra_forward in VELSTRA_PROGS")?;
            // Registered before the gate is attached, so the very first packet
            // already has somewhere to jump.
            prog_array
                .set(1, &main_fd, 0)
                .context("registering velstra_main in VELSTRA_PROGS")?;
            prog_array
                .set(6, &delivery_fd, 0)
                .context("registering guest delivery in VELSTRA_PROGS")?;
        }

        for (slot, name) in [
            (2, "velstra_v6"),
            (3, "velstra_local"),
            (4, "velstra_v6_state"),
            (5, "velstra_icmp_nat"),
            (7, "velstra_related"),
        ] {
            let fd = {
                let program: &mut Xdp = ebpf
                    .program_mut(name)
                    .ok_or_else(|| anyhow!("missing {name}"))?
                    .try_into()?;
                program.load().with_context(|| format!("loading {name}"))?;
                program.fd()?.try_clone()?
            };
            let mut programs = ProgramArray::try_from(
                ebpf.map_mut("VELSTRA_PROGS")
                    .ok_or_else(|| anyhow!("VELSTRA_PROGS missing"))?,
            )?;
            programs.set(slot, &fd, 0)?;
        }

        // Register the state-admission continuation before attaching ingress.
        // A missing stage is fatal: skipping it would bypass the final verdict
        // and conntrack publication rather than merely an optional transform.
        {
            let fd = {
                let program: &mut Xdp = ebpf
                    .program_mut("velstra_v4_state")
                    .ok_or_else(|| anyhow!("missing velstra_v4_state"))?
                    .try_into()?;
                program
                    .load()
                    .context("loading IPv4 state-admission stage")?;
                program.fd()?.try_clone()?
            };
            let mut programs = ProgramArray::try_from(
                ebpf.map_mut("V4_STATE_PROGS")
                    .ok_or_else(|| anyhow!("V4_STATE_PROGS missing"))?,
            )?;
            programs.set(0, &fd, 0)?;
        }

        // Before anything is attached: from here on a dead agent's links must
        // still find their tail-call targets.
        let program_arrays = persist
            .as_ref()
            .map(|persist| persist.pin_program_arrays(&ebpf))
            .transpose()?;
        // Link-layer framing before the first packet can reach the program.
        for name in ifaces {
            program_link_layer(&mut ebpf, name)?;
        }
        // The policy is programmed and every ingress tail call registered, so
        // open the gate before attaching. A fresh attach sees no packet before
        // this point either way; an ADOPTED link runs the new program the
        // instant it is swapped in, and a gate still closed until the end of
        // start-up dropped all traffic for the seconds the egress programs
        // took to load (measured: a 3.2 s TCP stall across a restart).
        Array::<_, u32>::try_from(
            ebpf.map_mut("APPLY_STATE")
                .ok_or_else(|| anyhow!("APPLY_STATE map missing"))?,
        )?
        .set(0, CONFIG_READY, 0)
        .context("opening the datapath gate before attaching")?;
        let program: &mut Xdp = ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        program
            .load()
            .context("loading XDP program into the kernel")?;

        let mut attached = Vec::with_capacity(ifaces.len());
        let mut xdp_links = BTreeMap::new();
        for iface in ifaces {
            if xdp_links.contains_key(iface) {
                continue;
            }
            let (chosen, link) = attach_with_fallback(program, iface, mode, persist.as_ref())?;
            xdp_links.insert(iface.clone(), link);
            attached.push((iface.clone(), chosen));
        }

        // Which interfaces need the TC egress hook, and why — see
        // [`egress_interfaces`]. Kept out of here so the rule can be read and
        // tested without loading an eBPF object.
        let egress_ifaces: Vec<String> = egress_interfaces(cfg, ifaces, egress)
            .into_iter()
            .filter(|n| if_nametoindex(n).is_ok())
            .collect();
        let egress_attached = if egress_ifaces.is_empty() {
            BTreeMap::new()
        } else {
            attach_egress(&mut ebpf, &egress_ifaces, persist.as_ref())?
        };

        let config_attached = cfg
            .interfaces
            .iter()
            .filter(|i| attached.iter().any(|(name, _)| name == &i.name))
            .filter_map(|i| {
                if_nametoindex(&i.name)
                    .ok()
                    .map(|index| (i.name.clone(), index))
            })
            .collect();
        let mut fw = Self {
            ha_guarded,
            raised: BTreeMap::new(),
            ebpf,
            attached,
            xdp_links,
            primary: ifaces.to_vec(),
            attach_mode: mode,
            applied: cfg.clone(),
            applied_host: prepared.clone(),
            applied_intent: AppliedIntent { current: true },
            last_apply_error: None,
            base: cfg.clone(),
            flowspec: Vec::new(),
            dynamic_routes: Vec::new(),
            flowspec_refused: Vec::new(),
            // The run's start time: distinct across restarts, which is all a
            // reader needs to know its cursor belongs to a previous run.
            packet_log: crate::packet_events::PacketEventLog::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_nanos() as u64),
            ),
            auto_attached: HashSet::new(),
            config_attached,
            route_ifindices: prepared.route_ifindices,
            bum_attached: BTreeMap::new(),
            egress_attached,
            explicit_egress_ifaces: if egress { ifaces.to_vec() } else { Vec::new() },
            conntrack: None,
            torn_inventory_polls: 0,
            tries,
            sizing,
            state_adopted: state_dir.as_ref().is_some_and(|dir| dir.adopted),
            persist,
            program_arrays,
            runtime_blocks: BTreeMap::new(),
            portal_sessions: BTreeMap::new(),
            runtime_mappings: BTreeMap::new(),
        };
        fw.sync_bum_attachments(cfg);
        fw.reopen_configuration()?;
        fw.reconcile_links()?;
        fw.sweep_unheld_pins();
        Ok(fw)
    }

    /// Remove every link pin no current attachment holds: hooks the previous
    /// agent had on interfaces this configuration no longer filters.
    fn sweep_unheld_pins(&self) {
        let Some(persist) = &self.persist else {
            return;
        };
        let held: HashSet<&std::path::Path> = self
            .xdp_links
            .values()
            .filter_map(InterfaceLink::pin_path)
            .chain(
                self.egress_attached
                    .values()
                    .filter_map(InterfaceLink::pin_path),
            )
            .collect();
        match persist.link_pins() {
            Ok(pins) => {
                for (_, iface, path) in pins {
                    if held.contains(path.as_path()) {
                        continue;
                    }
                    log::info!(
                        "detaching the previous agent's hook on {iface}: no longer configured"
                    );
                    if let Err(error) = crate::persist::remove_pin(&path) {
                        warn!("{error:#}");
                    }
                }
            }
            Err(error) => warn!("listing pinned hooks: {error:#}"),
        }
        if let Some(keep) = &self.program_arrays
            && let Err(error) = persist.sweep_program_arrays(keep)
        {
            warn!("removing the previous agent's program arrays: {error:#}");
        }
    }

    /// Leave every pinned hook attached and enforcing when this process exits,
    /// so the next agent adopts them instead of a link forwarding unfiltered
    /// in between (DP-12). A no-op unless persisting.
    pub fn keep_attached_for_restart(&mut self) {
        if self.persist.is_none() {
            return;
        }
        let mut kept = 0;
        for link in self.xdp_links.values_mut() {
            kept += usize::from(link.pin.is_some());
            link.keep_pinned();
        }
        for link in self.egress_attached.values_mut() {
            kept += usize::from(link.pin.is_some());
            link.keep_pinned();
        }
        log::info!("leaving {kept} pinned hook(s) enforcing for the next agent");
    }

    /// How the connection-state tables were sized, and whether they were
    /// adopted from the previous agent.
    pub fn state_tables(&self) -> (crate::state_tables::Sizing, bool) {
        (self.sizing, self.state_adopted)
    }

    /// A duplicate FD of one connection-state map, for the background
    /// collector: it walks the map without the firewall lock.
    pub fn state_map(&self, name: &str) -> Result<MapData> {
        let Some(aya::maps::Map::LruHashMap(data)) = self.ebpf.map(name) else {
            bail!("{name} LRU map missing");
        };
        Ok(MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?)
    }

    /// The applied conntrack timeouts, which decide what has expired.
    pub fn conntrack_timeouts(&self) -> velstra_common::ConntrackTimeouts {
        self.applied.conntrack
    }

    pub fn reconcile_links(&mut self) -> Result<()> {
        let present = std::fs::read_dir("/sys/class/net")?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<std::io::Result<Vec<String>>>()?;
        self.reconcile_config_interfaces(&present, self.attach_mode);
        let desired = self.applied.clone();
        self.sync_egress_attachments(&desired)?;
        self.retire_egress_attachments(&desired);
        anyhow::ensure!(
            self.configuration_state()? == CONFIG_READY,
            "{}",
            self.configuration_status()?
        );
        for iface in self.primary.clone() {
            if if_nametoindex(&iface).is_ok() && !self.xdp_links.contains_key(&iface) {
                self.attach_iface(&iface, self.attach_mode, 0)?;
            }
        }
        Ok(())
    }

    fn prune_stale_links(&mut self) {
        self.xdp_links.retain(|name, link| link.is_current(name));
        self.bum_attached.retain(|name, link| link.is_current(name));
        self.egress_attached
            .retain(|name, link| link.is_current(name));
        self.attached
            .retain(|(name, _)| self.xdp_links.contains_key(name));
    }

    /// Attach the BUM head-end replication classifier to every tenant tap the
    /// config names that is present and not already carrying it.
    ///
    /// **Called on every reprogram, not only at startup**, and that is the whole
    /// point. A config-file agent is restarted by `sentinel commit`, so its taps
    /// are always present when it loads; a controller-driven agent is
    /// reconfigured *live* and its taps arrive minutes later, when a tenant is
    /// placed on it. Attaching only at load therefore left every controller-driven
    /// fabric with its flood set programmed, its counters present, and no
    /// classifier to read them — `bum_replicated` and `srv6_bum_replicated` stuck
    /// at zero for the life of the process, on both overlays.
    ///
    /// That failure is invisible from the box: nothing errors, the maps are
    /// correct, and the only symptom is that broadcast traffic does not cross —
    /// so a tenant cannot ARP or get a DHCP lease, which reads like a tenant
    /// problem rather than an agent one.
    ///
    /// Best-effort by design: a load or attach failure costs replication and
    /// nothing else, where taking the agent down would cost the firewall.
    fn sync_bum_attachments(&mut self, cfg: &RuntimeConfig) {
        // Either overlay: `velstra_bum` dispatches on whichever is enabled, and
        // gating the attach on the VXLAN one alone left an SRv6 host without a
        // classifier at all.
        if cfg.overlay.is_none() && cfg.srv6.is_none() {
            self.bum_attached.clear();
            return;
        }
        // Forget taps whose netdev has gone (the TC classifier detached with it).
        // Without this, a VM restart that brings the tap back under the same name
        // leaves the stale name in the set, so the `wanted` filter below skips it
        // and it never gets a classifier again — `bum_replicated`/`srv6_bum_replicated`
        // stall until the agent restarts. Mirrors how `reconcile_auto_attach` and
        // `reconcile_config_interfaces` prune their attach sets.
        self.bum_attached.retain(|name, link| link.is_current(name));
        let wanted: Vec<(String, u32)> = cfg
            .interfaces
            .iter()
            .filter(|i| i.vni != 0 && !self.bum_attached.contains_key(&i.name))
            .filter(|i| {
                std::fs::read_to_string(format!("/sys/class/net/{}/type", i.name))
                    .ok()
                    .and_then(|v| v.trim().parse().ok())
                    .is_some_and(|kind| !raw_ip_link(kind))
            })
            .filter_map(|i| {
                if_nametoindex(&i.name)
                    .ok()
                    .map(|index| (i.name.clone(), index))
            })
            .collect();
        if wanted.is_empty() {
            return;
        }
        match attach_bum_ingress(
            &mut self.ebpf,
            &wanted
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>(),
        ) {
            Ok(links) => self.bum_attached.extend(links),
            Err(e) => warn!("BUM replication attach failed: {e:#}"),
        }
    }

    /// A newly declared tenant tap needs the egress classifier before its
    /// policy is programmed. Otherwise ingress allowances and default-deny
    /// rules exist in maps but no hook ever evaluates packets bound for it.
    fn egress_candidates(&self, cfg: &RuntimeConfig) -> Vec<String> {
        let mut names = self.explicit_egress_ifaces.clone();
        if cfg
            .policies
            .iter()
            .any(|p| p.global.has_flag(ConfigFlags::STATEFUL))
        {
            for (name, _) in &self.attached {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        names
    }

    fn sync_egress_attachments(&mut self, cfg: &RuntimeConfig) -> Result<()> {
        // A tap can disappear and return under the same name between two
        // config updates. Its old classifier vanished with the old ifindex.
        let desired = egress_interfaces(cfg, &self.egress_candidates(cfg), true);
        // Keep every old hook until either the complete candidate or the old
        // configuration has been installed. Detaching a removed tenant's TC
        // hook here bypasses its closed gate during a failed update.
        self.egress_attached
            .retain(|name, link| link.is_current(name));
        let wanted: Vec<(String, u32)> = desired
            .into_iter()
            .filter(|name| !self.egress_attached.contains_key(name))
            .filter_map(|name| if_nametoindex(&name).ok().map(|index| (name, index)))
            .collect();
        if !wanted.is_empty() {
            let links = attach_egress(
                &mut self.ebpf,
                &wanted
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect::<Vec<_>>(),
                self.persist.as_ref(),
            )?;
            self.egress_attached.extend(links);
        }
        Ok(())
    }

    /// Retire obsolete hooks only after map application or rollback succeeds.
    fn retire_egress_attachments(&mut self, cfg: &RuntimeConfig) {
        let desired = egress_interfaces(cfg, &self.egress_candidates(cfg), true);
        self.egress_attached
            .retain(|name, link| desired.contains(name) && link.is_current(name));
    }

    /// Attach the (already-loaded) program to one more interface and assign it a
    /// policy. Used by both startup and auto-attach.
    pub fn attach_iface(
        &mut self,
        iface: &str,
        mode: AttachMode,
        policy_id: PolicyId,
    ) -> Result<XdpMode> {
        program_link_layer(&mut self.ebpf, iface)?;
        {
            let ifindex = if_nametoindex(iface)?;
            let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
                self.ebpf
                    .map_mut("IFACE_POLICY")
                    .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
            )?;
            iface_policy
                .insert(ifindex, policy_id, 0)
                .with_context(|| format!("assigning {iface} to policy {policy_id}"))?;
        }
        let program: &mut Xdp = self
            .ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        let (chosen, link) = attach_with_fallback(program, iface, mode, self.persist.as_ref())?;
        self.xdp_links.insert(iface.to_owned(), link);
        self.attached.push((iface.to_string(), chosen));
        Ok(chosen)
    }

    /// Reconcile auto-attach against the current set of `present` interfaces:
    /// attach any new interface whose name starts with `prefix`, and drop any
    /// previously auto-attached interface that has since disappeared.
    ///
    /// A newly-attached interface gets the policy from the config's interface
    /// assignments if listed, else `default_policy`.
    pub fn reconcile_auto_attach(
        &mut self,
        present: &[String],
        prefix: &str,
        mode: AttachMode,
        default_policy: PolicyId,
    ) {
        self.prune_stale_links();
        // Collect new candidates first (ends the immutable borrow before we mutate).
        let candidates: Vec<(String, PolicyId)> = present
            .iter()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| !self.attached.iter().any(|(n, _)| n == *name))
            .map(|name| {
                let policy = self
                    .applied
                    .interfaces
                    .iter()
                    .find(|i| i.name == *name)
                    .map(|i| i.policy)
                    .unwrap_or(default_policy);
                (name.clone(), policy)
            })
            .collect();
        for (name, policy) in candidates {
            match self.attach_iface(&name, mode, policy) {
                Ok(chosen) => {
                    self.auto_attached.insert(name.clone());
                    log::info!("auto-attached {name} -> policy {policy} ({chosen:?})");
                }
                Err(e) => warn!("auto-attach {name} failed: {e:#}"),
            }
        }

        // Drop auto-attached interfaces that have gone away (the XDP link
        // detached with the interface; we just forget it so a recreated
        // same-named interface re-attaches).
        let gone: Vec<String> = self
            .auto_attached
            .iter()
            .filter(|n| !self.xdp_links.contains_key(*n))
            .cloned()
            .collect();
        for name in gone {
            self.auto_attached.remove(&name);
            self.attached.retain(|(n, _)| n != &name);
            log::info!("auto-detached {name} (interface gone)");
        }
    }

    /// Attach the (already-loaded) program to one **config-named** interface,
    /// programming its policy AND overlay VNI before attaching so the first
    /// packet already sees both.
    fn attach_config_iface(
        &mut self,
        iface: &str,
        mode: AttachMode,
        policy_id: PolicyId,
        vni: u32,
    ) -> Result<XdpMode> {
        let raw_ip = program_link_layer(&mut self.ebpf, iface)?;
        let vni = if raw_ip { 0 } else { vni };
        {
            let ifindex = if_nametoindex(iface)?;
            {
                let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
                    self.ebpf
                        .map_mut("IFACE_POLICY")
                        .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
                )?;
                iface_policy
                    .insert(ifindex, policy_id, 0)
                    .with_context(|| format!("assigning {iface} to policy {policy_id}"))?;
            }
            {
                let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
                    self.ebpf
                        .map_mut("IFACE_VNI")
                        .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
                )?;
                iface_vni
                    .insert(ifindex, vni, 0)
                    .with_context(|| format!("assigning {iface} to vni {vni}"))?;
            }
            if vni != 0 {
                let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
                    self.ebpf
                        .map_mut("LOCAL_VNIS")
                        .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
                )?;
                local_vnis
                    .insert(vni, 0, 0)
                    .with_context(|| format!("registering local vni {vni}"))?;
            }
            {
                let mut tx_ports: DevMap<_> = DevMap::try_from(
                    self.ebpf
                        .map_mut("TX_PORTS")
                        .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
                )?;
                tx_ports
                    .set(ifindex, ifindex, None, 0)
                    .with_context(|| format!("registering local redirect device {iface}"))?;
            }
        }
        let program: &mut Xdp = self
            .ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        let (chosen, link) = attach_with_fallback(program, iface, mode, self.persist.as_ref())?;
        self.xdp_links.insert(iface.to_owned(), link);
        self.attached.push((iface.to_string(), chosen));
        Ok(chosen)
    }

    /// Reconcile the **config-named** interfaces against `present`: attach (and
    /// program the policy + VNI for) any that have appeared, and forget any whose
    /// netdev has since gone (its XDP link detached with it).
    ///
    /// This is what attaches the XDP firewall/LB to a pod veth the controller
    /// declared — possibly *before* the CNI created it — without relying on an
    /// `--auto-attach` prefix. `program_interfaces` defers a not-yet-present
    /// interface's maps; this loop completes the job when it appears.
    pub fn reconcile_config_interfaces(&mut self, present: &[String], mode: AttachMode) {
        let hook_counts = (
            self.xdp_links.len(),
            self.bum_attached.len(),
            self.egress_attached.len(),
        );
        self.prune_stale_links();
        let hooks_unchanged = hook_counts
            == (
                self.xdp_links.len(),
                self.bum_attached.len(),
                self.egress_attached.len(),
            );
        let present_set: HashSet<&str> = present.iter().map(String::as_str).collect();

        // A guest can recreate a TAP under the same name between two polls.
        // Its old XDP and TC links vanished with the old ifindex, even though
        // a name-only inventory would still claim the interface is attached.
        let stale: Vec<String> = self
            .config_attached
            .iter()
            .filter(|(name, _)| !self.xdp_links.contains_key(*name))
            .map(|(name, _)| name.clone())
            .collect();
        // One observation feeds every address-derived map. An observation error
        // is not an empty inventory: retaining old grants in that case could
        // admit traffic under a subnet the interface no longer owns.
        // Always recover the canonical accepted source intent. A failed reopen
        // can leave `applied` ahead of the source inputs restored by the caller;
        // applied_intent excludes that state from the additive path below.
        let merged = self.merged_config();
        let prepared = match prepare_host_config(&merged) {
            Ok(prepared) => {
                self.torn_inventory_polls = 0;
                prepared
            }
            Err(error) => {
                if keep_last_inventory(
                    crate::host_inventory::is_raced(&error),
                    &mut self.torn_inventory_polls,
                ) {
                    // The host was changing while we looked. The last good
                    // snapshot stays in force for a bounded number of polls
                    // rather than blocking every flow on the box (DP-32).
                    warn!(
                        "interface observation raced a host change ({}/{MAX_TORN_INVENTORY_POLLS}); \
                         keeping the last good inventory: {error:#}",
                        self.torn_inventory_polls
                    );
                    return;
                }
                self.block_host_refresh(&error);
                return;
            }
        };
        let host_changed = prepared != self.applied_host;
        let configuration_state = self.configuration_state().ok();
        let recovery_required =
            configuration_state != Some(CONFIG_READY) || !self.applied_intent.current;
        if recovery_required {
            log::info!("retrying configuration recovery while traffic remains blocked");
        }
        let mut attachments_unchanged = hooks_unchanged && stale.is_empty();
        let mut changed = !attachments_unchanged || host_changed || recovery_required;
        for name in stale {
            self.config_attached.remove(&name);
            self.attached.retain(|(attached, _)| attached != &name);
            log::info!("config interface {name} disappeared or changed ifindex");
        }

        // Attach config interfaces that are present but not yet attached.
        let todo: Vec<(String, PolicyId, u32)> = self
            .applied
            .interfaces
            .iter()
            .filter(|i| present_set.contains(i.name.as_str()))
            .filter(|i| !self.attached.iter().any(|(n, _)| n == &i.name))
            .map(|i| (i.name.clone(), i.policy, i.vni))
            .collect();
        attachments_unchanged &= todo.is_empty();
        for (name, policy, vni) in todo {
            match self.attach_config_iface(&name, mode, policy, vni) {
                Ok(chosen) => {
                    if let Ok(index) = if_nametoindex(&name) {
                        self.config_attached.insert(name.clone(), index);
                    }
                    changed = true;
                    log::info!(
                        "attached config interface {name} -> policy {policy} vni {vni} ({chosen:?})"
                    );
                }
                Err(e) => warn!("attaching config interface {name} failed: {e:#}"),
            }
        }

        if changed {
            if self
                .applied_intent
                .allows_address_refresh(configuration_state, attachments_unchanged)
                && let Some(additions) = local_address_additions(&self.applied_host, &prepared)
            {
                // No policy meaning changed: only new exact local-address keys
                // became valid. Each atomic insertion is a conservative subset
                // of the observed target, so existing readers need no drain.
                // Do not touch epochs, NAT/flow state, or temporary grant timers.
                let result = self.add_observed_local_addresses(&merged, &prepared, &additions);
                if let Err(error) = result {
                    // An insertion may have partly succeeded. Retain the old
                    // snapshot and close the gate: the next closed full refresh
                    // removes any partial keys before reopening traffic.
                    self.block_host_refresh(&error);
                    return;
                }
                self.applied_host = prepared;
                self.activate_held_links(false);
                return;
            }
            // This also covers DHCP/secondary-address changes without a link
            // event. Quiesce once, refresh all derived permissions atomically,
            // and keep conntrack plus original temporary-grant deadlines.
            // An identical inventory causes no writes or policy-epoch churn.
            if let Err(error) = self.reprogram_prepared(merged, prepared, false, true) {
                warn!("refreshing live interface inventory failed: {error:#}");
            }
        }
        self.activate_held_links(false);
    }

    fn add_observed_local_addresses(
        &mut self,
        cfg: &RuntimeConfig,
        prepared: &PreparedHostConfig,
        additions: &BTreeSet<[u8; 8]>,
    ) -> Result<()> {
        anyhow::ensure!(
            self.configuration_state()? == CONFIG_READY,
            "additive address refresh requires a ready configuration"
        );
        {
            let _timing = timing::Span::start(timing::Phase::LocalAddressInsert);
            let mut map: HashMap<_, [u8; 8], u8> = HashMap::try_from(
                self.ebpf
                    .map_mut("LOCAL_EGRESS_ADDRS")
                    .ok_or_else(|| anyhow!("LOCAL_EGRESS_ADDRS map missing"))?,
            )?;
            for key in additions {
                map.insert(key, 1, 0)
                    .context("adding observed local IPv4 address")?;
            }
        }
        // Check every prepared host field, including observed overlay MACs,
        // before acknowledging the snapshot. Never accept stale observations.
        let _timing = timing::Span::start(timing::Phase::LocalAddressRevalidate);
        anyhow::ensure!(
            prepare_host_config(cfg)? == *prepared,
            "host inventory changed during additive local-address refresh"
        );
        Ok(())
    }

    fn block_host_refresh(&mut self, error: &anyhow::Error) {
        // Even if closing the map gate itself fails, force a complete retry.
        // In particular, never leave partial additive address grants eligible
        // for the no-change shortcut when host facts revert to the old set.
        self.applied_intent.begin();
        self.last_apply_error = Some(format!("live interface observation failed: {error:#}"));
        if let Err(close_error) = self.set_configuration_state(CONFIG_FAILED) {
            log::error!(
                "could not close the datapath after interface observation failed: {close_error:#}"
            );
        }
        warn!(
            "live interface observation failed; traffic remains blocked until recovery: {error:#}"
        );
    }

    /// The check a commit waits on: the held links that exist and are still
    /// down after one more attempt to raise them. A link that could not be
    /// hooked stays down — the fail-closed half — and this is the loud half, so
    /// the commit names the link instead of reporting success over a segment
    /// that is silently dark.
    pub fn dark_held_links(&mut self) -> Vec<String> {
        self.activate_held_links(true);
        self.applied
            .interfaces
            .iter()
            .filter(|i| i.activate && link_is_down(&i.name))
            .map(|i| i.name.clone())
            .collect()
    }

    /// Bring up the held links that are down and now carry every hook they
    /// need under a policy in force — and, on an HA member, the HA guard on
    /// the link as it exists now. A link that cannot come up yet stays down and
    /// is retried on the next reconcile.
    ///
    /// Which links those are is read from the configuration and the links'
    /// state every time, never remembered from the attach that hooked them: a
    /// link this process hooked long ago and its owner later took down and
    /// handed back (disabled, then enabled again) is held just the same, and
    /// a set filled only by new attaches never learned of it.
    ///
    /// Without `handed_back`, a link this agent already raised at its current
    /// ifindex is left alone: it is down because someone took it down.
    fn activate_held_links(&mut self, handed_back: bool) {
        self.note_raised_links();
        let in_force = self
            .configuration_state()
            .is_ok_and(|state| state == CONFIG_READY);
        if !in_force
            || !self
                .applied
                .interfaces
                .iter()
                .any(|i| i.activate && link_is_down(&i.name))
        {
            return;
        }
        let needs_egress =
            egress_interfaces(&self.applied, &self.egress_candidates(&self.applied), true);
        let raised = &self.raised;
        let ready = links_to_activate(
            &self.applied.interfaces,
            |name| {
                link_is_down(name)
                    && (handed_back || !raised_here(raised, name, if_nametoindex(name).ok()))
            },
            |name| {
                self.xdp_links.contains_key(name)
                    && (!needs_egress.iter().any(|n| n == name)
                        || self.egress_attached.contains_key(name))
            },
            |name| self.ha_guard_in_place(name),
            in_force,
        );
        for name in ready {
            match set_link_up(&name) {
                Ok(()) => {
                    if let Ok(index) = if_nametoindex(&name) {
                        self.raised.insert(name.clone(), index);
                    }
                    log::info!("{name}: hooks attached and policy in force; link brought up")
                }
                Err(error) => warn!("bringing held link {name} up failed: {error:#}"),
            }
        }
    }

    /// Count every held link that is up now as raised, whoever raised it —
    /// networkd before a policy change made it held, or an earlier agent
    /// before a restart. Taking it down after that is an operator's choice.
    fn note_raised_links(&mut self) {
        for i in self.applied.interfaces.iter().filter(|i| i.activate) {
            if let Ok(index) = if_nametoindex(&i.name)
                && !link_is_down(&i.name)
            {
                self.raised.insert(i.name.clone(), index);
            }
        }
    }

    /// Whether the HA guard, where HA guards `name`, is on the link as it
    /// exists now. A link HA does not guard needs none.
    fn ha_guard_in_place(&self, name: &str) -> bool {
        let Some(ha) = &self.applied.ha else {
            return true;
        };
        if !ha.interfaces.iter().any(|n| n == name) {
            return true;
        }
        if_nametoindex(name).is_ok_and(|index| self.ha_guarded.get(name) == Some(&index))
    }

    /// Re-program the policy maps in place with a new config, without detaching.
    ///
    /// Entries from the previously-applied config that are gone in `cfg` are
    /// removed first, then the new set is written. `CONNTRACK` is left alone (it
    /// is owned by the data plane), so existing flows keep working across a
    /// reconfigure. This is what the controller-driven live updates call.
    pub fn requires_restart(&self, cfg: &RuntimeConfig) -> bool {
        self.base.ha != cfg.ha
            || self.base.conntrack_sync != cfg.conntrack_sync
            || self.base.flow_export != cfg.flow_export
            // Table size and pinning are decided when the maps are created.
            || self.base.state != cfg.state
    }

    pub fn reconfigure(&mut self, cfg: &RuntimeConfig) -> Result<()> {
        self.reconfigure_with_reset(cfg, false)
    }

    pub fn reconfigure_with_reset(&mut self, cfg: &RuntimeConfig, reset: bool) -> Result<()> {
        let _timing = timing::Span::start(timing::Phase::Reload);
        // Query callers already check this, but controller updates call us
        // directly. Never replace the base or touch maps while HA/sync sidecars
        // still use the old configuration (even when reset was requested).
        if self.requires_restart(cfg) {
            anyhow::bail!(
                "restart-required: HA, conntrack sync, flow export or the state tables changed"
            );
        }
        let previous = std::mem::replace(&mut self.base, cfg.clone());
        if let Err(cause) = self.reprogram_with_reset(reset) {
            self.base = previous;
            self.last_apply_error = Some(format!("{cause:#}"));
            return Err(cause);
        }
        Ok(())
    }

    /// Replace the advertised (FlowSpec) rules and put the merged set in force.
    ///
    /// Separate from [`Self::reconfigure`] and not a variant of it: the two
    /// sources arrive on their own schedules, and each has to be able to change
    /// without knowing what the other last said.
    pub fn set_flowspec(
        &mut self,
        rules: Vec<velstra_config::ResolvedRule>,
        refused: Vec<(String, String)>,
    ) -> Result<()> {
        self.flowspec_refused = refused;
        // Only when the rules themselves moved. A rule that arrived and cannot
        // be enforced changes what an operator should be told and nothing about
        // the maps, and rewriting the whole policy set to record that would be
        // work for its own sake.
        if self.flowspec == rules {
            return Ok(());
        }
        let previous = std::mem::replace(&mut self.flowspec, rules);
        if let Err(error) = self.reprogram() {
            self.flowspec = previous;
            return Err(error);
        }
        // A rule that only stops flows which have not started yet is not a
        // mitigation: a flood with a stable five-tuple keeps being admitted by
        // the stateful fast path for as long as its entry lives, which is
        // exactly the traffic somebody advertised the rule to stop.
        //
        // Best-effort on purpose. The entries are an optimisation, so failing to
        // clear one costs that flow its mitigation and nothing else — where
        // refusing to program the rules over it would cost every flow theirs.
        if let Err(e) = self.purge_discarded_flows() {
            log::warn!("flowspec: could not clear the flows it discards ({e:#})");
        }
        Ok(())
    }

    /// What the FlowSpec feed has come to: the rules in force and, beside them,
    /// what arrived and is not being enforced.
    /// Replace the routes learned from Wren and put the merged set in force.
    /// `Ok(true)` when something changed; the same set again is a no-op, so a
    /// feed that repeats itself costs nothing in the maps.
    pub fn set_dynamic_routes(
        &mut self,
        routes: Vec<velstra_config::ResolvedRoute>,
    ) -> Result<bool> {
        if self.dynamic_routes == routes {
            return Ok(false);
        }
        let previous = std::mem::replace(&mut self.dynamic_routes, routes);
        if let Err(error) = self.reprogram() {
            self.dynamic_routes = previous;
            return Err(error);
        }
        Ok(true)
    }

    pub fn flowspec_state(&self) -> (&[velstra_config::ResolvedRule], &[(String, String)]) {
        (&self.flowspec, &self.flowspec_refused)
    }

    /// Remove the `FW_FLOWS` entries the advertised discards match.
    ///
    /// Narrow by construction — see `crate::flowspec::flow_is_discarded`.
    /// HA owns a duplicate FD so this remains effective while state sync runs.
    fn purge_discarded_flows(&mut self) -> Result<()> {
        let drops: Vec<_> = self
            .flowspec
            .iter()
            .filter(|r| r.action == Action::Drop)
            .cloned()
            .collect();
        if drops.is_empty() {
            return Ok(());
        }
        let Some(map) = self.ebpf.map_mut("FW_FLOWS") else {
            return Ok(());
        };
        // An LRU hash map is read and written through the same userspace handle
        // as an ordinary one; the eviction policy is the kernel's business.
        let mut flows: HashMap<_, FirewallKey, FirewallState> = HashMap::try_from(map)?;
        // Collected first: deleting while iterating a BPF map is how a scan
        // silently skips entries.
        let doomed: Vec<FirewallKey> = flows
            .keys()
            .flatten()
            .filter(|key| {
                key.as_ipv4().is_some_and(|key| {
                    drops
                        .iter()
                        .any(|r| crate::flowspec::flow_is_discarded(r, &key))
                })
            })
            .collect();
        let count = doomed.len();
        for key in doomed {
            let _ = flows.remove(&key);
        }
        if count > 0 {
            log::info!("flowspec: cleared {count} flow(s) an advertised rule discards");
        }
        Ok(())
    }

    /// Put `base` + `flowspec` in force as one set.
    ///
    /// The whole policy set is rewritten rather than the changed rules alone,
    /// which is what makes there be exactly one writer of the rule tries — see
    /// `crate::flowspec`. `remove_stale` runs against the previously *merged*
    /// config, so a withdrawn advertised rule is taken out as surely as a
    /// deleted configured one.
    fn merged_config(&self) -> RuntimeConfig {
        let mut merged = if self.flowspec.is_empty() {
            self.base.clone()
        } else {
            crate::flowspec::merge_into(&self.base, &self.flowspec)
        };
        // Learned routes under the static ones: a destination the operator
        // wrote a route for keeps that route, whatever Wren says about it.
        for learned in &self.dynamic_routes {
            let taken = merged
                .routes
                .iter()
                .any(|r| r.policy == learned.policy && r.dest == learned.dest);
            if !taken {
                merged.routes.push(learned.clone());
            }
        }
        merged
    }

    fn reprogram(&mut self) -> Result<()> {
        self.reprogram_with_reset(false)
    }

    fn reprogram_with_reset(&mut self, reset: bool) -> Result<()> {
        let merged = self.merged_config();
        merged.validate_firewall_capacity()?;
        // Resolve fallible host identity before changing any active hooks/maps.
        let prepared = prepare_host_config(&merged)?;
        self.reprogram_prepared(merged, prepared, reset, false)
    }

    fn reprogram_prepared(
        &mut self,
        merged: RuntimeConfig,
        prepared: PreparedHostConfig,
        reset: bool,
        host_refresh: bool,
    ) -> Result<()> {
        let result = self.reprogram_transaction(merged, prepared, reset, host_refresh);
        release_freed_memory();
        result
    }

    fn reprogram_transaction(
        &mut self,
        merged: RuntimeConfig,
        prepared: PreparedHostConfig,
        reset: bool,
        host_refresh: bool,
    ) -> Result<()> {
        let _timing = timing::Span::start(timing::Phase::FullTransaction);
        merged.validate_firewall_capacity()?;
        if self.unchanged(&merged, &prepared, reset, host_refresh)? {
            // A commit that changes nothing this agent enforces costs nothing:
            // no gate, no drain, no write (DP-28).
            log::info!("configuration unchanged; the datapath was not touched");
            self.last_apply_error = None;
            return Ok(());
        }
        // Resolved and checked against every trie's capacity while traffic
        // still flows: a configuration that cannot fit costs no blip (DP-17).
        let plan = PolicyPlan::new(&self.ebpf, &merged, &prepared)?;
        self.applied_intent.begin();
        let previous = self.applied.clone();
        let previous_host = self.applied_host.clone();
        // A rollback may restore policy intent, but cannot make old host facts
        // current again. Never reopen that stale inventory after a failed
        // refresh, even when rewriting the old maps happened to succeed.
        let reopen_rollback = !host_refresh && prepared.ipv4 == previous_host.ipv4;
        self.set_configuration_state(CONFIG_UPDATING)?;
        if reset {
            self.runtime_blocks.clear();
            self.portal_sessions.clear();
            self.runtime_mappings.clear();
        }
        let quiesced = match ReaderQuiescence::drain_with(synchronize_packet_readers) {
            Ok(quiesced) => quiesced,
            Err(error) => {
                let _ = self.set_configuration_state(CONFIG_FAILED);
                self.last_apply_error = Some(format!("could not drain packet readers: {error:#}"));
                return Err(error).context("configuration update blocked; firewall remains closed");
            }
        };
        let forwards = match self.port_forward_snapshot() {
            Ok(forwards) => forwards,
            Err(error) => {
                let _ = self.set_configuration_state(CONFIG_FAILED);
                self.last_apply_error =
                    Some(format!("could not snapshot port forwards: {error:#}"));
                return Err(error)
                    .context("configuration snapshot failed; firewall remains closed");
            }
        };
        let mut host_still_current = true;
        let update = (|| -> Result<HashSet<MappingKey>> {
            self.sync_egress_attachments(&merged)?;
            apply_config_quiesced(
                &mut self.ebpf,
                &merged,
                Some((&previous, &previous_host)),
                &prepared,
                reset,
                &quiesced,
                &plan,
                &mut self.tries,
            )?;
            let retained = self.reapply_runtime_mappings(&merged, &prepared.ipv4)?;
            // Other map writers also resolve Linux names. If a link/address
            // changed during the transaction, none of those mixed identities
            // may become active. Retry a new coherent snapshot next poll.
            let observed = revalidate_host_config(&merged, &prepared);
            host_still_current = observed.is_ok();
            observed.context("host inventory changed or became unreadable during policy update")?;
            Ok(retained)
        })();
        let retained_mappings = match update {
            Ok(retained) => retained,
            Err(error) => {
                let rollback = (|| -> Result<()> {
                    self.sync_egress_attachments(&previous)?;
                    let previous_plan = PolicyPlan::new(&self.ebpf, &previous, &previous_host)?;
                    apply_config_quiesced(
                        &mut self.ebpf,
                        &previous,
                        Some((&merged, &prepared)),
                        &previous_host,
                        reset,
                        &quiesced,
                        &previous_plan,
                        &mut self.tries,
                    )?;
                    self.restore_port_forward_snapshot(&forwards)?;
                    let blocks: Vec<String> = self
                        .runtime_blocks
                        .iter()
                        .filter(|(_, expiry)| **expiry > Instant::now())
                        .map(|(cidr, _)| cidr.clone())
                        .collect();
                    for cidr in blocks {
                        self.write_block(&cidr, true)?;
                    }
                    self.sync_bum_attachments(&previous);
                    self.retire_egress_attachments(&previous);
                    Ok(())
                })();
                match rollback {
                    Ok(()) => {
                        self.last_apply_error = Some(format!("{error:#}"));
                        if reopen_rollback && host_still_current {
                            // Early map failures never reach the candidate's
                            // final observation; rollback itself can also race
                            // Linux network changes. Only a fresh observation
                            // of the previous intent can authorize reopening.
                            if let Err(observation_error) =
                                revalidate_host_config(&previous, &previous_host)
                            {
                                self.last_apply_error = Some(format!(
                                    "{error:#}; rollback host observation: {observation_error:#}"
                                ));
                                let _ = self.set_configuration_state(CONFIG_FAILED);
                                return Err(error).context(
                                    "rollback host facts are stale or unreadable; firewall remains closed until reconciliation succeeds",
                                );
                            }
                            self.reopen_configuration()?;
                        } else {
                            let _ = self.set_configuration_state(CONFIG_FAILED);
                            return Err(error).context(
                                "host refresh failed; firewall remains closed until reconciliation succeeds",
                            );
                        }
                        return Err(error)
                            .context("update failed; previous configuration restored");
                    }
                    Err(rollback_error) => {
                        let message = format!(
                            "update failed: {error:#}; rollback failed: {rollback_error:#}"
                        );
                        self.last_apply_error = Some(message.clone());
                        let _ = self.set_configuration_state(CONFIG_FAILED);
                        bail!("{message}; firewall remains closed until reconciliation succeeds");
                    }
                }
            }
        };
        self.runtime_mappings
            .retain(|key, _| retained_mappings.contains(key));
        self.sync_bum_attachments(&merged);
        self.retire_egress_attachments(&merged);
        self.applied = merged;
        self.route_ifindices = prepared.route_ifindices.clone();
        self.applied_host = prepared;
        let reopened = self.reopen_configuration();
        self.applied_intent.finish(reopened)?;
        self.last_apply_error = None;
        Ok(())
    }

    /// Whether `merged` on `prepared` is exactly what the datapath already
    /// enforces, so a transaction would only rewrite every entry with itself.
    /// Never for a host refresh (a newly attached interface needs its maps), a
    /// reset, or a datapath that is not open with current intent.
    fn unchanged(
        &self,
        merged: &RuntimeConfig,
        prepared: &PreparedHostConfig,
        reset: bool,
        host_refresh: bool,
    ) -> Result<bool> {
        Ok(!reset
            && !host_refresh
            && self.applied_intent.current
            && *merged == self.applied
            && *prepared == self.applied_host
            && self.configuration_state()? == CONFIG_READY)
    }

    fn configuration_state(&self) -> Result<u32> {
        let map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map("APPLY_STATE")
                .ok_or_else(|| anyhow!("APPLY_STATE map missing"))?,
        )?;
        map.get(&0, 0).context("reading configuration state")
    }

    fn set_configuration_state(&mut self, state: u32) -> Result<()> {
        let mut map: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("APPLY_STATE")
                .ok_or_else(|| anyhow!("APPLY_STATE map missing"))?,
        )?;
        map.set(0, state, 0).context("writing configuration state")
    }

    fn reopen_configuration(&mut self) -> Result<()> {
        if let Err(error) = self.set_configuration_state(CONFIG_READY) {
            self.last_apply_error = Some(format!("could not reopen the datapath: {error:#}"));
            let _ = self.set_configuration_state(CONFIG_FAILED);
            return Err(error).context("configuration remains blocked; traffic is not admitted");
        }
        Ok(())
    }

    pub fn configuration_status(&self) -> Result<String> {
        let state = match self.configuration_state()? {
            CONFIG_READY => "Ready",
            CONFIG_UPDATING if self.last_apply_error.is_none() => "Updating",
            _ => "Failed (traffic blocked)",
        };
        let mut output = format!("{state}\n");
        if let Some(error) = &self.last_apply_error {
            output.push_str(&format!("Last update: {error}\n"));
        }
        Ok(output)
    }

    pub(crate) fn sync_generation(&self) -> Result<([u8; 32], u64)> {
        let policy = self.sync_policy()?;
        let epoch = Array::<_, u64>::try_from(
            self.ebpf
                .map("CONFIG_EPOCH")
                .ok_or_else(|| anyhow!("configuration epoch missing"))?,
        )?
        .get(&0, 0)?;
        anyhow::ensure!(epoch & 1 == 0, "policy update is incomplete");
        Ok((policy, epoch))
    }

    pub(crate) fn ha_deadline(&mut self, deadline: u64) -> Result<()> {
        Array::<_, u64>::try_from(
            self.ebpf
                .map_mut("HA_DEADLINE")
                .ok_or_else(|| anyhow!("HA deadline missing"))?,
        )?
        .set(0, deadline, 0)?;
        Ok(())
    }
    /// Keep the HA guard on every HA link. When it has just gone onto a link,
    /// that link may be the last thing a held link was waiting for, so the
    /// held links are offered up again — by the one place that raises them.
    pub(crate) fn ha_interfaces(&mut self, config: &velstra_config::HaConfig) -> Result<bool> {
        let before = self.ha_guarded.clone();
        let interfaces = &self.applied.interfaces;
        let complete =
            crate::ha::reconcile_interfaces(&mut self.ebpf, config, &mut self.ha_guarded, |name| {
                is_held(interfaces, name)
            });
        if self.ha_guarded != before {
            self.activate_held_links(false);
        }
        complete
    }

    /// Read under the same lock as live policy application. A failed or
    /// incomplete apply must never admit state from a previously valid policy.
    pub(crate) fn sync_policy(&self) -> Result<[u8; 32]> {
        anyhow::ensure!(
            self.configuration_state()? == CONFIG_READY,
            "firewall is not ready for state replication"
        );
        crate::conntrack_sync::secure::policy_fingerprint(&self.applied)
    }

    /// Keep unexpired temporary grants across a successful policy refresh,
    /// while configured forwards and removal of their policy take precedence.
    fn reapply_runtime_mappings(
        &mut self,
        cfg: &RuntimeConfig,
        ipv4: &Ipv4Inventory,
    ) -> Result<HashSet<MappingKey>> {
        let now = Instant::now();
        let active: Vec<_> = self
            .runtime_mappings
            .iter()
            .filter(|(key, value)| {
                value.2 > now
                    && cfg.policies.iter().any(|policy| policy.id == key.0)
                    && !cfg.port_forwards.iter().any(|forward| {
                        forward.policy == key.0 && forward.proto == key.1 && forward.port == key.2
                    })
            })
            .map(|(key, value)| (*key, *value))
            .collect();
        let mut retained = HashSet::new();
        for ((policy, proto, port), (internal, internal_port, _)) in active {
            let reply = resolve_reply_policy(internal, &cfg.interfaces, ipv4);
            let value = PortFwd::new(internal, internal_port).with_reply_policy(reply);
            self.write_mapping(policy, proto, port, Some(value))?;
            retained.insert((policy, proto, port));
        }
        Ok(retained)
    }

    fn port_forward_snapshot(&self) -> Result<Vec<(ScopedPortKey, PortFwd)>> {
        let map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
            self.ebpf
                .map("PORT_FORWARDS")
                .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
        )?;
        map.iter()
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("snapshotting configured and temporary port forwards")
    }

    fn restore_port_forward_snapshot(
        &mut self,
        entries: &[(ScopedPortKey, PortFwd)],
    ) -> Result<()> {
        let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
            self.ebpf
                .map_mut("PORT_FORWARDS")
                .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
        )?;
        let keep = entries.iter().map(|(key, _)| *key).collect();
        drop_unlisted(&mut map, &keep)?;
        for (key, value) in entries {
            map.insert(key, value, 0)
                .context("restoring port forward")?;
        }
        Ok(())
    }

    /// Block `cidr` as a source across every policy, until `ttl` has passed.
    ///
    /// The blocklist the data plane consults is per-policy, but a source blocked
    /// because of what it *did* is not blocked "in zone lan" — it is blocked. So
    /// the entry goes into every policy, and `unblock` takes it out of every one.
    ///
    /// A CIDR the **configuration** already blocks is left alone and reported as
    /// such: adding it here would mean the expiry later removed a permanent entry
    /// the operator wrote, quietly turning their block off.
    ///
    /// Returns `false` when the address was already blocked by configuration.
    pub fn block_source(&mut self, cidr: &str, ttl: Duration) -> Result<bool> {
        if self.blocked_by_config(cidr) {
            return Ok(false);
        }
        self.write_block(cidr, true)?;
        self.runtime_blocks
            .insert(cidr.to_string(), Instant::now() + ttl);
        Ok(true)
    }

    /// Drop a run-time block early. Returns whether there was one.
    pub fn unblock_source(&mut self, cidr: &str) -> Result<bool> {
        if self.runtime_blocks.remove(cidr).is_none() {
            return Ok(false);
        }
        self.write_block(cidr, false)?;
        Ok(true)
    }

    /// Lift every run-time block. Returns how many there were.
    ///
    /// For the false-positive storm: a rule that turned out too broad blocks a
    /// dozen sources in a minute, and undoing that one address at a time is the
    /// wrong thing to be doing while it is happening.
    pub fn unblock_all(&mut self) -> Result<usize> {
        let all: Vec<String> = self.runtime_blocks.keys().cloned().collect();
        for cidr in &all {
            self.runtime_blocks.remove(cidr);
            self.write_block(cidr, false)
                .with_context(|| format!("lifting the block on {cidr}"))?;
        }
        Ok(all.len())
    }

    /// Remove every run-time block whose time is up. Returns how many went.
    ///
    /// This is what makes an automatic block safe to switch on: whatever a
    /// detector decides, it undoes itself. An appliance that could permanently
    /// lock out an address on its own reading of a packet is one nobody should
    /// run.
    pub fn expire_blocks(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<String> = self
            .runtime_blocks
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(cidr, _)| cidr.clone())
            .collect();
        for cidr in &due {
            self.runtime_blocks.remove(cidr);
            if let Err(e) = self.write_block(cidr, false) {
                warn!("could not lift the expired block on {cidr}: {e:#}");
            }
        }
        due.len()
    }

    /// The live run-time blocks as `(cidr, seconds remaining)`.
    pub fn runtime_blocks(&self) -> Vec<(String, u64)> {
        let now = Instant::now();
        self.runtime_blocks
            .iter()
            .map(|(cidr, &expiry)| {
                (
                    cidr.clone(),
                    expiry.saturating_duration_since(now).as_secs(),
                )
            })
            .collect()
    }

    /// Open one port-forward at **run time**, until `ttl` has passed.
    ///
    /// This is what a NAT-PMP/PCP request becomes (roadmap C18). It is the only
    /// other thing besides a portal admission that opens the firewall without a
    /// configuration change, and it is bounded much more tightly, because the
    /// party asking is a host on the inside rather than a person at a page:
    ///
    /// * a `(policy, proto, port)` the **configuration** already forwards is
    ///   refused outright. Overwriting it would silently redirect somebody
    ///   else's service, and — worse — the expiry would later *delete* an entry
    ///   the operator wrote, turning their port-forward off hours after a LAN
    ///   host asked for something unrelated;
    /// * the number of run-time mappings is capped well below the map's size, so
    ///   one host cannot fill the table and starve the operator's own forwards;
    /// * every mapping carries a deadline, like every other run-time opening
    ///   here.
    ///
    /// Returns `false` when the configuration owns that key.
    pub fn map_port(
        &mut self,
        policy: PolicyId,
        proto: u8,
        external_port: u16,
        internal: [u8; 4],
        internal_port: u16,
        ttl: Duration,
    ) -> Result<bool> {
        if external_port == 0 {
            bail!("port 0 is not a port");
        }
        if internal == [0; 4] {
            bail!("0.0.0.0 is not a host to forward to");
        }
        let key = (policy, proto, external_port);
        if self.forwarded_by_config(policy, proto, external_port) {
            return Ok(false);
        }
        if !self.runtime_mappings.contains_key(&key)
            && self.runtime_mappings.len() >= MAX_RUNTIME_MAPPINGS
        {
            bail!(
                "already holding {MAX_RUNTIME_MAPPINGS} run-time mappings; \
                 refusing to crowd out the configured port-forwards"
            );
        }
        let reply =
            resolve_reply_policy(internal, &self.applied.interfaces, &self.applied_host.ipv4);
        let value = PortFwd::new(internal, internal_port).with_reply_policy(reply);
        self.write_mapping(policy, proto, external_port, Some(value))?;
        self.runtime_mappings
            .insert(key, (internal, internal_port, Instant::now() + ttl));
        Ok(true)
    }

    /// Close one run-time mapping early. Returns whether there was one.
    ///
    /// Only a **run-time** mapping: a configured port-forward is not something a
    /// request from the inside may take away, any more than it is something it
    /// may overwrite.
    pub fn unmap_port(&mut self, policy: PolicyId, proto: u8, external_port: u16) -> Result<bool> {
        if self
            .runtime_mappings
            .remove(&(policy, proto, external_port))
            .is_none()
        {
            return Ok(false);
        }
        self.write_mapping(policy, proto, external_port, None)?;
        Ok(true)
    }

    /// Close every run-time mapping. Returns how many there were.
    pub fn unmap_all(&mut self) -> Result<usize> {
        let all: Vec<MappingKey> = self.runtime_mappings.keys().copied().collect();
        for (policy, proto, port) in &all {
            self.runtime_mappings.remove(&(*policy, *proto, *port));
            self.write_mapping(*policy, *proto, *port, None)
                .with_context(|| format!("closing the mapping on {proto}/{port}"))?;
        }
        Ok(all.len())
    }

    /// Remove every mapping whose time is up. Returns how many went.
    pub fn expire_mappings(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<(PolicyId, u8, u16)> = self
            .runtime_mappings
            .iter()
            .filter(|(_, (_, _, expiry))| *expiry <= now)
            .map(|(key, _)| *key)
            .collect();
        for (policy, proto, port) in &due {
            self.runtime_mappings.remove(&(*policy, *proto, *port));
            if let Err(e) = self.write_mapping(*policy, *proto, *port, None) {
                warn!("could not close the expired mapping on {proto}/{port}: {e}");
            }
        }
        due.len()
    }

    /// The live run-time mappings as
    /// `(policy, proto, external port, internal ip, internal port, seconds left)`.
    pub fn runtime_mappings(&self) -> Vec<(PolicyId, u8, u16, [u8; 4], u16, u64)> {
        let now = Instant::now();
        self.runtime_mappings
            .iter()
            .map(|(&(policy, proto, port), &(ip, iport, expiry))| {
                (
                    policy,
                    proto,
                    port,
                    ip,
                    iport,
                    expiry.saturating_duration_since(now).as_secs(),
                )
            })
            .collect()
    }

    /// Whether the applied configuration already forwards this exact key.
    fn forwarded_by_config(&self, policy: PolicyId, proto: u8, port: u16) -> bool {
        self.applied
            .port_forwards
            .iter()
            .any(|pf| pf.policy == policy && pf.proto == proto && pf.port == port)
    }

    /// Insert or remove one `PORT_FORWARDS` entry.
    fn write_mapping(
        &mut self,
        policy: PolicyId,
        proto: u8,
        port: u16,
        value: Option<PortFwd>,
    ) -> Result<()> {
        let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
            self.ebpf
                .map_mut("PORT_FORWARDS")
                .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
        )?;
        let key = ScopedPortKey::new(policy, proto, port);
        match value {
            Some(value) => map
                .insert(key, value, 0)
                .with_context(|| format!("mapping {proto}/{port} in policy {policy}"))?,
            None => {
                let _ = map.remove(&key);
            }
        }
        Ok(())
    }

    /// The policies (zones) that are behind a captive portal, in id order.
    ///
    /// Only these can be admitted into: the `PORTAL_CLIENTS` map is consulted
    /// nowhere else, so an admission is structurally incapable of opening
    /// anything in a zone that has no portal. That is the property that makes a
    /// write verb on the portal socket a bounded thing rather than a hole.
    pub fn portal_policies(&self) -> Vec<PolicyId> {
        let mut ids: Vec<PolicyId> = self
            .applied
            .policies
            .iter()
            .filter(|p| p.portal.is_some())
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The MAC the data plane last saw `addr` use, in `policy`, on traffic
    /// addressed to the portal.
    ///
    /// `None` means that address has not talked to the portal — which is what a
    /// login from an address nobody has seen looks like, and is exactly the case
    /// that must not be admitted.
    pub fn portal_mac_for(
        &mut self,
        policy: PolicyId,
        addr: std::net::IpAddr,
    ) -> Result<Option<[u8; 6]>> {
        let key = match addr {
            std::net::IpAddr::V4(v4) => PortalSeenKey::v4(policy, v4.octets()),
            std::net::IpAddr::V6(v6) => PortalSeenKey::v6(policy, v6.octets()),
        };
        let seen: HashMap<_, PortalSeenKey, [u8; 6]> = HashMap::try_from(
            self.ebpf
                .map_mut("PORTAL_SEEN")
                .ok_or_else(|| anyhow!("PORTAL_SEEN map missing"))?,
        )?;
        Ok(seen.get(&key, 0).ok())
    }

    /// Admit `mac` to `policy` for `ttl`.
    ///
    /// Re-admitting a device that is already admitted **extends** its session
    /// rather than refusing: a guest who logs in again because a page said their
    /// time was nearly up means to keep going, and answering "you are already in"
    /// would let the old deadline end them mid-sentence.
    pub fn portal_admit(&mut self, policy: PolicyId, mac: [u8; 6], ttl: Duration) -> Result<()> {
        if !self.portal_policies().contains(&policy) {
            bail!("policy {policy} has no captive portal, so nothing can be admitted to it");
        }
        self.write_portal(policy, mac, true)?;
        self.portal_sessions
            .insert((policy, mac), Instant::now() + ttl);
        Ok(())
    }

    /// End one session early. Returns whether there was one.
    pub fn portal_revoke(&mut self, policy: PolicyId, mac: [u8; 6]) -> Result<bool> {
        if self.portal_sessions.remove(&(policy, mac)).is_none() {
            return Ok(false);
        }
        self.write_portal(policy, mac, false)?;
        Ok(true)
    }

    /// End every session. Returns how many there were.
    pub fn portal_revoke_all(&mut self) -> Result<usize> {
        let all: Vec<(PolicyId, [u8; 6])> = self.portal_sessions.keys().copied().collect();
        for (policy, mac) in &all {
            self.portal_sessions.remove(&(*policy, *mac));
            self.write_portal(*policy, *mac, false)
                .with_context(|| format!("ending the session for {}", render_mac(*mac)))?;
        }
        Ok(all.len())
    }

    /// Remove every session whose time is up. Returns how many went.
    ///
    /// The deadline lives here rather than in the map because the data plane has
    /// no wall clock — and because it is user space that must survive the
    /// question "why is this device still on the network".
    pub fn expire_portal_sessions(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<(PolicyId, [u8; 6])> = self
            .portal_sessions
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(key, _)| *key)
            .collect();
        for (policy, mac) in &due {
            self.portal_sessions.remove(&(*policy, *mac));
            if let Err(e) = self.write_portal(*policy, *mac, false) {
                warn!(
                    "could not end the expired session for {}: {e:#}",
                    render_mac(*mac)
                );
            }
        }
        due.len()
    }

    /// The live sessions as `(policy, mac, seconds remaining)`.
    pub fn portal_sessions(&self) -> Vec<(PolicyId, [u8; 6], u64)> {
        let now = Instant::now();
        self.portal_sessions
            .iter()
            .map(|(&(policy, mac), &expiry)| {
                (policy, mac, expiry.saturating_duration_since(now).as_secs())
            })
            .collect()
    }

    /// Insert or remove one `(policy, MAC)` in `PORTAL_CLIENTS`.
    fn write_portal(&mut self, policy: PolicyId, mac: [u8; 6], admit: bool) -> Result<()> {
        let mut clients: HashMap<_, PortalClientKey, u8> = HashMap::try_from(
            self.ebpf
                .map_mut("PORTAL_CLIENTS")
                .ok_or_else(|| anyhow!("PORTAL_CLIENTS map missing"))?,
        )?;
        let key = PortalClientKey::new(policy, mac);
        if admit {
            clients.insert(key, 1u8, 0).with_context(|| {
                format!(
                    "admitting {} to policy {policy} (the table may be full)",
                    render_mac(mac)
                )
            })?;
        } else {
            let _ = clients.remove(&key);
        }
        Ok(())
    }

    /// Whether the applied configuration already blocks this exact CIDR.
    fn blocked_by_config(&self, cidr: &str) -> bool {
        self.applied.policies.iter().any(|p| {
            p.blocklist.iter().any(|c| c.to_string() == cidr)
                || p.blocklist6.iter().any(|c| c.to_string() == cidr)
        })
    }

    /// Insert or remove `cidr` in the blocklist trie of every policy.
    ///
    /// Accepts a bare address as well as a CIDR — a detector reports the host it
    /// saw, not a prefix — and picks the v4 or v6 trie from what parses.
    fn write_block(&mut self, cidr: &str, insert: bool) -> Result<()> {
        let policies: Vec<PolicyId> = self.applied.policies.iter().map(|p| p.id).collect();
        if let Ok(v4) = parse_cidr_v4(cidr) {
            let (prefix, addr) = v4.lpm_key();
            let mut trie: LpmTrie<_, ScopedAddr, u32> = LpmTrie::try_from(
                self.ebpf
                    .map_mut("BLOCKLIST")
                    .ok_or_else(|| anyhow!("BLOCKLIST map missing"))?,
            )?;
            for id in policies {
                let scoped = ScopedAddr::new(id, addr);
                let key = Key::new(ScopedAddr::POLICY_BITS + prefix, scoped);
                if insert {
                    trie.insert(&key, 1u32, 0)
                        .with_context(|| format!("blocking {cidr} in policy {id}"))?;
                } else if !self
                    .tries
                    .has_block(ScopedAddr::POLICY_BITS + prefix, scoped)
                {
                    // A prefix the configuration also blocks stays blocked:
                    // the tries are written by difference, so nothing would
                    // put it back until the configuration changed (DP-28).
                    let _ = trie.remove(&key);
                }
            }
            return Ok(());
        }
        let v6 =
            parse_cidr_v6(cidr).map_err(|e| anyhow!("{cidr:?} is not an address or CIDR: {e}"))?;
        let (prefix, addr) = v6.lpm_key();
        let mut trie: LpmTrie<_, ScopedAddr6, u32> = LpmTrie::try_from(
            self.ebpf
                .map_mut("BLOCKLIST6")
                .ok_or_else(|| anyhow!("BLOCKLIST6 map missing"))?,
        )?;
        for id in policies {
            let scoped = ScopedAddr6::new(id, addr);
            let key = Key::new(ScopedAddr6::POLICY_BITS + prefix, scoped);
            if insert {
                trie.insert(&key, 1u32, 0)
                    .with_context(|| format!("blocking {cidr} in policy {id}"))?;
            } else if !self
                .tries
                .has_block6(ScopedAddr6::POLICY_BITS + prefix, scoped)
            {
                let _ = trie.remove(&key);
            }
        }
        Ok(())
    }

    /// The WAN port block `addr` is assigned on each CGNAT-configured egress, as
    /// `(interface, first_port, last_port)`.
    ///
    /// Read from the live map and computed with [`CgnatLayout::range_of`] — the
    /// same call the data plane makes — so the answer an operator reports and the
    /// ports actually handed out cannot disagree. That is the whole point of a
    /// deterministic layout: attribution without a translation log.
    pub fn cgnat_blocks(&self, addr: [u8; 4]) -> Result<Vec<(String, u16, u16)>> {
        let map: HashMap<_, u32, CgnatLayout> = HashMap::try_from(
            self.ebpf
                .map("CGNAT")
                .ok_or_else(|| anyhow!("CGNAT map missing"))?,
        )?;
        let mut out = Vec::new();
        for key in map.keys() {
            let ifindex = key?;
            let Ok(layout) = map.get(&ifindex, 0) else {
                continue;
            };
            if let Some((first, last)) = layout.range_of(addr) {
                out.push((if_indextoname(ifindex), first, last));
            }
        }
        out.sort();
        Ok(out)
    }

    /// Read and sum the per-CPU statistics into a flat [`Stats`] snapshot.
    /// Snapshot of live firewall state. Expired entries do not grant a reply
    /// permission and are not reported as active connections.
    pub fn read_firewall_states(&self) -> Result<serde_json::Value> {
        Ok(self.read_firewall_state_summary(usize::MAX)?["states"].take())
    }
    /// The live API needs a total and a bounded sample, not 65k JSON objects
    /// constructed under the HA configuration lock on every sample.
    pub fn read_firewall_state_summary(&self, limit: usize) -> Result<serde_json::Value> {
        let map = HashMap::<_, FirewallKey, FirewallState>::try_from(
            self.ebpf
                .map("FW_FLOWS")
                .ok_or_else(|| anyhow!("FW_FLOWS map missing"))?,
        )?;
        // Diagnostics share the short HA configuration lock. Read in kernel
        // batches rather than doing two syscalls per entry while holding it.
        let entries = crate::conntrack_sync::secure::batch_read(&map)?;
        let now = crate::conntrack_sync::monotonic_ns();
        let mut rows = Vec::new();
        let mut total = 0;
        for (key, state) in entries {
            if state.expired(key.proto, now, self.applied.conntrack) {
                continue;
            }
            total += 1;
            if rows.len() >= limit {
                continue;
            }
            let address = |bytes: [u8; 16]| {
                if key.family == 4 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ))
                    .to_string()
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)).to_string()
                }
            };
            rows.push(serde_json::json!({"policy":key.policy,"src":address(key.src),"dst":address(key.dst),
                "src_port":key.src_port,"dst_port":key.dst_port,"protocol":key.proto,
                "phase":state.phase,"reply":state.reply == 1,
                "idle_ns":state.idle_ns(now)}));
        }
        Ok(serde_json::json!({"total":total,"states":rows,"sample_limit":limit}))
    }

    /// Exact per-rule packet counters. The kernel keeps one value per CPU;
    /// aggregate here without contending a shared cache line on the hot path.
    pub fn rule_counter_snapshot(&self) -> Result<RuleCounterSnapshot> {
        let duplicate = |name: &str| -> Result<MapData> {
            let map = self
                .ebpf
                .map(name)
                .ok_or_else(|| anyhow!("{name} map missing"))?;
            let data = match map {
                aya::maps::Map::PerCpuHashMap(data) | aya::maps::Map::PerCpuArray(data) => data,
                _ => bail!("unexpected {name} map type"),
            };
            Ok(MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?)
        };
        Ok(RuleCounterSnapshot {
            counters: aya::maps::PerCpuHashMap::try_from(aya::maps::Map::PerCpuHashMap(
                duplicate("RULE_COUNTERS")?,
            ))?,
            lost: aya::maps::PerCpuArray::try_from(aya::maps::Map::PerCpuArray(duplicate(
                "PACKET_EVENTS_LOST",
            )?))?,
            names: self
                .applied
                .policies
                .iter()
                .flat_map(|policy| {
                    policy
                        .port_rules
                        .iter()
                        .map(move |rule| ((policy.id, rule.id()), rule.name.clone()))
                })
                .collect(),
        })
    }

    /// Move what the kernel ring holds into the agent's event log. Only the
    /// agent consumes the ring; readers page through the log (`packet_log`).
    fn drain_packet_ring(&mut self) -> Result<()> {
        let names: BTreeMap<(u32, u32), String> = self
            .applied
            .policies
            .iter()
            .flat_map(|p| {
                p.port_rules
                    .iter()
                    .map(move |r| ((p.id, r.id()), r.name.clone()))
            })
            .collect();
        let mut ring = aya::maps::RingBuf::try_from(
            self.ebpf
                .map_mut("PACKET_EVENTS")
                .ok_or_else(|| anyhow!("PACKET_EVENTS map missing"))?,
        )?;
        // Bounded per call: a ring refilled as fast as it is read must not hold
        // the firewall lock forever. One log's worth is all a reader could see.
        for _ in 0..crate::packet_events::CAPACITY {
            let Some(item) = ring.next() else {
                break;
            };
            anyhow::ensure!(
                item.len() == std::mem::size_of::<velstra_common::PacketEvent>(),
                "packet-event ABI mismatch"
            );
            // The shared POD layout contains integers/bytes only. Ring payloads
            // need not be aligned to the Rust struct's alignment.
            let event = unsafe {
                std::ptr::read_unaligned(item.as_ptr().cast::<velstra_common::PacketEvent>())
            };
            let address = |bytes: [u8; 16]| {
                if event.family == 4 {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                        bytes[0], bytes[1], bytes[2], bytes[3],
                    ))
                    .to_string()
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)).to_string()
                }
            };
            self.packet_log.push(serde_json::json!({"timestamp_ns": event.timestamp_ns,
                "policy": event.policy, "rule_id": event.rule_id,
                "rule": names.get(&(event.policy,event.rule_id)), "interface": event.ifindex,
                "length": event.length, "family": event.family, "src": address(event.src), "dst": address(event.dst),
                "src_port": event.src_port, "dst_port": event.dst_port, "protocol": event.proto,
                "action": match event.action { 0 => "accept", 1 => "drop", _ => "reject" },
                "direction": if event.direction == 0 { "in" } else { "out" }, "reason": event.reason}));
        }
        Ok(())
    }

    /// `packet-events [limit]`, the pre-cursor request: each event once across
    /// every client still using it, as the ring used to behave for them.
    pub fn read_packet_events(&mut self, limit: usize) -> Result<Vec<serde_json::Value>> {
        self.drain_packet_ring()?;
        Ok(self.packet_log.legacy(limit.clamp(1, 4096)))
    }

    /// `packet-events-since <id> [limit] [epoch]`: a page of the log after a
    /// reader's cursor, plus the kernel's own overflow count — events the ring
    /// dropped before the agent could drain them, which no cursor can recover.
    pub fn packet_events_since(
        &mut self,
        cursor: u64,
        epoch: Option<u64>,
        limit: usize,
    ) -> Result<serde_json::Value> {
        self.drain_packet_ring()?;
        let mut page = self.packet_log.since(cursor, epoch, limit.clamp(1, 4096));
        let lost: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.ebpf
                .map("PACKET_EVENTS_LOST")
                .ok_or_else(|| anyhow!("PACKET_EVENTS_LOST map missing"))?,
        )?;
        page["ring_lost"] = serde_json::json!(lost.get(&0, 0)?.iter().copied().sum::<u64>());
        Ok(page)
    }

    /// `packet-events-tail [limit]`: the newest events, consuming nothing.
    pub fn packet_events_tail(&mut self, limit: usize) -> Result<Vec<serde_json::Value>> {
        self.drain_packet_ring()?;
        Ok(self
            .packet_log
            .tail(limit.clamp(1, 4096))
            .cloned()
            .collect())
    }

    pub fn read_stats(&self) -> Result<Stats> {
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.ebpf
                .map("STATS")
                .ok_or_else(|| anyhow!("STATS map missing"))?,
        )?;

        let mut rows = Vec::with_capacity(Counter::COUNT as usize);
        for index in 0..Counter::COUNT {
            let per_cpu = map.get(&index, 0)?;
            let total: u64 = per_cpu.iter().copied().sum();
            // `index` is in range by construction, so `from_u32` cannot fail.
            let counter = Counter::from_u32(index).expect("counter index in range");
            rows.push((counter, total));
        }
        Ok(Stats { rows })
    }

    /// Duplicate `LOCAL_MACS` for the learn-and-advertise task. Keep the map in
    /// the firewall too, so a policy-namespace reset can clear learned state.
    pub fn take_local_macs(&mut self) -> Result<HashMap<MapData, LocalMacKey, LocalMac>> {
        let Some(aya::maps::Map::LruHashMap(data)) = self.ebpf.map("LOCAL_MACS") else {
            bail!("LOCAL_MACS LRU map missing");
        };
        let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        HashMap::try_from(aya::maps::Map::LruHashMap(duplicate)).context("LOCAL_MACS as a HashMap")
    }

    /// Share a duplicate `CONNTRACK` FD between diagnostics and HA sync. Retain
    /// the original map handle for fenced policy-namespace resets. Every handle
    /// addresses the same kernel map; no flow entries are copied.
    pub fn conntrack_handle(&mut self) -> Result<Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>> {
        if let Some(handle) = &self.conntrack {
            return Ok(handle.clone());
        }
        let Some(aya::maps::Map::LruHashMap(data)) = self.ebpf.map("CONNTRACK") else {
            bail!("CONNTRACK LRU map missing");
        };
        let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        let handle = Arc::new(Mutex::new(
            HashMap::try_from(aya::maps::Map::LruHashMap(duplicate))
                .context("CONNTRACK as a HashMap")?,
        ));
        self.conntrack = Some(handle.clone());
        Ok(handle)
    }

    /// A snapshot of the live NAT flow table (`CONNTRACK`), for the diagnostics
    /// view. Shares the handle with the C9 sync task via [`conntrack_handle`],
    /// so it works whether or not HA is enabled.
    ///
    /// A miss on an individual key is skipped rather than failing the snapshot: the
    /// map is an LRU the data plane mutates constantly, so an entry can be evicted
    /// between listing the keys and reading its value. A diagnostics view that
    /// errored out on that race would be unusable under load — exactly when it
    /// matters.
    ///
    /// [`conntrack_handle`]: Firewall::conntrack_handle
    pub async fn read_flows(&mut self) -> Result<Vec<(FlowKey, FlowState)>> {
        let handle = self.conntrack_handle()?;
        let map = handle.lock().await;
        let entries = crate::conntrack_sync::secure::batch_read(&*map)?;
        drop(map);
        // A timestamp refreshed during the dump belongs to this sample too.
        let now = crate::conntrack_sync::monotonic_ns();
        Ok(entries
            .into_iter()
            .filter(|(key, state)| !state.expired(key.proto, now, self.applied.conntrack))
            .collect())
    }

    /// Duplicate the userspace FD for HA sync while retaining the map in the
    /// firewall. Diagnostics and FlowSpec purges must keep working with HA on.
    /// All handles address the same kernel map; no state or counters are copied.
    pub fn fw_flows_handle(&self) -> Result<HashMap<MapData, FirewallKey, FirewallState>> {
        let Some(aya::maps::Map::LruHashMap(data)) = self.ebpf.map("FW_FLOWS") else {
            bail!("FW_FLOWS LRU map missing");
        };
        let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        HashMap::try_from(aya::maps::Map::LruHashMap(duplicate)).context("FW_FLOWS as a HashMap")
    }
    /// Keep the sequence-number splice alive on a standby without moving the
    /// map out of the firewall: configuration reconciliation must still clear it.
    pub fn syn_flows_handle(&self) -> Result<HashMap<MapData, FlowKey, SynFlow>> {
        let Some(aya::maps::Map::LruHashMap(data)) = self.ebpf.map("SYN_FLOWS") else {
            bail!("SYN_FLOWS LRU map missing");
        };
        let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        HashMap::try_from(aya::maps::Map::LruHashMap(duplicate)).context("SYN_FLOWS as a HashMap")
    }
}

/// How much of the verifier's one-million-instruction complexity budget a loaded
/// program used, on its own line so the `verified <name>` lines stay exact.
/// Headroom is what a datapath change spends, and it differs per kernel, so the
/// verifier checks record it rather than only pass or fail.
fn report_verified_insns(
    name: &str,
    info: std::result::Result<aya::programs::ProgramInfo, aya::programs::ProgramError>,
) {
    match info.map(|info| info.verified_instruction_count()) {
        Ok(Some(count)) => println!("verifier-insns {name} {count}"),
        Ok(None) | Err(_) => println!("verifier-insns {name} unknown"),
    }
}

/// Hand the memory a large transaction freed back to the kernel (PERF-04).
///
/// Parsing and resolving a configuration with tens of thousands of entries
/// allocates far more transiently than it keeps, on whichever runtime worker
/// served the reload. glibc keeps freed pages in that thread's arena, so the
/// agent's resident size ratcheted up with every large commit (148 MB against
/// 47 MB after a reboot with the same configuration). `malloc_trim` returns the
/// free pages of every arena.
pub(crate) fn release_freed_memory() {
    #[cfg(target_env = "gnu")]
    // SAFETY: malloc_trim takes no pointers and only releases free memory.
    unsafe {
        libc::malloc_trim(0);
    }
}

/// Raise the locked-memory rlimit so map allocation succeeds on older kernels
/// that still account BPF memory against `RLIMIT_MEMLOCK`.
/// LPM `(prefix_len, addr)` for a port rule's optional source constraint. `None`
/// ("from any") becomes a `/0` source — prefix == `FIXED_BITS`, address `0` —
/// which the trie matches for every packet; a `Some` CIDR extends the prefix by
/// the block's bits so a specific source outranks a `from any` rule.
/// The prefix length an address constraint matches on, for the specificity byte
/// packed into the rule value. `None` (any) is `0`.
pub(crate) fn cidr_bits(cidr: &Option<Cidr4>) -> u8 {
    cidr.as_ref().map_or(0, |c| c.prefix)
}

/// The `DST_RULES` LPM prefix + key tail for a destination constraint. Only called
/// for a rule that has one, so the `None` arm is the unreachable-but-total case.
pub(crate) fn port_rule_dst_lpm(dst: &Option<Cidr4>) -> (u32, u32) {
    match dst {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedDstPortKey::FIXED_BITS + bits, addr)
        }
        None => (ScopedDstPortKey::prefix_len(0), 0),
    }
}

/// The prefix length an IPv6 address constraint matches on, for the specificity
/// byte packed into the rule value.
pub(crate) fn cidr6_bits(cidr: &Option<Cidr6>) -> u8 {
    cidr.as_ref().map_or(0, |c| c.prefix)
}

/// The `PORT_RULES6` LPM prefix + key tail for an IPv6 source constraint.
pub(crate) fn port_rule_src6_lpm(src: &Option<Cidr6>) -> (u32, [u8; 16]) {
    match src {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedSrcPortKey6::FIXED_BITS + bits, addr)
        }
        None => (ScopedSrcPortKey6::prefix_len(0), [0; 16]),
    }
}

/// The `DST_RULES6` LPM prefix + key tail for an IPv6 destination constraint.
pub(crate) fn port_rule_dst6_lpm(dst: &Option<Cidr6>) -> (u32, [u8; 16]) {
    match dst {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedDstPortKey6::FIXED_BITS + bits, addr)
        }
        None => (ScopedDstPortKey6::prefix_len(0), [0; 16]),
    }
}

pub(crate) fn port_rule_src_lpm(src: &Option<Cidr4>) -> (u32, u32) {
    match src {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedSrcPortKey::FIXED_BITS + bits, addr)
        }
        None => (ScopedSrcPortKey::prefix_len(0), 0),
    }
}

fn bump_memlock_rlimit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `setrlimit` is a plain syscall wrapper; `limit` is fully
    // initialised and outlives the call.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if ret != 0 {
        warn!("could not raise RLIMIT_MEMLOCK (ret={ret}); map creation may fail on old kernels");
    }
}

/// Forward `aya-log` messages emitted by the eBPF program to the user-space
/// logger. Best effort: a program with no log statements simply yields no init.
fn spawn_log_forwarder(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Ok(logger) => {
            // SAFETY: EbpfLogger owns its RingBuf<MapData> and therefore the
            // registered map FD. AsyncFd owns the logger until deregistration;
            // the task only flushes records, never replaces/closes its map.
            // Aya's flush() advances ring positions without exchanging the FD.
            let registered = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            };
            let mut logger = match registered {
                Ok(fd) => fd,
                Err(e) => {
                    warn!("could not register eBPF log fd: {e}");
                    return;
                }
            };
            tokio::spawn(async move {
                loop {
                    let Ok(mut guard) = logger.readable_mut().await else {
                        break;
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => warn!("eBPF logger not initialised: {e}"),
    }
}

/// A MAC address as an operator writes it. Used wherever one appears in a
/// message, so a session, a log line and a diagnostic all name a device the same
/// way.
pub fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Remove every map entry that `old` installed, so a reconfigure doesn't leave
/// stale rules behind. Missing keys are ignored (the entry may already be gone).
fn remove_stale(ebpf: &mut Ebpf, old: &RuntimeConfig) -> Result<()> {
    {
        let mut config: HashMap<_, PolicyId, GlobalConfig> = HashMap::try_from(
            ebpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow!("CONFIG map missing"))?,
        )?;
        for policy in &old.policies {
            let _ = config.remove(&policy.id);
        }
    }
    {
        let mut gates: HashMap<_, PolicyId, PortalGate> = HashMap::try_from(
            ebpf.map_mut("PORTAL_GATES")
                .ok_or_else(|| anyhow!("PORTAL_GATES map missing"))?,
        )?;
        for policy in &old.policies {
            let _ = gates.remove(&policy.id);
        }
    }
    // The six policy tries are not swept here: they are brought to the new
    // configuration by difference against what was written (`policy_tries`).
    {
        let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
            ebpf.map_mut("IFACE_POLICY")
                .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
        )?;
        for iface in &old.interfaces {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = iface_policy.remove(&ifindex);
            }
        }
    }
    {
        let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
            ebpf.map_mut("IFACE_L3")
                .ok_or_else(|| anyhow!("IFACE_L3 map missing"))?,
        )?;
        for iface in &old.interfaces {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = iface_policy.remove(&ifindex);
            }
        }
    }
    {
        let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("IFACE_VNI")
                .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
        )?;
        for iface in &old.interfaces {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = iface_vni.remove(&ifindex);
            }
        }
    }
    {
        let mut masq: HashMap<_, u32, [u8; 4]> = HashMap::try_from(
            ebpf.map_mut("MASQUERADE")
                .ok_or_else(|| anyhow!("MASQUERADE map missing"))?,
        )?;
        for iface in old.interfaces.iter().filter(|i| i.masquerade) {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = masq.remove(&ifindex);
            }
        }
    }
    {
        let mut routes: LpmTrie<_, ScopedAddr, RouteEntry> = LpmTrie::try_from(
            ebpf.map_mut("ROUTES")
                .ok_or_else(|| anyhow!("ROUTES map missing"))?,
        )?;
        for route in &old.routes {
            let (prefix, data) = route.dest.lpm_key();
            let _ = routes.remove(&Key::new(
                ScopedAddr::POLICY_BITS + prefix,
                ScopedAddr::new(route.policy, data),
            ));
        }
    }
    {
        let mut services: HashMap<_, ServiceKey, ServiceValue> = HashMap::try_from(
            ebpf.map_mut("SERVICES")
                .ok_or_else(|| anyhow!("SERVICES map missing"))?,
        )?;
        for service in &old.services {
            let _ = services.remove(&service.key);
        }
    }
    {
        // Overlay FDB is an LPM trie keyed by `(vni, inner dst prefix)`; drop the
        // old set. `OVERLAY_CONFIG` needs no cleanup — it is always rewritten.
        let mut fdb: LpmTrie<_, TunnelKey, TunnelEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("OVERLAY_FDB")
                .ok_or_else(|| anyhow!("OVERLAY_FDB map missing"))?,
        )?;
        for tunnel in &old.tunnels {
            let (_, addr) = tunnel.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(tunnel.inner_dst.prefix),
                TunnelKey::new(tunnel.vni, addr),
            );
            let _ = fdb.remove(&key);
        }
    }
    {
        // B1 MAC-FDB is a HashMap keyed by `(vni, inner dst MAC)`; drop the old
        // set, mirroring the OVERLAY_FDB reconcile above.
        let mut mac_fdb: HashMap<_, MacFdbKey, TunnelEndpoint> = HashMap::try_from(
            ebpf.map_mut("MAC_FDB")
                .ok_or_else(|| anyhow!("MAC_FDB map missing"))?,
        )?;
        for mr in &old.mac_routes {
            let _ = mac_fdb.remove(&MacFdbKey::new(mr.vni, mr.mac));
        }
    }
    {
        // The set of segments this host admits a decap into. Drop the old set;
        // program_interfaces and program_overlay re-add every still-current VNI,
        // so a segment shared with a surviving port or IRB route is unaffected.
        //
        // Reconciled rather than left to accumulate because this map is a
        // **tenant-isolation** boundary: a VNI that lingers after its last local
        // port and route are gone lets any trusted peer VTEP keep injecting inner
        // frames into a segment this host no longer serves.
        let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("LOCAL_VNIS")
                .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
        )?;
        for vni in admitted_vnis(old) {
            let _ = local_vnis.remove(&vni);
        }
    }
    {
        // B7 IRB_ROUTES is an LpmTrie keyed exactly like OVERLAY_FDB; drop the old
        // set so a prefix the control plane withdrew stops being routed, rather
        // than lingering and sending its traffic to a VTEP that no longer owns it.
        let mut irb: LpmTrie<_, TunnelKey, IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("IRB_ROUTES")
                .ok_or_else(|| anyhow!("IRB_ROUTES map missing"))?,
        )?;
        for r in &old.irb_routes {
            let (_, addr) = r.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(r.inner_dst.prefix),
                TunnelKey::new(r.vni, addr),
            );
            let _ = irb.remove(&key);
        }
    }
    {
        // B2 flood set: drop every VNI that had a flood set; program_overlay
        // rebuilds each still-current one from the fresh config. Keyed by a bare
        // VNI, so removing by the old flood entries' distinct VNIs clears it.
        let mut flood: HashMap<_, u32, FloodSet> = HashMap::try_from(
            ebpf.map_mut("FLOOD_LIST")
                .ok_or_else(|| anyhow!("FLOOD_LIST map missing"))?,
        )?;
        for fv in &old.flood_vteps {
            let _ = flood.remove(&fv.vni);
        }
    }
    {
        // Trusted-VTEP set (C2): drop the old peers; program_overlay re-adds every
        // still-current one, so a peer shared by another live tunnel survives.
        // Both tunnels and MAC routes contribute trusted decap peers.
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for tunnel in &old.tunnels {
            let _ = peers.remove(&tunnel.remote_vtep_ip);
        }
        for mr in &old.mac_routes {
            let _ = peers.remove(&mr.remote_vtep_ip);
        }
        for r in &old.irb_routes {
            let _ = peers.remove(&r.remote_vtep_ip);
        }
        // Flood VTEPs are trusted decap peers too (they receive our encapped BUM
        // copies and send their own back).
        for fv in &old.flood_vteps {
            let _ = peers.remove(&fv.remote_vtep_ip);
        }
    }
    {
        // B9 SRV6_IRB_ROUTES is an LpmTrie keyed exactly like IRB_ROUTES, and needs
        // the same treatment for the same reason: a withdrawn prefix that lingers
        // keeps routing a tenant's traffic to a peer that no longer owns it.
        // (`program_srv6` reconciles the flood set by key, but a trie cannot be
        // enumerated, so its stale keys are removed from the *old* config here.)
        let mut irb: LpmTrie<_, TunnelKey, Srv6IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("SRV6_IRB_ROUTES")
                .ok_or_else(|| anyhow!("SRV6_IRB_ROUTES map missing"))?,
        )?;
        for r in &old.srv6_irb_routes {
            let (_, addr) = r.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(r.inner_dst.prefix),
                TunnelKey::new(r.vni, addr),
            );
            let _ = irb.remove(&key);
        }
    }
    if let Some(old_srv6) = &old.srv6 {
        // B9 trusted-SRv6-peer set (C2): drop the old peers so a peer removed from
        // the config stops being an authorized decap source on this live
        // reconfigure; program_srv6 re-adds every still-current one. (Unlike the
        // SRv6 SID/FDB maps this security-sensitive set is reconciled, so a
        // de-authorized peer never lingers trusted until the next restart.)
        let mut srv6_peers: HashMap<_, [u8; 16], u8> = HashMap::try_from(
            ebpf.map_mut("SRV6_PEERS")
                .ok_or_else(|| anyhow!("SRV6_PEERS map missing"))?,
        )?;
        for p in &old_srv6.peers {
            let _ = srv6_peers.remove(p);
        }
    }
    {
        let mut arp: HashMap<_, ArpKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ARP_TABLE")
                .ok_or_else(|| anyhow!("ARP_TABLE map missing"))?,
        )?;
        for n in &old.neighbors {
            let _ = arp.remove(&ArpKey::new(n.vni, n.ip));
        }
    }
    {
        let mut nd: HashMap<_, NdKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ND_TABLE")
                .ok_or_else(|| anyhow!("ND_TABLE map missing"))?,
        )?;
        for n in &old.nd_neighbors {
            let _ = nd.remove(&NdKey::new(n.vni, n.ip));
        }
    }
    Ok(())
}

/// Host-dependent values must be observed before a candidate changes policy.
#[derive(Clone, PartialEq, Eq)]
struct PreparedHostConfig {
    overlay: OverlayConfig,
    srv6: Srv6Config,
    route_ifindices: BTreeMap<String, u32>,
    ipv4: Ipv4Inventory,
    /// Every address this host holds, both families, when the configuration
    /// has a `dst-local` rule to resolve with it; empty otherwise, so a
    /// configuration without one keeps its old refresh behaviour exactly.
    local: BTreeSet<std::net::IpAddr>,
}

/// The merged source intent and the applied maps are known to agree only after
/// a complete successful transaction, including reopening. In particular, a
/// failed reopen or successful rollback cannot authorize an additive shortcut.
struct AppliedIntent {
    current: bool,
}

impl AppliedIntent {
    fn begin(&mut self) {
        self.current = false;
    }

    fn finish(&mut self, reopened: Result<()>) -> Result<()> {
        reopened?;
        self.current = true;
        Ok(())
    }

    fn allows_address_refresh(&self, state: Option<u32>, hooks_unchanged: bool) -> bool {
        self.current && state == Some(CONFIG_READY) && hooks_unchanged
    }
}

/// Plan a host-only refresh for the *same applied intent*. Every exclusion must
/// take the ordinary closed-gate transaction instead. Exact old address tuples
/// remain present; each new tuple has an already represented mask/network on
/// that interface. Hence subnet membership is identical for every possible
/// target, including ambiguous reply policies and runtime mapping destinations.
/// Only exact LOCAL_EGRESS_ADDRS membership grows; all other maps are unchanged.
fn local_address_additions(
    previous: &PreparedHostConfig,
    observed: &PreparedHostConfig,
) -> Option<BTreeSet<[u8; 8]>> {
    // A changed local set changes rule-trie entries (`dst-local`), which
    // only the full closed-gate rewrite may do.
    if previous.overlay != observed.overlay
        || previous.srv6 != observed.srv6
        || previous.route_ifindices != observed.route_ifindices
        || previous.ipv4.len() != observed.ipv4.len()
        || previous.local != observed.local
    {
        return None;
    }
    let mut additions = BTreeSet::new();
    for (name, old) in &previous.ipv4 {
        let new = observed.ipv4.get(name)?;
        if old.ifindex != new.ifindex
            || old.primary != new.primary
            || old.dhcp_mac != new.dhcp_mac
            || !old.prefixes.is_subset(&new.prefixes)
        {
            return None;
        }
        for (address, mask) in new.prefixes.difference(&old.prefixes) {
            let network = u32::from_be_bytes(*address) & u32::from_be_bytes(*mask);
            if !old.prefixes.iter().any(|(old_address, old_mask)| {
                old_mask == mask
                    && (u32::from_be_bytes(*old_address) & u32::from_be_bytes(*mask)) == network
            }) {
                return None;
            }
            if !old
                .prefixes
                .iter()
                .any(|(old_address, _)| old_address == address)
            {
                additions.insert(local_egress_address_key(new.ifindex, *address));
            }
        }
    }
    Some(additions)
}

fn prepare_host_config(cfg: &RuntimeConfig) -> Result<PreparedHostConfig> {
    let _timing = timing::Span::start(timing::Phase::HostPrepare);
    let overlay = match cfg.overlay.as_ref() {
        Some(o) => {
            let local_mac = match o.local_mac {
                Some(mac) => mac,
                None => read_iface_mac(&o.underlay_iface)?,
            };
            OverlayConfig::new(
                o.local_vtep_ip,
                local_mac,
                o.udp_port,
                o.encap,
                o.underlay_mtu,
            )
        }
        None => OverlayConfig::DISABLED,
    };
    let srv6 = match cfg.srv6.as_ref() {
        Some(s) => {
            let local_mac = match s.local_mac {
                Some(mac) => mac,
                None => read_iface_mac(&s.underlay_iface)?,
            };
            Srv6Config::new(s.local_src, local_mac, s.underlay_mtu)
        }
        None => Srv6Config::DISABLED,
    };
    let (ipv4, local) = observe_host(cfg)?;
    Ok(PreparedHostConfig {
        overlay,
        srv6,
        route_ifindices: route_interface_indices(&cfg.routes)?,
        ipv4,
        local,
    })
}

/// One rtnetlink observation, as the two host facts derived from it: the
/// configured interfaces' IPv4 inventory, and — only when a rule needs it —
/// every address the host holds.
fn observe_host(cfg: &RuntimeConfig) -> Result<(Ipv4Inventory, BTreeSet<std::net::IpAddr>)> {
    let _timing = timing::Span::start(timing::Phase::HostObserver);
    let links = crate::host_inventory::read()?;
    let local = if crate::local_destination::has_local_rules(cfg) {
        crate::local_destination::observed(&links)
    } else {
        BTreeSet::new()
    };
    Ok((ipv4_inventory_from(links, &cfg.interfaces)?, local))
}

fn revalidate_host_config(cfg: &RuntimeConfig, prepared: &PreparedHostConfig) -> Result<()> {
    let _timing = timing::Span::start(timing::Phase::HostRevalidate);
    let (ipv4, local) = observe_host(cfg)?;
    anyhow::ensure!(
        ipv4 == prepared.ipv4,
        "interface IPv4 inventory no longer matches the prepared policy"
    );
    anyhow::ensure!(
        local == prepared.local,
        "host addresses no longer match the prepared local-destination rules"
    );
    anyhow::ensure!(
        route_interface_indices(&cfg.routes)? == prepared.route_ifindices,
        "route interface identities no longer match the prepared policy"
    );
    Ok(())
}

fn route_interface_indices(routes: &[ResolvedRoute]) -> Result<BTreeMap<String, u32>> {
    let mut indices = BTreeMap::new();
    for name in routes
        .iter()
        .map(|route| &route.out_iface)
        .collect::<BTreeSet<_>>()
    {
        match if_nametoindex(name) {
            Ok(index) => {
                indices.insert(name.clone(), index);
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(interface_missing) => {}
            Err(error) => return Err(error).context("checking route interface dependencies"),
        }
    }
    Ok(indices)
}

/// Evidence for one continuously closed policy transaction, never a request to
/// skip synchronization. The initial object has no attached packet readers;
/// every live transaction must instead complete the real global reader drain.
/// Do not retain this capability across reopening APPLY_STATE or releasing the
/// firewall's exclusive writer. It deliberately has no reopening Drop action.
enum ReaderQuiescence {
    Unattached,
    Drained,
}

impl ReaderQuiescence {
    fn drain_with(drain: impl FnOnce() -> Result<()>) -> Result<Self> {
        drain()?;
        Ok(Self::Drained)
    }

    fn validate(&self, gate: u32, replaces_live: bool) -> Result<()> {
        anyhow::ensure!(
            gate == CONFIG_UPDATING,
            "policy writer requires a closed update gate"
        );
        anyhow::ensure!(
            !replaces_live || matches!(self, Self::Drained),
            "live policy replacement requires drained packet readers"
        );
        Ok(())
    }
}

/// Write policy under a continuously closed, already-quiesced gate. Candidate
/// and rollback share the same drain: neither this function nor its caller
/// reopens APPLY_STATE between them. New XDP/TC/BUM entries reject that gate,
/// and the first grace period already drained older invocations (including
/// their tail calls), even while CONFIG_EPOCH becomes even between writes.
/// When `old` is `Some`, remove its entries before installing the replacement.
/// `old` is the configuration whose entries are to be removed, with the host
/// facts it was written with: its `dst-local` rules were written as one
/// entry per address that host held then, and only those exact entries can be
/// found again to remove.
#[allow(clippy::too_many_arguments)]
fn apply_config_quiesced(
    ebpf: &mut Ebpf,
    cfg: &RuntimeConfig,
    old: Option<(&RuntimeConfig, &PreparedHostConfig)>,
    prepared: &PreparedHostConfig,
    reset: bool,
    quiesced: &ReaderQuiescence,
    plan: &PolicyPlan,
    written: &mut crate::policy_tries::PolicyTries,
) -> Result<()> {
    let _timing = timing::Span::start(timing::Phase::MapApply);
    // The writers below see only concrete rules; the symbolic configuration
    // stays what the caller keeps (and fingerprints).
    let cfg = &*crate::local_destination::concrete(cfg, &prepared.local);
    let old_concrete = old.map(|(o, host)| crate::local_destination::concrete(o, &host.local));
    let old = old_concrete.as_deref();
    let gate = Array::<_, u32>::try_from(
        ebpf.map("APPLY_STATE")
            .ok_or_else(|| anyhow!("APPLY_STATE map missing"))?,
    )?
    .get(&0, 0)
    .context("checking the quiesced policy writer gate")?;
    quiesced.validate(gate, old.is_some())?;
    cfg.validate_firewall_capacity()?;
    let writing = {
        let mut epoch = Array::<_, u64>::try_from(
            ebpf.map_mut("CONFIG_EPOCH")
                .ok_or_else(|| anyhow!("CONFIG_EPOCH map missing"))?,
        )?;
        let before = epoch.get(&0, 0)?;
        let writing = if before & 1 == 0 {
            before.wrapping_add(1)
        } else {
            before
        };
        epoch.set(0, writing, 0)?;
        writing
    };
    if let Some(old) = old {
        if reset {
            reset_runtime_namespace(ebpf)?;
        }
        remove_stale(ebpf, old)?;
    }

    if old.is_some() {
        let wanted: BTreeSet<(u32, u32)> = cfg
            .policies
            .iter()
            .flat_map(|p| {
                std::iter::once((p.id, 0)).chain(p.port_rules.iter().map(move |r| (p.id, r.id())))
            })
            .collect();
        let mut counters = aya::maps::PerCpuHashMap::<
            _,
            velstra_common::RuleCounterKey,
            velstra_common::RuleCounters,
        >::try_from(
            ebpf.map_mut("RULE_COUNTERS")
                .ok_or_else(|| anyhow!("RULE_COUNTERS map missing"))?,
        )?;
        let stale: Vec<_> = counters
            .keys()
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|k| !wanted.contains(&(k.policy, k.rule_id)))
            .collect();
        for key in stale {
            counters.remove(&key)?;
        }
    }
    program_fail_closed(ebpf, cfg.fail_closed)?;
    // Replicated mappings must remain discoverable by deployed peers. A
    // service restart creates fresh, unpinned NAT maps before changing modes.
    Array::<_, u32>::try_from(
        ebpf.map_mut("NAPT_MODE")
            .ok_or_else(|| anyhow!("NAPT_MODE map missing"))?,
    )?
    .set(0, standalone_napt_mode(cfg), 0)
    .context("programming standalone NAT allocation mode")?;
    let mut timeouts = Array::<_, velstra_common::ConntrackTimeouts>::try_from(
        ebpf.map_mut("CT_TIMEOUTS")
            .ok_or_else(|| anyhow!("CT_TIMEOUTS map missing"))?,
    )?;
    timeouts
        .set(0, cfg.conntrack, 0)
        .context("programming conntrack timeouts")?;

    program_policies(ebpf, &cfg.policies, plan, written)?;
    program_interfaces(ebpf, &cfg.interfaces)?;
    program_routes(ebpf, &cfg.routes)?;
    program_services(ebpf, &cfg.services, &cfg.interfaces, &prepared.ipv4)?;
    program_port_forwards(ebpf, &cfg.port_forwards, &cfg.interfaces, &prepared.ipv4)?;
    program_synproxy(ebpf, &cfg.synproxy)?;
    program_masquerade(ebpf, &cfg.interfaces, &prepared.ipv4)?;
    program_mss_clamp(ebpf, &cfg.interfaces)?;
    program_port_bindings(ebpf, &cfg.interfaces)?;
    program_port_limits(ebpf, &cfg.interfaces)?;
    program_mac_rules(ebpf, &cfg.policies)?;
    program_cgnat(ebpf, &cfg.interfaces)?;
    program_npt66(ebpf, &cfg.npt66)?;
    program_overlay(
        ebpf,
        prepared.overlay,
        &cfg.tunnels,
        &cfg.mac_routes,
        &cfg.irb_routes,
        &cfg.neighbors,
        &cfg.nd_neighbors,
        &cfg.flood_vteps,
    )?;
    program_srv6(
        ebpf,
        cfg.srv6.as_ref(),
        prepared.srv6,
        &cfg.srv6_routes,
        &cfg.srv6_local_sids,
        &cfg.srv6_floods,
        &cfg.srv6_irb_routes,
    )?;

    Array::<_, u64>::try_from(
        ebpf.map_mut("CONFIG_EPOCH")
            .ok_or_else(|| anyhow!("CONFIG_EPOCH map missing"))?,
    )?
    .set(0, writing.wrapping_add(1), 0)?;
    Ok(())
}

/// Called only with CONFIG_EPOCH odd and all earlier packet readers drained.
/// State from a previous policy-ID owner must not authorize its new owner.
fn reset_runtime_namespace(ebpf: &mut Ebpf) -> Result<()> {
    fn clear<K: aya::Pod, V: aya::Pod>(ebpf: &mut Ebpf, name: &str) -> Result<()> {
        let mut map: HashMap<_, K, V> = HashMap::try_from(
            ebpf.map_mut(name)
                .ok_or_else(|| anyhow!("{name} map missing"))?,
        )?;
        let keys = map.keys().collect::<std::result::Result<Vec<_>, _>>()?;
        for key in keys {
            map.remove(&key)?;
        }
        Ok(())
    }
    clear::<FirewallKey, FirewallState>(ebpf, "FW_FLOWS")?;
    clear::<FlowKey, FlowState>(ebpf, "CONNTRACK")?;
    clear::<FlowKey, SynFlow>(ebpf, "SYN_FLOWS")?;
    clear::<PortalClientKey, u8>(ebpf, "PORTAL_CLIENTS")?;
    clear::<PortalSeenKey, [u8; 6]>(ebpf, "PORTAL_SEEN")?;
    clear::<LocalMacKey, LocalMac>(ebpf, "LOCAL_MACS")?;
    clear::<ArpKey, ArpEntry>(ebpf, "ARP_TABLE")?;
    clear::<NdKey, ArpEntry>(ebpf, "ND_TABLE")?;
    let mut counters = aya::maps::PerCpuHashMap::<
        _,
        velstra_common::RuleCounterKey,
        velstra_common::RuleCounters,
    >::try_from(
        ebpf.map_mut("RULE_COUNTERS")
            .ok_or_else(|| anyhow!("RULE_COUNTERS missing"))?,
    )?;
    let keys = counters
        .keys()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for key in keys {
        counters.remove(&key)?;
    }
    let mut events = aya::maps::RingBuf::try_from(
        ebpf.map_mut("PACKET_EVENTS")
            .ok_or_else(|| anyhow!("PACKET_EVENTS missing"))?,
    )?;
    while events.next().is_some() {}
    Ok(())
}

/// Write the host-wide `FAIL_CLOSED` flag: whether the data plane drops a packet
/// it cannot parse instead of passing it. Slot `0` is always written — including
/// the `false` (fail-open) default — so a `reconfigure` that turns the flag off
/// actually takes it back rather than leaving the old value in the map.
fn standalone_napt_mode(cfg: &RuntimeConfig) -> u32 {
    u32::from(cfg.ha.is_none() && cfg.conntrack_sync.is_none())
}

fn program_fail_closed(ebpf: &mut Ebpf, fail_closed: bool) -> Result<()> {
    let mut map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("FAIL_CLOSED")
            .ok_or_else(|| anyhow!("FAIL_CLOSED map missing"))?,
    )?;
    map.set(0, u32::from(fail_closed), 0)
        .context("writing FAIL_CLOSED")?;
    Ok(())
}

/// Assign each rate-limited rule a `RULE_LIMITS` slot and the bucket it starts
/// with. Pure, so the policy tries can be computed before the gate closes.
///
/// Slots are handed out in iteration order and are 1-based, since `0` is what a
/// rule's packed value carries for "unlimited". The slot for each `(policy id,
/// rule index)` is stamped into the rule's trie value.
///
/// Capacity is validated before any live rules are changed. Keep the defensive
/// check here too: an unrepresentable limit must never become an unlimited rule.
pub(crate) fn rate_limit_plan(policies: &[PolicyConfig]) -> Result<RateLimitPlan> {
    let mut slots = std::collections::HashMap::new();
    let mut buckets: Vec<(u32, RateBucket)> = Vec::new();
    for policy in policies {
        for (index, rule) in policy.port_rules.iter().enumerate() {
            let Some((rate, burst)) = rule.limit else {
                continue;
            };
            let slot = buckets.len() as u32 + 1;
            if slot > MAX_RULE_LIMITS {
                bail!(
                    "more than {MAX_RULE_LIMITS} rate-limited rules; refusing an unlimited fallback"
                );
            }
            slots.insert((policy.id, index), slot);
            buckets.push((slot, RateBucket::new(rate, burst)));
        }
    }
    Ok(RateLimitPlan { slots, buckets })
}

/// See [`rate_limit_plan`].
pub(crate) struct RateLimitPlan {
    pub(crate) slots: std::collections::HashMap<(PolicyId, usize), u32>,
    buckets: Vec<(u32, RateBucket)>,
}

/// Everything a policy write needs that can be worked out — and refused —
/// before the datapath gate closes.
pub(crate) struct PolicyPlan {
    limits: RateLimitPlan,
    tries: crate::policy_tries::PolicyTries,
}

impl PolicyPlan {
    /// Resolve `cfg`'s policies against this host and refuse what cannot fit.
    /// The plan is made from the concrete configuration — every `dst-local`
    /// rule expanded into the host routes `host` observed (DP-16) — exactly
    /// as `apply_config_quiesced` writes it, so rate-limit slot indices and
    /// trie entries describe the same rule list.
    fn new(ebpf: &Ebpf, cfg: &RuntimeConfig, host: &PreparedHostConfig) -> Result<Self> {
        let concrete = crate::local_destination::concrete(cfg, &host.local);
        let policies = &concrete.policies;
        let limits = rate_limit_plan(policies)?;
        let tries = crate::policy_tries::desired(policies, &limits.slots, rule_ifindex)?;
        crate::policy_tries::check_capacity(ebpf, &tries)?;
        Ok(Self { limits, tries })
    }
}

fn program_rate_limits(ebpf: &mut Ebpf, plan: &RateLimitPlan) -> Result<()> {
    if plan.buckets.is_empty() {
        return Ok(());
    }
    let mut map: Array<_, RateBucket> = Array::try_from(
        ebpf.map_mut("RULE_LIMITS")
            .ok_or_else(|| anyhow!("RULE_LIMITS map missing"))?,
    )?;
    for (slot, bucket) in &plan.buckets {
        map.set(*slot, bucket, 0)
            .with_context(|| format!("inserting rate limit slot {slot}"))?;
    }
    Ok(())
}

/// Write every policy's `CONFIG` and `PORTAL_GATES` entry, then bring the six
/// policy tries from what was `written` to the plan by difference.
fn program_policies(
    ebpf: &mut Ebpf,
    policies: &[PolicyConfig],
    plan: &PolicyPlan,
    written: &mut crate::policy_tries::PolicyTries,
) -> Result<()> {
    program_rate_limits(ebpf, &plan.limits)?;
    {
        let mut config: HashMap<_, PolicyId, GlobalConfig> = HashMap::try_from(
            ebpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow!("CONFIG map missing"))?,
        )?;
        for policy in policies {
            config
                .insert(policy.id, policy.global, 0)
                .with_context(|| format!("writing CONFIG for policy {}", policy.id))?;
        }
    }
    {
        // C20: the gate entry and the policy's portal flag are written by the
        // same apply, in this order, so the flag is never set while the gate it
        // reads is missing.
        let mut gates: HashMap<_, PolicyId, PortalGate> = HashMap::try_from(
            ebpf.map_mut("PORTAL_GATES")
                .ok_or_else(|| anyhow!("PORTAL_GATES map missing"))?,
        )?;
        for policy in policies {
            match policy.portal {
                Some(gate) => gates
                    .insert(policy.id, gate, 0)
                    .with_context(|| format!("writing PORTAL_GATES for policy {}", policy.id))?,
                // A policy that lost its portal must lose its gate too, or a
                // later re-gating would inherit yesterday's address.
                None => {
                    let _ = gates.remove(&policy.id);
                }
            }
        }
    }
    let diff = crate::policy_tries::sync_all(ebpf, written, &plan.tries)?;
    if diff.written + diff.removed > 0 {
        log::info!(
            "policy tries: {} written, {} removed, {} unchanged",
            diff.written,
            diff.removed,
            diff.unchanged
        );
    }
    Ok(())
}

/// Every VNI a config could have admitted a decap into: each tenant port's
/// segment, plus the **routed** VNI of every IRB route (B7), which belongs to no
/// local port and is therefore registered from the routes alone.
///
/// Used to *clear* the old set on a reconfigure. The removal side is deliberately
/// broader than the add side: `program_interfaces` only registers a VNI whose
/// interface actually exists on the host right now, whereas this must name
/// everything the previous config might have registered — anything it misses is
/// a segment that stays decap-admitted after its last local port is gone.
fn admitted_vnis(cfg: &RuntimeConfig) -> BTreeSet<u32> {
    cfg.interfaces
        .iter()
        .map(|i| i.vni)
        .chain(cfg.irb_routes.iter().map(|r| r.l3_vni))
        .filter(|vni| *vni != 0)
        .collect()
}

/// Map each configured interface to its policy id (`IFACE_POLICY`) and overlay
/// segment (`IFACE_VNI`). The two are independent: a port's firewall ruleset and
/// its virtual network are separate concerns.
fn raw_ip_link(kind: u32) -> bool {
    // Linux ARPHRD_PPP, RAWIP, TUNNEL, TUNNEL6, SIT, NONE (WireGuard/TUN).
    matches!(kind, 512 | 519 | 768 | 769 | 776 | 65534)
}

fn program_link_layer(ebpf: &mut Ebpf, name: &str) -> Result<bool> {
    let index = if_nametoindex(name)?;
    let kind: u32 = std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
        .with_context(|| format!("reading link type of {name}"))?
        .trim()
        .parse()
        .context("invalid kernel link type")?;
    let raw = raw_ip_link(kind);
    let mut map: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.map_mut("IFACE_L3")
            .ok_or_else(|| anyhow!("IFACE_L3 map missing"))?,
    )?;
    if raw {
        map.insert(index, 1, 0)?;
    } else if map.get(&index, 0).is_ok() {
        map.remove(&index)?;
    }
    Ok(raw)
}

fn program_interfaces(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let mut raw_links = HashSet::new();
    for iface in interfaces {
        if if_nametoindex(&iface.name).is_ok() && program_link_layer(ebpf, &iface.name)? {
            raw_links.insert(iface.name.as_str());
        }
    }
    if interfaces.is_empty() {
        return Ok(());
    }
    // Resolve names to ifindexes, skipping any interface that doesn't exist yet
    // (e.g. a pod veth the controller named before the CNI created it). The
    // config-interface reconcile programs + attaches it once it appears, so a
    // not-yet-present interface must not fail the whole reconfigure.
    let prepared: Vec<(u32, PolicyId, u32)> = interfaces
        .iter()
        .filter_map(|i| match if_nametoindex(&i.name) {
            Ok(ifindex) => Some((
                ifindex,
                i.policy,
                if raw_links.contains(i.name.as_str()) {
                    0
                } else {
                    i.vni
                },
            )),
            Err(_) => {
                log::debug!("interface {} not present yet; deferring its maps", i.name);
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }

    {
        let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
            ebpf.map_mut("IFACE_POLICY")
                .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
        )?;
        for (ifindex, policy_id, _) in &prepared {
            iface_policy
                .insert(ifindex, policy_id, 0)
                .with_context(|| format!("assigning ifindex {ifindex} to policy {policy_id}"))?;
        }
    }

    {
        let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("IFACE_VNI")
                .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
        )?;
        for (ifindex, _, vni) in &prepared {
            iface_vni
                .insert(ifindex, vni, 0)
                .with_context(|| format!("assigning ifindex {ifindex} to vni {vni}"))?;
        }
    }

    {
        let mut tx_ports: DevMap<_> = DevMap::try_from(
            ebpf.map_mut("TX_PORTS")
                .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
        )?;
        for (ifindex, _, _) in &prepared {
            tx_ports
                .set(*ifindex, *ifindex, None, 0)
                .with_context(|| format!("registering local redirect device {ifindex}"))?;
        }
    }

    // The set of segments this host serves, for decap VNI enforcement: a tunnel
    // frame is only decapsulated into a VNI a local tenant port lives on. Value is
    // a reserved per-VNI bridge ifindex (0 today ⇒ shared kernel bridge).
    let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.map_mut("LOCAL_VNIS")
            .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
    )?;
    for (_, _, vni) in &prepared {
        if *vni != 0 {
            local_vnis
                .insert(vni, 0u32, 0)
                .with_context(|| format!("registering local vni {vni}"))?;
        }
    }
    Ok(())
}

/// An interface's name from its index, falling back to `if<N>` so a NIC that has
/// gone away still produces a readable line rather than an error.
fn if_indextoname(ifindex: u32) -> String {
    let mut buf = [0i8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, which is what the call is documented to
    // write at most; a null return means the index is gone and we fall back.
    let ok = unsafe { !libc::if_indextoname(ifindex, buf.as_mut_ptr()).is_null() };
    if ok {
        // SAFETY: on success the kernel wrote a NUL-terminated name into `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        if let Ok(s) = name.to_str() {
            return s.to_string();
        }
    }
    format!("if{ifindex}")
}

/// Program the Phase 3 load-balancer maps: `BACKENDS` (a flat pool) and
/// `SERVICES` (`(VIP, port, proto)` → a window into that pool). No-op without
/// services.
fn program_services(
    ebpf: &mut Ebpf,
    services: &[ResolvedService],
    interfaces: &[ResolvedInterface],
    ipv4: &Ipv4Inventory,
) -> Result<()> {
    if services.is_empty() {
        return Ok(());
    }

    // Flatten every service's pool into one array, recording each service's
    // [start, count) window as we go.
    let mut flat: Vec<Backend> = Vec::new();
    let mut entries: Vec<(ServiceKey, ServiceValue)> = Vec::new();
    for service in services {
        let start = flat.len() as u32;
        flat.extend_from_slice(&service.backends);
        // Only the live prefix is offered to new flows. A draining member is
        // still *in* the array — it costs one slot and keeps the window
        // contiguous — and simply sits past the end of it, so nothing new is
        // sent there. Its established flows are untouched: they are answered
        // from conntrack, which holds the backend's address rather than its
        // place in the pool.
        let count = service.live as u32;
        entries.push((
            service.key,
            if service.router_nat {
                // The pool's reply policy, explicit config first. Resolved from the
                // pool rather than from one member so a pool spread across zones
                // yields none: one entry cannot name two zones, and naming either
                // would leave the other's replies unadmitted.
                let reply = if service.reply_policy != 0 {
                    service.reply_policy
                } else {
                    pool_reply_policy(&service.backends, interfaces, ipv4)
                };
                ServiceValue::new_router_nat(start, count, reply)
                    .with_client_affinity(service.client_affinity)
            } else {
                ServiceValue::new(start, count).with_client_affinity(service.client_affinity)
            },
        ));
    }

    {
        let mut backends: Array<_, Backend> = Array::try_from(
            ebpf.map_mut("BACKENDS")
                .ok_or_else(|| anyhow!("BACKENDS map missing"))?,
        )?;
        for (index, backend) in flat.iter().enumerate() {
            backends
                .set(index as u32, backend, 0)
                .context("inserting backend")?;
        }
    }

    let mut svc_map: HashMap<_, ServiceKey, ServiceValue> = HashMap::try_from(
        ebpf.map_mut("SERVICES")
            .ok_or_else(|| anyhow!("SERVICES map missing"))?,
    )?;
    for (key, value) in &entries {
        svc_map.insert(key, value, 0).context("inserting service")?;
    }

    Ok(())
}

/// Write the Phase 4 `PORT_FORWARDS` map: `(policy, proto, dport)` →
/// internal `(ip, port)`. Keyed by [`ScopedPortKey`] like the firewall's port
/// rules, so the data plane looks it up the same way.
fn program_port_forwards(
    ebpf: &mut Ebpf,
    forwards: &[ResolvedPortForward],
    interfaces: &[ResolvedInterface],
    ipv4: &Ipv4Inventory,
) -> Result<()> {
    // Deliberately no early return: deleting the last port forward is the case
    // where leaving the map untouched kept forwarding it inward.
    //
    // Resolve each target's reply policy from the common host snapshot. A config
    // that states one explicitly wins: it can name a zone reached
    // over a route, which no interface subnet contains.
    let prepared: Vec<(ScopedPortKey, PortFwd)> = forwards
        .iter()
        .map(|pf| {
            let reply = if pf.reply_policy != 0 {
                pf.reply_policy
            } else {
                resolve_reply_policy(pf.dst_ip, interfaces, ipv4)
            };
            (
                ScopedPortKey::new(pf.policy, pf.proto, pf.port),
                PortFwd::new_hairpin(pf.dst_ip, pf.dst_port, pf.match_dst, pf.snat_ip)
                    .with_reply_policy(reply)
                    .with_local_destination(pf.local_destination),
            )
        })
        .collect();
    let keep: HashSet<ScopedPortKey> = prepared.iter().map(|(k, _)| *k).collect();
    let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
        ebpf.map_mut("PORT_FORWARDS")
            .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (key, value) in &prepared {
        map.insert(key, value, 0)
            .context("inserting port-forward")?;
    }
    Ok(())
}

/// Write the C15 `SYNPROXY` map and, the first time a proxy is configured, the
/// key its cookies are minted with.
///
/// **The key is generated here, per boot, from the kernel's random source.** It
/// is the whole basis of the defence: anyone who knows it can mint a cookie for
/// a connection they cannot receive, and so walk straight past the proxy. It is
/// therefore never derived from the config, never logged, and never the same
/// twice — a fixed key in a shipped image would protect nothing at all.
///
/// Rotating it on every reconfigure would be worse than useless: every client
/// mid-handshake would have its ACK rejected. So it is written once, when it is
/// still zero.
fn program_synproxy(ebpf: &mut Ebpf, ports: &[ResolvedSynProxy]) -> Result<()> {
    // The cookie key is drawn only when a port actually uses it; the port map is
    // reconciled either way, so unprotecting the last port takes effect.
    if !ports.is_empty() {
        let mut secret: Array<_, u64> = Array::try_from(
            ebpf.map_mut("SYN_SECRET")
                .ok_or_else(|| anyhow!("SYN_SECRET map missing"))?,
        )?;
        let installed = secret.get(&0, 0).unwrap_or(0) | secret.get(&1, 0).unwrap_or(0);
        if installed == 0 {
            // Straight from the kernel's pool. No crate for this: a sixteen-byte
            // read is the whole requirement, and a dependency that could ever be
            // swapped for something deterministic sits under the one secret the
            // feature cannot afford to have guessed.
            let mut bytes = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
                .context("drawing a SYN-cookie key from /dev/urandom")?;
            secret
                .set(0, u64::from_ne_bytes(bytes[..8].try_into().unwrap()), 0)
                .context("installing the SYN-cookie key")?;
            secret
                .set(1, u64::from_ne_bytes(bytes[8..].try_into().unwrap()), 0)
                .context("installing the SYN-cookie key")?;
        }
    }

    let keep: HashSet<SynProxyKey> = ports.iter().map(|p| SynProxyKey::tcp(p.port)).collect();
    let mut map: HashMap<_, SynProxyKey, SynProxyCfg> = HashMap::try_from(
        ebpf.map_mut("SYNPROXY")
            .ok_or_else(|| anyhow!("SYNPROXY map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for port in ports {
        map.insert(SynProxyKey::tcp(port.port), SynProxyCfg::new(port.mss), 0)
            .context("inserting a synproxy port")?;
    }
    Ok(())
}

/// Resolve live masquerade targets. Explicit SNAT/HA VIP addresses always win
/// over a member's DHCP address. Missing interfaces/addresses are retried by
/// the normal two-second interface reconciliation loop.
fn masquerade_targets(
    interfaces: &[ResolvedInterface],
    mut index: impl FnMut(&str) -> Result<u32>,
    mut address: impl FnMut(&str) -> Result<[u8; 4]>,
) -> BTreeMap<u32, [u8; 4]> {
    interfaces
        .iter()
        .filter(|i| i.masquerade)
        .filter_map(|i| {
            let ifindex = index(&i.name).ok()?;
            // A present uplink with no address keeps its entry, unaddressed:
            // deleting it would hand the uplink to the plain egress policy and
            // let LAN traffic leave with its private source address.
            let ip = i
                .snat_address
                .or_else(|| address(&i.name).ok())
                .unwrap_or(velstra_common::UNADDRESSED);
            Some((ifindex, ip))
        })
        .collect()
}

fn local_egress_address_key(ifindex: u32, ip: [u8; 4]) -> [u8; 8] {
    let index = ifindex.to_ne_bytes();
    [
        index[0], index[1], index[2], index[3], ip[0], ip[1], ip[2], ip[3],
    ]
}

fn local_egress_addresses(
    interfaces: &[ResolvedInterface],
    mut index: impl FnMut(&str) -> Result<u32>,
    mut addresses: impl FnMut(&str) -> Result<Vec<[u8; 4]>>,
) -> HashSet<[u8; 8]> {
    interfaces
        .iter()
        .flat_map(|i| {
            let Ok(ifindex) = index(&i.name) else {
                return Vec::new();
            };
            let Ok(ips) = addresses(&i.name) else {
                return Vec::new();
            };
            ips.into_iter()
                .map(|ip| local_egress_address_key(ifindex, ip))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether the link's owner holds `name` down for this agent to raise.
/// Polls in a row a torn host inventory may leave the last good snapshot in
/// force. At the 2-second poll this bounds a stale address grant to about six
/// seconds, the same order as the poll's own staleness; a host that keeps
/// changing under every observation for longer than that still closes the gate.
const MAX_TORN_INVENTORY_POLLS: u32 = 3;

/// Whether a failed inventory poll keeps the last good snapshot (`true`) or
/// blocks the datapath (`false`). Only a raced observation is tolerated, and
/// only [`MAX_TORN_INVENTORY_POLLS`] times in a row; any other failure blocks
/// at once and restarts the count.
fn keep_last_inventory(raced: bool, consecutive: &mut u32) -> bool {
    if !raced {
        *consecutive = 0;
        return false;
    }
    *consecutive = consecutive.saturating_add(1);
    *consecutive <= MAX_TORN_INVENTORY_POLLS
}

fn is_held(interfaces: &[ResolvedInterface], name: &str) -> bool {
    interfaces.iter().any(|i| i.activate && i.name == name)
}

/// The held links that may come up now: declared as held, down, carrying every
/// hook they need (`attached`) and, where HA guards them, the HA guard
/// (`guarded`) — and only while the configuration is in force.
fn links_to_activate(
    interfaces: &[ResolvedInterface],
    down: impl Fn(&str) -> bool,
    attached: impl Fn(&str) -> bool,
    guarded: impl Fn(&str) -> bool,
    in_force: bool,
) -> Vec<String> {
    if !in_force {
        return Vec::new();
    }
    interfaces
        .iter()
        .filter(|i| i.activate)
        .map(|i| i.name.as_str())
        .filter(|name| down(name) && attached(name) && guarded(name))
        .map(String::from)
        .collect()
}

/// Whether this agent already raised `name` at the incarnation `index` names.
/// A recreated link (a new ifindex) or one never raised is not.
fn raised_here(raised: &BTreeMap<String, u32>, name: &str, index: Option<u32>) -> bool {
    index.is_some_and(|index| raised.get(name) == Some(&index))
}

/// Whether `name` exists and is administratively down. A link that is absent
/// is not dark, it is not there; one whose flags cannot be read is not
/// claimed down either.
fn link_is_down(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|flags| u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|flags| flags & libc::IFF_UP as u32 == 0)
}

/// `ip link set dev <name> up`, through the pinned iproute2 the appliance hands
/// the agent.
fn set_link_up(name: &str) -> Result<()> {
    let ip = std::env::var("VELSTRA_IP_BIN").unwrap_or_else(|_| "ip".into());
    let output = std::process::Command::new(ip)
        .args(["link", "set", "dev", name, "up"])
        .output()
        .context("running ip link set up")?;
    anyhow::ensure!(
        output.status.success(),
        "ip link set dev {name} up: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

/// Program the same observed addresses used to derive NAT reply permissions.
/// The caller holds the configuration gate closed during this whole update.
fn program_masquerade(
    ebpf: &mut Ebpf,
    interfaces: &[ResolvedInterface],
    ipv4: &Ipv4Inventory,
) -> Result<()> {
    let clients: BTreeMap<_, _> = interfaces
        .iter()
        .filter(|i| i.dhcp_client)
        .filter_map(|i| {
            let observed = ipv4.get(&i.name)?;
            let index = observed.ifindex;
            let mac = observed.dhcp_mac?;
            Some((
                index,
                [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], 0, 0],
            ))
        })
        .collect();
    {
        let mut map: HashMap<_, u32, [u8; 8]> = HashMap::try_from(
            ebpf.map_mut("DHCP_CLIENTS")
                .ok_or_else(|| anyhow!("DHCP_CLIENTS map missing"))?,
        )?;
        drop_unlisted(&mut map, &clients.keys().copied().collect())?;
        for (index, mac) in clients {
            map.insert(index, mac, 0)?;
        }
    }
    let index = |name: &str| {
        ipv4.get(name)
            .map(|iface| iface.ifindex)
            .ok_or_else(|| anyhow!("interface {name} is absent from the host snapshot"))
    };
    let prepared = masquerade_targets(interfaces, index, |name| {
        ipv4.get(name)
            .and_then(|iface| iface.primary)
            .ok_or_else(|| anyhow!("interface {name} has no primary IPv4 address"))
    });
    let local = local_egress_addresses(interfaces, index, |name| {
        Ok(ipv4
            .get(name)
            .map(|iface| iface.prefixes.iter().map(|(ip, _)| *ip).collect())
            .unwrap_or_default())
    });
    {
        let mut map: HashMap<_, [u8; 8], u8> = HashMap::try_from(
            ebpf.map_mut("LOCAL_EGRESS_ADDRS")
                .ok_or_else(|| anyhow!("LOCAL_EGRESS_ADDRS map missing"))?,
        )?;
        drop_unlisted(&mut map, &local)?;
        for key in local {
            map.insert(key, 1, 0)?;
        }
    }
    let mut map: HashMap<_, u32, [u8; 4]> = HashMap::try_from(
        ebpf.map_mut("MASQUERADE")
            .ok_or_else(|| anyhow!("MASQUERADE map missing"))?,
    )?;
    let keep: HashSet<_> = prepared.keys().copied().collect();
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, ip) in prepared {
        if map.get(&ifindex, 0).ok() != Some(ip) {
            map.insert(ifindex, ip, 0)
                .with_context(|| format!("inserting masquerade ifindex {ifindex}"))?;
        }
    }
    Ok(())
}

/// The ifindex a rule is scoped to, or `0` for "every interface".
///
/// An interface that is named and absent resolves to `0` rather than to a
/// nonexistent index — which would make the rule match nothing at all. `0` makes
/// it match everywhere, so the failure is a rule that is too broad rather than
/// one that is silently inert, and the reconfigure that follows a NIC appearing
/// narrows it.
/// Resolve a rule's `in-interface` to the ifindex the data plane keys on.
///
/// An empty name is the *unscoped* rule and resolves to `0`, which the data
/// plane reads as "on any interface". That is the whole difficulty: `0` is a
/// meaning, not an absence. This function used to answer `unwrap_or(0)`, so an
/// operator who mistyped an interface name got the unscoped sentinel — and
/// `allow ssh in on mgmt0` silently became `allow ssh in on every interface,
/// WAN included`, with a green apply and nothing in the log.
///
/// There is no safe value to guess. Widening opens a hole on a `pass` rule;
/// dropping the rule opens one on a `deny`. A name that does not resolve cannot
/// be expressed in the map at all, so the honest answer is to refuse the apply
/// and leave the previous configuration in force — the fail-closed direction for
/// a firewall, and the one the operator will notice.
pub(crate) fn rule_ifindex(name: &str) -> Result<u32> {
    if name.is_empty() {
        return Ok(0);
    }
    if_nametoindex(name).map_err(|e| {
        anyhow!(
            "a firewall rule is scoped to interface `{name}`, which does not exist on this \
             host ({e}); refusing the configuration rather than applying the rule to every \
             interface"
        )
    })
}

/// Write the `MAC_RULES` map: a policy's verdicts on sender hardware addresses.
///
/// One entry per (policy, MAC). Empty on a box with no MAC groups, so the
/// datapath's single lookup misses immediately and costs nothing.
fn program_mac_rules(ebpf: &mut Ebpf, policies: &[PolicyConfig]) -> Result<()> {
    // No early return on an empty set: lifting the last quarantine must clear
    // the map, not skip it and leave the device blocked.
    let keep: HashSet<ScopedMac> = policies
        .iter()
        .flat_map(|p| {
            p.mac_rules
                .iter()
                .map(move |(mac, _)| ScopedMac::new(p.id, *mac))
        })
        .collect();
    let mut map: HashMap<_, ScopedMac, u64> = HashMap::try_from(
        ebpf.map_mut("MAC_RULES")
            .ok_or_else(|| anyhow!("MAC_RULES map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for policy in policies {
        for (mac, action) in &policy.mac_rules {
            map.insert(
                ScopedMac::new(policy.id, *mac),
                port_rule_value(*action, false, 0) as u64,
                0,
            )
            .with_context(|| format!("inserting mac rule for policy {}", policy.id))?;
        }
    }
    Ok(())
}

/// Write the `MSS_CLAMP` map: egress ifindex → the largest MSS a departing SYN
/// may advertise. Only interfaces that configure one get an entry, so a box with
/// no tunnels pays nothing and the datapath's lookup misses immediately.
fn program_mss_clamp(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let prepared: Vec<(u32, u16)> = interfaces
        .iter()
        .filter(|i| i.mss != 0)
        .filter_map(|i| if_nametoindex(&i.name).ok().map(|idx| (idx, i.mss)))
        .collect();
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, u16> = HashMap::try_from(
        ebpf.map_mut("MSS_CLAMP")
            .ok_or_else(|| anyhow!("MSS_CLAMP map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, mss) in prepared {
        map.insert(ifindex, mss, 0)
            .with_context(|| format!("inserting mss clamp for ifindex {ifindex}"))?;
    }
    Ok(())
}

/// Delete every key of `map` that the new configuration does not name.
///
/// The writers below used to only ever `insert`, and `remove_stale` — which
/// reconstructs the old keys from the previous configuration — covered 22 of the
/// 41 maps an apply writes. The port-security maps, the port forwards and the
/// MAC verdicts were among the 19 it did not, so *removing* something from the
/// configuration left it in force in the data plane:
///
/// * take an address off a port and the workload keeps sending under it;
/// * delete a port forward and the box keeps forwarding it inward;
/// * lift a MAC quarantine and the device stays blocked.
///
/// Each of those reported a successful apply. Worse, the writers returned early
/// when their input was empty, so removing the *last* entry of a kind skipped
/// the map altogether — the one case where the operator is most certain the rule
/// is gone.
///
/// Reconciling against the desired set is what fixes it, rather than another
/// hand-written sweep beside the existing one. It needs no memory of the
/// previous configuration, so it is also correct after a crash mid-apply and
/// after an agent restart, and there is one list to keep in step instead of two.
fn drop_unlisted<K, V>(map: &mut HashMap<&mut MapData, K, V>, keep: &HashSet<K>) -> Result<()>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    // Collected before removing: the iterator borrows the map.
    let stale: Vec<K> = map.keys().flatten().filter(|k| !keep.contains(k)).collect();
    for key in stale {
        map.remove(&key).context("removing a stale map entry")?;
    }
    Ok(())
}

/// Write the port-security maps (B12): which identity each tenant port is bound
/// to, and which addresses it may send from.
///
/// Only bound interfaces get entries, so a box with no tenant ports pays one
/// missing lookup per frame and nothing else. An interface that has gone away is
/// skipped with a warning rather than failing the whole apply: the rest of the
/// policy is still worth installing, and a port that does not exist cannot be
/// spoofed from.
fn program_port_bindings(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    // Program known local destinations independently of traffic learning. An
    // idle guest must remain reachable after this agent replaces its maps.
    let local: Vec<_> = interfaces
        .iter()
        .filter_map(|interface| {
            let mac = interface.binding.as_ref()?.mac?;
            if interface.vni == 0 {
                return None;
            }
            let index = if_nametoindex(&interface.name).ok()?;
            Some((LocalMacKey::new(interface.vni, mac), index))
        })
        .collect();
    {
        let mut ports: HashMap<_, LocalMacKey, u32> = HashMap::try_from(
            ebpf.map_mut("LOCAL_PORTS")
                .ok_or_else(|| anyhow!("LOCAL_PORTS map missing"))?,
        )?;
        drop_unlisted(&mut ports, &local.iter().map(|(key, _)| *key).collect())?;
        for (key, index) in local {
            ports.insert(key, index, 0)?;
        }
    }

    let bound: Vec<(u32, &PortIdentity)> = interfaces
        .iter()
        .filter_map(|i| {
            let identity = i.binding.as_ref()?;
            match if_nametoindex(&i.name) {
                Ok(idx) => Some((idx, identity)),
                Err(_) => {
                    warn!("port binding skipped: no interface named {}", i.name);
                    None
                }
            }
        })
        .collect();

    // No early return on an empty set. Unbinding the last port is exactly when
    // the map must be emptied, and returning here left every binding in force.
    let keep_ports: HashSet<u32> = bound.iter().map(|(idx, _)| *idx).collect();
    let keep_v4: HashSet<PortAddr4> = bound
        .iter()
        .flat_map(|(idx, id)| {
            id.v4
                .iter()
                .map(move |a| PortAddr4::new(*idx, u32::from_ne_bytes(a.octets())))
        })
        .collect();
    let keep_v6: HashSet<PortAddr6> = bound
        .iter()
        .flat_map(|(idx, id)| id.v6.iter().map(move |a| PortAddr6::new(*idx, a.octets())))
        .collect();

    {
        let mut bindings: HashMap<_, u32, PortBinding> = HashMap::try_from(
            ebpf.map_mut("PORT_BINDINGS")
                .ok_or_else(|| anyhow!("PORT_BINDINGS map missing"))?,
        )?;
        drop_unlisted(&mut bindings, &keep_ports)?;
        for (ifindex, identity) in &bound {
            bindings
                .insert(
                    ifindex,
                    PortBinding::new(identity.mac.unwrap_or([0; 6]), identity.flags()),
                    0,
                )
                .with_context(|| format!("binding port {ifindex}"))?;
        }
        // The handle borrows `ebpf` mutably, and the next one cannot be taken until
        // that borrow ends. A block says so; `drop` of a type with no `Drop` impl
        // only looks like it does.
    }

    {
        let mut v4: HashMap<_, PortAddr4, u8> = HashMap::try_from(
            ebpf.map_mut("PORT_ADDRS_V4")
                .ok_or_else(|| anyhow!("PORT_ADDRS_V4 map missing"))?,
        )?;
        drop_unlisted(&mut v4, &keep_v4)?;
        for (ifindex, identity) in &bound {
            for addr in &identity.v4 {
                // Network order, exactly as it sits in the header the data plane
                // reads: converting on one side only is how a binding silently
                // matches nothing.
                v4.insert(
                    PortAddr4::new(*ifindex, u32::from_ne_bytes(addr.octets())),
                    1,
                    0,
                )
                .with_context(|| format!("binding {addr} to port {ifindex}"))?;
            }
        }
    }

    {
        let mut v6: HashMap<_, PortAddr6, u8> = HashMap::try_from(
            ebpf.map_mut("PORT_ADDRS_V6")
                .ok_or_else(|| anyhow!("PORT_ADDRS_V6 map missing"))?,
        )?;
        drop_unlisted(&mut v6, &keep_v6)?;
        for (ifindex, identity) in &bound {
            for addr in &identity.v6 {
                v6.insert(PortAddr6::new(*ifindex, addr.octets()), 1, 0)
                    .with_context(|| format!("binding {addr} to port {ifindex}"))?;
            }
        }
    }
    Ok(())
}

/// Write the C16 `NPTV6` map: boundary ifindex → its NPTv6 (RFC 6296) prefix
/// translation. The interface name resolves to the live ifindex here (the data
/// plane keys on ifindex); an absent interface is skipped with a warning, so a
/// later reconfigure picks it up once the NIC appears.
/// Write the C16 `CGNAT` map: egress ifindex → its deterministic port-block
/// layout, for every masquerade interface that configures one. No entry means the
/// plain hash-spread NAPT, so a box that is not a carrier NAT is untouched.
fn program_cgnat(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let prepared: Vec<(u32, CgnatLayout)> = interfaces
        .iter()
        .filter(|i| i.masquerade && i.cgnat.is_enabled())
        .filter_map(|i| match if_nametoindex(&i.name) {
            Ok(ifindex) => Some((ifindex, i.cgnat)),
            Err(_) => {
                warn!(
                    "cgnat interface {} not present yet; deferring its port blocks",
                    i.name
                );
                None
            }
        })
        .collect();
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, CgnatLayout> = HashMap::try_from(
        ebpf.map_mut("CGNAT")
            .ok_or_else(|| anyhow!("CGNAT map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, layout) in prepared {
        map.insert(ifindex, layout, 0)
            .with_context(|| format!("inserting cgnat layout for ifindex {ifindex}"))?;
    }
    Ok(())
}

fn program_npt66(ebpf: &mut Ebpf, rules: &[ResolvedNpt66]) -> Result<()> {
    let prepared: Vec<(u32, Npt66)> = rules
        .iter()
        .filter_map(|r| match if_nametoindex(&r.interface) {
            Ok(ifindex) => Some((ifindex, r.npt)),
            Err(_) => {
                warn!(
                    "npt66 interface {} not present yet; deferring its translation",
                    r.interface
                );
                None
            }
        })
        .collect();
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, Npt66> = HashMap::try_from(
        ebpf.map_mut("NPTV6")
            .ok_or_else(|| anyhow!("NPTV6 map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, npt) in prepared {
        map.insert(ifindex, npt, 0)
            .with_context(|| format!("inserting npt66 ifindex {ifindex}"))?;
    }
    Ok(())
}

type Ipv4Prefix = ([u8; 4], [u8; 4]);
type Ipv4Inventory = BTreeMap<String, InterfaceIpv4>;

/// Normalized, permission-relevant facts from one rtnetlink snapshot. Address
/// ordering is irrelevant except for the primary address used by masquerade.
#[derive(Clone, Debug, PartialEq, Eq)]
struct InterfaceIpv4 {
    ifindex: u32,
    primary: Option<[u8; 4]>,
    prefixes: BTreeSet<Ipv4Prefix>,
    dhcp_mac: Option<[u8; 6]>,
}

fn normalize_interface_ipv4(
    iface: &ResolvedInterface,
    ifindex: u32,
    addresses: &[Ipv4Prefix],
    mac: Option<[u8; 6]>,
) -> Result<InterfaceIpv4> {
    anyhow::ensure!(ifindex != 0, "interface {} has invalid index 0", iface.name);
    let dhcp_mac = if iface.dhcp_client {
        Some(mac.ok_or_else(|| anyhow!("DHCP interface {} has no Ethernet MAC", iface.name))?)
    } else {
        None
    };
    Ok(InterfaceIpv4 {
        ifindex,
        // An explicit SNAT address wins, so an unrelated address-order change
        // must not cause policy epoch churn on that interface.
        primary: if iface.masquerade && iface.snat_address.is_none() {
            addresses.first().map(|(ip, _)| *ip)
        } else {
            None
        },
        prefixes: addresses.iter().copied().collect(),
        dhcp_mac,
    })
}

/// Keep the netlink ifindex/address association, not glibc's IPv4 ifa_name:
/// getifaddrs exposes IFA_LABEL there and loses the actual owning ifindex.
/// In particular, interpreting an arbitrary label's prefix as a device name
/// could grant a different zone's reply policy. iproute2's JSON preserves the
/// actual owning link; labels are never used for authorization.
#[cfg(test)]
fn read_ipv4_inventory(interfaces: &[ResolvedInterface]) -> Result<Ipv4Inventory> {
    let _timing = timing::Span::start(timing::Phase::HostObserver);
    ipv4_inventory_from(crate::host_inventory::read()?, interfaces)
}

fn ipv4_inventory_from(
    links: Vec<crate::host_inventory::Interface>,
    interfaces: &[ResolvedInterface],
) -> Result<Ipv4Inventory> {
    let mut inventory = BTreeMap::new();
    for link in links {
        let Some(iface) = interfaces.iter().find(|iface| iface.name == link.name) else {
            continue;
        };
        let mac = if iface.dhcp_client {
            Some(
                link.mac
                    .context("DHCP interface has no MAC")?
                    .try_into()
                    .map_err(|_| anyhow!("DHCP interface has no Ethernet MAC"))?,
            )
        } else {
            None
        };
        inventory.insert(
            link.name,
            normalize_interface_ipv4(iface, link.index, &link.addresses, mac)?,
        );
    }
    Ok(inventory)
}

/// Test-only differential oracle. Production never falls back to an external
/// observer, including after a native dump fails or is interrupted.
#[cfg(test)]
fn read_ipv4_inventory_ip(interfaces: &[ResolvedInterface]) -> Result<Ipv4Inventory> {
    let ip = std::env::var("VELSTRA_IP_BIN").unwrap_or_else(|_| "ip".into());
    let mut command = std::process::Command::new(ip);
    // Do not filter -4 here: ip suppresses links with no address in the chosen
    // family. Empty addr_info must remain distinguishable from a missing link.
    command.args(["-j", "-details", "address", "show"]);
    parse_ipv4_inventory(&read_inventory_output(command)?, interfaces)
}

/// Bound both wall time and allocation. A hung/failed/truncated observation
/// must close the gate rather than be mistaken for an address withdrawal.
#[cfg(test)]
fn read_inventory_output(mut command: std::process::Command) -> Result<Vec<u8>> {
    let _timing = timing::Span::start(timing::Phase::HostObserver);
    use std::{io::Read, process::Stdio};
    const LIMIT: usize = 8 * 1024 * 1024;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting live interface observation")?;
    let result = (|| -> Result<Vec<u8>> {
        let mut stdout = child
            .stdout
            .take()
            .context("interface observer has no stdout")?;
        // SAFETY: stdout is an owned, valid pipe FD. Preserve its current flags.
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(std::io::Error::last_os_error()).context("bounding interface observation");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            loop {
                match stdout.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(length) => {
                        anyhow::ensure!(
                            bytes.len() + length <= LIMIT,
                            "interface inventory exceeds 8 MiB"
                        );
                        bytes.extend_from_slice(&buffer[..length]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error).context("reading interface inventory"),
                }
            }
            if let Some(status) = child.try_wait().context("waiting for interface observer")? {
                anyhow::ensure!(status.success(), "interface observer failed: {status}");
                // The next read after the writer exits drains any final bytes
                // that arrived between the first read and try_wait.
                stdout
                    .take((LIMIT + 1 - bytes.len()) as u64)
                    .read_to_end(&mut bytes)
                    .context("draining interface inventory")?;
                anyhow::ensure!(bytes.len() <= LIMIT, "interface inventory exceeds 8 MiB");
                return Ok(bytes);
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "interface observer timed out after 2 seconds"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(test)]
fn parse_ipv4_inventory(bytes: &[u8], interfaces: &[ResolvedInterface]) -> Result<Ipv4Inventory> {
    #[derive(serde::Deserialize)]
    struct Link {
        ifindex: u32,
        ifname: String,
        address: Option<String>,
        addr_info: Vec<Address>,
    }
    #[derive(serde::Deserialize)]
    struct Address {
        family: String,
        local: String,
        prefixlen: u8,
    }
    let links: Vec<Link> = serde_json::from_slice(bytes).context("decoding interface inventory")?;
    let mut names = HashSet::new();
    let mut indices = HashSet::new();
    let mut inventory = BTreeMap::new();
    for link in links {
        anyhow::ensure!(link.ifindex > 0, "invalid observed interface index");
        anyhow::ensure!(
            names.insert(link.ifname.clone()),
            "duplicate observed interface name"
        );
        anyhow::ensure!(
            indices.insert(link.ifindex),
            "duplicate observed interface index"
        );
        let Some(iface) = interfaces.iter().find(|iface| iface.name == link.ifname) else {
            continue;
        };
        let mut addresses = Vec::new();
        for address in link.addr_info {
            if address.family != "inet" {
                anyhow::ensure!(address.family == "inet6", "unknown observed address family");
                continue;
            }
            anyhow::ensure!(
                address.prefixlen <= 32,
                "invalid observed IPv4 prefix length"
            );
            let ip: std::net::Ipv4Addr = address
                .local
                .parse()
                .context("invalid observed IPv4 address")?;
            let mask = u32::MAX
                .checked_shl(u32::from(32 - address.prefixlen))
                .unwrap_or(0);
            addresses.push((ip.octets(), mask.to_be_bytes()));
        }
        let mac = if iface.dhcp_client {
            Some(parse_mac(
                link.address
                    .as_deref()
                    .context("DHCP interface has no MAC")?,
            )?)
        } else {
            None
        };
        let observed = normalize_interface_ipv4(iface, link.ifindex, &addresses, mac)?;
        inventory.insert(link.ifname, observed);
    }
    Ok(inventory)
}

/// The policy a reply from `target` will arrive under: the policy bound to the
/// interface whose observed IPv4 subnet contains it. `0` when no interface's subnet
/// does (the host is reached over a route, or its segment has no address yet) — or
/// when two interfaces on *different* policies both match, since one entry cannot
/// name two zones and picking either would admit nothing while looking resolved.
///
/// Derived from the common live snapshot rather than the config on purpose: an
/// interface may be DHCP-addressed, in which case its subnet is not in the config
/// at all, and a compile-time guess would also go stale when the address moves.
fn resolve_reply_policy(
    target: [u8; 4],
    interfaces: &[ResolvedInterface],
    ipv4: &Ipv4Inventory,
) -> PolicyId {
    let want = u32::from_be_bytes(target);
    let mut found: Option<PolicyId> = None;
    for iface in interfaces {
        let Some(observed) = ipv4.get(&iface.name) else {
            continue;
        };
        if !observed.prefixes.iter().any(|(addr, mask)| {
            let mask = u32::from_be_bytes(*mask);
            (want & mask) == (u32::from_be_bytes(*addr) & mask)
        }) {
            continue;
        }
        match found {
            None => found = Some(iface.policy),
            Some(p) if p == iface.policy => {}
            Some(_) => return 0,
        }
    }
    found.unwrap_or(0)
}

/// The one policy every member of `backends` answers under, or `0` if they do not
/// all agree (or none resolves). See [`resolve_reply_policy`].
fn pool_reply_policy(
    backends: &[Backend],
    interfaces: &[ResolvedInterface],
    ipv4: &Ipv4Inventory,
) -> PolicyId {
    let mut agreed: Option<PolicyId> = None;
    for backend in backends {
        let policy = resolve_reply_policy(backend.ip, interfaces, ipv4);
        if policy == 0 {
            return 0;
        }
        match agreed {
            None => agreed = Some(policy),
            Some(p) if p == policy => {}
            Some(_) => return 0,
        }
    }
    agreed.unwrap_or(0)
}

/// Program the Phase 4 overlay maps: `OVERLAY_CONFIG` (this host's VTEP, a single
/// entry), `OVERLAY_FDB` (`(vni, inner dst)` → remote endpoint), the B1
/// `MAC_FDB` (`(vni, inner dst MAC)` → remote endpoint, consulted first for L2
/// bridging), and the B2 `FLOOD_LIST` (`vni` → the [`FloodSet`] of remote VTEPs
/// a BUM frame on that segment head-end replicates to). Each tunnel's, MAC
/// route's and flood VTEP's underlay egress ifindex is also mirrored into
/// `TX_PORTS` so the data plane can redirect after encapsulating, and each
/// remote VTEP is added to the trusted-decap `VTEP_PEERS` set.
///
/// Slot `0` of `OVERLAY_CONFIG` is **always** written — with the resolved config
/// or, when the overlay is absent, with the disabled default — so a live
/// reconfigure that drops the overlay correctly turns encap/decap off.
#[allow(clippy::too_many_arguments)]
fn program_overlay(
    ebpf: &mut Ebpf,
    config: OverlayConfig,
    tunnels: &[ResolvedTunnel],
    mac_routes: &[ResolvedMacRoute],
    irb_routes: &[ResolvedIrbRoute],
    neighbors: &[ResolvedNeighbor],
    nd_neighbors: &[ResolvedNd6],
    flood_vteps: &[ResolvedFloodVtep],
) -> Result<()> {
    {
        let mut cfg_map: Array<_, OverlayConfig> = Array::try_from(
            ebpf.map_mut("OVERLAY_CONFIG")
                .ok_or_else(|| anyhow!("OVERLAY_CONFIG map missing"))?,
        )?;
        cfg_map
            .set(0, config, 0)
            .context("writing OVERLAY_CONFIG")?;
    }

    // ARP suppression table: `(vni, tenant IP)` → MAC.
    if !neighbors.is_empty() {
        let mut arp: HashMap<_, ArpKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ARP_TABLE")
                .ok_or_else(|| anyhow!("ARP_TABLE map missing"))?,
        )?;
        for n in neighbors {
            arp.insert(ArpKey::new(n.vni, n.ip), ArpEntry::new(n.mac), 0)
                .context("inserting ARP neighbour")?;
        }
    }

    // B3 IPv6 ND-suppression table: `(vni, tenant IPv6)` → MAC (same value shape
    // as ARP). The IPv6 mirror of the ARP table above.
    if !nd_neighbors.is_empty() {
        let mut nd: HashMap<_, NdKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ND_TABLE")
                .ok_or_else(|| anyhow!("ND_TABLE map missing"))?,
        )?;
        for n in nd_neighbors {
            nd.insert(NdKey::new(n.vni, n.ip), ArpEntry::new(n.mac), 0)
                .context("inserting ND neighbour")?;
        }
    }

    if tunnels.is_empty()
        && mac_routes.is_empty()
        && irb_routes.is_empty()
        && flood_vteps.is_empty()
    {
        return Ok(());
    }

    // Resolve every tunnel's egress ifindex up front (needs the OS), then do the
    // two map-borrow passes. Each tunnel becomes an LPM key `(vni exact, inner
    // dst prefix)` → endpoint. Skip (defer) a tunnel whose out_iface isn't
    // present yet rather than hard-aborting the whole reconfigure — consistent
    // with program_interfaces/program_routes; a hard abort would blackhole
    // overlay traffic after remove_stale already ran.
    let prepared: Vec<(Key<TunnelKey>, TunnelEndpoint)> = tunnels
        .iter()
        .filter_map(|t| match if_nametoindex(&t.out_iface) {
            Ok(ifindex) => {
                let (_, addr) = t.inner_dst.lpm_key();
                let key = Key::new(
                    TunnelKey::prefix_len(t.inner_dst.prefix),
                    TunnelKey::new(t.vni, addr),
                );
                Some((
                    key,
                    TunnelEndpoint::new(ifindex, t.remote_vtep_ip, t.outer_dst_mac),
                ))
            }
            Err(_) => {
                log::debug!(
                    "tunnel egress {} not present yet; deferring its FDB entry",
                    t.out_iface
                );
                None
            }
        })
        .collect();

    // B1: resolve every MAC route's egress ifindex the same way. Each becomes an
    // exact-match MAC-FDB key `(vni, inner dst MAC)` → endpoint.
    let prepared_mac: Vec<(MacFdbKey, TunnelEndpoint)> = mac_routes
        .iter()
        .filter_map(|m| match if_nametoindex(&m.out_iface) {
            Ok(ifindex) => Some((
                MacFdbKey::new(m.vni, m.mac),
                TunnelEndpoint::new(ifindex, m.remote_vtep_ip, m.outer_dst_mac),
            )),
            Err(_) => {
                log::debug!(
                    "mac_route egress {} not present yet; deferring its MAC-FDB entry",
                    m.out_iface
                );
                None
            }
        })
        .collect();

    // B7: resolve every symmetric-IRB route the same way. The LPM key is
    // `(ingress vni exact, remote tenant prefix)` — the *ingress* segment, not the
    // routed one, because that is all the datapath knows about an arriving frame;
    // the routed VNI travels in the value.
    let prepared_irb: Vec<(Key<TunnelKey>, IrbEndpoint)> = irb_routes
        .iter()
        .filter_map(|r| match if_nametoindex(&r.out_iface) {
            Ok(ifindex) => {
                let (_, addr) = r.inner_dst.lpm_key();
                let key = Key::new(
                    TunnelKey::prefix_len(r.inner_dst.prefix),
                    TunnelKey::new(r.vni, addr),
                );
                Some((
                    key,
                    IrbEndpoint::new(
                        ifindex,
                        r.l3_vni,
                        r.remote_vtep_ip,
                        r.outer_dst_mac,
                        r.router_mac,
                        r.gateway_mac,
                    ),
                ))
            }
            Err(_) => {
                log::debug!(
                    "irb_route egress {} not present yet; deferring its IRB entry",
                    r.out_iface
                );
                None
            }
        })
        .collect();

    // B2: group flood VTEPs by VNI into one FloodSet per segment. Resolve each
    // entry's egress ifindex the same way (deferring an absent one), collecting
    // endpoints per VNI in config order. `flood_groups` feeds both FLOOD_LIST
    // and (via each endpoint's ifindex) TX_PORTS. A plain `Vec` of pairs keeps
    // insertion order and avoids clashing with the `aya` `HashMap` alias in
    // scope here.
    let mut flood_groups: Vec<(u32, Vec<TunnelEndpoint>)> = Vec::new();
    for fv in flood_vteps {
        let ifindex = match if_nametoindex(&fv.out_iface) {
            Ok(i) => i,
            Err(_) => {
                log::debug!(
                    "flood_vtep egress {} not present yet; deferring its flood entry",
                    fv.out_iface
                );
                continue;
            }
        };
        let ep = TunnelEndpoint::new(ifindex, fv.remote_vtep_ip, fv.outer_dst_mac);
        match flood_groups.iter_mut().find(|(v, _)| *v == fv.vni) {
            Some((_, eps)) => eps.push(ep),
            None => flood_groups.push((fv.vni, vec![ep])),
        }
    }

    {
        let mut fdb: LpmTrie<_, TunnelKey, TunnelEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("OVERLAY_FDB")
                .ok_or_else(|| anyhow!("OVERLAY_FDB map missing"))?,
        )?;
        for (key, endpoint) in &prepared {
            fdb.insert(key, endpoint, 0)
                .context("inserting overlay FDB entry")?;
        }
    }

    {
        // B1 MAC-FDB: consulted before OVERLAY_FDB so a true L2 overlay bridges
        // by destination MAC.
        let mut mac_fdb: HashMap<_, MacFdbKey, TunnelEndpoint> = HashMap::try_from(
            ebpf.map_mut("MAC_FDB")
                .ok_or_else(|| anyhow!("MAC_FDB map missing"))?,
        )?;
        for (key, endpoint) in &prepared_mac {
            mac_fdb
                .insert(key, endpoint, 0)
                .context("inserting MAC-FDB entry")?;
        }
    }

    {
        // B7 IRB_ROUTES: consulted before both bridging FDBs, and only for frames
        // addressed to the tenant's anycast gateway MAC.
        let mut irb: LpmTrie<_, TunnelKey, IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("IRB_ROUTES")
                .ok_or_else(|| anyhow!("IRB_ROUTES map missing"))?,
        )?;
        for (key, endpoint) in &prepared_irb {
            irb.insert(key, endpoint, 0)
                .context("inserting IRB route entry")?;
        }
    }

    if !irb_routes.is_empty() {
        // Symmetric IRB is symmetric: whatever we encapsulate into a tenant's L3
        // VNI, the peer sends back into the same one. So a host that routes into
        // an L3 VNI must also *admit* decap from it — the decap path drops any
        // inner VNI absent from `LOCAL_VNIS`, and an L3 VNI belongs to no local
        // tenant port, so `program_interfaces` never registers it.
        //
        // `remove_stale` clears the whole set first, so a tenant dropped from the
        // config stops being decap-admitted on this live reconfigure instead of
        // lingering until the agent restarts.
        let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("LOCAL_VNIS")
                .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
        )?;
        for r in irb_routes {
            local_vnis
                .insert(r.l3_vni, 0u32, 0)
                .with_context(|| format!("registering local l3 vni {}", r.l3_vni))?;
        }
    }

    {
        // B2 FLOOD_LIST: one FloodSet per VNI, walked by the TC ingress
        // `velstra_bum` classifier to head-end replicate BUM frames.
        let mut flood: HashMap<_, u32, FloodSet> = HashMap::try_from(
            ebpf.map_mut("FLOOD_LIST")
                .ok_or_else(|| anyhow!("FLOOD_LIST map missing"))?,
        )?;
        for (vni, eps) in &flood_groups {
            flood
                .insert(vni, FloodSet::new(eps), 0)
                .with_context(|| format!("inserting flood set for vni {vni}"))?;
        }
    }

    {
        // Trusted-VTEP set (C2): every distinct remote VTEP we tunnel with is an
        // authorized decap source. remove_stale dropped the old set first, and we
        // re-add every current peer here, so a still-valid VTEP survives a
        // reconfigure (mirrors the OVERLAY_FDB reconcile). MAC routes reach the
        // same remote VTEPs, so their VTEPs must be trusted decap peers too.
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for t in tunnels {
            peers
                .insert(t.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer")?;
        }
        for m in mac_routes {
            peers
                .insert(m.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (mac route)")?;
        }
        // B7: an IRB route's remote VTEP is where the routed reply comes back
        // from, so it must be an authorized decap source as well.
        for r in irb_routes {
            peers
                .insert(r.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (irb route)")?;
        }
        // B2: flood VTEPs receive our encapped BUM copies (and send their own
        // back), so they are trusted decap peers as well.
        for fv in flood_vteps {
            peers
                .insert(fv.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (flood vtep)")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    for (_, endpoint) in &prepared {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device")?;
    }
    for (_, endpoint) in &prepared_mac {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device (mac route)")?;
    }
    for (_, endpoint) in &prepared_irb {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device (irb route)")?;
    }
    // B2: the TC `velstra_bum` classifier `clone_redirect`s each BUM copy onto a
    // flood VTEP's underlay ifindex, so those ifindexes must be in the devmap too.
    for (_, eps) in &flood_groups {
        for endpoint in eps {
            tx_ports
                .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
                .context("registering overlay redirect device (flood vtep)")?;
        }
    }

    Ok(())
}

/// B9: program this host's SRv6 identity (`SRV6_CONFIG`) and its `End.DT2U`
/// per-MAC forwarding entries (`SRV6_FDB`), plus register each egress ifindex in
/// the `TX_PORTS` devmap so the datapath can redirect encapsulated frames. The
/// SRv6 analogue of the [`program_overlay`] unicast path; SRv6 and VXLAN are
/// mutually exclusive per host, so exactly one of the two configs is enabled.
fn program_srv6(
    ebpf: &mut Ebpf,
    srv6: Option<&ResolvedSrv6>,
    config: Srv6Config,
    routes: &[ResolvedSrv6Route],
    local_sids: &[ResolvedSrv6LocalSid],
    floods: &[ResolvedSrv6Flood],
    irb_routes: &[ResolvedSrv6IrbRoute],
) -> Result<()> {
    {
        let mut cfg_map: Array<_, Srv6Config> = Array::try_from(
            ebpf.map_mut("SRV6_CONFIG")
                .ok_or_else(|| anyhow!("SRV6_CONFIG map missing"))?,
        )?;
        cfg_map.set(0, config, 0).context("writing SRV6_CONFIG")?;
    }

    // C2 decap source-auth: every trusted peer's outer IPv6 source → the
    // `SRV6_PEERS` set the datapath checks before decapsulating an End.DT2U frame
    // to one of our SIDs. remove_stale dropped the old set first; an empty set
    // (no peers configured) leaves decap fail-closed. The SRv6 analogue of the
    // VTEP_PEERS population in program_overlay.
    if let Some(s) = srv6 {
        let mut peers: HashMap<_, [u8; 16], u8> = HashMap::try_from(
            ebpf.map_mut("SRV6_PEERS")
                .ok_or_else(|| anyhow!("SRV6_PEERS map missing"))?,
        )?;
        for src in &s.peers {
            peers
                .insert(src, 1, 0)
                .context("inserting trusted SRv6 peer")?;
        }
    }

    // B9 decap: every service SID this host instantiates → its (vni, behaviour).
    // A packet whose outer IPv6 destination matches is decapsulated and bridged.
    {
        // Reconciled unconditionally: a SID left in this map keeps decapsulating
        // traffic addressed to it after the operator withdrew it.
        let keep: HashSet<Srv6SidKey> = local_sids
            .iter()
            .map(|ls| Srv6SidKey::new(ls.sid))
            .collect();
        let mut sids: HashMap<_, Srv6SidKey, Srv6LocalSid> = HashMap::try_from(
            ebpf.map_mut("SRV6_LOCAL_SIDS")
                .ok_or_else(|| anyhow!("SRV6_LOCAL_SIDS map missing"))?,
        )?;
        drop_unlisted(&mut sids, &keep)?;
        for ls in local_sids {
            sids.insert(
                Srv6SidKey::new(ls.sid),
                Srv6LocalSid::new(ls.vni, ls.behavior),
                0,
            )
            .context("inserting SRv6 local SID")?;
        }
    }

    // No early return on an empty route set: withdrawing the last SRv6 route has
    // to empty the FDB, and returning here left every entry forwarding.
    //
    // Resolve every route's egress ifindex (needs the OS). Each becomes an
    // exact-match SRv6-FDB key `(vni, inner dst MAC)` → remote-SID endpoint. Skip
    // (defer) a route whose out_iface isn't present yet rather than hard-aborting
    // the whole reconfigure — consistent with program_overlay/program_routes.
    let prepared: Vec<(MacFdbKey, Srv6Endpoint)> = routes
        .iter()
        .filter_map(|r| match if_nametoindex(&r.out_iface) {
            Ok(ifindex) => Some((
                MacFdbKey::new(r.vni, r.mac),
                Srv6Endpoint::new(ifindex, r.remote_sid, r.outer_dst_mac),
            )),
            Err(_) => {
                log::debug!(
                    "srv6_route egress {} not present yet; deferring its SRv6-FDB entry",
                    r.out_iface
                );
                None
            }
        })
        .collect();

    {
        let keep: HashSet<MacFdbKey> = prepared.iter().map(|(k, _)| *k).collect();
        let mut fdb: HashMap<_, MacFdbKey, Srv6Endpoint> = HashMap::try_from(
            ebpf.map_mut("SRV6_FDB")
                .ok_or_else(|| anyhow!("SRV6_FDB map missing"))?,
        )?;
        drop_unlisted(&mut fdb, &keep)?;
        for (key, endpoint) in &prepared {
            fdb.insert(key, endpoint, 0)
                .context("inserting SRv6-FDB entry")?;
        }
    }

    // B9 flood sets: group by VNI into one `Srv6FloodSet` per segment, the SRv6
    // twin of the FLOOD_LIST grouping in `program_overlay`. Deferring an
    // unresolvable egress matches every other table here — a tap that appears
    // later is picked up on the next reconcile rather than aborting this one.
    let mut flood_groups: Vec<(u32, Vec<Srv6Endpoint>)> = Vec::new();
    for f in floods {
        let ifindex = match if_nametoindex(&f.out_iface) {
            Ok(i) => i,
            Err(_) => {
                log::debug!(
                    "srv6_flood egress {} not present yet; deferring its flood entry",
                    f.out_iface
                );
                continue;
            }
        };
        let ep = Srv6Endpoint::new(ifindex, f.remote_sid, f.outer_dst_mac);
        match flood_groups.iter_mut().find(|(v, _)| *v == f.vni) {
            Some((_, eps)) => eps.push(ep),
            None => flood_groups.push((f.vni, vec![ep])),
        }
    }

    {
        // Reconciled, not merely written: a VNI whose flood set the control plane
        // withdrew must stop replicating, and a stale set keeps sending every BUM
        // frame to a peer that no longer serves the tenant.
        let keep: HashSet<u32> = flood_groups.iter().map(|(v, _)| *v).collect();
        let mut flood: HashMap<_, u32, Srv6FloodSet> = HashMap::try_from(
            ebpf.map_mut("SRV6_FLOOD_LIST")
                .ok_or_else(|| anyhow!("SRV6_FLOOD_LIST map missing"))?,
        )?;
        drop_unlisted(&mut flood, &keep)?;
        for (vni, eps) in &flood_groups {
            flood
                .insert(vni, Srv6FloodSet::new(eps), 0)
                .with_context(|| format!("inserting SRv6 flood set for vni {vni}"))?;
        }
    }

    // B9 symmetric-IRB routes, keyed exactly like the VXLAN trie: longest-prefix
    // on `(ingress vni, inner dst)`.
    let prepared_irb: Vec<(Key<TunnelKey>, Srv6IrbEndpoint)> = irb_routes
        .iter()
        .filter_map(|r| {
            let ifindex = match if_nametoindex(&r.out_iface) {
                Ok(i) => i,
                Err(_) => {
                    log::debug!(
                        "srv6_irb_route egress {} not present yet; deferring its route",
                        r.out_iface
                    );
                    return None;
                }
            };
            let (_, addr) = r.inner_dst.lpm_key();
            Some((
                Key::new(
                    TunnelKey::prefix_len(r.inner_dst.prefix),
                    TunnelKey::new(r.vni, addr),
                ),
                Srv6IrbEndpoint::new(
                    ifindex,
                    r.l3_vni,
                    r.remote_sid,
                    r.outer_dst_mac,
                    r.router_mac,
                    r.gateway_mac,
                ),
            ))
        })
        .collect();

    {
        let mut irb: LpmTrie<_, TunnelKey, Srv6IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("SRV6_IRB_ROUTES")
                .ok_or_else(|| anyhow!("SRV6_IRB_ROUTES map missing"))?,
        )?;
        for (key, endpoint) in &prepared_irb {
            irb.insert(key, endpoint, 0)
                .context("inserting SRv6 IRB route entry")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    // Every table that can redirect needs its egress in the devmap, not just the
    // unicast FDB: a flood copy and a routed frame leave through the same helper,
    // and an ifindex missing here turns `redirect` into `XDP_ABORTED`.
    for ifindex in prepared
        .iter()
        .map(|(_, e)| e.out_ifindex)
        .chain(
            flood_groups
                .iter()
                .flat_map(|(_, eps)| eps.iter().map(|e| e.out_ifindex)),
        )
        .chain(prepared_irb.iter().map(|(_, e)| e.out_ifindex))
    {
        tx_ports
            .set(ifindex, ifindex, None, 0)
            .context("registering SRv6 redirect device")?;
    }

    Ok(())
}

/// A route resolved against the live system: ifindex looked up, source MAC
/// settled, ready to drop straight into the `ROUTES` and `TX_PORTS` maps.
struct PreparedRoute {
    policy: PolicyId,
    prefix: u32,
    data: u32,
    entry: RouteEntry,
}

/// Program the Phase 2 forwarding maps: `ROUTES` (the FIB) and `TX_PORTS` (the
/// redirect devmap). No-op when there are no routes, so a firewall-only
/// deployment never pays for it.
fn program_routes(ebpf: &mut Ebpf, routes: &[ResolvedRoute]) -> Result<()> {
    if routes.is_empty() {
        return Ok(());
    }

    // Resolve everything that needs the OS up front, so the two map-borrow
    // passes below don't each have to (and can't both hold `ebpf` at once).
    // Skip (defer) a route whose out_iface isn't resolvable yet instead of
    // hard-aborting the whole reconfigure — consistent with program_interfaces
    // and program_masquerade. A hard abort here would leave apply_config half
    // applied (remove_stale already ran) and blackhole traffic; the config
    // reconcile re-runs once the interface appears.
    let prepared: Vec<PreparedRoute> = routes
        .iter()
        .filter_map(|r| match prepare_route(r) {
            Ok(p) => Some(p),
            Err(e) => {
                log::debug!(
                    "route via {} not programmable yet ({e}); deferring",
                    r.out_iface
                );
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }

    {
        let mut fib: LpmTrie<_, ScopedAddr, RouteEntry> = LpmTrie::try_from(
            ebpf.map_mut("ROUTES")
                .ok_or_else(|| anyhow!("ROUTES map missing"))?,
        )?;
        for route in &prepared {
            fib.insert(
                &Key::new(
                    ScopedAddr::POLICY_BITS + route.prefix,
                    ScopedAddr::new(route.policy, route.data),
                ),
                route.entry,
                0,
            )
            .context("inserting route")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    for route in &prepared {
        // Index the devmap by ifindex so the data plane can redirect with the
        // ifindex it already has from the route entry.
        tx_ports
            .set(route.entry.out_ifindex, route.entry.out_ifindex, None, 0)
            .context("registering redirect device")?;
    }

    Ok(())
}

/// Resolve a [`ResolvedRoute`]'s egress interface to an ifindex (and, if needed,
/// its MAC) and build the kernel [`RouteEntry`].
fn prepare_route(route: &ResolvedRoute) -> Result<PreparedRoute> {
    let ifindex = if_nametoindex(&route.out_iface)?;
    let src_mac = match route.src_mac {
        Some(mac) => mac,
        None => read_iface_mac(&route.out_iface)?,
    };
    let (prefix, data) = route.dest.lpm_key();
    Ok(PreparedRoute {
        policy: route.policy,
        prefix,
        data,
        entry: RouteEntry::new(ifindex, src_mac, route.dst_mac, route.flags),
    })
}

/// `MEMBARRIER_CMD_GLOBAL` waits for a kernel RCU grace period on Linux.
/// XDP/NAPI and TC readers finish before map mutation starts. Do not replace
/// this with an expedited userspace-only barrier or a timing-based sleep.
/// See Linux kernel/sched/membarrier.c and Documentation/RCU/checklist.rst.
fn ensure_reader_barrier_supported() -> Result<()> {
    // SAFETY: membarrier QUERY takes integer arguments and no pointers.
    let supported =
        unsafe { libc::syscall(libc::SYS_membarrier, libc::MEMBARRIER_CMD_QUERY, 0, 0) };
    if supported < 0 {
        return Err(std::io::Error::last_os_error())
            .context("querying kernel packet-reader barrier");
    }
    if supported & libc::MEMBARRIER_CMD_GLOBAL as libc::c_long == 0 {
        bail!(
            "kernel does not support MEMBARRIER_CMD_GLOBAL; safe live configuration requires it (nohz_full must be disabled)"
        );
    }
    Ok(())
}

fn synchronize_packet_readers() -> Result<()> {
    let _timing = timing::Span::start(timing::Phase::ReaderDrain);
    loop {
        // SAFETY: GLOBAL takes integer arguments and no pointers. Its kernel
        // RCU grace period drains readers that passed the now-closed gate.
        if unsafe { libc::syscall(libc::SYS_membarrier, libc::MEMBARRIER_CMD_GLOBAL, 0, 0) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("draining packet readers");
        }
    }
}

/// Query the kernel directly so an unavailable observation cannot be mistaken
/// for a removed interface. Some libc `if_nametoindex` implementations replace
/// socket creation failures (including EMFILE) with ENOENT.
fn if_nametoindex(iface: &str) -> Result<u32> {
    if iface.is_empty() || iface.len() >= libc::IFNAMSIZ || iface.as_bytes().contains(&0) {
        bail!("invalid interface name {iface:?}");
    }
    let socket = loop {
        // SAFETY: socket has no pointer arguments; a successful descriptor is
        // owned below and closed on every return path.
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd >= 0 {
            // SAFETY: fd is a newly created, exclusively owned descriptor.
            break unsafe { OwnedFd::from_raw_fd(fd) };
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("opening interface lookup socket");
        }
    };
    // SAFETY: an all-zero ifreq is valid; its name is filled and terminated
    // below before the kernel receives it.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (destination, source) in request.ifr_name.iter_mut().zip(iface.bytes()) {
        *destination = source as libc::c_char;
    }
    loop {
        // SAFETY: request is a valid writable ifreq and socket stays open.
        let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFINDEX, &mut request) };
        if result == 0 {
            // SAFETY: SIOCGIFINDEX initialized this union member on success.
            return Ok(unsafe { request.ifr_ifru.ifru_ifindex } as u32);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        let context = if interface_missing(&error) {
            format!("interface {iface:?} not found")
        } else {
            format!("looking up interface {iface:?}")
        };
        return Err(error).context(context);
    }
}

fn interface_missing(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ENODEV | libc::ENXIO))
}

/// Read an interface's MAC address from `/sys/class/net/<iface>/address`.
fn read_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    parse_mac(text.trim()).map_err(|e| anyhow!("MAC of {iface}: {e}"))
}

/// The interfaces the TC **egress** hook has to be attached to.
///
/// The XDP ingress hook is attached to every configured interface; this one is
/// attached only where something needs it, because it is a second verdict stage
/// in the path of traffic nobody asked us to filter. Five things need it:
///
/// * `--egress`, the opt-in egress firewall, over the `--iface` set;
/// * an interface that **masquerades** (the SNAT happens here) or **clamps MSS**
///   (the option is rewritten here and nowhere else);
/// * a policy carrying a rule scoped to the way **out** — otherwise the rule
///   loads, matches nothing and says nothing, and the operator who wrote
///   `direction out` gets silence;
/// * a policy with **egress default drop**. On a guest tap this hook sees
///   packets entering the guest, so omitting it makes a cloud security group
///   look active while every inbound packet passes;
/// * a **stateful** policy that does not pass by default. The ingress hook
///   records a flow when it admits one, so a reply to something that *arrived*
///   is covered — but a connection the box itself starts never crosses that hook
///   on the way out, so nothing vouches for its reply and the default action
///   drops it. That is the whole of DNS, NTP, ACME, the update channel, dyndns,
///   alert webhooks and config-sync: on real hardware the box could send and
///   never hear an answer, while `stateful = true` said otherwise;
/// * an NPTv6 boundary interface (C16), where the source prefix is translated.
///
/// Names may repeat across the reasons; the result is deduplicated and keeps the
/// order the reasons are listed in.
fn egress_interfaces(cfg: &RuntimeConfig, ifaces: &[String], egress: bool) -> Vec<String> {
    let mut out: Vec<String> = if egress { ifaces.to_vec() } else { Vec::new() };
    let push = |name: &str, out: &mut Vec<String>| {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    };
    for i in &cfg.interfaces {
        if i.masquerade || i.mss != 0 {
            push(&i.name, &mut out);
        }
    }
    let out_scoped: Vec<PolicyId> = cfg
        .policies
        .iter()
        .filter(|p| {
            p.port_rules
                .iter()
                .any(|r| r.scope & PORT_RULE_OUT_ONLY != 0)
        })
        .map(|p| p.id)
        .collect();
    let needs_reply_state: Vec<PolicyId> = cfg
        .policies
        .iter()
        .filter(|p| p.global.has_flag(ConfigFlags::STATEFUL))
        .map(|p| p.id)
        .collect();
    for i in &cfg.interfaces {
        let drops_egress = cfg
            .policies
            .iter()
            .any(|p| p.id == i.policy && p.global.has_flag(ConfigFlags::EGRESS_DEFAULT_DROP));
        if out_scoped.contains(&i.policy) || needs_reply_state.contains(&i.policy) || drops_egress {
            push(&i.name, &mut out);
        }
    }
    for name in ifaces {
        let policy = cfg
            .interfaces
            .iter()
            .find(|i| &i.name == name)
            .map_or(0, |i| i.policy);
        if needs_reply_state.contains(&policy) || out_scoped.contains(&policy) {
            push(name, &mut out);
        }
    }
    for r in &cfg.npt66 {
        push(&r.interface, &mut out);
    }
    out
}

/// Load the `velstra_egress` TC classifier and attach it at **egress** on each
/// interface. Requires a `clsact` qdisc, which we create first (ignoring the
/// "already exists" case so a restart is idempotent).
fn attach_egress(
    ebpf: &mut Ebpf,
    ifaces: &[String],
    persist: Option<&crate::persist::Persist>,
) -> Result<BTreeMap<String, InterfaceLink<SchedClassifierLink>>> {
    for (slot, name) in [
        (0, "velstra_egress_v4"),
        (1, "velstra_egress_v6"),
        (2, "velstra_egress_icmp"),
        (3, "velstra_deferred_snat"),
        (4, "velstra_masquerade"),
        (5, "velstra_egress_v6_state"),
        (6, "velstra_related_egress"),
        (7, "velstra_related_egress_apply"),
        (8, "velstra_egress_v4_state"),
    ] {
        let fd = {
            let program: &mut SchedClassifier = ebpf
                .program_mut(name)
                .ok_or_else(|| anyhow!("missing {name}"))?
                .try_into()?;
            match program.load() {
                Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
                Err(e) => return Err(e).with_context(|| format!("loading {name}")),
            }
            program.fd()?.try_clone()?
        };
        let mut tails = ProgramArray::try_from(
            ebpf.map_mut("EGRESS_PROGS")
                .ok_or_else(|| anyhow!("EGRESS_PROGS missing"))?,
        )?;
        tails.set(slot, &fd, 0)?;
    }
    let program: &mut SchedClassifier = ebpf
        .program_mut("velstra_egress")
        .ok_or_else(|| anyhow!("eBPF object has no `velstra_egress` program"))?
        .try_into()?;
    match program.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(e) => return Err(e).context("loading TC egress program into the kernel"),
    }
    let mut links = BTreeMap::new();
    for iface in ifaces {
        let ifindex = if_nametoindex(iface)?;
        // Idempotent: a pre-existing clsact qdisc is fine.
        let _ = qdisc_add_clsact(iface);
        let link = attach_egress_one(program, iface, ifindex, persist)?;
        links.insert(iface.clone(), link);
        log::info!("attached egress firewall to {iface}");
    }
    // On a partial failure, the links collected so far drop and detach too.
    Ok(links)
}

/// One egress hook: adopt the previous agent's pinned one when persisting,
/// else attach (and pin when persisting). A TCX interface takes several
/// programs, so a pin that is not adopted must be removed before attaching —
/// two egress firewalls in a row would enforce the old policy and the new one.
fn attach_egress_one(
    program: &mut SchedClassifier,
    iface: &str,
    ifindex: u32,
    persist: Option<&crate::persist::Persist>,
) -> Result<InterfaceLink<SchedClassifierLink>> {
    let attach = |program: &mut SchedClassifier| -> Result<SchedClassifierLink> {
        let id = program
            .attach(iface, TcAttachType::Egress)
            .with_context(|| format!("attaching TC egress program to {iface}"))?;
        program.take_link(id).context("owning TC egress attachment")
    };
    let Some(persist) = persist else {
        return InterfaceLink::new(iface, ifindex, attach(program)?);
    };
    let path = persist.link_path(crate::persist::LinkRole::Egress, iface);
    if path.exists() {
        match swap_pinned::<SchedClassifierLink>(&path, |link| {
            let id = program.attach_to_link(link)?;
            Ok(program.take_link(id)?)
        }) {
            Ok((link, link_id)) => {
                log::info!("adopted the pinned egress firewall on {iface}");
                let pin = LinkPin { path, link_id };
                return InterfaceLink::with_pin(iface, ifindex, link, Some(pin));
            }
            Err(error) => {
                warn!(
                    "{iface}: not adopting {}: {error:#}; attaching afresh",
                    path.display()
                );
                crate::persist::remove_pin(&path)?;
            }
        }
    }
    let link = attach(program)?;
    if <&aya::programs::links::FdLink>::try_from(&link).is_err() {
        warn!("{iface}: the egress hook is a netlink tc filter (no TCX); it cannot be pinned");
        return InterfaceLink::new(iface, ifindex, link);
    }
    match pin_link::<SchedClassifierLink>(link, &path) {
        Ok((link, pin)) => InterfaceLink::with_pin(iface, ifindex, link, Some(pin)),
        Err(error) => {
            warn!("{iface}: {error:#}; this egress hook will not survive the agent");
            InterfaceLink::new(iface, ifindex, attach(program)?)
        }
    }
}

/// Load the B2 `velstra_bum` TC classifier and attach it at **ingress** on each
/// tenant tap, so a BUM (broadcast/unknown-unicast/multicast) frame from the VM
/// is head-end replicated to the VNI's flood set. Requires a `clsact` qdisc,
/// created first (idempotent, like [`attach_egress`]).
///
/// The caller retries failed replication attachments without taking down
/// working firewall links. Newly attached links are owned by the returned map,
/// so a partial failure also releases every link created by this attempt.
fn attach_bum_ingress(
    ebpf: &mut Ebpf,
    ifaces: &[String],
) -> Result<BTreeMap<String, InterfaceLink<SchedClassifierLink>>> {
    let program: &mut SchedClassifier = ebpf
        .program_mut("velstra_bum")
        .ok_or_else(|| anyhow!("eBPF object has no `velstra_bum` program"))?
        .try_into()?;
    // The load is attempted once per call, and an *already-loaded* program is the
    // normal case from the second call onward: a controller-driven agent picks up
    // new tenant taps on every reconfigure, and the program is already in the
    // kernel by then. Aya reports that as `ProgramError::AlreadyLoaded`, which we
    // swallow — treating it as fatal would mean only the taps present at startup
    // ever got a classifier, the bug this routine exists to fix.
    //
    // Any *other* load error is a genuine failure (a verifier rejection on the
    // first real attempt, most importantly) and is surfaced with its full context
    // instead of being lost to a debug line.
    match program.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(e) => return Err(e).context("loading TC BUM-replication program into the kernel"),
    }
    let mut links = BTreeMap::new();
    for iface in ifaces {
        let ifindex = if_nametoindex(iface)?;
        // Idempotent: a pre-existing clsact qdisc is fine.
        let _ = qdisc_add_clsact(iface);
        let id = program
            .attach(iface, TcAttachType::Ingress)
            .with_context(|| format!("attaching TC BUM-replication program to {iface}"))?;
        let link = program.take_link(id).context("owning TC BUM attachment")?;
        links.insert(iface.clone(), InterfaceLink::new(iface, ifindex, link)?);
        log::info!("attached BUM head-end replication (ingress) to {iface}");
    }
    Ok(links)
}

/// Attach `program` to `iface`: adopt the previous agent's pinned attachment
/// when persisting, else walk the candidate modes for `mode` until one
/// succeeds (and pin the result when persisting).
fn attach_with_fallback(
    program: &mut Xdp,
    iface: &str,
    mode: AttachMode,
    persist: Option<&crate::persist::Persist>,
) -> Result<(XdpMode, InterfaceLink<XdpLink>)> {
    let ifindex = if_nametoindex(iface)?;
    let Some(persist) = persist else {
        let (chosen, link) = attach_xdp_fresh(program, iface, mode)?;
        return Ok((chosen, InterfaceLink::new(iface, ifindex, link)?));
    };
    if let Some(adopted) = adopt_xdp(program, iface, ifindex, mode, persist)? {
        return Ok(adopted);
    }
    let (chosen, link) = attach_xdp_fresh(program, iface, mode)?;
    let path = persist.link_path(crate::persist::LinkRole::Xdp(xdp_mode_name(chosen)), iface);
    match pin_link::<XdpLink>(link, &path) {
        Ok((link, pin)) => Ok((
            chosen,
            InterfaceLink::with_pin(iface, ifindex, link, Some(pin))?,
        )),
        Err(error) => {
            // The failed pin released the attachment; take one that at least
            // lives as long as this agent.
            warn!("{iface}: {error:#}; this XDP attachment will not survive the agent");
            let (chosen, link) = attach_xdp_fresh(program, iface, mode)?;
            Ok((chosen, InterfaceLink::new(iface, ifindex, link)?))
        }
    }
}

fn attach_xdp_fresh(
    program: &mut Xdp,
    iface: &str,
    mode: AttachMode,
) -> Result<(XdpMode, XdpLink)> {
    let mut last_err = None;
    for candidate in mode.candidates() {
        match program.attach(iface, *candidate) {
            Ok(id) => {
                let link = program.take_link(id).context("owning XDP attachment")?;
                return Ok((*candidate, link));
            }
            Err(e) => {
                warn!("attach to {iface} in {candidate:?} mode failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(match last_err {
        Some(e) => anyhow!("could not attach XDP program to {iface}: {e}"),
        None => anyhow!("no XDP attach mode was attempted for {iface}"),
    })
}

/// Swap `program` into the previous agent's pinned XDP attachment on `iface`
/// (one atomic `bpf_link_update`: the interface is never unfiltered). A pin
/// that cannot be adopted — another mode, a link whose interface was
/// recreated — is removed so the fresh attach is not refused.
fn adopt_xdp(
    program: &mut Xdp,
    iface: &str,
    ifindex: u32,
    mode: AttachMode,
    persist: &crate::persist::Persist,
) -> Result<Option<(XdpMode, InterfaceLink<XdpLink>)>> {
    for (name, path) in persist.xdp_pins(iface)? {
        let chosen = xdp_mode_of(name);
        if mode.candidates().contains(&chosen) {
            match swap_pinned::<XdpLink>(&path, |link| {
                let id = program.attach_to_link(link)?;
                Ok(program.take_link(id)?)
            }) {
                Ok((link, link_id)) => {
                    log::info!("adopted the pinned XDP attachment on {iface} ({chosen:?})");
                    let pin = LinkPin { path, link_id };
                    return Ok(Some((
                        chosen,
                        InterfaceLink::with_pin(iface, ifindex, link, Some(pin))?,
                    )));
                }
                Err(error) => warn!(
                    "{iface}: not adopting {}: {error:#}; attaching afresh",
                    path.display()
                ),
            }
        }
        crate::persist::remove_pin(&path)?;
    }
    Ok(None)
}

/// Open the pinned link at `path` and hand it to `update`, which swaps the new
/// program in. Returns the updated link and its kernel id.
fn swap_pinned<L>(path: &std::path::Path, update: impl FnOnce(L) -> Result<L>) -> Result<(L, u32)>
where
    L: TryFrom<aya::programs::links::FdLink, Error = aya::programs::links::LinkError>,
{
    let link = aya::programs::links::FdLink::from(
        aya::programs::links::PinnedLink::from_pin(path).context("opening the pin")?,
    );
    let link_id = link.info().context("reading the pinned link")?.id();
    let typed = L::try_from(link).context("the pin is not this kind of attachment")?;
    Ok((update(typed).context("bpf_link_update")?, link_id))
}

/// Pin a freshly attached `link` at `path`. Consumes it: on failure the
/// attachment is gone and the caller must attach again.
fn pin_link<L>(link: L, path: &std::path::Path) -> Result<(L, LinkPin)>
where
    L: TryFrom<aya::programs::links::FdLink, Error = aya::programs::links::LinkError>,
    aya::programs::links::FdLink: TryFrom<L, Error = aya::programs::links::LinkError>,
{
    let link = aya::programs::links::FdLink::try_from(link)
        .context("the attachment is not a bpf_link and cannot be pinned")?;
    let link_id = link.info().context("reading the new link")?.id();
    // Whatever is still at this path was not adoptable: a defunct link.
    crate::persist::remove_pin(path)?;
    let pinned = link
        .pin(path)
        .with_context(|| format!("pinning {}", path.display()))?;
    let link = L::try_from(aya::programs::links::FdLink::from(pinned))
        .context("re-typing the pinned link")?;
    Ok((
        link,
        LinkPin {
            path: path.to_path_buf(),
            link_id,
        },
    ))
}

fn xdp_mode_name(mode: XdpMode) -> crate::persist::XdpModeName {
    use crate::persist::XdpModeName;
    match mode {
        XdpMode::Driver => XdpModeName::Driver,
        XdpMode::Hardware => XdpModeName::Hardware,
        _ => XdpModeName::Skb,
    }
}

fn xdp_mode_of(name: crate::persist::XdpModeName) -> XdpMode {
    use crate::persist::XdpModeName;
    match name {
        XdpModeName::Driver => XdpMode::Driver,
        XdpModeName::Hardware => XdpMode::Hardware,
        XdpModeName::Skb => XdpMode::Skb,
    }
}

/// A summed snapshot of the per-CPU statistics.
pub struct Stats {
    /// `(counter, total-across-cpus)` for every [`Counter`], in index order.
    pub rows: Vec<(Counter, u64)>,
}

impl Stats {
    /// Look up a single counter's total.
    pub fn get(&self, counter: Counter) -> u64 {
        self.rows
            .get(counter.index() as usize)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    /// Render an aligned, human-readable table.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let rx = self.get(Counter::RxPackets);
        let dropped: u64 = self
            .rows
            .iter()
            .filter(|(c, _)| is_drop_counter(*c))
            .map(|(_, v)| *v)
            .sum();
        let drop_pct = if rx > 0 {
            (dropped as f64 / rx as f64) * 100.0
        } else {
            0.0
        };

        let mut out = String::new();
        let _ = writeln!(out, "  {:<20} {:>14}", "counter", "value");
        let _ = writeln!(out, "  {:-<20} {:->14}", "", "");
        for (counter, value) in &self.rows {
            let _ = writeln!(out, "  {:<20} {:>14}", counter.label(), value);
        }
        let _ = writeln!(out, "  {:-<20} {:->14}", "", "");
        let _ = writeln!(out, "  {:<20} {:>13.2}%", "drop rate", drop_pct);
        out
    }
}

/// Whether a counter records a dropped packet (used for the drop-rate summary).
fn is_drop_counter(counter: Counter) -> bool {
    matches!(
        counter,
        Counter::DroppedDefault
            | Counter::DroppedBlocklist
            | Counter::DroppedRule
            | Counter::DroppedIcmp
            | Counter::DroppedRateLimit
            | Counter::DroppedSpoofed
            | Counter::SynproxyRejected
            | Counter::ForwardTtlExceeded
            | Counter::EgressDropped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_napt_domain_requires_absence_of_both_ha_and_sync() {
        let base = serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({}))
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(standalone_napt_mode(&base), 1);
        let mut ha = base.clone();
        ha.ha = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": false, "cluster": "test", "node": 1, "interfaces": []
            }))
            .unwrap(),
        );
        // Even a disabled HA configuration cannot opt into a mapping format
        // that deployed synchronized peers cannot discover.
        assert_eq!(standalone_napt_mode(&ha), 0);
        let sync = serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({
            "conntrack_sync": { "listen": "0.0.0.0:5429", "peer": ["10.0.0.2:5429"],
                "secret": "unit-test-credential-at-least-32-bytes" }
        }))
        .unwrap()
        .resolve()
        .unwrap();
        assert_eq!(standalone_napt_mode(&sync), 0);
        ha.conntrack_sync = sync.conntrack_sync;
        assert_eq!(standalone_napt_mode(&ha), 0);
    }

    #[test]
    fn direct_and_controller_reconfigure_guard_precedes_all_configuration_mutation() {
        let source = include_str!("firewall.rs");
        let body = source
            .split("pub fn reconfigure_with_reset(")
            .nth(1)
            .unwrap()
            .split("/// Replace the advertised")
            .next()
            .unwrap();
        assert!(
            body.find("self.requires_restart(cfg)").unwrap()
                < body.find("std::mem::replace").unwrap()
        );
        assert!(
            body.find("restart-required").unwrap()
                < body.find("self.reprogram_with_reset(reset)").unwrap()
        );
        assert!(!body.contains("if !reset"));
    }

    #[test]
    fn quiesced_initial_writer_requires_unattached_closed_gate() {
        let initial = ReaderQuiescence::Unattached;
        initial.validate(CONFIG_UPDATING, false).unwrap();
        assert!(initial.validate(CONFIG_UPDATING, true).is_err());
        for state in [CONFIG_READY, CONFIG_FAILED, u32::MAX] {
            assert!(initial.validate(state, false).is_err());
        }
    }

    #[test]
    fn quiesced_live_candidate_and_rollback_share_exactly_one_drain() {
        let drains = std::cell::Cell::new(0);
        let quiesced = ReaderQuiescence::drain_with(|| {
            drains.set(drains.get() + 1);
            Ok(())
        })
        .unwrap();
        quiesced.validate(CONFIG_UPDATING, true).unwrap(); // candidate
        quiesced.validate(CONFIG_UPDATING, true).unwrap(); // rollback
        assert_eq!(drains.get(), 1);
        assert!(quiesced.validate(CONFIG_READY, true).is_err());
        assert!(quiesced.validate(CONFIG_FAILED, true).is_err());
    }

    #[test]
    fn quiesced_failed_first_barrier_never_authorizes_a_writer() {
        let mut writes = 0;
        let result =
            ReaderQuiescence::drain_with(|| Err(anyhow!("injected global reader drain failure")))
                .and_then(|quiesced| {
                    quiesced.validate(CONFIG_UPDATING, true)?;
                    writes += 1;
                    Ok(())
                });
        assert_eq!(
            result.unwrap_err().to_string(),
            "injected global reader drain failure"
        );
        assert_eq!(writes, 0);
    }

    fn ipv4_test_interfaces() -> Vec<ResolvedInterface> {
        serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({
            "policy": [{"id":1,"name":"lan"}, {"id":2,"name":"other"}],
            "interface": [{"name":"lan0","policy":1}, {"name":"other0","policy":2}]
        }))
        .unwrap()
        .resolve()
        .unwrap()
        .interfaces
    }

    fn address_addition_fixture() -> (PreparedHostConfig, PreparedHostConfig) {
        let previous = PreparedHostConfig {
            overlay: OverlayConfig::DISABLED,
            srv6: Srv6Config::DISABLED,
            route_ifindices: BTreeMap::from([("lan0".into(), 9)]),
            ipv4: BTreeMap::from([(
                "lan0".into(),
                InterfaceIpv4 {
                    ifindex: 9,
                    primary: Some([192, 0, 2, 1]),
                    dhcp_mac: Some([2, 0, 0, 0, 0, 1]),
                    prefixes: BTreeSet::from([([192, 0, 2, 1], [255, 255, 255, 0])]),
                },
            )]),
            local: BTreeSet::new(),
        };
        let mut observed = previous.clone();
        observed
            .ipv4
            .get_mut("lan0")
            .unwrap()
            .prefixes
            .insert(([192, 0, 2, 100], [255, 255, 255, 0]));
        (previous, observed)
    }

    #[test]
    fn monotonic_local_address_addition_requires_completed_intent_and_live_hooks() {
        let mut intent = AppliedIntent { current: true };
        assert!(intent.allows_address_refresh(Some(CONFIG_READY), true));
        for state in [
            None,
            Some(CONFIG_FAILED),
            Some(CONFIG_UPDATING),
            Some(u32::MAX),
        ] {
            assert!(!intent.allows_address_refresh(state, true));
        }
        assert!(!intent.allows_address_refresh(Some(CONFIG_READY), false));
        // All policy/FlowSpec/learned-route transactions invalidate the same
        // capability before mutations. Rollback reopening READY is not success.
        intent.begin();
        assert!(!intent.allows_address_refresh(Some(CONFIG_READY), true));
        assert!(
            intent
                .finish(Err(anyhow!("injected failed reopen")))
                .is_err()
        );
        assert!(!intent.allows_address_refresh(Some(CONFIG_READY), true));
        // Only a fresh successful full application of merged source intent
        // restores the capability; failed candidates cannot be acknowledged.
        intent.begin();
        intent.finish(Ok(())).unwrap();
        assert!(intent.allows_address_refresh(Some(CONFIG_READY), true));
    }

    /// DP-16: with a `dst-local` rule, a new host address (a DHCP lease,
    /// a VRRP address arriving on failover) changes rule-trie entries. The
    /// additive shortcut only grows LOCAL_EGRESS_ADDRS and must not be taken,
    /// or the rule would keep matching the old address set.
    #[test]
    fn a_changed_local_destination_set_takes_the_full_rewrite() {
        let (mut previous, mut observed) = address_addition_fixture();
        previous.local = BTreeSet::from(["192.0.2.1".parse().unwrap()]);
        observed.local =
            BTreeSet::from(["192.0.2.1".parse().unwrap(), "192.0.2.100".parse().unwrap()]);
        assert_eq!(local_address_additions(&previous, &observed), None);
        // Unchanged local sets keep the shortcut available.
        observed.local = previous.local.clone();
        assert!(local_address_additions(&previous, &observed).is_some());
    }

    #[test]
    fn monotonic_local_address_addition_retains_exact_host_keys() {
        let (previous, observed) = address_addition_fixture();
        assert_eq!(
            local_address_additions(&previous, &observed),
            Some(BTreeSet::from([local_egress_address_key(
                9,
                [192, 0, 2, 100]
            )]))
        );
        assert_eq!(
            local_address_additions(&previous, &previous),
            Some(BTreeSet::new())
        );
    }

    #[test]
    fn monotonic_local_address_addition_preserves_all_reply_memberships() {
        let (mut previous, mut observed) = address_addition_fixture();
        // The proof includes overlap between different policies, not merely a
        // currently configured DNAT target. Runtime mappings use this resolver
        // too, and must retain their existing reply policy and expiry.
        let overlap = InterfaceIpv4 {
            ifindex: 10,
            primary: None,
            dhcp_mac: None,
            prefixes: BTreeSet::from([([192, 0, 2, 129], [255, 255, 255, 128])]),
        };
        previous.ipv4.insert("other0".into(), overlap.clone());
        observed.ipv4.insert("other0".into(), overlap);
        assert!(local_address_additions(&previous, &observed).is_some());
        let interfaces = ipv4_test_interfaces();
        for subnet in [1, 2, 3] {
            for host in 0..=255 {
                let target = [192, 0, subnet, host];
                assert_eq!(
                    resolve_reply_policy(target, &interfaces, &previous.ipv4),
                    resolve_reply_policy(target, &interfaces, &observed.ipv4),
                    "reply policy changed for {target:?}"
                );
            }
        }
    }

    #[test]
    fn monotonic_local_address_addition_rejects_changed_permissions_and_identity() {
        let (previous, observed) = address_addition_fixture();
        let mut cases = Vec::new();
        let mut changed = observed.clone();
        changed
            .ipv4
            .get_mut("lan0")
            .unwrap()
            .prefixes
            .remove(&([192, 0, 2, 1], [255, 255, 255, 0]));
        cases.push(("deletion", changed));
        for (label, prefix) in [
            ("new subnet", ([198, 51, 100, 1], [255, 255, 255, 0])),
            ("wider prefix", ([192, 0, 2, 100], [255, 255, 0, 0])),
            (
                "different prefix length",
                ([192, 0, 2, 100], [255, 255, 255, 255]),
            ),
        ] {
            let mut changed = observed.clone();
            changed
                .ipv4
                .get_mut("lan0")
                .unwrap()
                .prefixes
                .insert(prefix);
            cases.push((label, changed));
        }
        let mut changed = observed.clone();
        changed.ipv4.get_mut("lan0").unwrap().primary = Some([192, 0, 2, 100]);
        cases.push(("DHCP/masquerade primary", changed));
        let mut changed = observed.clone();
        changed.ipv4.get_mut("lan0").unwrap().dhcp_mac = Some([2, 0, 0, 0, 0, 2]);
        cases.push(("DHCP MAC", changed));
        let mut changed = observed.clone();
        changed.ipv4.get_mut("lan0").unwrap().ifindex = 10;
        cases.push(("recreated link", changed));
        let mut changed = observed.clone();
        changed.route_ifindices.insert("lan0".into(), 10);
        cases.push(("route interface", changed));
        let mut changed = observed.clone();
        changed.ipv4.remove("lan0");
        cases.push(("missing interface", changed));
        let mut changed = observed.clone();
        changed
            .ipv4
            .insert("other0".into(), observed.ipv4["lan0"].clone());
        cases.push(("new interface", changed));
        let mut changed = observed.clone();
        changed.overlay = OverlayConfig::new([192, 0, 2, 1], [2, 0, 0, 0, 0, 1], 4789, 0, 1500);
        cases.push(("overlay", changed));
        let mut changed = observed.clone();
        changed.srv6 = Srv6Config::new([0; 16], [2, 0, 0, 0, 0, 1], 1500);
        cases.push(("SRv6", changed));
        for (label, changed) in cases {
            assert!(
                local_address_additions(&previous, &changed).is_none(),
                "accepted {label}"
            );
        }
    }

    #[test]
    fn reply_policy_uses_every_prefix_and_withdraws_without_a_match() {
        let interfaces = ipv4_test_interfaces();
        let lan = &interfaces[0];
        let prefixes = [
            ([192, 0, 2, 1], [255, 255, 255, 0]),
            ([10, 44, 16, 1], [255, 255, 240, 0]),
        ];
        let mut inventory = BTreeMap::from([(
            lan.name.clone(),
            normalize_interface_ipv4(lan, 9, &prefixes, None).unwrap(),
        )]);
        assert_eq!(
            resolve_reply_policy([192, 0, 2, 4], &interfaces, &inventory),
            1
        );
        assert_eq!(
            resolve_reply_policy([10, 44, 31, 254], &interfaces, &inventory),
            1
        );
        assert_eq!(
            resolve_reply_policy([10, 44, 32, 1], &interfaces, &inventory),
            0
        );
        inventory
            .get_mut("lan0")
            .unwrap()
            .prefixes
            .remove(&prefixes[1]);
        assert_eq!(
            resolve_reply_policy([10, 44, 31, 254], &interfaces, &inventory),
            0
        );
        inventory.clear();
        assert_eq!(
            resolve_reply_policy([192, 0, 2, 4], &interfaces, &inventory),
            0
        );
    }

    #[test]
    fn overlapping_zones_and_backend_pools_never_guess_a_reply_policy() {
        let mut interfaces = ipv4_test_interfaces();
        let prefixes = [([10, 44, 16, 1], [255, 255, 240, 0])];
        let inventory: Ipv4Inventory = interfaces
            .iter()
            .enumerate()
            .map(|(index, iface)| {
                (
                    iface.name.clone(),
                    normalize_interface_ipv4(iface, index as u32 + 9, &prefixes, None).unwrap(),
                )
            })
            .collect();
        let backend = Backend::new([10, 44, 20, 2], 80);
        assert_eq!(resolve_reply_policy(backend.ip, &interfaces, &inventory), 0);
        interfaces[1].policy = interfaces[0].policy;
        assert_eq!(resolve_reply_policy(backend.ip, &interfaces, &inventory), 1);
        assert_eq!(pool_reply_policy(&[backend], &interfaces, &inventory), 1);
        assert_eq!(pool_reply_policy(&[], &interfaces, &inventory), 0);
        assert_eq!(
            pool_reply_policy(
                &[backend, Backend::new([203, 0, 113, 2], 80)],
                &interfaces,
                &inventory,
            ),
            0
        );
    }

    #[test]
    fn inventory_normalization_ignores_only_semantically_irrelevant_order() {
        let mut iface = ipv4_test_interfaces().remove(0);
        let first = ([192, 0, 2, 1], [255, 255, 255, 0]);
        let second = ([10, 44, 16, 1], [255, 255, 240, 0]);
        let observed = |iface: &ResolvedInterface, addresses: &[Ipv4Prefix], mac| {
            normalize_interface_ipv4(iface, 9, addresses, mac).unwrap()
        };
        assert_eq!(
            observed(&iface, &[first, second, first], None),
            observed(&iface, &[second, first], None),
            "non-SNAT prefix order/duplicates have no policy effect"
        );
        iface.masquerade = true;
        assert_ne!(
            observed(&iface, &[first, second], None),
            observed(&iface, &[second, first], None),
            "a changed kernel primary changes implicit SNAT"
        );
        assert_eq!(observed(&iface, &[], None).primary, None);
        iface.snat_address = Some([203, 0, 113, 10]);
        assert_eq!(
            observed(&iface, &[first, second], None),
            observed(&iface, &[second, first], None),
            "explicit SNAT must not depend on primary ordering"
        );
        iface.dhcp_client = true;
        assert!(normalize_interface_ipv4(&iface, 9, &[first], None).is_err());
        let mac = [2, 0, 0, 0, 0, 1];
        assert_eq!(observed(&iface, &[first], Some(mac)).dhcp_mac, Some(mac));
        assert_ne!(
            observed(&iface, &[first], Some(mac)),
            observed(&iface, &[first], Some([2, 0, 0, 0, 0, 2]))
        );
        assert!(normalize_interface_ipv4(&iface, 0, &[first], Some(mac)).is_err());
    }

    #[test]
    fn ipv4_labels_cannot_reassign_an_address_to_a_different_policy() {
        let interfaces = ipv4_test_interfaces();
        let json = serde_json::json!([
            {"ifindex":9,"ifname":"lan0","addr_info":[
                {"family":"inet","local":"192.0.2.1","prefixlen":24,"label":"lan0"},
                {"family":"inet","local":"10.44.16.1","prefixlen":20,"label":"other0:forged"},
                {"family":"inet6","local":"fe80::1","prefixlen":64}
            ]},
            {"ifindex":10,"ifname":"other0","addr_info":[]}
        ]);
        let inventory =
            parse_ipv4_inventory(&serde_json::to_vec(&json).unwrap(), &interfaces).unwrap();
        assert_eq!(inventory["lan0"].prefixes.len(), 2);
        assert!(inventory["other0"].prefixes.is_empty());
        assert_eq!(
            resolve_reply_policy([10, 44, 20, 2], &interfaces, &inventory),
            1
        );
        assert_eq!(inventory["other0"].ifindex, 10);
    }

    #[test]
    fn malformed_or_ambiguous_inventory_is_never_an_empty_success() {
        let interfaces = ipv4_test_interfaces();
        for json in [
            serde_json::json!({}),
            serde_json::json!([{"ifindex":9,"ifname":"lan0"}]),
            serde_json::json!([{"ifindex":0,"ifname":"lan0","addr_info":[]}]),
            serde_json::json!([
                {"ifindex":9,"ifname":"lan0","addr_info":[]},
                {"ifindex":9,"ifname":"other0","addr_info":[]}
            ]),
            serde_json::json!([
                {"ifindex":9,"ifname":"lan0","addr_info":[]},
                {"ifindex":10,"ifname":"lan0","addr_info":[]}
            ]),
            serde_json::json!([{"ifindex":9,"ifname":"lan0","addr_info":[
                {"family":"inet","local":"192.0.2.1","prefixlen":33}
            ]}]),
            serde_json::json!([{"ifindex":9,"ifname":"lan0","addr_info":[
                {"family":"inet","local":"::1","prefixlen":24}
            ]}]),
            serde_json::json!([{"ifindex":9,"ifname":"lan0","addr_info":[
                {"family":"surprise","local":"192.0.2.1","prefixlen":24}
            ]}]),
        ] {
            assert!(
                parse_ipv4_inventory(&serde_json::to_vec(&json).unwrap(), &interfaces).is_err(),
                "{json}"
            );
        }
        assert!(parse_ipv4_inventory(b"[{", &interfaces).is_err());
        assert!(parse_ipv4_inventory(b"[]", &interfaces).unwrap().is_empty());
    }

    // A child of this test executable supplies controlled subprocess failure
    // modes without changing global environment or requiring a host shell.
    #[test]
    fn inventory_observer_subprocess_fixture() {
        use std::io::Write;
        match std::env::var("VELSTRA_TEST_OBSERVER_CHILD").as_deref() {
            Ok("timeout") => std::thread::sleep(Duration::from_secs(10)),
            Ok("oversize") => {
                let mut out = std::io::stdout().lock();
                for _ in 0..2304 {
                    if out.write_all(&[b'x'; 4096]).is_err() {
                        break;
                    }
                }
            }
            Ok("failed") => std::process::exit(9),
            _ => {}
        }
    }

    #[test]
    fn observer_spawn_status_time_and_output_failures_are_bounded_errors() {
        assert!(
            read_inventory_output(std::process::Command::new("/no-such-velstra-observer")).is_err()
        );
        for mode in ["failed", "timeout", "oversize"] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command.args([
                "--exact",
                "firewall::tests::inventory_observer_subprocess_fixture",
                "--nocapture",
            ]);
            command.env("VELSTRA_TEST_OBSERVER_CHILD", mode);
            let before = Instant::now();
            let error = read_inventory_output(command).unwrap_err();
            let message = format!("{error:#}");
            let expected = match mode {
                "failed" => "failed",
                "timeout" => "timed out",
                _ => "exceeds",
            };
            assert!(message.contains(expected), "{mode}: {message}");
            assert!(
                before.elapsed() < Duration::from_secs(4),
                "{mode}: unbounded observer"
            );
        }
    }

    #[test]
    fn real_rtnetlink_inventory_distinguishes_loopback_from_an_absent_link() {
        let mut interfaces = ipv4_test_interfaces();
        interfaces[0].name = "lo".into();
        interfaces[1].name = "velstra-no-such".into();
        let inventory = read_ipv4_inventory(&interfaces).unwrap();
        assert_eq!(inventory.len(), 1);
        let observed = inventory.get("lo").unwrap();
        assert_eq!(observed.ifindex, if_nametoindex("lo").unwrap());
        assert!(
            observed
                .prefixes
                .contains(&([127, 0, 0, 1], [255, 0, 0, 0]))
        );
        assert_eq!(
            resolve_reply_policy([127, 0, 0, 2], &interfaces, &inventory),
            1
        );
        assert_eq!(inventory, read_ipv4_inventory_ip(&interfaces).unwrap());
    }

    #[test]
    fn native_inventory_matches_ip_for_every_present_host_link() {
        let base = ipv4_test_interfaces().remove(0);
        let interfaces: Vec<_> = crate::host_inventory::read()
            .unwrap()
            .into_iter()
            .map(|link| {
                let mut iface = base.clone();
                iface.name = link.name;
                iface.masquerade = true;
                iface.snat_address = None;
                iface.dhcp_client = link.mac.as_ref().is_some_and(|mac| mac.len() == 6);
                iface
            })
            .collect();
        assert!(!interfaces.is_empty());
        assert_eq!(
            read_ipv4_inventory(&interfaces).unwrap(),
            read_ipv4_inventory_ip(&interfaces).unwrap()
        );
    }

    /// Run explicitly where user/network namespaces are available. All link
    /// mutations happen in a child whose network namespace differs from its
    /// parent's; no sudo and no mutations to the developer/runner namespace.
    #[test]
    #[ignore = "requires unshare user/network namespaces and iproute2"]
    fn native_inventory_isolated_namespace_parity() {
        let output = std::process::Command::new("unshare")
            .args(["-Urn", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "firewall::tests::native_inventory_namespace_fixture",
                "--nocapture",
            ])
            .env(
                "VELSTRA_TEST_INVENTORY_PARENT_NS",
                std::fs::read_link("/proc/self/ns/net").unwrap(),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn native_inventory_namespace_fixture() {
        let Some(parent) = std::env::var_os("VELSTRA_TEST_INVENTORY_PARENT_NS") else {
            return;
        };
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(parent),
            "refusing mutations outside a new network namespace"
        );
        let ip = |args: &[&str]| {
            let output = std::process::Command::new("ip")
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "ip {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        ip(&["link", "set", "lo", "up"]);
        for name in ["lan0", "empty0", "v6only0"] {
            ip(&["link", "add", name, "type", "dummy"]);
            ip(&["link", "set", name, "up"]);
        }
        ip(&["address", "add", "192.0.2.1/24", "dev", "lan0"]);
        ip(&[
            "address",
            "add",
            "192.0.2.9/24",
            "dev",
            "lan0",
            "label",
            "lan0:vip",
        ]);
        ip(&[
            "address",
            "add",
            "198.51.100.10/24",
            "dev",
            "lan0",
            "preferred_lft",
            "0",
            "valid_lft",
            "30",
        ]);
        ip(&[
            "address",
            "add",
            "203.0.113.1",
            "peer",
            "203.0.113.2/32",
            "dev",
            "lan0",
        ]);
        ip(&[
            "-6",
            "address",
            "add",
            "2001:db8::1/64",
            "dev",
            "v6only0",
            "nodad",
        ]);
        let base = ipv4_test_interfaces().remove(0);
        let mut interfaces: Vec<_> = ["lan0", "empty0", "v6only0", "absent0"]
            .into_iter()
            .map(|name| {
                let mut iface = base.clone();
                iface.name = name.into();
                iface.masquerade = true;
                iface.dhcp_client = true;
                iface
            })
            .collect();
        let parity = |interfaces: &[ResolvedInterface]| {
            let native = read_ipv4_inventory(interfaces).unwrap();
            assert_eq!(native, read_ipv4_inventory_ip(interfaces).unwrap());
            native
        };
        let initial = parity(&interfaces);
        assert_eq!(initial["lan0"].primary, Some([192, 0, 2, 1]));
        assert!(
            initial["lan0"]
                .prefixes
                .contains(&([203, 0, 113, 1], [255; 4]))
        );
        assert!(
            !initial["lan0"]
                .prefixes
                .iter()
                .any(|(address, _)| *address == [203, 0, 113, 2])
        );
        assert!(initial["empty0"].prefixes.is_empty() && initial["v6only0"].prefixes.is_empty());
        assert!(!initial.contains_key("absent0"));
        interfaces[0].snat_address = Some([192, 0, 2, 99]);
        assert_eq!(parity(&interfaces)["lan0"].primary, None);
        ip(&["link", "set", "lan0", "address", "02:00:00:00:00:99"]);
        assert_eq!(
            parity(&interfaces)["lan0"].dhcp_mac,
            Some([2, 0, 0, 0, 0, 0x99])
        );
        ip(&[
            "address",
            "add",
            "10.99.0.1/24",
            "dev",
            "lan0",
            "preferred_lft",
            "0",
            "valid_lft",
            "1",
        ]);
        assert!(
            parity(&interfaces)["lan0"]
                .prefixes
                .iter()
                .any(|(address, _)| *address == [10, 99, 0, 1])
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while read_ipv4_inventory(&interfaces).unwrap()["lan0"]
            .prefixes
            .iter()
            .any(|(address, _)| *address == [10, 99, 0, 1])
        {
            assert!(
                Instant::now() < deadline,
                "kernel address lifetime did not expire"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        parity(&interfaces);
        ip(&["link", "delete", "lan0"]);
        assert!(!parity(&interfaces).contains_key("lan0"));
        ip(&["link", "add", "lan0", "type", "dummy"]);
        let replacement = parity(&interfaces);
        assert_ne!(replacement["lan0"].ifindex, initial["lan0"].ifindex);
        assert!(replacement["lan0"].prefixes.is_empty());
    }

    #[test]
    fn masquerade_follows_live_addresses_and_preserves_explicit_snat() {
        let cfg = serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({
            "interface": [
                {"name":"wan0", "policy":0, "masquerade":true},
                {"name":"wan1", "policy":0, "masquerade":true, "snat_address":"203.0.113.100"},
                {"name":"lan0", "policy":0}
            ]
        }))
        .unwrap()
        .resolve()
        .unwrap();
        let indices = |name: &str| Ok(if name == "wan0" { 10 } else { 11 });
        let absent = |_: &str| Err(anyhow!("no lease yet"));
        // No lease: the entry stays, unaddressed, so the data plane drops what
        // would otherwise leave un-translated (see `velstra_common::UNADDRESSED`).
        assert_eq!(
            masquerade_targets(&cfg.interfaces, indices, absent),
            BTreeMap::from([(10, velstra_common::UNADDRESSED), (11, [203, 0, 113, 100])])
        );
        for ip in [[198, 51, 100, 2], [198, 51, 100, 9]] {
            assert_eq!(
                masquerade_targets(&cfg.interfaces, indices, |_| Ok(ip)),
                BTreeMap::from([(10, ip), (11, [203, 0, 113, 100])])
            );
        }
        assert!(
            masquerade_targets(&cfg.interfaces, |_| Err(anyhow!("removed")), absent).is_empty()
        );
    }

    /// A held link comes up only once it carries its hooks and the policy is in
    /// force: bringing it up any earlier is the unfiltered window the hold
    /// exists to close.
    #[test]
    fn a_torn_inventory_keeps_the_last_snapshot_for_a_bounded_number_of_polls() {
        // DP-32: an interrupted dump used to block the datapath on first sight.
        let mut polls = 0;
        for _ in 0..MAX_TORN_INVENTORY_POLLS {
            assert!(keep_last_inventory(true, &mut polls));
        }
        // A host that never settles still fails closed.
        assert!(!keep_last_inventory(true, &mut polls));
        assert!(!keep_last_inventory(true, &mut polls));
        // A real observation failure is never tolerated and resets the count.
        assert!(!keep_last_inventory(false, &mut polls));
        assert_eq!(polls, 0);
        assert!(keep_last_inventory(true, &mut polls));
    }

    #[test]
    fn a_held_link_comes_up_only_attached_and_programmed() {
        let iface = |name: &str, activate: bool| ResolvedInterface {
            name: name.into(),
            policy: 0,
            dhcp_client: false,
            vni: 0,
            masquerade: false,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate,
        };
        let interfaces = [
            iface("lan0", true),
            iface("wan0", true),
            iface("tap0", false),
            iface("up0", true),
        ];
        let down = |name: &str| name != "up0";
        let attached = |name: &str| name != "wan0";
        let anywhere = |_: &str| true;
        assert_eq!(
            links_to_activate(&interfaces, down, attached, anywhere, true),
            vec!["lan0".to_string()],
            "wan0 has no hook yet; tap0 is not held; up0 is up already"
        );
        assert!(
            links_to_activate(&interfaces, down, attached, anywhere, false).is_empty(),
            "a configuration that is not in force must not open a link"
        );
    }

    /// A held link the agent raised and an operator then took down stays down
    /// through every later reconcile; a recreated link (new ifindex) or one
    /// never raised is the agent's to raise.
    #[test]
    fn a_raised_link_taken_down_is_not_raised_again() {
        let raised = BTreeMap::from([("wan0".to_string(), 7)]);
        assert!(raised_here(&raised, "wan0", Some(7)));
        assert!(!raised_here(&raised, "wan0", Some(8)), "recreated link");
        assert!(!raised_here(&raised, "lan0", Some(3)), "never raised");
        assert!(!raised_here(&raised, "wan0", None), "absent link");
    }

    /// On an HA member the guard and the firewall's hooks go on at different
    /// times — the guard first, at load and within one poll of a link being
    /// recreated. A held link HA guards comes up only with both in place: the
    /// guard alone is the unfiltered window, the hooks alone an unfenced one.
    #[test]
    fn a_held_ha_link_comes_up_only_with_the_guard_and_the_hooks() {
        let iface = |name: &str| ResolvedInterface {
            name: name.into(),
            policy: 0,
            dhcp_client: false,
            vni: 0,
            masquerade: false,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate: true,
        };
        let interfaces = [iface("vlan10"), iface("br0")];
        let down = |_: &str| true;
        let guarded = |name: &str| name == "vlan10";
        assert_eq!(
            links_to_activate(&interfaces, down, |_| false, guarded, true),
            Vec::<String>::new(),
            "the HA guard alone must not open a held link"
        );
        assert_eq!(
            links_to_activate(&interfaces, down, |_| true, guarded, true),
            vec!["vlan10".to_string()],
            "br0 is hooked but its guard is not on the current link yet"
        );
    }

    /// A link this process hooked long ago, then disabled by its owner (taken
    /// down, dropped from the configuration while its hook stayed) and enabled
    /// again (held: it stays down). Nothing new is attached, so a held set
    /// filled by new attaches never learned of it and the link stayed dark on
    /// every commit. The configuration and the link's state decide instead.
    #[test]
    fn a_re_enabled_link_hooked_long_ago_is_raised_again() {
        let lan = ResolvedInterface {
            name: "lan0".into(),
            policy: 0,
            dhcp_client: false,
            vni: 0,
            masquerade: false,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate: true,
        };
        assert_eq!(
            links_to_activate(&[lan], |_| true, |_| true, |_| true, true),
            vec!["lan0".to_string()]
        );
    }

    #[test]
    fn local_addresses_are_scoped_to_the_actual_interface() {
        let cfg = serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({
            "interface": [{"name":"wan0", "policy":0, "dhcp_client":true},
                          {"name":"lan0", "policy":0}]
        }))
        .unwrap()
        .resolve()
        .unwrap();
        let keys = local_egress_addresses(
            &cfg.interfaces,
            |name| Ok(if name == "wan0" { 10 } else { 11 }),
            |name| {
                Ok(vec![if name == "wan0" {
                    [198, 18, 88, 100]
                } else {
                    [198, 18, 20, 1]
                }])
            },
        );
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&local_egress_address_key(10, [198, 18, 88, 100])));
        assert!(!keys.contains(&local_egress_address_key(11, [198, 18, 88, 100])));
        assert!(keys.contains(&local_egress_address_key(11, [198, 18, 20, 1])));
        assert!(local_egress_addresses(&cfg.interfaces, |_| Ok(10), |_| Ok(vec![])).is_empty());
    }

    #[test]
    fn local_control_sources_are_distinguished_from_forwarded_nat_clients() {
        let cfg = serde_json::from_value::<velstra_config::FileConfig>(serde_json::json!({
            "interface": [{"name":"wan0", "policy":0, "masquerade":true},
                          {"name":"lan0", "policy":0}]
        }))
        .unwrap()
        .resolve()
        .unwrap();
        let keys = local_egress_addresses(
            &cfg.interfaces,
            |_| Ok(10),
            |_| Ok(vec![[10, 1, 0, 1], [10, 1, 0, 100]]),
        );
        assert!(keys.contains(&local_egress_address_key(10, [10, 1, 0, 1])));
        assert!(keys.contains(&local_egress_address_key(10, [10, 1, 0, 100])));
        assert!(!keys.contains(&local_egress_address_key(10, [10, 2, 0, 10])));
        assert!(!keys.contains(&local_egress_address_key(11, [10, 1, 0, 1])));
    }

    #[test]
    fn raw_ip_kernel_types_do_not_use_ethernet_classification() {
        for kind in [512, 519, 768, 769, 776, 65534] {
            assert!(raw_ip_link(kind));
        }
        for kind in [1, 772] {
            assert!(!raw_ip_link(kind));
        }
    }

    #[test]
    fn interface_lookup_reports_the_kernel_index() {
        let expected: u32 = std::fs::read_to_string("/sys/class/net/lo/ifindex")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(if_nametoindex("lo").unwrap(), expected);
    }

    #[test]
    fn interface_lookup_preserves_a_missing_device_error() {
        let error = if_nametoindex("vs-no-such-if").unwrap_err();
        assert!(interface_missing(
            error.downcast_ref::<std::io::Error>().unwrap()
        ));
    }

    #[test]
    fn interface_lookup_rejects_truncated_or_nul_names() {
        for name in ["", "lo\0other", "0123456789abcdef"] {
            assert!(if_nametoindex(name).is_err(), "accepted {name:?}");
        }
    }

    /// `LOCAL_VNIS` is a tenant-isolation boundary — a VNI left in it lets any
    /// trusted peer VTEP keep injecting frames into a segment this host no longer
    /// serves — so the reconcile has to name every VNI the old config could have
    /// registered, including the routed ones no interface mentions.
    #[test]
    fn admitted_vnis_covers_ports_and_routed_vnis() {
        let mut cfg = RuntimeConfig::passthrough();
        cfg.interfaces.push(ResolvedInterface {
            name: "tap0".into(),
            policy: 100,
            dhcp_client: false,
            vni: 100,
            masquerade: false,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate: false,
        });
        // An uplink with no tenant segment must not register VNI 0.
        cfg.interfaces.push(ResolvedInterface {
            name: "eth0".into(),
            policy: 0,
            dhcp_client: false,
            vni: 0,
            masquerade: true,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate: false,
        });
        cfg.irb_routes.push(ResolvedIrbRoute {
            vni: 100,
            inner_dst: velstra_common::parse_cidr_v4("10.20.0.0/24").unwrap(),
            l3_vni: 50100,
            remote_vtep_ip: [10, 0, 0, 2],
            outer_dst_mac: [0x02, 0, 0, 0, 0, 0x02],
            out_iface: "eth0".into(),
            router_mac: [0x02, 0, 0x5e, 0, 0, 0x01],
            gateway_mac: [0x02, 0, 0x5e, 0, 0, 0xaa],
        });

        let vnis = admitted_vnis(&cfg);
        assert!(vnis.contains(&100), "the port's segment");
        assert!(vnis.contains(&50100), "the tenant's routed VNI");
        assert!(!vnis.contains(&0), "VNI 0 is not a segment");
        assert_eq!(vnis.len(), 2);
    }

    /// A stateful deny-by-default policy has to bring the egress hook with it.
    ///
    /// The ingress hook records a flow when it admits one, so a reply to
    /// something that arrived is covered. A connection the *box* starts never
    /// crosses that hook on the way out — nothing vouches for its reply, and the
    /// default action drops it. On hardware that was DNS, NTP, ACME, the update
    /// channel, webhooks and config-sync all failing while `stateful = true`
    /// claimed otherwise, and nothing in the configuration hinted at why.
    #[test]
    fn a_stateful_deny_by_default_policy_brings_the_egress_hook() {
        let iface = |name: &str, policy: PolicyId| ResolvedInterface {
            name: name.into(),
            policy,
            dhcp_client: false,
            vni: 0,
            masquerade: false,
            snat_address: None,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
            activate: false,
        };
        let policy = |id: PolicyId, action: Action, stateful: bool| PolicyConfig {
            mac_rules: Vec::new(),
            id,
            global: GlobalConfig::new(action, if stateful { ConfigFlags::STATEFUL } else { 0 }),
            portal: None,
            blocklist: Vec::new(),
            blocklist6: Vec::new(),
            port_rules: Vec::new(),
        };

        // Deny by default and stateful: the hook comes along.
        let mut cfg = RuntimeConfig::passthrough();
        cfg.policies = vec![policy(1, Action::Drop, true)];
        cfg.interfaces = vec![iface("eth0", 1)];
        assert_eq!(egress_interfaces(&cfg, &[], false), ["eth0"]);

        // Cloud port policies pass traffic leaving the guest at XDP but
        // default-deny traffic entering it at TC egress. An empty group still
        // needs this hook or its promised ingress isolation disappears.
        cfg.policies = vec![PolicyConfig {
            global: GlobalConfig::new(Action::Pass, ConfigFlags::EGRESS_DEFAULT_DROP),
            ..policy(1, Action::Pass, false)
        }];
        assert_eq!(egress_interfaces(&cfg, &[], false), ["eth0"]);

        // Deny by default but NOT stateful: nothing is tracked, so there is
        // nothing for the hook to record.
        cfg.policies = vec![policy(1, Action::Drop, false)];
        assert!(egress_interfaces(&cfg, &[], false).is_empty());

        // Even a default-pass policy must observe the SYN-ACK to advance its
        // TCP state before the client's ACK arrives at ingress.
        cfg.policies = vec![policy(1, Action::Pass, true)];
        assert_eq!(egress_interfaces(&cfg, &[], false), ["eth0"]);
        cfg.policies = vec![policy(0, Action::Pass, true)];
        cfg.interfaces.clear();
        assert_eq!(egress_interfaces(&cfg, &["wan0".into()], false), ["wan0"]);

        // The other reasons still hold, and a name is listed once however many
        // reasons name it.
        cfg.policies = vec![policy(1, Action::Drop, true)];
        cfg.interfaces = vec![ResolvedInterface {
            masquerade: true,
            snat_address: None,
            ..iface("eth0", 1)
        }];
        assert_eq!(egress_interfaces(&cfg, &["eth0".into()], true), ["eth0"]);
    }

    #[test]
    fn auto_mode_falls_back_driver_then_skb() {
        assert_eq!(
            AttachMode::Auto.candidates(),
            &[XdpMode::Driver, XdpMode::Skb]
        );
        assert_eq!(AttachMode::Skb.candidates(), &[XdpMode::Skb]);
    }

    #[test]
    fn drop_counters_are_classified() {
        assert!(is_drop_counter(Counter::DroppedBlocklist));
        assert!(is_drop_counter(Counter::DroppedIcmp));
        assert!(!is_drop_counter(Counter::PassedDefault));
        assert!(!is_drop_counter(Counter::RxPackets));
    }

    #[test]
    fn stats_render_and_drop_rate() {
        let mut rows = Vec::new();
        for index in 0..Counter::COUNT {
            let counter = Counter::from_u32(index).unwrap();
            let value = match counter {
                Counter::RxPackets => 100,
                Counter::DroppedBlocklist => 25,
                _ => 0,
            };
            rows.push((counter, value));
        }
        let stats = Stats { rows };
        assert_eq!(stats.get(Counter::RxPackets), 100);
        let rendered = stats.render();
        assert!(rendered.contains("dropped_blocklist"));
        assert!(rendered.contains("25.00%"), "drop rate; got:\n{rendered}");
    }

    #[test]
    fn nat_failure_reason_counters_are_visible_without_double_counting_drops() {
        let rows = (0..Counter::COUNT)
            .map(|index| {
                let counter = Counter::from_u32(index).unwrap();
                let value = match counter {
                    Counter::RxPackets => 100,
                    Counter::EgressDropped => 7,
                    Counter::EgressNatNoCandidate => 5,
                    Counter::EgressNatClaimFailed => 2,
                    Counter::FirewallStateWriteFailed => 3,
                    _ => 0,
                };
                (counter, value)
            })
            .collect();
        let stats = Stats { rows };
        assert!(!is_drop_counter(Counter::EgressNatNoCandidate));
        assert!(!is_drop_counter(Counter::EgressNatClaimFailed));
        assert!(!is_drop_counter(Counter::FirewallStateWriteFailed));
        assert_eq!(stats.get(Counter::EgressNatNoCandidate), 5);
        assert_eq!(stats.get(Counter::EgressNatClaimFailed), 2);
        let rendered = stats.render();
        assert!(rendered.contains("egress_nat_no_candidate"));
        assert!(rendered.contains("egress_nat_claim_failed"));
        assert!(rendered.contains("firewall_state_write_failed"));
        assert!(
            rendered.contains("7.00%"),
            "reason counts must not inflate drop rate: {rendered}"
        );
    }
}

/// Write the B13 `PORT_LIMITS` map: ingress ifindex → the port's send ceiling as
/// a byte bucket.
///
/// A port that had a ceiling and no longer does is **removed**, not zeroed: an
/// entry with `rate == 0` allows everything, so either would work, but leaving
/// dead entries behind makes the map's size a function of how often the config
/// changed rather than of how many ports have ceilings.
///
/// The bucket starts full, so a port is not throttled for the first instant
/// after a config apply — a limiter that made the first frames wait would look
/// exactly like packet loss whenever anything was committed.
fn program_port_limits(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    // The loop below clears the ceiling of an interface still in the
    // configuration whose limit was taken away. It cannot see an interface
    // deleted from the configuration outright, which kept its ceiling — hence
    // the reconcile as well.
    let keep: HashSet<u32> = interfaces
        .iter()
        .filter(|i| i.rate_limit_mbit.is_some())
        .filter_map(|i| if_nametoindex(&i.name).ok())
        .collect();
    let mut limits: HashMap<_, u32, RateBucket> = HashMap::try_from(
        ebpf.map_mut("PORT_LIMITS")
            .ok_or_else(|| anyhow!("PORT_LIMITS map missing"))?,
    )?;
    drop_unlisted(&mut limits, &keep)?;
    for iface in interfaces {
        let Ok(ifindex) = if_nametoindex(&iface.name) else {
            // Not present yet — a tap that has not been created. The next apply
            // picks it up; programming a ceiling for an ifindex that does not
            // exist would be a ceiling on whatever gets that number next.
            continue;
        };
        match iface.rate_limit_mbit {
            Some(mbit) => {
                let bucket = port_rate_bucket(mbit);
                limits
                    .insert(ifindex, bucket, 0)
                    .with_context(|| format!("limiting port {} to {mbit} Mbit/s", iface.name))?;
            }
            None => {
                let _ = limits.remove(&ifindex);
            }
        }
    }
    Ok(())
}

/// The byte bucket a megabit ceiling comes to.
///
/// The burst is **one tenth of a second's worth**, floored at a jumbo frame.
/// Both halves matter: a burst smaller than one frame can never pass one, so a
/// ceiling below about 0.7 Mbit would black-hole the port rather than throttle
/// it; and a burst measured in time rather than bytes means the same
/// configuration behaves the same way at 10 Mbit and at 10 Gbit.
fn port_rate_bucket(mbit: u32) -> RateBucket {
    const JUMBO: u32 = 9_216;
    let bytes_per_sec = mbit.saturating_mul(125_000);
    let burst = (bytes_per_sec / 10).max(JUMBO);
    RateBucket::new(bytes_per_sec, burst)
}

#[cfg(test)]
mod port_limit_tests {
    use super::*;

    #[test]
    fn a_megabit_is_a_hundred_and_twenty_five_thousand_bytes() {
        assert_eq!(port_rate_bucket(1).rate, 125_000);
        assert_eq!(port_rate_bucket(1000).rate, 125_000_000);
    }

    #[test]
    fn even_the_smallest_ceiling_can_pass_a_frame() {
        // A burst below one frame is a blackhole, not a limit: the bucket can
        // never hold enough to spend on anything.
        let mut b = port_rate_bucket(1);
        assert!(
            b.take_n(1_000, 9_216),
            "a 1 Mbit port could not pass a jumbo frame"
        );
    }

    #[test]
    fn the_burst_is_a_tenth_of_a_second_once_that_exceeds_a_frame() {
        assert_eq!(port_rate_bucket(1000).burst, 12_500_000);
    }

    #[test]
    fn a_ceiling_actually_bites() {
        // 10 Mbit = 1_250_000 bytes/s, burst 125_000. Spending the burst and one
        // more frame in the same instant must refuse.
        let mut b = port_rate_bucket(10);
        let mut spent = 0;
        while spent < 125_000 {
            assert!(
                b.take_n(1_000, 1_250),
                "the burst refused a frame it could hold"
            );
            spent += 1_250;
        }
        assert!(!b.take_n(1_000, 1_250), "the ceiling did not bite");
    }
}

#[cfg(test)]
mod interface_scoping {
    //! An `in-interface` that does not resolve must not become "every interface".

    use super::*;

    /// The unscoped rule keeps its meaning: no name, index `0`, matches anywhere.
    #[test]
    fn an_unnamed_interface_is_the_unscoped_rule() {
        assert_eq!(rule_ifindex("").expect("the empty name is not an error"), 0);
    }

    /// The loopback exists on every host this ever runs on, so it is the one
    /// name a unit test may resolve for real — and it must not come back as the
    /// unscoped sentinel.
    #[test]
    fn a_real_interface_resolves_to_its_own_index() {
        let idx = rule_ifindex("lo").expect("lo does not resolve on this host");
        assert_ne!(
            idx, 0,
            "a named interface resolved to the any-interface sentinel"
        );
    }

    /// The defect this module exists for. Before the fix this returned `0`, so a
    /// rule scoped to a mistyped interface was applied to every interface —
    /// including the WAN — and the apply reported success.
    #[test]
    fn a_mistyped_interface_is_refused_rather_than_widened() {
        let error =
            rule_ifindex("nosuchif0").expect_err("an interface that does not exist was accepted");
        let text = error.to_string();
        assert!(
            text.contains("nosuchif0"),
            "the refusal must name the interface, got: {text}"
        );
    }
}

#[cfg(test)]
mod every_map_is_reconciled {
    //! A map an apply writes must also be a map an apply can empty.
    //!
    //! On 2026-08-18 `apply_config` wrote 41 maps and `remove_stale` cleared 22.
    //! The 19 in between were write-only, so *removing* something from the
    //! configuration left it in force: an address taken off a port, a port
    //! forward deleted, a MAC quarantine lifted. Every one of those reported a
    //! successful apply, and nothing in the log said otherwise.
    //!
    //! Counting them by hand is what let it drift that far, so this test counts
    //! them from the source. It reads this very file, pairs each map handle a
    //! `program_*` function takes with the reconcile or sweep that covers it, and
    //! fails on anything left over that is not listed below with a reason.
    //!
    //! It is a source-text test rather than a runtime one because programming a
    //! map needs a loaded eBPF object, and therefore root. That would put the
    //! check in the VM suite, where it would run in ten minutes rather than ten
    //! milliseconds — and this defect is about a map somebody *adds*, which is
    //! exactly the moment a fast test earns its place. The VM suite proves the
    //! behaviour; this proves the coverage.

    const SOURCE: &str = include_str!("firewall.rs");

    /// Maps that need no reconcile, each with the reason it does not.
    ///
    /// Everything here is an `Array` or a `DevMap`: fixed-size and index-keyed,
    /// so there is no key to go stale — only a slot that may hold an old value.
    /// A slot is safe when it is either always rewritten, or only ever reached
    /// through a map that *is* reconciled.
    const EXEMPT: &[(&str, &str)] = &[
        (
            "APPLY_STATE",
            "slot zero belongs to the guarded update engine; reopening follows only a complete apply or rollback",
        ),
        (
            "FAIL_CLOSED",
            "slot 0 is written on every apply, including the false default",
        ),
        (
            "SYN_SECRET",
            "a cookie key, not a rule; keeping the installed one across an apply is the point",
        ),
        (
            "OVERLAY_CONFIG",
            "slot 0 is written on every apply — OverlayConfig::DISABLED when no overlay is \
             configured, so turning it off takes effect",
        ),
        (
            "SRV6_CONFIG",
            "slot 0 is written on every apply — Srv6Config::DISABLED when no SRv6 is \
             configured, so turning it off takes effect",
        ),
        (
            "RULE_LIMITS",
            "slot-indexed token buckets, reachable only from a rule that names the slot; the \
             rules are reconciled, so an unreferenced slot is never read",
        ),
        (
            "BACKENDS",
            "slot-indexed backends, reachable only from a service entry carrying the count; the \
             services are rewritten, so a slot past the count is never read",
        ),
        (
            "TX_PORTS",
            "a DevMap of redirect targets keyed by ifindex, reachable only from a route or local \
             MAC that the datapath resolved out of a reconciled or kernel-aged map",
        ),
    ];

    /// Every map name a function takes a handle to, in source order.
    fn handles_in(body: &str) -> Vec<&str> {
        body.match_indices("map_mut(\"")
            .filter_map(|(at, _)| {
                let rest = &body[at + "map_mut(\"".len()..];
                rest.find('"').map(|end| &rest[..end])
            })
            .collect()
    }

    /// The body of every function whose name starts with `prefix`.
    fn bodies(prefix: &str) -> Vec<&'static str> {
        SOURCE
            .match_indices(prefix)
            .filter(|(at, _)| *at == 0 || SOURCE.as_bytes()[at - 1] == b'\n')
            .map(|(at, _)| {
                let rest = &SOURCE[at..];
                // A top-level `}` in the first column closes the function.
                let end = rest.find("\n}\n").map(|e| e + 2).unwrap_or(rest.len());
                &rest[..end]
            })
            .collect()
    }

    #[test]
    fn a_map_an_apply_writes_can_also_be_emptied() {
        let mut written: Vec<&str> = Vec::new();
        let mut covered: Vec<&str> = Vec::new();

        for body in bodies("fn program_") {
            let handles = handles_in(body);
            written.extend(&handles);
            // A handle is reconciled when `drop_unlisted` appears after it and
            // before the next handle is taken — the map is borrowed until then,
            // so no other order is even expressible.
            for (i, name) in handles.iter().enumerate() {
                let from = body.match_indices("map_mut(\"").nth(i).map(|(a, _)| a);
                let to = body
                    .match_indices("map_mut(\"")
                    .nth(i + 1)
                    .map(|(a, _)| a)
                    .unwrap_or(body.len());
                if let Some(from) = from
                    && body[from..to].contains("drop_unlisted")
                {
                    covered.push(name);
                }
            }
        }
        for body in bodies("fn remove_stale") {
            covered.extend(handles_in(body));
        }

        let exempt: Vec<&str> = EXEMPT.iter().map(|(n, _)| *n).collect();
        let mut orphans: Vec<&str> = written
            .iter()
            .filter(|n| !covered.contains(n) && !exempt.contains(n))
            .copied()
            .collect();
        orphans.sort_unstable();
        orphans.dedup();

        assert!(
            orphans.is_empty(),
            "these maps are written by an apply and never emptied by one, so removing the \
             configuration that created their entries leaves those entries in force: {orphans:?}. \
             Reconcile the map with `drop_unlisted`, or add it to EXEMPT with the reason it \
             needs none."
        );
    }

    /// The exempt list is a set of claims, and a claim needs a reason attached.
    #[test]
    fn every_exemption_carries_its_reason() {
        for (name, reason) in EXEMPT {
            assert!(
                reason.len() > 30,
                "{name} is exempt without saying why; the next reader has to re-derive it"
            );
        }
    }
}
