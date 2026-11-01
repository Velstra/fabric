//! Coherent firewall state management through a syscall-only BPF program.
//!
//! No map-value dump or userspace mutex is treated as a protocol-state lock.
//! Maps remain owned by Ebpf (and available for persistent pinning); callers
//! share this handle, which owns only a cloned control program FD. Peer records
//! require authenticated ordering/lifecycle checks BEFORE invoking imports.
use std::{
    fmt,
    os::fd::{AsFd, AsRawFd},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, anyhow, ensure};
use aya::{
    Ebpf,
    maps::Map,
    programs::{ProgramFd, Xdp},
};
use velstra_common::{
    FirewallFlow, FirewallFlowAllocator, FirewallFlowKey, FirewallFlowRecord, FirewallFlowSlot,
    FirewallFlowTransfer, FlowControlMessage as Message, FlowControlOp as Op,
    FlowControlStatus as Status, FlowRecordKind as Kind, FlowTimeouts, FlowVersion,
    firewall_control::FIREWALL_FLOW_CAPACITY,
};

pub type SharedFlowStore = Arc<Mutex<FlowStore>>;

#[derive(Debug)]
pub struct FlowControlError {
    pub status: u32,
}
impl fmt::Display for FlowControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.status {
            Status::MISSING => "firewall flow not found",
            Status::BUSY => "firewall flow is busy; retry observation",
            Status::CONFLICT => "firewall flow changed; reload its current version",
            Status::FULL => "firewall state table is full",
            Status::INVALID => "invalid firewall state request",
            Status::EXHAUSTED => "firewall state version exhausted",
            Status::STORAGE => "firewall state index operation failed",
            Status::CORRUPT => "inconsistent firewall state metadata",
            _ => "invalid firewall control response status",
        })
    }
}
impl std::error::Error for FlowControlError {}

/// All syscalls are bounded to one command, with repeat1 and NO live-frame flag.
/// Callers should run large scans on a blocking worker, never across socket awaits.
pub struct FlowStore {
    control: ProgramFd,
    sequence: u64,
    capacity: u32,
}
impl FlowStore {
    pub fn from_ebpf(ebpf: &mut Ebpf) -> Result<Self> {
        // All four maps form one storage ABI. Validating just the slots could
        // advertise65536 bindings with a smaller index, or bind control to an
        // incompatible allocator/scratch buffer. Reject before program load.
        let specs = [
            (
                "FW_SLOT",
                4,
                core::mem::size_of::<FirewallFlowSlot>() as u32,
                FIREWALL_FLOW_CAPACITY,
            ),
            (
                "FW_ALLOC",
                4,
                core::mem::size_of::<FirewallFlowAllocator>() as u32,
                1,
            ),
            (
                "FW_INDEX",
                core::mem::size_of::<FirewallFlowKey>() as u32,
                core::mem::size_of::<velstra_common::FirewallFlowRef>() as u32,
                FIREWALL_FLOW_CAPACITY,
            ),
            (
                "FW_CTL_BUF",
                4,
                8 + 2 * core::mem::size_of::<Message>() as u32,
                1,
            ),
        ];
        let mut bindings = Vec::with_capacity(specs.len());
        for (name, key_size, value_size, capacity) in specs {
            let data = match (name, ebpf.map(name)) {
                ("FW_SLOT" | "FW_ALLOC", Some(Map::Array(data)))
                | ("FW_INDEX", Some(Map::HashMap(data)))
                | ("FW_CTL_BUF", Some(Map::PerCpuArray(data))) => data,
                _ => return Err(anyhow!("{name} map missing or has an incompatible type")),
            };
            let info = data
                .info()
                .with_context(|| format!("reading {name} map ABI"))?;
            ensure!(
                info.key_size() == key_size
                    && info.value_size() == value_size
                    && info.max_entries() == capacity,
                "incompatible {name} map ABI"
            );
            bindings.push(info.id());
        }
        let program: &mut Xdp = ebpf
            .program_mut("fw_flow_control")
            .context("firewall control entry missing")?
            .try_into()?;
        if program.fd().is_err() {
            program
                .load()
                .context("loading coherent firewall control entry")?;
        }
        let map_ids = program
            .info()?
            .map_ids()?
            .context("kernel cannot verify firewall control map binding")?;
        ensure!(
            bindings.iter().all(|id| map_ids.contains(id)),
            "firewall control entry is not bound to all of this store's maps"
        );
        Ok(Self {
            control: program.fd()?.try_clone()?,
            sequence: 0,
            capacity: FIREWALL_FLOW_CAPACITY,
        })
    }
    pub fn shared(ebpf: &mut Ebpf) -> Result<SharedFlowStore> {
        Ok(Arc::new(Mutex::new(Self::from_ebpf(ebpf)?)))
    }
    pub const fn capacity(&self) -> u32 {
        self.capacity
    }

    fn request(&mut self, operation: u16) -> Result<Message> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .context("firewall control request sequence exhausted")?;
        Ok(Message::new(operation, self.sequence))
    }
    fn execute(&self, request: &Message) -> Result<Message> {
        let input = encode(request);
        let mut output = vec![0u8; input.len()];
        let mut attr = ProgRunAttr {
            prog_fd: self.control.as_fd().as_raw_fd() as u32,
            data_size_in: input.len() as u32,
            data_size_out: output.len() as u32,
            data_in: input.as_ptr() as u64,
            data_out: output.as_mut_ptr() as u64,
            repeat: 1,
            ..ProgRunAttr::default()
        };
        // Linux UAPI BPF_PROG_TEST_RUN=10. All pointers remain valid throughout
        // this synchronous call; no shared output map or packet is involved.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                10u32,
                &mut attr as *mut ProgRunAttr,
                core::mem::size_of::<ProgRunAttr>(),
            )
        };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("executing coherent firewall control request; reload state before retrying a mutation");
        }
        ensure!(
            attr.retval == 2 && attr.data_size_out as usize == output.len(),
            "firewall control request rejected or response truncated"
        );
        let response = decode(&output, request)?;
        if !matches!(response.status, Status::APPLIED | Status::UNCHANGED) {
            return Err(FlowControlError {
                status: response.status,
            }
            .into());
        }
        Ok(response)
    }
    pub fn allocated_slots(&mut self) -> Result<u32> {
        let request = self.request(Op::ALLOCATED_SLOTS)?;
        let count = self.execute(&request)?.record.entry.slot;
        ensure!(
            count <= self.capacity,
            "invalid firewall allocator high-water mark"
        );
        Ok(count)
    }
    pub fn snapshot(&mut self, key: &FirewallFlowKey) -> Result<FirewallFlowRecord> {
        let mut request = self.request(Op::SNAPSHOT)?;
        request.record.key = *key;
        Ok(self.execute(&request)?.record)
    }
    pub fn snapshot_slot(&mut self, index: u32) -> Result<Option<FirewallFlowRecord>> {
        let mut request = self.request(Op::SNAPSHOT_SLOT)?;
        request.record.entry.slot = index;
        match self.execute(&request) {
            Ok(response) => Ok(Some(response.record)),
            Err(error) if status(&error) == Some(Status::MISSING) => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// Enumerate the initialized slot prefix, including holes and retired slots.
    /// Busy/replaced slots and any tail allocated during enumeration are explicit
    /// retry work. This is a sequence of coherent records, not an atomic table
    /// snapshot: policy reconciliation must still quiesce packet writers and
    /// serialize control writers before advertising a completed apply.
    pub fn scan(&mut self) -> Result<FlowScan> {
        scan_initialized(self)
    }
    /// Snapshot age/expiry must be evaluated with the canonical PRIMARY scope's
    /// current timeouts. REMOVE rechecks both alias and primary versions in BPF.
    pub fn remove_if_unchanged(&mut self, record: &FirewallFlowRecord) -> Result<()> {
        self.remove(record, false)
    }
    /// Use for a currently enforced explicit denial; no reliance on idle state.
    pub fn revoke_if_unchanged(&mut self, record: &FirewallFlowRecord) -> Result<()> {
        self.remove(record, true)
    }
    fn remove(&mut self, record: &FirewallFlowRecord, explicit: bool) -> Result<()> {
        let mut request = self.request(if explicit { Op::REVOKE } else { Op::REMOVE })?;
        request.record = *record;
        self.execute(&request)?;
        Ok(())
    }
    /// Import an already authenticated/ordered relative peer record. Supplying
    /// no expected version is NOEXIST, never an unconditional upsert. A different
    /// wire incarnation requires conditional revocation and a fresh creation.
    pub fn import_primary(
        &mut self,
        key: &FirewallFlowKey,
        transfer: FirewallFlowTransfer,
        transit_ms: u32,
        timeouts: FlowTimeouts,
        expected: Option<FlowVersion>,
    ) -> Result<FlowVersion> {
        let state = FirewallFlow::import(
            transfer,
            key.protocol,
            monotonic_ms()?,
            transit_ms,
            timeouts,
        )
        .context("invalid or expired relative firewall state")?;
        self.write_primary(key, state, expected)
    }

    fn write_primary(
        &mut self,
        key: &FirewallFlowKey,
        state: FirewallFlow,
        expected: Option<FlowVersion>,
    ) -> Result<FlowVersion> {
        let mut request = self.request(Op::IMPORT_PRIMARY)?;
        request.record.kind = Kind::PRIMARY;
        request.record.key = *key;
        request.record.state = state;
        if let Some(expected) = expected {
            request.record.entry = expected.entry;
            request.record.revision = expected.revision;
        }
        let response = self.execute(&request)?;
        Ok(response.record.version())
    }

    /// Permanently constrain a coherent PRIMARY snapshot to its current scope's
    /// timeout policy. A later timeout increase or config rollback may not
    /// resurrect expired state or extend an untouched grant's stored deadline.
    ///
    /// Configuration reconciliation must close and drain packet readers AND
    /// serialize other control writers before scanning/constraining the table.
    /// Busy/conflict is a failed apply, never permission to skip a record and
    /// reopen with partially reconciled timeouts. This operation only shortens
    /// deadlines; rollback deliberately does not restore previous longer ones.
    pub fn constrain_timeout(
        &mut self,
        record: &FirewallFlowRecord,
        timeouts: FlowTimeouts,
    ) -> Result<TimeoutChange> {
        match timeout_change(record, timeouts, monotonic_ms()?)? {
            PreparedTimeout::Keep => {
                let actual = self.snapshot(&record.key)?;
                if actual.version() != record.version() {
                    return Err(FlowControlError {
                        status: Status::CONFLICT,
                    }
                    .into());
                }
                Ok(TimeoutChange::Unchanged(actual.version()))
            }
            PreparedTimeout::Remove => {
                self.remove_if_unchanged(record)?;
                Ok(TimeoutChange::Removed)
            }
            PreparedTimeout::Replace(state) => {
                // Both timestamps are LOCAL and copied under the slot lock.
                // A relative export/import here would shift the deadline by
                // userspace processing time on every repeated reconciliation.
                match self.write_primary(&record.key, state, Some(record.version())) {
                    Ok(version) => Ok(TimeoutChange::Shortened(version)),
                    Err(error)
                        if status(&error) == Some(Status::INVALID)
                            && state.expires_at_ms <= monotonic_ms()? =>
                    {
                        // The shortened deadline elapsed between preparation
                        // and BPF execution. Still compare the original version.
                        self.remove_if_unchanged(record)?;
                        Ok(TimeoutChange::Removed)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }
    pub fn import_alias(
        &mut self,
        key: &FirewallFlowKey,
        primary_key: &FirewallFlowKey,
        wire_incarnation: u64,
        flip: bool,
        expected: Option<FlowVersion>,
    ) -> Result<FlowVersion> {
        let mut request = self.request(Op::IMPORT_ALIAS)?;
        request.record.kind = Kind::ALIAS;
        request.record.key = *key;
        request.record.primary_key = *primary_key;
        request.record.flip = flip as u32;
        request.wire_incarnation = wire_incarnation;
        if let Some(expected) = expected {
            request.record.entry = expected.entry;
            request.record.revision = expected.revision;
        }
        let response = self.execute(&request)?;
        Ok(response.record.version())
    }
    pub fn reclaim_retired(&mut self, index: u32) -> Result<bool> {
        let mut request = self.request(Op::RECLAIM)?;
        request.record.entry.slot = index;
        Ok(self.execute(&request)?.status == Status::APPLIED)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutChange {
    Unchanged(FlowVersion),
    Shortened(FlowVersion),
    Removed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedTimeout {
    Keep,
    Remove,
    Replace(FirewallFlow),
}
fn timeout_change(
    record: &FirewallFlowRecord,
    timeouts: FlowTimeouts,
    now_ms: u64,
) -> Result<PreparedTimeout> {
    ensure!(
        timeouts.valid()
            && record.kind == Kind::PRIMARY
            && record.key.valid()
            && record.primary_key == record.key
            && record.entry == record.primary
            && record.entry.incarnation != 0
            && record.entry._pad == 0
            && record.revision != 0
            && record.primary_revision == record.revision
            && record.flip == 0
            && record.reserved == 0
            && record.state.valid_for(record.key.protocol),
        "timeout reconciliation requires a valid primary snapshot and timeout policy"
    );
    ensure!(
        now_ms >= record.state.last_seen_ms,
        "timeout snapshot is newer than the local clock"
    );
    let Some(relative) = record.state.export(record.key.protocol, now_ms, timeouts) else {
        return Ok(PreparedTimeout::Remove);
    };
    let deadline = now_ms
        .checked_add(relative.remaining_ms as u64)
        .context("firewall deadline overflow")?;
    ensure!(
        deadline <= record.state.expires_at_ms,
        "timeout reconciliation attempted to extend a deadline"
    );
    if deadline == record.state.expires_at_ms {
        return Ok(PreparedTimeout::Keep);
    }
    let mut state = record.state;
    state.expires_at_ms = deadline;
    Ok(PreparedTimeout::Replace(state))
}
pub struct FlowScan {
    pub records: Vec<FirewallFlowRecord>,
    pub retry_slots: Vec<u32>,
    /// Slots actually visited; never the configured table capacity by default.
    pub scanned_slots: u32,
    /// Monotone allocator extent observed after the scan, including its holes.
    pub initialized_slots: u32,
}
trait ScanSource {
    fn capacity(&self) -> u32;
    fn extent(&mut self) -> Result<u32>;
    fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>>;
}
impl ScanSource for FlowStore {
    fn capacity(&self) -> u32 {
        self.capacity()
    }
    fn extent(&mut self) -> Result<u32> {
        self.allocated_slots()
    }
    fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>> {
        self.snapshot_slot(slot)
    }
}
fn scan_initialized(source: &mut impl ScanSource) -> Result<FlowScan> {
    let initial = source
        .extent()
        .context("reading firewall allocator before scan")?;
    ensure!(
        initial <= source.capacity(),
        "firewall allocator exceeds table capacity"
    );
    let mut scan = FlowScan {
        records: Vec::new(),
        retry_slots: Vec::new(),
        scanned_slots: initial,
        initialized_slots: initial,
    };
    for slot in 0..initial {
        match source.snapshot(slot) {
            Ok(Some(record)) => scan.records.push(record),
            Ok(None) => {}
            Err(error) if matches!(status(&error), Some(Status::BUSY | Status::CONFLICT)) => {
                scan.retry_slots.push(slot);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("scanning firewall slot {slot}"));
            }
        }
    }
    let final_extent = source
        .extent()
        .context("reading firewall allocator after scan")?;
    ensure!(
        final_extent <= source.capacity(),
        "firewall allocator exceeds table capacity"
    );
    ensure!(
        final_extent >= initial,
        "firewall allocator regressed during scan"
    );
    // Do not chase an attacker-controlled stream of new allocations. Report the
    // unvisited tail exactly once. The caller must close/drain readers before
    // retrying a security-sensitive policy transition, as before this optimization.
    scan.retry_slots.extend(initial..final_extent);
    scan.initialized_slots = final_extent;
    Ok(scan)
}
pub fn status(error: &anyhow::Error) -> Option<u32> {
    error
        .downcast_ref::<FlowControlError>()
        .map(|error| error.status)
}

/// Same local monotonic epoch as bpf_ktime_get_ns, never a peer's absolute clock.
pub fn monotonic_ms() -> Result<u64> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let result = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("reading local monotonic clock");
    }
    ensure!(
        clock.tv_sec >= 0 && (0..1_000_000_000).contains(&clock.tv_nsec),
        "invalid local monotonic clock"
    );
    (clock.tv_sec as u64)
        .checked_mul(1000)
        .and_then(|n| n.checked_add(clock.tv_nsec as u64 / 1_000_000))
        .context("local monotonic clock overflow")
}
fn encode(message: &Message) -> Vec<u8> {
    let mut bytes = vec![0u8; Message::PREFIX_LEN + core::mem::size_of::<Message>()];
    bytes[12..14].copy_from_slice(&[0x88, 0xb5]);
    // Pod consists entirely of initialized integer fields with explicit padding.
    let input = unsafe {
        core::slice::from_raw_parts(
            (message as *const Message).cast::<u8>(),
            core::mem::size_of::<Message>(),
        )
    };
    bytes[Message::PREFIX_LEN..].copy_from_slice(input);
    bytes
}
fn decode(bytes: &[u8], request: &Message) -> Result<Message> {
    ensure!(
        bytes.len() == Message::PREFIX_LEN + core::mem::size_of::<Message>(),
        "invalid firewall control response size"
    );
    let response = unsafe {
        core::ptr::read_unaligned(bytes[Message::PREFIX_LEN..].as_ptr().cast::<Message>())
    };
    ensure!(
        response.magic == Message::MAGIC
            && response.version == Message::VERSION
            && response.request_id == request.request_id
            && response.operation == request.operation
            && response.reserved == 0
            && response.record.reserved == 0
            && response.status != Status::PENDING,
        "invalid or mismatched firewall control response"
    );
    Ok(response)
}
#[repr(C)]
#[derive(Default)]
struct ProgRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    pad: u32,
}
#[cfg(test)]
mod tests {
    use velstra_common::{FlowDirection, FlowPacket, FlowScope, ip_proto};

    use super::*;

    #[derive(Default)]
    struct ScanFixture {
        extents: std::collections::VecDeque<Result<u32>>,
        records: std::collections::BTreeMap<u32, FirewallFlowRecord>,
        errors: std::collections::BTreeMap<u32, u32>,
        visited: Vec<u32>,
    }
    impl ScanSource for ScanFixture {
        fn capacity(&self) -> u32 {
            65536
        }
        fn extent(&mut self) -> Result<u32> {
            self.extents.pop_front().expect("unexpected allocator read")
        }
        fn snapshot(&mut self, slot: u32) -> Result<Option<FirewallFlowRecord>> {
            self.visited.push(slot);
            if let Some(status) = self.errors.get(&slot) {
                return Err(FlowControlError { status: *status }.into());
            }
            Ok(self.records.get(&slot).copied())
        }
    }
    fn scan_fixture(initial: u32, final_extent: u32) -> ScanFixture {
        ScanFixture {
            extents: [Ok(initial), Ok(final_extent)].into(),
            ..ScanFixture::default()
        }
    }
    #[test]
    fn empty_initialized_scan_does_not_visit_unused_slots() {
        let mut store = scan_fixture(0, 0);
        let scan = scan_initialized(&mut store).unwrap();
        assert!(scan.records.is_empty() && scan.retry_slots.is_empty());
        assert!(store.visited.is_empty());
        assert_eq!((scan.scanned_slots, scan.initialized_slots), (0, 0));
        assert!(store.extents.is_empty());
    }
    #[test]
    fn sparse_initialized_scan_keeps_holes_and_last_slot() {
        let mut store = scan_fixture(8, 8);
        store.records.insert(7, udp_record());
        let scan = scan_initialized(&mut store).unwrap();
        assert_eq!(store.visited, (0..8).collect::<Vec<_>>());
        assert_eq!(scan.records.len(), 1);
        assert!(scan.retry_slots.is_empty());
        assert_eq!((scan.scanned_slots, scan.initialized_slots), (8, 8));
    }
    #[test]
    fn allocation_during_empty_scan_is_explicit_retry_work() {
        let mut store = scan_fixture(0, 3);
        let scan = scan_initialized(&mut store).unwrap();
        assert!(store.visited.is_empty());
        assert_eq!(scan.retry_slots, [0, 1, 2]);
        assert_eq!((scan.scanned_slots, scan.initialized_slots), (0, 3));
    }
    #[test]
    fn busy_slots_and_new_allocations_are_not_a_complete_scan() {
        let mut store = scan_fixture(3, 5);
        store.errors.insert(0, Status::BUSY);
        store.errors.insert(1, Status::CONFLICT);
        store.records.insert(2, udp_record());
        let scan = scan_initialized(&mut store).unwrap();
        assert_eq!(store.visited, [0, 1, 2]);
        assert_eq!(scan.records.len(), 1);
        assert_eq!(scan.retry_slots, [0, 1, 3, 4]);
        assert_eq!((scan.scanned_slots, scan.initialized_slots), (3, 5));
    }
    #[test]
    fn invalid_or_regressing_allocator_extent_fails_closed() {
        for (initial, end) in [(65537, 65537), (1, 65537), (2, 1)] {
            assert!(scan_initialized(&mut scan_fixture(initial, end)).is_err());
        }
    }
    #[test]
    fn allocator_failure_before_or_after_scan_is_never_an_empty_success() {
        for extents in [
            vec![Err(FlowControlError {
                status: Status::BUSY,
            }
            .into())],
            vec![
                Ok(0),
                Err(FlowControlError {
                    status: Status::BUSY,
                }
                .into()),
            ],
        ] {
            let error = scan_initialized(&mut ScanFixture {
                extents: extents.into(),
                ..ScanFixture::default()
            })
            .err()
            .unwrap();
            assert_eq!(status(&error), Some(Status::BUSY));
        }
    }
    #[test]
    fn fatal_snapshot_failure_cannot_publish_partial_results() {
        let mut store = scan_fixture(3, 3);
        store.records.insert(0, udp_record());
        store.errors.insert(1, Status::STORAGE);
        let error = scan_initialized(&mut store).err().unwrap();
        assert_eq!(status(&error), Some(Status::STORAGE));
        assert!(format!("{error:#}").contains("scanning firewall slot 1"));
        assert_eq!(store.visited, [0, 1]);
    }
    #[test]
    fn full_initialized_scan_includes_capacity_boundary() {
        let mut store = scan_fixture(65536, 65536);
        store.records.insert(65535, udp_record());
        let scan = scan_initialized(&mut store).unwrap();
        assert_eq!(store.visited.len(), 65536);
        assert_eq!(store.visited.last(), Some(&65535));
        assert_eq!(scan.scanned_slots, 65536);
        assert_eq!(scan.records.len(), 1);
        assert!(scan.retry_slots.is_empty());
    }

    fn timeout_record(state: FirewallFlow) -> FirewallFlowRecord {
        let key = FirewallFlowKey::transport_v4(
            FlowScope {
                identity: 9,
                generation: 11,
            },
            [10, 0, 0, 1],
            [198, 51, 100, 1],
            1234,
            53,
            ip_proto::UDP,
        )
        .unwrap()
        .0;
        let mut record = FirewallFlowRecord::EMPTY;
        record.kind = Kind::PRIMARY;
        record.key = key;
        record.primary_key = key;
        record.entry.incarnation = 13;
        record.primary = record.entry;
        record.revision = 17;
        record.primary_revision = 17;
        record.state = state;
        record
    }
    fn udp_record() -> FirewallFlowRecord {
        timeout_record(
            FirewallFlow::begin(
                FlowPacket::Udp,
                FlowDirection::Forward,
                100,
                19,
                FlowTimeouts::DEFAULT,
            )
            .unwrap(),
        )
    }
    #[test]
    fn timeout_shrink_persists_exact_deadline_across_grow_and_repeated_apply() {
        let mut record = udp_record();
        let short = FlowTimeouts {
            udp_unreplied_ms: 5_000,
            ..FlowTimeouts::DEFAULT
        };
        let PreparedTimeout::Replace(state) = timeout_change(&record, short, 1_000).unwrap() else {
            panic!("shorter timeout was not applied");
        };
        assert_eq!(state.last_seen_ms, 100);
        assert_eq!(state.expires_at_ms, 5_100);
        record.state = state;
        assert_eq!(
            timeout_change(&record, short, 2_000).unwrap(),
            PreparedTimeout::Keep
        );
        assert_eq!(
            timeout_change(&record, FlowTimeouts::DEFAULT, 2_000).unwrap(),
            PreparedTimeout::Keep
        );
        assert_eq!(
            timeout_change(&record, FlowTimeouts::DEFAULT, 5_100).unwrap(),
            PreparedTimeout::Remove
        );
    }
    #[test]
    fn applied_timeout_shrink_removes_expired_grants_instead_of_reviving_them() {
        let record = udp_record();
        let short = FlowTimeouts {
            udp_unreplied_ms: 5_000,
            ..FlowTimeouts::DEFAULT
        };
        // Reproduces why checking only the current effective expiry is wrong:
        // shrink says expired, then grow would expose the old stored grant.
        assert!(record.state.export(ip_proto::UDP, 10_000, short).is_none());
        assert!(
            record
                .state
                .export(ip_proto::UDP, 10_000, FlowTimeouts::DEFAULT)
                .is_some()
        );
        assert_eq!(
            timeout_change(&record, short, 10_000).unwrap(),
            PreparedTimeout::Remove
        );
    }
    #[test]
    fn timeout_reconciliation_preserves_preboot_idle_age() {
        let original = udp_record();
        let relative = original
            .state
            .export(ip_proto::UDP, 10_000, FlowTimeouts::DEFAULT)
            .unwrap();
        let imported =
            FirewallFlow::import(relative, ip_proto::UDP, 100, 0, FlowTimeouts::DEFAULT).unwrap();
        let record = timeout_record(imported);
        let short = FlowTimeouts {
            udp_unreplied_ms: 5_000,
            ..FlowTimeouts::DEFAULT
        };
        assert_eq!(
            timeout_change(&record, short, 100).unwrap(),
            PreparedTimeout::Remove
        );
        let medium = FlowTimeouts {
            udp_unreplied_ms: 15_000,
            ..FlowTimeouts::DEFAULT
        };
        let PreparedTimeout::Replace(state) = timeout_change(&record, medium, 100).unwrap() else {
            panic!("preboot idle deadline was not shortened");
        };
        assert_eq!(state.expires_at_ms, 5_200);
        assert_eq!(
            state.export(ip_proto::UDP, 100, medium).unwrap().idle_ms,
            relative.idle_ms
        );
    }
    #[test]
    fn timeout_reconciliation_rejects_invalid_policy_and_nonprimary_snapshots() {
        let mut record = udp_record();
        let bad = FlowTimeouts {
            udp_unreplied_ms: 0,
            ..FlowTimeouts::DEFAULT
        };
        assert!(timeout_change(&record, bad, 1_000).is_err());
        assert!(timeout_change(&record, FlowTimeouts::DEFAULT, 99).is_err());
        record.kind = Kind::ALIAS;
        assert!(timeout_change(&record, FlowTimeouts::DEFAULT, 1_000).is_err());
        record.kind = Kind::PRIMARY;
        record.primary_revision += 1;
        assert!(timeout_change(&record, FlowTimeouts::DEFAULT, 1_000).is_err());
    }
    #[test]
    fn syscall_layout_and_response_correlation() {
        assert_eq!(core::mem::size_of::<ProgRunAttr>(), 80);
        assert_eq!(core::mem::offset_of!(ProgRunAttr, repeat), 32);
        assert_eq!(core::mem::offset_of!(ProgRunAttr, ctx_in), 48);
        assert_eq!(core::mem::offset_of!(ProgRunAttr, flags), 64);
        let request = Message::new(Op::SNAPSHOT, 42);
        assert!(decode(&encode(&request), &request).is_err());
        let mut response = request;
        response.status = Status::APPLIED;
        assert_eq!(decode(&encode(&response), &request).unwrap(), response);
        response.request_id += 1;
        assert!(decode(&encode(&response), &request).is_err());
    }
    #[test]
    fn local_clock_has_one_monotonic_epoch() {
        let before = monotonic_ms().unwrap();
        let after = monotonic_ms().unwrap();
        assert!(after >= before);
    }
}
