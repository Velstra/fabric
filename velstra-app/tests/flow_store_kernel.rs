//! Real kernel qualification of the local Rust API and actual BPF control entry.
//! Run by the Nix VM check. It deliberately uses no raw protocol-value map dumps
//! or overwrites; only the explicit quiescent held-lock fixture touches a buffer.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    programs::{TestRun, TestRunOptions, Xdp},
};
use velstra::flow_store::{FlowStore, TimeoutChange, monotonic_ms, status};
use velstra_common::{
    FirewallFlow, FirewallFlowKey, FirewallFlowRecord, FlowControlStatus as Status, FlowDirection,
    FlowPacket, FlowRecordKind as Kind, FlowScope, FlowTimeouts, ip_proto,
};
const T: FlowTimeouts = FlowTimeouts::DEFAULT;

#[test]
#[ignore = "requires bpffs, packaged ELF and CAP_BPF; executed by the privileged Nix check"]
fn native_policy_scope_lifecycle_and_restart() -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    use velstra::flow_scopes::{ScopeCatalogue, install_views, reconcile_store};
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("missing packaged object")?,
    );
    let root = PathBuf::from(format!("/sys/fs/bpf/native-scopes-{}", std::process::id()));
    std::fs::DirBuilder::new().mode(0o700).create(&root)?;
    let load = || -> Result<Ebpf> {
        let mut loader = aya::EbpfLoader::new();
        for (name, path) in [
            ("FW_SLOT", "slots"),
            ("FW_INDEX", "index"),
            ("FW_ALLOC", "allocator"),
            ("FW_SCOPE_META", "metadata"),
            ("FW_LABELS", "labels"),
            ("FW_POLICY", "policies"),
            ("FW_TIMEOUT", "timeouts"),
        ] {
            loader.map_pin_path(name, root.join(path));
        }
        Ok(loader.load_file(&object)?)
    };
    let cfg = |bindings: &[(u32, &str)]| -> Result<velstra_config::RuntimeConfig> {
        let policies: Vec<_> = bindings
            .iter()
            .map(|(id, label)| serde_json::json!({"id":id,"state_scope":label,"stateful":true}))
            .collect();
        serde_json::from_value::<velstra_config::FileConfig>(
            serde_json::json!({"policy":policies}),
        )?
        .resolve()
    };
    let original = cfg(&[(1, "zone/b")])?;
    let moved = cfg(&[(1, "zone/a"), (2, "zone/b")])?;
    let deleted = cfg(&[(1, "zone/a")])?;
    let mut ebpf = load()?;
    let mut catalogue = ScopeCatalogue::open(&mut ebpf)?;
    let first = catalogue.prepare(&original.policies)?;
    install_views(&mut ebpf, &first)?;
    catalogue.commit(&first)?;
    let b = first.scope(1).unwrap();
    let mut store = FlowStore::from_ebpf(&mut ebpf)?;
    let mut primary = key(123);
    primary.scope = b;
    let wire = FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 0, 77, T)
        .unwrap()
        .export(ip_proto::UDP, 0, T)
        .unwrap();
    store.import_primary(&primary, wire, 0, T, None)?;
    let retained = store.snapshot(&primary)?;
    let next = catalogue.prepare(&moved.policies)?;
    ensure!(next.scope(2) == Some(b) && next.scope(1) != Some(b));
    install_views(&mut ebpf, &next)?;
    reconcile_store(&mut store, &next)?;
    catalogue.commit(&next)?;
    ensure!(store.snapshot(&primary)? == retained);
    {
        let map: aya::maps::HashMap<_, u32, FlowScope> =
            aya::maps::HashMap::try_from(ebpf.map("FW_POLICY").unwrap())?;
        ensure!(map.get(&2, 0)? == b && map.get(&1, 0)? == next.scope(1).unwrap());
    }
    let mut alias = key(124);
    alias.scope = next.scope(1).unwrap();
    store.import_alias(&alias, &primary, 77, false, None)?;
    drop(store);
    drop(catalogue);
    drop(ebpf);
    let mut ebpf = load()?;
    let mut catalogue = ScopeCatalogue::open(&mut ebpf)?;
    let restarted = catalogue.prepare(&moved.policies)?;
    ensure!(restarted == next);
    let mut store = FlowStore::from_ebpf(&mut ebpf)?;
    ensure!(store.snapshot(&primary)? == retained);
    ensure!(store.snapshot(&alias)?.kind == Kind::ALIAS);
    let removed = catalogue.prepare(&deleted.policies)?;
    install_views(&mut ebpf, &removed)?;
    reconcile_store(&mut store, &removed)?;
    catalogue.commit(&removed)?;
    same_status(store.snapshot(&primary), Status::MISSING);
    same_status(store.snapshot(&alias), Status::MISSING);
    let recreated = catalogue.prepare(&moved.policies)?;
    ensure!(recreated.scope(2).unwrap() != b && recreated.scope(2).unwrap().identity > b.identity);
    install_views(&mut ebpf, &recreated)?;
    reconcile_store(&mut store, &recreated)?;
    catalogue.commit(&recreated)?;
    let with_c = cfg(&[(1, "zone/a"), (2, "zone/b"), (3, "zone/c")])?;
    let abandoned = catalogue.prepare(&with_c.policies)?;
    drop(store);
    drop(catalogue);
    drop(ebpf);
    let mut ebpf = load()?;
    let mut catalogue = ScopeCatalogue::open(&mut ebpf)?;
    let retried = catalogue.prepare(&with_c.policies)?;
    ensure!(retried.scope(3).unwrap().identity > abandoned.scope(3).unwrap().identity);
    drop(catalogue);
    drop(ebpf);
    for item in std::fs::read_dir(&root)? {
        std::fs::remove_file(item?.path())?;
    }
    std::fs::remove_dir(root)?;
    println!(
        "ACTUAL_POLICY_SCOPE_LIFECYCLE {}",
        serde_json::json!({"result":"PASS","renumber":true,"restart":true,"recreate":true,"aliasesRevoked":true,"reservationSurvivesRestart":true})
    );
    Ok(())
}

struct CapturedFlow {
    name: &'static str,
    family: u8,
    packets: &'static [(u64, &'static str)],
}
include!("../../velstra-common/src/firewall_capture_fixture.rs");

#[test]
#[ignore = "requires the packaged production ELF and CAP_BPF; executed by the privileged Nix check"]
fn native_flow_store_rejects_incompatible_maps() -> Result<()> {
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT")
            .context("missing packaged datapath object")?,
    );
    for (name, entries) in [
        ("FW_SLOT", 65535),
        ("FW_INDEX", 65535),
        ("FW_ALLOC", 2),
        ("FW_CTL_BUF", 2),
    ] {
        let mut loader = aya::EbpfLoader::new();
        loader.map_max_entries(name, entries);
        let mut ebpf = loader.load_file(&object)?;
        ensure!(
            FlowStore::from_ebpf(&mut ebpf).is_err(),
            "incompatible {name} map capacity was accepted"
        );
        let program: &Xdp = ebpf.program("fw_flow_control").unwrap().try_into()?;
        ensure!(
            program.fd().is_err(),
            "control loaded before its map ABI was validated"
        );
    }
    println!(
        "ACTUAL_PACKAGED_FLOW_SCHEMA {}",
        serde_json::json!({"result":"PASS","rejectedMaps":4})
    );
    Ok(())
}

/// Exercise the same native controller against the complete, packaged datapath
/// rather than the packet-writer component harness. Its program/map ownership
/// and verifier acceptance must agree with the object the real agent embeds.
#[test]
#[ignore = "requires the packaged production ELF and CAP_BPF; executed by the privileged Nix check"]
fn native_flow_store_in_packaged_datapath() -> Result<()> {
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT")
            .context("missing packaged datapath object")?,
    );
    let mut ebpf = Ebpf::load_file(object)?;
    for name in [
        "velstra",
        "velstra_main",
        "velstra_ipv6",
        "velstra_guest_ipv6",
        "velstra_state_v6",
        "velstra_guest_delivery",
        "velstra_forward",
        "velstra_egress",
        "velstra_bum",
    ] {
        ensure!(
            ebpf.program(name).is_some(),
            "production program {name} missing"
        );
    }
    // Loading only the syscall control entry misses BTF failures that break
    // tail calls in the real packet programs. Verify the complete packaged
    // packet entries without attaching them to any host interface.
    for name in [
        "velstra",
        "velstra_main",
        "velstra_ipv6",
        "velstra_guest_ipv6",
        "velstra_state_v6",
        "velstra_guest_delivery",
        "velstra_forward",
    ] {
        let program: &mut Xdp = ebpf.program_mut(name).unwrap().try_into()?;
        program
            .load()
            .with_context(|| format!("verifying {name}"))?;
        ensure!(program.info()?.btf_id().is_some(), "{name} lost BTF");
    }
    for name in ["velstra_egress", "velstra_state_tc6", "velstra_bum"] {
        let program: &mut aya::programs::SchedClassifier =
            ebpf.program_mut(name).unwrap().try_into()?;
        program
            .load()
            .with_context(|| format!("verifying {name}"))?;
        ensure!(program.info()?.btf_id().is_some(), "{name} lost BTF");
    }
    let first = FlowStore::shared(&mut ebpf)?;
    let second = first.clone();
    let initial = seed(&mut first.lock().unwrap(), 123, 991)?;
    let short = FlowTimeouts {
        udp_unreplied_ms: 5_000,
        ..T
    };
    {
        let mut store = second.lock().unwrap();
        ensure!(matches!(
            store.constrain_timeout(&initial, short)?,
            TimeoutChange::Shortened(_)
        ));
        store.import_alias(&key(124), &key(123), 991, false, None)?;
        let alias = store.snapshot(&key(124))?;
        ensure!(alias.kind == Kind::ALIAS && alias.primary == initial.entry);
    }
    drop(ebpf);
    drop(first);
    let mut store = second.lock().unwrap();
    let current = store.snapshot(&key(123))?;
    ensure!(current.state.expires_at_ms == initial.state.last_seen_ms + 5_000);
    store.revoke_if_unchanged(&current)?;
    ensure!(store.snapshot(&key(124))?.kind == Kind::ORPHAN_ALIAS);
    let orphan = store.snapshot(&key(124))?;
    store.revoke_if_unchanged(&orphan)?;

    // Exact capacity of the ACTUAL packaged168-byte slot table. All bindings
    // are live; no timer, LRU eviction or GC may disguise a missing final slot.
    let limits = FlowTimeouts {
        udp_unreplied_ms: velstra_common::MAX_FLOW_TIMEOUT_MS,
        ..T
    };
    let mut wire = FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 0, 1, limits)
        .unwrap()
        .export(ip_proto::UDP, 0, limits)
        .unwrap();
    for index in 0..store.capacity() {
        wire.incarnation = 1000 + index as u64;
        store.import_primary(&capacity_key(index), wire, 0, limits, None)?;
    }
    same_status(
        store.import_primary(&key(125), wire, 0, limits, None),
        Status::FULL,
    );
    let retired = store.snapshot(&capacity_key(32768))?;
    store.revoke_if_unchanged(&retired)?;
    let fresh = store.import_primary(&key(125), wire, 0, limits, None)?;
    ensure!(
        fresh.entry.slot == retired.entry.slot
            && fresh.entry.incarnation > retired.entry.incarnation
    );
    same_status(store.remove_if_unchanged(&retired), Status::CONFLICT);
    let full = store.scan()?;
    ensure!(full.scanned_slots == 65536 && full.initialized_slots == 65536);
    ensure!(full.records.len() == 65536 && full.retry_slots.is_empty());
    ensure!(
        full.records.iter().any(|r| r.entry.slot == 65535),
        "last slot omitted"
    );
    println!(
        "ACTUAL_PACKAGED_FLOW_CONTROL {}",
        serde_json::json!({"result":"PASS","capacity":store.capacity(),"sharedOwnership":true,"conditionalTimeout":true,"aliasRevocation":true,"fullCapacity":65536,"fullScan":true,"overflowRejected":true,"slotReuse":true})
    );
    Ok(())
}

fn capacity_key(index: u32) -> FirewallFlowKey {
    FirewallFlowKey::transport_v4(
        FlowScope {
            identity: 701,
            generation: 901,
        },
        [10, 0, (index >> 8) as u8, index as u8],
        [198, 51, 100, 2],
        1234,
        443,
        ip_proto::UDP,
    )
    .unwrap()
    .0
}

fn key(port: u16) -> FirewallFlowKey {
    FirewallFlowKey::transport_v4(
        FlowScope {
            identity: 700,
            generation: 900,
        },
        [10, 0, 0, 1],
        [198, 51, 100, 2],
        port,
        443,
        ip_proto::UDP,
    )
    .unwrap()
    .0
}
fn tcp_key(frame: &[u8]) -> FirewallFlowKey {
    if frame[12..14] == [8, 0] {
        let off = 14 + (frame[14] & 15) as usize * 4;
        FirewallFlowKey::transport_v4(
            FlowScope {
                identity: 7,
                generation: 19,
            },
            frame[26..30].try_into().unwrap(),
            frame[30..34].try_into().unwrap(),
            u16::from_be_bytes(frame[off..off + 2].try_into().unwrap()),
            u16::from_be_bytes(frame[off + 2..off + 4].try_into().unwrap()),
            ip_proto::TCP,
        )
        .unwrap()
        .0
    } else {
        FirewallFlowKey::transport_v6(
            FlowScope {
                identity: 7,
                generation: 19,
            },
            frame[22..38].try_into().unwrap(),
            frame[38..54].try_into().unwrap(),
            u16::from_be_bytes(frame[54..56].try_into().unwrap()),
            u16::from_be_bytes(frame[56..58].try_into().unwrap()),
            ip_proto::TCP,
        )
        .unwrap()
        .0
    }
}
fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn frame(ebpf: &Ebpf, data: &[u8]) -> Result<u32> {
    let program: &Xdp = ebpf
        .program("rust_cas_probe")
        .context("packet writer entry")?
        .try_into()?;
    Ok(program
        .test_run(TestRunOptions {
            data_in: Some(data),
            ..TestRunOptions::new()
        })?
        .return_value)
}
fn same_status<T: std::fmt::Debug>(result: Result<T>, expected: u32) {
    let error = result.unwrap_err();
    assert_eq!(status(&error), Some(expected), "{error:#}");
}
fn seed(store: &mut FlowStore, port: u16, inc: u64) -> Result<FirewallFlowRecord> {
    let original =
        FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 100, inc, T).unwrap();
    let transfer = original.export(ip_proto::UDP, 100, T).unwrap();
    store.import_primary(&key(port), transfer, 0, T, None)?;
    store.snapshot(&key(port))
}

fn allowed_cpus() -> Result<Vec<usize>> {
    let mut set = unsafe { core::mem::zeroed::<libc::cpu_set_t>() };
    ensure!(
        unsafe { libc::sched_getaffinity(0, core::mem::size_of_val(&set), &mut set) } == 0,
        "reading CPU affinity failed"
    );
    Ok((0..libc::CPU_SETSIZE as usize)
        .filter(|cpu| unsafe { libc::CPU_ISSET(*cpu, &set) })
        .collect())
}
fn pin_cpu(cpu: usize) -> Result<()> {
    let mut set = unsafe { core::mem::zeroed::<libc::cpu_set_t>() };
    unsafe {
        libc::CPU_SET(cpu, &mut set);
    }
    ensure!(
        unsafe { libc::sched_setaffinity(0, core::mem::size_of_val(&set), &set) } == 0,
        "pinning CPU failed"
    );
    Ok(())
}
fn stats(ebpf: &mut Ebpf) -> Result<[u64; 10]> {
    let map: aya::maps::PerCpuArray<_, u64> =
        aya::maps::PerCpuArray::try_from(ebpf.map_mut("PSTATS").context("packet counters")?)?;
    let mut values = [0; 10];
    for (i, value) in values.iter_mut().enumerate() {
        *value = map.get(&(i as u32), 0)?.iter().sum();
    }
    Ok(values)
}

#[test]
#[ignore = "requires CAP_BPF, actual XDP object and VM kernel; executed by the privileged Nix check"]
fn native_flow_store_and_kernel_control_end_to_end() -> Result<()> {
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_TEST_OBJECT").context("missing kernel object")?,
    );
    let mut ebpf = Ebpf::load_file(object)?;
    let packet: &mut Xdp = ebpf
        .program_mut("rust_cas_probe")
        .context("packet entry")?
        .try_into()?;
    packet.load()?;
    let mut store = FlowStore::from_ebpf(&mut ebpf)?;
    let mut completed = Vec::new();
    same_status(store.snapshot(&key(1)), Status::MISSING);
    let first = seed(&mut store, 1, 42)?;
    ensure!(first.state.incarnation == 42 && first.entry.incarnation != 42 && first.revision == 1);
    same_status(seed(&mut store, 1, 42), Status::CONFLICT);
    let by_slot = store
        .snapshot_slot(first.entry.slot)?
        .context("allocated slot missing")?;
    ensure!(by_slot == first);
    ensure!(!store.reclaim_retired(first.entry.slot)?);
    completed.push("coherent-snapshot-and-create-only");

    let transfer = first
        .state
        .export(ip_proto::UDP, monotonic_ms()?, T)
        .unwrap();
    let next = store.import_primary(&key(1), transfer, 0, T, Some(first.version()))?;
    ensure!(next.entry == first.entry && next.revision == 2);
    same_status(store.remove_if_unchanged(&first), Status::CONFLICT);
    same_status(
        store.import_primary(&key(1), transfer, 0, T, Some(first.version())),
        Status::CONFLICT,
    );
    let current = store.snapshot(&key(1))?;
    store.import_alias(&key(2), &key(1), 42, false, None)?;
    let alias = store.snapshot(&key(2))?;
    ensure!(
        alias.kind == Kind::ALIAS
            && alias.primary == current.entry
            && alias.primary_revision == current.revision
    );
    store.import_primary(
        &key(1),
        current
            .state
            .export(ip_proto::UDP, monotonic_ms()?, T)
            .unwrap(),
        0,
        T,
        Some(current.version()),
    )?;
    same_status(store.remove_if_unchanged(&alias), Status::CONFLICT);
    store.revoke_if_unchanged(&alias)?;
    completed.push("revision-guards-primary-and-alias");

    store.import_alias(&key(2), &key(1), 42, false, None)?;
    let primary = store.snapshot(&key(1))?;
    store.revoke_if_unchanged(&primary)?;
    seed(&mut store, 1, 43)?;
    let orphan = store.snapshot(&key(2))?;
    ensure!(
        orphan.kind == Kind::ORPHAN_ALIAS
            && orphan.primary == primary.entry
            && orphan.primary_key == primary.key
    );
    ensure!(orphan.state == FirewallFlow::ZERO);
    store.import_alias(&key(2), &key(1), 43, true, Some(orphan.version()))?;
    same_status(store.remove_if_unchanged(&orphan), Status::CONFLICT);
    let alias = store.snapshot(&key(2))?;
    ensure!(alias.flip == 1 && alias.revision > orphan.revision);
    same_status(
        store.import_alias(&key(3), &key(1), 42, false, None),
        Status::CONFLICT,
    );
    completed.push("wire-incarnation-rebind-and-orphan-recovery");

    // Its last remote packet predates this VM's boot. Re-export must preserve
    // the idle age, and a shorter CURRENT timeout must expire it immediately.
    let age_limits = FlowTimeouts {
        udp_replied_ms: velstra_common::MAX_FLOW_TIMEOUT_MS,
        ..T
    };
    let remote_idle = monotonic_ms()?
        .checked_add(60_000)
        .context("idle fixture overflow")?;
    let mut source =
        FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 0, 99, age_limits).unwrap();
    source.observe(
        ip_proto::UDP,
        FlowPacket::Udp,
        FlowDirection::Reverse,
        0,
        age_limits,
    );
    let relative = source
        .export(ip_proto::UDP, remote_idle, age_limits)
        .unwrap();
    store.import_primary(&key(4), relative, 5, age_limits, None)?;
    let aged = store.snapshot(&key(4))?;
    ensure!(
        aged.state
            .export(ip_proto::UDP, monotonic_ms()?, age_limits)
            .unwrap()
            .idle_ms
            >= remote_idle as u32 + 5
    );
    let shorter = FlowTimeouts {
        udp_replied_ms: 30_000,
        ..T
    };
    ensure!(
        aged.state
            .export(ip_proto::UDP, monotonic_ms()?, shorter)
            .is_none()
    );
    store.remove_if_unchanged(&aged)?;
    completed.push("preboot-idle-and-timeout-shrink");

    // Model a drained configuration transaction: shrinking then growing a
    // timeout must not revive a grant or repeatedly move its stored deadline.
    let short = FlowTimeouts {
        udp_unreplied_ms: 5_000,
        ..T
    };
    let original = seed(&mut store, 5, 55)?;
    store.import_alias(&key(6), &key(5), 55, false, None)?;
    let old_alias = store.snapshot(&key(6))?;
    ensure!(matches!(
        store.constrain_timeout(&original, short)?,
        TimeoutChange::Shortened(_)
    ));
    let limited = store.snapshot(&key(5))?;
    ensure!(limited.state.expires_at_ms == original.state.last_seen_ms + 5_000);
    ensure!(limited.state.last_seen_ms == original.state.last_seen_ms);
    ensure!(limited.revision == original.revision + 1);
    same_status(store.remove_if_unchanged(&old_alias), Status::CONFLICT);
    same_status(store.constrain_timeout(&original, T), Status::CONFLICT);
    ensure!(
        store.constrain_timeout(&limited, short)? == TimeoutChange::Unchanged(limited.version())
    );
    ensure!(store.constrain_timeout(&limited, T)? == TimeoutChange::Unchanged(limited.version()));
    ensure!(store.snapshot(&key(5))? == limited);
    ensure!(
        store
            .constrain_timeout(&limited, FlowTimeouts { echo_ms: 0, ..T })
            .is_err()
    );
    ensure!(store.snapshot(&key(5))? == limited);
    let idle = FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 0, 77, T)
        .unwrap()
        .export(ip_proto::UDP, 10_000, T)
        .unwrap();
    store.import_primary(&key(7), idle, 0, T, None)?;
    store.import_alias(&key(8), &key(7), 77, false, None)?;
    let expired = store.snapshot(&key(7))?;
    ensure!(
        expired
            .state
            .export(ip_proto::UDP, monotonic_ms()?, short)
            .is_none()
    );
    ensure!(
        expired
            .state
            .export(ip_proto::UDP, monotonic_ms()?, T)
            .is_some()
    );
    ensure!(store.constrain_timeout(&expired, short)? == TimeoutChange::Removed);
    same_status(store.snapshot(&key(7)), Status::MISSING);
    let orphan = store.snapshot(&key(8))?;
    ensure!(orphan.kind == Kind::ORPHAN_ALIAS && orphan.state == FirewallFlow::ZERO);
    for port in [5, 6, 8] {
        let record = store.snapshot(&key(port))?;
        store.revoke_if_unchanged(&record)?;
    }
    completed.push("commit-timeout-shrink-grow-does-not-resurrect");

    // Reentrant control invocations cannot overwrite an occupied CPU buffer.
    // All calls are quiescent during injection; slot/allocator values are never
    // overwritten. Per-CPU map values are filled for every possible CPU.
    {
        let mut buffers: aya::maps::PerCpuArray<_, [u8; 584]> = aya::maps::PerCpuArray::try_from(
            ebpf.map_mut("FW_CTL_BUF").context("control buffer")?,
        )?;
        let before = buffers.get(&0, 0)?;
        let mut held = before.clone();
        for value in held.iter_mut() {
            value[..4].copy_from_slice(&1u32.to_ne_bytes());
        }
        buffers.set(0, aya::maps::PerCpuValues::try_from(held.to_vec())?, 0)?;
        same_status(store.snapshot(&key(1)), Status::BUSY);
        let after = buffers.get(&0, 0)?;
        ensure!(
            after
                .iter()
                .zip(held.iter())
                .all(|(actual, expected)| actual == expected)
        );
        buffers.set(0, before, 0)?;
    }
    store.snapshot(&key(1))?;
    completed.push("control-buffer-contention-recovers");

    // Actual Linux captures drive the packet writer while native Rust control
    // reads each resulting protocol revision through the syscall-only entry.
    let cases = CAPTURED_FLOWS;
    let mut frames = 0;
    let mut tcp_keys = std::collections::HashSet::new();
    for case in cases {
        let packets = case.packets;
        let first = unhex(packets[0].1);
        let key = tcp_key(&first);
        tcp_keys.insert(key);
        if let Ok(old) = store.snapshot(&key) {
            store.revoke_if_unchanged(&old)?;
        }
        let mut previous = 0;
        for (_, hex) in packets {
            let data = unhex(hex);
            ensure!(frame(&ebpf, &data)? == 2);
            let state = store.snapshot(&key)?;
            ensure!(state.revision >= previous && state.state.valid_for(ip_proto::TCP));
            previous = state.revision;
            frames += 1;
        }
        let closed = store.snapshot(&key)?;
        ensure!(closed.state.tcp_closed());
        ensure!(frame(&ebpf, &first)? == 1);
        ensure!(store.snapshot(&key)? == closed);
    }
    ensure!(frames == 162);
    completed.push("162-real-tcp-frames-through-native-snapshots");
    let case = cases
        .iter()
        .find(|c| c.family == 4 && c.name == "half-close")
        .context("SMP capture")?;
    let packets = case.packets;
    let first = unhex(packets[0].1);
    let tcp = tcp_key(&first);
    if let Ok(old) = store.snapshot(&tcp) {
        store.revoke_if_unchanged(&old)?;
    }
    for packet in &packets[..3] {
        ensure!(frame(&ebpf, &unhex(packet.1))? == 2);
    }
    let stale = store.snapshot(&tcp)?;
    let ack = unhex(packets[2].1);
    ensure!(frame(&ebpf, &ack)? == 2); // make stale unconditionally older before racing
    let baseline = store.snapshot(&tcp)?;
    let before = stats(&mut ebpf)?;
    let cpus = allowed_cpus()?;
    ensure!(
        cpus.len() >= 4,
        "SMP qualification requires four actual CPUs"
    );
    let control_a = FlowStore::from_ebpf(&mut ebpf)?;
    let control_b = FlowStore::from_ebpf(&mut ebpf)?;
    let packet: &Xdp = ebpf.program("rust_cas_probe").unwrap().try_into()?;
    let (cpu0, cpu1, cpu2, cpu3) = (cpus[0], cpus[1], cpus[2], cpus[3]);
    let gate = std::sync::Barrier::new(4);
    let (reads, imports, control_busy, conflicts) =
        std::thread::scope(|scope| -> Result<(u64, u64, u64, u64)> {
            let writer = |cpu: usize| -> Result<()> {
                pin_cpu(cpu)?;
                let program = packet;
                gate.wait();
                program.test_run(TestRunOptions {
                    data_in: Some(&ack),
                    repeat: 2000,
                    ..TestRunOptions::new()
                })?;
                Ok(())
            };
            let w0 = scope.spawn(move || writer(cpu0));
            let w1 = scope.spawn(move || writer(cpu1));
            let observer = |cpu: usize,
                            mut control: FlowStore,
                            can_import: bool|
             -> Result<(u64, u64, u64, u64)> {
                pin_cpu(cpu)?;
                gate.wait();
                let (mut reads, mut imports, mut busy, mut conflicts) = (0, 0, 0, 0);
                for i in 0..1000 {
                    match control.snapshot(&tcp) {
                        Ok(record) => {
                            ensure!(
                                record.state.valid_for(ip_proto::TCP)
                                    && record.primary_revision == record.revision
                                    && record.primary == record.entry
                                    && record.key == tcp
                                    && record.state.incarnation == baseline.state.incarnation
                            );
                            reads += 1;
                            if can_import
                                && i % 5 == 0
                                && let Some(wire) =
                                    record.state.export(ip_proto::TCP, monotonic_ms()?, T)
                            {
                                match control.import_primary(
                                    &tcp,
                                    wire,
                                    0,
                                    T,
                                    Some(record.version()),
                                ) {
                                    Ok(_) => imports += 1,
                                    Err(e) if status(&e) == Some(Status::CONFLICT) => {
                                        conflicts += 1
                                    }
                                    Err(e) if status(&e) == Some(Status::BUSY) => busy += 1,
                                    Err(e) => return Err(e),
                                }
                            }
                        }
                        Err(e) if status(&e) == Some(Status::BUSY) => busy += 1,
                        Err(e) => return Err(e),
                    }
                    if !can_import && i % 10 == 0 {
                        match control.remove_if_unchanged(&stale) {
                            Err(e) if status(&e) == Some(Status::CONFLICT) => conflicts += 1,
                            Err(e) if status(&e) == Some(Status::BUSY) => busy += 1,
                            value => {
                                return Err(anyhow::anyhow!(
                                    "stale GC mutation unexpectedly succeeded: {value:?}"
                                ));
                            }
                        }
                    }
                }
                Ok((reads, imports, busy, conflicts))
            };
            let c0 = scope.spawn(move || observer(cpu2, control_a, true));
            let c1 = scope.spawn(move || observer(cpu3, control_b, false));
            w0.join()
                .map_err(|_| anyhow::anyhow!("packet worker panicked"))??;
            w1.join()
                .map_err(|_| anyhow::anyhow!("packet worker panicked"))??;
            let a = c0
                .join()
                .map_err(|_| anyhow::anyhow!("control worker panicked"))??;
            let b = c1
                .join()
                .map_err(|_| anyhow::anyhow!("control worker panicked"))??;
            Ok((a.0 + b.0, a.1 + b.1, a.2 + b.2, a.3 + b.3))
        })?;
    let after = stats(&mut ebpf)?;
    let final_tcp = store.snapshot(&tcp)?;
    let tracked = after[2] - before[2];
    let packet_busy = after[7] - before[7];
    ensure!(reads > 0 && imports > 0 && tracked > 0);
    ensure!(
        after[0] - before[0] == 4000 && tracked + packet_busy == 4000,
        "unexpected packet outcome counters"
    );
    ensure!(
        final_tcp.revision - baseline.revision == tracked + imports,
        "lost or unaccounted protocol revision"
    );
    same_status(store.remove_if_unchanged(&stale), Status::CONFLICT);
    println!(
        "ACTUAL_NATIVE_FLOW_CONTROL_SMP {}",
        serde_json::json!({"cpus":4,"packetCalls":4000,"tracked":tracked,
        "packetBusy":packet_busy,"coherentReads":reads,"conditionalImports":imports,"controlBusy":control_busy,
        "conflicts":conflicts,"revisionDelta":final_tcp.revision-baseline.revision})
    );
    completed.push("four-cpu-packets-snapshots-imports-and-stale-gc");
    let scan = store.scan()?;
    ensure!(scan.retry_slots.is_empty());
    ensure!(scan.records.len() == tcp_keys.len() + 2);
    completed.push("bounded-complete-stable-slot-scan");

    // The cloned program FD, rather than a surrendered map FD, retains control
    // access even after the loader and all its userspace map handles are gone.
    let shared = Arc::new(Mutex::new(store));
    let observer = shared.clone();
    drop(shared);
    drop(ebpf);
    let mut retained = observer.lock().unwrap();
    let final_state = retained.snapshot(&key(1))?;
    retained.revoke_if_unchanged(&final_state)?;
    same_status(retained.snapshot(&key(1)), Status::MISSING);
    completed.push("shared-owner-survives-loader-drop");
    println!(
        "ACTUAL_NATIVE_FLOW_CONTROL {}",
        serde_json::json!({"result":"PASS","checks":completed,"frames":frames,"capacity":retained.capacity()})
    );
    Ok(())
}

/// The product daemon, not the test collector, owns expiration. Seed its real
/// pinned maps through the same conditional control ABI used by reconciliation.
#[test]
#[ignore = "requires root, bpffs and a veth; executed by the privileged kernel checks"]
fn native_agent_state_gc_end_to_end() -> Result<()> {
    use std::{
        fs::File,
        io::{Read, Write},
        os::unix::{fs::DirBuilderExt, net::UnixStream},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    struct Agent {
        binary: PathBuf,
        iface: String,
        pins: PathBuf,
        directory: PathBuf,
        child: Option<Child>,
    }
    impl Drop for Agent {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if self.pins.exists() {
                let _ = Command::new(&self.binary)
                    .args(["detach", "--datapath-state-dir"])
                    .arg(&self.pins)
                    .output();
                let _ = std::fs::remove_dir_all(&self.pins);
            }
            let _ = Command::new("ip")
                .args(["link", "del", &self.iface])
                .output();
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn query(path: &std::path::Path) -> Result<serde_json::Value> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"state-gc\n")?;
        let mut output = String::new();
        stream.read_to_string(&mut output)?;
        Ok(serde_json::from_str(&output)?)
    }
    let binary = std::env::var_os("VELSTRA_CONTROL_AGENT_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_velstra")));
    ensure!(
        binary.is_file(),
        "actual agent executable missing: {binary:?}"
    );
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("missing packaged object")?,
    );
    let id = std::process::id();
    let mut agent = Agent {
        binary,
        iface: format!("gc-u{id}"),
        pins: PathBuf::from(format!("/sys/fs/bpf/native-gc-{id}")),
        directory: PathBuf::from(format!("/run/native-gc-{id}")),
        child: None,
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&agent.directory)?;
    let socket = agent.directory.join("query.sock");
    let config = agent.directory.join("policy.toml");
    let logfile = agent.directory.join("agent.log");
    std::fs::write(&config, "default_action = \"drop\"\nstateful = true\n")?;
    let peer = format!("gc-p{id}");
    let created = Command::new("ip")
        .args([
            "link",
            "add",
            &agent.iface,
            "type",
            "veth",
            "peer",
            "name",
            &peer,
        ])
        .output()?;
    ensure!(
        created.status.success(),
        "creating isolated veth: {created:?}"
    );
    for iface in [&agent.iface, &peer] {
        ensure!(
            Command::new("ip")
                .args(["link", "set", iface, "up"])
                .status()?
                .success()
        );
    }
    let log = File::create(&logfile)?;
    agent.child = Some(
        Command::new(&agent.binary)
            .args([
                "run",
                "--iface",
                &agent.iface,
                "--xdp-mode",
                "skb",
                "--config",
            ])
            .arg(&config)
            .arg("--datapath-state-dir")
            .arg(&agent.pins)
            .arg("--query-socket")
            .arg(&socket)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    let ready = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = agent.child.as_mut().unwrap().try_wait()? {
            anyhow::bail!(
                "agent exited {status}: {}",
                std::fs::read_to_string(&logfile)?
            );
        }
        if let Ok(state) = query(&socket)
            && state["state"] == "Ready"
        {
            ensure!(state["allocatedSlots"] == 0 && state["errors"] == 0);
            break;
        }
        ensure!(
            Instant::now() < ready,
            "agent did not become ready: {}",
            std::fs::read_to_string(&logfile)?
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let mut loader = aya::EbpfLoader::new();
    for (name, path) in [
        ("FW_SLOT", "flow-slot-v1"),
        ("FW_ALLOC", "flow-allocator-v1"),
        ("FW_INDEX", "flow-index-v1"),
        ("FW_SCOPE_META", "flow-scope-meta-v1"),
        ("FW_LABELS", "flow-labels-v1"),
        ("FW_POLICY", "flow-policies-v1"),
        ("FW_TIMEOUT", "flow-timeouts-v1"),
    ] {
        loader.map_pin_path(name, agent.pins.join(path));
    }
    let mut ebpf = loader.load_file(&object)?;
    let scopes: aya::maps::HashMap<_, u32, FlowScope> =
        aya::maps::HashMap::try_from(ebpf.map("FW_POLICY").unwrap())?;
    let scope = scopes.get(&0, 0)?;
    let mut store = FlowStore::from_ebpf(&mut ebpf)?;
    ensure!(store.allocated_slots()? == 0);
    let scoped = |port| {
        let mut key = key(port);
        key.scope = scope;
        key
    };
    let long = scoped(101);
    let live_alias = scoped(102);
    let short = scoped(103);
    let short_alias = scoped(104);
    let orphan_parent = scoped(105);
    let orphan = scoped(106);
    let mut transfer = FirewallFlow::begin(FlowPacket::Udp, FlowDirection::Forward, 100, 777, T)
        .unwrap()
        .export(ip_proto::UDP, 100, T)
        .unwrap();
    for primary in [long, orphan_parent] {
        store.import_primary(&primary, transfer, 0, T, None)?;
    }
    store.import_alias(&live_alias, &long, 777, false, None)?;
    store.import_alias(&orphan, &orphan_parent, 777, false, None)?;
    let dead_parent = store.snapshot(&orphan_parent)?;
    store.revoke_if_unchanged(&dead_parent)?;
    let retained = store.snapshot(&long)?;
    let retained_alias = store.snapshot(&live_alias)?;
    transfer.incarnation = 778;
    transfer.remaining_ms = 500;
    store.import_primary(&short, transfer, 0, T, None)?;
    store.import_alias(&short_alias, &short, 778, false, None)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    // No diagnostics requests drive this wait. Only the actual agent's
    // autonomous maintenance task can remove these seeded kernel records.
    loop {
        let missing = [short, short_alias, orphan].iter().all(|key| {
            store
                .snapshot(key)
                .err()
                .is_some_and(|e| status(&e) == Some(Status::MISSING))
        });
        ensure!(store.snapshot(&long)? == retained);
        ensure!(store.snapshot(&live_alias)? == retained_alias);
        if missing {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "autonomous expiration did not finish"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let state = query(&socket)?;
    ensure!(
        state["expiredEntries"].as_u64().unwrap_or(0) >= 1,
        "{state}"
    );
    ensure!(
        state["orphanedAliases"].as_u64().unwrap_or(0) >= 1,
        "{state}"
    );
    ensure!(
        state["errors"] == 0 && state["allocatedSlots"].as_u64().unwrap_or(0) <= 6,
        "{state}"
    );
    // Restart with no query socket at all. Persistent live entries survive,
    // and short-lived entries still expire without a diagnostics server.
    let child = agent.child.as_mut().unwrap();
    child.kill()?;
    child.wait()?;
    std::fs::remove_file(&socket)?;
    let log = File::options().append(true).open(&logfile)?;
    agent.child = Some(
        Command::new(&agent.binary)
            .args([
                "run",
                "--iface",
                &agent.iface,
                "--xdp-mode",
                "skb",
                "--config",
            ])
            .arg(&config)
            .arg("--datapath-state-dir")
            .arg(&agent.pins)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?,
    );
    // Readiness log is appended only after config/scope reconciliation completed.
    let restart_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let log = std::fs::read_to_string(&logfile)?;
        ensure!(
            agent.child.as_mut().unwrap().try_wait()?.is_none(),
            "restart failed: {log}"
        );
        if log.matches("Kernel enforcement persists").count() == 2 {
            break;
        }
        ensure!(
            Instant::now() < restart_deadline,
            "restart readiness timed out: {log}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    ensure!(!socket.exists());
    ensure!(store.snapshot(&long)? == retained);
    ensure!(store.snapshot(&live_alias)? == retained_alias);
    transfer.incarnation = 779;
    store.import_primary(&short, transfer, 0, T, None)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match store.snapshot(&short) {
            Err(error) if status(&error) == Some(Status::MISSING) => break,
            Err(error) => return Err(error),
            Ok(_) => {}
        }
        ensure!(
            Instant::now() < deadline,
            "expiration depends on the query socket"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    ensure!(store.snapshot(&long)? == retained);
    ensure!(store.snapshot(&live_alias)? == retained_alias);
    ensure!(agent.child.as_mut().unwrap().try_wait()?.is_none());
    println!(
        "ACTUAL_AGENT_STATE_GC {}",
        serde_json::json!({
            "result":"PASS","expiredPrimary":true,"expiredAlias":true,"orphanRemoved":true,
            "liveEntriesPreserved":true,"restart":true,"withoutQuerySocket":true,"health":state,
        })
    );
    Ok(())
}

#[test]
#[ignore = "requires the packaged production ELF and CAP_BPF; executed by the privileged kernel checks"]
fn native_flow_scan_initialized_prefix() -> Result<()> {
    let object = PathBuf::from(
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("missing packaged object")?,
    );
    let mut ebpf = Ebpf::load_file(object)?;
    let mut store = FlowStore::from_ebpf(&mut ebpf)?;
    let empty = store.scan()?;
    ensure!(empty.scanned_slots == 0 && empty.initialized_slots == 0);
    ensure!(empty.records.is_empty() && empty.retry_slots.is_empty());
    let first = seed(&mut store, 41, 800)?;
    store.import_alias(&key(42), &key(41), 800, false, None)?;
    let filled = store.scan()?;
    ensure!(filled.scanned_slots == 2 && filled.initialized_slots == 2);
    ensure!(filled.records.len() == 2 && filled.retry_slots.is_empty());
    store.revoke_if_unchanged(&first)?;
    let sparse = store.scan()?;
    ensure!(sparse.scanned_slots == 2 && sparse.initialized_slots == 2);
    ensure!(sparse.records.len() == 1 && sparse.records[0].kind == Kind::ORPHAN_ALIAS);
    let fresh = seed(&mut store, 43, 801)?;
    ensure!(
        fresh.entry.slot == first.entry.slot && fresh.entry.incarnation > first.entry.incarnation
    );
    let reused = store.scan()?;
    ensure!(
        reused.scanned_slots == 2 && reused.records.len() == 2 && reused.retry_slots.is_empty()
    );
    let orphan = store.snapshot(&key(42))?;
    ensure!(orphan.kind == Kind::ORPHAN_ALIAS);
    store.revoke_if_unchanged(&orphan)?;
    store.revoke_if_unchanged(&fresh)?;
    let holes = store.scan()?;
    ensure!(holes.records.is_empty() && holes.retry_slots.is_empty());
    ensure!(holes.scanned_slots == 2 && holes.initialized_slots == 2);
    println!(
        "ACTUAL_INITIALIZED_FLOW_SCAN {}",
        serde_json::json!({
            "result":"PASS","emptySlotsVisited":empty.scanned_slots,"sparseSlotsVisited":sparse.scanned_slots,
            "holesVisited":holes.scanned_slots,"aliasIncluded":true,"slotReuse":true,
        })
    );
    Ok(())
}

#[path = "flow_store_kernel/synproxy.rs"]
mod synproxy_kernel;

#[path = "flow_store_kernel/guest_policy.rs"]
mod guest_policy_kernel;

#[path = "flow_store_kernel/ipv6_state.rs"]
mod ipv6_state_kernel;

#[path = "flow_store_kernel/rule_contexts.rs"]
mod rule_contexts_kernel;
