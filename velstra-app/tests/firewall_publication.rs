//! Deterministic, privileged packet tests for an explicitly instrumented object.
//! See firewall-publication.md; this is not production-object qualification.
use std::{
    env, fs,
    mem::{align_of, offset_of, size_of},
};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, HashMap, Map, PerCpuArray, ProgramArray},
    programs::{SchedClassifier, TestRun, TestRunOptions, Xdp},
};
use serde_json::{Value, json};
use velstra_common::{
    Action, ConfigFlags, ConntrackTimeouts, Counter, FirewallKey, FirewallState, FlowKey,
    GlobalConfig, ip_proto,
};

#[path = "../src/btf.rs"]
mod btf;

const POLICY: u32 = 2;
const PRIVATE: [u8; 4] = [192, 0, 2, 7];
const REMOTE: [u8; 4] = [198, 51, 100, 8];
const PUBLIC: [u8; 4] = [198, 18, 10, 100];
const SPORT: u16 = 41000;
const DPORT: u16 = 9000;

// Mirror only the private map's layout, never its publication implementation.
// We transfer initialized u64 arrays through Aya, not this padded Rust struct.
#[repr(C)]
struct ScratchLayout {
    key: FirewallKey,
    reverse: FirewallKey,
    state: FirewallState,
    reverse_state: FirewallState,
    flow: FlowKey,
}

const SCRATCH_WORDS: usize = 24;
const SCRATCH_POISON: u64 = 0xa5a5_a5a5_a5a5_a5a5;
const SCRATCH_DECLARATION: &str = "#[repr(C)]\nstruct Scratch {\n    key: FirewallKey,\n    reverse: FirewallKey,\n    state: FirewallState,\n    reverse_state: FirewallState,\n    flow: FlowKey,\n}";
const _: () = {
    assert!(size_of::<FirewallKey>() == 44);
    assert!(offset_of!(FirewallKey, src) == 4);
    assert!(offset_of!(FirewallKey, dst) == 20);
    assert!(size_of::<FirewallState>() == 40);
    assert!(size_of::<FlowKey>() == 20);
    assert!(align_of::<ScratchLayout>() == 8);
    assert!(size_of::<ScratchLayout>() == SCRATCH_WORDS * size_of::<u64>());
    assert!(offset_of!(ScratchLayout, key) == 0);
    assert!(offset_of!(ScratchLayout, reverse) == 44);
    assert!(offset_of!(ScratchLayout, state) == 88);
    assert!(offset_of!(ScratchLayout, reverse_state) == 128);
    assert!(offset_of!(ScratchLayout, flow) == 168);
};

fn check_scratch_source_layout() -> Result<()> {
    // Bind the mirrored private ABI to the same frozen source used to build
    // this probe; the Nix wrapper separately binds that source to the object.
    let source = include_str!("../../velstra-ebpf/src/conntrack.rs");
    ensure!(
        source.matches(SCRATCH_DECLARATION).count() == 1,
        "CT_SCRATCH source ABI changed; re-review the explicit layout oracle"
    );
    Ok(())
}

fn poison_scratch(ebpf: &mut Ebpf) -> Result<usize> {
    check_scratch_source_layout()?;
    match ebpf.map("CT_SCRATCH").context("CT_SCRATCH missing")? {
        Map::PerCpuArray(data) => {
            let info = data.info()?;
            ensure!(info.key_size() == 4 && info.max_entries() == 1);
            ensure!(info.value_size() == size_of::<ScratchLayout>() as u32);
            ensure!(info.map_flags() == 0);
        }
        _ => anyhow::bail!("CT_SCRATCH must be an ordinary per-CPU array"),
    }
    let mut scratch =
        PerCpuArray::<_, [u64; SCRATCH_WORDS]>::try_from(ebpf.map_mut("CT_SCRATCH").unwrap())?;
    let count = scratch.get(&0, 0)?.len();
    ensure!(count > 0);
    let poisoned = [SCRATCH_POISON; SCRATCH_WORDS];
    scratch.set(0, vec![poisoned; count].try_into()?, 0)?;
    let observed = scratch.get(&0, 0)?;
    ensure!(
        observed.len() == count && observed.iter().all(|value| *value == poisoned),
        "every possible CPU must contain the poison before test-run"
    );
    Ok(count)
}

#[derive(Clone, Copy, Debug)]
enum Path {
    Ingress,
    Egress,
    Masquerade,
    IcmpMasquerade,
}

impl Path {
    fn program(self) -> &'static str {
        match self {
            Self::Ingress => "velstra_main",
            Self::Egress => "velstra_egress_v4",
            Self::Masquerade => "velstra_masquerade",
            Self::IcmpMasquerade => "velstra_egress_icmp",
        }
    }

    fn nat(self) -> bool {
        matches!(self, Self::Masquerade | Self::IcmpMasquerade)
    }

    fn ingress(self) -> bool {
        matches!(self, Self::Ingress)
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in data.chunks(2) {
        sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn frame(protocol: u8, reverse: bool, control: u8) -> Vec<u8> {
    let transport_len = if protocol == ip_proto::TCP { 20 } else { 16 };
    let mut frame = vec![0u8; 34 + transport_len];
    frame[..12].copy_from_slice(&[2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&((20 + transport_len) as u16).to_be_bytes());
    frame[22] = 64;
    frame[23] = protocol;
    let (source, destination, source_port, destination_port) = if reverse {
        (REMOTE, PRIVATE, DPORT, SPORT)
    } else {
        (PRIVATE, REMOTE, SPORT, DPORT)
    };
    frame[26..30].copy_from_slice(&source);
    frame[30..34].copy_from_slice(&destination);
    if protocol == ip_proto::TCP {
        frame[34..36].copy_from_slice(&source_port.to_be_bytes());
        frame[36..38].copy_from_slice(&destination_port.to_be_bytes());
        frame[38..42].copy_from_slice(&1u32.to_be_bytes());
        if control & 0x10 != 0 {
            frame[42..46].copy_from_slice(&2u32.to_be_bytes());
        }
        frame[46] = 5 << 4;
        frame[47] = control;
        frame[48..50].copy_from_slice(&4096u16.to_be_bytes());
        let check = checksum(&tcp_pseudo(&frame));
        frame[50..52].copy_from_slice(&check.to_be_bytes());
    } else {
        frame[34] = control;
        frame[38..40].copy_from_slice(&SPORT.to_be_bytes());
        frame[40..42].copy_from_slice(&1u16.to_be_bytes());
        frame[42..].copy_from_slice(b"FWPROBE!");
        let check = checksum(&frame[34..]);
        frame[36..38].copy_from_slice(&check.to_be_bytes());
    }
    let check = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&check.to_be_bytes());
    frame
}

fn tcp_pseudo(frame: &[u8]) -> Vec<u8> {
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, ip_proto::TCP]);
    pseudo.extend_from_slice(&((frame.len() - 34) as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    pseudo
}

fn key(packet: &[u8]) -> FirewallKey {
    let proto = packet[23];
    let (source_port, destination_port) = if proto == ip_proto::ICMP {
        (
            u16::from_be_bytes([packet[38], packet[39]]),
            packet[34] as u16,
        )
    } else {
        (
            u16::from_be_bytes([packet[34], packet[35]]),
            u16::from_be_bytes([packet[36], packet[37]]),
        )
    };
    FirewallKey::ipv4(FlowKey::new(
        POLICY,
        packet[26..30].try_into().unwrap(),
        packet[30..34].try_into().unwrap(),
        source_port,
        destination_port,
        proto,
    ))
}

fn load(bytes: &[u8], path: Path, stateful: bool) -> Result<Ebpf> {
    let normalized = btf::kernel_object(bytes)?;
    let mut ebpf = Ebpf::load(&normalized)?;
    match ebpf.map("FW_FLOWS").context("FW_FLOWS missing")? {
        Map::HashMap(data) => {
            let info = data.info()?;
            ensure!(
                info.max_entries() == 4,
                "instrumented capacity must be exactly four"
            );
            ensure!(info.key_size() == size_of::<FirewallKey>() as u32);
            ensure!(info.value_size() == size_of::<FirewallState>() as u32);
            ensure!(
                info.map_flags() == 0,
                "instrumented HASH must be preallocated"
            );
        }
        _ => anyhow::bail!("requires source-derived ordinary HASH, not production LRU"),
    }
    {
        let mut policies = HashMap::<_, u32, u32>::try_from(ebpf.map_mut("IFACE_POLICY").unwrap())?;
        // Test-run default skb/XDP context uses loopback; cover the zero default
        // context as well. No program is attached to either interface.
        policies.insert(0, POLICY, 0)?;
        policies.insert(1, POLICY, 0)?;
    }
    HashMap::<_, u32, GlobalConfig>::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
        POLICY,
        GlobalConfig::new(
            Action::Pass,
            if stateful { ConfigFlags::STATEFUL } else { 0 },
        ),
        0,
    )?;
    Array::<_, ConntrackTimeouts>::try_from(ebpf.map_mut("CT_TIMEOUTS").unwrap())?.set(
        0,
        ConntrackTimeouts::DEFAULT,
        0,
    )?;
    Array::<_, u32>::try_from(ebpf.map_mut("FAIL_CLOSED").unwrap())?.set(0, 1, 0)?;
    Array::<_, u32>::try_from(ebpf.map_mut("NAPT_MODE").unwrap())?.set(0, 1, 0)?;
    if path.nat() {
        let mut map = HashMap::<_, u32, [u8; 4]>::try_from(ebpf.map_mut("MASQUERADE").unwrap())?;
        map.insert(0, PUBLIC, 0)?;
        map.insert(1, PUBLIC, 0)?;
    }
    if path.ingress() {
        let forward: &mut Xdp = ebpf.program_mut("velstra_forward").unwrap().try_into()?;
        forward.load()?;
        let fd = forward.fd()?.try_clone()?;
        ProgramArray::try_from(ebpf.map_mut("VELSTRA_PROGS").unwrap())?.set(0, &fd, 0)?;
        let program: &mut Xdp = ebpf.program_mut(path.program()).unwrap().try_into()?;
        program.load()?;
    } else {
        let program: &mut SchedClassifier = ebpf.program_mut(path.program()).unwrap().try_into()?;
        program.load()?;
    }
    Ok(ebpf)
}

fn states(ebpf: &Ebpf) -> Result<Vec<(FirewallKey, FirewallState)>> {
    HashMap::<_, FirewallKey, FirewallState>::try_from(ebpf.map("FW_FLOWS").unwrap())?
        .iter()
        .map(|entry| entry.map_err(Into::into))
        .collect()
}

fn state_evidence(entries: &[(FirewallKey, FirewallState)]) -> Vec<Value> {
    entries
        .iter()
        .map(|(key, state)| {
            json!({
                "policy": key.policy, "source": key.src, "destination": key.dst,
                "source_port": key.src_port, "destination_port": key.dst_port,
                "protocol": key.proto, "family": key.family,
                "last_seen_ns": state.last_seen_ns, "age_ns": state.age_ns,
                "phase": state.phase, "reply": state.reply,
            })
        })
        .collect()
}

fn counters(ebpf: &Ebpf) -> Result<Vec<u64>> {
    let stats = PerCpuArray::<_, u64>::try_from(ebpf.map("STATS").unwrap())?;
    (0..Counter::COUNT)
        .map(|index| Ok(stats.get(&index, 0)?.iter().sum()))
        .collect()
}

fn populate(ebpf: &mut Ebpf, count: usize) -> Result<Vec<(FirewallKey, FirewallState)>> {
    let mut map =
        HashMap::<_, FirewallKey, FirewallState>::try_from(ebpf.map_mut("FW_FLOWS").unwrap())?;
    let mut entries = Vec::new();
    for index in 0..count {
        let key = FirewallKey::ipv4(FlowKey::new(
            99,
            [203, 0, 113, 1],
            [203, 0, 113, 2],
            1000 + index as u16,
            8000,
            ip_proto::TCP,
        ));
        let state = FirewallState {
            last_seen_ns: 123 + index as u64,
            age_ns: 17,
            phase: FirewallState::ESTABLISHED,
            reply: (index % 2) as u32,
            ..FirewallState::UNTRACKED
        };
        map.insert(key, state, 1)?;
        entries.push((key, state));
    }
    Ok(entries)
}

fn run(ebpf: &mut Ebpf, path: Path, input: &[u8]) -> Result<(u32, Vec<u8>)> {
    // Refresh before EVERY packet, including SYN-ACK/ACK controls. No live
    // attachments exist, so there is no concurrent kernel user of these maps.
    let cpus = poison_scratch(ebpf)?;
    println!(
        "CT_SCRATCH_POISONED path={} possible_cpus={cpus} value_bytes=160 byte=0xa5",
        path.program()
    );
    let mut output = vec![0; 4096];
    let options = TestRunOptions {
        data_in: Some(input),
        data_out: Some(&mut output),
        repeat: 1,
        ..Default::default()
    };
    let result = if path.ingress() {
        let program: &Xdp = ebpf.program(path.program()).unwrap().try_into()?;
        program.test_run(options)?
    } else {
        let program: &SchedClassifier = ebpf.program(path.program()).unwrap().try_into()?;
        program.test_run(options)?
    };
    output.truncate(result.data_size_out as usize);
    Ok((result.return_value, output))
}

fn check_counters(before: &[u64], after: &[u64], path: Path, failed: bool) -> Result<()> {
    for (counter, expected) in [
        (Counter::FirewallStateWriteFailed, u64::from(failed)),
        (Counter::EgressDropped, u64::from(failed && !path.ingress())),
        (Counter::DroppedRule, u64::from(failed && path.ingress())),
        (Counter::EgressMasqueraded, u64::from(!failed && path.nat())),
        (Counter::EgressNatClaimFailed, 0),
        (Counter::EgressNatNoCandidate, 0),
        (Counter::Malformed, 0),
    ] {
        let index = counter.index() as usize;
        ensure!(
            after[index] - before[index] == expected,
            "{:?} counter {}: expected {}, got {}",
            path,
            counter.label(),
            expected,
            after[index] - before[index]
        );
    }
    Ok(())
}

fn capacity_case(bytes: &[u8], path: Path, occupied: usize) -> Result<Value> {
    let mut ebpf = load(bytes, path, true)?;
    let original = populate(&mut ebpf, occupied)?;
    let icmp = matches!(path, Path::IcmpMasquerade);
    let packet = frame(
        if icmp { ip_proto::ICMP } else { ip_proto::TCP },
        false,
        if icmp { 8 } else { 2 },
    );
    let before = counters(&ebpf)?;
    let (action, output) = run(&mut ebpf, path, &packet)?;
    let after = counters(&ebpf)?;
    let entries = states(&ebpf)?;
    // Retain evidence in the VM log even if a subsequent strict assertion fails.
    let evidence = json!({"path": path.program(), "occupied_before": occupied,
        "action": action, "packet_in": packet, "packet_out": output,
        "states_before": state_evidence(&original), "states_after": state_evidence(&entries),
        "counters_before": before, "counters_after": after});
    println!("FIREWALL_PUBLICATION_CASE={evidence}");
    let failed = occupied > 2;
    let expected_action = if path.ingress() {
        if failed { 1 } else { 2 }
    } else if failed {
        2
    } else {
        0
    };
    ensure!(
        action == expected_action,
        "{path:?}/{occupied} action {action} != {expected_action}"
    );
    ensure!(output.len() == packet.len());
    ensure!(
        checksum(&output[14..34]) == 0,
        "invalid output IPv4 checksum"
    );
    if icmp {
        ensure!(checksum(&output[34..]) == 0);
    } else {
        ensure!(checksum(&tcp_pseudo(&output)) == 0);
    }
    if path.nat() {
        ensure!(output[26..30] == PUBLIC);
    } else {
        ensure!(output == packet);
    }
    check_counters(&before, &after, path, failed)?;
    for preserved in &original {
        ensure!(
            entries.contains(preserved),
            "unrelated entry changed or evicted"
        );
    }
    let forward = key(&output);
    let reverse = forward.reverse();
    // ct_seed_reply writes reverse first; ct_record writes forward first.
    let first = if matches!(path, Path::Masquerade) {
        reverse
    } else {
        forward
    };
    let expected_new = 4 - occupied;
    ensure!(entries.len() == occupied + expected_new);
    for target in [forward, reverse] {
        let found = entries
            .iter()
            .find(|(key, _)| *key == target)
            .map(|(_, value)| *value);
        let expected_present = occupied == 2 || (occupied == 3 && target == first);
        ensure!(
            found.is_some() == expected_present,
            "wrong partial-publication shape for {path:?}"
        );
        if let Some(state) = found {
            ensure!(
                state.phase == FirewallState::NEW && state.age_ns == 0 && state.last_seen_ns > 0
            );
            ensure!(state.reply == u32::from(target == reverse));
        }
    }
    Ok(evidence)
}

fn noop_case(bytes: &[u8], path: Path, stateful: bool) -> Result<Value> {
    let mut ebpf = load(bytes, path, stateful)?;
    let original = populate(&mut ebpf, 4)?;
    let packet = frame(ip_proto::TCP, false, if stateful { 0x10 } else { 2 });
    let before = counters(&ebpf)?;
    let (action, output) = run(&mut ebpf, path, &packet)?;
    ensure!(action == if path.ingress() { 2 } else { 0 });
    ensure!(output == packet);
    let entries = states(&ebpf)?;
    ensure!(entries.len() == 4 && original.iter().all(|entry| entries.contains(entry)));
    let after = counters(&ebpf)?;
    check_counters(&before, &after, path, false)?;
    Ok(
        json!({"path": path.program(), "case": if stateful { "untracked_ack_no_publication" } else { "stateless_syn_no_publication" }, "action": action}),
    )
}

fn handshake_case(bytes: &[u8], path: Path) -> Result<Value> {
    let mut ebpf = load(bytes, path, true)?;
    let preserved = populate(&mut ebpf, 2)?;
    let forward = key(&frame(ip_proto::TCP, false, 2));
    for (reverse, flags, phase) in [
        (false, 2, FirewallState::NEW),
        (true, 0x12, FirewallState::SYN_RECV),
        (false, 0x10, FirewallState::ESTABLISHED),
    ] {
        let packet = frame(ip_proto::TCP, reverse, flags);
        let before = counters(&ebpf)?;
        let (action, output) = run(&mut ebpf, path, &packet)?;
        ensure!(action == if path.ingress() { 2 } else { 0 });
        ensure!(output == packet);
        check_counters(&before, &counters(&ebpf)?, path, false)?;
        let entries = states(&ebpf)?;
        ensure!(entries.len() == 4 && preserved.iter().all(|entry| entries.contains(entry)));
        for (key, reply) in [(forward, 0), (forward.reverse(), 1)] {
            let value = entries
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .context("handshake direction missing")?
                .1;
            ensure!(value.phase == phase && value.reply == reply);
        }
    }
    Ok(
        json!({"path": path.program(), "case": "bidirectional_handshake_updates_full_map", "phase": "established"}),
    )
}

#[test]
fn scratch_layout_and_tail_poison_oracle() {
    check_scratch_source_layout().unwrap();
    let expected = key(&frame(ip_proto::TCP, false, 2));
    assert!(
        expected.src[4..]
            .iter()
            .chain(&expected.dst[4..])
            .all(|byte| *byte == 0)
    );
    for source_tail in [true, false] {
        let mut stale = expected;
        if source_tail {
            stale.src[4..].fill(0xa5);
        } else {
            stale.dst[4..].fill(0xa5);
        }
        // capacity_case and handshake_case compare the entire key, including
        // address tails. Either stale tail therefore fails both role oracles.
        assert_ne!(stale, expected);
        assert_ne!(stale.reverse(), expected.reverse());
    }
}

#[test]
fn packet_fixture_checksums_and_keys() {
    for reverse in [false, true] {
        for flags in [2, 0x12, 0x10] {
            let packet = frame(ip_proto::TCP, reverse, flags);
            assert_eq!(checksum(&packet[14..34]), 0);
            assert_eq!(checksum(&tcp_pseudo(&packet)), 0);
            assert_eq!(key(&packet).reverse().reverse(), key(&packet));
            assert_eq!(packet[47], flags);
        }
    }
    for control in [8, 0] {
        let packet = frame(ip_proto::ICMP, control == 0, control);
        assert_eq!(checksum(&packet[14..34]), 0);
        assert_eq!(checksum(&packet[34..]), 0);
        assert_eq!(key(&packet).src_port, SPORT);
        assert_eq!(key(&packet).dst_port, control as u16);
    }
}

#[test]
#[ignore = "requires CAP_BPF/CAP_SYS_ADMIN and an explicitly source-derived HASH4 object"]
fn kernel_publication_failures() -> Result<()> {
    let object =
        env::var("VELSTRA_FW_PUBLICATION_OBJECT").context("instrumented object path required")?;
    let receipt = env::var("VELSTRA_FW_PUBLICATION_RECEIPT").context("receipt path required")?;
    let bytes = fs::read(&object)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    let sha256: String = digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut results = Vec::new();
    for path in [
        Path::Ingress,
        Path::Egress,
        Path::Masquerade,
        Path::IcmpMasquerade,
    ] {
        for occupied in [2, 3, 4] {
            results.push(
                capacity_case(&bytes, path, occupied)
                    .with_context(|| format!("{path:?}/occupied={occupied}"))?,
            );
        }
    }
    for path in [Path::Ingress, Path::Egress] {
        results.push(noop_case(&bytes, path, true)?);
        results.push(noop_case(&bytes, path, false)?);
        results.push(handshake_case(&bytes, path)?);
    }
    let result = json!({"schema": 1, "instrumented_not_release_object": true, "object": object, "object_sha256": sha256, "fw_map": {"type": "HASH", "max_entries": 4, "flags": 0, "key_size": size_of::<FirewallKey>(), "value_size": size_of::<FirewallState>()}, "scratch_prefill": {"type": "PERCPU_ARRAY", "max_entries": 1, "value_size": size_of::<ScratchLayout>(), "byte": 165, "all_possible_cpus": true, "before_every_packet": true, "readback_verified": true}, "attached_programs": 0, "cases": results});
    fs::write(receipt, serde_json::to_vec_pretty(&result)?)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
