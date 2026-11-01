//! Independent family/direction matchers exercised on production XDP and TC.
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{
        HashMap, ProgramArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TestRun, TestRunOptions, Xdp},
};
use velstra_common::{
    Action, ConfigFlags, FlowScope, FlowTimeouts, GlobalConfig, ScopedSrcPortKey, port_rule_value,
};
const S: FlowScope = FlowScope {
    identity: 7,
    generation: 19,
};
const SRC: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const DST: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
fn load_production() -> Result<Ebpf> {
    let file =
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("production object")?;
    let mut bpf = Ebpf::load_file(file)?;
    for name in [
        "velstra",
        "velstra_main",
        "velstra_forward",
        "velstra_guest_delivery",
    ] {
        let p: &mut Xdp = bpf.program_mut(name).unwrap().try_into()?;
        p.load().with_context(|| format!("verifying {name}"))?;
    }
    for (index, name) in [
        (0, "velstra_forward"),
        (1, "velstra_main"),
        (2, "velstra_guest_delivery"),
    ] {
        let p: &Xdp = bpf.program(name).unwrap().try_into()?;
        let fd = p.fd()?.try_clone()?;
        ProgramArray::try_from(bpf.map_mut("VELSTRA_PROGS").unwrap())?.set(index, &fd, 0)?;
    }
    for (index, name) in [
        (0, "velstra_ipv6"),
        (1, "velstra_guest_ipv6"),
        (2, "velstra_state_v6"),
    ] {
        if bpf.program(name).is_none() {
            continue;
        }
        let p: &mut Xdp = bpf.program_mut(name).unwrap().try_into()?;
        p.load().with_context(|| format!("verifying {name}"))?;
        let fd = p.fd()?.try_clone()?;
        ProgramArray::try_from(bpf.map_mut("VELSTRA_V6").unwrap())?.set(index, &fd, 0)?;
    }
    if bpf.program("velstra_state_tc6").is_some() {
        let p: &mut SchedClassifier = bpf.program_mut("velstra_state_tc6").unwrap().try_into()?;
        p.load().context("verifying TC state")?;
        let fd = p.fd()?.try_clone()?;
        ProgramArray::try_from(bpf.map_mut("VELSTRA_TC6").unwrap())?.set(0, &fd, 0)?;
    }
    let p: &mut SchedClassifier = bpf.program_mut("velstra_egress").unwrap().try_into()?;
    p.load().context("verifying TC")?;
    HashMap::try_from(bpf.map_mut("FW_POLICY").unwrap())?.insert(0u32, S, 0)?;
    HashMap::try_from(bpf.map_mut("FW_TIMEOUT").unwrap())?.insert(S, FlowTimeouts::DEFAULT, 0)?;
    Ok(bpf)
}
fn frame(proto: u8, port: u16, reverse: bool, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 54 + if proto == 6 { 20 } else { 8 }];
    p[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    p[14] = 0x60;
    p[20] = proto;
    p[21] = 64;
    let payload = (p.len() - 54) as u16;
    p[18..20].copy_from_slice(&payload.to_be_bytes());
    p[22..38].copy_from_slice(if reverse { &DST } else { &SRC });
    p[38..54].copy_from_slice(if reverse { &SRC } else { &DST });
    if proto == 58 {
        p[54] = if reverse { 129 } else { 128 };
        p[58..60].copy_from_slice(&port.to_be_bytes());
    } else {
        p[54..56].copy_from_slice(&(if reverse { 443 } else { port }).to_be_bytes());
        p[56..58].copy_from_slice(&(if reverse { port } else { 443 }).to_be_bytes());
        if proto == 6 {
            p[58..62].copy_from_slice(&seq.to_be_bytes());
            p[62..66].copy_from_slice(&ack.to_be_bytes());
            p[66] = 0x50;
            p[67] = flags;
            p[68..70].copy_from_slice(&64240u16.to_be_bytes());
        } else {
            p[58..60].copy_from_slice(&8u16.to_be_bytes());
        }
    }
    p
}
fn run(bpf: &Ebpf, tc: bool, packet: &[u8]) -> Result<bool> {
    let options = TestRunOptions {
        data_in: Some(packet),
        ..TestRunOptions::new()
    };
    let code = if tc {
        let p: &SchedClassifier = bpf.program("velstra_egress").unwrap().try_into()?;
        p.test_run(options)?.return_value
    } else {
        let p: &Xdp = bpf.program("velstra").unwrap().try_into()?;
        p.test_run(options)?.return_value
    };
    Ok(code == if tc { 0 } else { 2 })
}
fn config(bpf: &mut Ebpf, stateful: bool) -> Result<()> {
    HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?.insert(
        0u32,
        GlobalConfig::new(
            Action::Drop,
            ConfigFlags::EGRESS_DEFAULT_DROP | if stateful { ConfigFlags::STATEFUL } else { 0 },
        ),
        0,
    )?;
    Ok(())
}
fn frame4(
    proto: u8,
    port: u16,
    reverse: bool,
    seq: u32,
    ack: u32,
    flags: u8,
    data: bool,
) -> Vec<u8> {
    let l4 = if proto == 6 { 20 } else { 8 };
    let mut p = vec![0u8; 34 + l4 + usize::from(data)];
    p[0] = 2;
    p[6] = 2;
    p[11] = 1;
    p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    p[14] = 0x45;
    let len = (p.len() - 14) as u16;
    p[16..18].copy_from_slice(&len.to_be_bytes());
    p[22] = 64;
    p[23] = proto;
    p[26..30].copy_from_slice(if reverse {
        &[198, 51, 100, 9]
    } else {
        &[192, 0, 2, 2]
    });
    p[30..34].copy_from_slice(if reverse {
        &[192, 0, 2, 2]
    } else {
        &[198, 51, 100, 9]
    });
    if proto == 1 {
        p[34] = if reverse { 0 } else { 8 };
        p[38..40].copy_from_slice(&port.to_be_bytes());
    } else {
        p[34..36].copy_from_slice(&(if reverse { 443 } else { port }).to_be_bytes());
        p[36..38].copy_from_slice(&(if reverse { port } else { 443 }).to_be_bytes());
        if proto == 6 {
            p[38..42].copy_from_slice(&seq.to_be_bytes());
            p[42..46].copy_from_slice(&ack.to_be_bytes());
            p[46] = 0x50;
            p[47] = flags;
            p[48..50].copy_from_slice(&64240u16.to_be_bytes());
        } else {
            let len = (p.len() - 34) as u16;
            p[38..40].copy_from_slice(&len.to_be_bytes());
        }
    }
    if data {
        *p.last_mut().unwrap() = 42;
    }
    let checksum = |bytes: &[u8]| {
        let mut sum = 0u32;
        for word in bytes.chunks(2) {
            sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
        }
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    };
    let ip = checksum(&p[14..34]);
    p[24..26].copy_from_slice(&ip.to_be_bytes());
    let mut transport = if proto == 1 {
        Vec::new()
    } else {
        let mut v = p[26..34].to_vec();
        v.extend_from_slice(&[0, proto]);
        v.extend_from_slice(&((p.len() - 34) as u16).to_be_bytes());
        v
    };
    transport.extend_from_slice(&p[34..]);
    let mut sum = checksum(&transport);
    if proto == 17 && sum == 0 {
        sum = 65535;
    }
    let offset = if proto == 6 {
        50
    } else if proto == 17 {
        40
    } else {
        36
    };
    p[offset..offset + 2].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(checksum(&p[14..34]), 0);
    let n = transport.len() - (p.len() - 34);
    transport[n..].copy_from_slice(&p[34..]);
    assert_eq!(checksum(&transport), 0);
    p
}
fn checksum4(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in bytes.chunks(2) {
        sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
#[test]
#[ignore = "requires CAP_BPF; executed in privileged kernel VM"]
fn production_independent_rule_contexts() -> Result<()> {
    let mut bpf = load_production()?;
    config(&mut bpf, false)?;
    let key = ScopedSrcPortKey::new(0, 17, 443, 0);
    let packet4 = frame4(17, 60000, false, 0, 0, 0, false);
    let mut packet6 = frame(17, 60000, false, 0, 0, 0);
    let mut pseudo = SRC.to_vec();
    pseudo.extend_from_slice(&DST);
    pseudo.extend_from_slice(&8u32.to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&packet6[54..]);
    let sum = checksum4(&pseudo);
    packet6[60..62].copy_from_slice(&sum.to_be_bytes());
    let mut cases = 0;
    // All combinations at exactly the same logical matcher. This catches both
    // value overwrites and accidental family/direction wildcard lookups.
    for pattern in 0..16 {
        for context in 0..4 {
            let allow = pattern & (1 << context) != 0;
            LpmTrie::try_from(bpf.map_mut("PORT_RULES").unwrap())?.insert(
                &Key::new(ScopedSrcPortKey::prefix_len(0), key.in_context(context)),
                port_rule_value(if allow { Action::Pass } else { Action::Drop }, false, 0),
                0,
            )?;
        }
        for context in 0..4 {
            ensure!(
                run(
                    &bpf,
                    context & 1 != 0,
                    if context & 2 == 0 { &packet4 } else { &packet6 }
                )? == (pattern & (1 << context) != 0),
                "context {context} pattern {pattern} borrowed another context"
            );
            cases += 1;
        }
    }
    // A specific prefix in one direction must not hide a broader rule in the
    // other direction, which post-lookup value filtering cannot guarantee.
    for context in 0..4 {
        LpmTrie::try_from(bpf.map_mut("PORT_RULES").unwrap())?.insert(
            &Key::new(ScopedSrcPortKey::prefix_len(0), key.in_context(context)),
            port_rule_value(Action::Drop, false, 0),
            0,
        )?;
    }
    let specific = Key::new(
        ScopedSrcPortKey::prefix_len(24),
        ScopedSrcPortKey::new(0, 17, 443, velstra_common::lpm_key_addr([192, 0, 2, 0]))
            .in_context(1),
    );
    LpmTrie::try_from(bpf.map_mut("PORT_RULES").unwrap())?.insert(
        &specific,
        port_rule_value(Action::Pass, false, 24),
        0,
    )?;
    ensure!(
        !run(&bpf, false, &packet4)?,
        "egress prefix hid ingress deny"
    );
    ensure!(
        run(&bpf, true, &packet4)?,
        "egress prefix not independently matched"
    );
    LpmTrie::<_, ScopedSrcPortKey, u32>::try_from(bpf.map_mut("PORT_RULES").unwrap())?
        .remove(&specific)?;
    ensure!(
        !run(&bpf, true, &packet4)?,
        "removed prefix remained allowed"
    );
    println!(
        "ACTUAL_INDEPENDENT_RULE_CONTEXTS {}",
        serde_json::json!({"result":"PASS","cases":cases,"ipv4":true,"ipv6":true,"xdp":true,"tc":true,"sameMatcher":true,"longerPrefixIsolation":true,"delete":true,"checksums":true})
    );
    Ok(())
}
