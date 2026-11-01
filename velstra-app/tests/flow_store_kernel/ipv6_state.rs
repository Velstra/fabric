//! Executed in the privileged kernel VM using the production object and hooks.
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{
        Array, HashMap, ProgramArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{SchedClassifier, TestRun, TestRunOptions, Xdp},
};
use velstra::flow_store::FlowStore;
use velstra_common::{
    Action, ConfigFlags, FirewallFlowKey, FlowScope, FlowTimeouts, GlobalConfig, PORT_RULE_IN_ONLY,
    PORT_RULE_OUT_ONLY, RateBucket, ScopedSrcPortKey, ScopedSrcPortKey6, ip_proto, port_rule_value,
    port_rule_with_limit, tcp_flags,
};
const S: FlowScope = FlowScope {
    identity: 7,
    generation: 19,
};
const SRC: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const DST: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
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
fn rule_key(proto: u8, port: u16) -> Key<ScopedSrcPortKey6> {
    Key::new(
        ScopedSrcPortKey6::prefix_len(0),
        ScopedSrcPortKey6::with_ifindex(
            0,
            proto,
            0,
            if proto == 58 { 0 } else { port },
            0,
            [0; 16],
        ),
    )
}
fn remove_rule(bpf: &mut Ebpf, proto: u8, port: u16) -> Result<()> {
    let mut map =
        LpmTrie::<_, ScopedSrcPortKey6, u32>::try_from(bpf.map_mut("PORT_RULES6").unwrap())?;
    let mut key = rule_key(proto, port);
    let mut removed = false;
    for context in [2, 3] {
        key = Key::new(key.prefix_len(), key.data().in_context(context));
        removed |= map.remove(&key).is_ok();
    }
    ensure!(removed, "expected rule not present in either IPv6 context");
    Ok(())
}
fn rule(
    bpf: &mut Ebpf,
    proto: u8,
    tc: bool,
    action: Action,
    limit: bool,
    destination: u16,
) -> Result<()> {
    let mut key = rule_key(
        proto,
        if action == Action::Drop {
            destination
        } else {
            443
        },
    );
    key = Key::new(key.prefix_len(), key.data().in_context(2 | u32::from(tc)));
    let value = port_rule_value(action, false, 0)
        | if tc {
            PORT_RULE_OUT_ONLY
        } else {
            PORT_RULE_IN_ONLY
        };
    let value = if limit {
        port_rule_with_limit(value, 1)
    } else {
        value
    };
    LpmTrie::try_from(bpf.map_mut("PORT_RULES6").unwrap())?.insert(&key, value, 0)?;
    Ok(())
}
#[test]
#[ignore = "requires CAP_BPF; executed in privileged kernel VM"]
fn production_ipv6_protocol_state_and_rule_limits() -> Result<()> {
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
    let mut store = FlowStore::from_ebpf(&mut bpf)?;
    for tc in [false, true] {
        config(&mut bpf, true)?;
        for proto in [6, 17, 58] {
            rule(&mut bpf, proto, tc, Action::Pass, true, 443)?;
            Array::try_from(bpf.map_mut("RULE_LIMITS").unwrap())?.set(
                1,
                RateBucket::new(1, 1),
                0,
            )?;
            let port = 45000 + u16::from(proto) + u16::from(tc) * 100;
            let first = frame(proto, port, false, 100, 0, tcp_flags::SYN);
            ensure!(
                run(&bpf, tc, &first)?,
                "initial packet proto={proto} tc={tc}"
            );
            // Same flow must not spend another token, new tuples must.
            ensure!(run(&bpf, tc, &first)?, "retransmit throttled");
            ensure!(
                !run(
                    &bpf,
                    tc,
                    &frame(proto, port + 1, false, 100, 0, tcp_flags::SYN)
                )?,
                "new tuple bypassed limit"
            );
            ensure!(
                run(
                    &bpf,
                    !tc,
                    &frame(proto, port, true, 200, 101, tcp_flags::SYN | tcp_flags::ACK)
                )?,
                "reply denied proto={proto} tc={tc}"
            );
            rule(&mut bpf, proto, !tc, Action::Drop, false, port)?;
            ensure!(
                !run(
                    &bpf,
                    !tc,
                    &frame(proto, port, true, 200, 101, tcp_flags::SYN | tcp_flags::ACK)
                )?,
                "explicit denial overridden proto={proto} tc={tc}"
            );
            remove_rule(&mut bpf, proto, port)?;
            rule(&mut bpf, proto, tc, Action::Pass, true, 443)?;
            if proto == 6 {
                ensure!(
                    run(
                        &bpf,
                        tc,
                        &frame(proto, port, false, 101, 201, tcp_flags::ACK)
                    )?,
                    "final ACK"
                );
                let key = FirewallFlowKey::transport_v6(S, SRC, DST, port, 443, ip_proto::TCP)
                    .unwrap()
                    .0;
                let record = store.snapshot(&key)?;
                ensure!(record.state.valid_for(ip_proto::TCP));
                ensure!(
                    run(
                        &bpf,
                        !tc,
                        &frame(proto, port, true, 201, 101, tcp_flags::RST | tcp_flags::ACK)
                    )?,
                    "valid reset"
                );
                let closed = store.snapshot(&key)?;
                ensure!(closed.state.tcp_closed(), "reset was not tracked");
                // Final empty ACKs remain harmless during the short close
                // timeout, without renewing state. No further data may pass.
                ensure!(run(
                    &bpf,
                    !tc,
                    &frame(proto, port, true, 201, 101, tcp_flags::ACK)
                )?);
                ensure!(store.snapshot(&key)?.revision == closed.revision);
                let mut data = frame(proto, port, true, 201, 101, tcp_flags::ACK);
                data.push(42);
                data[18..20].copy_from_slice(&21u16.to_be_bytes());
                ensure!(
                    !run(&bpf, !tc, &data)?,
                    "reset connection still grants data"
                );
                ensure!(
                    !run(
                        &bpf,
                        tc,
                        &frame(proto, port, false, 9000, 0, tcp_flags::SYN)
                    )?,
                    "tuple reuse bypasses new-flow limit"
                );
            }
            remove_rule(&mut bpf, proto, 443)?;
        }
    }
    // Route/NPT paths often have the initiator above the responder in the
    // canonical address order. Exercise both orientations, with real ISNs and
    // an ACK carrying data, instead of assuming origin == canonical forward.
    for (index, reversed) in [false, true].into_iter().enumerate() {
        let port = 49000 + index as u16;
        config(&mut bpf, false)?;
        HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?.insert(
            0u32,
            GlobalConfig::new(Action::Pass, ConfigFlags::STATEFUL),
            0,
        )?;
        let orient = |mut packet: Vec<u8>| {
            if reversed {
                for i in 0..16 {
                    packet.swap(22 + i, 38 + i);
                }
            }
            packet
        };
        let syn = orient(frame(6, port, false, 0xb4313ca5, 0, tcp_flags::SYN));
        ensure!(run(&bpf, false, &syn)?, "reverse-origin SYN");
        let reply = orient(frame(
            6,
            port,
            true,
            0xf8e10904,
            0xb4313ca6,
            tcp_flags::SYN | tcp_flags::ACK,
        ));
        ensure!(run(&bpf, true, &reply)?, "reverse-origin SYNACK");
        let mut data = orient(frame(
            6,
            port,
            false,
            0xb4313ca6,
            0xf8e10905,
            tcp_flags::ACK,
        ));
        data.extend_from_slice(&[42; 87]);
        data[18..20].copy_from_slice(&107u16.to_be_bytes());
        ensure!(
            run(&bpf, false, &data)?,
            "reverse-origin data reversed={reversed}"
        );
    }
    verify_ipv4_egress_limit(&mut bpf)?;
    println!(
        "ACTUAL_IPV6_PROTOCOL_STATE {}",
        serde_json::json!({"result":"PASS","xdp":true,"tc":true,"tcp":true,"udp":true,"echo":true,"rateLimits":true,"resetRevokes":true,"explicitDenies":true})
    );
    Ok(())
}

// IPv4 still uses the legacy tuple store. This regression verifies outbound
// rule budgets without presenting that store as protocol-state qualification.
fn verify_ipv4_egress_limit(bpf: &mut Ebpf) -> Result<()> {
    for stateful in [false, true] {
        HashMap::try_from(bpf.map_mut("CONFIG").unwrap())?.insert(
            0u32,
            GlobalConfig::new(
                Action::Pass,
                if stateful { ConfigFlags::STATEFUL } else { 0 },
            ),
            0,
        )?;
        let key = Key::new(
            ScopedSrcPortKey::prefix_len(0),
            ScopedSrcPortKey::with_ifindex(0, 17, 0, 443, 0, 0).in_context(1),
        );
        LpmTrie::try_from(bpf.map_mut("PORT_RULES").unwrap())?.insert(
            &key,
            port_rule_with_limit(
                port_rule_value(Action::Pass, false, 0) | PORT_RULE_OUT_ONLY,
                1,
            ),
            0,
        )?;
        Array::try_from(bpf.map_mut("RULE_LIMITS").unwrap())?.set(1, RateBucket::new(1, 1), 0)?;
        let packet = |port: u16| {
            let mut p = vec![0u8; 42];
            p[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            p[14] = 0x45;
            p[16..18].copy_from_slice(&28u16.to_be_bytes());
            p[22] = 64;
            p[23] = 17;
            p[26..30].copy_from_slice(&[192, 0, 2, 1]);
            p[30..34].copy_from_slice(&[192, 0, 2, 2]);
            p[34..36].copy_from_slice(&port.to_be_bytes());
            p[36..38].copy_from_slice(&443u16.to_be_bytes());
            p[38..40].copy_from_slice(&8u16.to_be_bytes());
            p
        };
        let port = if stateful { 53100 } else { 53200 };
        ensure!(run(bpf, true, &packet(port))?, "first IPv4 egress packet");
        ensure!(
            !run(bpf, true, &packet(port + 1))?,
            "new IPv4 egress tuple bypassed limit"
        );
        ensure!(
            run(bpf, true, &packet(port))? == stateful,
            "IPv4 egress retransmit accounting stateful={stateful}"
        );
        LpmTrie::<_, ScopedSrcPortKey, u32>::try_from(bpf.map_mut("PORT_RULES").unwrap())?
            .remove(&key)?;
    }
    println!("ACTUAL_IPV4_EGRESS_RULE_LIMIT PASS legacyTupleStore=true");
    Ok(())
}
