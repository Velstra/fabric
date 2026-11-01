//! Actual production XDP gate, firewall and forward tail calls. No replacement
//! packet program: both valid and adversarial handshake frames enter `velstra`.
use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{Array, HashMap, ProgramArray},
    programs::{TestRun, TestRunOptions, Xdp},
};
use velstra_common::{
    Action, ConfigFlags, FlowKey, GlobalConfig, SynFlow, SynProxyCfg, SynProxyKey, ip_proto,
    tcp_flags::{ACK, FIN, RST, SYN},
};

const PSH: u8 = 0x08;
const URG: u8 = 0x20;
const CLIENT: [u8; 4] = [198, 51, 100, 9];
const SERVER: [u8; 4] = [192, 0, 2, 9];
const CLIENT_ISN: u32 = u32::MAX - 7;
const SERVER_ISN: u32 = u32::MAX - 3;

fn packet(client: bool, port: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let (src, dst, sport, dport) = if client {
        (CLIENT, SERVER, port, 443)
    } else {
        (SERVER, CLIENT, 443, port)
    };
    // Ethernet padding lets the proxy replace a 20-byte ACK with its MSS SYN.
    let mut bytes = vec![0u8; 64];
    bytes[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = ip_proto::TCP;
    bytes[26..30].copy_from_slice(&src);
    bytes[30..34].copy_from_slice(&dst);
    let sum = checksum(&bytes[14..34]);
    bytes[24..26].copy_from_slice(&sum.to_be_bytes());
    bytes[34..36].copy_from_slice(&sport.to_be_bytes());
    bytes[36..38].copy_from_slice(&dport.to_be_bytes());
    bytes[38..42].copy_from_slice(&seq.to_be_bytes());
    bytes[42..46].copy_from_slice(&ack.to_be_bytes());
    bytes[46] = 5 << 4;
    bytes[47] = flags;
    bytes[48..50].copy_from_slice(&64240u16.to_be_bytes());
    let sum = tcp_checksum(&bytes);
    bytes[50..52].copy_from_slice(&sum.to_be_bytes());
    bytes
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for part in bytes.chunks(2) {
        sum += u16::from_be_bytes([part[0], *part.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(frame: &[u8]) -> u16 {
    let total = u16::from_be_bytes(frame[16..18].try_into().unwrap()) as usize;
    let ihl = (frame[14] & 0x0f) as usize * 4;
    let mut pseudo = frame[26..34].to_vec();
    pseudo.extend_from_slice(&[0, ip_proto::TCP]);
    pseudo.extend_from_slice(&((total - ihl) as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[14 + ihl..14 + total]);
    checksum(&pseudo)
}

fn run(ebpf: &Ebpf, frame: &[u8]) -> Result<(u32, Vec<u8>)> {
    let mut output = vec![0u8; 128];
    let gate: &Xdp = ebpf.program("velstra").unwrap().try_into()?;
    let result = gate.test_run(TestRunOptions {
        data_in: Some(frame),
        data_out: Some(&mut output),
        ..TestRunOptions::new()
    })?;
    output.truncate(result.data_size_out as usize);
    Ok((result.return_value, output))
}

fn state(ebpf: &Ebpf, port: u16) -> Result<SynFlow> {
    let map: HashMap<_, FlowKey, SynFlow> = HashMap::try_from(ebpf.map("SYN_FLOWS").unwrap())?;
    Ok(map.get(
        &FlowKey::new(0, CLIENT, [0; 4], port, 443, ip_proto::TCP),
        0,
    )?)
}

fn proxy_fixture(install_secret: bool) -> Result<Ebpf> {
    let object =
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("missing packaged object")?;
    let mut ebpf = Ebpf::load_file(object)?;
    // This is the actual gate -> main -> forward program array, not a helper
    // that only exercises the pure state model in isolation.
    for name in ["velstra", "velstra_main", "velstra_forward"] {
        let program: &mut Xdp = ebpf.program_mut(name).unwrap().try_into()?;
        program.load().with_context(|| format!("loading {name}"))?;
    }
    for (slot, name) in [(0, "velstra_forward"), (1, "velstra_main")] {
        let program: &Xdp = ebpf.program(name).unwrap().try_into()?;
        let fd = program.fd()?.try_clone()?;
        ProgramArray::try_from(ebpf.map_mut("VELSTRA_PROGS").unwrap())?.set(slot, &fd, 0)?;
    }
    HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
        0,
        GlobalConfig::new(Action::Pass, ConfigFlags::STATEFUL),
        0,
    )?;
    if install_secret {
        let mut secret: Array<_, u64> = Array::try_from(ebpf.map_mut("SYN_SECRET").unwrap())?;
        secret.set(0, 0x0012_3456_78ab_cdef_u64, 0)?;
        secret.set(1, 0xfedc_ba98_7654_3210u64, 0)?;
    }
    HashMap::try_from(ebpf.map_mut("SYNPROXY").unwrap())?.insert(
        SynProxyKey::tcp(443),
        SynProxyCfg::new(1460),
        0,
    )?;

    Ok(ebpf)
}

#[test]
#[ignore = "requires the production ELF and CAP_BPF; run by the privileged kernel check"]
fn production_synproxy_server_handshake_validation() -> Result<()> {
    let mut ebpf = proxy_fixture(true)?;
    let mut checks = Vec::new();
    for stateful in [false, true] {
        HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
            0,
            GlobalConfig::new(
                Action::Pass,
                if stateful { ConfigFlags::STATEFUL } else { 0 },
            ),
            0,
        )?;
        for (index, (label, seq, ack, flags)) in [
            ("ack_before_client_syn", SERVER_ISN, CLIENT_ISN, SYN | ACK),
            (
                "ack_after_client_syn",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(2),
                SYN | ACK,
            ),
            ("ack_zero", SERVER_ISN, 0, SYN | ACK),
            ("server_syn_without_ack", SERVER_ISN, 0, SYN),
            (
                "unnegotiated_ece",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | 0x40,
            ),
            (
                "unnegotiated_cwr",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | 0x80,
            ),
            (
                "reset_syn_ack",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | RST,
            ),
            (
                "fin_syn_ack",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | FIN,
            ),
            (
                "push_syn_ack",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | PSH,
            ),
            (
                "urgent_syn_ack",
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK | URG,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let port = 42000 + index as u16 + if stateful { 100 } else { 0 };
            let (action, challenge) = run(&ebpf, &packet(true, port, CLIENT_ISN, 0, SYN))?;
            ensure!(
                action == 3 && challenge[47] == SYN | ACK,
                "no cookie challenge"
            );
            ensure!(checksum(&challenge[14..34]) == 0 && tcp_checksum(&challenge) == 0);
            let cookie = u32::from_be_bytes(challenge[38..42].try_into().unwrap());
            let (action, syn) = run(
                &ebpf,
                &packet(
                    true,
                    port,
                    CLIENT_ISN.wrapping_add(1),
                    cookie.wrapping_add(1),
                    ACK,
                ),
            )?;
            ensure!(
                action == 2 && syn[47] == SYN,
                "cookie did not open server half"
            );
            let pending = state(&ebpf, port)?;
            ensure!(!pending.is_spliced());
            let (action, _) = run(&ebpf, &packet(false, port, seq, ack, flags))?;
            let unchanged = state(&ebpf, port)? == pending;
            println!("SYNPROXY_NEGATIVE {label} action={action} unchanged={unchanged}");
            ensure!(
                action == 1 && unchanged,
                "{label} admitted or mutated pending state"
            );

            // The invalid answer must not poison the valid retry. Verify the
            // generated ACK on the wire, not merely the splice flag in the map.
            let answer = packet(
                false,
                port,
                SERVER_ISN,
                CLIENT_ISN.wrapping_add(1),
                SYN | ACK,
            );
            let (action, reply) = run(&ebpf, &answer)?;
            ensure!(action == 3 && reply[47] == ACK);
            ensure!(
                u32::from_be_bytes(reply[38..42].try_into().unwrap()) == CLIENT_ISN.wrapping_add(1)
            );
            ensure!(
                u32::from_be_bytes(reply[42..46].try_into().unwrap()) == SERVER_ISN.wrapping_add(1)
            );
            ensure!(checksum(&reply[14..34]) == 0 && tcp_checksum(&reply) == 0);
            let spliced = state(&ebpf, port)?;
            ensure!(spliced.is_spliced());
            let (action, retransmit) = run(&ebpf, &answer)?;
            ensure!(action == 3 && retransmit == reply && state(&ebpf, port)? == spliced);
            // A different ISN is not a retransmission of this server handshake.
            let (action, _) = run(
                &ebpf,
                &packet(
                    false,
                    port,
                    SERVER_ISN.wrapping_add(1),
                    CLIENT_ISN.wrapping_add(1),
                    SYN | ACK,
                ),
            )?;
            ensure!(
                action == 1 && state(&ebpf, port)? == spliced,
                "changed server ISN accepted"
            );
            let (action, _) = run(
                &ebpf,
                &packet(
                    false,
                    port,
                    SERVER_ISN,
                    CLIENT_ISN.wrapping_add(2),
                    SYN | ACK,
                ),
            )?;
            ensure!(
                action == 1 && state(&ebpf, port)? == spliced,
                "changed ACK accepted after splice"
            );
            // Check both live sequence-translation directions after the rejected
            // answers, including IP/TCP checksum validity.
            let (action, data) = run(
                &ebpf,
                &packet(
                    false,
                    port,
                    SERVER_ISN.wrapping_add(1),
                    CLIENT_ISN.wrapping_add(1),
                    ACK | PSH,
                ),
            )?;
            ensure!(
                action == 2
                    && u32::from_be_bytes(data[38..42].try_into().unwrap())
                        == cookie.wrapping_add(1)
            );
            ensure!(checksum(&data[14..34]) == 0 && tcp_checksum(&data) == 0);
            let (action, data) = run(
                &ebpf,
                &packet(
                    true,
                    port,
                    CLIENT_ISN.wrapping_add(1),
                    cookie.wrapping_add(1),
                    ACK,
                ),
            )?;
            ensure!(
                action == 2
                    && u32::from_be_bytes(data[42..46].try_into().unwrap())
                        == SERVER_ISN.wrapping_add(1)
            );
            ensure!(checksum(&data[14..34]) == 0 && tcp_checksum(&data) == 0);
            checks.push(serde_json::json!({"case":label,"stateful":stateful}));
        }
    }
    println!(
        "ACTUAL_SYNPROXY_HANDSHAKE {}",
        serde_json::json!({
            "result":"PASS", "productionGate":true, "negativeCases":checks,
            "invalidStateUnchanged":true, "validRetry":true, "retransmit":true,
            "sequenceWrap":true, "checksums":true, "changedServerIsnRejected":true, "bidirectionalTranslation":true, "statefulAndStateless":true
        })
    );
    Ok(())
}

fn flow_count(ebpf: &Ebpf) -> Result<usize> {
    let map: HashMap<_, FlowKey, u8> = HashMap::try_from(ebpf.map("FW_FLOWS").unwrap())?;
    Ok(map.iter().collect::<Result<Vec<_>, _>>()?.len())
}

#[test]
#[ignore = "requires the production ELF and CAP_BPF; run by the privileged kernel check"]
fn production_synproxy_protection_never_fails_open() -> Result<()> {
    let mut cases = Vec::new();
    for stateful in [false, true] {
        let mut ebpf = proxy_fixture(false)?;
        HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
            0,
            GlobalConfig::new(
                Action::Pass,
                if stateful { ConfigFlags::STATEFUL } else { 0 },
            ),
            0,
        )?;
        for client in [true, false] {
            let allocated = flow_count(&ebpf)?;
            let (action, _) = run(
                &ebpf,
                &packet(
                    client,
                    46000,
                    CLIENT_ISN,
                    0,
                    if client { SYN } else { SYN | ACK },
                ),
            )?;
            ensure!(
                action == 1,
                "configured proxy bypassed with no cookie secret: stateful={stateful}, client={client}, action={action}"
            );
            ensure!(
                flow_count(&ebpf)? == allocated,
                "missing-secret packet allocated firewall state"
            );
            ensure!(
                state(&ebpf, 46000).is_err(),
                "missing-secret packet allocated proxy state"
            );
            cases.push(
                serde_json::json!({"stateful":stateful,"client":client,"case":"missing_secret"}),
            );
        }
        // A missing proxy secret must not turn the appliance into a general
        // TCP outage. An unprotected port still follows its configured policy.
        let mut ordinary = packet(true, 46001, CLIENT_ISN, 0, SYN);
        ordinary[36..38].copy_from_slice(&8080u16.to_be_bytes());
        ordinary[50..52].fill(0);
        let sum = tcp_checksum(&ordinary);
        ordinary[50..52].copy_from_slice(&sum.to_be_bytes());
        ensure!(
            run(&ebpf, &ordinary)?.0 == 2,
            "unprotected service blocked by missing proxy secret"
        );
    }
    println!(
        "ACTUAL_SYNPROXY_FAIL_CLOSED {}",
        serde_json::json!({"result":"PASS","productionGate":true,"cases":cases,"unprotectedControl":true,"noLegacyOrProxyAllocation":true})
    );
    Ok(())
}

#[test]
#[ignore = "requires the production ELF and CAP_BPF; run by the privileged kernel check"]
fn production_synproxy_ipv4_options_cannot_bypass_protection() -> Result<()> {
    let mut cases = Vec::new();
    for stateful in [false, true] {
        let mut ebpf = proxy_fixture(true)?;
        HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
            0,
            GlobalConfig::new(
                Action::Pass,
                if stateful { ConfigFlags::STATEFUL } else { 0 },
            ),
            0,
        )?;
        for client in [true, false] {
            let mut frame = packet(
                client,
                47000,
                CLIENT_ISN,
                0,
                if client { SYN } else { SYN | ACK },
            );
            frame.splice(34..34, [1, 1, 1, 1]); // well-formed IPv4 NOP options
            frame[14] = 0x46;
            frame[16..18].copy_from_slice(&44u16.to_be_bytes());
            frame[24..26].fill(0);
            let sum = checksum(&frame[14..38]);
            frame[24..26].copy_from_slice(&sum.to_be_bytes());
            ensure!(checksum(&frame[14..38]) == 0 && tcp_checksum(&frame) == 0);
            let allocated = flow_count(&ebpf)?;
            ensure!(
                run(&ebpf, &frame)?.0 == 1,
                "IPv4 options bypassed configured proxy: stateful={stateful}, client={client}"
            );
            ensure!(
                flow_count(&ebpf)? == allocated,
                "unsupported proxy header allocated firewall state"
            );
            ensure!(
                state(&ebpf, 47000).is_err(),
                "unsupported header allocated proxy state"
            );
            // The same supported service remains usable immediately afterwards.
            let (action, challenge) = run(&ebpf, &packet(true, 47001, CLIENT_ISN, 0, SYN))?;
            ensure!(
                action == 3 && challenge[47] == SYN | ACK,
                "supported proxy challenge no longer works"
            );
            ensure!(checksum(&challenge[14..34]) == 0 && tcp_checksum(&challenge) == 0);
            ensure!(
                flow_count(&ebpf)? == allocated,
                "cookie challenge allocated firewall state"
            );
            cases.push(
                serde_json::json!({"stateful":stateful,"client":client,"case":"ipv4_options"}),
            );
        }
    }
    println!(
        "ACTUAL_SYNPROXY_OPTIONS_CLOSED {}",
        serde_json::json!({"result":"PASS","productionGate":true,"cases":cases,"supportedChallengeControl":true,"noLegacyOrProxyAllocation":true})
    );
    Ok(())
}

#[test]
#[ignore = "requires the production ELF and CAP_BPF; run by the privileged kernel check"]
fn production_synproxy_mss_negotiation_respects_client_limit() -> Result<()> {
    let mut cases = Vec::new();
    for stateful in [false, true] {
        let mut ebpf = proxy_fixture(true)?;
        HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
            0,
            GlobalConfig::new(
                Action::Pass,
                if stateful { ConfigFlags::STATEFUL } else { 0 },
            ),
            0,
        )?;
        for (index, (label, options, expected)) in [
            ("absent", &[][..], Some(536u16)),
            ("first", &[2, 4, 5, 180], Some(1460)),
            ("unaligned", &[1, 2, 4, 3, 132, 0, 0, 0], Some(536)),
            ("after_unknown", &[30, 3, 99, 2, 4, 5, 120, 0], Some(1400)),
            (
                "after_window_scale",
                &[3, 3, 7, 1, 2, 4, 5, 180],
                Some(1460),
            ),
            ("after_eol", &[0, 2, 4, 5], Some(536)),
            ("zero", &[2, 4, 0, 0], None),
            ("unrepresentable", &[2, 4, 2, 23], None),
            ("malformed_mss", &[2, 3, 5, 0], None),
            ("duplicate", &[2, 4, 5, 180, 2, 4, 5, 180], None),
            ("truncated", &[1, 2, 4, 5], None),
            ("malformed_unknown", &[30, 0, 1, 1], None),
        ]
        .into_iter()
        .enumerate()
        {
            let port = 48000 + index as u16;
            let mut frame = packet(true, port, CLIENT_ISN, 0, SYN);
            frame.splice(54..54, options.iter().copied());
            frame[46] = (((20 + options.len()) / 4) as u8) << 4;
            frame[16..18].copy_from_slice(&((40 + options.len()) as u16).to_be_bytes());
            frame[24..26].fill(0);
            let sum = checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&sum.to_be_bytes());
            frame[50..52].fill(0);
            let sum = tcp_checksum(&frame);
            frame[50..52].copy_from_slice(&sum.to_be_bytes());
            ensure!(checksum(&frame[14..34]) == 0 && tcp_checksum(&frame) == 0);
            let allocated = flow_count(&ebpf)?;
            let (action, challenge) = run(&ebpf, &frame)?;
            ensure!(
                flow_count(&ebpf)? == allocated,
                "{label}: unverified SYN allocated state"
            );
            ensure!(
                state(&ebpf, port).is_err(),
                "{label}: SYN allocated proxy state"
            );
            if let Some(expected) = expected {
                ensure!(
                    action == 3 && challenge[47] == SYN | ACK,
                    "{label}: no challenge (action {action})"
                );
                ensure!(checksum(&challenge[14..34]) == 0 && tcp_checksum(&challenge) == 0);
                let cookie = u32::from_be_bytes(challenge[38..42].try_into().unwrap());
                let (action, syn) = run(
                    &ebpf,
                    &packet(
                        true,
                        port,
                        CLIENT_ISN.wrapping_add(1),
                        cookie.wrapping_add(1),
                        ACK,
                    ),
                )?;
                ensure!(
                    action == 2 && syn[47] == SYN,
                    "{label}: cookie ACK did not open server half"
                );
                ensure!(checksum(&syn[14..34]) == 0 && tcp_checksum(&syn) == 0);
                ensure!(syn[54..56] == [2, 4]);
                let actual = u16::from_be_bytes(syn[56..58].try_into().unwrap());
                ensure!(
                    actual == expected,
                    "{label}: server was promised MSS {actual}, expected {expected}"
                );
            } else {
                ensure!(
                    action == 1,
                    "{label}: invalid MSS/header received a cookie or forwarded (action {action})"
                );
            }
            cases.push(serde_json::json!({"stateful":stateful,"case":label,"serverMss":expected}));
        }
    }
    println!(
        "ACTUAL_SYNPROXY_MSS {}",
        serde_json::json!({"result":"PASS","productionGate":true,"cases":cases,"wireMss":true,"checksums":true,"cookieAllocatesNoState":true,"ipv4Default":536,"minimumSupportedMss":536})
    );
    Ok(())
}
