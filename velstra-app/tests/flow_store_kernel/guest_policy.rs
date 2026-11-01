//! Real Ethernet frames across veths and the attached production XDP tunnel
//! datapath. The receiving socket is beyond the guest devmap redirect: a PASS
//! return value or a populated map alone cannot satisfy this test.
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::{
        Array, DevMap, HashMap, ProgramArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{Xdp, XdpMode},
};
use velstra_common::{
    Action, ConfigFlags, GlobalConfig, LocalMacKey, OverlayConfig, PORT_RULE_IN_ONLY,
    PORT_RULE_OUT_ONLY, PORT_RULE_V4_ONLY, PORT_RULE_V6_ONLY, ScopedAddr6, ScopedDstPortKey6,
    ScopedSrcPortKey, ScopedSrcPortKey6, Srv6Config, Srv6LocalSid, Srv6SidKey, encap_kind,
    icmp_type_probe, ip_proto, parse_mac, port_rule_value,
};

const POLICY: u32 = 7;
const VNI: u32 = 1042;
const GUEST_MAC: [u8; 6] = [2, 0, 0, 0, 0, 0x77];
const SRC: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const DST: [u8; 16] = [0x20, 1, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
const SID: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7];
const PEER: [u8; 16] = [0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];

struct Links {
    names: [String; 4],
}
impl Links {
    fn new() -> Result<Self> {
        let pid = std::process::id();
        let lab = Self {
            names: ['a', 'b', 'c', 'd'].map(|part| format!("vg{pid}{part}")),
        };
        for pair in lab.names.chunks(2) {
            ip(&[
                "link", "add", &pair[0], "type", "veth", "peer", "name", &pair[1],
            ])?;
        }
        ip(&["link", "set", &lab.names[3], "address", "02:00:00:00:00:77"])?;
        for name in &lab.names {
            ip(&["link", "set", name, "up"])?;
        }
        Ok(lab)
    }
    fn index(&self, index: usize) -> Result<u32> {
        Ok(
            std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", self.names[index]))?
                .trim()
                .parse()?,
        )
    }
    fn mac(&self, index: usize) -> Result<[u8; 6]> {
        Ok(parse_mac(
            std::fs::read_to_string(format!("/sys/class/net/{}/address", self.names[index]))?
                .trim(),
        )?)
    }
}
impl Drop for Links {
    fn drop(&mut self) {
        for name in [&self.names[0], &self.names[2]] {
            let _ = Command::new("ip")
                .args(["link", "del", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
fn ip(args: &[&str]) -> Result<()> {
    let output = Command::new("ip").args(args).output()?;
    ensure!(
        output.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

struct Wire(OwnedFd);
impl Wire {
    fn bind(index: u32) -> Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                3u16.to_be() as i32,
            )
        };
        ensure!(fd >= 0, "AF_PACKET: {}", std::io::Error::last_os_error());
        let socket = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let mut addr = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = 3u16.to_be();
        addr.sll_ifindex = index as i32;
        let result = unsafe {
            libc::bind(
                fd,
                (&addr as *const libc::sockaddr_ll).cast(),
                std::mem::size_of_val(&addr) as u32,
            )
        };
        ensure!(
            result == 0,
            "bind AF_PACKET: {}",
            std::io::Error::last_os_error()
        );
        Ok(socket)
    }
    fn send(&self, packet: &[u8]) -> Result<()> {
        let result =
            unsafe { libc::send(self.0.as_raw_fd(), packet.as_ptr().cast(), packet.len(), 0) };
        ensure!(
            result == packet.len() as isize,
            "send Ethernet frame: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn receives(&self, expected: &[u8], allowed: bool) -> Result<bool> {
        let deadline = Instant::now() + Duration::from_millis(if allowed { 2000 } else { 150 });
        let mut bytes = [0u8; 2048];
        while Instant::now() < deadline {
            let mut event = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut event, 1, 20) };
            ensure!(
                result >= 0,
                "poll Ethernet capture: {}",
                std::io::Error::last_os_error()
            );
            if result == 0 {
                continue;
            }
            let count = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    bytes.as_mut_ptr().cast(),
                    bytes.len(),
                    0,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    continue;
                }
                return Err(error.into());
            }
            if &bytes[..count as usize] == expected {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = bytes
        .chunks(2)
        .map(|p| u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)]) as u32)
        .sum::<u32>();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
fn inner(proto: u8, extension: bool, serial: u64) -> Vec<u8> {
    let mut l4 = vec![0u8; if proto == ip_proto::TCP { 28 } else { 16 }];
    if proto == ip_proto::ICMPV6 {
        l4[0] = 128;
        l4[4..6].copy_from_slice(&(serial as u16).to_be_bytes());
    } else {
        l4[..2].copy_from_slice(&(45000u16 + serial as u16).to_be_bytes());
        l4[2..4].copy_from_slice(&9000u16.to_be_bytes());
        if proto == ip_proto::TCP {
            l4[12] = 5 << 4;
            l4[13] = 2;
        } else {
            let len = l4.len() as u16;
            l4[4..6].copy_from_slice(&len.to_be_bytes());
        }
    }
    let end = l4.len();
    l4[end - 8..].copy_from_slice(&serial.to_be_bytes());
    let mut pseudo = SRC.to_vec();
    pseudo.extend_from_slice(&DST);
    pseudo.extend_from_slice(&(l4.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, proto]);
    pseudo.extend_from_slice(&l4);
    let cs = checksum(&pseudo);
    let cs = if proto == ip_proto::UDP && cs == 0 {
        u16::MAX
    } else {
        cs
    };
    let offset = if proto == ip_proto::TCP {
        16
    } else if proto == ip_proto::UDP {
        6
    } else {
        2
    };
    l4[offset..offset + 2].copy_from_slice(&cs.to_be_bytes());
    let mut frame = vec![0u8; 54];
    frame[..6].copy_from_slice(&GUEST_MAC);
    frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 0x88]);
    frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    frame[14] = 0x60;
    frame[21] = 64;
    frame[18..20]
        .copy_from_slice(&((l4.len() + if extension { 8 } else { 0 }) as u16).to_be_bytes());
    frame[20] = if extension { 60 } else { proto };
    frame[22..38].copy_from_slice(&SRC);
    frame[38..54].copy_from_slice(&DST);
    if extension {
        frame.extend_from_slice(&[proto, 0, 0, 0, 0, 0, 0, 0]);
    }
    frame.extend_from_slice(&l4);
    frame
}
fn outer(tunnel: &str, inner: &[u8], dest: [u8; 6], source: [u8; 6]) -> Vec<u8> {
    let srv6 = tunnel.starts_with("srv6");
    let mut frame = vec![0u8; if srv6 { 54 } else { 50 }];
    frame[..6].copy_from_slice(&dest);
    frame[6..12].copy_from_slice(&source);
    if srv6 {
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        frame[14] = 0x60;
        frame[21] = 64;
        frame[18..20].copy_from_slice(&(inner.len() as u16).to_be_bytes());
        frame[20] = 143;
        frame[22..38].copy_from_slice(&PEER);
        frame[38..54].copy_from_slice(&SID);
    } else {
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame[14] = 0x45;
        frame[22] = 64;
        frame[23] = 17;
        frame[16..18].copy_from_slice(&((36 + inner.len()) as u16).to_be_bytes());
        frame[26..30].copy_from_slice(&[10, 77, 0, 2]);
        frame[30..34].copy_from_slice(&[10, 77, 0, 1]);
        let cs = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&cs.to_be_bytes());
        frame[34..36].copy_from_slice(&45000u16.to_be_bytes());
        frame[36..38]
            .copy_from_slice(&(if tunnel == "geneve" { 6081u16 } else { 4789u16 }).to_be_bytes());
        frame[38..40].copy_from_slice(&((16 + inner.len()) as u16).to_be_bytes());
        if tunnel == "geneve" {
            frame[44..46].copy_from_slice(&0x6558u16.to_be_bytes());
        } else {
            frame[42] = 8;
        }
        frame[46..49].copy_from_slice(&VNI.to_be_bytes()[1..]);
    }
    frame.extend_from_slice(inner);
    frame
}
fn config(ebpf: &mut Ebpf, flags: u32) -> Result<()> {
    let scope = velstra_common::FlowScope {
        identity: 7,
        generation: 19,
    };
    HashMap::try_from(ebpf.map_mut("FW_POLICY").unwrap())?.insert(POLICY, scope, 0)?;
    HashMap::try_from(ebpf.map_mut("FW_TIMEOUT").unwrap())?.insert(
        scope,
        velstra_common::FlowTimeouts::DEFAULT,
        0,
    )?;
    HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
        POLICY,
        GlobalConfig::new(Action::Pass, flags),
        0,
    )?;
    Ok(())
}
fn src_rule(
    ebpf: &mut Ebpf,
    proto: u8,
    ifindex: u32,
    flags: u32,
    action: Option<Action>,
) -> Result<()> {
    let key = Key::new(
        ScopedSrcPortKey6::prefix_len(128),
        ScopedSrcPortKey6::with_ifindex(
            POLICY,
            proto,
            if proto == 58 { icmp_type_probe(128) } else { 0 },
            if proto == 58 { 0 } else { 9000 },
            ifindex,
            SRC,
        ),
    );
    let mut map =
        LpmTrie::<_, ScopedSrcPortKey6, u32>::try_from(ebpf.map_mut("PORT_RULES6").unwrap())?;
    for context in 0..4 {
        let exclude = if context & 2 == 0 {
            PORT_RULE_V6_ONLY
        } else {
            PORT_RULE_V4_ONLY
        } | if context & 1 == 0 {
            PORT_RULE_OUT_ONLY
        } else {
            PORT_RULE_IN_ONLY
        };
        let mut key = key;
        key = Key::new(key.prefix_len(), key.data().in_context(context));
        if let Some(action) = action {
            if flags & exclude == 0 {
                map.insert(&key, port_rule_value(action, false, 128) | flags, 0)?;
            }
        } else {
            let _ = map.remove(&key);
        }
    }
    Ok(())
}

fn datapath(lab: &Links) -> Result<Ebpf> {
    let object =
        std::env::var_os("VELSTRA_CONTROL_PRODUCTION_OBJECT").context("missing production ELF")?;
    let target = lab.index(2)?;
    let mut ebpf = Ebpf::load_file(object)?;
    for name in [
        "velstra",
        "velstra_main",
        "velstra_forward",
        "velstra_guest_delivery",
    ] {
        let program: &mut Xdp = ebpf.program_mut(name).unwrap().try_into()?;
        program
            .load()
            .with_context(|| format!("verifying {name}"))?;
    }
    for (index, name) in [
        (0, "velstra_forward"),
        (1, "velstra_main"),
        (2, "velstra_guest_delivery"),
    ] {
        let program: &Xdp = ebpf.program(name).unwrap().try_into()?;
        let fd = program.fd()?.try_clone()?;
        ProgramArray::try_from(ebpf.map_mut("VELSTRA_PROGS").unwrap())?.set(index, &fd, 0)?;
    }
    for (index, name) in [
        (0, "velstra_ipv6"),
        (1, "velstra_guest_ipv6"),
        (2, "velstra_state_v6"),
    ] {
        if ebpf.program(name).is_none() {
            continue;
        }
        let p: &mut Xdp = ebpf.program_mut(name).unwrap().try_into()?;
        p.load().with_context(|| format!("verifying {name}"))?;
        let fd = p.fd()?.try_clone()?;
        ProgramArray::try_from(ebpf.map_mut("VELSTRA_V6").unwrap())?.set(index, &fd, 0)?;
    }
    HashMap::try_from(ebpf.map_mut("IFACE_POLICY").unwrap())?.insert(target, POLICY, 0)?;
    HashMap::try_from(ebpf.map_mut("LOCAL_PORTS").unwrap())?.insert(
        LocalMacKey::new(VNI, GUEST_MAC),
        target,
        0,
    )?;
    HashMap::try_from(ebpf.map_mut("LOCAL_VNIS").unwrap())?.insert(VNI, 0u32, 0)?;
    HashMap::<_, [u8; 4], u8>::try_from(ebpf.map_mut("VTEP_PEERS").unwrap())?.insert(
        [10u8, 77, 0, 2],
        1u8,
        0,
    )?;
    HashMap::<_, [u8; 16], u8>::try_from(ebpf.map_mut("SRV6_PEERS").unwrap())?
        .insert(PEER, 1u8, 0)?;
    DevMap::try_from(ebpf.map_mut("TX_PORTS").unwrap())?.set(target, target, None, 0)?;
    let program: &mut Xdp = ebpf.program_mut("velstra").unwrap().try_into()?;
    program.attach(&lab.names[0], XdpMode::Skb)?;
    Ok(ebpf)
}

fn configure_tunnel(ebpf: &mut Ebpf, tunnel: &str, dest: [u8; 6]) -> Result<()> {
    let srv6 = tunnel.starts_with("srv6");
    Array::try_from(ebpf.map_mut("OVERLAY_CONFIG").unwrap())?.set(
        0,
        if srv6 {
            OverlayConfig::DISABLED
        } else {
            OverlayConfig::new(
                [10, 77, 0, 1],
                dest,
                if tunnel == "geneve" { 6081 } else { 4789 },
                if tunnel == "geneve" {
                    encap_kind::GENEVE
                } else {
                    encap_kind::VXLAN
                },
                1500,
            )
        },
        0,
    )?;
    Array::try_from(ebpf.map_mut("SRV6_CONFIG").unwrap())?.set(
        0,
        if srv6 {
            Srv6Config::new(SID, dest, 1500)
        } else {
            Srv6Config::DISABLED
        },
        0,
    )?;
    HashMap::try_from(ebpf.map_mut("SRV6_LOCAL_SIDS").unwrap())?.insert(
        Srv6SidKey::new(SID),
        Srv6LocalSid::new(
            VNI,
            if tunnel == "srv6-flood" {
                velstra_common::srv6::behavior::END_DT2M
            } else {
                velstra_common::srv6::behavior::END_DT2U
            },
        ),
        0,
    )?;
    Ok(())
}

#[test]
#[ignore = "requires production ELF, veth, CAP_BPF, CAP_NET_ADMIN and CAP_NET_RAW; run by the kernel VM"]
fn production_ipv6_decap_guest_policy() -> Result<()> {
    let lab = Links::new()?;
    let ingress = lab.index(0)?;
    let target = lab.index(2)?;
    let mut ebpf = datapath(&lab)?;
    let sender = Wire::bind(lab.index(1)?)?;
    let receiver = Wire::bind(lab.index(3)?)?;
    let (dest, source) = (lab.mac(0)?, lab.mac(1)?);
    let mut serial = 0u64;
    let mut checks = Vec::new();
    for tunnel in ["vxlan", "geneve", "srv6-unicast", "srv6-flood"] {
        configure_tunnel(&mut ebpf, tunnel, dest)?;
        for stateful in [false, true] {
            let flags = if stateful { ConfigFlags::STATEFUL } else { 0 };
            config(&mut ebpf, flags)?;
            let mut exercise = |name: &str,
                                proto: u8,
                                extension: bool,
                                allowed: bool|
             -> Result<()> {
                serial += 1;
                let mut expected = inner(proto, extension, serial);
                match name {
                    "invalid-version" => expected[14] = 0x40,
                    "truncated-payload" => {
                        expected[18..20].copy_from_slice(&65535u16.to_be_bytes())
                    }
                    "invalid-udp-length" => expected[58..60].copy_from_slice(&0u16.to_be_bytes()),
                    "truncated-extension" => expected[55] = 255,
                    _ => {}
                }
                sender.send(&outer(tunnel, &expected, dest, source))?;
                let delivered = receiver.receives(&expected, allowed)?;
                println!(
                    "IPV6_DECAP_CASE tunnel={tunnel} stateful={stateful} case={name} delivered={delivered} proto={proto} extension={extension}"
                );
                ensure!(
                    delivered == allowed,
                    "{tunnel} {name}: delivery {delivered}, expected {allowed}"
                );
                checks.push(serde_json::json!({"tunnel":tunnel,"stateful":stateful,"case":name,"allowed":allowed,"proto":proto,"extension":extension}));
                Ok(())
            };
            exercise("initial-positive", 17, false, true)?;
            for proto in [17, 6, 58] {
                src_rule(
                    &mut ebpf,
                    proto,
                    target,
                    PORT_RULE_OUT_ONLY | PORT_RULE_V6_ONLY,
                    Some(Action::Drop),
                )?;
                exercise("source-deny", proto, false, false)?;
                exercise("source-deny-extension", proto, true, false)?;
                src_rule(&mut ebpf, proto, target, 0, None)?;
                exercise("rule-removal", proto, false, true)?;
            }
            src_rule(
                &mut ebpf,
                17,
                ingress,
                PORT_RULE_OUT_ONLY,
                Some(Action::Drop),
            )?;
            exercise("other-interface", 17, false, true)?;
            src_rule(&mut ebpf, 17, ingress, 0, None)?;
            for mask in [PORT_RULE_IN_ONLY, PORT_RULE_V4_ONLY] {
                src_rule(&mut ebpf, 17, target, mask, Some(Action::Drop))?;
                exercise("excluded-direction-or-family", 17, false, true)?;
                src_rule(&mut ebpf, 17, target, 0, None)?;
            }
            let dkey = Key::new(
                ScopedDstPortKey6::prefix_len(128),
                ScopedDstPortKey6::new(POLICY, 17, 9000, DST).in_context(3),
            );
            LpmTrie::<_, ScopedDstPortKey6, u32>::try_from(ebpf.map_mut("DST_RULES6").unwrap())?
                .insert(
                    &dkey,
                    port_rule_value(Action::Drop, false, 128) | PORT_RULE_OUT_ONLY,
                    0,
                )?;
            exercise("destination-deny", 17, false, false)?;
            LpmTrie::<_, ScopedDstPortKey6, u32>::try_from(ebpf.map_mut("DST_RULES6").unwrap())?
                .remove(&dkey)?;
            let neutral = Key::new(
                ScopedSrcPortKey::prefix_len(0),
                ScopedSrcPortKey::new(POLICY, 17, 9000, 0).in_context(3),
            );
            LpmTrie::<_, ScopedSrcPortKey, u32>::try_from(ebpf.map_mut("PORT_RULES").unwrap())?
                .insert(
                    &neutral,
                    port_rule_value(Action::Drop, false, 0) | PORT_RULE_OUT_ONLY,
                    0,
                )?;
            exercise("family-neutral-deny", 17, false, false)?;
            LpmTrie::<_, ScopedSrcPortKey, u32>::try_from(ebpf.map_mut("PORT_RULES").unwrap())?
                .remove(&neutral)?;
            config(&mut ebpf, flags | ConfigFlags::EGRESS_DEFAULT_DROP)?;
            exercise("default-deny", 17, false, false)?;
            src_rule(
                &mut ebpf,
                17,
                target,
                PORT_RULE_OUT_ONLY,
                Some(Action::Pass),
            )?;
            exercise("allow-over-default-deny", 17, false, true)?;
            let blocked = Key::new(160, ScopedAddr6::new(POLICY, DST));
            LpmTrie::<_, ScopedAddr6, u32>::try_from(ebpf.map_mut("BLOCKLIST6").unwrap())?
                .insert(&blocked, 1u32, 0)?;
            exercise("destination-blocklist-over-allow", 17, false, false)?;
            LpmTrie::<_, ScopedAddr6, u32>::try_from(ebpf.map_mut("BLOCKLIST6").unwrap())?
                .remove(&blocked)?;
            src_rule(&mut ebpf, 17, target, 0, None)?;
            config(&mut ebpf, flags | ConfigFlags::DROP_ICMP)?;
            exercise("icmp-block", 58, false, false)?;
            config(&mut ebpf, flags)?;
            for name in [
                "invalid-version",
                "truncated-payload",
                "invalid-udp-length",
                "truncated-extension",
            ] {
                exercise(name, 17, name == "truncated-extension", false)?;
            }
            exercise("final-positive", 17, false, true)?;
        }
    }
    let negative_count = checks.iter().filter(|c| c["allowed"] == false).count();
    let statistics: aya::maps::PerCpuArray<_, u64> =
        aya::maps::PerCpuArray::try_from(ebpf.map("STATS").unwrap())?;
    let count = |counter: velstra_common::Counter| -> Result<u64> {
        Ok(statistics.get(&counter.index(), 0)?.iter().sum())
    };
    let drops = count(velstra_common::Counter::EgressDropped)?;
    let decaps =
        count(velstra_common::Counter::OverlayDecap)? + count(velstra_common::Counter::Srv6Decap)?;
    ensure!(
        drops >= negative_count as u64 && decaps >= checks.len() as u64,
        "missing packet/drop telemetry"
    );
    let names = lab.names.clone();
    drop(sender);
    drop(receiver);
    drop(ebpf);
    drop(lab);
    ensure!(
        names
            .iter()
            .all(|n| !std::path::Path::new("/sys/class/net").join(n).exists()),
        "veth cleanup incomplete"
    );
    println!(
        "ACTUAL_IPV6_DECAP_GUEST_POLICY {}",
        serde_json::json!({"result":"PASS","liveFrames":true,"tunnels":4,"statefulAndStateless":true,"packetCases":checks.len(),"negativeCases":negative_count,"dropCounter":drops,"decapCounter":decaps,"cleanup":true,"checks":checks})
    );
    Ok(())
}

/// A peer IP is not an ingress-port identity. Even when tenant address security
/// is disabled, a tenant must not inject an authenticated-looking tunnel into a
/// different segment. Verify delivery beyond the real XDP devmap redirect, then
/// change the port's role without reloading the program.
#[test]
#[ignore = "requires production ELF, veth, CAP_BPF, CAP_NET_ADMIN and CAP_NET_RAW; run by the kernel VM"]
fn production_tunnel_ingress_boundary() -> Result<()> {
    const INGRESS_POLICY: u32 = POLICY + 1;
    let lab = Links::new()?;
    let ingress = lab.index(0)?;
    let mut ebpf = datapath(&lab)?;
    HashMap::try_from(ebpf.map_mut("IFACE_POLICY").unwrap())?.insert(ingress, INGRESS_POLICY, 0)?;
    let sender = Wire::bind(lab.index(1)?)?;
    let receiver = Wire::bind(lab.index(3)?)?;
    let (dest, source) = (lab.mac(0)?, lab.mac(1)?);
    let mut checks = Vec::new();
    let mut serial = 0u64;
    for tunnel in ["vxlan", "geneve", "srv6-unicast", "srv6-flood"] {
        configure_tunnel(&mut ebpf, tunnel, dest)?;
        for stateful in [false, true] {
            let flags = if stateful { ConfigFlags::STATEFUL } else { 0 };
            config(&mut ebpf, flags)?;
            // The ingress policy deliberately denies ordinary traffic. Tunnel
            // termination is privileged underlay behavior, never a tenant ACL
            // exception. Destination policy remains accepting.
            HashMap::try_from(ebpf.map_mut("CONFIG").unwrap())?.insert(
                INGRESS_POLICY,
                GlobalConfig::new(Action::Drop, flags),
                0,
            )?;
            for (name, vni, allowed) in [
                ("underlay-initial", None, true),
                ("tenant-other-segment", Some(VNI + 1), false),
                ("tenant-same-segment", Some(VNI), false),
                ("underlay-explicit-zero", Some(0), true),
                ("tenant-after-underlay", Some(VNI + 1), false),
                ("underlay-role-removed", None, true),
            ] {
                let mut ports =
                    HashMap::<_, u32, u32>::try_from(ebpf.map_mut("IFACE_VNI").unwrap())?;
                if let Some(vni) = vni {
                    ports.insert(ingress, vni, 0)?;
                } else if ports.get(&ingress, 0).is_ok() {
                    ports.remove(&ingress)?;
                }
                serial += 1;
                let expected = inner(ip_proto::UDP, false, serial);
                sender.send(&outer(tunnel, &expected, dest, source))?;
                let delivered = receiver.receives(&expected, allowed)?;
                println!(
                    "TUNNEL_INGRESS_CASE tunnel={tunnel} stateful={stateful} case={name} delivered={delivered}"
                );
                ensure!(
                    delivered == allowed,
                    "{tunnel} {name}: delivery {delivered}, expected {allowed}"
                );
                checks.push(serde_json::json!({"tunnel":tunnel,"stateful":stateful,"case":name,"allowed":allowed}));
            }
        }
    }
    let statistics: aya::maps::PerCpuArray<_, u64> =
        aya::maps::PerCpuArray::try_from(ebpf.map("STATS").unwrap())?;
    let count = |counter: velstra_common::Counter| -> Result<u64> {
        Ok(statistics.get(&counter.index(), 0)?.iter().sum())
    };
    let decaps =
        count(velstra_common::Counter::OverlayDecap)? + count(velstra_common::Counter::Srv6Decap)?;
    let untrusted = count(velstra_common::Counter::OverlayDropUntrusted)?;
    ensure!(
        decaps == 24 && untrusted == 12,
        "unexpected ingress-boundary counters: decaps={decaps} untrusted={untrusted}"
    );
    let names = lab.names.clone();
    drop(sender);
    drop(receiver);
    drop(ebpf);
    drop(lab);
    ensure!(
        names
            .iter()
            .all(|name| !std::path::Path::new("/sys/class/net").join(name).exists()),
        "veth cleanup incomplete"
    );
    println!(
        "ACTUAL_TUNNEL_INGRESS_BOUNDARY {}",
        serde_json::json!({"result":"PASS","liveFrames":true,"tunnels":4,"statefulAndStateless":true,"packetCases":checks.len(),"negativeCases":24,"decapCounter":decaps,"untrustedCounter":untrusted,"cleanup":true,"checks":checks})
    );
    Ok(())
}
