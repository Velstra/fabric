use super::*;
const T: FlowTimeouts = FlowTimeouts::DEFAULT;
const F: FlowDirection = FlowDirection::Forward;
const R: FlowDirection = FlowDirection::Reverse;

#[test]
fn aggregated_tcp_parser_preserves_payload_and_sequence_wrap() {
    let mut head = [0u8; 20];
    let sequence = u32::MAX - 123;
    head[4..8].copy_from_slice(&sequence.to_be_bytes());
    head[12] = 5 << 4;
    head[13] = tcp_flags::ACK;
    for length in [65536, 70000, 262144, MAX_TCP_SEGMENT_LEN] {
        let packet = TcpSegment::parse_header(&head, length, |_| None).unwrap();
        assert_eq!(packet.payload_len as usize, length - 20);
        assert_eq!(packet.end(), sequence.wrapping_add((length - 20) as u32));
    }
    for length in [19, MAX_TCP_SEGMENT_LEN + 1, usize::MAX] {
        assert!(TcpSegment::parse_header(&head, length, |_| None).is_none());
    }
    head[12] = 6 << 4;
    let packet = TcpSegment::parse_header(&head, 262144, |_| Some(1)).unwrap();
    assert_eq!(packet.payload_len, 262120);
    head[13] = tcp_flags::SYN | tcp_flags::RST;
    assert!(TcpSegment::parse_header(&head, 262144, |_| Some(1)).is_none());
}

#[test]
fn aggregated_tcp_flow_tracks_full_span_and_preserves_invalid_state() {
    let client = u32::MAX - 1000;
    let server = 5000;
    let scaled = |flags, sequence, acknowledgement, payload_len| {
        FlowPacket::Tcp(TcpSegment {
            flags,
            sequence,
            acknowledgement,
            payload_len,
            window: 65535,
            window_scale: if flags & tcp_flags::SYN != 0 {
                4
            } else {
                TCP_NO_WINDOW_SCALE
            },
        })
    };
    let mut state = FirewallFlow::begin(scaled(tcp_flags::SYN, client, 0, 0), F, 1, 42, T).unwrap();
    step(
        &mut state,
        scaled(
            tcp_flags::SYN | tcp_flags::ACK,
            server,
            client.wrapping_add(1),
            0,
        ),
        R,
        2,
    );
    step(
        &mut state,
        scaled(tcp_flags::ACK, client.wrapping_add(1), server + 1, 0),
        F,
        3,
    );
    let payload = 262144;
    let end = client.wrapping_add(1).wrapping_add(payload);
    step(
        &mut state,
        scaled(tcp_flags::ACK, client.wrapping_add(1), server + 1, payload),
        F,
        4,
    );
    assert_eq!(state.tcp[0].end_sequence, end);
    step(&mut state, scaled(tcp_flags::ACK, server + 1, end, 0), R, 5);
    assert_eq!(state.tcp[0].acknowledged_sequence, end);
    let before = state;
    assert_eq!(
        state.observe(
            ip_proto::TCP,
            scaled(
                tcp_flags::ACK,
                end.wrapping_add(2_000_000),
                server + 1,
                262144
            ),
            F,
            6,
            T
        ),
        FlowObservation::Unchanged
    );
    assert_eq!(
        state, before,
        "out-of-window aggregates must not renew state"
    );
    assert_eq!(
        state.observe(
            ip_proto::TCP,
            scaled(tcp_flags::ACK, end, server + 1, u32::MAX),
            F,
            7,
            T
        ),
        FlowObservation::Invalid
    );
    assert_eq!(
        state, before,
        "ambiguous sequence lengths must not renew state"
    );
}
fn p(flags: u8, sequence: u32, acknowledgement: u32, payload_len: u32) -> FlowPacket {
    FlowPacket::Tcp(TcpSegment {
        flags,
        sequence,
        acknowledgement,
        payload_len,
        window: 65535,
        window_scale: TCP_NO_WINDOW_SCALE,
    })
}
fn step(s: &mut FirewallFlow, packet: FlowPacket, direction: FlowDirection, now: u64) {
    assert_eq!(
        s.observe(ip_proto::TCP, packet, direction, now, T),
        FlowObservation::Tracked
    );
}
fn established_at(a: u32, b: u32) -> FirewallFlow {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, a, 0, 0), F, 1, 42, T).unwrap();
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, b, a.wrapping_add(1), 0),
        R,
        2,
    );
    step(
        &mut s,
        p(tcp_flags::ACK, a.wrapping_add(1), b.wrapping_add(1), 0),
        F,
        3,
    );
    assert!(s.tcp_established());
    s
}
fn established() -> FirewallFlow {
    established_at(1000, 5000)
}
#[test]
fn layout_is_padding_free() {
    assert_eq!(core::mem::size_of::<TcpSegment>(), 16);
    assert_eq!(core::mem::size_of::<FirewallFlow>(), 80);
    assert_eq!(core::mem::align_of::<FirewallFlow>(), 8);
}
#[test]
fn rejects_unsolicited_openers_and_invalid_parameters() {
    for flags in [
        0,
        tcp_flags::ACK,
        tcp_flags::RST,
        tcp_flags::SYN | tcp_flags::ACK,
        tcp_flags::SYN | tcp_flags::FIN,
        tcp_flags::SYN | tcp_flags::RST,
    ] {
        assert_eq!(FirewallFlow::begin(p(flags, 1000, 0, 0), F, 1, 42, T), None);
    }
    assert_eq!(
        FirewallFlow::begin(FlowPacket::EchoReply, F, 1, 42, T),
        None
    );
    assert_eq!(FirewallFlow::begin(FlowPacket::Udp, F, 1, 0, T), None);
    let mut t = T;
    t.echo_ms = 0;
    assert_eq!(FirewallFlow::begin(FlowPacket::Udp, F, 1, 42, t), None);
}
#[test]
fn canonical_origin_can_be_either_direction() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), R, 1, 42, T).unwrap();
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        F,
        2,
    );
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 0), R, 3);
    assert!(s.tcp_established());
}
#[test]
fn retransmissions_final_ack_loss_and_simultaneous_open() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    step(&mut s, p(tcp_flags::SYN, 1000, 0, 0), F, 2);
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        R,
        3,
    );
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        R,
        4,
    );
    assert!(!s.tcp_established());
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 0), F, 5);
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        R,
        6,
    );
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    step(&mut s, p(tcp_flags::SYN, 5000, 0, 0), R, 2);
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 1000, 5001, 0),
        F,
        3,
    );
    assert!(!s.tcp_established());
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        R,
        4,
    );
    assert!(s.tcp_established());
}
#[test]
fn new_isn_requires_a_new_admission_even_while_pending() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    let before = s;
    assert_eq!(
        s.observe(ip_proto::TCP, p(tcp_flags::SYN, 2000, 0, 0), F, 2, T),
        FlowObservation::PolicyRequired
    );
    assert_eq!(s, before);
    let mut s = established();
    let before = s;
    for d in [F, R] {
        assert_eq!(
            s.observe(ip_proto::TCP, p(tcp_flags::SYN, 1001, 0, 0), d, 4, T),
            FlowObservation::PolicyRequired
        );
        assert_eq!(s, before);
    }
}
#[test]
fn invalid_reset_cannot_shorten_or_refresh_a_live_connection() {
    let mut s = established();
    let before = s;
    for (seq, ack, flags) in [
        (1002, 0, tcp_flags::RST),
        (1001, 9000, tcp_flags::RST | tcp_flags::ACK),
    ] {
        assert_eq!(
            s.observe(ip_proto::TCP, p(flags, seq, ack, 0), F, 4, T),
            FlowObservation::Unchanged
        );
        assert_eq!(s, before);
    }
    step(
        &mut s,
        p(tcp_flags::RST | tcp_flags::ACK, 1001, 5001, 0),
        F,
        5,
    );
    assert!(s.tcp_closed());
    assert_eq!(s.expires_at_ms, 5 + T.tcp_closed_ms as u64);
}
#[test]
fn pending_reset_must_acknowledge_an_actual_syn() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    let before = s;
    for ack in [1000, 1002, u32::MAX] {
        assert_eq!(
            s.observe(
                ip_proto::TCP,
                p(tcp_flags::RST | tcp_flags::ACK, 0, ack, 0),
                R,
                2,
                T
            ),
            FlowObservation::Unchanged
        );
        assert_eq!(s, before);
    }
    step(&mut s, p(tcp_flags::RST | tcp_flags::ACK, 0, 1001, 0), R, 3);
    assert!(s.tcp_closed());
}
#[test]
fn half_close_keeps_response_data_and_closes_after_both_fin_acks() {
    let mut s = established();
    step(
        &mut s,
        p(tcp_flags::FIN | tcp_flags::ACK, 1001, 5001, 0),
        F,
        4,
    );
    step(&mut s, p(tcp_flags::ACK, 5001, 1002, 25), R, 5);
    assert!(!s.tcp_closed());
    step(
        &mut s,
        p(tcp_flags::FIN | tcp_flags::ACK, 5026, 1002, 0),
        R,
        6,
    );
    assert!(!s.tcp_closed());
    step(&mut s, p(tcp_flags::ACK, 1002, 5027, 0), F, 7);
    assert!(s.tcp_closed());
    assert_eq!(s.expires_at_ms, 7 + T.tcp_closed_ms as u64);
    let before = s;
    assert_eq!(
        s.observe(ip_proto::TCP, p(tcp_flags::ACK, 1002, 5027, 0), F, 8, T),
        FlowObservation::Unchanged
    );
    assert_eq!(s, before);
}
#[test]
fn unacknowledged_or_inconsistent_fin_does_not_close_a_flow() {
    let mut s = established();
    step(
        &mut s,
        p(tcp_flags::FIN | tcp_flags::ACK, 1001, 5001, 0),
        F,
        4,
    );
    let before = s;
    assert_eq!(
        s.observe(
            ip_proto::TCP,
            p(tcp_flags::FIN | tcp_flags::ACK, 1100, 5001, 0),
            F,
            5,
            T
        ),
        FlowObservation::Unchanged
    );
    assert_eq!(s, before);
    assert_eq!(
        s.observe(ip_proto::TCP, p(tcp_flags::ACK, 5001, 2000, 0), R, 5, T),
        FlowObservation::Unchanged
    );
    assert_eq!(s, before);
    assert!(!s.tcp_closed());
}
#[test]
fn old_ack_reordering_and_sequence_wrap_do_not_reset_progress() {
    let mut s = established_at(u32::MAX - 10, u32::MAX - 20);
    step(
        &mut s,
        p(tcp_flags::ACK, u32::MAX - 9, u32::MAX - 19, 100),
        F,
        4,
    );
    step(&mut s, p(tcp_flags::ACK, u32::MAX - 19, 90, 0), R, 5);
    let end = s.tcp[0].end_sequence;
    assert_eq!(end, 90);
    step(
        &mut s,
        p(tcp_flags::ACK, u32::MAX - 19, u32::MAX - 9, 0),
        R,
        6,
    );
    assert_eq!(s.tcp[0].acknowledged_sequence, 90);
    assert_eq!(s.tcp[0].end_sequence, end);
}
#[test]
fn fast_open_allows_partial_syn_payload_acknowledgement() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 20), F, 1, 42, T).unwrap();
    step(
        &mut s,
        p(tcp_flags::SYN | tcp_flags::ACK, 5000, 1001, 0),
        R,
        2,
    );
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 20), F, 3);
    assert!(s.tcp_established());
    step(&mut s, p(tcp_flags::ACK, 5001, 1021, 0), R, 4);
}
#[test]
fn window_scaling_requires_both_syn_options_and_zero_window_probes_survive() {
    let syn = FlowPacket::Tcp(TcpSegment {
        flags: tcp_flags::SYN,
        sequence: 1000,
        acknowledgement: 0,
        payload_len: 0,
        window: 0,
        window_scale: 14,
    });
    let mut s = FirewallFlow::begin(syn, F, 1, 42, T).unwrap();
    let synack = FlowPacket::Tcp(TcpSegment {
        flags: tcp_flags::SYN | tcp_flags::ACK,
        sequence: 5000,
        acknowledgement: 1001,
        payload_len: 0,
        window: 65535,
        window_scale: 14,
    });
    step(&mut s, synack, R, 2);
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 0), F, 3);
    assert_eq!(s.tcp[0].max_window, 65535 << 14);
    // The normal ACK advertises a window; test a probe immediately before ACK.
    step(&mut s, p(tcp_flags::ACK, 1000, 5001, 1), F, 4);
}
#[test]
fn invalid_and_expired_observations_never_mutate_an_incarnation() {
    let mut s = established();
    let before = s;
    assert_eq!(
        s.observe(ip_proto::TCP, p(0, 1001, 0, 0), F, 4, T),
        FlowObservation::Invalid
    );
    assert_eq!(s, before);
    assert_eq!(
        s.observe(
            ip_proto::TCP,
            p(tcp_flags::ACK, 1001, 5001, 0),
            F,
            s.expires_at_ms,
            T
        ),
        FlowObservation::PolicyRequired
    );
    assert_eq!(s, before);
}
#[test]
fn delayed_cpu_observations_never_rewind_the_idle_clock() {
    let mut s = established();
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 0), F, 50);
    let expires = s.expires_at_ms;
    step(&mut s, p(tcp_flags::ACK, 1001, 5001, 0), F, 25);
    assert_eq!(s.last_seen_ms, 50);
    assert_eq!(s.expires_at_ms, expires);
}
#[test]
fn udp_and_echo_lifetimes_are_direction_bound() {
    let mut udp = FirewallFlow::begin(FlowPacket::Udp, R, 1, 42, T).unwrap();
    assert_eq!(udp.expires_at_ms, 1 + T.udp_unreplied_ms as u64);
    assert_eq!(
        udp.observe(ip_proto::UDP, FlowPacket::Udp, F, 2, T),
        FlowObservation::Tracked
    );
    assert_eq!(udp.expires_at_ms, 2 + T.udp_replied_ms as u64);
    for proto in [ip_proto::ICMP, ip_proto::ICMPV6] {
        let mut echo = FirewallFlow::begin(FlowPacket::EchoRequest, F, 1, 42, T).unwrap();
        let before = echo;
        assert_eq!(
            echo.observe(proto, FlowPacket::EchoReply, F, 2, T),
            FlowObservation::Invalid
        );
        assert_eq!(echo, before);
        assert_eq!(
            echo.observe(proto, FlowPacket::EchoReply, R, 2, T),
            FlowObservation::Tracked
        );
    }
}

struct CapturedFlow {
    name: &'static str,
    family: u8,
    packets: &'static [(u64, &'static str)],
}

include!("firewall_capture_fixture.rs");

#[test]
fn real_linux_ipv4_ipv6_captures_replay_without_losing_a_valid_connection() {
    use crate::{FirewallFlowKey, FlowScope};
    for captured in CAPTURED_FLOWS {
        let (name, family, frames) = (captured.name, captured.family, captured.packets);
        let mut state = None;
        let mut expected_key = None;
        for (index, (ms, hex)) in frames.iter().enumerate() {
            let raw: std::vec::Vec<u8> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let scope = FlowScope {
                identity: 1,
                generation: 2,
            };
            let (key, direction, bytes) = if family == 4 {
                let hlen = (raw[14] & 15) as usize * 4;
                let len = u16::from_be_bytes([raw[16], raw[17]]) as usize;
                let off = 14 + hlen;
                let src = [raw[26], raw[27], raw[28], raw[29]];
                let dst = [raw[30], raw[31], raw[32], raw[33]];
                let sport = u16::from_be_bytes([raw[off], raw[off + 1]]);
                let dport = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
                let (key, direction) =
                    FirewallFlowKey::transport_v4(scope, src, dst, sport, dport, ip_proto::TCP)
                        .unwrap();
                (key, direction, &raw[off..14 + len])
            } else {
                let len = u16::from_be_bytes([raw[18], raw[19]]) as usize;
                let src: [u8; 16] = raw[22..38].try_into().unwrap();
                let dst: [u8; 16] = raw[38..54].try_into().unwrap();
                let sport = u16::from_be_bytes([raw[54], raw[55]]);
                let dport = u16::from_be_bytes([raw[56], raw[57]]);
                let (key, direction) =
                    FirewallFlowKey::transport_v6(scope, src, dst, sport, dport, ip_proto::TCP)
                        .unwrap();
                (key, direction, &raw[54..54 + len])
            };
            let packet = TcpSegment::parse(bytes).unwrap();
            if let Some(expected) = expected_key {
                assert_eq!(key, expected);
            } else {
                expected_key = Some(key);
            }
            let packet = FlowPacket::Tcp(packet);
            if let Some(ref mut state) = state {
                let result =
                    FirewallFlow::observe(state, ip_proto::TCP, packet, direction, ms + 1, T);
                assert!(
                    matches!(
                        result,
                        FlowObservation::Tracked | FlowObservation::Unchanged
                    ),
                    "{name} IPv{family} packet {index} at {ms}ms: {packet:?}: {result:?}, {state:?}"
                );
            } else {
                state = FirewallFlow::begin(packet, direction, ms + 1, 42, T);
                assert!(state.is_some());
            }
            let current = state.as_ref().unwrap();
            assert!(
                current.valid_for(ip_proto::TCP),
                "{name} IPv{family} packet {index}: invalid snapshot"
            );
            let wire = current.export(ip_proto::TCP, ms + 1, T).unwrap();
            let imported = FirewallFlow::import(wire, ip_proto::TCP, 17, 0, T).unwrap();
            assert_eq!(imported.tcp, current.tcp);
            assert_eq!(imported.flags, current.flags);
            assert_eq!(imported.expires_at_ms - 17, wire.remaining_ms as u64);
        }
        let state = state.unwrap();
        assert!(
            state.tcp_established() || state.tcp_closed(),
            "{name} IPv{family}"
        );
        assert!(
            state.tcp_closed(),
            "{name} IPv{family}: complete recorded teardown was not observed: {state:?}"
        );
    }
}

#[test]
fn incremental_tcp_options_require_completion_and_keep_failures_sticky() {
    let mut bytes = [0u8; 28];
    bytes[12] = 7 << 4;
    bytes[13] = tcp_flags::SYN;
    bytes[20..24].copy_from_slice(&[3, 3, 12, 0]);
    let head = bytes[..20].try_into().unwrap();
    let mut parser = TcpHeaderParser::new(head, bytes.len()).unwrap();
    assert!(parser.finish().is_none());
    for _ in 0..3 {
        assert!(parser.step(|offset| bytes.get(offset).copied()));
        assert!(parser.finish().is_none());
    }
    assert!(!parser.step(|offset| bytes.get(offset).copied()));
    assert_eq!(parser.finish(), TcpSegment::parse(&bytes));
    assert_eq!(parser.finish().unwrap().window_scale, 12);
    assert!(!parser.step(|_| panic!("completed parser read more bytes")));

    let mut unavailable = TcpHeaderParser::new(head, bytes.len()).unwrap();
    assert!(!unavailable.step(|_| None));
    assert!(unavailable.finish().is_none());
    assert!(!unavailable.step(|_| panic!("failed parser resumed")));
    assert!(unavailable.finish().is_none());
}

#[test]
fn tcp_parser_rejects_truncated_headers_and_malformed_options() {
    for length in 0..20 {
        assert!(TcpSegment::parse(&std::vec![0;length]).is_none());
    }
    let mut bytes = [0u8; 28];
    bytes[12] = 7 << 4;
    bytes[13] = tcp_flags::SYN;
    bytes[20..24].copy_from_slice(&[3, 3, 15, 0]);
    assert_eq!(TcpSegment::parse(&bytes).unwrap().window_scale, 14);
    bytes[23..27].copy_from_slice(&[3, 3, 7, 0]);
    assert!(TcpSegment::parse(&bytes).is_none());
    bytes[20..28].copy_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]);
    assert!(TcpSegment::parse(&bytes).is_none());
    bytes[20..28].copy_from_slice(&[2, 9, 0, 0, 0, 0, 0, 0]);
    assert!(TcpSegment::parse(&bytes).is_none());
}

#[test]
fn rejected_handshake_ack_does_not_mutate_or_admit_a_pending_flow() {
    let mut s = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    let before = s;
    assert_eq!(
        s.observe(
            ip_proto::TCP,
            p(tcp_flags::SYN | tcp_flags::ACK, 5000, 2000, 0),
            R,
            2,
            T
        ),
        FlowObservation::Invalid
    );
    assert_eq!(s, before);
}

#[test]
fn ha_round_trip_uses_remaining_lifetime_between_different_uptimes() {
    let primary = established();
    let wire = primary.export(ip_proto::TCP, 1000, T).unwrap();
    let imported = FirewallFlow::import(wire, ip_proto::TCP, 50, 5, T).unwrap();
    assert_eq!(imported.incarnation, primary.incarnation);
    assert_eq!(imported.expires_at_ms, 50 + wire.remaining_ms as u64 - 5);
    assert_eq!(imported.last_seen_ms, 0);
    assert_eq!(imported.tcp, primary.tcp);
    assert!(imported.tcp_established());
    let imported = FirewallFlow::import(wire, ip_proto::TCP, 90_000_000, 5, T).unwrap();
    assert_eq!(
        imported.expires_at_ms - 90_000_000,
        wire.remaining_ms as u64 - 5
    );
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 50, wire.remaining_ms, T).is_none());
}

#[test]
fn ha_import_rejects_forged_flags_windows_and_oversized_permissions() {
    let primary = established();
    let original = primary.export(ip_proto::TCP, 4, T).unwrap();
    let mut wire = original;
    wire.flags |= 1 << 31;
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 100, 0, T).is_none());
    let mut wire = original;
    wire.tcp[0].scale = 32;
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 100, 0, T).is_none());
    let mut wire = original;
    wire.tcp[0].max_window = u32::MAX;
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 100, 0, T).is_none());
    let mut wire = original;
    wire.remaining_ms = T.tcp_established_ms + 1;
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 100, 0, T).is_none());
    let mut wire = original;
    wire.incarnation = 0;
    assert!(FirewallFlow::import(wire, ip_proto::TCP, 100, 0, T).is_none());
    assert!(FirewallFlow::import(original, ip_proto::UDP, 100, 0, T).is_none());
    assert!(
        primary
            .export(ip_proto::TCP, primary.expires_at_ms, T)
            .is_none()
    );
}

#[test]
fn complete_close_snapshots_remain_structurally_valid() {
    // Export/import does not depend on the absolute uptime or enum layout.
    let mut s = established();
    assert!(s.valid_for(ip_proto::TCP));
    step(
        &mut s,
        p(tcp_flags::FIN | tcp_flags::ACK, 1001, 5001, 0),
        F,
        4,
    );
    assert!(s.valid_for(ip_proto::TCP));
    step(&mut s, p(tcp_flags::ACK, 5001, 1002, 0), R, 5);
    assert!(s.valid_for(ip_proto::TCP));
    step(
        &mut s,
        p(tcp_flags::FIN | tcp_flags::ACK, 5001, 1002, 0),
        R,
        6,
    );
    step(&mut s, p(tcp_flags::ACK, 1002, 5002, 0), F, 7);
    assert!(s.valid_for(ip_proto::TCP));
    assert!(s.export(ip_proto::TCP, 8, T).is_some());
}

#[test]
fn option_scanner_never_reads_beyond_the_declared_header() {
    let mut random = 0x12345678u32;
    for round in 0..10_000 {
        let header_len = 20 + (round % 11) * 4;
        let mut bytes = [0u8; 60];
        for b in &mut bytes {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            *b = random as u8;
        }
        bytes[12] = (header_len as u8 / 4) << 4;
        bytes[13] = tcp_flags::SYN;
        let head: &[u8; 20] = bytes[..20].try_into().unwrap();
        let _ = TcpSegment::parse_header(head, header_len, |offset| {
            assert!((20..header_len).contains(&offset));
            Some(bytes[offset])
        });
    }
}

#[test]
fn maximum_nop_padding_and_last_window_scale_option_parse() {
    let mut bytes = [1u8; 60];
    bytes[12] = 15 << 4;
    bytes[13] = tcp_flags::SYN;
    assert_eq!(
        TcpSegment::parse(&bytes).unwrap().window_scale,
        TCP_NO_WINDOW_SCALE
    );
    bytes[57..60].copy_from_slice(&[3, 3, 14]);
    assert_eq!(TcpSegment::parse(&bytes).unwrap().window_scale, 14);
    bytes[58] = 4;
    assert!(TcpSegment::parse(&bytes).is_none());
}

#[test]
fn timeout_changes_do_not_reanimate_or_extend_an_idle_grant() {
    let mut s = established();
    let before = s;
    let mut shorter = T;
    shorter.tcp_established_ms = 1000;
    assert_eq!(
        s.observe(
            ip_proto::TCP,
            p(tcp_flags::ACK, 1001, 5001, 0),
            F,
            1004,
            shorter
        ),
        FlowObservation::PolicyRequired
    );
    assert_eq!(s, before);
    let mut pending = FirewallFlow::begin(p(tcp_flags::SYN, 1000, 0, 0), F, 1, 42, T).unwrap();
    let mut longer = T;
    longer.tcp_pending_ms = T.tcp_established_ms;
    assert_eq!(
        pending.observe(
            ip_proto::TCP,
            p(tcp_flags::SYN, 1000, 0, 0),
            F,
            70_000,
            longer
        ),
        FlowObservation::PolicyRequired
    );
}

#[test]
fn snapshot_export_clamps_a_shortened_configuration_without_mutating_state() {
    let s = established();
    let before = s;
    let mut shorter = T;
    shorter.tcp_established_ms = 1000;
    let wire = s.export(ip_proto::TCP, 1000, shorter).unwrap();
    assert_eq!(wire.remaining_ms, 3);
    assert_eq!(wire.idle_ms, 997);
    assert_eq!(s, before);
    assert!(s.export(ip_proto::TCP, 1004, shorter).is_none());
    let imported = FirewallFlow::import(wire, ip_proto::TCP, 90_000, 2, shorter).unwrap();
    assert_eq!(imported.expires_at_ms, 90_001);
}

#[test]
fn importing_into_a_newer_boot_preserves_remote_idle_age_and_timeout_shrink() {
    let original = established().export(ip_proto::TCP, 1000, T).unwrap();
    assert_eq!(original.idle_ms, 997);
    let mut imported = FirewallFlow::import(original, ip_proto::TCP, 50, 5, T).unwrap();
    let again = imported.export(ip_proto::TCP, 50, T).unwrap();
    assert_eq!(again.idle_ms, 1002, "peer activity may predate our boot");
    assert_eq!(again.remaining_ms, original.remaining_ms - 5);
    let shorter = FlowTimeouts {
        tcp_established_ms: 100,
        ..T
    };
    assert!(imported.export(ip_proto::TCP, 50, shorter).is_none());
    // Real traffic resets the imported pre-boot age, not the peer's clock.
    step(&mut imported, p(tcp_flags::ACK, 1001, 5001, 0), F, 60);
    assert_eq!(imported.export(ip_proto::TCP, 60, T).unwrap().idle_ms, 0);
    assert!(imported.export(ip_proto::TCP, 60, shorter).is_some());
}

#[test]
fn reserved_slot_initialization_rejects_invalid_openers_without_clobbering_state() {
    let initial = FirewallFlow::begin(FlowPacket::Udp, F, 100, 77, T).unwrap();
    for packet in [
        FlowPacket::EchoReply,
        FlowPacket::Tcp(TcpSegment {
            sequence: 1,
            acknowledgement: 0,
            payload_len: 0,
            window: 100,
            flags: tcp_flags::ACK,
            window_scale: TCP_NO_WINDOW_SCALE,
        }),
    ] {
        let mut state = initial;
        assert!(!state.begin_into(packet, R, 200, 78, T));
        assert_eq!(state, initial);
    }
    for (incarnation, timeouts) in [(0, T), (78, FlowTimeouts { echo_ms: 0, ..T })] {
        let mut state = initial;
        assert!(!state.begin_into(FlowPacket::Udp, R, 200, incarnation, timeouts));
        assert_eq!(state, initial);
    }
    let mut state = initial;
    assert!(state.begin_into(FlowPacket::EchoRequest, R, 200, 78, T));
    assert_eq!(state.incarnation, 78);
    assert_eq!(state.last_seen_ms, 200);
    assert_eq!(state.expires_at_ms, 200 + u64::from(T.echo_ms));
    assert!(state.valid_for(ip_proto::ICMPV6));
}
