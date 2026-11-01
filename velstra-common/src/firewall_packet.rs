//! Structural validation before a packet can consult or create firewall state.
//! Readers must bound every access; TC readers may use skb helpers for non-linear
//! payloads. Ethernet padding is never part of the IP-declared transport bytes.
use crate::{
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, FirewallFlowKey, FlowPacket, FlowScope, TcpSegment, ip_proto,
    ipv6_ext_len, is_ipv6_ext,
};

pub trait FirewallPacketReader {
    fn frame_len(&self) -> usize;
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]>;
    #[inline(always)]
    fn tcp_valid(&self, offset: usize, len: usize) -> Option<bool> {
        Some(self.tcp_segment(offset, len).is_some())
    }
    #[inline(always)]
    fn tcp_segment(&self, offset: usize, len: usize) -> Option<TcpSegment> {
        let head = self.read::<20>(offset)?;
        TcpSegment::parse_header(&head, len, |index| {
            self.read::<1>(offset + index).map(|value| value[0])
        })
    }
    /// Kernel-provided skb segmentation metadata, never inferred from a packet
    /// header. BIG TCP can have a zero IP length before kernel segmentation.
    fn segmentation_offload(&self) -> bool {
        false
    }
    /// Apply a configured checksum-neutral boundary mapping to the state key
    /// only. Packet rewriting and ACL evaluation remain the caller's duties.
    fn normalize_v6_destination(&self, destination: [u8; 16]) -> [u8; 16] {
        destination
    }
}

/// Caller-owned parsed metadata. A successful parse writes every field; callers
/// must not use a previous packet's metadata after an unsupported/failed parse.
pub struct FirewallPacketFlow {
    pub key: FirewallFlowKey,
    pub packet: FlowPacket,
    pub direction: u32,
}

// Keep payload-free enum writes out of the TCP/UDP value merge. LLVM may fill
// an inactive enum payload with arbitrary registers; on BPF that can copy a
// map pointer into scalar arithmetic, which the verifier correctly refuses.
#[inline(never)]
fn set_udp(out: &mut FirewallPacketFlow) {
    out.packet = FlowPacket::Udp;
}
#[inline(never)]
fn set_echo(out: &mut FirewallPacketFlow, request: bool) {
    if request {
        out.packet = FlowPacket::EchoRequest;
    } else {
        out.packet = FlowPacket::EchoReply;
    }
}

/// Parse complete IPv6 transport metadata for protocol state, independently of
/// linear skb payload layout. Fragmented datagrams never create L4 permission;
/// atomic fragments are complete datagrams and can be tracked normally.
#[inline(always)]
pub fn firewall_packet_flow_v6(
    reader: &impl FirewallPacketReader,
    scope: FlowScope,
    out: &mut FirewallPacketFlow,
) -> Option<bool> {
    let ip = reader.read::<40>(14)?;
    let payload = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let offload = payload == 0 && reader.frame_len() > 65589 && reader.segmentation_offload();
    let total = if offload {
        reader.frame_len()
    } else {
        54 + payload
    };
    if ip[0] >> 4 != 6 || total > reader.frame_len() {
        return None;
    }
    let mut proto = ip[6];
    let mut offset = 54;
    for _ in 0..8 {
        if !is_ipv6_ext(proto) {
            break;
        }
        if offset + 4 > total {
            return None;
        }
        let ext = reader.read::<4>(offset)?;
        let length = ipv6_ext_len(proto, ext[1]);
        if offset + length > total {
            return None;
        }
        if proto == ip_proto::FRAGMENT && u16::from_be_bytes([ext[2], ext[3]]) & 0xfff9 != 0 {
            return Some(false);
        }
        offset += length;
        proto = ext[0];
    }
    if is_ipv6_ext(proto) || offset > total || offload && proto != ip_proto::TCP {
        return None;
    }
    out.key.scope = scope;
    out.key.family = 6;
    out.key.protocol = proto;
    out.key.query_type = 0;
    out.key._pad = 0;
    out.key.low_addr = ip[8..24].try_into().ok()?;
    out.key.high_addr = reader.normalize_v6_destination(ip[24..40].try_into().ok()?);
    let len = total - offset;
    match proto {
        ip_proto::TCP | ip_proto::UDP => {
            let head = reader.read::<8>(offset)?;
            out.key.low_port = u16::from_be_bytes([head[0], head[1]]);
            out.key.high_port = u16::from_be_bytes([head[2], head[3]]);
            if proto == ip_proto::TCP {
                out.packet = FlowPacket::Tcp(reader.tcp_segment(offset, len)?);
            } else {
                let length = u16::from_be_bytes([head[4], head[5]]) as usize;
                if length < 8 || length > len {
                    return None;
                }
                set_udp(out);
            }
        }
        ip_proto::ICMPV6 => {
            if len < 8 {
                return None;
            }
            let head = reader.read::<8>(offset)?;
            if head[0] != 128 && head[0] != 129 {
                return Some(false);
            }
            if head[1] != 0 {
                return None;
            }
            out.key.low_port = u16::from_be_bytes([head[4], head[5]]);
            out.key.high_port = out.key.low_port;
            out.key.query_type = 128;
            set_echo(out, head[0] == 128);
        }
        _ => return Some(false),
    }
    out.direction = out.key.canonicalize().index() as u32;
    Some(true)
}

/// This does not authorize traffic. Fragments with an incomplete transport are
/// structurally checked only; a state tracker must not derive L4 state from them.
#[inline(always)]
pub fn firewall_packet_valid(reader: &impl FirewallPacketReader) -> bool {
    let Some(ether) = reader.read::<2>(12) else {
        return false;
    };
    match u16::from_be_bytes(ether) {
        ETHERTYPE_IPV4 => validate_v4(reader).unwrap_or(false),
        ETHERTYPE_IPV6 => validate_v6(reader).unwrap_or(false),
        _ => true,
    }
}

#[inline(always)]
fn validate_v4(reader: &impl FirewallPacketReader) -> Option<bool> {
    let ip = reader.read::<20>(14)?;
    let header = ((ip[0] & 15) as usize) * 4;
    let mut total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let big_tcp = total == 0
        && reader.frame_len() > 65549
        && ip[9] == ip_proto::TCP
        && reader.segmentation_offload();
    if big_tcp {
        total = reader.frame_len() - 14;
    }
    if ip[0] >> 4 != 4 || header < 20 || total < header || 14 + total > reader.frame_len() {
        return Some(false);
    }
    // MF or a non-zero offset: the IP payload is only a fragment of L4.
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        return Some(!big_tcp);
    }
    transport(reader, 14 + header, total - header, ip[9])
}

#[inline(always)]
fn validate_v6(reader: &impl FirewallPacketReader) -> Option<bool> {
    let ip = reader.read::<8>(14)?;
    let payload = u16::from_be_bytes([ip[4], ip[5]]) as usize;
    let big_tcp = payload == 0 && reader.frame_len() > 65589 && reader.segmentation_offload();
    let total = if big_tcp {
        reader.frame_len()
    } else {
        54 + payload
    };
    if ip[0] >> 4 != 6 || reader.frame_len() < 54 || total > reader.frame_len() {
        return Some(false);
    }
    let mut proto = ip[6];
    let mut offset = 54usize;
    for _ in 0..8 {
        if !is_ipv6_ext(proto) {
            break;
        }
        if offset + 4 > total {
            return Some(false);
        }
        let ext = reader.read::<4>(offset)?;
        let length = ipv6_ext_len(proto, ext[1]);
        if offset + length > total {
            return Some(false);
        }
        if proto == ip_proto::FRAGMENT && u16::from_be_bytes([ext[2], ext[3]]) & 0xfff9 != 0 {
            return Some(!big_tcp);
        }
        offset += length;
        proto = ext[0];
    }
    if is_ipv6_ext(proto) || offset > total {
        return Some(false);
    }
    if big_tcp && proto != ip_proto::TCP {
        return Some(false);
    }
    transport(reader, offset, total - offset, proto)
}

#[inline(always)]
fn transport(
    reader: &impl FirewallPacketReader,
    offset: usize,
    len: usize,
    proto: u8,
) -> Option<bool> {
    match proto {
        ip_proto::TCP => {
            if len < 20 {
                return Some(false);
            }
            reader.tcp_valid(offset, len)
        }
        ip_proto::UDP => {
            if len < 8 {
                return Some(false);
            }
            let head = reader.read::<8>(offset)?;
            let length = u16::from_be_bytes([head[4], head[5]]) as usize;
            Some(length >= 8 && length <= len)
        }
        ip_proto::ICMP | ip_proto::ICMPV6 => Some(len >= 8),
        _ => Some(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Packet(Vec<u8>);
    impl FirewallPacketReader for Packet {
        fn frame_len(&self) -> usize {
            self.0.len()
        }
        fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
            self.0.get(offset..offset.checked_add(N)?)?.try_into().ok()
        }
    }
    fn tcp() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[12] = 5 << 4;
        p[13] = 2;
        p
    }
    fn v4(l4: &[u8], proto: u8) -> Packet {
        let mut bytes = vec![0; 34];
        bytes[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&((20 + l4.len()) as u16).to_be_bytes());
        bytes[23] = proto;
        bytes.extend_from_slice(l4);
        Packet(bytes)
    }
    fn v6(l4: &[u8], proto: u8) -> Packet {
        let mut bytes = vec![0; 54];
        bytes[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        bytes[14] = 0x60;
        bytes[18..20].copy_from_slice(&(l4.len() as u16).to_be_bytes());
        bytes[20] = proto;
        bytes.extend_from_slice(l4);
        Packet(bytes)
    }
    fn parse_flow(p: &impl FirewallPacketReader) -> (Option<bool>, FirewallPacketFlow) {
        let mut out = FirewallPacketFlow {
            key: FirewallFlowKey::ZERO,
            packet: FlowPacket::Udp,
            direction: 0,
        };
        let result = firewall_packet_flow_v6(
            p,
            FlowScope {
                identity: 7,
                generation: 9,
            },
            &mut out,
        );
        (result, out)
    }
    #[test]
    fn native_v6_metadata_tracks_transport_echo_ids_options_and_reverse_direction() {
        let mut syn = tcp();
        syn[0..2].copy_from_slice(&45000u16.to_be_bytes());
        syn[2..4].copy_from_slice(&443u16.to_be_bytes());
        syn[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        syn[12] = 6 << 4;
        syn.extend_from_slice(&[3, 3, 7, 0]);
        let mut p = v6(&syn, ip_proto::TCP);
        p.0[22] = 0x20;
        p.0[37] = 1;
        p.0[38] = 0x20;
        p.0[53] = 2;
        let (result, forward) = parse_flow(&p);
        assert_eq!(result, Some(true));
        let FlowPacket::Tcp(segment) = forward.packet else {
            panic!("TCP expected")
        };
        assert_eq!(segment.sequence, u32::MAX);
        assert_eq!(segment.window_scale, 7);
        assert_eq!(segment.payload_len, 0);
        for n in 0..16 {
            p.0.swap(22 + n, 38 + n);
        }
        for n in 0..2 {
            p.0.swap(54 + n, 56 + n);
        }
        let (_, reverse) = parse_flow(&p);
        assert_eq!(forward.key, reverse.key);
        assert_ne!(forward.direction, reverse.direction);
        for id in [1u16, 2, 65535] {
            let mut echo = [0u8; 8];
            echo[0] = 128;
            echo[4..6].copy_from_slice(&id.to_be_bytes());
            let (result, request) = parse_flow(&v6(&echo, ip_proto::ICMPV6));
            assert_eq!(result, Some(true));
            assert_eq!(request.packet, FlowPacket::EchoRequest);
            assert_eq!(request.key.low_port, id);
            echo[0] = 129;
            let (result, reply) = parse_flow(&v6(&echo, ip_proto::ICMPV6));
            assert_eq!(result, Some(true));
            assert_eq!(reply.key, request.key);
            assert_eq!(reply.packet, FlowPacket::EchoReply);
            echo[1] = 1;
            assert_eq!(parse_flow(&v6(&echo, ip_proto::ICMPV6)).0, None);
        }
    }
    #[test]
    fn native_v6_metadata_never_tracks_incomplete_fragment_or_padding() {
        let mut l4 = vec![ip_proto::TCP, 0, 0, 0, 0, 0, 0, 0];
        l4.extend_from_slice(&tcp());
        let mut p = v6(&l4, ip_proto::FRAGMENT);
        assert_eq!(parse_flow(&p).0, Some(true)); // atomic fragment
        for fragment in [1u16, 8, 9, 0xfff8] {
            p.0[56..58].copy_from_slice(&fragment.to_be_bytes());
            assert_eq!(parse_flow(&p).0, Some(false));
        }
        let mut p = v6(&tcp(), ip_proto::TCP);
        p.0[18..20].copy_from_slice(&19u16.to_be_bytes());
        p.0.extend_from_slice(&[0; 100]);
        assert_eq!(parse_flow(&p).0, None);
        let mut udp = [0u8; 8];
        for length in [0u16, 7, 9, 65535] {
            udp[4..6].copy_from_slice(&length.to_be_bytes());
            assert_eq!(parse_flow(&v6(&udp, ip_proto::UDP)).0, None);
        }
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(parse_flow(&v6(&udp, ip_proto::UDP)).0, Some(true));
    }
    #[test]
    fn tcp_requires_complete_ip_declared_header_in_both_families() {
        for packet in [v4(&tcp(), 6), v6(&tcp(), 6)] {
            assert!(firewall_packet_valid(&packet));
        }
        for len in 0..20 {
            for packet in [v4(&tcp()[..len], 6), v6(&tcp()[..len], 6)] {
                assert!(!firewall_packet_valid(&packet));
            }
        }
        let mut padded = v4(&tcp(), 6);
        padded.0[16..18].copy_from_slice(&24u16.to_be_bytes());
        assert!(!firewall_packet_valid(&padded));
    }
    #[test]
    fn validates_tcp_flags_offset_and_options() {
        for (offset, flags) in [(4, 2), (6, 2), (5, 6), (5, 3), (5, 0)] {
            let mut p = tcp();
            p[12] = offset << 4;
            p[13] = flags;
            assert!(!firewall_packet_valid(&v4(&p, 6)));
        }
        let mut p = tcp();
        p[12] = 7 << 4;
        p.extend_from_slice(&[3, 3, 2, 3, 3, 4, 1, 1]);
        assert!(!firewall_packet_valid(&v6(&p, 6)));
        let mut p = tcp();
        p[12] = 6 << 4;
        p.extend_from_slice(&[3, 3, 14, 1]);
        assert!(firewall_packet_valid(&v6(&p, 6)));
    }
    #[test]
    fn udp_length_must_fit_declared_ip_payload() {
        for length in [0u16, 4, 7, 9, 65535] {
            let mut p = [0; 8];
            p[4..6].copy_from_slice(&length.to_be_bytes());
            for frame in [v4(&p, 17), v6(&p, 17)] {
                assert!(!firewall_packet_valid(&frame));
            }
        }
        let mut p = [0; 8];
        p[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert!(firewall_packet_valid(&v4(&p, 17)));
        assert!(firewall_packet_valid(&v6(&p, 17)));
    }
    #[test]
    fn declared_ip_lengths_and_extension_bounds_are_authoritative() {
        let mut p = v4(&tcp(), 6);
        p.0[16..18].copy_from_slice(&19u16.to_be_bytes());
        assert!(!firewall_packet_valid(&p));
        let mut p = v6(&tcp(), 6);
        p.0[18..20].copy_from_slice(&100u16.to_be_bytes());
        assert!(!firewall_packet_valid(&p));
        let mut p = v6(&[6, 255, 0, 0, 0, 0, 0, 0], 0);
        assert!(!firewall_packet_valid(&p));
        p.0[55] = 0;
        assert!(!firewall_packet_valid(&p));
        for len in 0..14 {
            assert!(!firewall_packet_valid(&Packet(vec![0; len])));
        }
    }
    #[test]
    fn fragments_are_not_misread_as_transport_headers() {
        let mut p = v4(&[1, 2, 3, 4], 6);
        p.0[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(firewall_packet_valid(&p));
        let p = v6(&[6, 0, 0, 1, 0, 0, 0, 0, 1, 2, 3, 4], 44);
        assert!(firewall_packet_valid(&p));
        let p = v6(&[6, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4], 44);
        assert!(!firewall_packet_valid(&p));
    }

    #[test]
    fn big_tcp_requires_kernel_segmentation_metadata_and_still_validates_tcp() {
        struct Segmented(Packet);
        impl FirewallPacketReader for Segmented {
            fn frame_len(&self) -> usize {
                self.0.frame_len()
            }
            fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
                self.0.read(offset)
            }
            fn segmentation_offload(&self) -> bool {
                true
            }
        }
        let mut ipv4 = v4(&tcp(), 6);
        ipv4.0.resize(70034, 0);
        ipv4.0[16..18].copy_from_slice(&[0, 0]);
        let mut ipv6 = v6(&tcp(), 6);
        ipv6.0.resize(70054, 0);
        ipv6.0[18..20].copy_from_slice(&[0, 0]);
        for (frame, offset) in [(ipv4, 34), (ipv6, 54)] {
            assert!(!firewall_packet_valid(&frame));
            let mut segmented = Segmented(frame);
            assert!(firewall_packet_valid(&segmented));
            segmented.0.0[offset + 12] = 4 << 4;
            assert!(!firewall_packet_valid(&segmented));
        }
    }

    #[test]
    fn offload_validation_preserves_full_tcp_length() {
        struct Aggregate {
            packet: Packet,
            expected: usize,
        }
        impl FirewallPacketReader for Aggregate {
            fn frame_len(&self) -> usize {
                self.packet.frame_len()
            }
            fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
                self.packet.read(offset)
            }
            fn segmentation_offload(&self) -> bool {
                true
            }
            fn tcp_valid(&self, offset: usize, len: usize) -> Option<bool> {
                assert_eq!(len, self.expected, "offloaded TCP length was truncated");
                let head = self.read::<20>(offset)?;
                let parsed = TcpSegment::parse_header(&head, len, |index| {
                    self.read::<1>(offset + index).map(|v| v[0])
                })?;
                Some(parsed.payload_len as usize == len - 20)
            }
        }
        for length in [65536, 70000, 262144] {
            let mut ipv4 = v4(&tcp(), 6);
            ipv4.0.resize(34 + length, 0);
            ipv4.0[16..18].fill(0);
            let mut ipv6 = v6(&tcp(), 6);
            ipv6.0.resize(54 + length, 0);
            ipv6.0[18..20].fill(0);
            for packet in [ipv4, ipv6] {
                assert!(firewall_packet_valid(&Aggregate {
                    packet,
                    expected: length
                }));
            }
            // Offload metadata does not override a nonzero IP-declared length;
            // Ethernet padding must never become TCP payload.
            let mut declared_v4 = v4(&tcp(), 6);
            declared_v4.0.resize(34 + length, 0);
            let mut declared_v6 = v6(&tcp(), 6);
            declared_v6.0.resize(54 + length, 0);
            for packet in [declared_v4, declared_v6] {
                assert!(firewall_packet_valid(&Aggregate {
                    packet,
                    expected: 20
                }));
            }
            // The same complete length must survive extension-header removal.
            let mut ipv6 = v6(&[6, 0, 0, 0, 0, 0, 0, 0], 60);
            ipv6.0.extend_from_slice(&tcp());
            ipv6.0.resize(62 + length, 0);
            ipv6.0[18..20].fill(0);
            let aggregate = Aggregate {
                packet: ipv6,
                expected: length,
            };
            assert!(firewall_packet_valid(&aggregate));
            let (result, state) = parse_flow(&aggregate);
            assert_eq!(result, Some(true));
            let FlowPacket::Tcp(tcp) = state.packet else {
                panic!("TCP expected")
            };
            assert_eq!(tcp.payload_len as usize, length - 20);
        }
    }
}
