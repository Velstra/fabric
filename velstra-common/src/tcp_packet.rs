//! Complete-datagram TCP evidence, not a firewall verdict or offload fallback.
//!
//! Input starts at the IP header. Only complete wire-format checksums produce a
//! segment carrying TCP_SEGMENT_VALIDATED. TC CHECKSUM_PARTIAL/GSO, fragments,
//! source routes and unsupported extension semantics require a separate
//! completion/reassembly path; they never become guessed-valid metadata here.
//! This parser is currently unwired from the running XDP/TC programs.

use crate::{TCP_SCALE_ABSENT, TCP_SEGMENT_VALIDATED, TcpSegment, TcpSessionKey, tcp_flags};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpChecksumState {
    /// Caller proves these are complete wire bytes, not a partial/offload skb.
    CompleteWire,
    /// Includes CHECKSUM_PARTIAL, GSO, or unknown offload provenance.
    NeedsCompletion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpPacketError {
    Truncated,
    NotIp,
    NotTcp,
    MalformedIp,
    FragmentNeedsReassembly,
    UnsupportedSourceRoute,
    UnsupportedIpOptions,
    UnsupportedExtension,
    UnsupportedRouting,
    UnsupportedJumbo,
    ChecksumNeedsCompletion,
    BadChecksum,
    MalformedTcp,
    MalformedOptions,
    AmbiguousWindowScale,
    /// TCP-MD5/AO or IP AH shape parsed, but authentication was NOT verified.
    EndpointAuthenticationRequired,
}

/// Successful parse of one declared IP datagram. Private fields prevent this
/// type from being constructed without its parser. The returned TcpSegment is
/// still only a LOCAL proof contract, not a cross-hook authorization receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPacket {
    family: u32,
    source: [u8; 16],
    destination: [u8; 16],
    source_port: u16,
    destination_port: u16,
    l4_offset: u32,
    ip_length: u32,
    segment: TcpSegment,
}

impl TcpPacket {
    pub fn family(&self) -> u32 {
        self.family
    }
    pub fn source(&self) -> [u8; 16] {
        self.source
    }
    pub fn destination(&self) -> [u8; 16] {
        self.destination
    }
    pub fn source_port(&self) -> u16 {
        self.source_port
    }
    pub fn destination_port(&self) -> u16 {
        self.destination_port
    }
    pub fn l4_offset(&self) -> u32 {
        self.l4_offset
    }
    pub fn ip_length(&self) -> u32 {
        self.ip_length
    }
    pub fn segment(&self) -> TcpSegment {
        self.segment
    }

    /// Policy must come from the real hook, not packet bytes. An identical
    /// endpoint pair is explicitly unsupported because direction is ambiguous.
    pub fn key(&self, policy: u32) -> Option<(TcpSessionKey, u32)> {
        TcpSessionKey::new(
            policy,
            self.family,
            self.source,
            self.destination,
            self.source_port,
            self.destination_port,
        )
    }
}

/// Ignore trailing link padding only AFTER checking the IP-declared length.
/// IPv6 jumbograms are explicitly unsupported, not truncated to a u16 length.
pub fn parse_tcp_packet(
    packet: &[u8],
    checksum: TcpChecksumState,
) -> Result<TcpPacket, TcpPacketError> {
    if checksum != TcpChecksumState::CompleteWire {
        return Err(TcpPacketError::ChecksumNeedsCompletion);
    }
    let version = packet.first().ok_or(TcpPacketError::Truncated)? >> 4;
    match version {
        4 => ipv4(packet),
        6 => ipv6(packet),
        _ => Err(TcpPacketError::NotIp),
    }
}

fn ipv4(packet: &[u8]) -> Result<TcpPacket, TcpPacketError> {
    if packet.len() < 20 {
        return Err(TcpPacketError::Truncated);
    }
    let ihl = (packet[0] & 15) as usize * 4;
    let total = word(packet, 2) as usize;
    if ihl < 20 || total < ihl {
        return Err(TcpPacketError::MalformedIp);
    }
    if total > packet.len() || ihl > packet.len() {
        return Err(TcpPacketError::Truncated);
    }
    let packet = &packet[..total];
    if folded(sum(&packet[..ihl], 0)) != 65535 {
        return Err(TcpPacketError::BadChecksum);
    }
    let fragments = word(packet, 6);
    if fragments & 0x8000 != 0 {
        return Err(TcpPacketError::MalformedIp);
    }
    if fragments & 0x3fff != 0 {
        return Err(TcpPacketError::FragmentNeedsReassembly);
    }
    if packet[9] != 6 {
        return Err(TcpPacketError::NotTcp);
    }
    ipv4_options(&packet[20..ihl])?;
    let mut source = [0; 16];
    let mut destination = [0; 16];
    source[..4].copy_from_slice(&packet[12..16]);
    destination[..4].copy_from_slice(&packet[16..20]);
    let tcp = &packet[ihl..];
    let pseudo = sum(&packet[12..20], 6 + tcp.len() as u32);
    transport(tcp, pseudo, 4, source, destination, ihl, total)
}

fn ipv4_options(options: &[u8]) -> Result<(), TcpPacketError> {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => break,
            1 => offset += 1,
            kind => {
                let length = *options.get(offset + 1).ok_or(TcpPacketError::MalformedIp)? as usize;
                if length < 2 || offset + length > options.len() {
                    return Err(TcpPacketError::MalformedIp);
                }
                // Source routing can change the TCP pseudo-header destination.
                // Never verify against a guessed final address.
                if matches!(kind, 131 | 137) {
                    return Err(TcpPacketError::UnsupportedSourceRoute);
                }
                // RR/TS/RouterAlert and unknown IPv4 options have additional
                // pointer/length/semantic rules. Until modeled, do not call a
                // generic TLV skip proof of a kernel-acceptable header.
                return Err(TcpPacketError::UnsupportedIpOptions);
            }
        }
    }
    Ok(())
}

fn ipv6(packet: &[u8]) -> Result<TcpPacket, TcpPacketError> {
    if packet.len() < 40 {
        return Err(TcpPacketError::Truncated);
    }
    let payload = word(packet, 4) as usize;
    if payload == 0 {
        return Err(TcpPacketError::UnsupportedJumbo);
    }
    let total = 40 + payload;
    if total > packet.len() {
        return Err(TcpPacketError::Truncated);
    }
    let packet = &packet[..total];
    let mut source = [0; 16];
    let mut destination = [0; 16];
    source.copy_from_slice(&packet[8..24]);
    destination.copy_from_slice(&packet[24..40]);
    let mut protocol = packet[6];
    let mut offset = 40;
    let mut count = 0;
    while protocol != 6 {
        if count == 8 {
            return Err(TcpPacketError::UnsupportedExtension);
        }
        count += 1;
        if protocol == 44 {
            return Err(TcpPacketError::FragmentNeedsReassembly);
        }
        if !matches!(protocol, 0 | 43 | 60 | 51) {
            return Err(if matches!(protocol, 17 | 58 | 59) {
                TcpPacketError::NotTcp
            } else {
                TcpPacketError::UnsupportedExtension
            });
        }
        if offset + 2 > total {
            return Err(TcpPacketError::Truncated);
        }
        let length = if protocol == 51 {
            (packet[offset + 1] as usize + 2) * 4
        } else {
            (packet[offset + 1] as usize + 1) * 8
        };
        if protocol == 51 && length < 12 {
            return Err(TcpPacketError::MalformedIp);
        }
        if offset + length > total {
            return Err(TcpPacketError::Truncated);
        }
        if protocol == 51 {
            // An AH-protected datagram with a valid TCP checksum can still be
            // rejected for authentication. No MAC/security association proof
            // is available here; do not create sequence authority from it.
            return Err(TcpPacketError::EndpointAuthenticationRequired);
        }
        if protocol == 0 && offset != 40 {
            return Err(TcpPacketError::MalformedIp);
        }
        if protocol == 43 {
            // Even Segments Left == 0 does not establish acceptance: known
            // routing types can require SRH/HMAC or mobility policy before the
            // endpoint reaches TCP. Those semantics are not proved here.
            return Err(TcpPacketError::UnsupportedRouting);
        }
        if matches!(protocol, 0 | 60) {
            ipv6_options(&packet[offset + 2..offset + length], protocol == 0)?;
        }
        protocol = packet[offset];
        offset += length;
    }
    let tcp = &packet[offset..];
    let pseudo = sum(&packet[8..40], tcp.len() as u32 + 6);
    transport(tcp, pseudo, 6, source, destination, offset, total)
}

fn ipv6_options(options: &[u8], hop: bool) -> Result<(), TcpPacketError> {
    let mut offset = 0;
    let mut padding = 0;
    while offset < options.len() {
        let kind = options[offset];
        if kind == 0 {
            padding += 1;
            if padding > 7 {
                return Err(TcpPacketError::MalformedIp);
            }
            offset += 1;
            continue;
        }
        let length = *options.get(offset + 1).ok_or(TcpPacketError::MalformedIp)? as usize + 2;
        if offset + length > options.len() {
            return Err(TcpPacketError::MalformedIp);
        }
        if kind == 1 {
            padding += length;
            if padding > 7 || options[offset + 2..offset + length].iter().any(|b| *b != 0) {
                return Err(TcpPacketError::MalformedIp);
            }
        } else {
            padding = 0;
        }
        if hop && kind == 5 && length != 4 {
            return Err(TcpPacketError::MalformedIp);
        }
        // Only padding and the specifically checked hop-by-hop Router Alert
        // have modeled semantics. Even action00 is not proof of harmlessness:
        // an endpoint can recognize CALIPSO/IOAM or another extension that this
        // parser does not implement. Never guess from generic TLV bounds.
        if kind != 1 && !(hop && kind == 5) {
            return Err(TcpPacketError::UnsupportedExtension);
        }
        offset += length;
    }
    Ok(())
}

fn transport(
    tcp: &[u8],
    pseudo: u32,
    family: u32,
    source: [u8; 16],
    destination: [u8; 16],
    offset: usize,
    total: usize,
) -> Result<TcpPacket, TcpPacketError> {
    if tcp.len() < 20 {
        return Err(TcpPacketError::MalformedTcp);
    }
    let header = (tcp[12] >> 4) as usize * 4;
    if header < 20 || header > tcp.len() {
        return Err(TcpPacketError::MalformedTcp);
    }
    if folded(sum(tcp, pseudo)) != 65535 {
        return Err(TcpPacketError::BadChecksum);
    }
    let flags = tcp[13];
    let scale = tcp_options(&tcp[20..header], flags & tcp_flags::SYN != 0)?;
    Ok(TcpPacket {
        family,
        source,
        destination,
        source_port: word(tcp, 0),
        destination_port: word(tcp, 2),
        l4_offset: offset as u32,
        ip_length: total as u32,
        segment: TcpSegment {
            seq: dword(tcp, 4),
            ack: dword(tcp, 8),
            payload_len: (tcp.len() - header) as u32,
            window: word(tcp, 14) as u32,
            flags: flags as u32,
            scale,
            validated: TCP_SEGMENT_VALIDATED,
            reserved: 0,
        },
    })
}

fn tcp_options(options: &[u8], syn: bool) -> Result<u32, TcpPacketError> {
    let mut offset = 0;
    let mut scale = TCP_SCALE_ABSENT;
    while offset < options.len() {
        let kind = options[offset];
        if kind == 0 {
            break;
        } // Remaining padding is checksum-covered, not options.
        if kind == 1 {
            offset += 1;
            continue;
        }
        let length = *options
            .get(offset + 1)
            .ok_or(TcpPacketError::MalformedOptions)? as usize;
        if length < 2 || offset + length > options.len() {
            return Err(TcpPacketError::MalformedOptions);
        }
        let shape = match kind {
            2 => length == 4,
            3 => length == 3,
            4 => length == 2,
            5 => length >= 10 && (length - 2) & 7 == 0,
            8 => length == 10,
            19 => length == 18,
            29 => length >= 4,
            _ => true,
        };
        if !shape {
            return Err(TcpPacketError::MalformedOptions);
        }
        if matches!(kind, 19 | 29) {
            // Syntax/checksum is not a MAC verification. A future authority
            // must also remember session authentication requirements so a
            // later packet MISSING this option cannot retire authenticated TCP.
            return Err(TcpPacketError::EndpointAuthenticationRequired);
        }
        if kind == 3 && syn {
            let offered = (options[offset + 2] as u32).min(14);
            if scale != TCP_SCALE_ABSENT && scale != offered {
                return Err(TcpPacketError::AmbiguousWindowScale);
            }
            scale = offered;
        }
        offset += length;
    }
    Ok(scale)
}

fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}
fn dword(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
fn sum(bytes: &[u8], mut value: u32) -> u32 {
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        value += word(bytes, offset) as u32;
        offset += 2;
    }
    if offset < bytes.len() {
        value += (bytes[offset] as u32) << 8;
    }
    value
}
fn folded(mut value: u32) -> u16 {
    while value >> 16 != 0 {
        value = (value & 65535) + (value >> 16);
    }
    value as u16
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use super::*;

    // Independent u64 RFC1071 oracle, carrying after EVERY word rather than
    // using the parser's accumulation/fold implementation.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut accumulator = 0u64;
        for pair in bytes.chunks(2) {
            accumulator += ((pair[0] as u64) << 8) | pair.get(1).copied().unwrap_or(0) as u64;
            accumulator = (accumulator & 65535) + (accumulator >> 16);
        }
        !(accumulator as u16)
    }

    fn tcp(options: &[u8], payload: usize) -> Vec<u8> {
        assert!(options.len() <= 40 && options.len() & 3 == 0);
        let mut result = vec![0; 20 + options.len() + payload];
        result[..4].copy_from_slice(&[0, 0, 1, 187]); // source port0, dest443
        result[4..8].copy_from_slice(&0u32.to_be_bytes());
        result[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        result[12] = ((20 + options.len()) / 4) as u8 * 16;
        result[13] = tcp_flags::SYN;
        result[14..16].copy_from_slice(&32768u16.to_be_bytes());
        result[20..20 + options.len()].copy_from_slice(options);
        for (i, byte) in result[20 + options.len()..].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        result
    }

    fn ipv4_packet(options: &[u8], payload: usize, ip_options: &[u8]) -> Vec<u8> {
        let mut tcp = tcp(options, payload);
        let mut pseudo = vec![192, 0, 2, 1, 198, 51, 100, 2, 0, 6];
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&tcp);
        tcp[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        let ihl = 20 + ip_options.len();
        let mut packet = vec![0; ihl];
        packet[0] = 0x40 | (ihl / 4) as u8;
        packet[2..4].copy_from_slice(&((ihl + tcp.len()) as u16).to_be_bytes());
        packet[6] = 0x40; // DF is allowed.
        packet[8] = 64;
        packet[9] = 6;
        packet[12..20].copy_from_slice(&pseudo[..8]);
        packet[20..].copy_from_slice(ip_options);
        let header_sum = checksum(&packet);
        packet[10..12].copy_from_slice(&header_sum.to_be_bytes());
        packet.extend_from_slice(&tcp);
        packet
    }

    fn ipv6_packet(options: &[u8], payload: usize, extensions: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut tcp = tcp(options, payload);
        let source: [u8; 16] = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut target = source;
        target[15] = 2;
        let mut pseudo = source.to_vec();
        pseudo.extend_from_slice(&target);
        pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
        pseudo.extend_from_slice(&tcp);
        tcp[16..18].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        let extension_len: usize = extensions.iter().map(|(_, value)| value.len()).sum();
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((tcp.len() + extension_len) as u16).to_be_bytes());
        packet[6] = extensions.first().map(|e| e.0).unwrap_or(6);
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&target);
        for (i, (_, ext)) in extensions.iter().enumerate() {
            let mut value = ext.clone();
            value[0] = extensions.get(i + 1).map(|e| e.0).unwrap_or(6);
            packet.extend_from_slice(&value);
        }
        packet.extend_from_slice(&tcp);
        packet
    }

    fn parse(bytes: &[u8]) -> Result<TcpPacket, TcpPacketError> {
        parse_tcp_packet(bytes, TcpChecksumState::CompleteWire)
    }

    fn repair_ip(packet: &mut [u8]) {
        let ihl = (packet[0] & 15) as usize * 4;
        packet[10..12].fill(0);
        let sum = checksum(&packet[..ihl]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
    }

    fn repair_tcp(packet: &mut [u8]) {
        let offset = if packet[0] >> 4 == 4 {
            (packet[0] & 15) as usize * 4
        } else {
            40
        };
        packet[offset + 16..offset + 18].fill(0);
        let mut pseudo = if offset == 40 {
            packet[8..40].to_vec()
        } else {
            packet[12..20].to_vec()
        };
        if offset == 40 {
            pseudo.extend_from_slice(&((packet.len() - offset) as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        } else {
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&((packet.len() - offset) as u16).to_be_bytes());
        }
        pseudo.extend_from_slice(&packet[offset..]);
        let value = checksum(&pseudo);
        packet[offset + 16..offset + 18].copy_from_slice(&value.to_be_bytes());
    }

    #[test]
    fn independent_rfc1071_checksum_vector_and_odd_padding() {
        assert_eq!(checksum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
        assert_eq!(
            folded(sum(&[0, 1, 0xf2, 3, 0xf4, 0xf5, 0xf6, 0xf7], 0)),
            0xddf2
        );
        assert_eq!(checksum(&[1, 2, 3]), checksum(&[1, 2, 3, 0]));
    }

    #[test]
    fn complete_wire_evidence_and_key_preserve_zero_ports_sequence_and_padding() {
        let mut packet = ipv4_packet(&[3, 3, 0, 0], 17, &[]);
        let actual_len = packet.len();
        packet.extend_from_slice(&[0xaa; 32]);
        let parsed = parse(&packet).unwrap();
        assert_eq!(
            (
                parsed.family(),
                parsed.source_port(),
                parsed.destination_port()
            ),
            (4, 0, 443)
        );
        assert_eq!(
            (parsed.l4_offset(), parsed.ip_length()),
            (20, actual_len as u32)
        );
        assert_eq!(parsed.segment().seq, 0);
        assert_eq!(parsed.segment().ack, u32::MAX);
        assert_eq!(parsed.segment().payload_len, 17);
        assert_eq!(parsed.segment().scale, 0);
        assert_eq!(parsed.segment().validated, TCP_SEGMENT_VALIDATED);
        assert!(parsed.key(17).unwrap().0.valid());
    }

    #[test]
    fn complete_checksums_cover_odd_lengths_maximum_datagrams_and_ip_options() {
        for length in [0, 1, 2, 3, 31, 32, 63, 64, 511, 4097, 65495] {
            let packet = ipv4_packet(&[], length, &[]);
            assert_eq!(parse(&packet).unwrap().segment().payload_len, length as u32);
        }
        for length in [0, 1, 31, 4097, 65515] {
            let packet = ipv6_packet(&[], length, &[]);
            assert_eq!(parse(&packet).unwrap().segment().payload_len, length as u32);
        }
        for count in 0..=10 {
            let packet = ipv4_packet(&[], 17, &vec![1; count * 4]);
            assert_eq!(parse(&packet).unwrap().l4_offset(), (20 + count * 4) as u32);
        }
    }

    #[test]
    fn truncation_and_every_checksum_covered_byte_corruption_are_rejected() {
        for packet in [
            ipv4_packet(&[1; 12], 97, &[]),
            ipv6_packet(&[1; 12], 97, &[]),
        ] {
            for length in 0..packet.len() {
                assert!(parse(&packet[..length]).is_err(), "length={length}");
            }
            let start = if packet[0] >> 4 == 4 { 0 } else { 8 };
            for offset in start..packet.len() {
                if packet[0] >> 4 == 6 && (40..).contains(&offset)
                    || packet[0] >> 4 == 4
                    || (8..40).contains(&offset)
                {
                    let mut bad = packet.clone();
                    bad[offset] ^= 1;
                    assert!(parse(&bad).is_err(), "offset={offset}");
                }
            }
        }
    }

    #[test]
    fn deferred_offload_or_unknown_provenance_never_mints_validated_evidence() {
        let good = ipv4_packet(&[], 0, &[]);
        assert_eq!(
            parse_tcp_packet(&good, TcpChecksumState::NeedsCompletion),
            Err(TcpPacketError::ChecksumNeedsCompletion)
        );
        let mut partial = good;
        partial[36..38].fill(0);
        assert_eq!(
            parse_tcp_packet(&partial, TcpChecksumState::NeedsCompletion),
            Err(TcpPacketError::ChecksumNeedsCompletion)
        );
        assert_eq!(parse(&partial), Err(TcpPacketError::BadChecksum));
    }

    #[test]
    fn fragments_and_source_route_are_explicitly_unsupported() {
        for fragment in [1u16, 8191, 0x2000, 0x2001] {
            let mut packet = ipv4_packet(&[], 8, &[]);
            packet[6..8].copy_from_slice(&fragment.to_be_bytes());
            repair_ip(&mut packet);
            assert_eq!(parse(&packet), Err(TcpPacketError::FragmentNeedsReassembly));
        }
        for option in [131, 137] {
            assert_eq!(
                parse(&ipv4_packet(&[], 0, &[option, 3, 4, 0])),
                Err(TcpPacketError::UnsupportedSourceRoute)
            );
        }
        let maximum_options = ipv4_packet(&[1; 40], 65415, &[1; 40]);
        let parsed = parse(&maximum_options).unwrap();
        assert_eq!(
            (
                parsed.ip_length(),
                parsed.l4_offset(),
                parsed.segment().payload_len
            ),
            (65535, 60, 65415)
        );
        let maximum_v6 = ipv6_packet(&[1; 40], 65467, &[(0, vec![0; 8])]);
        let parsed = parse(&maximum_v6).unwrap();
        assert_eq!(
            (
                parsed.ip_length(),
                parsed.l4_offset(),
                parsed.segment().payload_len
            ),
            (65575, 48, 65467)
        );
        let fragment = ipv6_packet(&[], 8, &[(44, vec![0; 8])]);
        assert_eq!(
            parse(&fragment),
            Err(TcpPacketError::FragmentNeedsReassembly)
        );
    }

    #[test]
    fn ipv6_extension_lengths_and_routing_never_guess_endpoint_acceptance() {
        let packet = ipv6_packet(&[], 9, &[(0, vec![0; 8]), (60, vec![0; 8])]);
        assert_eq!(parse(&packet).unwrap().l4_offset(), 56);
        let ah = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse(&ipv6_packet(
                &[],
                9,
                &[(0, vec![0; 8]), (60, vec![0; 8]), (51, ah)]
            )),
            Err(TcpPacketError::EndpointAuthenticationRequired)
        );
        assert_eq!(
            parse(&ipv6_packet(&[], 9, &[(51, vec![0; 8])])),
            Err(TcpPacketError::MalformedIp)
        );
        for kind in [0, 2, 3, 4, 255] {
            for segments_left in [0, 1] {
                let mut routing = vec![0; 8];
                routing[2] = kind;
                routing[3] = segments_left;
                assert_eq!(
                    parse(&ipv6_packet(&[], 9, &[(43, routing)])),
                    Err(TcpPacketError::UnsupportedRouting)
                );
            }
        }
        let too_many: Vec<_> = (0..9).map(|_| (60, vec![0; 8])).collect();
        assert_eq!(
            parse(&ipv6_packet(&[], 0, &too_many)),
            Err(TcpPacketError::UnsupportedExtension)
        );
        let mut jumbo = ipv6_packet(&[], 0, &[]);
        jumbo[4..6].fill(0);
        assert_eq!(parse(&jumbo), Err(TcpPacketError::UnsupportedJumbo));
    }

    #[test]
    fn scale_normalization_duplicates_unknown_options_and_end_marker() {
        for scale in 0..=255 {
            assert_eq!(
                parse(&ipv4_packet(&[3, 3, scale, 0], 0, &[]))
                    .unwrap()
                    .segment()
                    .scale,
                (scale as u32).min(14)
            );
        }
        assert_eq!(
            parse(&ipv4_packet(&[3, 3, 4, 1, 3, 3, 4, 0], 0, &[]))
                .unwrap()
                .segment()
                .scale,
            4
        );
        assert_eq!(
            parse(&ipv4_packet(&[3, 3, 4, 1, 3, 3, 5, 0], 0, &[])),
            Err(TcpPacketError::AmbiguousWindowScale)
        );
        assert!(
            parse(&ipv4_packet(
                &[254, 4, 0xaa, 0xbb, 0, 0xff, 0xff, 0xff],
                0,
                &[]
            ))
            .is_ok()
        );
        let mut not_syn = ipv4_packet(&[3, 3, 14, 0], 0, &[]);
        not_syn[33] = tcp_flags::ACK;
        repair_tcp(&mut not_syn);
        assert_eq!(parse(&not_syn).unwrap().segment().scale, TCP_SCALE_ABSENT);
    }

    #[test]
    fn malformed_tcp_options_offsets_and_declared_lengths_are_refused() {
        for options in [
            [3, 2, 0, 0],
            [3, 5, 0, 0],
            [2, 3, 0, 0],
            [8, 4, 0, 0],
            [1, 1, 1, 3],
            [254, 0, 0, 0],
        ] {
            assert_eq!(
                parse(&ipv4_packet(&options, 0, &[])),
                Err(TcpPacketError::MalformedOptions)
            );
        }
        for offset in [0, 4, 15] {
            let mut packet = ipv4_packet(&[], 0, &[]);
            packet[32] = offset << 4;
            repair_tcp(&mut packet);
            assert_eq!(parse(&packet), Err(TcpPacketError::MalformedTcp));
        }
        let mut small = ipv4_packet(&[], 0, &[]);
        small[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(parse(&small), Err(TcpPacketError::MalformedIp));
        let mut bad = ipv4_packet(&[], 0, &[]);
        bad[12] ^= 1;
        repair_ip(&mut bad);
        assert_eq!(parse(&bad), Err(TcpPacketError::BadChecksum)); // TCP pseudo-header changes too.
    }

    #[test]
    fn ip_option_semantics_do_not_become_guessed_transport_proof() {
        for options in [
            [148, 3, 0, 0],
            [7, 3, 0, 0],
            [68, 4, 0, 0],
            [148, 4, 0, 0],
            [30, 2, 0, 0],
        ] {
            assert_eq!(
                parse(&ipv4_packet(&[], 0, &options)),
                Err(TcpPacketError::UnsupportedIpOptions)
            );
        }
        let invalid_ra = vec![0, 0, 5, 0, 0, 0, 0, 0];
        let bad_padn = vec![0, 0, 1, 2, 0xaa, 0xbb, 0, 0];
        let excessive_padding = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for extension in [invalid_ra, bad_padn, excessive_padding] {
            assert_eq!(
                parse(&ipv6_packet(&[], 0, &[(0, extension)])),
                Err(TcpPacketError::MalformedIp)
            );
        }
        for kind in [7, 30, 49, 0xc2, 0xc9] {
            assert_eq!(
                parse(&ipv6_packet(
                    &[],
                    0,
                    &[(0, vec![0, 0, kind, 0, 0, 0, 0, 0])]
                )),
                Err(TcpPacketError::UnsupportedExtension)
            );
        }
        for extension in [vec![0, 0, 5, 2, 0, 0, 0, 0], vec![0, 0, 1, 2, 0, 0, 0, 0]] {
            assert!(parse(&ipv6_packet(&[], 0, &[(0, extension)])).is_ok());
        }
    }

    #[test]
    fn md5_and_ao_are_not_endpoint_authentication_proofs() {
        let mut md5 = vec![0; 20];
        md5[0] = 19;
        md5[1] = 18;
        let mut ao = vec![0; 16];
        ao[0] = 29;
        ao[1] = 16;
        for options in [md5, ao] {
            for syn in [true, false] {
                let mut packet = ipv4_packet(&options, 0, &[]);
                if !syn {
                    packet[33] = tcp_flags::RST | tcp_flags::ACK;
                    repair_tcp(&mut packet);
                }
                assert_eq!(
                    parse(&packet),
                    Err(TcpPacketError::EndpointAuthenticationRequired)
                );
            }
        }
        assert_eq!(
            parse(&ipv4_packet(&[19, 4, 0, 0], 0, &[])),
            Err(TcpPacketError::MalformedOptions)
        );
        assert_eq!(
            parse(&ipv4_packet(&[29, 4, 0, 0], 0, &[])),
            Err(TcpPacketError::EndpointAuthenticationRequired)
        );
        assert_eq!(
            parse(&ipv4_packet(&[29, 3, 0, 0], 0, &[])),
            Err(TcpPacketError::MalformedOptions)
        );
        // A packet without an auth option is NOT proof the session is auth-free.
        // The running authority must supply that context; this parser cannot.
        assert!(parse(&ipv4_packet(&[], 0, &[])).is_ok());
    }

    #[test]
    fn actual_retained_vm_wire_vectors_parse_without_generated_checksum_agreement() {
        // Exact IP datagrams from dut-before-guest.pcap in the retained v7
        // socket differential run. PCAP SHA256:
        // 7f84a69ba26c5222f871b023507614757101a5843b181c643bb4a43b596dd7c2
        // These immutable input bytes do NOT call this test's packet builder.
        let vectors = [
            (
                "450000287200000040065d79c6130afec61314324716a411ab172b92fb8c8e3c50141000a8de0000",
                2870422418u32,
                4220292668u32,
                42001,
            ),
            (
                "450000287201000040065d78c6130afec61314324716a424c150a37eec10019450141000b6ca0000",
                3243287422u32,
                3960471956u32,
                42020,
            ),
            (
                "450000287202000040065d77c6130afec61314324716a438d64f42908d0b1f675014100043d80000",
                3595518608u32,
                2366316391u32,
                42040,
            ),
            (
                "450000287203000040065d76c6130afec61314324716a44cec1e853caccbdd00501410000def0000",
                3961423164u32,
                2899041536u32,
                42060,
            ),
        ];
        for (hex, seq, ack, port) in vectors {
            let bytes: Vec<_> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            let packet = parse(&bytes).unwrap();
            assert_eq!(
                (packet.source_port(), packet.destination_port()),
                (18198, port)
            );
            assert_eq!((packet.segment().seq, packet.segment().ack), (seq, ack));
            assert_eq!(
                (packet.segment().flags, packet.segment().payload_len),
                (20, 0)
            );
            assert_eq!(packet.source()[..4], [198, 19, 10, 254]);
            assert_eq!(packet.destination()[..4], [198, 19, 20, 50]);
            assert_eq!(packet.segment().validated, TCP_SEGMENT_VALIDATED);
        }
    }
}
