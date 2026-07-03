//! Safe, slice-based reference parser for Ethernet + IPv4 (+ L4 ports).
//!
//! This is the **executable specification** of Velstra's wire format. The eBPF
//! data plane performs the identical sequence of offset/bounds checks on raw
//! packet pointers (where the verifier forbids slices), but cannot be unit
//! tested directly. This function does the same work on a `&[u8]`, so every
//! edge case — short frames, IP options, non-IPv4, truncated L4 — is covered by
//! the test suite below and serves as the contract the kernel code must match.

use crate::packet::{ETHERTYPE_IPV4, PacketMeta, ip_proto};

/// Length of a fixed Ethernet II header (no VLAN tag).
const ETH_HDR_LEN: usize = 14;
/// Minimum length of an IPv4 header (no options).
const IPV4_MIN_HDR_LEN: usize = 20;
/// Offset of the EtherType field within the Ethernet header.
const ETH_TYPE_OFF: usize = 12;

/// Outcome of [`parse_frame`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParseResult {
    /// A well-formed IPv4 packet with the extracted [`PacketMeta`].
    Ipv4(PacketMeta),
    /// A frame that is not IPv4 (ARP, IPv6, …). The firewall passes these
    /// untouched in Phase 1.
    NotIpv4,
    /// A frame that claims to be IPv4 but is truncated or internally
    /// inconsistent. Counted as `malformed`; passed (fail-open) by the caller.
    Malformed,
}

/// Read a big-endian `u16` at `off`, or `None` if it would read past the end.
#[inline]
fn be_u16(data: &[u8], off: usize) -> Option<u16> {
    let bytes = data.get(off..off + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Parse an Ethernet frame and, if it carries IPv4, extract the fields the
/// firewall needs.
///
/// The parser is intentionally strict about lengths but lenient about content:
/// it never panics and never reads out of bounds. L4 ports are extracted only
/// for TCP/UDP and only when the segment is long enough; otherwise they default
/// to `0`, which simply means "no `(proto, port)` rule can match".
pub fn parse_frame(data: &[u8]) -> ParseResult {
    // --- Ethernet -----------------------------------------------------------
    let Some(ethertype) = be_u16(data, ETH_TYPE_OFF) else {
        return ParseResult::Malformed;
    };
    if ethertype != ETHERTYPE_IPV4 {
        return ParseResult::NotIpv4;
    }

    // --- IPv4 ---------------------------------------------------------------
    let ip = &data[ETH_HDR_LEN..];
    if ip.len() < IPV4_MIN_HDR_LEN {
        return ParseResult::Malformed;
    }
    let version = ip[0] >> 4;
    let ihl_bytes = ((ip[0] & 0x0f) as usize) * 4;
    if version != 4 || ihl_bytes < IPV4_MIN_HDR_LEN || ip.len() < ihl_bytes {
        return ParseResult::Malformed;
    }

    let total_len = u16::from_be_bytes([ip[2], ip[3]]);
    let proto = ip[9];
    let src_addr = [ip[12], ip[13], ip[14], ip[15]];
    let dst_addr = [ip[16], ip[17], ip[18], ip[19]];

    // Fragmentation: the flags + 13-bit fragment offset live in bytes 6..8. Only
    // the FIRST fragment (offset 0) carries the L4 header; a non-first fragment's
    // bytes at the L4 position are payload continuation. Reading them as ports
    // would let an attacker smuggle a packet past a `(proto, port)` rule
    // (fragmentation firewall evasion), and NAT-rewriting them would corrupt the
    // payload — so we treat a non-first fragment as having no ports (M1).
    let frag_offset = be_u16(ip, 6).map_or(0, |f| f & 0x1FFF);

    // --- L4 ports (best effort, TCP/UDP, first fragment only) ---------------
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    if (proto == ip_proto::TCP || proto == ip_proto::UDP) && frag_offset == 0 {
        // Source/destination ports are the first two u16s of the L4 header,
        // which begins right after the (variable-length) IPv4 header.
        if let (Some(s), Some(d)) = (be_u16(ip, ihl_bytes), be_u16(ip, ihl_bytes + 2)) {
            src_port = s;
            dst_port = d;
        }
    }

    ParseResult::Ipv4(PacketMeta::new(
        src_addr, dst_addr, proto, src_port, dst_port, total_len,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an Ethernet + IPv4 (+ optional 4-byte L4 prefix) frame for tests.
    fn frame(
        ethertype: u16,
        ihl_words: u8,
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        l4: Option<(u16, u16)>,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0xff; 6]); // dst mac
        v.extend_from_slice(&[0xaa; 6]); // src mac
        v.extend_from_slice(&ethertype.to_be_bytes());

        let ihl_bytes = (ihl_words as usize) * 4;
        let mut ip = vec![0u8; ihl_bytes];
        ip[0] = (4 << 4) | (ihl_words & 0x0f); // version=4, ihl
        let total_len = (ihl_bytes + l4.map_or(0, |_| 4)) as u16;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[9] = proto;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        v.extend_from_slice(&ip);

        if let Some((sp, dp)) = l4 {
            v.extend_from_slice(&sp.to_be_bytes());
            v.extend_from_slice(&dp.to_be_bytes());
        }
        v
    }

    #[test]
    fn parses_tcp_with_ports() {
        let f = frame(
            ETHERTYPE_IPV4,
            5,
            ip_proto::TCP,
            [203, 0, 113, 1],
            [10, 0, 0, 1],
            Some((40000, 443)),
        );
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!(m.src_addr, [203, 0, 113, 1]);
        assert_eq!(m.dst_addr, [10, 0, 0, 1]);
        assert_eq!(m.proto, ip_proto::TCP);
        assert_eq!(m.src_port, 40000);
        assert_eq!(m.dst_port, 443);
    }

    #[test]
    fn parses_ipv4_options_and_finds_l4() {
        // IHL = 6 words (24 bytes): 4 bytes of IP options before the L4 header.
        let f = frame(
            ETHERTYPE_IPV4,
            6,
            ip_proto::UDP,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            Some((1111, 53)),
        );
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!(m.proto, ip_proto::UDP);
        assert_eq!(m.dst_port, 53, "L4 offset must account for IP options");
    }

    #[test]
    fn icmp_has_no_ports() {
        let f = frame(
            ETHERTYPE_IPV4,
            5,
            ip_proto::ICMP,
            [9, 9, 9, 9],
            [10, 0, 0, 1],
            None,
        );
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!(m.proto, ip_proto::ICMP);
        assert_eq!((m.src_port, m.dst_port), (0, 0));
    }

    #[test]
    fn non_ipv4_is_detected() {
        let f = frame(0x86DD, 5, ip_proto::TCP, [0; 4], [0; 4], None); // IPv6 ethertype
        assert_eq!(parse_frame(&f), ParseResult::NotIpv4);
    }

    #[test]
    fn truncated_ethernet_is_malformed() {
        assert_eq!(parse_frame(&[0u8; 10]), ParseResult::Malformed);
    }

    #[test]
    fn truncated_ipv4_header_is_malformed() {
        // Claims IPv4 but only 10 bytes of IP header present.
        let mut f = Vec::new();
        f.extend_from_slice(&[0u8; 12]);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        f.extend_from_slice(&[0x45; 10]);
        assert_eq!(parse_frame(&f), ParseResult::Malformed);
    }

    #[test]
    fn bogus_ihl_is_malformed() {
        // A full 20-byte IPv4 header whose IHL nibble claims only 1 word
        // (4 bytes) — below the 20-byte minimum, so it must be rejected.
        let mut f = frame(ETHERTYPE_IPV4, 5, ip_proto::TCP, [1; 4], [1; 4], None);
        f[ETH_HDR_LEN] = (4 << 4) | 1; // version=4, ihl=1
        assert_eq!(parse_frame(&f), ParseResult::Malformed);
    }

    #[test]
    fn non_first_fragment_ignores_l4_bytes_as_ports() {
        // A TCP-proto packet whose fragment offset is non-zero: the four "L4"
        // bytes are really payload continuation and must NOT be read as ports
        // (fragmentation firewall evasion / NAT corruption — M1).
        let mut f = frame(
            ETHERTYPE_IPV4,
            5,
            ip_proto::TCP,
            [203, 0, 113, 9],
            [10, 0, 0, 1],
            Some((40000, 443)),
        );
        // Set fragment offset = 185 (in 8-byte units) in IP header bytes 6..8.
        let frag = 185u16;
        f[ETH_HDR_LEN + 6..ETH_HDR_LEN + 8].copy_from_slice(&frag.to_be_bytes());
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!(
            (m.src_port, m.dst_port),
            (0, 0),
            "non-first fragment must not expose L4 ports"
        );
        // L3 fields are still parsed so the blocklist/default action apply.
        assert_eq!(m.src_addr, [203, 0, 113, 9]);
        assert_eq!(m.proto, ip_proto::TCP);
    }

    #[test]
    fn first_fragment_still_reads_ports() {
        // First fragment (offset 0, More-Fragments set) DOES carry the L4 header.
        let mut f = frame(
            ETHERTYPE_IPV4,
            5,
            ip_proto::UDP,
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            Some((1234, 53)),
        );
        // flags = More Fragments (0x2000), offset = 0.
        let frag = 0x2000u16;
        f[ETH_HDR_LEN + 6..ETH_HDR_LEN + 8].copy_from_slice(&frag.to_be_bytes());
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!((m.src_port, m.dst_port), (1234, 53));
    }

    #[test]
    fn tcp_without_l4_bytes_defaults_ports_to_zero() {
        // Well-formed 20-byte IPv4 header, proto=TCP, but no L4 segment bytes.
        let f = frame(
            ETHERTYPE_IPV4,
            5,
            ip_proto::TCP,
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            None,
        );
        let ParseResult::Ipv4(m) = parse_frame(&f) else {
            panic!("expected ipv4");
        };
        assert_eq!((m.src_port, m.dst_port), (0, 0));
    }
}
