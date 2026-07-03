//! Phase 3 — **reject**: actively refusing a packet instead of silently
//! dropping it.
//!
//! Where [`crate::Action::Drop`] black-holes a packet (the peer times out),
//! [`crate::Action::Reject`] answers it. For TCP that means a **RST** segment,
//! the same thing a closed port's kernel would send — so a refused connection
//! fails *immediately* with "connection refused" instead of hanging.
//!
//! As with the rest of `velstra-common`, the part that needs care — building the
//! response header and its checksums — is a **pure, unit-tested function**
//! ([`plan_tcp_rst`]). The eBPF program does only the unavoidable, untestable
//! work: swap the L2/L3/L4 addresses in place, write these computed fields, trim
//! the packet to 54 bytes and `XDP_TX` it back out.
//!
//! Non-TCP reject (UDP/ICMP) currently degrades to a drop; an ICMP
//! destination-unreachable response is a follow-up (it requires relocating the
//! offending packet's header into the ICMP body, which XDP can't do in place).

use crate::forward::ipv4_checksum;

/// TCP control-flag bits (the low byte of the flags/data-offset word).
pub mod tcp_flags {
    /// No more data from sender.
    pub const FIN: u8 = 0x01;
    /// Synchronise sequence numbers (connection open).
    pub const SYN: u8 = 0x02;
    /// Reset the connection.
    pub const RST: u8 = 0x04;
    /// Acknowledgement field is significant.
    pub const ACK: u8 = 0x10;
}

/// The fields of a TCP **RST** response, computed by [`plan_tcp_rst`]. The
/// addresses/ports of the response are just the incoming packet's swapped, so
/// the data plane derives those itself; this carries only what needs arithmetic.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcpRst {
    /// RST sequence number (host order — the data plane writes it big-endian).
    pub seq: u32,
    /// RST acknowledgement number (host order).
    pub ack: u32,
    /// TCP flags byte: `RST`, or `RST|ACK` when acknowledging an unacked segment.
    pub flags: u8,
    /// Repaired IPv4 header checksum for the 40-byte response.
    pub ip_checksum: u16,
    /// TCP checksum over the response's pseudo-header + 20-byte TCP header.
    pub tcp_checksum: u16,
}

/// Plan a TCP RST in reply to an incoming TCP segment, per RFC 793 §3.4.
///
/// `ip_src`/`ip_dst` and `sport`/`dport` are the **incoming** packet's (the
/// response swaps them). `in_seq`/`in_ack`/`in_flags` come from its TCP header,
/// and `in_seg_len` is its TCP payload length plus one for each of SYN/FIN
/// (which occupy a sequence number) — i.e. the amount the sender's sequence
/// space advanced.
///
/// The rule: if the incoming segment carried an `ACK`, the RST takes its
/// acknowledgement number as the sequence and carries no ACK; otherwise the RST
/// acknowledges the incoming sequence (`in_seq + in_seg_len`) with `RST|ACK` and
/// sequence zero. This is exactly what a host's TCP emits for a port with no
/// listener, so the peer reacts identically.
///
/// ```
/// use velstra_common::{plan_tcp_rst, tcp_flags};
///
/// // A SYN to a refused port → RST|ACK acking the SYN (seq+1).
/// let rst = plan_tcp_rst([10, 0, 0, 9], [10, 0, 0, 1], 40000, 80, 0x1111_2222, 0, tcp_flags::SYN, 1);
/// assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);
/// assert_eq!(rst.seq, 0);
/// assert_eq!(rst.ack, 0x1111_2222u32.wrapping_add(1));
/// ```
#[inline]
#[allow(clippy::too_many_arguments)]
pub fn plan_tcp_rst(
    ip_src: [u8; 4],
    ip_dst: [u8; 4],
    sport: u16,
    dport: u16,
    in_seq: u32,
    in_ack: u32,
    in_flags: u8,
    in_seg_len: u32,
) -> TcpRst {
    // Response addresses/ports are the incoming ones swapped.
    let (new_src, new_dst) = (ip_dst, ip_src);
    let (new_sport, new_dport) = (dport, sport);

    let (seq, ack, flags) = if in_flags & tcp_flags::ACK != 0 {
        // The peer already has a sequence space — reset from its ACK point.
        (in_ack, 0, tcp_flags::RST)
    } else {
        // Acknowledge what the peer sent (SYN/FIN count as one) and reset.
        (
            0,
            in_seq.wrapping_add(in_seg_len),
            tcp_flags::RST | tcp_flags::ACK,
        )
    };

    let ip_checksum = ipv4_checksum(&rst_ip_header(new_src, new_dst));
    let tcp_checksum = tcp_checksum(
        new_src,
        new_dst,
        &rst_tcp_header(new_sport, new_dport, seq, ack, flags),
    );

    TcpRst {
        seq,
        ack,
        flags,
        ip_checksum,
        tcp_checksum,
    }
}

/// The 20-byte IPv4 header of a RST response (checksum field left zero for
/// [`ipv4_checksum`]). Total length 40 (20 IP + 20 TCP), TTL 64, protocol TCP.
fn rst_ip_header(src: [u8; 4], dst: [u8; 4]) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // version 4, IHL 5
    h[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
    h[8] = 64; // TTL
    h[9] = crate::packet::ip_proto::TCP;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    h
}

/// The 20-byte TCP header of a RST response (checksum field left zero). Data
/// offset 5 words, zero window, no options or payload.
fn rst_tcp_header(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) -> [u8; 20] {
    let mut t = [0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 5 << 4; // data offset = 5 words (no options)
    t[13] = flags;
    // window (14..16), checksum (16..18), urgent (18..20) all zero.
    t
}

/// TCP checksum over the IPv4 pseudo-header + a (checksum-zeroed) TCP segment.
fn tcp_checksum(src: [u8; 4], dst: [u8; 4], segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    // Pseudo-header: src, dst, zero/proto, TCP length.
    for w in [
        u16::from_be_bytes([src[0], src[1]]),
        u16::from_be_bytes([src[2], src[3]]),
        u16::from_be_bytes([dst[0], dst[1]]),
        u16::from_be_bytes([dst[2], dst[3]]),
        crate::packet::ip_proto::TCP as u16,
        segment.len() as u16,
    ] {
        sum += w as u32;
    }
    let mut i = 0;
    while i + 1 < segment.len() {
        sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
        i += 2;
    }
    if i < segment.len() {
        sum += (segment[i] as u32) << 8;
    }
    // Two folds reduce any u32 to 16 bits (the verifier rejects a data-dependent
    // fold loop, so this matches the rest of the crate's checksum code).
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// ICMP message types/codes Velstra emits for a non-TCP reject.
pub mod icmp {
    /// ICMP type 3 — Destination Unreachable.
    pub const DEST_UNREACHABLE: u8 = 3;
    /// Code 3 under [`DEST_UNREACHABLE`] — Port Unreachable (what a host sends
    /// for a closed UDP port; the natural non-TCP analogue of a TCP RST).
    pub const PORT_UNREACHABLE: u8 = 3;
}

/// Total IPv4 length of an ICMP port-unreachable response: IP(20) + ICMP(8) +
/// the embedded offending IP header(20) + its first 8 datagram bytes = 56. The
/// data plane grows the frame by IP(20)+ICMP(8) = 28 bytes at the head so the
/// offending packet's own header lands exactly in the ICMP body.
pub const ICMP_UNREACH_TOTAL_LEN: u16 = 56;
/// Bytes the data plane prepends (grows at head) to turn the offending packet
/// into the ICMP error: a fresh IP header (20) + the ICMP header (8).
pub const ICMP_UNREACH_PREPEND: usize = 28;

/// The pure part of an ICMP destination-unreachable response: the repaired IPv4
/// header checksum. The ICMP checksum covers the embedded offending packet, which
/// lives in the frame, so the data plane computes that one with [`icmp_checksum`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IcmpUnreach {
    /// Repaired IPv4 header checksum for the 56-byte response.
    pub ip_checksum: u16,
}

/// Plan an ICMP **destination unreachable / port unreachable** (type 3, code 3)
/// in reply to a rejected non-TCP packet, per RFC 792. `ip_src`/`ip_dst` are the
/// **incoming** packet's addresses (the response swaps them).
pub fn plan_icmp_unreachable(ip_src: [u8; 4], ip_dst: [u8; 4]) -> IcmpUnreach {
    let (new_src, new_dst) = (ip_dst, ip_src);
    IcmpUnreach {
        ip_checksum: ipv4_checksum(&icmp_unreach_ip_header(new_src, new_dst)),
    }
}

/// The 20-byte IPv4 header wrapping an ICMP unreachable (checksum field left zero
/// for [`ipv4_checksum`]). Total length 56, TTL 64, protocol ICMP.
fn icmp_unreach_ip_header(src: [u8; 4], dst: [u8; 4]) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // version 4, IHL 5
    h[2..4].copy_from_slice(&ICMP_UNREACH_TOTAL_LEN.to_be_bytes());
    h[8] = 64; // TTL
    h[9] = crate::packet::ip_proto::ICMP;
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    h
}

/// Internet checksum (RFC 1071) over an ICMP message — its 8-byte header (with
/// the checksum field zeroed) followed by the embedded offending packet. The data
/// plane passes the header + embedded bytes as one slice.
pub fn icmp_checksum(message: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < message.len() {
        sum += u16::from_be_bytes([message[i], message[i + 1]]) as u32;
        i += 2;
    }
    if i < message.len() {
        sum += (message[i] as u32) << 8;
    }
    // Two folds reduce any u32 to 16 bits without a data-dependent loop (the
    // verifier rejects the `while sum >> 16 != 0` form), matching the crate's
    // other checksum code.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sum a buffer of 16-bit words including any checksum field; a valid
    /// header/segment folds to zero.
    fn ones_complement(words: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < words.len() {
            sum += u16::from_be_bytes([words[i], words[i + 1]]) as u32;
            i += 2;
        }
        if i < words.len() {
            sum += (words[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn syn_gets_rst_ack_acking_the_syn() {
        // No ACK on the incoming SYN → RST|ACK, seq 0, ack = in_seq + 1.
        let rst = plan_tcp_rst(
            [203, 0, 113, 7],
            [10, 0, 0, 1],
            51000,
            443,
            0xDEAD_0000,
            0,
            tcp_flags::SYN,
            1,
        );
        assert_eq!(rst.flags, tcp_flags::RST | tcp_flags::ACK);
        assert_eq!(rst.seq, 0);
        assert_eq!(rst.ack, 0xDEAD_0001);
    }

    #[test]
    fn acked_segment_gets_bare_rst_from_its_ack() {
        // Incoming carried an ACK → RST (no ACK flag), seq = incoming ack.
        let rst = plan_tcp_rst(
            [203, 0, 113, 7],
            [10, 0, 0, 1],
            51000,
            443,
            0x1000,
            0x5555_0000,
            tcp_flags::ACK,
            0,
        );
        assert_eq!(rst.flags, tcp_flags::RST);
        assert_eq!(rst.seq, 0x5555_0000);
        assert_eq!(rst.ack, 0);
    }

    #[test]
    fn rst_ip_and_tcp_checksums_validate_from_scratch() {
        let in_src = [203, 0, 113, 7];
        let in_dst = [10, 0, 0, 1];
        let (sport, dport) = (51000u16, 443u16);
        let rst = plan_tcp_rst(
            in_src,
            in_dst,
            sport,
            dport,
            0x0011_2233,
            0,
            tcp_flags::SYN,
            1,
        );

        // Rebuild the response headers with the computed checksums in place and
        // confirm each folds to zero (i.e. is a valid checksum).
        let mut ip = rst_ip_header(in_dst, in_src);
        ip[10..12].copy_from_slice(&rst.ip_checksum.to_be_bytes());
        assert_eq!(ones_complement(&ip), 0, "IP checksum invalid");

        let mut seg = rst_tcp_header(dport, sport, rst.seq, rst.ack, rst.flags);
        seg[16..18].copy_from_slice(&rst.tcp_checksum.to_be_bytes());
        // Prepend the pseudo-header and confirm the whole thing folds to zero.
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&in_dst); // response src
        pseudo.extend_from_slice(&in_src); // response dst
        pseudo.push(0);
        pseudo.push(crate::packet::ip_proto::TCP);
        pseudo.extend_from_slice(&(seg.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(&seg);
        assert_eq!(ones_complement(&pseudo), 0, "TCP checksum invalid");
    }

    #[test]
    fn tcp_checksum_covers_the_ports_and_seq() {
        // Two RSTs to different ports must differ in their TCP checksum (the
        // checksum genuinely covers the swapped ports / seq fields, not just the
        // order-independent address pair).
        let a = plan_tcp_rst(
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            1234,
            80,
            7,
            0,
            tcp_flags::SYN,
            1,
        );
        let b = plan_tcp_rst(
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            1234,
            81,
            7,
            0,
            tcp_flags::SYN,
            1,
        );
        assert_ne!(a.tcp_checksum, b.tcp_checksum);
    }

    #[test]
    fn icmp_unreach_ip_checksum_validates_from_scratch() {
        let in_src = [203, 0, 113, 7];
        let in_dst = [10, 0, 0, 1];
        let plan = plan_icmp_unreachable(in_src, in_dst);
        // Rebuild the response IP header (swapped addresses) with the computed
        // checksum in place; a valid header folds to zero.
        let mut ip = icmp_unreach_ip_header(in_dst, in_src);
        ip[10..12].copy_from_slice(&plan.ip_checksum.to_be_bytes());
        assert_eq!(
            ones_complement(&ip),
            0,
            "ICMP-unreachable IP checksum invalid"
        );
        // Header carries protocol ICMP and total length 56.
        assert_eq!(ip[9], crate::packet::ip_proto::ICMP);
        assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), ICMP_UNREACH_TOTAL_LEN);
    }

    #[test]
    fn icmp_checksum_validates_and_covers_the_body() {
        // An 8-byte ICMP header (type 3, code 3, csum 0, unused 0) + a 28-byte
        // embedded offending packet, checksum field left zero.
        let mut base = [0u8; 36];
        base[0] = icmp::DEST_UNREACHABLE;
        base[1] = icmp::PORT_UNREACHABLE;
        for (i, b) in base[8..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let csum = icmp_checksum(&base);

        // Placing the checksum back makes the whole message fold to zero.
        let mut with_csum = base;
        with_csum[2..4].copy_from_slice(&csum.to_be_bytes());
        assert_eq!(ones_complement(&with_csum), 0, "ICMP checksum invalid");

        // The checksum genuinely covers the body: flipping an embedded byte (csum
        // field still zero on both) changes it.
        let mut flipped = base;
        flipped[20] ^= 0xff;
        assert_ne!(icmp_checksum(&flipped), csum);
    }
}
