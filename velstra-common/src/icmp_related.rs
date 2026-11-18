//! Checksums for an ICMPv4 error's quoted, inverse-translated packet.
//!
//! RFC 5508 §4 and RFC 3022 §4.3 require repairing the quote, not only the
//! envelope. Never validate a truncated quote's transport checksum: its suffix
//! is normally absent. Update that checksum only when its field is present.
use crate::{FlowKey, csum_replace_u16, ip_proto};

/// The three checksum fields affected by editing a quote. `transport` is None
/// when the quote ends before that field (ordinary eight-byte TCP quotes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelatedChecksums {
    pub ip: u16,
    pub transport: Option<u16>,
    pub error: u16,
}

/// Validate the checksum copy's nonzero chunk size, then emit an explicit
/// arithmetic 1..64 bound for older kernel verifiers. The volatile local stops
/// LLVM replacing that bound with its stronger language-level branch proof.
#[inline(always)]
pub fn related_checksum_copy_length(length: u32) -> Option<u32> {
    if length == 0 || length > 64 {
        return None;
    }
    let length = unsafe { core::ptr::read_volatile(&length) };
    Some((length.wrapping_sub(1) & 63) + 1)
}

/// Candidate physical-policy tuple at TC before deferred hairpin source NAT.
/// This is NOT an admission decision. The caller must first prove an exact,
/// unexpired dual-NAT mapping, then require live firewall state under the
/// packet's physical interface policy. Global canonical state alone is unsafe.
#[inline(always)]
pub fn related_hairpin_firewall_candidate(
    original: &FlowKey,
    restored: &FlowKey,
    candidate: &mut FlowKey,
) -> bool {
    if !matches!(original.proto, ip_proto::TCP | ip_proto::UDP)
        || original.proto != restored.proto
        || original.src_ip == restored.src_ip
        || original.dst_ip == restored.dst_ip
    {
        return false;
    }
    *candidate = *original;
    candidate.src_ip = restored.src_ip;
    candidate.src_port = restored.src_port;
    true
}

/// Supported error types, with Linux conntrack's opaque code handling. Unknown
/// codes are delivered to the endpoint, not promoted into additional policy
/// permissions. Redirect and source-quench intentionally remain unsupported;
/// echo cannot quote itself into an error permission.
#[inline(always)]
pub const fn related_icmp_error(kind: u8, _code: u8) -> bool {
    matches!(kind, 3 | 11 | 12)
}

/// Repair every checksum nested in an ICMP error. Echo uses FirewallKey's
/// identifier/type convention; TCP/UDP use ordinary source/destination ports.
#[inline(always)]
pub fn related_checksums(
    before: &FlowKey,
    after: &FlowKey,
    checksums: RelatedChecksums,
) -> RelatedChecksums {
    let mut result = checksums;
    let mut transport = checksums.transport.unwrap_or(0);
    let update_transport =
        checksums.transport.is_some() && !(before.proto == ip_proto::UDP && transport == 0);
    let mut i = 0;
    while i < 4 {
        let old = u16::from_be_bytes([before.src_ip[i], before.src_ip[i + 1]]);
        let new = u16::from_be_bytes([after.src_ip[i], after.src_ip[i + 1]]);
        result.ip = csum_replace_u16(result.ip, old, new);
        result.error = csum_replace_u16(result.error, old, new);
        if update_transport && before.proto != ip_proto::ICMP {
            transport = csum_replace_u16(transport, old, new);
        }
        let old = u16::from_be_bytes([before.dst_ip[i], before.dst_ip[i + 1]]);
        let new = u16::from_be_bytes([after.dst_ip[i], after.dst_ip[i + 1]]);
        result.ip = csum_replace_u16(result.ip, old, new);
        result.error = csum_replace_u16(result.error, old, new);
        if update_transport && before.proto != ip_proto::ICMP {
            transport = csum_replace_u16(transport, old, new);
        }
        i += 2;
    }
    result.error = csum_replace_u16(result.error, checksums.ip, result.ip);
    result.error = csum_replace_u16(result.error, before.src_port, after.src_port);
    if update_transport {
        transport = csum_replace_u16(transport, before.src_port, after.src_port);
    }
    if before.proto != ip_proto::ICMP {
        result.error = csum_replace_u16(result.error, before.dst_port, after.dst_port);
        if update_transport {
            transport = csum_replace_u16(transport, before.dst_port, after.dst_port);
        }
    }
    if update_transport {
        // RFC 768: the computed zero checksum is transmitted as all ones.
        if before.proto == ip_proto::UDP && transport == 0 {
            transport = u16::MAX;
        }
        result.error = csum_replace_u16(result.error, checksums.transport.unwrap_or(0), transport);
        result.transport = Some(transport);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use super::*;

    #[test]
    fn hairpin_candidate_is_the_exact_physical_pre_source_nat_tuple() {
        for proto in [ip_proto::TCP, ip_proto::UDP] {
            let wire = FlowKey::new(7, [10, 0, 0, 1], [10, 0, 0, 51], 44000, 8080, proto);
            let restored = FlowKey::new(0, [10, 0, 0, 50], [198, 51, 100, 1], 42000, 80, proto);
            let mut candidate = wire;
            assert!(related_hairpin_firewall_candidate(
                &wire,
                &restored,
                &mut candidate
            ));
            assert_eq!(
                candidate,
                FlowKey::new(7, restored.src_ip, wire.dst_ip, 42000, 8080, proto)
            );
            // The candidate keeps the real hook's policy, destination and L4
            // protocol. It is not the globally scoped canonical client/VIP key.
            assert_ne!(candidate, restored);
        }
    }

    #[test]
    fn one_sided_nat_or_protocol_mismatch_cannot_make_a_hairpin_candidate() {
        let wire = FlowKey::new(7, [10, 0, 0, 1], [10, 0, 0, 51], 44000, 8080, ip_proto::UDP);
        let mut restored = wire;
        let mut candidate = wire;
        assert!(!related_hairpin_firewall_candidate(
            &wire,
            &restored,
            &mut candidate
        ));
        restored.src_ip = [10, 0, 0, 50];
        assert!(!related_hairpin_firewall_candidate(
            &wire,
            &restored,
            &mut candidate
        ));
        restored = wire;
        restored.dst_ip = [198, 51, 100, 1];
        assert!(!related_hairpin_firewall_candidate(
            &wire,
            &restored,
            &mut candidate
        ));
        restored.src_ip = [10, 0, 0, 50];
        restored.proto = ip_proto::TCP;
        assert!(!related_hairpin_firewall_candidate(
            &wire,
            &restored,
            &mut candidate
        ));
        let echo = FlowKey {
            proto: ip_proto::ICMP,
            ..wire
        };
        restored.proto = ip_proto::ICMP;
        assert!(!related_hairpin_firewall_candidate(
            &echo,
            &restored,
            &mut candidate
        ));
    }

    // Independent full Internet checksum, not the incremental implementation.
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u64;
        for word in bytes.chunks(2) {
            sum += (u16::from(word[0]) << 8 | u16::from(*word.get(1).unwrap_or(&0))) as u64;
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn transport_checksum(flow: &FlowKey, segment: &[u8]) -> u16 {
        let mut bytes = Vec::new();
        if flow.proto != ip_proto::ICMP {
            bytes.extend_from_slice(&flow.src_ip);
            bytes.extend_from_slice(&flow.dst_ip);
            bytes.extend_from_slice(&[0, flow.proto]);
            bytes.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        }
        bytes.extend_from_slice(segment);
        checksum(&bytes)
    }

    fn exercise(
        proto: u8,
        quote_len: usize,
        options: usize,
        disabled: bool,
        quote_checksum_corruption: u16,
    ) {
        let before = FlowKey::new(
            41,
            [192, 0, 2, 10],
            [198, 51, 100, 20],
            49001,
            if proto == 1 { 8 } else { 8080 },
            proto,
        );
        let after = FlowKey::new(
            41,
            [10, 0, 0, 7],
            [203, 0, 113, 8],
            1234,
            if proto == 1 { 8 } else { 53 },
            proto,
        );
        let mut segment = vec![0u8; if proto == 6 { 37 } else { 29 }];
        let check_off = match proto {
            6 => 16,
            17 => 6,
            _ => 2,
        };
        if proto == 1 {
            segment[0] = 8;
            segment[4..6].copy_from_slice(&before.src_port.to_be_bytes());
        } else {
            segment[..2].copy_from_slice(&before.src_port.to_be_bytes());
            segment[2..4].copy_from_slice(&before.dst_port.to_be_bytes());
            if proto == 17 {
                let len = segment.len() as u16;
                segment[4..6].copy_from_slice(&len.to_be_bytes());
            } else {
                segment[12] = 0x50;
                segment[13] = 0x18;
            }
        }
        for (i, byte) in segment.iter_mut().enumerate().skip(20) {
            *byte = (i * 17) as u8;
        }
        let tc = if disabled {
            0
        } else {
            transport_checksum(&before, &segment)
        };
        segment[check_off..check_off + 2].copy_from_slice(&tc.to_be_bytes());
        let ihl = 20 + options;
        let mut ip = vec![0u8; ihl];
        ip[0] = 0x40 | (ihl / 4) as u8;
        ip[2..4].copy_from_slice(&((ihl + segment.len()) as u16).to_be_bytes());
        ip[8] = 1;
        ip[9] = proto;
        ip[12..16].copy_from_slice(&before.src_ip);
        ip[16..20].copy_from_slice(&before.dst_ip);
        ip[20..].fill(1); // NOP options
        let ic = checksum(&ip) ^ quote_checksum_corruption;
        ip[10..12].copy_from_slice(&ic.to_be_bytes());
        let original_quote_residual = checksum(&ip);
        assert_eq!(original_quote_residual == 0, quote_checksum_corruption == 0);
        let mut error = vec![3, 4, 0, 0, 0, 0, 5, 120]; // MTU 1400, preserved
        error.extend_from_slice(&ip);
        error.extend_from_slice(&segment[..quote_len]);
        let ec = checksum(&error);
        error[2..4].copy_from_slice(&ec.to_be_bytes());
        let fixed = related_checksums(
            &before,
            &after,
            RelatedChecksums {
                ip: ic,
                transport: (quote_len >= check_off + 2).then_some(tc),
                error: ec,
            },
        );
        ip[12..16].copy_from_slice(&after.src_ip);
        ip[16..20].copy_from_slice(&after.dst_ip);
        ip[10..12].copy_from_slice(&fixed.ip.to_be_bytes());
        // A quote is data carried inside the valid ICMP envelope. Linux NAT
        // adjusts its checksum incrementally, preserving any original corrupt
        // residual instead of repairing it into a valid packet.
        assert_eq!(checksum(&ip), original_quote_residual);
        if proto == 1 {
            segment[4..6].copy_from_slice(&after.src_port.to_be_bytes());
        } else {
            segment[..2].copy_from_slice(&after.src_port.to_be_bytes());
            segment[2..4].copy_from_slice(&after.dst_port.to_be_bytes());
        }
        if let Some(tc) = fixed.transport {
            segment[check_off..check_off + 2].copy_from_slice(&tc.to_be_bytes());
            if !disabled {
                assert_eq!(transport_checksum(&after, &segment), 0);
            } else {
                assert_eq!(tc, 0);
            }
        }
        error.truncate(8);
        error.extend_from_slice(&ip);
        error.extend_from_slice(&segment[..quote_len]);
        error[2..4].copy_from_slice(&fixed.error.to_be_bytes());
        assert_eq!(checksum(&error), 0);
        assert_eq!(&error[4..8], &[0, 0, 5, 120]);
    }

    #[test]
    fn nested_checksums_match_full_rfc1071_oracle() {
        for options in [0, 4, 40] {
            for quote in [8, 17, 18, 20, 37] {
                exercise(6, quote, options, false, 0);
            }
            for quote in [8, 9, 29] {
                exercise(17, quote, options, false, 0);
                exercise(17, quote, options, true, 0);
                exercise(1, quote, options, false, 0);
            }
        }
    }

    #[test]
    fn corrupt_quoted_checksum_keeps_its_residual_and_valid_outer_error() {
        for bit in 0..16 {
            let corruption = 1 << bit;
            for options in [0, 4, 40] {
                for quote in [8, 17, 18, 20, 37] {
                    exercise(6, quote, options, false, corruption);
                }
                for quote in [8, 9, 29] {
                    exercise(17, quote, options, false, corruption);
                    exercise(17, quote, options, true, corruption);
                    exercise(1, quote, options, false, corruption);
                }
            }
        }
    }

    #[test]
    fn supported_error_types_preserve_all_codes_like_linux_conntrack() {
        for kind in 0..=255u8 {
            for code in 0..=255u8 {
                assert_eq!(related_icmp_error(kind, code), matches!(kind, 3 | 11 | 12));
            }
        }
    }

    #[test]
    fn checksum_copy_length_preserves_every_valid_size_and_rejects_boundaries() {
        for length in 1..=64 {
            assert_eq!(related_checksum_copy_length(length), Some(length));
        }
        for length in [0, 65, 66, 127, 128, 65535, u32::MAX - 1, u32::MAX] {
            assert_eq!(related_checksum_copy_length(length), None);
        }
    }

    #[test]
    fn padded_chunk_checksum_matches_independent_full_sum_through_maximum_ip_size() {
        for length in [
            1, 2, 3, 4, 5, 63, 64, 65, 127, 128, 129, 511, 512, 513, 65507, 65515, 65535,
        ] {
            let payload: Vec<u8> = (0..length).map(|n| (n * 71 + 19) as u8).collect();
            let mut seed = 0u64;
            for chunk in payload.chunks(64) {
                let count = related_checksum_copy_length(chunk.len() as u32).unwrap();
                let mut padded = [0u8; 64];
                padded[..count as usize].copy_from_slice(chunk);
                for word in padded.chunks_exact(2) {
                    seed += u16::from_le_bytes([word[0], word[1]]) as u64;
                }
                while seed >> 16 != 0 {
                    seed = (seed & 65535) + (seed >> 16);
                }
            }
            let result = (!(seed as u16)).to_le_bytes();
            assert_eq!(result, checksum(&payload).to_be_bytes(), "length {length}");
        }
    }
}
