//! Narrow validation for replies to a declared local Ethernet DHCPv4 client.
//! This is not DHCP authentication: the local client still verifies transactions,
//! options and checksums. It must never open arbitrary traffic on UDP port 68.

/// Kernel uapi `BPF_FIB_LKUP_RET_NOT_FWDED`. A unicast destination with a
/// non-unicast route type (local, broadcast, anycast) produces this code, and
/// only after `bpf_ipv4_fib_lookup` has passed the ingress forwarding check.
pub const DHCP_FIB_NOT_FORWARDED: i32 = 4;

/// Whether `bpf_fib_lookup` proved that a unicast DHCPv4 reply is local.
///
/// `BPF_FIB_LKUP_RET_FWD_DISABLED` (5) is returned before any route lookup when
/// forwarding is disabled on the ingress interface (Linux 6.12
/// `net/core/filter.c`, `bpf_ipv4_fib_lookup`). It does not distinguish a local
/// address from a stale owned-address entry that is now routable, so it must
/// not admit the firewall exception. Success and `NO_NEIGH` mean the
/// destination is forwarded unicast.
#[inline(always)]
pub fn dhcp_fib_is_local(rc: i64) -> bool {
    rc == i64::from(DHCP_FIB_NOT_FORWARDED)
}

/// Check the fixed headers without copying the 240-byte BOOTP prefix onto the
/// BPF stack. The caller bounds-checks the full IPv4 datagram and separately
/// proves that its destination is broadcast or an address owned by this NIC.
#[inline(always)]
pub fn dhcpv4_reply_matches(
    ip: &[u8; 20],
    udp: &[u8; 8],
    bootp: &[u8; 240],
    local_mac: &[u8; 8],
) -> bool {
    let ihl = (ip[0] & 15) as u16 * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]);
    let length = u16::from_be_bytes([udp[4], udp[5]]);
    ip[0] >> 4 == 4
        // DHCP does not need source-route or other IPv4 options. Do not admit
        // a nominally local datagram which an option could make routable.
        && ihl == 20
        && ip[9] == 17
        && u16::from_be_bytes([ip[6], ip[7]]) & 0xbfff == 0
        && total >= ihl + 248
        && length == total - ihl
        && udp[0] == 0
        && udp[1] == 67
        && udp[2] == 0
        && udp[3] == 68
        && ip[12] != 0
        && ip[12] != 127
        && ip[12] < 224
        && bootp[0] == 2
        && bootp[1] == 1
        && bootp[2] == 6
        && bootp[28] == local_mac[0]
        && bootp[29] == local_mac[1]
        && bootp[30] == local_mac[2]
        && bootp[31] == local_mac[3]
        && bootp[32] == local_mac[4]
        && bootp[33] == local_mac[5]
        && bootp[236] == 99
        && bootp[237] == 130
        && bootp[238] == 83
        && bootp[239] == 99
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ([u8; 20], [u8; 8], [u8; 240], [u8; 8]) {
        let mut ip = [0; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&268u16.to_be_bytes());
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[198, 18, 88, 1]);
        let udp = [0, 67, 0, 68, 0, 248, 0, 0];
        let mac = [2, 3, 4, 5, 6, 7, 0, 0];
        let mut bootp = [0; 240];
        bootp[0..3].copy_from_slice(&[2, 1, 6]);
        bootp[28..34].copy_from_slice(&mac[..6]);
        bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        (ip, udp, bootp, mac)
    }

    #[test]
    fn accepts_valid_reply_with_ethernet_client_identity() {
        let (ip, udp, bootp, mac) = fixture();
        assert!(dhcpv4_reply_matches(&ip, &udp, &bootp, &mac));
    }

    #[test]
    fn refuses_wrong_ports_protocol_and_ip_version() {
        let (ip, udp, bootp, mac) = fixture();
        for field in 0..4 {
            let mut bad = udp;
            bad[field] ^= 1;
            assert!(!dhcpv4_reply_matches(&ip, &bad, &bootp, &mac));
        }
        for (offset, value) in [(0, 0x65), (0, 0x44), (0, 0x46), (9, 6)] {
            let mut bad = ip;
            bad[offset] = value;
            assert!(!dhcpv4_reply_matches(&bad, &udp, &bootp, &mac));
        }
    }

    #[test]
    fn refuses_fragments_and_inconsistent_lengths() {
        let (ip, udp, bootp, mac) = fixture();
        for (offset, value) in [(6, 0x20), (6, 0x80), (7, 1), (2, 0), (3, 0)] {
            let mut bad = ip;
            bad[offset] = value;
            assert!(!dhcpv4_reply_matches(&bad, &udp, &bootp, &mac));
        }
        for value in [247u16, 249, 65535] {
            let mut bad = udp;
            bad[4..6].copy_from_slice(&value.to_be_bytes());
            assert!(!dhcpv4_reply_matches(&ip, &bad, &bootp, &mac));
        }
    }

    #[test]
    fn allows_dont_fragment_but_no_other_fragment_bits() {
        let (mut ip, udp, bootp, mac) = fixture();
        ip[6] = 0x40;
        assert!(dhcpv4_reply_matches(&ip, &udp, &bootp, &mac));
    }

    #[test]
    fn refuses_requests_wrong_hardware_cookie_and_foreign_client() {
        let (ip, udp, bootp, mac) = fixture();
        for offset in [0, 1, 2, 28, 29, 30, 31, 32, 33, 236, 237, 238, 239] {
            let mut bad = bootp;
            bad[offset] ^= 1;
            assert!(!dhcpv4_reply_matches(&ip, &udp, &bad, &mac));
        }
    }

    #[test]
    fn refuses_nonunicast_server_sources() {
        let (ip, udp, bootp, mac) = fixture();
        for first in [0, 127, 224, 239, 240, 255] {
            let mut bad = ip;
            bad[12] = first;
            assert!(!dhcpv4_reply_matches(&bad, &udp, &bootp, &mac));
        }
    }

    #[test]
    fn unicast_dhcp_exception_requires_a_not_forwarded_fib_result() {
        assert!(dhcp_fib_is_local(i64::from(DHCP_FIB_NOT_FORWARDED)));
        // FWD_DISABLED, SUCCESS, BLACKHOLE, UNREACHABLE, PROHIBIT, NO_NEIGH,
        // FRAG_NEEDED, NO_SRC_ADDR, and a helper refusal (-ENODEV = -19).
        for rc in [5i64, 0, 1, 2, 3, 7, 8, 9, -19] {
            assert!(
                !dhcp_fib_is_local(rc),
                "rc {rc} must not prove a local destination"
            );
        }
    }
}
