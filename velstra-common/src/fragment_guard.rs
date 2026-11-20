//! Forwarded IPv4 fragments through NAT: the first fragment is translated with
//! its datagram's L4 header and records the rewrite; later fragments receive the
//! same address rewrite. A later fragment without a record is refused on a
//! masquerade uplink rather than leaving with an untranslated source.

/// Refuse a nonlocal-source fragment on a masquerade uplink. `fragment_word` is
/// the IPv4 flags/offset word in host order: MF and a nonzero offset both count,
/// DF alone does not. A fragment has no independently usable transport tuple.
///
/// Already-public sources and addresses owned by this egress interface do not
/// need ordinary masquerade. This address exemption is not proof of local
/// origin. The caller supplies ownership from the agent's
/// live per-interface registry, not from packet contents or an RFC1918 test.
/// Fragmented routed replies without a provable tuple are conservatively
/// refused too. Non-masquerade links are unaffected. Special local HA
/// translation, ingress DNAT and paths bypassing TC remain separate limitations.
#[inline(always)]
pub fn forwarded_masquerade_fragment_drops(
    nat_ip: Option<[u8; 4]>,
    source: [u8; 4],
    fragment_word: u16,
    source_owned_by_egress: bool,
) -> bool {
    fragment_word & 0x3fff != 0
        && nat_ip.is_some_and(|public| public != source)
        && !source_owned_by_egress
}

/// Which hook translated a datagram's first fragment. Ingress (XDP) and egress
/// (TC) records are kept apart so a datagram's two NAT directions never alias.
pub const FRAGMENT_HOOK_EGRESS: u8 = 0;
pub const FRAGMENT_HOOK_INGRESS: u8 = 1;

/// How long a later fragment may follow its datagram's first fragment. Linux
/// keeps an incomplete reassembly for 30 s (`ipfrag_time`).
pub const FRAGMENT_NAT_TIMEOUT_NS: u64 = 30_000_000_000;

/// The datagram a fragment belongs to (RFC 791: source, destination, protocol
/// and identification), as it looked BEFORE translation. Only the first
/// fragment carries the L4 header, so ports cannot be part of the key.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    /// IPv4 identification, host order.
    pub id: u16,
    pub proto: u8,
    /// `FRAGMENT_HOOK_*`.
    pub hook: u8,
}

/// The addresses the first fragment was translated to. Later fragments get the
/// same IPv4 header rewrite and nothing else: their bytes are payload, and the
/// L4 checksum (covering the whole datagram) was already adjusted in the first.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentNat {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub created_ns: u64,
}

/// Where an IPv4 packet sits in its datagram, from the flags/offset word in
/// host order. DF alone is not fragmentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FragmentPosition {
    Whole,
    /// Offset zero with More Fragments: carries the L4 header.
    First,
    /// A nonzero offset: payload only.
    Later,
}

impl FragmentPosition {
    #[inline(always)]
    pub fn of(fragment_word: u16) -> Self {
        if fragment_word & 0x1fff != 0 {
            Self::Later
        } else if fragment_word & 0x2000 != 0 {
            Self::First
        } else {
            Self::Whole
        }
    }
}

impl FragmentNat {
    /// A record is usable only within the reassembly window. A clock read on
    /// another CPU may precede the record's own timestamp: that is "fresh".
    #[inline(always)]
    pub fn live(&self, now: u64) -> bool {
        now.saturating_sub(self.created_ns) < FRAGMENT_NAT_TIMEOUT_NS
    }

    /// RFC 1624 update of an IPv4 header checksum for rewriting `old_src`/
    /// `old_dst` to this record's addresses.
    #[inline(always)]
    pub fn header_checksum(&self, checksum: u16, old_src: [u8; 4], old_dst: [u8; 4]) -> u16 {
        let checksum = replace_address(checksum, old_src, self.src);
        replace_address(checksum, old_dst, self.dst)
    }
}

#[inline(always)]
fn replace_address(checksum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let checksum = crate::csum_replace_u16(
        checksum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new[0], new[1]]),
    );
    crate::csum_replace_u16(
        checksum,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new[2], new[3]]),
    )
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FragmentKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FragmentNat {}

#[cfg(test)]
mod fragment_nat_tests {
    use super::*;

    #[test]
    fn positions_follow_the_offset_and_more_fragments_bits() {
        assert_eq!(FragmentPosition::of(0), FragmentPosition::Whole);
        assert_eq!(FragmentPosition::of(0x4000), FragmentPosition::Whole);
        assert_eq!(FragmentPosition::of(0x2000), FragmentPosition::First);
        assert_eq!(FragmentPosition::of(0x2001), FragmentPosition::Later);
        assert_eq!(FragmentPosition::of(0x00b9), FragmentPosition::Later);
        assert_eq!(FragmentPosition::of(0x1fff), FragmentPosition::Later);
    }

    #[test]
    fn layouts_are_fixed_for_the_kernel_map() {
        assert_eq!(core::mem::size_of::<FragmentKey>(), 12);
        assert_eq!(core::mem::size_of::<FragmentNat>(), 16);
    }

    fn header(src: [u8; 4], dst: [u8; 4]) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&1500u16.to_be_bytes());
        h[4..6].copy_from_slice(&0x1234u16.to_be_bytes());
        h[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
        h[8] = 64;
        h[9] = 17;
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        let c = crate::ipv4_checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h
    }

    #[test]
    fn a_later_fragment_gets_exactly_the_first_fragments_header_rewrite() {
        let private = [192, 168, 50, 100];
        let remote = [198, 18, 10, 254];
        let public = [198, 18, 10, 100];
        let before = header(private, remote);
        let nat = FragmentNat {
            src: public,
            dst: remote,
            created_ns: 5,
        };
        let checksum = nat.header_checksum(
            u16::from_be_bytes([before[10], before[11]]),
            private,
            remote,
        );
        assert_eq!(
            checksum,
            u16::from_be_bytes(header(public, remote)[10..12].try_into().unwrap())
        );
        // Destination rewrite (an inbound reply's later fragment).
        let inbound = FragmentNat {
            src: remote,
            dst: private,
            created_ns: 5,
        };
        let reply = header(remote, public);
        assert_eq!(
            inbound.header_checksum(u16::from_be_bytes([reply[10], reply[11]]), remote, public),
            u16::from_be_bytes(header(remote, private)[10..12].try_into().unwrap())
        );
    }

    #[test]
    fn a_record_outlives_neither_the_reassembly_window_nor_a_clock_race() {
        let nat = FragmentNat {
            src: [0; 4],
            dst: [0; 4],
            created_ns: 1_000,
        };
        assert!(nat.live(999));
        assert!(nat.live(1_000 + FRAGMENT_NAT_TIMEOUT_NS - 1));
        assert!(!nat.live(1_000 + FRAGMENT_NAT_TIMEOUT_NS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_middle_and_last_fragments_needing_translation_are_refused() {
        for word in [0x2000, 0x2001, 1, 0x1fff, 0x3fff, 0x6001] {
            assert!(forwarded_masquerade_fragment_drops(
                Some([198, 18, 10, 100]),
                [198, 18, 20, 50],
                word,
                false,
            ));
        }
    }

    #[test]
    fn df_unfragmented_non_nat_and_owned_sources_are_not_a_fragment_nat_path() {
        for word in [0, 0x4000, 0x8000] {
            assert!(!forwarded_masquerade_fragment_drops(
                Some([198, 18, 10, 100]),
                [198, 18, 20, 50],
                word,
                false,
            ));
        }
        for word in [0x2000, 1, 0x3fff] {
            assert!(!forwarded_masquerade_fragment_drops(
                None,
                [198, 18, 20, 50],
                word,
                false
            ));
            assert!(!forwarded_masquerade_fragment_drops(
                Some([198, 18, 10, 100]),
                [198, 18, 10, 100],
                word,
                false,
            ));
            assert!(!forwarded_masquerade_fragment_drops(
                Some([198, 18, 10, 100]),
                [198, 18, 10, 101],
                word,
                true,
            ));
        }
    }

    #[test]
    fn ownership_is_not_guessed_from_a_public_looking_source_address() {
        assert!(forwarded_masquerade_fragment_drops(
            Some([198, 18, 10, 100]),
            [203, 0, 113, 50],
            0x2000,
            false,
        ));
    }
}
