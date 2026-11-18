//! Containment of unsupported forwarded IPv4 fragmentation on a masquerade
//! uplink. This is not reassembly or working fragmented NAT.

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
