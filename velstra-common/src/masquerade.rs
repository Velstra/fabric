//! The `MASQUERADE` map's contract: egress ifindex → the address to translate to.
//!
//! An uplink that masquerades and has lost its address (a DHCP lease that
//! lapsed, a PPPoE session that dropped) used to lose its entry. Without one, a
//! packet leaving it is not masqueraded at all — it falls through to the plain
//! egress policy, which passes by default, and a LAN host's private source
//! address goes out onto the provider's wire whenever a route out of the uplink
//! survives the lease. So the entry stays, holding [`UNADDRESSED`], and the data
//! plane reads that as "nothing may leave here but the box asking for an address".

/// The value an uplink's `MASQUERADE` entry holds while it has no IPv4 address.
///
/// The unspecified address, because it is the one value that can never be a
/// real translation target — and because it is exactly the source a DHCP client
/// sends from before it has a lease, which is the traffic that must still leave.
pub const UNADDRESSED: [u8; 4] = [0; 4];

/// Whether an IPv4 packet with source `src` must be dropped leaving an uplink
/// whose `MASQUERADE` entry is `nat_ip`.
///
/// Only an unaddressed masquerade uplink drops, and it drops everything except
/// what is itself unaddressed: a forwarded packet would leave with an internal
/// source, and the box's own packet — from some other interface's address —
/// would leave un-translated the same way. What remains is the DHCP client's
/// DISCOVER/REQUEST, sent from `0.0.0.0`, which is how the uplink gets an
/// address back.
#[inline(always)]
pub fn unaddressed_uplink_drops(nat_ip: Option<[u8; 4]>, src: [u8; 4]) -> bool {
    matches!(nat_ip, Some(ip) if ip == UNADDRESSED) && src != UNADDRESSED
}

/// Stable per-flow seed for bounded masquerade port allocation.
///
/// Fold the complete tuple into the low bits BEFORE reducing it to the port
/// range. Multiplication alone cannot do that: source ports in the upper16bits
/// would otherwise disappear modulo32768, making every such client compete
/// for the same eight ports. Explicit network order is architecture independent.
/// This is distribution, not a cryptographic secret or a SYN-cookie primitive.
#[inline(always)]
pub fn napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    let mut hash = u32::from_be_bytes(src)
        ^ u32::from_be_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ dport as u32;
    // Fixed-cost 32-bit avalanche; no allocation, loop, helper or map lookup.
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x7feb_352d);
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(0x846c_a68b);
    hash ^ (hash >> 16)
}

/// Allocator used by deployed images before the avalanche correction.
///
/// Only search for an EXISTING replicated binding with this seed. Never
/// allocate a new flow from it: its poor distribution is the bug corrected by
/// [`napt_seed`]. Keep this compatibility search while rolling upgrades from
/// that allocator are supported. A chosen public port is connection state, not
/// something an upgraded peer may replace with its own preferred candidate.
#[inline(always)]
pub fn legacy_napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    (u32::from_le_bytes(src)
        ^ u32::from_le_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ dport as u32)
        .wrapping_mul(2654435761)
}

/// An allocation belongs to this inside endpoint only when it is a genuine
/// single-ended masquerade entry, not a coincident DNAT/hairpin target.
#[inline(always)]
pub fn napt_binding_matches(state: &crate::FlowState, origin: [u8; 4], port: u16) -> bool {
    state.flags == crate::FlowState::ORIGIN
        && state.nat_ip == origin
        && state.nat_port == port
        && state.nat2_ip == [0; 4]
        && state.nat2_port == 0
}

/// Bounded existing-binding search shared with the real egress dataplane.
/// A free/foreign/expired earlier slot is NOT a reason to stop looking for the
/// allocation this connection already owns. Zero means no existing allocation.
#[inline(always)]
pub fn napt_find_existing(
    src: [u8; 4],
    seed: u32,
    layout: &crate::CgnatLayout,
    mut belongs_to_flow: impl FnMut(u16) -> bool,
) -> u16 {
    for probe in 0..8 {
        let candidate = layout
            .candidate(src, seed, probe)
            .unwrap_or_else(|| napt_port(seed, probe));
        if belongs_to_flow(candidate) {
            return candidate;
        }
    }
    0
}

/// Candidate `i` in the inclusive ephemeral range32768..65535, never port0.
/// The dataplane retains its separate small, verifier-bounded probe count.
#[inline(always)]
pub fn napt_port(seed: u32, i: u16) -> u16 {
    32768 + (seed.wrapping_add(i as u32) % 32768) as u16
}

/// What the egress masquerade path may do after the port probe.
///
/// A translated packet and its reverse conntrack entry are one publication.
/// Installing either without the other leaves a private source on the wire or
/// a public port that DNATs an unsolicited packet to the inside host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasqueradeCommit {
    /// Reverse state exists and this packet was rewritten to the public tuple.
    Translated,
    /// Do not emit the packet. Leave any pre-existing binding in place.
    Drop,
    /// Do not emit the packet, and delete the reverse binding just created.
    DropAndForget,
}

/// `existing` is a live binding for this inside endpoint. `inserted` is a new
/// reverse entry created for this packet. `rewritten` is true only when the
/// source translation of this packet succeeded.
#[inline(always)]
pub fn masquerade_commit(existing: bool, inserted: bool, rewritten: bool) -> MasqueradeCommit {
    if existing {
        return if rewritten {
            MasqueradeCommit::Translated
        } else {
            MasqueradeCommit::Drop
        };
    }
    if !inserted || !rewritten {
        return if inserted {
            MasqueradeCommit::DropAndForget
        } else {
            MasqueradeCommit::Drop
        };
    }
    MasqueradeCommit::Translated
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn mixed_version_native_reset_tuple_has_distinct_old_and_new_windows() {
        // Actual two-node rolling trace: old owner39759, upgraded owner57646,
        // same TCP sequence; the independent backend reset the new tuple.
        let src = [198, 18, 20, 50];
        let dst = [198, 18, 10, 253];
        let old = legacy_napt_seed(src, dst, 43251, 19251);
        let current = napt_seed(src, dst, 43251, 19251);
        assert_eq!(napt_port(old, 0), 39759);
        assert_eq!(napt_port(current, 0), 57646);
        assert!((0..8).all(|i| napt_port(current, i) != napt_port(old, 0)));
        assert!(napt_binding_matches(
            &crate::FlowState::masquerade(src, 43251),
            src,
            43251
        ));
        let layout = crate::CgnatLayout::default();
        let allocated = napt_port(old, 0);
        assert_eq!(
            napt_find_existing(src, current, &layout, |p| p == allocated),
            0
        );
        assert_eq!(
            napt_find_existing(src, old, &layout, |p| p == allocated),
            allocated
        );
    }

    #[test]
    fn free_earlier_collision_slots_cannot_renumber_an_established_flow() {
        let src = [198, 18, 20, 50];
        let seed = napt_seed(src, [198, 18, 10, 253], 43251, 19251);
        for layout in [
            crate::CgnatLayout::default(),
            crate::CgnatLayout::new(1024, 64),
        ] {
            for occupied_probe in 1..8 {
                let allocated = layout
                    .candidate(src, seed, occupied_probe)
                    .unwrap_or_else(|| napt_port(seed, occupied_probe));
                let mut observed = Vec::new();
                assert_eq!(
                    napt_find_existing(src, seed, &layout, |candidate| {
                        observed.push(candidate);
                        candidate == allocated
                    }),
                    allocated
                );
                assert_eq!(observed.len(), usize::from(occupied_probe) + 1);
            }
            let mut probes = 0;
            assert_eq!(
                napt_find_existing(src, seed, &layout, |_| {
                    probes += 1;
                    false
                }),
                0
            );
            assert_eq!(probes, 8);
        }
    }

    #[test]
    fn masquerade_ownership_never_accepts_dnat_hairpin_or_another_endpoint() {
        let ip = [192, 0, 2, 7];
        let state = crate::FlowState::masquerade(ip, 43000);
        assert!(napt_binding_matches(&state, ip, 43000));
        assert!(!napt_binding_matches(&state, [192, 0, 2, 8], 43000));
        assert!(!napt_binding_matches(&state, ip, 43001));
        assert!(!napt_binding_matches(
            &crate::FlowState::forward(ip, 43000),
            ip,
            43000
        ));
        assert!(!napt_binding_matches(
            &crate::FlowState::reverse(ip, 43000),
            ip,
            43000
        ));
        for changed in [
            crate::FlowState {
                nat2_ip: [192, 0, 2, 1],
                ..state
            },
            crate::FlowState {
                nat2_port: 7,
                ..state
            },
            crate::FlowState {
                flags: state.flags | crate::FlowState::REVERSE,
                ..state
            },
        ] {
            assert!(!napt_binding_matches(&changed, ip, 43000));
        }
    }

    #[test]
    fn native_ten_session_regression_no_longer_collapses_to_one_eight_port_window() {
        let src = [198, 18, 20, 50];
        let dst = [198, 18, 10, 254];
        let mut legacy = BTreeSet::new();
        let mut corrected = BTreeSet::new();
        for sport in 43000..43010 {
            let old = (u32::from_le_bytes(src)
                ^ u32::from_le_bytes(dst).rotate_left(16)
                ^ ((sport as u32) << 16)
                ^ 9101)
                .wrapping_mul(2654435761);
            let seed = napt_seed(src, dst, sport, 9101);
            for probe in 0..8 {
                legacy.insert(napt_port(old, probe));
                corrected.insert(napt_port(seed, probe));
            }
        }
        // Exact observed x86_64 defect remains an explicit negative control.
        assert_eq!(legacy.len(), 8);
        assert!(corrected.len() >= 64, "{corrected:?}");
    }

    #[test]
    fn every_tuple_bit_affects_the_seed_not_just_the_destination_port() {
        let src = u32::from_be_bytes([198, 18, 20, 50]);
        let dst = u32::from_be_bytes([198, 18, 10, 254]);
        let seed = napt_seed(src.to_be_bytes(), dst.to_be_bytes(), 43000, 9101);
        for bit in 0..32 {
            assert_ne!(
                seed,
                napt_seed(
                    (src ^ (1 << bit)).to_be_bytes(),
                    dst.to_be_bytes(),
                    43000,
                    9101
                )
            );
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    (dst ^ (1 << bit)).to_be_bytes(),
                    43000,
                    9101
                )
            );
        }
        for bit in 0..16 {
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    dst.to_be_bytes(),
                    43000 ^ (1 << bit),
                    9101
                )
            );
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    dst.to_be_bytes(),
                    43000,
                    9101 ^ (1 << bit)
                )
            );
        }
    }

    #[test]
    fn adjacent_client_ports_and_addresses_spread_over_the_ephemeral_range() {
        for source in [
            [198, 18, 20, 50],
            [198, 18, 20, 51],
            [192, 0, 2, 18],
            [192, 0, 3, 18],
        ] {
            let bases: BTreeSet<_> = (32768..=65535)
                .map(|sport| napt_port(napt_seed(source, [198, 18, 10, 254], sport, 10920), 0))
                .collect();
            // A uniform32768-sample/32768-bin distribution occupies about20713
            // bins; the old implementation occupies exactly one for each IP.
            assert!(bases.len() > 20000, "{source:?}: {} bins", bases.len());
        }
    }

    #[test]
    fn candidates_stay_in_range_and_wrap_without_overflow() {
        for seed in [0, 1, 32767, 32768, u32::MAX - 7, u32::MAX] {
            for probe in 0..=u16::MAX {
                assert!((32768..=65535).contains(&napt_port(seed, probe)));
            }
            let candidates: BTreeSet<_> = (0..8).map(|probe| napt_port(seed, probe)).collect();
            assert_eq!(candidates.len(), 8);
        }
    }

    #[test]
    fn an_unaddressed_uplink_carries_only_its_own_address_request() {
        // A LAN host's forwarded packet, and the box's own from another link.
        assert!(unaddressed_uplink_drops(
            Some(UNADDRESSED),
            [192, 168, 1, 10]
        ));
        assert!(unaddressed_uplink_drops(Some(UNADDRESSED), [10, 0, 0, 1]));
        // The DHCP client asking for a lease.
        assert!(!unaddressed_uplink_drops(Some(UNADDRESSED), [0, 0, 0, 0]));
    }

    #[test]
    fn an_addressed_or_ordinary_link_is_not_this_rule_s_business() {
        assert!(!unaddressed_uplink_drops(
            Some([203, 0, 113, 9]),
            [192, 168, 1, 10]
        ));
        assert!(!unaddressed_uplink_drops(None, [192, 168, 1, 10]));
    }

    #[test]
    fn masquerade_drops_when_reverse_state_or_rewrite_is_missing() {
        // Map insert failed, or every probe was occupied: do not translate.
        assert_eq!(
            masquerade_commit(false, false, false),
            MasqueradeCommit::Drop
        );
        // A rewrite reported without a binding is still not publishable.
        assert_eq!(
            masquerade_commit(false, false, true),
            MasqueradeCommit::Drop
        );
        // New binding installed, packet rewrite failed: forget the binding so
        // the public port cannot DNAT an unsolicited packet, and do not emit
        // the original private source.
        assert_eq!(
            masquerade_commit(false, true, false),
            MasqueradeCommit::DropAndForget
        );
        // Existing binding, this packet could not be rewritten: drop it and
        // keep the binding created by an earlier successful packet.
        assert_eq!(
            masquerade_commit(true, false, false),
            MasqueradeCommit::Drop
        );
        assert_eq!(
            masquerade_commit(false, true, true),
            MasqueradeCommit::Translated
        );
        assert_eq!(
            masquerade_commit(true, false, true),
            MasqueradeCommit::Translated
        );
    }
}
