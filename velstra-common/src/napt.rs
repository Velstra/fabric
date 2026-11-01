//! Bounded source-NAT port candidates, shared by the datapath and tests.
use crate::CgnatLayout;

/// Bound allocation work per packet. Exhaustion drops the packet; it must never
/// fall back outside a subscriber's port block or replace another flow's key.
pub const NAPT_PROBES: u16 = 8;

/// Mix every byte of a flow's addresses and ports before reducing to a port.
/// In particular, placing the source port only in the high bits and then taking
/// a power-of-two modulus discards its entropy entirely.
#[inline(always)]
pub fn napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    let mut h = u32::from_be_bytes(src)
        ^ u32::from_be_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ dport as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x7feb_352d);
    h ^= h >> 15;
    h = h.wrapping_mul(0x846c_a68b);
    h ^ (h >> 16)
}

/// Candidate inside the configured subscriber block, or the ephemeral range
/// [32768, 65535] when deterministic blocks are disabled. Never returns zero.
#[inline(always)]
pub fn napt_candidate(layout: CgnatLayout, src: [u8; 4], seed: u32, i: u16) -> u16 {
    match layout.candidate(src, seed, i) {
        Some(port) => port,
        None => 32768 + (seed.wrapping_add(i as u32) % 32768) as u16,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn source_ports_spread_across_the_ephemeral_range() {
        let ports: BTreeSet<_> = (40000..41000)
            .map(|sport| {
                napt_candidate(
                    CgnatLayout::default(),
                    [10, 0, 0, 2],
                    napt_seed([10, 0, 0, 2], [198, 18, 0, 2], sport, 443),
                    0,
                )
            })
            .collect();
        assert!(
            ports.len() > 950,
            "source-port entropy was lost: {} candidates",
            ports.len()
        );
    }

    #[test]
    fn candidates_never_escape_a_subscriber_block() {
        for size in [1, 3, 8, 512, 32768] {
            let layout = CgnatLayout::new(32768, size);
            for src in [[10, 0, 0, 2], [10, 90, 0, 2], [192, 0, 2, 254]] {
                let (first, last) = layout.range_of(src).unwrap();
                for seed in [0, 1, u32::MAX, napt_seed(src, [198, 18, 0, 2], 44331, 443)] {
                    for i in 0..NAPT_PROBES {
                        assert!((first..=last).contains(&napt_candidate(layout, src, seed, i)));
                    }
                }
            }
        }
    }

    #[test]
    fn ephemeral_candidates_wrap_without_using_reserved_ports() {
        let ports: Vec<_> = (0..NAPT_PROBES)
            .map(|i| napt_candidate(CgnatLayout::default(), [0; 4], u32::MAX, i))
            .collect();
        assert_eq!(
            ports,
            [65535, 32768, 32769, 32770, 32771, 32772, 32773, 32774]
        );
    }
}
