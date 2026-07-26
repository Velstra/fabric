//! Deterministic CGNAT port blocks (roadmap C16).
//!
//! Carrier NAT has to answer "who was behind this address and port at this time".
//! The usual answer is to log every translation, which is a firehose. The better
//! one is to make the mapping **deterministic**: give each internal address a fixed
//! block of WAN ports, and the question is answered by arithmetic — one line
//! recording the block assignment covers every flow inside it, forever.
//!
//! This module is that arithmetic, and nothing else. It is pure so the data plane
//! and the CLI that reports a block to an operator compute the *same* answer; two
//! implementations would eventually disagree, and a disagreement here is an
//! attribution that points at the wrong subscriber.

/// A configured port-block layout. `blocks == 0` means CGNAT is off and the plain
/// hash-spread NAPT applies.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct CgnatLayout {
    /// First WAN port that may be handed out.
    pub base_port: u16,
    /// Ports per internal address.
    pub block_size: u16,
    /// How many blocks fit above `base_port`; `0` disables CGNAT.
    pub blocks: u16,
    /// Explicit padding, always zero.
    pub _pad: u16,
}

impl CgnatLayout {
    /// Build a layout, deriving the block count from the space above `base_port`.
    ///
    /// Returns a disabled layout for a `block_size` of 0 or one that leaves no
    /// room, rather than a layout that would divide by zero or hand out port 0.
    #[inline]
    pub const fn new(base_port: u16, block_size: u16) -> Self {
        if block_size == 0 || base_port == 0 {
            return Self {
                base_port: 0,
                block_size: 0,
                blocks: 0,
                _pad: 0,
            };
        }
        // Ports [base_port, 65535] inclusive.
        let space = 65535 - base_port as u32 + 1;
        let blocks = space / block_size as u32;
        if blocks == 0 {
            return Self {
                base_port: 0,
                block_size: 0,
                blocks: 0,
                _pad: 0,
            };
        }
        Self {
            base_port,
            block_size,
            blocks: blocks as u16,
            _pad: 0,
        }
    }

    /// Whether this layout assigns blocks at all.
    #[inline]
    pub const fn is_enabled(&self) -> bool {
        self.blocks != 0 && self.block_size != 0
    }

    /// The block index an internal address is assigned to.
    ///
    /// Derived from the address alone — **not** from the flow — because that is
    /// what makes the assignment stable for the lifetime of the configuration.
    /// Mixing in a port or destination would spread one subscriber across blocks
    /// and destroy the property the whole feature exists for.
    #[inline]
    pub const fn block_of(&self, src: [u8; 4]) -> u16 {
        if !self.is_enabled() {
            return 0;
        }
        // Knuth multiplicative hash, as in the plain NAPT path: cheap and stable.
        let h = u32::from_be_bytes(src).wrapping_mul(2654435761);
        (h % self.blocks as u32) as u16
    }

    /// The inclusive `(first, last)` WAN port range assigned to `src`, or `None`
    /// when CGNAT is off.
    #[inline]
    pub const fn range_of(&self, src: [u8; 4]) -> Option<(u16, u16)> {
        if !self.is_enabled() {
            return None;
        }
        let first = self.base_port as u32 + self.block_of(src) as u32 * self.block_size as u32;
        let last = first + self.block_size as u32 - 1;
        Some((first as u16, last as u16))
    }

    /// The `i`-th candidate WAN port for a flow from `src`, kept inside that
    /// address's block. `seed` spreads a subscriber's own flows within the block so
    /// two of them do not collide on the first probe.
    #[inline]
    pub const fn candidate(&self, src: [u8; 4], seed: u32, i: u16) -> Option<u16> {
        let (first, _) = match self.range_of(src) {
            Some(r) => r,
            None => return None,
        };
        let offset = seed.wrapping_add(i as u32) % self.block_size as u32;
        Some((first as u32 + offset) as u16)
    }
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CgnatLayout {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the feature exists for: one address, one block, always. If this
    /// ever depended on the flow, an operator answering a legal request would name
    /// the wrong subscriber.
    #[test]
    fn an_address_always_lands_in_the_same_block() {
        let l = CgnatLayout::new(32768, 512);
        let src = [10, 0, 0, 7];
        let first = l.range_of(src).unwrap();
        for seed in [0u32, 1, 999, u32::MAX] {
            for i in 0..8 {
                let port = l.candidate(src, seed, i).unwrap();
                assert!(
                    (first.0..=first.1).contains(&port),
                    "seed {seed} probe {i} left the block: {port} not in {first:?}"
                );
            }
        }
        assert_eq!(l.range_of(src).unwrap(), first);
    }

    /// Blocks are contiguous, sized as configured, and start where configured — the
    /// three things an operator reads off a block assignment record.
    #[test]
    fn blocks_tile_the_range_from_the_base_port() {
        let l = CgnatLayout::new(40000, 512);
        assert!(l.is_enabled());
        // 65535 - 40000 + 1 = 25536 ports, 49 whole blocks of 512.
        assert_eq!(l.blocks, 49);
        for src in [[10, 0, 0, 1], [10, 0, 0, 2], [192, 168, 5, 9]] {
            let (first, last) = l.range_of(src).unwrap();
            assert_eq!(last - first, 511, "block is not the configured size");
            assert!(first >= 40000, "block starts below the base port");
            assert_eq!(
                (first - 40000) % 512,
                0,
                "block is not aligned to the tiling"
            );
            // (`last <= 65535` holds by construction — it is a u16.)
        }
    }

    /// A layout that cannot work must disable itself rather than produce ports.
    /// Handing out port 0, or dividing by a zero block count, would be a datapath
    /// fault for what is really a configuration mistake.
    #[test]
    fn an_impossible_layout_disables_itself() {
        for (base, size) in [(32768u16, 0u16), (0, 512), (65000, 1024)] {
            let l = CgnatLayout::new(base, size);
            assert!(
                !l.is_enabled(),
                "base {base} size {size} should be disabled"
            );
            assert_eq!(l.range_of([10, 0, 0, 1]), None);
            assert_eq!(l.candidate([10, 0, 0, 1], 0, 0), None);
        }
    }

    /// Different addresses should not all pile into one block — a hash that
    /// clustered would exhaust one block while the rest sat idle.
    #[test]
    fn addresses_spread_across_the_blocks() {
        let l = CgnatLayout::new(32768, 64);
        let mut seen: Vec<u16> = Vec::new();
        for host in 1..=200u8 {
            seen.push(l.block_of([10, 0, 0, host]));
        }
        seen.sort_unstable();
        seen.dedup();
        // 200 addresses over 511 blocks: collisions are expected, wholesale
        // clustering is not.
        assert!(seen.len() > 150, "only {} distinct blocks", seen.len());
    }
}
