//! Phase 2 — switching & routing.
//!
//! Where Phase 1 only ever answers *pass* or *drop*, Phase 2 lets Velstra
//! **forward** a packet out of a different interface: a software router/switch
//! in XDP. The forwarding *decision and arithmetic* live here as pure functions
//! ([`plan_forward`], [`csum_replace_u16`]) so the kernel and the test suite run
//! identical logic — exactly as with [`crate::decide`] in Phase 1. The eBPF
//! program is left to do only the unavoidable, untestable part: mutate the
//! packet bytes and issue the redirect.
//!
//! ## Route vs. switch
//!
//! A [`RouteEntry`] with [`RouteEntry::DECREMENT_TTL`] behaves like an L3
//! **router**: it decrements the IPv4 TTL (dropping the packet if it would hit
//! zero) and repairs the header checksum incrementally. Without the flag it is a
//! pure L2 **switch**: the frame is re-addressed and redirected unchanged.

/// A forwarding rule: where to send a packet whose destination matched, and how
/// to rewrite its L2 header on the way out.
///
/// Stored as the value of the `ROUTES` LPM trie (keyed on destination prefix).
/// `#[repr(C)]` with explicit tail padding keeps the 20-byte layout identical
/// and fully-initialised on both sides of the map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    /// Interface index to redirect the packet out of.
    pub out_ifindex: u32,
    /// New source MAC (usually the egress interface's own MAC).
    pub src_mac: [u8; 6],
    /// New destination MAC (the next hop's MAC).
    pub dst_mac: [u8; 6],
    /// Bitmask of behaviour flags; see [`RouteEntry::DECREMENT_TTL`].
    pub flags: u16,
    /// Explicit padding, always zero, so the value has no uninitialised bytes.
    pub _pad: u16,
}

impl RouteEntry {
    /// Act as an L3 router: decrement the IPv4 TTL and fix up the checksum.
    /// When unset, the entry is a pure L2 switch (no TTL/checksum change).
    pub const DECREMENT_TTL: u16 = 1 << 0;

    /// Construct a route entry.
    #[inline]
    pub const fn new(out_ifindex: u32, src_mac: [u8; 6], dst_mac: [u8; 6], flags: u16) -> Self {
        Self {
            out_ifindex,
            src_mac,
            dst_mac,
            flags,
            _pad: 0,
        }
    }

    /// Whether this entry decrements the TTL (router) or not (switch).
    #[inline]
    pub const fn decrements_ttl(&self) -> bool {
        self.flags & Self::DECREMENT_TTL != 0
    }
}

// SAFETY: `#[repr(C)]`, integer/byte-array fields only, padding explicitly
// zeroed — plain old data, safe to copy to/from a BPF map.
#[cfg(feature = "user")]
unsafe impl aya::Pod for RouteEntry {}

/// The concrete packet edits to apply before redirecting, produced by
/// [`plan_forward`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rewrite {
    /// Interface index to redirect out of.
    pub out_ifindex: u32,
    /// New Ethernet source MAC.
    pub src_mac: [u8; 6],
    /// New Ethernet destination MAC.
    pub dst_mac: [u8; 6],
    /// New IPv4 TTL to write, or `None` to leave TTL/checksum untouched
    /// (L2 switch mode).
    pub new_ttl: Option<u8>,
    /// New IPv4 header checksum (only meaningful when `new_ttl` is `Some`).
    pub new_checksum: u16,
}

/// What the data plane should do with a packet that passed the firewall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// No route matched — hand the packet to the kernel stack (`XDP_PASS`).
    Pass,
    /// A routed packet's TTL would reach zero — drop it (`XDP_DROP`). A full
    /// router would also emit an ICMP "time exceeded"; Velstra just drops.
    TtlExceeded,
    /// Rewrite the packet per [`Rewrite`] and redirect it (`XDP_REDIRECT`).
    Redirect(Rewrite),
}

/// Decide how to forward an IPv4 packet, given its TTL/checksum/protocol and the
/// matching [`RouteEntry`] (if any).
///
/// Pure and side-effect free: the caller performs the `ROUTES` lookup and the
/// packet mutation. This is the routing counterpart to [`crate::decide`].
///
/// ```
/// use velstra_common::{plan_forward, ForwardOutcome, RouteEntry};
///
/// let mac_a = [0x02, 0, 0, 0, 0, 0x01];
/// let mac_b = [0x02, 0, 0, 0, 0, 0x02];
/// let route = RouteEntry::new(7, mac_a, mac_b, RouteEntry::DECREMENT_TTL);
///
/// // No route -> pass to the kernel.
/// assert_eq!(plan_forward(64, 0, 6, None), ForwardOutcome::Pass);
///
/// // Routed packet: TTL is decremented and the checksum repaired.
/// match plan_forward(64, 0xb861, 6, Some(route)) {
///     ForwardOutcome::Redirect(rw) => {
///         assert_eq!(rw.out_ifindex, 7);
///         assert_eq!(rw.new_ttl, Some(63));
///     }
///     other => panic!("expected redirect, got {other:?}"),
/// }
///
/// // A packet about to expire is dropped, not forwarded.
/// assert_eq!(plan_forward(1, 0, 6, Some(route)), ForwardOutcome::TtlExceeded);
/// ```
#[inline]
pub fn plan_forward(
    ttl: u8,
    checksum: u16,
    proto: u8,
    route: Option<RouteEntry>,
) -> ForwardOutcome {
    let Some(route) = route else {
        return ForwardOutcome::Pass;
    };

    if !route.decrements_ttl() {
        // L2 switch: re-address and redirect, no L3 edits.
        return ForwardOutcome::Redirect(Rewrite {
            out_ifindex: route.out_ifindex,
            src_mac: route.src_mac,
            dst_mac: route.dst_mac,
            new_ttl: None,
            new_checksum: checksum,
        });
    }

    // L3 router: a packet that cannot survive another hop is dropped.
    if ttl <= 1 {
        return ForwardOutcome::TtlExceeded;
    }
    let new_ttl = ttl - 1;

    // The TTL is the high byte of the 16-bit word {ttl, proto} at IPv4 offset 8.
    let old_word = ((ttl as u16) << 8) | proto as u16;
    let new_word = ((new_ttl as u16) << 8) | proto as u16;
    let new_checksum = csum_replace_u16(checksum, old_word, new_word);

    ForwardOutcome::Redirect(Rewrite {
        out_ifindex: route.out_ifindex,
        src_mac: route.src_mac,
        dst_mac: route.dst_mac,
        new_ttl: Some(new_ttl),
        new_checksum,
    })
}

/// Incrementally update a 16-bit one's-complement (IP/TCP/UDP) checksum when a
/// single 16-bit word of the data changes from `old` to `new`.
///
/// Implements RFC 1624's `HC' = ~(C + ~m + m')`. Far cheaper than recomputing
/// the whole header, and the only correct way to touch a checksum in the XDP
/// hot path.
#[inline]
pub const fn csum_replace_u16(check: u16, old: u16, new: u16) -> u16 {
    // C = ~HC, then add ~old and new, folding the carries.
    let mut sum = (!check) as u32 + (!old) as u32 + new as u32;
    // At most two folds are needed for three 16-bit addends.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Compute a full IPv4 header checksum over `header` (the checksum field at
/// offset 10..12 is treated as zero). Used to validate [`csum_replace_u16`] and
/// available to callers that want to recompute from scratch.
///
/// Returns `0` for a header shorter than the minimum 20 bytes.
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    if header.len() < 20 {
        return 0;
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = if i == 10 {
            0 // skip the checksum field itself
        } else {
            u16::from_be_bytes([header[i], header[i + 1]]) as u32
        };
        sum += word;
        i += 2;
    }
    if i < header.len() {
        // Odd trailing byte (does not occur for 20/24-byte headers).
        sum += (header[i] as u32) << 8;
    }
    // Fold the carries with a *fixed* number of passes rather than a
    // data-dependent `while sum >> 16 != 0` loop: the eBPF verifier rejects the
    // latter as a potential infinite loop (it cannot bound the iteration count).
    // Two passes provably reduce any `u32` to 16 bits: the first yields at most
    // `0xffff + 0xffff = 0x1fffe`, the second `0xfffe + 1 = 0xffff`.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    /// A 20-byte IPv4 header with a valid checksum already filled in.
    fn ipv4_header(ttl: u8, proto: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45; // version 4, IHL 5
        h[2..4].copy_from_slice(&40u16.to_be_bytes()); // total length
        h[8] = ttl;
        h[9] = proto;
        h[12..16].copy_from_slice(&[192, 0, 2, 1]); // src
        h[16..20].copy_from_slice(&[198, 51, 100, 9]); // dst
        let check = ipv4_checksum(&h);
        h[10..12].copy_from_slice(&check.to_be_bytes());
        h
    }

    #[test]
    fn no_route_passes() {
        assert_eq!(plan_forward(64, 0x1234, 6, None), ForwardOutcome::Pass);
    }

    #[test]
    fn switch_mode_leaves_l3_untouched() {
        let route = RouteEntry::new(3, MAC_A, MAC_B, 0); // no DECREMENT_TTL
        match plan_forward(64, 0xabcd, 6, Some(route)) {
            ForwardOutcome::Redirect(rw) => {
                assert_eq!(rw.out_ifindex, 3);
                assert_eq!(rw.src_mac, MAC_A);
                assert_eq!(rw.dst_mac, MAC_B);
                assert_eq!(rw.new_ttl, None);
                assert_eq!(rw.new_checksum, 0xabcd);
            }
            other => panic!("expected redirect, got {other:?}"),
        }
    }

    #[test]
    fn router_drops_when_ttl_would_expire() {
        let route = RouteEntry::new(3, MAC_A, MAC_B, RouteEntry::DECREMENT_TTL);
        assert_eq!(
            plan_forward(1, 0, 6, Some(route)),
            ForwardOutcome::TtlExceeded
        );
        assert_eq!(
            plan_forward(0, 0, 6, Some(route)),
            ForwardOutcome::TtlExceeded
        );
    }

    #[test]
    fn router_decrements_ttl_and_keeps_checksum_valid() {
        // For several TTLs and protocols, the incremental checksum update must
        // match a full recomputation of the post-decrement header.
        for proto in [1u8, 6, 17] {
            for ttl in [2u8, 33, 64, 128, 255] {
                let before = ipv4_header(ttl, proto);
                let old_check = u16::from_be_bytes([before[10], before[11]]);

                // A correct original header has a checksum that validates to 0.
                assert_eq!(ipv4_checksum_full(&before), 0, "test header must be valid");

                let route = RouteEntry::new(9, MAC_A, MAC_B, RouteEntry::DECREMENT_TTL);
                let ForwardOutcome::Redirect(rw) = plan_forward(ttl, old_check, proto, Some(route))
                else {
                    panic!("expected redirect");
                };
                assert_eq!(rw.new_ttl, Some(ttl - 1));

                // Apply the rewrite and confirm the header re-validates.
                let mut after = before;
                after[8] = rw.new_ttl.unwrap();
                after[10..12].copy_from_slice(&rw.new_checksum.to_be_bytes());
                assert_eq!(
                    ipv4_checksum_full(&after),
                    0,
                    "checksum invalid after ttl {ttl} proto {proto}"
                );

                // And it equals a from-scratch recomputation.
                let mut scratch = after;
                scratch[10..12].copy_from_slice(&[0, 0]);
                assert_eq!(rw.new_checksum, ipv4_checksum(&scratch));
            }
        }
    }

    /// Sum a header *including* its checksum field; a valid header folds to 0.
    fn ipv4_checksum_full(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < header.len() {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
            i += 2;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn route_entry_layout_is_pod() {
        // 4 + 6 + 6 + 2 + 2 = 20, no implicit padding.
        assert_eq!(core::mem::size_of::<RouteEntry>(), 20);
        assert_eq!(core::mem::align_of::<RouteEntry>(), 4);
        let r = RouteEntry::new(1, MAC_A, MAC_B, RouteEntry::DECREMENT_TTL);
        assert!(r.decrements_ttl());
        assert!(!RouteEntry::new(1, MAC_A, MAC_B, 0).decrements_ttl());
    }
}
