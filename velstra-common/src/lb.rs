//! Phase 3 — L4 load balancing & NAT.
//!
//! A packet addressed to a **virtual IP** (`VIP:port`) is steered to one of
//! several real **backends** and NAT-rewritten so the kernel then delivers it
//! there. As with Phases 1 and 2, all the decision logic and — crucially — the
//! **checksum arithmetic** lives here as pure, unit-tested functions; the eBPF
//! program only mutates bytes.
//!
//! ## Backend selection
//!
//! New flows pick a backend by hashing the *source* identity ([`session_hash`]),
//! so absent any state every packet of a flow would still pick the same backend.
//!
//! ## Connection tracking (stateful NAT)
//!
//! The data plane records each new flow in a `CONNTRACK` map with two entries: a
//! **forward** entry (client→VIP ⇒ DNAT to the chosen backend, [`FlowState`])
//! and a **reverse** entry (backend→client ⇒ SNAT the source back to the VIP).
//! This keeps a flow pinned to its backend even if the pool changes, and lets
//! replies be un-NAT-ed so a real client connection completes end-to-end. The
//! rewrite itself is [`plan_nat`], used for both directions.
//!
//! ## Checksums
//!
//! Rewriting the destination IP changes both the IPv4 header checksum and the
//! L4 (TCP/UDP) checksum (the latter covers the IP pseudo-header); rewriting the
//! port changes only the L4 checksum. All three updates are done incrementally
//! per RFC 1624 via [`crate::csum_replace_u16`]. A UDP datagram with a zero
//! checksum (checksum disabled) is left untouched.

use crate::{forward::csum_replace_u16, packet::ip_proto};

/// Exact-match key for the `SERVICES` hash map: a virtual service endpoint.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ServiceKey {
    /// Virtual IP, network-order octets.
    pub vip: [u8; 4],
    /// Service port, host byte order.
    pub port: u16,
    /// IP protocol (TCP/UDP).
    pub proto: u8,
    /// Explicit padding, always zero.
    pub _pad: u8,
}

impl ServiceKey {
    /// Build a service key.
    #[inline]
    pub const fn new(vip: [u8; 4], port: u16, proto: u8) -> Self {
        Self {
            vip,
            port,
            proto,
            _pad: 0,
        }
    }
}

/// Value for `SERVICES`: a contiguous window `[start, start+count)` into the
/// flat `BACKENDS` array.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ServiceValue {
    /// Index of the first backend in the `BACKENDS` array.
    pub backend_start: u32,
    /// Number of backends in this service's pool.
    pub backend_count: u32,
}

impl ServiceValue {
    /// Build a service value.
    #[inline]
    pub const fn new(backend_start: u32, backend_count: u32) -> Self {
        Self {
            backend_start,
            backend_count,
        }
    }
}

/// One real server in the `BACKENDS` array.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Backend {
    /// Backend IP, network-order octets.
    pub ip: [u8; 4],
    /// Backend port (host order), or `0` to keep the packet's original port.
    pub port: u16,
    /// Explicit padding, always zero.
    pub _pad: u16,
}

impl Backend {
    /// Build a backend. `port == 0` means "leave the destination port as-is"
    /// (IP-only DNAT).
    #[inline]
    pub const fn new(ip: [u8; 4], port: u16) -> Self {
        Self { ip, port, _pad: 0 }
    }
}

// SAFETY: all three are `#[repr(C)]` POD with explicit padding — safe to copy
// to/from BPF maps.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ServiceValue {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Backend {}

/// Hash a flow's *source* identity to a 32-bit value (FNV-1a). Deterministic, so
/// every packet of a flow selects the same backend.
#[inline]
pub const fn session_hash(src_ip: [u8; 4], src_port: u16, proto: u8) -> u32 {
    let bytes = [
        src_ip[0],
        src_ip[1],
        src_ip[2],
        src_ip[3],
        (src_port >> 8) as u8,
        src_port as u8,
        proto,
    ];
    let mut hash: u32 = 0x811c_9dc5; // FNV offset basis
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193); // FNV prime
        i += 1;
    }
    hash
}

/// Map a [`session_hash`] onto a backend index in `0..count`. Returns `0` for an
/// empty pool (the caller must check `count` first).
#[inline]
pub const fn select_backend(hash: u32, count: u32) -> u32 {
    if count == 0 { 0 } else { hash % count }
}

/// The packet edits a NAT rewrite requires, produced by [`plan_nat`].
///
/// The same shape describes a destination rewrite (DNAT, on the way to a
/// backend) and a source rewrite (SNAT, un-NAT-ing a reply): only *which*
/// address/port offset the data plane writes to differs. The checksum maths is
/// identical either way, since both the source and destination addresses live
/// in the IPv4 header and the L4 pseudo-header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Nat {
    /// New IP address to write (destination for DNAT, source for SNAT).
    pub new_ip: [u8; 4],
    /// New port to write.
    pub new_port: u16,
    /// Repaired IPv4 header checksum.
    pub new_ip_checksum: u16,
    /// Repaired L4 checksum (meaningful only if `rewrite_l4_checksum`).
    pub new_l4_checksum: u16,
    /// Whether the port actually changed (and must be written).
    pub rewrite_port: bool,
    /// Whether the L4 checksum must be written. `false` for a UDP datagram whose
    /// checksum was already disabled (zero).
    pub rewrite_l4_checksum: bool,
}

/// Plan a NAT rewrite that changes one address/port pair from `(old_ip,
/// old_port)` to `(new_ip, new_port)` and repairs the checksums incrementally.
///
/// `new_port == 0` means "leave the port unchanged" (IP-only NAT). Works for
/// either direction — the caller decides whether to write the result to the
/// source or destination fields.
///
/// ```
/// use velstra_common::{plan_nat, ip_proto};
///
/// // SNAT a reply's source 10.0.0.7:8080 back to the VIP 10.0.0.100:80.
/// let nat = plan_nat([10, 0, 0, 7], 8080, [10, 0, 0, 100], 80, 0, 0, ip_proto::TCP);
/// assert_eq!(nat.new_ip, [10, 0, 0, 100]);
/// assert_eq!(nat.new_port, 80);
/// assert!(nat.rewrite_port);
/// ```
#[inline]
pub fn plan_nat(
    old_ip: [u8; 4],
    old_port: u16,
    new_ip: [u8; 4],
    new_port: u16,
    ip_checksum: u16,
    l4_checksum: u16,
    proto: u8,
) -> Nat {
    let (new_port, rewrite_port) = if new_port == 0 || new_port == old_port {
        (old_port, false)
    } else {
        (new_port, true)
    };

    // IPv4 header checksum: only the one address changed.
    let new_ip_checksum = replace_addr(ip_checksum, old_ip, new_ip);

    // L4 checksum covers the IP pseudo-header (the address) and the port. A UDP
    // datagram with a zero checksum has checksums disabled — leave it.
    let rewrite_l4_checksum = !(proto == ip_proto::UDP && l4_checksum == 0);
    let new_l4_checksum = if rewrite_l4_checksum {
        let mut c = replace_addr(l4_checksum, old_ip, new_ip);
        if rewrite_port {
            c = csum_replace_u16(c, old_port, new_port);
        }
        c
    } else {
        l4_checksum
    };

    Nat {
        new_ip,
        new_port,
        new_ip_checksum,
        new_l4_checksum,
        rewrite_port,
        rewrite_l4_checksum,
    }
}

/// Convenience wrapper over [`plan_nat`] for the DNAT-to-backend case.
#[inline]
pub fn plan_dnat(
    dst_ip: [u8; 4],
    dst_port: u16,
    backend: Backend,
    ip_checksum: u16,
    l4_checksum: u16,
    proto: u8,
) -> Nat {
    plan_nat(
        dst_ip,
        dst_port,
        backend.ip,
        backend.port,
        ip_checksum,
        l4_checksum,
        proto,
    )
}

/// Lookup key for the `CONNTRACK` LRU map: a flow's 5-tuple. Addresses are
/// network-order octets, ports host order.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct FlowKey {
    /// Source address.
    pub src_ip: [u8; 4],
    /// Destination address.
    pub dst_ip: [u8; 4],
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol.
    pub proto: u8,
    /// Explicit padding, always zero.
    pub _pad: [u8; 3],
}

impl FlowKey {
    /// Build a flow key.
    #[inline]
    pub const fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        proto: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            proto,
            _pad: [0; 3],
        }
    }
}

/// Value for `CONNTRACK`: where to NAT a tracked flow, and in which direction.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FlowState {
    /// NAT target IP (the backend for a forward flow, the VIP for a reply).
    pub nat_ip: [u8; 4],
    /// NAT target port (`0` keeps the packet's port).
    pub nat_port: u16,
    /// Bit flags; see [`FlowState::REVERSE`].
    pub flags: u16,
}

impl FlowState {
    /// This entry rewrites the packet's **source** (SNAT a reply) rather than
    /// its destination (DNAT a request).
    pub const REVERSE: u16 = 1 << 0;

    /// A forward (DNAT) entry: rewrite the destination to `nat_ip:nat_port`.
    #[inline]
    pub const fn forward(nat_ip: [u8; 4], nat_port: u16) -> Self {
        Self {
            nat_ip,
            nat_port,
            flags: 0,
        }
    }

    /// A reverse (SNAT) entry: rewrite the source to `nat_ip:nat_port`.
    #[inline]
    pub const fn reverse(nat_ip: [u8; 4], nat_port: u16) -> Self {
        Self {
            nat_ip,
            nat_port,
            flags: Self::REVERSE,
        }
    }

    /// Whether this entry rewrites the source (SNAT) instead of the destination.
    #[inline]
    pub const fn is_reverse(&self) -> bool {
        self.flags & Self::REVERSE != 0
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowState {}

/// Apply a checksum update for a changed 4-byte IPv4 address (two 16-bit words).
#[inline]
const fn replace_addr(check: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let c = csum_replace_u16(
        check,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new[0], new[1]]),
    );
    csum_replace_u16(
        c,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new[2], new[3]]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forward::ipv4_checksum;

    #[test]
    fn session_hash_is_deterministic_and_varied() {
        let a = session_hash([10, 0, 0, 5], 12345, ip_proto::TCP);
        assert_eq!(a, session_hash([10, 0, 0, 5], 12345, ip_proto::TCP));
        assert_ne!(a, session_hash([10, 0, 0, 6], 12345, ip_proto::TCP));
        assert_ne!(a, session_hash([10, 0, 0, 5], 12346, ip_proto::TCP));
        assert_ne!(a, session_hash([10, 0, 0, 5], 12345, ip_proto::UDP));
    }

    #[test]
    fn select_backend_stays_in_range_and_spreads() {
        let count = 4;
        let mut seen = [false; 4];
        for src in 0u8..40 {
            let h = session_hash([10, 0, 0, src], 1000, ip_proto::TCP);
            let idx = select_backend(h, count);
            assert!(idx < count);
            seen[idx as usize] = true;
        }
        // With 40 distinct sources over 4 backends, every backend should be hit.
        assert!(seen.iter().all(|&s| s), "uneven spread: {seen:?}");
        assert_eq!(select_backend(123, 0), 0); // empty pool is safe
    }

    /// Full L4 checksum over the IP pseudo-header + segment (checksum field
    /// already zeroed in `segment`).
    fn l4_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], proto: u8, segment: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for w in [
            u16::from_be_bytes([src_ip[0], src_ip[1]]),
            u16::from_be_bytes([src_ip[2], src_ip[3]]),
            u16::from_be_bytes([dst_ip[0], dst_ip[1]]),
            u16::from_be_bytes([dst_ip[2], dst_ip[3]]),
            proto as u16,
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
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A 20-byte IPv4 header with `dst`, valid checksum filled in.
    fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&40u16.to_be_bytes());
        h[8] = 64;
        h[9] = proto;
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        let c = ipv4_checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h
    }

    /// A 20-byte TCP header (no options) with src/dst port and a payload.
    fn tcp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut seg = vec![0u8; 20 + payload.len()];
        seg[0..2].copy_from_slice(&src_port.to_be_bytes());
        seg[2..4].copy_from_slice(&dst_port.to_be_bytes());
        seg[12] = 5 << 4; // data offset = 5 words
        seg[20..].copy_from_slice(payload);
        seg // checksum field (16..18) stays zero for computation
    }

    #[test]
    fn dnat_repairs_ip_and_tcp_checksums() {
        let src_ip = [10, 0, 0, 5];
        let vip = [10, 0, 0, 100];
        let backend_ip = [192, 168, 7, 9];
        let (src_port, vip_port, backend_port) = (40000u16, 80u16, 8080u16);

        // Build a valid TCP/IP packet addressed to the VIP.
        let ip = ipv4_header(src_ip, vip, ip_proto::TCP);
        let ip_check = u16::from_be_bytes([ip[10], ip[11]]);
        let mut seg = tcp_segment(src_port, vip_port, b"velstra!");
        let l4_check = l4_checksum(src_ip, vip, ip_proto::TCP, &seg);
        seg[16..18].copy_from_slice(&l4_check.to_be_bytes());

        // DNAT to the backend.
        let dnat = plan_dnat(
            vip,
            vip_port,
            Backend::new(backend_ip, backend_port),
            ip_check,
            l4_check,
            ip_proto::TCP,
        );
        assert_eq!(dnat.new_ip, backend_ip);
        assert_eq!(dnat.new_port, backend_port);
        assert!(dnat.rewrite_port && dnat.rewrite_l4_checksum);

        // Verify the IPv4 checksum matches a from-scratch recompute.
        let new_ip = ipv4_header(src_ip, backend_ip, ip_proto::TCP);
        assert_eq!(
            dnat.new_ip_checksum,
            u16::from_be_bytes([new_ip[10], new_ip[11]])
        );

        // Verify the TCP checksum matches a from-scratch recompute.
        let mut new_seg = seg.clone();
        new_seg[2..4].copy_from_slice(&backend_port.to_be_bytes());
        new_seg[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(
            dnat.new_l4_checksum,
            l4_checksum(src_ip, backend_ip, ip_proto::TCP, &new_seg)
        );
    }

    #[test]
    fn snat_reverses_a_dnat_exactly() {
        // A reply from the backend, SNAT'd back to the VIP, must reconstruct the
        // original checksums — i.e. SNAT is the exact inverse of the DNAT.
        let client = [203, 0, 113, 9];
        let vip = [10, 0, 0, 100];
        let backend = [192, 168, 7, 9];
        let (client_port, vip_port, backend_port) = (50000u16, 443u16, 9090u16);

        // Original reply: backend -> client.
        let ip = ipv4_header(backend, client, ip_proto::TCP);
        let ip_check = u16::from_be_bytes([ip[10], ip[11]]);
        let mut seg = tcp_segment(backend_port, client_port, b"reply-data");
        let l4_check = l4_checksum(backend, client, ip_proto::TCP, &seg);
        seg[16..18].copy_from_slice(&l4_check.to_be_bytes());

        // SNAT the source backend:backend_port -> vip:vip_port.
        let nat = plan_nat(
            backend,
            backend_port,
            vip,
            vip_port,
            ip_check,
            l4_check,
            ip_proto::TCP,
        );
        assert_eq!(nat.new_ip, vip);
        assert_eq!(nat.new_port, vip_port);

        // The rewritten reply (vip -> client) must re-validate from scratch.
        let new_ip = ipv4_header(vip, client, ip_proto::TCP);
        assert_eq!(
            nat.new_ip_checksum,
            u16::from_be_bytes([new_ip[10], new_ip[11]])
        );
        let mut new_seg = seg.clone();
        new_seg[0..2].copy_from_slice(&vip_port.to_be_bytes()); // source port
        new_seg[16..18].copy_from_slice(&[0, 0]);
        assert_eq!(
            nat.new_l4_checksum,
            l4_checksum(vip, client, ip_proto::TCP, &new_seg)
        );
    }

    #[test]
    fn nat_keeps_port_when_target_port_zero_or_equal() {
        let nat = plan_nat(
            [10, 0, 0, 1],
            443,
            [10, 0, 0, 7],
            0,
            0x1234,
            0x5678,
            ip_proto::TCP,
        );
        assert_eq!(nat.new_port, 443);
        assert!(!nat.rewrite_port);
        // Same port in and out is also a no-op rewrite.
        let same = plan_nat(
            [10, 0, 0, 1],
            80,
            [10, 0, 0, 7],
            80,
            0x1234,
            0x5678,
            ip_proto::TCP,
        );
        assert!(!same.rewrite_port);
    }

    #[test]
    fn nat_leaves_disabled_udp_checksum() {
        let nat = plan_nat(
            [10, 0, 0, 100],
            53,
            [10, 0, 0, 7],
            5353,
            0x1234,
            0, // UDP checksum disabled
            ip_proto::UDP,
        );
        assert!(!nat.rewrite_l4_checksum);
        assert_eq!(nat.new_l4_checksum, 0);
    }

    #[test]
    fn flow_state_direction() {
        let f = FlowState::forward([10, 0, 0, 7], 8080);
        assert!(!f.is_reverse());
        let r = FlowState::reverse([10, 0, 0, 100], 80);
        assert!(r.is_reverse());
    }

    #[test]
    fn map_types_are_pod_sized() {
        assert_eq!(core::mem::size_of::<ServiceKey>(), 8);
        assert_eq!(core::mem::size_of::<ServiceValue>(), 8);
        assert_eq!(core::mem::size_of::<Backend>(), 8);
        assert_eq!(core::mem::size_of::<FlowKey>(), 16);
        assert_eq!(core::mem::size_of::<FlowState>(), 8);
    }
}
