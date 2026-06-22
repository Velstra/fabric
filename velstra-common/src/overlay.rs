//! Phase 4 — the VXLAN/Geneve overlay (multi-host tenants).
//!
//! Phases 1–3 act on packets that stay on one host. Phase 4 lets a tenant span
//! **many** hosts: a VM on host A and a VM on host B share one virtual L2
//! segment even though the physical *underlay* between A and B only carries
//! routed IP. Velstra does this the standard way — by **encapsulating** the
//! tenant's Ethernet frame inside a UDP/VXLAN (or UDP/Geneve) tunnel between the
//! two hosts' tunnel endpoints (VTEPs).
//!
//! This is the open-source Andromeda model: a central controller knows the whole
//! topology and **pushes**, to each host, just the tunnel endpoints that host
//! needs (the [`TunnelEndpoint`] entries of `OVERLAY_FDB`). No message queue, no
//! flooding — the dataplane already holds the answer when the first packet
//! arrives.
//!
//! ## What lives here vs. in the kernel
//!
//! As everywhere in Velstra, all the *arithmetic* is a pure, unit-tested
//! function: [`build_encap`] constructs the entire 50-byte outer header stack
//! (outer Ethernet + IPv4 + UDP + VXLAN/Geneve), including the outer IPv4
//! checksum and an entropy-bearing UDP source port for underlay ECMP. The eBPF
//! program does only the one thing it alone can: grow the packet
//! (`bpf_xdp_adjust_head`) and copy these bytes in. Decap is even simpler — the
//! VNI sits at the *same* offset for both encapsulations ([`decode_vni`]), so the
//! kernel just validates the UDP port, reads the VNI and shrinks the packet.
//!
//! ## VNI vs. policy
//!
//! A tenant's 24-bit VXLAN Network Identifier (its virtual *network*) is kept
//! **separate** from its firewall `policy_id` (its *ruleset* / security group):
//! many ports can share one policy on different VNIs, or one VNI can host ports
//! with different policies. The control plane maps each port to both (`IFACE_VNI`
//! and `IFACE_POLICY`); for convenience the VNI defaults to the policy id when a
//! deployment wants the simple one-number-per-tenant case.

use crate::{forward::ipv4_checksum, packet::ETHERTYPE_IPV4};

/// IANA-assigned UDP destination port for VXLAN (RFC 7348).
pub const VXLAN_PORT: u16 = 4789;
/// IANA-assigned UDP destination port for Geneve (RFC 8926).
pub const GENEVE_PORT: u16 = 6081;

/// Geneve "protocol type" for an inner Ethernet frame: Trans-Ether-Bridging.
const GENEVE_PROTO_ETHERNET: u16 = 0x6558;
/// VXLAN flags byte with the "VNI present" (I) bit set.
const VXLAN_FLAGS_VNI: u8 = 0x08;

/// Bytes prepended to a frame on encap: outer Ethernet (14) + outer IPv4 (20) +
/// UDP (8) + VXLAN/Geneve shim (8). Identical for both encapsulations, which is
/// why a single `bpf_xdp_adjust_head(-OVERLAY_OUTER_LEN)` serves both.
pub const OVERLAY_OUTER_LEN: usize = 14 + 20 + 8 + 8;

/// Byte offset of the 8-byte VXLAN/Geneve shim within the outer header stack.
const SHIM_OFFSET: usize = 14 + 20 + 8;

/// Which encapsulation a [`OverlayConfig`] uses. The wire formats differ only in
/// the 8-byte shim; the outer Ethernet/IPv4/UDP stack is identical.
pub mod encap_kind {
    /// VXLAN (RFC 7348): flags + 24-bit VNI.
    pub const VXLAN: u8 = 0;
    /// Geneve (RFC 8926) with no options: a base header + 24-bit VNI.
    pub const GENEVE: u8 = 1;
}

/// Per-host overlay configuration: this host's tunnel endpoint identity. Exactly
/// one entry (index `0`) of the `OVERLAY_CONFIG` array map.
///
/// `#[repr(C)]`, field order chosen so the 16-byte layout has no implicit
/// padding (largest alignment is the `u16` port).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OverlayConfig {
    /// This host's VTEP underlay IPv4 address (outer source IP), network order.
    pub local_vtep_ip: [u8; 4],
    /// This host's underlay MAC (outer source MAC).
    pub local_mac: [u8; 6],
    /// UDP destination port for the tunnel (host byte order): 4789 or 6081.
    pub udp_port: u16,
    /// Underlay path MTU in bytes (the largest outer IP packet that fits). An
    /// inner frame whose encapsulation would exceed this is dropped rather than
    /// silently black-holed by the underlay. Typically 1500 (so the inner frame
    /// must be ≤ `mtu - 36`).
    pub underlay_mtu: u16,
    /// Encapsulation ([`encap_kind`]).
    pub encap: u8,
    /// `1` when the overlay is active; `0` disables encap/decap entirely.
    pub enabled: u8,
}

impl OverlayConfig {
    /// A disabled config — no encap, no decap. The default when no `[overlay]`
    /// section is present.
    pub const DISABLED: Self = Self {
        local_vtep_ip: [0; 4],
        local_mac: [0; 6],
        udp_port: 0,
        underlay_mtu: 1500,
        encap: encap_kind::VXLAN,
        enabled: 0,
    };

    /// Build an enabled config.
    #[inline]
    pub const fn new(
        local_vtep_ip: [u8; 4],
        local_mac: [u8; 6],
        udp_port: u16,
        encap: u8,
        underlay_mtu: u16,
    ) -> Self {
        Self {
            local_vtep_ip,
            local_mac,
            udp_port,
            underlay_mtu,
            encap,
            enabled: 1,
        }
    }

    /// Whether the overlay is active.
    #[inline]
    pub const fn is_enabled(&self) -> bool {
        self.enabled != 0
    }

    /// The largest inner frame (in bytes) that still fits the underlay MTU once
    /// the outer headers are added. The outer IPv4 packet is `36 + inner_len`
    /// bytes (IPv4 20 + UDP 8 + shim 8), so the inner frame must be
    /// `≤ underlay_mtu - 36`. Returns `0` for absurdly small MTUs.
    #[inline]
    pub const fn max_inner_len(&self) -> u16 {
        let overhead = (OVERLAY_OUTER_LEN - 14) as u16; // outer IP+UDP+shim = 36
        self.underlay_mtu.saturating_sub(overhead)
    }
}

// SAFETY: `#[repr(C)]`, byte-array/integer fields, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for OverlayConfig {}

/// Key into the overlay forwarding database (`OVERLAY_FDB`), an **LPM trie**:
/// a tenant `vni` (matched exactly) followed by an inner-destination IPv4
/// **prefix**. Longest-prefix matching lets the controller push one entry for a
/// whole remote subnet (`10.1.0.0/16 → VTEP`) instead of one per `/32` host —
/// the difference between thousands and millions of entries at scale.
///
/// The trie walks the key bytes from the front: `vni` (offset 0) is consumed by
/// its 32 exact prefix bits, then the address prefix — mirroring [`ScopedAddr`].
/// `inner_dst` is in [`lpm_key_addr`] form so its in-memory bytes are
/// network-order.
///
/// [`ScopedAddr`]: crate::ScopedAddr
/// [`lpm_key_addr`]: crate::lpm_key_addr
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct TunnelKey {
    /// Tenant VXLAN Network Identifier, matched exactly (the first
    /// [`Self::VNI_BITS`] prefix bits).
    pub vni: u32,
    /// Inner destination IPv4 in [`lpm_key_addr`](crate::lpm_key_addr) form.
    pub inner_dst: u32,
}

impl TunnelKey {
    /// Prefix bits that cover the (exactly-matched) VNI.
    pub const VNI_BITS: u32 = 32;

    /// Build a key from a VNI and an `lpm_key_addr` inner destination.
    #[inline]
    pub const fn new(vni: u32, inner_dst: u32) -> Self {
        Self { vni, inner_dst }
    }

    /// The LPM prefix length to insert a `/cidr_bits` inner subnet for a VNI.
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::VNI_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for an exact (`/32`) inner-destination lookup.
    pub const FULL_PREFIX: u32 = Self::VNI_BITS + 32;
}

// SAFETY: `#[repr(C)]`, two `u32`s, no padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TunnelKey {}

/// The remote endpoint a [`TunnelKey`] resolves to: where on the underlay to
/// send the encapsulated frame, and how to address it at L2.
///
/// Field order keeps the 16-byte layout padding-free (the `u32` leads).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TunnelEndpoint {
    /// Underlay interface index to redirect the encapsulated packet out of.
    pub out_ifindex: u32,
    /// Remote VTEP underlay IPv4 (outer destination IP), network order.
    pub remote_vtep_ip: [u8; 4],
    /// Outer destination MAC: the next hop on the underlay toward the remote
    /// VTEP (the remote VTEP's MAC if on the same segment, else the gateway's).
    pub outer_dst_mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl TunnelEndpoint {
    /// Build an endpoint.
    #[inline]
    pub const fn new(out_ifindex: u32, remote_vtep_ip: [u8; 4], outer_dst_mac: [u8; 6]) -> Self {
        Self {
            out_ifindex,
            remote_vtep_ip,
            outer_dst_mac,
            _pad: [0; 2],
        }
    }
}

// SAFETY: `#[repr(C)]`, `u32` + byte arrays, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for TunnelEndpoint {}

/// Derive the outer UDP **source** port from a flow-entropy hash.
///
/// Per RFC 7348 the source port carries entropy so the underlay's ECMP/LAG
/// hashing spreads different inner flows across paths while keeping each flow on
/// one path. We map the hash into the IANA ephemeral range `49152..=65535`.
#[inline]
pub const fn overlay_src_port(entropy: u32) -> u16 {
    0xC000 | (entropy & 0x3FFF) as u16
}

/// The fully-built outer header stack and where to send it, produced by
/// [`build_encap`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Encap {
    /// The [`OVERLAY_OUTER_LEN`] bytes to prepend, ready to copy in after a
    /// `bpf_xdp_adjust_head(-OVERLAY_OUTER_LEN)`.
    pub headers: [u8; OVERLAY_OUTER_LEN],
    /// Underlay interface index to redirect the encapsulated frame out of.
    pub out_ifindex: u32,
}

/// Build the complete outer header stack to encapsulate an inner Ethernet frame.
///
/// Pure and allocation-free: the caller supplies the inner frame's current
/// length (the whole ingress L2 frame becomes the tunnel payload) and a 32-bit
/// `entropy` value hashed from the inner flow; this returns the bytes to prepend.
/// The outer IPv4 checksum is computed here; the outer UDP checksum is left `0`,
/// which RFC 7348/8926 explicitly permit for IPv4 tunnels.
///
/// ```
/// use velstra_common::{build_encap, decode_vni, OverlayConfig, TunnelEndpoint,
///     encap_kind, VXLAN_PORT, OVERLAY_OUTER_LEN};
///
/// let cfg = OverlayConfig::new([10, 0, 0, 1], [0x02, 0, 0, 0, 0, 0x01], VXLAN_PORT, encap_kind::VXLAN, 1500);
/// let ep = TunnelEndpoint::new(7, [10, 0, 0, 2], [0x02, 0, 0, 0, 0, 0x02]);
///
/// let e = build_encap(&cfg, &ep, 100, 1500, 0xABCD);
/// assert_eq!(e.out_ifindex, 7);
/// // The encapsulated VNI reads back from the shim, at the same offset Geneve uses.
/// let shim: [u8; 8] = e.headers[OVERLAY_OUTER_LEN - 8..].try_into().unwrap();
/// assert_eq!(decode_vni(shim), 100);
/// ```
#[inline]
pub fn build_encap(
    cfg: &OverlayConfig,
    ep: &TunnelEndpoint,
    vni: u32,
    inner_frame_len: u16,
    entropy: u32,
) -> Encap {
    let mut h = [0u8; OVERLAY_OUTER_LEN];

    // --- Outer Ethernet (0..14) ---------------------------------------------
    h[0..6].copy_from_slice(&ep.outer_dst_mac);
    h[6..12].copy_from_slice(&cfg.local_mac);
    h[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    // --- Outer IPv4 (14..34) ------------------------------------------------
    let udp_len = 8 + 8 + inner_frame_len; // UDP header + shim + inner frame
    let ip_total = 20 + udp_len;
    h[14] = 0x45; // version 4, IHL 5 (no options)
    h[15] = 0; // DSCP/ECN
    h[16..18].copy_from_slice(&ip_total.to_be_bytes());
    h[18..20].copy_from_slice(&0u16.to_be_bytes()); // identification
    h[20..22].copy_from_slice(&0x4000u16.to_be_bytes()); // flags: Don't Fragment
    h[22] = 64; // TTL
    h[23] = crate::ip_proto::UDP;
    // h[24..26] checksum: left zero, filled in below.
    h[26..30].copy_from_slice(&cfg.local_vtep_ip);
    h[30..34].copy_from_slice(&ep.remote_vtep_ip);
    let ip_csum = ipv4_checksum(&h[14..34]);
    h[24..26].copy_from_slice(&ip_csum.to_be_bytes());

    // --- Outer UDP (34..42) -------------------------------------------------
    h[34..36].copy_from_slice(&overlay_src_port(entropy).to_be_bytes());
    h[36..38].copy_from_slice(&cfg.udp_port.to_be_bytes());
    h[38..40].copy_from_slice(&udp_len.to_be_bytes());
    h[40..42].copy_from_slice(&0u16.to_be_bytes()); // checksum 0 (allowed on IPv4)

    // --- VXLAN / Geneve shim (42..50) ---------------------------------------
    // The 24-bit VNI sits at shim bytes 4..7 in *both* formats, so decap can read
    // it without knowing which was used.
    let vni_be = [(vni >> 16) as u8, (vni >> 8) as u8, vni as u8];
    if cfg.encap == encap_kind::GENEVE {
        h[SHIM_OFFSET] = 0; // version 0, options length 0
        h[SHIM_OFFSET + 1] = 0; // flags
        h[SHIM_OFFSET + 2..SHIM_OFFSET + 4].copy_from_slice(&GENEVE_PROTO_ETHERNET.to_be_bytes());
    } else {
        h[SHIM_OFFSET] = VXLAN_FLAGS_VNI;
        // bytes 1..4 reserved (zero)
    }
    h[SHIM_OFFSET + 4..SHIM_OFFSET + 7].copy_from_slice(&vni_be);
    // h[SHIM_OFFSET + 7] reserved (zero)

    Encap {
        headers: h,
        out_ifindex: ep.out_ifindex,
    }
}

/// Read the 24-bit VNI out of an 8-byte VXLAN or Geneve shim. The VNI occupies
/// bytes 4..7 in both formats.
#[inline]
pub const fn decode_vni(shim: [u8; 8]) -> u32 {
    ((shim[4] as u32) << 16) | ((shim[5] as u32) << 8) | (shim[6] as u32)
}

/// Whether an inbound UDP datagram is one of *our* tunnel packets: the overlay is
/// enabled and the (host-order) UDP destination port matches the configured one.
#[inline]
pub const fn is_overlay_dport(cfg: &OverlayConfig, udp_dst_port: u16) -> bool {
    cfg.is_enabled() && udp_dst_port == cfg.udp_port
}

// === ARP suppression =======================================================
//
// In an L2 overlay, a tenant VM ARPs for a peer that may live on another host.
// Flooding that broadcast to every VTEP (BUM replication) scales poorly, so —
// like Andromeda/OVN — Velstra answers ARP **locally**: the controller has
// already pushed every tenant address's MAC into `ARP_TABLE`, so the host
// synthesises the reply and never puts the broadcast on the wire.

/// EtherType for ARP, in host byte order (compare after `u16::from_be`).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// ARP opcode for a request.
pub const ARP_REQUEST: u16 = 1;
/// ARP opcode for a reply.
pub const ARP_REPLY: u16 = 2;

/// Key into `ARP_TABLE`: which tenant segment (`vni`) and which target IPv4 an
/// ARP request is asking about. Exact match — one entry per tenant address.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ArpKey {
    /// Tenant VNI the requesting port belongs to.
    pub vni: u32,
    /// Target IPv4 being resolved, network-order octets.
    pub ip: [u8; 4],
}

impl ArpKey {
    /// Build a key for `(vni, ip)`.
    #[inline]
    pub const fn new(vni: u32, ip: [u8; 4]) -> Self {
        Self { vni, ip }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` and a 4-byte array, no padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpKey {}

/// Value in `ARP_TABLE`: the MAC that answers for the keyed tenant address.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArpEntry {
    /// The hardware address to return in the synthesised ARP reply.
    pub mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl ArpEntry {
    /// Build an entry for `mac`.
    #[inline]
    pub const fn new(mac: [u8; 6]) -> Self {
        Self { mac, _pad: [0; 2] }
    }
}

// SAFETY: `#[repr(C)]`, a 6-byte array + explicit padding, no uninit bytes.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ArpEntry {}

/// The field values that turn an ARP **request** into the **reply** to send back
/// out the same interface (`XDP_TX`), produced by [`plan_arp_reply`]. Pure data;
/// the data plane writes these at constant offsets in place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArpReply {
    /// New Ethernet destination (the original requester).
    pub eth_dst: [u8; 6],
    /// New Ethernet source (the answered MAC).
    pub eth_src: [u8; 6],
    /// ARP sender hardware address (the answered MAC).
    pub sha: [u8; 6],
    /// ARP sender protocol address (the IP that was queried).
    pub spa: [u8; 4],
    /// ARP target hardware address (the original requester's MAC).
    pub tha: [u8; 6],
    /// ARP target protocol address (the original requester's IP).
    pub tpa: [u8; 4],
}

/// Build the [`ArpReply`] that answers an ARP request for `req_tpa` with
/// `answer_mac`. Pure and unit-testable; mirrors a standard ARP responder: the
/// requester becomes the target, the answered host becomes the sender.
///
/// ```
/// use velstra_common::{plan_arp_reply, ARP_REPLY};
/// let req_sha = [0x02, 0, 0, 0, 0, 0x0a];
/// let r = plan_arp_reply(req_sha, [10, 0, 0, 10], [10, 0, 0, 20], [0x02, 0, 0, 0, 0, 0x14]);
/// assert_eq!(r.eth_dst, req_sha);          // reply goes back to the requester
/// assert_eq!(r.sha, [0x02, 0, 0, 0, 0, 0x14]); // answered MAC
/// assert_eq!(r.spa, [10, 0, 0, 20]);       // the IP that was queried
/// assert_eq!(r.tpa, [10, 0, 0, 10]);       // the requester's IP
/// ```
#[inline]
pub const fn plan_arp_reply(
    req_sha: [u8; 6],
    req_spa: [u8; 4],
    req_tpa: [u8; 4],
    answer_mac: [u8; 6],
) -> ArpReply {
    ArpReply {
        eth_dst: req_sha,
        eth_src: answer_mac,
        sha: answer_mac,
        spa: req_tpa,
        tha: req_sha,
        tpa: req_spa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_proto;

    const LOCAL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const NEXTHOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    /// Re-sum a header *including* its checksum field; a valid one folds to 0.
    fn ipv4_validate(header: &[u8]) -> u16 {
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
    fn pod_layouts_have_no_padding() {
        assert_eq!(core::mem::size_of::<OverlayConfig>(), 16);
        assert_eq!(core::mem::size_of::<TunnelKey>(), 8);
        assert_eq!(core::mem::size_of::<TunnelEndpoint>(), 16);
        assert_eq!(OVERLAY_OUTER_LEN, 50);
    }

    #[test]
    fn tunnel_key_lpm_prefixes() {
        // A /16 inner subnet in a VNI matches 32 (vni) + 16 (addr) = 48 bits.
        assert_eq!(TunnelKey::prefix_len(16), 48);
        assert_eq!(TunnelKey::FULL_PREFIX, 64);
    }

    #[test]
    fn max_inner_len_reserves_outer_overhead() {
        let cfg = OverlayConfig::new(
            [10, 0, 0, 1],
            LOCAL_MAC,
            VXLAN_PORT,
            encap_kind::VXLAN,
            1500,
        );
        // 1500 underlay - 36 (outer IP+UDP+shim) = 1464 max inner frame.
        assert_eq!(cfg.max_inner_len(), 1464);
        // Jumbo underlay.
        let jumbo = OverlayConfig::new(
            [10, 0, 0, 1],
            LOCAL_MAC,
            VXLAN_PORT,
            encap_kind::VXLAN,
            9000,
        );
        assert_eq!(jumbo.max_inner_len(), 8964);
        // Absurdly small MTU saturates to 0 rather than underflowing.
        let tiny = OverlayConfig::new([10, 0, 0, 1], LOCAL_MAC, VXLAN_PORT, encap_kind::VXLAN, 20);
        assert_eq!(tiny.max_inner_len(), 0);
    }

    #[test]
    fn arp_layouts_and_reply_fields() {
        assert_eq!(core::mem::size_of::<ArpKey>(), 8);
        assert_eq!(core::mem::size_of::<ArpEntry>(), 8);
        let req_sha = [0x02, 0, 0, 0, 0, 0x0a];
        let answer = [0x02, 0, 0, 0, 0, 0x14];
        let r = plan_arp_reply(req_sha, [10, 0, 0, 10], [10, 0, 0, 20], answer);
        // The reply is addressed back to the requester, sourced from the answer.
        assert_eq!(r.eth_dst, req_sha);
        assert_eq!(r.eth_src, answer);
        assert_eq!(r.sha, answer);
        assert_eq!(r.spa, [10, 0, 0, 20]); // the queried IP
        assert_eq!(r.tha, req_sha);
        assert_eq!(r.tpa, [10, 0, 0, 10]); // the requester's IP
    }

    #[test]
    fn vxlan_encap_builds_a_valid_outer_stack() {
        let cfg = OverlayConfig::new(
            [10, 0, 0, 1],
            LOCAL_MAC,
            VXLAN_PORT,
            encap_kind::VXLAN,
            1500,
        );
        let ep = TunnelEndpoint::new(7, [10, 0, 0, 2], NEXTHOP_MAC);
        let inner = 98u16;
        let e = build_encap(&cfg, &ep, 0x0A_BCDE & 0xFFFFFF, inner, 0x1234);
        assert_eq!(e.out_ifindex, 7);
        let h = e.headers;

        // Outer Ethernet.
        assert_eq!(&h[0..6], &NEXTHOP_MAC);
        assert_eq!(&h[6..12], &LOCAL_MAC);
        assert_eq!(&h[12..14], &0x0800u16.to_be_bytes());

        // Outer IPv4: version/IHL, proto UDP, addresses, DF, valid checksum.
        assert_eq!(h[14], 0x45);
        assert_eq!(h[23], ip_proto::UDP);
        assert_eq!(&h[26..30], &[10, 0, 0, 1]);
        assert_eq!(&h[30..34], &[10, 0, 0, 2]);
        assert_eq!(&h[20..22], &0x4000u16.to_be_bytes());
        let ip_total = u16::from_be_bytes([h[16], h[17]]);
        assert_eq!(ip_total, 20 + 8 + 8 + inner);
        assert_eq!(ipv4_validate(&h[14..34]), 0, "outer IPv4 checksum invalid");

        // Outer UDP: dst port, length, entropy source port, zero checksum.
        assert_eq!(u16::from_be_bytes([h[36], h[37]]), VXLAN_PORT);
        assert_eq!(u16::from_be_bytes([h[38], h[39]]), 8 + 8 + inner);
        assert_eq!(&h[40..42], &[0, 0]);
        let sport = u16::from_be_bytes([h[34], h[35]]);
        assert!(
            (49152..=65535).contains(&sport),
            "sport {sport} out of range"
        );

        // VXLAN shim: I-bit set, VNI round-trips.
        assert_eq!(h[42], VXLAN_FLAGS_VNI);
        let shim: [u8; 8] = h[42..50].try_into().unwrap();
        assert_eq!(decode_vni(shim), 0x0A_BCDE & 0xFFFFFF);
    }

    #[test]
    fn geneve_encap_sets_base_header_and_same_vni_offset() {
        let cfg = OverlayConfig::new(
            [192, 168, 1, 5],
            LOCAL_MAC,
            GENEVE_PORT,
            encap_kind::GENEVE,
            1500,
        );
        let ep = TunnelEndpoint::new(3, [192, 168, 1, 9], NEXTHOP_MAC);
        let e = build_encap(&cfg, &ep, 4242, 200, 0);
        let h = e.headers;
        // Geneve base: ver/optlen 0, flags 0, protocol = Ethernet (0x6558).
        assert_eq!(h[42], 0);
        assert_eq!(h[43], 0);
        assert_eq!(&h[44..46], &0x6558u16.to_be_bytes());
        // VNI at the same 4..7 offset as VXLAN.
        let shim: [u8; 8] = h[42..50].try_into().unwrap();
        assert_eq!(decode_vni(shim), 4242);
        assert_eq!(u16::from_be_bytes([h[36], h[37]]), GENEVE_PORT);
    }

    #[test]
    fn entropy_varies_source_port_but_stays_in_range_and_is_deterministic() {
        // Different entropy -> (generally) different port; same entropy -> same.
        let a = overlay_src_port(0x0000);
        let b = overlay_src_port(0x3FFF);
        let c = overlay_src_port(0x3FFF);
        assert_eq!(b, c);
        assert_ne!(a, b);
        assert_eq!(a, 0xC000);
        assert_eq!(b, 0xFFFF);
        // High bits of entropy never push it out of the ephemeral range.
        assert_eq!(overlay_src_port(0xFFFF_FFFF), 0xFFFF);
    }

    #[test]
    fn decode_vni_ignores_flag_and_reserved_bytes() {
        // Only bytes 4..7 matter; flags (byte 0) and reserved bytes are ignored.
        let shim = [0x08, 0xAA, 0xBB, 0xCC, 0x12, 0x34, 0x56, 0x99];
        assert_eq!(decode_vni(shim), 0x123456);
    }

    #[test]
    fn overlay_dport_gate_respects_enabled_and_port() {
        let on = OverlayConfig::new(
            [10, 0, 0, 1],
            LOCAL_MAC,
            VXLAN_PORT,
            encap_kind::VXLAN,
            1500,
        );
        assert!(is_overlay_dport(&on, VXLAN_PORT));
        assert!(!is_overlay_dport(&on, 1234));
        // Disabled config never claims a packet, even on the right port.
        assert!(!is_overlay_dport(&OverlayConfig::DISABLED, VXLAN_PORT));
    }

    #[test]
    fn vni_top_bits_above_24_are_dropped_on_encode() {
        let cfg = OverlayConfig::new(
            [10, 0, 0, 1],
            LOCAL_MAC,
            VXLAN_PORT,
            encap_kind::VXLAN,
            1500,
        );
        let ep = TunnelEndpoint::new(1, [10, 0, 0, 2], NEXTHOP_MAC);
        // 0xFF_123456 -> only low 24 bits (0x123456) survive in the 3-byte field.
        let e = build_encap(&cfg, &ep, 0xFF_123456, 64, 0);
        let shim: [u8; 8] = e.headers[42..50].try_into().unwrap();
        assert_eq!(decode_vni(shim), 0x123456);
    }
}
