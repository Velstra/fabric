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

/// Maximum number of remote VTEPs a single VNI's flood set (`FLOOD_LIST`) can
/// hold. The B2 BUM head-end replication datapath iterates this set with a
/// **constant** upper bound so the eBPF verifier can bound the loop; picking a
/// fixed cap (rather than a variable-length list) is what makes that possible.
/// 16 covers a comfortable fan-out for a small/medium fabric; larger fabrics
/// would move to a multicast underlay instead of head-end replication.
pub const MAX_FLOOD_VTEPS: usize = 16;

/// B2 per-VNI **flood set**: the remote VTEPs a broadcast/unknown-unicast/
/// multicast (BUM) frame on a tenant segment must be head-end replicated to.
/// Keyed in `FLOOD_LIST` by a bare `u32` VNI.
///
/// A **fixed-size** array (not a variable list) so the datapath can walk it with
/// a compile-time-bounded loop the verifier accepts; `count` says how many of
/// the [`MAX_FLOOD_VTEPS`] slots are valid (the rest are zeroed). Each valid slot
/// reuses [`TunnelEndpoint`] — the very same `(out_ifindex, remote_vtep_ip,
/// outer_dst_mac)` triple the unicast FDB uses — so [`build_encap`] can encap a
/// copy toward each one with no new arithmetic.
///
/// `#[repr(C)]`: a `u32` count (offset 0) followed by `[TunnelEndpoint; 16]`
/// (each 16-byte, 4-aligned), so the whole struct is 4-aligned with no implicit
/// padding — `4 + 16*16 = 260` bytes, identical across the kernel/userspace
/// boundary.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FloodSet {
    /// Number of valid entries in [`Self::vteps`] (`0..=MAX_FLOOD_VTEPS`).
    pub count: u32,
    /// The flood endpoints. Only the first `count` are meaningful; the rest are
    /// zeroed so the layout is deterministic.
    pub vteps: [TunnelEndpoint; MAX_FLOOD_VTEPS],
}

impl FloodSet {
    /// Build a flood set from a slice of endpoints. Truncates to
    /// [`MAX_FLOOD_VTEPS`] if the slice is longer, and zero-pads the unused
    /// slots so two equal sets compare byte-for-byte.
    pub fn new(vteps: &[TunnelEndpoint]) -> Self {
        let mut arr = [TunnelEndpoint::new(0, [0; 4], [0; 6]); MAX_FLOOD_VTEPS];
        let count = if vteps.len() > MAX_FLOOD_VTEPS {
            MAX_FLOOD_VTEPS
        } else {
            vteps.len()
        };
        arr[..count].copy_from_slice(&vteps[..count]);
        Self {
            count: count as u32,
            vteps: arr,
        }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` + a fixed array of `Pod` `TunnelEndpoint`s;
// every byte is initialised (unused slots are explicitly zeroed) and there is no
// implicit padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for FloodSet {}

/// B1 MAC-FDB key: a tenant VNI plus an inner destination MAC, matched
/// exactly (a `HashMap` key, unlike the LPM `TunnelKey`). Explicit trailing
/// padding keeps the layout deterministic across the kernel/userspace boundary
/// (mirrors `TunnelEndpoint::_pad`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct MacFdbKey {
    /// Tenant VNI the destination MAC lives on, matched exactly.
    pub vni: u32,
    /// Inner destination MAC to bridge toward.
    pub mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl MacFdbKey {
    /// Build a key for `(vni, mac)`.
    #[inline]
    pub const fn new(vni: u32, mac: [u8; 6]) -> Self {
        Self {
            vni,
            mac,
            _pad: [0; 2],
        }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` + byte arrays, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for MacFdbKey {}

/// B4b **local-MAC learning** key: a tenant VNI plus a **source** MAC the data
/// plane observed on a tenant port, matched exactly (the key of the `LOCAL_MACS`
/// LRU map). Mirrors [`MacFdbKey`]'s 12-byte layout — a `u32` VNI, a 6-byte MAC
/// and explicit trailing padding — so the kernel and userspace agree
/// byte-for-byte across the map boundary.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct LocalMacKey {
    /// Tenant VNI the source MAC was learned on, matched exactly.
    pub vni: u32,
    /// The learned tenant source MAC.
    pub mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl LocalMacKey {
    /// Build a key for `(vni, mac)`.
    #[inline]
    pub const fn new(vni: u32, mac: [u8; 6]) -> Self {
        Self {
            vni,
            mac,
            _pad: [0; 2],
        }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` + byte arrays, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for LocalMacKey {}

/// B4b **local-MAC learning** value: the tenant IPv4 last seen bound to the keyed
/// source MAC. The agent reads these out and advertises each `(vni, mac, ip)` to
/// the co-located Wren routing daemon (which re-advertises them as type-2 EVPN
/// routes). 8 bytes, explicit padding zeroed so the layout is deterministic.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LocalMac {
    /// The learned tenant IPv4, network-order octets.
    pub ip: [u8; 4],
    /// Explicit padding, always zero.
    pub _pad: [u8; 4],
}

impl LocalMac {
    /// Build a value binding `ip` to a learned source MAC.
    #[inline]
    pub const fn new(ip: [u8; 4]) -> Self {
        Self { ip, _pad: [0; 4] }
    }
}

// SAFETY: `#[repr(C)]`, a 4-byte array + explicit padding, no uninit bytes.
#[cfg(feature = "user")]
unsafe impl aya::Pod for LocalMac {}

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

// === IPv6 Neighbor-Discovery suppression (B3) ==============================
//
// The IPv6 mirror of ARP suppression. A tenant VM sends an ICMPv6 Neighbor
// Solicitation (NS, type 135) to resolve a peer's link-layer address; flooding
// that to every VTEP scales as poorly as ARP does. So — exactly as [`try_arp`]
// does for IPv4 — the host answers **locally** with a synthesised Neighbor
// Advertisement (NA, type 136) from `ND_TABLE`, pushed by the controller, and
// the solicitation never reaches the overlay.
//
// [`try_arp`]: (the eBPF data-plane function)

/// ICMPv6 type for a Neighbor Solicitation (RFC 4861 §4.3).
pub const ICMPV6_NEIGHBOR_SOLICIT: u8 = 135;
/// ICMPv6 type for a Neighbor Advertisement (RFC 4861 §4.4).
pub const ICMPV6_NEIGHBOR_ADVERT: u8 = 136;

/// Length of the synthesised NA ICMPv6 message: the 24-byte NA header (type,
/// code, checksum, 4-byte flags, 16-byte target) plus an 8-byte Target
/// Link-Layer Address option (type, length, 6-byte MAC).
pub const ND_NA_MSG_LEN: usize = 32;

/// NA flags word (RFC 4861 §4.4): Solicited (`S`, `0x4000_0000`) + Override
/// (`O`, `0x2000_0000`). The Router (`R`) bit is **not** set — we answer for
/// tenant hosts, not routers.
const ND_NA_FLAGS: u32 = 0x6000_0000;

/// ICMPv6 NDP option type for a Target Link-Layer Address (RFC 4861 §4.6.1).
const ND_OPT_TARGET_LLA: u8 = 2;

/// Key into `ND_TABLE`: which tenant segment (`vni`) and which target IPv6 a
/// Neighbor Solicitation is asking about. Exact match — one entry per tenant
/// address. `4 + 16 = 20` bytes, 4-aligned with no implicit padding (the
/// [`ArpEntry`] value is reused unchanged).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NdKey {
    /// Tenant VNI the requesting port belongs to.
    pub vni: u32,
    /// Target IPv6 being resolved, network-order octets.
    pub ip: [u8; 16],
}

impl NdKey {
    /// Build a key for `(vni, ip)`.
    #[inline]
    pub const fn new(vni: u32, ip: [u8; 16]) -> Self {
        Self { vni, ip }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` and a 16-byte array — 20 bytes, no padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for NdKey {}

/// The field values that turn an ICMPv6 Neighbor **Solicitation** into the
/// Neighbor **Advertisement** to unicast back out the same interface
/// (`XDP_TX`), produced by [`plan_na_reply`]. Pure data; the data plane writes
/// these at constant offsets in place.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NaReply {
    /// New Ethernet destination (the soliciting host's MAC).
    pub eth_dst: [u8; 6],
    /// New Ethernet source (the answered MAC).
    pub eth_src: [u8; 6],
    /// New IPv6 source (the solicited target address).
    pub ipv6_src: [u8; 16],
    /// New IPv6 destination (the soliciting host's address — unicast reply).
    pub ipv6_dst: [u8; 16],
    /// The complete 32-byte ICMPv6 Neighbor Advertisement message, checksum
    /// filled in, ready to write over the NS body at a constant offset.
    pub na_msg: [u8; ND_NA_MSG_LEN],
}

/// Internet checksum (RFC 4443 §2.3) over an ICMPv6 message, prefixed by the
/// IPv6 **pseudo-header**: source (16) + destination (16) + upper-layer length
/// (`u32` big-endian) + 3 zero bytes + next-header (58). The `icmpv6_msg` slice
/// must carry its own checksum field zeroed; the returned folded complement is
/// what goes in that field.
#[inline]
pub fn icmpv6_checksum(src: [u8; 16], dst: [u8; 16], icmpv6_msg: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header addresses.
    let mut i = 0;
    while i + 1 < src.len() {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        i += 2;
    }
    let mut i = 0;
    while i + 1 < dst.len() {
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
        i += 2;
    }
    // Upper-layer length (u32), then [0, 0, 0, next-header]: only the length and
    // the next-header byte are non-zero.
    let len = icmpv6_msg.len() as u32;
    sum += (len >> 16) & 0xffff;
    sum += len & 0xffff;
    sum += crate::packet::ip_proto::ICMPV6 as u32;

    // The ICMPv6 message itself (checksum field zeroed by the caller).
    let mut i = 0;
    while i + 1 < icmpv6_msg.len() {
        sum += u16::from_be_bytes([icmpv6_msg[i], icmpv6_msg[i + 1]]) as u32;
        i += 2;
    }
    if i < icmpv6_msg.len() {
        sum += (icmpv6_msg[i] as u32) << 8;
    }

    // Two folds reduce any u32 to 16 bits without a data-dependent loop (the
    // verifier rejects the `while sum >> 16 != 0` form), matching the crate's
    // other checksum code.
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Build the [`NaReply`] that answers a Neighbor Solicitation for `target` with
/// `answer_mac`. Pure and unit-testable; mirrors a standard NDP responder: the
/// solicited target becomes the NA's source, the reply unicasts straight back
/// to the soliciting host.
///
/// * `target` — the solicited target IPv6 (becomes the NA IPv6 source).
/// * `answer_mac` — the MAC that answers (NA Ethernet source + TLLA option).
/// * `ns_src_mac` — the soliciting host's MAC (becomes the NA Ethernet dst).
/// * `ns_src_ip` — the soliciting host's IPv6 (becomes the NA IPv6 dst).
///
/// ```
/// use velstra_common::{plan_na_reply, ICMPV6_NEIGHBOR_ADVERT};
/// let tgt = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
/// let ns_src = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// let r = plan_na_reply(tgt, [0x02, 0, 0, 0, 0, 0x14], [0x02, 0, 0, 0, 0, 0x0a], ns_src);
/// assert_eq!(r.na_msg[0], ICMPV6_NEIGHBOR_ADVERT);
/// assert_eq!(r.ipv6_src, tgt);       // NA is sourced from the target
/// assert_eq!(r.ipv6_dst, ns_src);    // unicast back to the requester
/// ```
#[inline]
pub fn plan_na_reply(
    target: [u8; 16],
    answer_mac: [u8; 6],
    ns_src_mac: [u8; 6],
    ns_src_ip: [u8; 16],
) -> NaReply {
    let mut msg = [0u8; ND_NA_MSG_LEN];
    msg[0] = ICMPV6_NEIGHBOR_ADVERT; // type 136
    // msg[1] code = 0, msg[2..4] checksum filled below.
    msg[4..8].copy_from_slice(&ND_NA_FLAGS.to_be_bytes());
    msg[8..24].copy_from_slice(&target);
    // Target Link-Layer Address option: type 2, length 1 (in 8-octet units).
    msg[24] = ND_OPT_TARGET_LLA;
    msg[25] = 1;
    msg[26..32].copy_from_slice(&answer_mac);

    let ipv6_src = target;
    let ipv6_dst = ns_src_ip;
    let csum = icmpv6_checksum(ipv6_src, ipv6_dst, &msg);
    msg[2..4].copy_from_slice(&csum.to_be_bytes());

    NaReply {
        eth_dst: ns_src_mac,
        eth_src: answer_mac,
        ipv6_src,
        ipv6_dst,
        na_msg: msg,
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
    fn mac_fdb_key_layout_and_equality() {
        // 4 (vni) + 6 (mac) + 2 (pad) = 12; explicit pad keeps it deterministic.
        assert_eq!(core::mem::size_of::<MacFdbKey>(), 12);
        let mac = [0x02, 0, 0, 0, 0, 0x0a];
        let k = MacFdbKey::new(7, mac);
        // `new` always zeroes the padding, so two equal (vni, mac) hash/compare
        // identically — a stable map key.
        assert_eq!(k._pad, [0, 0]);
        assert_eq!(k, MacFdbKey::new(7, mac));
        // Different vni or mac is a different key.
        assert_ne!(k, MacFdbKey::new(8, mac));
        assert_ne!(k, MacFdbKey::new(7, [0x02, 0, 0, 0, 0, 0x0b]));
    }

    #[test]
    fn local_mac_layout_pad_and_equality() {
        // 4 (vni) + 6 (mac) + 2 (pad) = 12; value is 4 (ip) + 4 (pad) = 8.
        assert_eq!(core::mem::size_of::<LocalMacKey>(), 12);
        assert_eq!(core::mem::size_of::<LocalMac>(), 8);

        // `new` zeroes the padding, so equal (vni, mac) hash/compare identically.
        let mac = [0x02, 0, 0, 0, 0, 0x0a];
        let k = LocalMacKey::new(9, mac);
        assert_eq!(k._pad, [0, 0]);
        assert_eq!(k, LocalMacKey::new(9, mac));
        // A different vni or a different MAC is a different key.
        assert_ne!(k, LocalMacKey::new(10, mac));
        assert_ne!(k, LocalMacKey::new(9, [0x02, 0, 0, 0, 0, 0x0b]));

        // The value carries the bound IPv4 with zeroed padding.
        let v = LocalMac::new([192, 168, 1, 5]);
        assert_eq!(v._pad, [0, 0, 0, 0]);
        assert_eq!(v.ip, [192, 168, 1, 5]);
        assert_eq!(v, LocalMac::new([192, 168, 1, 5]));
        assert_ne!(v, LocalMac::new([192, 168, 1, 6]));
    }

    #[test]
    fn flood_set_layout_count_and_truncation() {
        // 4 (count) + 16 * 16 (TunnelEndpoint) = 260 bytes, 4-aligned, no padding.
        assert_eq!(core::mem::size_of::<FloodSet>(), 4 + MAX_FLOOD_VTEPS * 16);
        assert_eq!(core::mem::size_of::<FloodSet>(), 260);
        assert_eq!(core::mem::align_of::<FloodSet>(), 4);

        // Empty set: count 0, every slot zeroed.
        let empty = FloodSet::new(&[]);
        assert_eq!(empty.count, 0);
        assert_eq!(empty.vteps[0], TunnelEndpoint::new(0, [0; 4], [0; 6]));

        // A short set keeps its entries and zero-pads the rest.
        let a = TunnelEndpoint::new(7, [10, 0, 0, 2], NEXTHOP_MAC);
        let b = TunnelEndpoint::new(9, [10, 0, 0, 3], LOCAL_MAC);
        let two = FloodSet::new(&[a, b]);
        assert_eq!(two.count, 2);
        assert_eq!(two.vteps[0], a);
        assert_eq!(two.vteps[1], b);
        assert_eq!(two.vteps[2], TunnelEndpoint::new(0, [0; 4], [0; 6]));
        // Equal inputs produce byte-identical sets (padding is deterministic).
        assert_eq!(two, FloodSet::new(&[a, b]));

        // Over-long input truncates to MAX_FLOOD_VTEPS without panicking.
        let many: Vec<TunnelEndpoint> = (0..MAX_FLOOD_VTEPS as u32 + 5)
            .map(|i| TunnelEndpoint::new(i, [10, 0, 0, i as u8], NEXTHOP_MAC))
            .collect();
        let capped = FloodSet::new(&many);
        assert_eq!(capped.count as usize, MAX_FLOOD_VTEPS);
        assert_eq!(capped.vteps[0], many[0]);
        assert_eq!(capped.vteps[MAX_FLOOD_VTEPS - 1], many[MAX_FLOOD_VTEPS - 1]);
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
    fn nd_key_layout_and_equality() {
        // 4 (vni) + 16 (ip) = 20 bytes, 4-aligned, no padding. The value type is
        // the reused `ArpEntry` (same 8-byte shape as ARP).
        assert_eq!(core::mem::size_of::<NdKey>(), 20);
        let ip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let k = NdKey::new(7, ip);
        assert_eq!(k, NdKey::new(7, ip));
        // A different vni or a different address is a different key.
        assert_ne!(k, NdKey::new(8, ip));
        let mut other = ip;
        other[15] = 3;
        assert_ne!(k, NdKey::new(7, other));
    }

    /// Re-sum an ICMPv6 message *including* its in-place checksum field over the
    /// pseudo-header; a valid message folds to zero.
    fn icmpv6_validate(src: [u8; 16], dst: [u8; 16], msg: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in [&src[..], &dst[..]] {
            let mut i = 0;
            while i + 1 < chunk.len() {
                sum += u16::from_be_bytes([chunk[i], chunk[i + 1]]) as u32;
                i += 2;
            }
        }
        let len = msg.len() as u32;
        sum += (len >> 16) & 0xffff;
        sum += len & 0xffff;
        sum += ip_proto::ICMPV6 as u32;
        let mut i = 0;
        while i + 1 < msg.len() {
            sum += u16::from_be_bytes([msg[i], msg[i + 1]]) as u32;
            i += 2;
        }
        if i < msg.len() {
            sum += (msg[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn na_reply_fields_flags_and_option() {
        let target = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ns_src_ip = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ns_src_mac = [0x02, 0, 0, 0, 0, 0x0a];
        let answer = [0x02, 0, 0, 0, 0, 0x14];
        let r = plan_na_reply(target, answer, ns_src_mac, ns_src_ip);

        // Addresses: reply is sourced from the target, unicast back to the asker.
        assert_eq!(r.eth_dst, ns_src_mac);
        assert_eq!(r.eth_src, answer);
        assert_eq!(r.ipv6_src, target);
        assert_eq!(r.ipv6_dst, ns_src_ip);

        // NA message: type 136, code 0, Solicited+Override flags (R clear).
        assert_eq!(r.na_msg[0], ICMPV6_NEIGHBOR_ADVERT);
        assert_eq!(r.na_msg[1], 0);
        assert_eq!(&r.na_msg[4..8], &0x6000_0000u32.to_be_bytes());
        // Target address echoed into the NA body.
        assert_eq!(&r.na_msg[8..24], &target);
        // Target Link-Layer Address option: type 2, length 1, the answered MAC.
        assert_eq!(r.na_msg[24], 2);
        assert_eq!(r.na_msg[25], 1);
        assert_eq!(&r.na_msg[26..32], &answer);
    }

    #[test]
    fn na_checksum_validates_and_covers_the_body() {
        let target = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02];
        let ns_src_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x99];
        let answer = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let r = plan_na_reply(target, answer, [0x02, 0, 0, 0, 0, 0x0a], ns_src_ip);

        // The synthesised NA, fed back through the pseudo-header sum with its
        // checksum field in place, folds to zero (i.e. is a valid checksum).
        assert_eq!(
            icmpv6_validate(r.ipv6_src, r.ipv6_dst, &r.na_msg),
            0,
            "ICMPv6 NA checksum invalid"
        );

        // The checksum genuinely covers the message: zeroing the checksum field
        // and flipping a TLLA byte changes the recomputed value.
        let mut zeroed = r.na_msg;
        zeroed[2] = 0;
        zeroed[3] = 0;
        let base = icmpv6_checksum(r.ipv6_src, r.ipv6_dst, &zeroed);
        let mut flipped = zeroed;
        flipped[30] ^= 0xff;
        assert_ne!(icmpv6_checksum(r.ipv6_src, r.ipv6_dst, &flipped), base);
    }

    #[test]
    fn na_checksum_depends_on_the_addresses() {
        // Two NAs that differ only in the destination (pseudo-header) address
        // must differ in checksum — proving the pseudo-header is folded in.
        let target = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let a = plan_na_reply(
            target,
            [0x02, 0, 0, 0, 0, 0x14],
            [0; 6],
            [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        let b = plan_na_reply(
            target,
            [0x02, 0, 0, 0, 0, 0x14],
            [0; 6],
            [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        );
        assert_ne!(a.na_msg[2..4], b.na_msg[2..4]);
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
