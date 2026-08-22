//! SRv6 (RFC 8986 network programming) — the modern, SID-based overlay wire
//! format that unifies L2VPN and L3VPN behind **one** data-plane primitive.
//!
//! Where the VXLAN/Geneve overlay ([`crate::overlay`]) carries the tenant
//! identity in a separate 8-byte shim over UDP/IPv4, SRv6 folds *both* the
//! forwarding path and the tenant/behaviour selection into a single 128-bit
//! **SID** — an IPv6 address that routes the packet across the underlay and, on
//! the egress node, selects an *endpoint behaviour* (RFC 8986 §4):
//!
//! * `End.DT2U` / `End.DT2M` — decapsulate and bridge into an L2 tenant
//!   (EVPN type-2 unicast / type-3 BUM flood), and
//! * `End.DT4` / `End.DT6` — decapsulate and route into an L3 VRF.
//!
//! ## Reduced encapsulation (H.Encaps.Red)
//!
//! For EVPN-over-SRv6 the segment list is a *single* service SID, so — per
//! RFC 8986 §5.2 and RFC 9252 — no Segment Routing Header is needed: the one
//! SID rides directly in the outer IPv6 destination address. The encapsulated
//! frame is therefore just **outer Ethernet + outer IPv6 + inner payload**,
//! which the eBPF datapath grows with a single `bpf_xdp_adjust_head` and one
//! fixed-size store, exactly as [`crate::build_encap`] does for VXLAN. IPv6 has
//! no header checksum, so — unlike the VXLAN path — there is no outer-checksum
//! arithmetic at all.
//!
//! ## Where the identity lives
//!
//! There is no VNI field on the wire outside the SID. The tenant/behaviour is
//! encoded *in* the SID by the originating node's locator layout (see
//! [`build_service_sid`]); the terminating node maps a locally-instantiated SID
//! back to `(behaviour, vni)` via an explicit table the control plane pushes
//! ([`Srv6LocalSid`]), rather than re-deriving it — the same "controller holds
//! the answer" model the VXLAN FDB uses.
//!
//! Everything here is a pure, `no_std`, allocation-free, unit-tested function or
//! `#[repr(C)]` map type — the eBPF program does only the packet grow/shrink the
//! kernel alone can do.

use crate::packet::ETHERTYPE_IPV6;

/// A 128-bit SRv6 SID — an IPv6 address that both routes the packet across the
/// underlay *and* selects an endpoint behaviour on the egress node.
pub type Srv6Sid = [u8; 16];

/// SRv6 endpoint behaviours (RFC 8986 code points). These mirror wren's
/// `wren-bgp/src/srv6.rs` `behavior` module so a SID's behaviour means the same
/// thing on both the control plane (origination) and the data plane (this crate).
pub mod behavior {
    /// End.DT6 — decapsulate and IPv6 table lookup (L3VPN IPv6).
    pub const END_DT6: u16 = 0x0012;
    /// End.DT4 — decapsulate and IPv4 table lookup (L3VPN IPv4).
    pub const END_DT4: u16 = 0x0013;
    /// End.DT46 — decapsulate and IP table lookup (dual-stack L3VPN).
    pub const END_DT46: u16 = 0x0014;
    /// End.DT2U — decapsulate and L2 **unicast** bridge lookup (EVPN type-2).
    pub const END_DT2U: u16 = 0x0016;
    /// End.DT2M — decapsulate and L2 **flood** (EVPN type-3 BUM).
    pub const END_DT2M: u16 = 0x0017;
}

/// The unicast/multicast discriminator wren writes into a locator-derived
/// service SID so an EVI's `End.DT2U` and `End.DT2M` SIDs differ (RFC 9252 — a
/// SID maps to exactly one behaviour on its egress node).
pub mod sid_disc {
    /// Unicast — an `End.DT2U` bridge SID.
    pub const UNICAST: u8 = 0;
    /// Multicast — an `End.DT2M` flood SID.
    pub const MULTICAST: u8 = 1;
}

/// IANA "Ethernet" IP protocol number (RFC 8986 §6.6): the outer IPv6
/// next-header value when the inner payload is a full Ethernet frame, i.e. the
/// `End.DT2U` / `End.DT2M` (L2) case.
pub const IPPROTO_ETHERNET: u8 = 143;
/// IPv4-in-IPv6 next-header (RFC 2003): the `End.DT4` (L3 IPv4) inner protocol.
pub const IPPROTO_IPIP: u8 = 4;
/// IPv6-in-IPv6 next-header (RFC 2473): the `End.DT6` (L3 IPv6) inner protocol.
pub const IPPROTO_IPV6: u8 = 41;

/// Bytes prepended on an SRv6 **L2** encap: outer Ethernet (14) + outer IPv6
/// (40). Reduced encapsulation (H.Encaps.Red) with a single service SID needs no
/// Segment Routing Header, so this is a fixed 54 bytes — one
/// `bpf_xdp_adjust_head(-SRV6_L2_OUTER_LEN)` grows the headroom.
pub const SRV6_L2_OUTER_LEN: usize = 14 + 40;

/// Per-host SRv6 configuration: this node's tunnel-source identity. Exactly one
/// entry (index `0`) of the `SRV6_CONFIG` array map — the SRv6 analogue of
/// [`crate::OverlayConfig`]. SRv6 and VXLAN/Geneve are mutually exclusive per
/// host (one overlay wire format at a time), so when this is enabled the
/// `OverlayConfig` is disabled and vice versa.
///
/// Field order keeps the 28-byte layout padding-free (the 16-byte SID leads,
/// then the MAC, then the `u16`, closing with `enabled` + explicit `_pad`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6Config {
    /// This host's SRv6 source address (the outer IPv6 **source**): an address
    /// out of its own locator, network-order octets.
    pub local_src: Srv6Sid,
    /// This host's underlay MAC (outer source MAC).
    pub local_mac: [u8; 6],
    /// Underlay path MTU in bytes (the largest outer IPv6 packet that fits). An
    /// inner frame whose encapsulation would exceed this is dropped rather than
    /// silently black-holed. The outer IPv6 packet is `40 + inner_len` bytes.
    pub underlay_mtu: u16,
    /// `1` when the SRv6 overlay is active; `0` disables encap/decap entirely.
    pub enabled: u8,
    /// Explicit padding, always zero.
    pub _pad: [u8; 3],
}

impl Srv6Config {
    /// A disabled config — no SRv6 encap/decap. The default when no `[srv6]`
    /// section is present.
    pub const DISABLED: Self = Self {
        local_src: [0; 16],
        local_mac: [0; 6],
        underlay_mtu: 1500,
        enabled: 0,
        _pad: [0; 3],
    };

    /// Build an enabled config.
    #[inline]
    pub const fn new(local_src: Srv6Sid, local_mac: [u8; 6], underlay_mtu: u16) -> Self {
        Self {
            local_src,
            local_mac,
            underlay_mtu,
            enabled: 1,
            _pad: [0; 3],
        }
    }

    /// Whether the SRv6 overlay is active.
    #[inline]
    pub const fn is_enabled(&self) -> bool {
        self.enabled != 0
    }

    /// The largest inner frame (in bytes) that still fits the underlay MTU once
    /// the outer IPv6 header is added. The outer IPv6 packet is `40 + inner_len`
    /// bytes (no UDP, no shim, no SRH — reduced encap), so the inner frame must
    /// be `≤ underlay_mtu - 40`. Returns `0` for absurdly small MTUs.
    #[inline]
    pub const fn max_inner_len(&self) -> u16 {
        let overhead = (SRV6_L2_OUTER_LEN - 14) as u16; // outer IPv6 = 40
        self.underlay_mtu.saturating_sub(overhead)
    }
}

// SAFETY: `#[repr(C)]`, byte arrays + `u16` + bytes, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6Config {}

/// The remote endpoint an inner `(vni, dst-mac)` resolves to for SRv6 encap:
/// which service SID to send *to* (the outer IPv6 destination), which underlay
/// interface to redirect out of, and the underlay next-hop L2 address. The SRv6
/// analogue of [`crate::TunnelEndpoint`] — but the 4-byte VTEP IPv4 is replaced
/// by the 16-byte service SID.
///
/// Field order keeps the 28-byte layout padding-free (the `u32` leads, the
/// 16-byte SID and 6-byte MAC follow, explicit `_pad` closes it out).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6Endpoint {
    /// Underlay interface index to redirect the encapsulated packet out of.
    pub out_ifindex: u32,
    /// Remote service SID = the outer IPv6 **destination** address.
    pub remote_sid: Srv6Sid,
    /// Outer destination MAC: the underlay next hop toward the remote SID.
    pub outer_dst_mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl Srv6Endpoint {
    /// Build an endpoint.
    #[inline]
    pub const fn new(out_ifindex: u32, remote_sid: Srv6Sid, outer_dst_mac: [u8; 6]) -> Self {
        Self {
            out_ifindex,
            remote_sid,
            outer_dst_mac,
            _pad: [0; 2],
        }
    }
}

// SAFETY: `#[repr(C)]`, `u32` + byte arrays, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6Endpoint {}

/// Key into the local-SID table (`SRV6_LOCAL_SIDS`): a 128-bit SID this node has
/// **instantiated** (advertised to its EVPN peers). An exact-match lookup on the
/// arriving packet's outer IPv6 destination decides whether — and how — to apply
/// an endpoint behaviour.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct Srv6SidKey {
    /// The instantiated SID (network-order octets, i.e. IPv6 wire form).
    pub sid: Srv6Sid,
}

impl Srv6SidKey {
    /// Build a key for `sid`.
    #[inline]
    pub const fn new(sid: Srv6Sid) -> Self {
        Self { sid }
    }
}

// SAFETY: `#[repr(C)]`, a single 16-byte array, no padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6SidKey {}

/// The behaviour a locally-instantiated SID resolves to on decap: which tenant
/// (`vni`) it terminates into and which endpoint behaviour to apply
/// ([`behavior`]).
///
/// Field order keeps the 8-byte layout padding-free (the `u32` leads).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6LocalSid {
    /// Tenant VNI this SID bridges/routes into.
    pub vni: u32,
    /// Endpoint behaviour ([`behavior`]): `END_DT2U`, `END_DT2M`, ...
    pub behavior: u16,
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl Srv6LocalSid {
    /// Build a local-SID descriptor for `(vni, behaviour)`.
    #[inline]
    pub const fn new(vni: u32, behavior: u16) -> Self {
        Self {
            vni,
            behavior,
            _pad: [0; 2],
        }
    }

    /// Whether this SID applies an L2 behaviour (`End.DT2U`/`End.DT2M`), i.e. the
    /// inner payload is an Ethernet frame.
    #[inline]
    pub const fn is_l2(&self) -> bool {
        self.behavior == behavior::END_DT2U || self.behavior == behavior::END_DT2M
    }
}

// SAFETY: `#[repr(C)]`, `u32` + `u16` + explicit padding, no uninit bytes.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6LocalSid {}

/// The fully-built outer header stack and where to send it, produced by
/// [`build_srv6_encap`] — the SRv6 analogue of [`crate::Encap`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6Encap {
    /// The [`SRV6_L2_OUTER_LEN`] bytes to prepend, ready to copy in after a
    /// `bpf_xdp_adjust_head(-SRV6_L2_OUTER_LEN)`.
    pub headers: [u8; SRV6_L2_OUTER_LEN],
    /// Underlay interface index to redirect the encapsulated frame out of.
    pub out_ifindex: u32,
}

/// Build the complete outer header stack to encapsulate an inner Ethernet frame
/// into SRv6 (reduced encapsulation, a single service SID; `End.DT2U`/`End.DT2M`).
///
/// Pure and allocation-free: the caller supplies this host's SRv6 source address
/// (the outer IPv6 source), its underlay MAC, the resolved [`Srv6Endpoint`], the
/// inner Ethernet frame's current length (the whole ingress L2 frame becomes the
/// tunnel payload), and a 32-bit `entropy` value hashed from the inner flow. The
/// entropy goes into the IPv6 **flow label** so the underlay's ECMP hashing
/// spreads inner flows across paths (RFC 6438). IPv6 carries no header checksum,
/// so nothing else needs computing.
///
/// ```
/// use velstra_common::{build_srv6_encap, Srv6Endpoint, SRV6_L2_OUTER_LEN};
/// use velstra_common::srv6::IPPROTO_ETHERNET;
///
/// let local_src = [0xfc, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// let sid = [0xfc, 0, 0, 0, 0, 2, 0, 0x27, 0x10, 0, 0, 0, 0, 0, 0, 0];
/// let ep = Srv6Endpoint::new(7, sid, [0x02, 0, 0, 0, 0, 0x02]);
///
/// let e = build_srv6_encap(&local_src, &[0x02, 0, 0, 0, 0, 0x01], &ep, 98, 0xABCDE);
/// assert_eq!(e.out_ifindex, 7);
/// // Outer IPv6 next-header is "Ethernet" (End.DT2), dst is the service SID.
/// assert_eq!(e.headers[14 + 6], IPPROTO_ETHERNET);
/// assert_eq!(&e.headers[14 + 24..14 + 40], &sid);
/// ```
#[inline]
pub fn build_srv6_encap(
    local_src: &Srv6Sid,
    local_mac: &[u8; 6],
    ep: &Srv6Endpoint,
    inner_frame_len: u16,
    entropy: u32,
) -> Srv6Encap {
    let mut h = [0u8; SRV6_L2_OUTER_LEN];
    write_srv6_encap(&mut h, local_src, local_mac, ep, inner_frame_len, entropy);
    Srv6Encap {
        headers: h,
        out_ifindex: ep.out_ifindex,
    }
}

/// The same header stack, written **into a caller-owned buffer** instead of
/// returned by value.
///
/// This exists for one reason and it is a hard constraint rather than a
/// preference: [`Srv6Encap`] is 60 bytes, and returning it by value puts those
/// 60 bytes on the caller's frame. In the XDP encapsulation path that frame is
/// already the deepest in the program, and BPF caps the *combined* depth of a
/// call chain at 512 bytes — so a build that inlines slightly differently turns a
/// working data plane into one the verifier refuses to load, with the failure
/// appearing on whichever machine has the other compiler. The datapath therefore
/// points this at a per-CPU scratch map; [`build_srv6_encap`] stays for the TC
/// path, where the frame has room, and for the tests.
#[inline]
pub fn write_srv6_encap(
    h: &mut [u8; SRV6_L2_OUTER_LEN],
    local_src: &Srv6Sid,
    local_mac: &[u8; 6],
    ep: &Srv6Endpoint,
    inner_frame_len: u16,
    entropy: u32,
) {
    // --- Outer Ethernet (0..14) ---------------------------------------------
    h[0..6].copy_from_slice(&ep.outer_dst_mac);
    h[6..12].copy_from_slice(local_mac);
    h[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

    // --- Outer IPv6 (14..54) ------------------------------------------------
    // version 6, traffic class 0, flow label = low 20 bits of the flow entropy.
    let vtf = 0x6000_0000u32 | (entropy & 0x000F_FFFF);
    h[14..18].copy_from_slice(&vtf.to_be_bytes());
    h[18..20].copy_from_slice(&inner_frame_len.to_be_bytes()); // payload length
    h[20] = IPPROTO_ETHERNET; // next header: inner is an Ethernet frame
    h[21] = 64; // hop limit
    h[22..38].copy_from_slice(local_src); // source address
    h[38..54].copy_from_slice(&ep.remote_sid); // destination = service SID
}

/// Compose a locator-derived service SID, mirroring wren's
/// `wren-bgp/src/srv6.rs::build_service_sid`: the layout is
/// `locator ++ discriminator(1 byte) ++ vni(3 bytes, low 24 bits) ++ zero-fill`.
///
/// `locator_len_bits` is the byte-aligned locator length (block + node) in bits,
/// `8..=96`; the function slots the 1-byte discriminator and 3-byte VNI right
/// after it. The controller uses this to compute *this* host's own service SIDs
/// (to populate the local-SID table) and to cross-check a peer's SID.
///
/// Returns `None` if the locator length is not byte-aligned or leaves no room
/// for the 4-byte function.
#[inline]
pub fn build_service_sid(
    locator: &Srv6Sid,
    locator_len_bits: u8,
    discriminator: u8,
    vni: u32,
) -> Option<Srv6Sid> {
    if locator_len_bits % 8 != 0 {
        return None;
    }
    let off = (locator_len_bits / 8) as usize;
    if off + 4 > 16 {
        return None;
    }
    let mut sid = *locator;
    // Zero the function/argument region so a caller passing a non-truncated
    // locator still gets a deterministic SID.
    let mut i = off;
    while i < 16 {
        sid[i] = 0;
        i += 1;
    }
    sid[off] = discriminator;
    sid[off + 1] = (vni >> 16) as u8;
    sid[off + 2] = (vni >> 8) as u8;
    sid[off + 3] = vni as u8;
    Some(sid)
}

/// Decode the `(discriminator, vni)` a locator-derived service SID carries, the
/// inverse of [`build_service_sid`]. Used to cross-check or infer the behaviour
/// of a SID whose locator length is known (`discriminator` selects
/// `End.DT2U`=[`sid_disc::UNICAST`] vs `End.DT2M`=[`sid_disc::MULTICAST`]).
///
/// Returns `None` if the locator length is not byte-aligned or leaves no room
/// for the 4-byte function.
#[inline]
pub const fn decode_service_sid(sid: &Srv6Sid, locator_len_bits: u8) -> Option<(u8, u32)> {
    if locator_len_bits % 8 != 0 {
        return None;
    }
    let off = (locator_len_bits / 8) as usize;
    if off + 4 > 16 {
        return None;
    }
    let disc = sid[off];
    let vni = ((sid[off + 1] as u32) << 16) | ((sid[off + 2] as u32) << 8) | (sid[off + 3] as u32);
    Some((disc, vni))
}

/// B9 SRv6 per-VNI **flood set**: the remote `End.DT2M` service SIDs a
/// broadcast/unknown-unicast/multicast frame on a tenant segment must be
/// head-end replicated to. The SRv6 analogue of [`crate::FloodSet`], keyed in
/// `SRV6_FLOOD_LIST` by a bare `u32` VNI.
///
/// Fixed-size for the same reason the VXLAN one is: the TC replication loop is
/// bounded by the constant [`crate::MAX_FLOOD_VTEPS`] so the verifier can bound
/// it, and `count` says how many slots are valid (the rest are zeroed).
///
/// Note the endpoints hold `End.DT2M` SIDs, **not** the `End.DT2U` SIDs the
/// unicast `SRV6_FDB` holds. RFC 9252 binds a SID to exactly one behaviour, so
/// an EVI needs both, and sending a BUM copy to a peer's unicast SID would have
/// it bridged to a single MAC instead of flooded.
///
/// `#[repr(C)]`: a `u32` count (offset 0) followed by `[Srv6Endpoint; 16]` (each
/// 28-byte, 4-aligned) — `4 + 16*28 = 452` bytes, no implicit padding.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6FloodSet {
    /// Number of valid entries in [`Self::endpoints`] (`0..=MAX_FLOOD_VTEPS`).
    pub count: u32,
    /// The flood endpoints. Only the first `count` are meaningful; the rest are
    /// zeroed so the layout is deterministic.
    pub endpoints: [Srv6Endpoint; crate::MAX_FLOOD_VTEPS],
}

impl Srv6FloodSet {
    /// An empty flood set — nothing to replicate to.
    pub const EMPTY: Self = Self {
        count: 0,
        endpoints: [Srv6Endpoint::new(0, [0; 16], [0; 6]); crate::MAX_FLOOD_VTEPS],
    };

    /// Build a flood set from a slice of endpoints. Truncates to
    /// [`crate::MAX_FLOOD_VTEPS`] if the slice is longer, and zero-pads the
    /// unused slots so two equal sets compare byte-for-byte.
    pub fn new(endpoints: &[Srv6Endpoint]) -> Self {
        let mut arr = [Srv6Endpoint::new(0, [0; 16], [0; 6]); crate::MAX_FLOOD_VTEPS];
        let count = if endpoints.len() > crate::MAX_FLOOD_VTEPS {
            crate::MAX_FLOOD_VTEPS
        } else {
            endpoints.len()
        };
        arr[..count].copy_from_slice(&endpoints[..count]);
        Self {
            count: count as u32,
            endpoints: arr,
        }
    }
}

// SAFETY: `#[repr(C)]`, a `u32` followed by an array of `Pod` `Srv6Endpoint`s,
// no implicit padding.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6FloodSet {}

/// B9 SRv6 **symmetric-IRB** route entry: the SRv6 analogue of
/// [`crate::IrbEndpoint`], keyed in `SRV6_IRB_ROUTES` by `(vni, inner dst IP)`.
///
/// The wire behaviour mirrors the VXLAN IRB path: RFC 9136 symmetric IRB
/// encapsulates a *rewritten Ethernet frame* with the tenant's **L3 VNI**, and
/// here that becomes an `End.DT2U` SID derived from that L3 VNI. One
/// encapsulation shape (`IPPROTO_ETHERNET`, [`SRV6_L2_OUTER_LEN`]) on the wire,
/// one decap path in the datapath.
///
/// **This is not what RFC 9252 §6 specifies for a type-5 route**, which is
/// `End.DT4`/`End.DT6` — a *bare IP* payload the egress looks up in a VRF. wren
/// already originates those SIDs. The reason this datapath cannot consume one is
/// concrete rather than aesthetic: an `End.DT4` decap yields a packet with no
/// Ethernet header, which has to be delivered into the tenant's own L3 device to
/// be routed in the right VRF — and this host model has a single shared kernel
/// bridge (`LOCAL_VNIS`' value is a reserved per-VNI bridge ifindex that is not
/// populated yet). Handing a bare IP packet to the ingress interface would route
/// it in the default VRF, i.e. leak it out of its tenant.
///
/// So: fabric-to-fabric IRB works over these SIDs, and the controller derives the
/// peer's L3-VNI `End.DT2U` SID from the peer's locator rather than trusting the
/// `End.DT4` SID a type-5 route advertises. Interop with a third-party PE needs
/// the L3 behaviours, and those need per-tenant L3 devices first.
///
/// `#[repr(C)]`: two `u32`s, then the 16-byte SID, then three 6-byte MACs and
/// explicit padding — `4+4+16+6+6+6+2 = 44` bytes, 4-aligned, no implicit
/// padding.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Srv6IrbEndpoint {
    /// Underlay interface index to redirect the encapsulated packet out of.
    pub out_ifindex: u32,
    /// The tenant's **L3 VNI** — the VNI whose `End.DT2U` SID this entry points
    /// at, replacing the ingress segment's (RFC 9136 §4.4.1).
    pub l3_vni: u32,
    /// Remote `End.DT2U` service SID for the tenant's L3 VNI (outer IPv6
    /// destination).
    pub remote_sid: Srv6Sid,
    /// Outer destination MAC: the underlay next hop toward that SID.
    pub outer_dst_mac: [u8; 6],
    /// The remote PE's **Router's MAC** (RFC 9135 §4), which becomes the inner
    /// destination MAC.
    pub router_mac: [u8; 6],
    /// This tenant's **anycast gateway MAC**, which becomes the inner source
    /// MAC — and, on ingress, the L2 address that gates whether to route at all.
    pub gateway_mac: [u8; 6],
    /// Explicit padding, always zero.
    pub _pad: [u8; 2],
}

impl Srv6IrbEndpoint {
    /// Build an SRv6 IRB route entry.
    #[inline]
    pub const fn new(
        out_ifindex: u32,
        l3_vni: u32,
        remote_sid: Srv6Sid,
        outer_dst_mac: [u8; 6],
        router_mac: [u8; 6],
        gateway_mac: [u8; 6],
    ) -> Self {
        Self {
            out_ifindex,
            l3_vni,
            remote_sid,
            outer_dst_mac,
            router_mac,
            gateway_mac,
            _pad: [0; 2],
        }
    }

    /// The plain [`Srv6Endpoint`] this route encapsulates toward, so the routed
    /// path can hand [`build_srv6_encap`] exactly what the bridged path does.
    #[inline]
    pub const fn endpoint(&self) -> Srv6Endpoint {
        Srv6Endpoint::new(self.out_ifindex, self.remote_sid, self.outer_dst_mac)
    }
}

// SAFETY: `#[repr(C)]`, `u32`s + byte arrays, padding explicitly zeroed.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Srv6IrbEndpoint {}

/// Plan the inner rewrite for an SRv6 symmetric-IRB hit — the SRv6 twin of
/// [`crate::plan_irb`], and deliberately producing the very same
/// [`crate::IrbRewrite`]: the rewrite is a property of RFC 9135 routing, not of
/// the encapsulation carrying it, so both paths apply identical inner edits and
/// a change to one can never silently diverge from the other.
///
/// Returns `None` when the packet cannot survive another hop.
///
/// As with the VXLAN path, the gate on *whether* to route (inner destination MAC
/// == the anycast gateway MAC) belongs to the caller.
///
/// ```
/// use velstra_common::{plan_srv6_irb, Srv6IrbEndpoint};
///
/// let ep = Srv6IrbEndpoint::new(
///     3, 50100, [0xfc, 0, 0, 0, 0, 2, 0, 0xc3, 0xb4, 0, 0, 0, 0, 0, 0, 0],
///     [0x02, 0, 0, 0, 0, 0x02], [0x02, 0xaa, 0, 0, 0, 0x01], [0x02, 0, 0x5e, 0, 0, 0x01],
/// );
/// let rw = plan_srv6_irb(&ep, 64, 0xb761, 6).expect("a TTL-64 packet survives the hop");
/// assert_eq!(rw.inner_dst_mac, [0x02, 0xaa, 0, 0, 0, 0x01]);
/// assert_eq!(rw.inner_src_mac, [0x02, 0, 0x5e, 0, 0, 0x01]);
/// assert_eq!(rw.new_ttl, 63);
/// // A packet at the end of its life is dropped, not routed onto the overlay.
/// assert!(plan_srv6_irb(&ep, 1, 0xb861, 6).is_none());
/// ```
#[inline]
pub const fn plan_srv6_irb(
    ep: &Srv6IrbEndpoint,
    ttl: u8,
    checksum: u16,
    proto: u8,
) -> Option<crate::IrbRewrite> {
    let Some((new_ttl, new_checksum)) = crate::decrement_ttl(ttl, checksum, proto) else {
        return None;
    };
    Some(crate::IrbRewrite {
        inner_dst_mac: ep.router_mac,
        inner_src_mac: ep.gateway_mac,
        new_ttl,
        new_checksum,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pod_layouts_have_no_padding() {
        // 4 (out_ifindex) + 16 (sid) + 6 (mac) + 2 (pad) = 28, 4-aligned.
        assert_eq!(core::mem::size_of::<Srv6Endpoint>(), 28);
        assert_eq!(core::mem::align_of::<Srv6Endpoint>(), 4);
        // A bare 16-byte SID key.
        assert_eq!(core::mem::size_of::<Srv6SidKey>(), 16);
        assert_eq!(core::mem::align_of::<Srv6SidKey>(), 1);
        // 4 (vni) + 2 (behavior) + 2 (pad) = 8, 4-aligned.
        assert_eq!(core::mem::size_of::<Srv6LocalSid>(), 8);
        assert_eq!(core::mem::align_of::<Srv6LocalSid>(), 4);
        // 16 (src) + 6 (mac) + 2 (mtu) + 1 (enabled) + 3 (pad) = 28, 2-aligned.
        assert_eq!(core::mem::size_of::<Srv6Config>(), 28);
        assert_eq!(core::mem::align_of::<Srv6Config>(), 2);
        // Outer stack: eth 14 + IPv6 40, no SRH (reduced encap).
        assert_eq!(SRV6_L2_OUTER_LEN, 54);
    }

    #[test]
    fn config_disabled_and_mtu_headroom() {
        assert!(!Srv6Config::DISABLED.is_enabled());
        let c = Srv6Config::new(
            [0xfc, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0; 6],
            1500,
        );
        assert!(c.is_enabled());
        assert_eq!(c._pad, [0, 0, 0]);
        // Inner frame must leave room for the 40-byte outer IPv6 header.
        assert_eq!(c.max_inner_len(), 1460);
        // An absurdly small MTU saturates to zero rather than underflowing.
        assert_eq!(Srv6Config::new([0; 16], [0; 6], 20).max_inner_len(), 0);
    }

    #[test]
    fn endpoint_new_zeroes_padding() {
        let sid = [0xfc, 0, 0, 0, 0, 2, 0, 0x27, 0x10, 0, 0, 0, 0, 0, 0, 0];
        let ep = Srv6Endpoint::new(9, sid, [0x02, 0, 0, 0, 0, 0x0a]);
        assert_eq!(ep._pad, [0, 0]);
        assert_eq!(ep.remote_sid, sid);
        assert_eq!(ep, Srv6Endpoint::new(9, sid, [0x02, 0, 0, 0, 0, 0x0a]));
        assert_ne!(ep, Srv6Endpoint::new(10, sid, [0x02, 0, 0, 0, 0, 0x0a]));
    }

    #[test]
    fn local_sid_new_zeroes_padding_and_classifies_l2() {
        let u = Srv6LocalSid::new(10000, behavior::END_DT2U);
        assert_eq!(u._pad, [0, 0]);
        assert!(u.is_l2());
        assert!(Srv6LocalSid::new(10000, behavior::END_DT2M).is_l2());
        assert!(!Srv6LocalSid::new(10000, behavior::END_DT4).is_l2());
        assert!(!Srv6LocalSid::new(10000, behavior::END_DT6).is_l2());
    }

    #[test]
    fn srv6_encap_builds_outer_ethernet_and_ipv6() {
        let local_src = [0xfc, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sid = [0xfc, 0, 0, 0, 0, 2, 0, 0x27, 0x10, 0, 0, 0, 0, 0, 0, 0];
        let ep = Srv6Endpoint::new(7, sid, [0x02, 0, 0, 0, 0, 0x02]);
        let e = build_srv6_encap(&local_src, &[0x02, 0, 0, 0, 0, 0x01], &ep, 98, 0xABCDE);

        assert_eq!(e.out_ifindex, 7);
        // Outer Ethernet: dst = underlay next hop, src = local MAC, ethertype IPv6.
        assert_eq!(&e.headers[0..6], &[0x02, 0, 0, 0, 0, 0x02]);
        assert_eq!(&e.headers[6..12], &[0x02, 0, 0, 0, 0, 0x01]);
        assert_eq!(&e.headers[12..14], &ETHERTYPE_IPV6.to_be_bytes());
        // Outer IPv6: version nibble 6, flow label carries the entropy.
        assert_eq!(e.headers[14] >> 4, 6);
        let vtf = u32::from_be_bytes(e.headers[14..18].try_into().unwrap());
        assert_eq!(vtf & 0x000F_FFFF, 0xABCDE);
        assert_eq!(vtf >> 28, 6);
        // Payload length = inner frame length; next-header Ethernet; hop limit 64.
        assert_eq!(
            u16::from_be_bytes(e.headers[18..20].try_into().unwrap()),
            98
        );
        assert_eq!(e.headers[20], IPPROTO_ETHERNET);
        assert_eq!(e.headers[21], 64);
        // Source = local SRv6 address, destination = service SID.
        assert_eq!(&e.headers[22..38], &local_src);
        assert_eq!(&e.headers[38..54], &sid);
    }

    #[test]
    fn service_sid_round_trips_through_locator_layout() {
        // A /48 locator (block+node = 48 bits = 6 bytes): disc at byte 6, VNI at 7..10.
        let locator = [
            0xfc, 0, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0,
        ];
        let sid = build_service_sid(&locator, 48, sid_disc::UNICAST, 10000).unwrap();
        // Locator bytes preserved, function region carries disc + 24-bit VNI, rest zero.
        assert_eq!(&sid[0..6], &[0xfc, 0, 0, 0, 0, 1]);
        assert_eq!(sid[6], sid_disc::UNICAST);
        assert_eq!(&sid[7..10], &[0x00, 0x27, 0x10]); // 10000 = 0x2710
        assert_eq!(&sid[10..16], &[0, 0, 0, 0, 0, 0]);

        assert_eq!(
            decode_service_sid(&sid, 48),
            Some((sid_disc::UNICAST, 10000))
        );

        // Multicast SID of the same EVI differs only in the discriminator byte.
        let m = build_service_sid(&locator, 48, sid_disc::MULTICAST, 10000).unwrap();
        assert_ne!(sid, m);
        assert_eq!(
            decode_service_sid(&m, 48),
            Some((sid_disc::MULTICAST, 10000))
        );
    }

    #[test]
    fn service_sid_rejects_unaligned_or_oversized_locator() {
        let locator = [0u8; 16];
        // Not byte-aligned.
        assert_eq!(build_service_sid(&locator, 44, 0, 1), None);
        assert_eq!(decode_service_sid(&locator, 44), None);
        // 104-bit locator leaves < 4 bytes for the function (13 + 4 > 16).
        assert_eq!(build_service_sid(&locator, 104, 0, 1), None);
        assert_eq!(decode_service_sid(&locator, 104), None);
        // 96-bit locator is the maximum that still fits the 4-byte function.
        assert!(build_service_sid(&locator, 96, 0, 1).is_some());
    }

    #[test]
    fn the_new_pod_layouts_have_no_padding_either() {
        // 4 (count) + 16 * 28 (endpoints) = 452, 4-aligned like `Srv6Endpoint`.
        assert_eq!(core::mem::size_of::<Srv6FloodSet>(), 452);
        assert_eq!(core::mem::align_of::<Srv6FloodSet>(), 4);
        // 4 + 4 + 16 + 6 + 6 + 6 + 2 = 44, 4-aligned.
        assert_eq!(core::mem::size_of::<Srv6IrbEndpoint>(), 44);
        assert_eq!(core::mem::align_of::<Srv6IrbEndpoint>(), 4);
    }

    #[test]
    fn a_flood_set_zero_pads_so_equal_sets_compare_byte_for_byte() {
        let a = Srv6Endpoint::new(3, [0xfc; 16], [0x02, 0, 0, 0, 0, 1]);
        let one = Srv6FloodSet::new(&[a]);
        assert_eq!(one.count, 1);
        assert_eq!(one.endpoints[0], a);
        // The unused slots are zeroed, not left uninitialised, so two sets built
        // from the same endpoints are bitwise identical — what lets the agent
        // skip an unchanged map write.
        assert_eq!(one, Srv6FloodSet::new(&[a]));
        assert_eq!(one.endpoints[1], Srv6Endpoint::new(0, [0; 16], [0; 6]));
        assert_eq!(Srv6FloodSet::new(&[]), Srv6FloodSet::EMPTY);
    }

    #[test]
    fn a_flood_set_truncates_rather_than_overflowing_its_fixed_array() {
        // The datapath loop is bounded by the constant, so a longer list must be
        // cut here — silently growing the array would not be representable.
        let many: Vec<_> = (0..crate::MAX_FLOOD_VTEPS as u32 + 5)
            .map(|i| Srv6Endpoint::new(i, [0; 16], [0; 6]))
            .collect();
        let set = Srv6FloodSet::new(&many);
        assert_eq!(set.count as usize, crate::MAX_FLOOD_VTEPS);
        assert_eq!(set.endpoints[crate::MAX_FLOOD_VTEPS - 1].out_ifindex, 15);
    }

    #[test]
    fn an_irb_route_hands_the_bridged_builder_exactly_what_it_expects() {
        // The routed path must reach `build_srv6_encap` through the same
        // `Srv6Endpoint` shape the bridged path uses — that identity is what
        // keeps one encap builder correct for both.
        let sid = [0xfc, 0, 0, 0, 0, 2, 0, 0xc3, 0xb4, 0, 0, 0, 0, 0, 0, 0];
        let via = [0x02, 0, 0, 0, 0, 0x02];
        let irb = Srv6IrbEndpoint::new(
            7,
            50100,
            sid,
            via,
            [0x02, 0xaa, 0, 0, 0, 1],
            [0x02, 0, 0x5e, 0, 0, 1],
        );
        assert_eq!(irb.endpoint(), Srv6Endpoint::new(7, sid, via));
    }

    #[test]
    fn the_two_irb_paths_plan_identical_inner_rewrites() {
        // The rewrite is a property of RFC 9135 routing, not of the encap. If the
        // VXLAN and SRv6 planners ever disagree, one of the two overlays silently
        // routes differently from the other — assert they cannot.
        let router_mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let gw_mac = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x01];
        let v = crate::IrbEndpoint::new(
            7,
            50100,
            [10, 0, 0, 2],
            [0x02, 0, 0, 0, 0, 2],
            router_mac,
            gw_mac,
        );
        let s = Srv6IrbEndpoint::new(
            7,
            50100,
            [0xfc; 16],
            [0x02, 0, 0, 0, 0, 2],
            router_mac,
            gw_mac,
        );
        for ttl in [2u8, 64, 255] {
            assert_eq!(
                crate::plan_irb(&v, ttl, 0xb761, 6),
                plan_srv6_irb(&s, ttl, 0xb761, 6)
            );
        }
        // Including the refusal at the end of a packet's life.
        assert_eq!(crate::plan_irb(&v, 1, 0xb861, 6), None);
        assert_eq!(plan_srv6_irb(&s, 1, 0xb861, 6), None);
    }
}
