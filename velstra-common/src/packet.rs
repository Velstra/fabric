//! Wire-format constants and the shared packet/map data types.

/// IANA IP protocol numbers Velstra cares about in Phase 1.
///
/// These are single bytes in the IPv4 header, so they are endianness-neutral.
pub mod ip_proto {
    /// Internet Control Message Protocol (ping, etc.).
    pub const ICMP: u8 = 1;
    /// Transmission Control Protocol.
    pub const TCP: u8 = 6;
    /// User Datagram Protocol.
    pub const UDP: u8 = 17;
    /// ICMPv6 (the IPv6 equivalent of ICMP; also IPv6's next-header value).
    pub const ICMPV6: u8 = 58;

    // --- IPv6 extension headers (RFC 8200 §4) -------------------------------
    // These sit as next-header values *between* the fixed IPv6 header and the
    // upper-layer protocol. A filter that stops at the fixed header sees one of
    // these instead of the real protocol — which is precisely what makes them an
    // evasion tool. See `is_ipv6_ext` / `ipv6_ext_len`.

    /// Hop-by-Hop Options — must come first when present.
    pub const HOPOPT: u8 = 0;
    /// Routing header.
    pub const ROUTING: u8 = 43;
    /// Fragment header (fixed 8 bytes; carries the fragment offset).
    pub const FRAGMENT: u8 = 44;
    /// Encapsulating Security Payload — everything past it is encrypted, so the
    /// chain cannot be walked further.
    pub const ESP: u8 = 50;
    /// Authentication Header (its length counts 4-byte units, unlike the others).
    pub const AH: u8 = 51;
    /// "No Next Header": nothing follows.
    pub const NO_NEXT_HEADER: u8 = 59;
    /// Destination Options.
    pub const DSTOPTS: u8 = 60;
    /// Mobility header (RFC 6275).
    pub const MOBILITY: u8 = 135;
    /// Host Identity Protocol.
    pub const HIP: u8 = 139;
    /// Shim6.
    pub const SHIM6: u8 = 140;
}

/// Whether `proto` is an IPv6 extension header whose chain can be walked on to
/// reach the upper-layer protocol.
///
/// [`ip_proto::ESP`] is deliberately **not** walkable — what follows it is
/// encrypted — and [`ip_proto::NO_NEXT_HEADER`] terminates the chain. Both
/// therefore read as "upper layer" to a caller, which stops the walk. That is the
/// safe outcome: neither yields ports a rule could match.
#[inline]
pub const fn is_ipv6_ext(proto: u8) -> bool {
    matches!(
        proto,
        ip_proto::HOPOPT
            | ip_proto::ROUTING
            | ip_proto::FRAGMENT
            | ip_proto::AH
            | ip_proto::DSTOPTS
            | ip_proto::MOBILITY
            | ip_proto::HIP
            | ip_proto::SHIM6
    )
}

/// The total length in bytes of the IPv6 extension header `proto`, given the
/// `hdr_ext_len` byte at offset 1 of that header.
///
/// The units differ per header, which is why this is a named function rather than
/// an inline expression: most extension headers count 8-byte units *excluding*
/// the first 8 (`(len + 1) * 8`); the Authentication Header counts 4-byte units
/// excluding the first 8 (`(len + 2) * 4`, RFC 4302 §2.2); and the Fragment header
/// is a fixed 8 bytes, with that byte reserved. Returns `0` for a `proto` that is
/// not a walkable extension header — callers gate on [`is_ipv6_ext`] first.
#[inline]
pub const fn ipv6_ext_len(proto: u8, hdr_ext_len: u8) -> usize {
    match proto {
        ip_proto::FRAGMENT => 8,
        ip_proto::AH => (hdr_ext_len as usize + 2) * 4,
        ip_proto::HOPOPT
        | ip_proto::ROUTING
        | ip_proto::DSTOPTS
        | ip_proto::MOBILITY
        | ip_proto::HIP
        | ip_proto::SHIM6 => (hdr_ext_len as usize + 1) * 8,
        _ => 0,
    }
}

/// EtherType for IPv4, in **host** byte order. Compare against the value read
/// from the frame *after* a `u16::from_be`.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6, in host byte order.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

/// Whether a frame of this (host-order) EtherType, which the firewall does not
/// parse, may still reach the kernel on a fail-closed host.
///
/// `FAIL_CLOSED` means "a packet the filter cannot classify is not admitted",
/// and a non-IP EtherType used to pass regardless of it (audit DP-22). What
/// remains is link control a link needs in order to work at all, and the
/// encapsulations whose payload is classified again on its own interface:
/// ARP, 802.1Q / 802.1ad VLAN tags, PPPoE discovery and session, LLDP, 802.1X
/// (EAPOL — some WANs authenticate the port with it), the slow protocols (LACP)
/// and MACsec. Everything else — MPLS, legacy protocols, anything unknown — is
/// dropped when the operator asked for fail-closed, and passes as before when
/// they did not.
#[inline(always)]
pub const fn ethertype_passes_unfiltered(ethertype: u16) -> bool {
    matches!(
        ethertype,
        0x0806 // ARP
            | 0x8100 // 802.1Q
            | 0x88a8 // 802.1ad
            | 0x8863 // PPPoE discovery
            | 0x8864 // PPPoE session
            | 0x88cc // LLDP
            | 0x888e // EAPOL
            | 0x8809 // slow protocols (LACP, marker)
            | 0x88e5 // MACsec
    )
}

/// Whether a stateful policy refuses a TCP or UDP datagram because it carries
/// IPv4 options (`ihl_bytes > 20`).
///
/// Connection tracking, the SYN proxy and NAT all require the fixed 20-byte
/// header, so such a datagram used to be handled statelessly — admitted by a
/// rule alone, past the SYN proxy and per-rule state (audit DP-34). No ordinary
/// TCP or UDP traffic carries IPv4 options (RFC 7126 recommends dropping
/// nearly all of them); IGMP's Router Alert and ICMP are not affected.
#[inline(always)]
pub const fn ipv4_options_refused(stateful: bool, proto: u8, ihl_bytes: usize) -> bool {
    stateful && (proto == ip_proto::TCP || proto == ip_proto::UDP) && ihl_bytes != 20
}

/// How a frame on a raw-IP link (WireGuard, PPP, an IP tunnel or XFRM) is laid
/// out, from its first 34 bytes and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawFraming {
    /// A bare IP packet: the classifier needs a temporary Ethernet header.
    Bare,
    /// The packet still carries a MAC header (XFRM keeps the one the ESP
    /// arrived in).
    Framed,
    /// Self-consistent read both ways. Only a crafted packet does this; it is
    /// refused rather than classified as one thing while the kernel sees the
    /// other.
    Ambiguous,
}

#[inline(always)]
fn ipv4_header_checksum_ok(h: &[u8; 34], at: usize) -> bool {
    let mut sum = 0u32;
    let mut i = 0;
    while i < 10 {
        sum += u16::from_be_bytes([h[at + 2 * i], h[at + 2 * i + 1]]) as u32;
        i += 1;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum == 0xffff
}

/// Classify a raw-IP link's frame (audit DP-36).
///
/// `head` is the first 34 bytes of the frame and `len` its length. Each reading
/// must be self-consistent to count: a bare IPv4 packet's total length is the
/// frame's and its header checksum verifies; a bare IPv6 packet's payload
/// length plus 40 is the frame's; a framed packet has an IP EtherType at
/// 12..14, the matching version at 14 and an IP length that accounts for the
/// rest of the frame (and, for IPv4, a valid header checksum). Reading only the
/// framed shape — what this replaced — took a bare IPv4 packet from
/// 8.0.64.0/12 whose destination's first two octets equal `len - 14` for a
/// framed one, and parsed a shifted header the kernel never saw.
#[inline(always)]
pub fn raw_ip_framing(head: &[u8; 34], len: usize) -> RawFraming {
    let bare = match head[0] >> 4 {
        4 => {
            head[0] & 0x0f == 5
                && u16::from_be_bytes([head[2], head[3]]) as usize == len
                && ipv4_header_checksum_ok(head, 0)
                || head[0] & 0x0f > 5 && u16::from_be_bytes([head[2], head[3]]) as usize == len
        }
        6 => u16::from_be_bytes([head[4], head[5]]) as usize + 40 == len,
        _ => false,
    };
    let framed = len >= 14
        && match (head[12], head[13], head[14] >> 4) {
            (0x08, 0x00, 4) => {
                u16::from_be_bytes([head[16], head[17]]) as usize == len - 14
                    && (head[14] & 0x0f != 5 || ipv4_header_checksum_ok(head, 14))
            }
            (0x86, 0xdd, 6) => u16::from_be_bytes([head[18], head[19]]) as usize + 40 == len - 14,
            _ => false,
        };
    match (bare, framed) {
        (_, false) => RawFraming::Bare,
        (false, true) => RawFraming::Framed,
        (true, true) => RawFraming::Ambiguous,
    }
}

/// Key for the `PORT_RULES` hash map: a `(protocol, destination port)` pair.
///
/// `#[repr(C)]` with an explicit padding byte makes the 4-byte layout identical
/// and fully-initialised on both sides — important because BPF hash-map lookups
/// compare the *whole* key including padding. `port` is stored in **host** byte
/// order; the data plane converts the on-wire big-endian port before lookup.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PortKey {
    /// IP protocol number (see [`ip_proto`]).
    pub proto: u8,
    /// Explicit padding, always zero, so the key has no uninitialised bytes.
    pub _pad: u8,
    /// Destination port in host byte order.
    pub port: u16,
}

impl PortKey {
    /// Build a key for the given protocol and (host-order) destination port.
    #[inline]
    pub const fn new(proto: u8, port: u16) -> Self {
        Self {
            proto,
            _pad: 0,
            port,
        }
    }
}

// SAFETY: `#[repr(C)]`, only integer fields, padding explicitly zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortKey {}

/// A policy/tenant identifier. Interface `0` is the default policy applied to
/// any interface without an explicit assignment, so a single-tenant deployment
/// (everything in policy `0`) behaves exactly as before.
pub type PolicyId = u32;

/// Key for the per-policy blocklist LPM trie: a policy id (matched exactly)
/// followed by an IPv4 prefix. Scoping the firewall by `policy_id` is what lets
/// one XDP program enforce a different policy per interface/tenant — the
/// foundation for multi-tenant VM networking and multi-firewall hosts.
///
/// Key for the source-MAC rule map: a policy and a hardware address.
///
/// A hash map rather than a trie, and its own map rather than a dimension on the
/// firewall keys, for one reason: the rule tries are consulted twice per packet
/// already, and a fifth lookup on that merge is what the verifier refuses. This
/// is consulted **once**, from the Ethernet header, exactly as the blocklist is —
/// which is also why a MAC rule is a verdict on its own rather than something
/// that combines with a port.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedMac {
    /// Policy id.
    pub policy_id: PolicyId,
    /// The source hardware address, as it sits on the wire.
    pub mac: [u8; 6],
    /// Explicit padding, always zero — a hash map compares the whole key, so a
    /// struct with a hole in it would compare uninitialised bytes.
    pub _pad: [u8; 2],
}

impl ScopedMac {
    #[inline]
    pub const fn new(policy_id: PolicyId, mac: [u8; 6]) -> Self {
        Self {
            policy_id,
            mac,
            _pad: [0; 2],
        }
    }
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedMac {}

/// The kernel LPM trie walks the key bytes from the start, so `policy_id` (at
/// offset 0) is consumed first by its 32 prefix bits, then the address prefix —
/// see [`ScopedAddr::POLICY_BITS`].
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedAddr {
    /// Policy id, matched exactly (the first [`Self::POLICY_BITS`] prefix bits).
    pub policy_id: PolicyId,
    /// IPv4 address in [`lpm_key_addr`] form.
    pub addr: u32,
}

impl ScopedAddr {
    /// Prefix bits that cover the (exactly-matched) policy id.
    pub const POLICY_BITS: u32 = 32;

    /// Build a scoped address from a policy id and an `lpm_key_addr` value.
    #[inline]
    pub const fn new(policy_id: PolicyId, addr: u32) -> Self {
        Self { policy_id, addr }
    }

    /// The LPM prefix length to insert a `/cidr_bits` route in this policy.
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::POLICY_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for an exact (`/32`) lookup.
    pub const FULL_PREFIX: u32 = Self::POLICY_BITS + 32;
}

// SAFETY: `#[repr(C)]`, two `u32`s, no padding — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedAddr {}

/// Key for the per-policy `(proto, dst_port)` rule map: a [`PortKey`] scoped by
/// policy id.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedPortKey {
    /// Policy id.
    pub policy_id: PolicyId,
    /// IP protocol number.
    pub proto: u8,
    /// Explicit padding, always zero.
    pub _pad: u8,
    /// Destination port, host byte order.
    pub port: u16,
}

impl ScopedPortKey {
    /// Build a scoped port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16) -> Self {
        Self {
            policy_id,
            proto,
            _pad: 0,
            port,
        }
    }
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedPortKey {}

/// Key for the per-policy firewall-rule LPM trie: a `(proto, dst_port)` scoped by
/// policy id, plus a **source address prefix** matched longest-first.
///
/// The kernel LPM trie walks the key bytes from offset 0, so the fixed head —
/// `policy_id`, `proto`, `_pad`, `port` (the first [`Self::FIXED_BITS`] bits) — is
/// always matched in full (every entry and every lookup carry all of it), and the
/// trailing [`src`](Self::src) is the only variable-length part. That gives the
/// firewall the natural precedence: a rule with a more specific source wins over a
/// `from any` rule on the same port. A rule with **no** source constraint is stored
/// as a `/0` source (prefix == `FIXED_BITS`), which matches every packet.
///
/// `src` is a [`lpm_key_addr`] value so its in-memory bytes are network order,
/// exactly like [`ScopedAddr::addr`].
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedSrcPortKey {
    /// Policy id, matched exactly.
    pub policy_id: PolicyId,
    /// IP protocol number.
    pub proto: u8,
    /// The ICMP type this rule matches, or `0` for "any type" — and for every
    /// protocol that has no types at all, which is why it is exactly the byte
    /// that used to be padding. It sits inside the exactly-matched head, so a
    /// typed rule and an untyped one are different entries in the same trie and
    /// no key grew by a byte to get here.
    ///
    /// A lookup therefore asks twice on the ICMP path: once with the packet's
    /// own type, once with `0`. The first that answers wins, which is what makes
    /// `icmp type echo-request` beat a plain `icmp` rule.
    pub icmp_type: u8,
    /// Destination port, host byte order.
    pub port: u16,
    /// The interface this rule is scoped to, or `0` for "any interface".
    ///
    /// In the exactly-matched head, so a rule scoped to one link is a different
    /// entry from one that is not — and a lookup therefore asks twice, with this
    /// packet's own ifindex and then with `0`. That is the same shape the ICMP
    /// type uses, and the reason is the same: an LPM prefix is contiguous from
    /// byte zero, so a wildcard cannot sit in the middle of a key.
    pub ifindex: u32,
    /// Source address in [`lpm_key_addr`] form, matched longest-prefix.
    pub src: u32,
}

/// The key encoding for a rule's ICMP-type constraint.
///
/// `0` in the key means "every type", which is also what a rule naming no type
/// at all compiles to — so a *named* type is stored one higher. Without that
/// bias, `icmp-type echo-reply` (type **0**) was indistinguishable from "any
/// ICMP": a rule written to admit ping *answers* admitted ping itself, and every
/// other ICMP message with it. A rule that matches more than it says is worse
/// than a rule that was refused.
///
/// The cost is type 255, which is reserved and has never been assignable.
#[inline]
pub const fn icmp_type_key(constraint: Option<u8>) -> u8 {
    match constraint {
        Some(t) => t.wrapping_add(1),
        None => 0,
    }
}

/// The value a lookup probes with for a packet carrying ICMP type `t`. The
/// counterpart of [`icmp_type_key`]: the data plane asks once with this, then
/// once with `0`, so a typed rule beats an untyped one.
#[inline]
pub const fn icmp_type_probe(t: u8) -> u8 {
    t.wrapping_add(1)
}

/// The conntrack "port" a flow key carries for an ICMP packet of probed type
/// `probe` (see [`icmp_type_probe`]), and the one its **answer** will carry.
///
/// ICMP has no ports, so a flow key that leaves them zero cannot tell a reply
/// from a fresh request: after the box pings a host, that host could ping back
/// and be admitted by the entry — including where `block-icmp` says otherwise.
/// Carrying the type instead makes the entry name what it is waiting for, so
/// only the echo *reply* to an echo request we sent matches.
///
/// Types with no reply keep their own value: the entry then admits the same
/// type back, which is what a symmetric exchange (an unsolicited error, say)
/// needs, and nothing else.
#[inline]
pub const fn icmp_reply_probe(probe: u8) -> u8 {
    match probe {
        // Probed values are `type + 1`: echo request 8 → 9, echo reply 0 → 1.
        9 => 1,   // echo request → echo reply
        14 => 15, // timestamp → timestamp reply
        16 => 17, // information request → information reply
        18 => 19, // address mask request → address mask reply
        other => other,
    }
}

impl ScopedSrcPortKey {
    /// Prefix bits covering the exactly-matched head (`policy_id` + `proto` +
    /// `_pad` + `port` = 32 + 8 + 8 + 16).
    pub const FIXED_BITS: u32 = 96;

    /// Build a scoped source/port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16, src: u32) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type: 0,
            ifindex: 0,
            port,
            src,
        }
    }

    /// The same key for a rule that names an ICMP type. `port` stays `0`:
    /// ICMP has no ports, and keeping the two fields separate means a typed
    /// rule cannot be confused with a port rule that happens to share a number.
    #[inline]
    pub const fn with_icmp_type(policy_id: PolicyId, proto: u8, icmp_type: u8, src: u32) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex: 0,
            port: 0,
            src,
        }
    }

    /// The same key, scoped to one interface. `0` means every interface, which
    /// is what a rule that names none has always meant — so an unscoped rule and
    /// a scoped one are different entries, and a lookup asks for both.
    #[inline]
    pub const fn with_ifindex(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        port: u16,
        ifindex: u32,
        src: u32,
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex,
            port,
            src,
        }
    }

    /// The LPM prefix length for a rule whose source is a `/cidr_bits` block
    /// (`cidr_bits == 0` for `from any`).
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::FIXED_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for a lookup (all source bits known).
    pub const FULL_PREFIX: u32 = Self::FIXED_BITS + 32;
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedSrcPortKey {}

/// Key for the IPv6 firewall-rule LPM tries: the same fixed
/// `(policy, proto, port)` head as [`ScopedSrcPortKey`], with a **128-bit**
/// address as the longest-prefix-matched tail.
///
/// A separate key (and a separate map) rather than a widened one: an LPM trie
/// walks the key from byte zero, so a v4 rule and a v6 rule cannot share a trie
/// without one of them carrying dead bits that every lookup would still have to
/// match. Two tries also keep the v4 path's key — and its stack use inside the
/// XDP program — exactly as it was.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedSrcPortKey6 {
    /// Policy id, matched exactly.
    pub policy_id: PolicyId,
    /// IP protocol number (the upper-layer one, after the extension chain).
    pub proto: u8,
    /// The ICMP type this rule matches, or `0` for "any type" — and for every
    /// protocol that has no types at all, which is why it is exactly the byte
    /// that used to be padding. It sits inside the exactly-matched head, so a
    /// typed rule and an untyped one are different entries in the same trie and
    /// no key grew by a byte to get here.
    ///
    /// A lookup therefore asks twice on the ICMP path: once with the packet's
    /// own type, once with `0`. The first that answers wins, which is what makes
    /// `icmp type echo-request` beat a plain `icmp` rule.
    pub icmp_type: u8,
    /// Destination port, host byte order.
    pub port: u16,
    /// The interface this rule is scoped to, or `0` for "any interface".
    ///
    /// In the exactly-matched head, so a rule scoped to one link is a different
    /// entry from one that is not — and a lookup therefore asks twice, with this
    /// packet's own ifindex and then with `0`. That is the same shape the ICMP
    /// type uses, and the reason is the same: an LPM prefix is contiguous from
    /// byte zero, so a wildcard cannot sit in the middle of a key.
    pub ifindex: u32,
    /// Source address, network-order octets, matched longest-prefix.
    pub src: [u8; 16],
}

impl ScopedSrcPortKey6 {
    /// Prefix bits covering the exactly-matched head, as for the v4 key.
    pub const FIXED_BITS: u32 = 96;

    /// Build a scoped IPv6 source/port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16, src: [u8; 16]) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type: 0,
            ifindex: 0,
            port,
            src,
        }
    }

    /// The same key for a rule that names an ICMP type. `port` stays `0`:
    /// ICMP has no ports, and keeping the two fields separate means a typed
    /// rule cannot be confused with a port rule that happens to share a number.
    #[inline]
    pub const fn with_icmp_type(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        src: [u8; 16],
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex: 0,
            port: 0,
            src,
        }
    }

    /// The same key, scoped to one interface. `0` means every interface, which
    /// is what a rule that names none has always meant — so an unscoped rule and
    /// a scoped one are different entries, and a lookup asks for both.
    #[inline]
    pub const fn with_ifindex(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        port: u16,
        ifindex: u32,
        src: [u8; 16],
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex,
            port,
            src,
        }
    }

    /// The LPM prefix length for a rule whose source is a `/cidr_bits` block
    /// (`0` for "from any").
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::FIXED_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for a lookup (every source bit known).
    pub const FULL_PREFIX: u32 = Self::FIXED_BITS + 128;
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedSrcPortKey6 {}

/// The destination counterpart of [`ScopedSrcPortKey6`], for the same reason the
/// v4 path has two tries: one trie ranks exactly one address field.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedDstPortKey6 {
    /// Policy id, matched exactly.
    pub policy_id: PolicyId,
    /// IP protocol number.
    pub proto: u8,
    /// The ICMP type this rule matches, or `0` for "any type" — and for every
    /// protocol that has no types at all, which is why it is exactly the byte
    /// that used to be padding. It sits inside the exactly-matched head, so a
    /// typed rule and an untyped one are different entries in the same trie and
    /// no key grew by a byte to get here.
    ///
    /// A lookup therefore asks twice on the ICMP path: once with the packet's
    /// own type, once with `0`. The first that answers wins, which is what makes
    /// `icmp type echo-request` beat a plain `icmp` rule.
    pub icmp_type: u8,
    /// Destination port, host byte order.
    pub port: u16,
    /// The interface this rule is scoped to, or `0` for "any interface".
    ///
    /// In the exactly-matched head, so a rule scoped to one link is a different
    /// entry from one that is not — and a lookup therefore asks twice, with this
    /// packet's own ifindex and then with `0`. That is the same shape the ICMP
    /// type uses, and the reason is the same: an LPM prefix is contiguous from
    /// byte zero, so a wildcard cannot sit in the middle of a key.
    pub ifindex: u32,
    /// Destination address, network-order octets, matched longest-prefix.
    pub dst: [u8; 16],
}

impl ScopedDstPortKey6 {
    /// Prefix bits covering the exactly-matched head.
    pub const FIXED_BITS: u32 = 96;

    /// Build a scoped IPv6 destination/port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16, dst: [u8; 16]) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type: 0,
            ifindex: 0,
            port,
            dst,
        }
    }

    /// The same key for a rule that names an ICMP type. `port` stays `0`:
    /// ICMP has no ports, and keeping the two fields separate means a typed
    /// rule cannot be confused with a port rule that happens to share a number.
    #[inline]
    pub const fn with_icmp_type(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        dst: [u8; 16],
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex: 0,
            port: 0,
            dst,
        }
    }

    /// The same key, scoped to one interface. `0` means every interface, which
    /// is what a rule that names none has always meant — so an unscoped rule and
    /// a scoped one are different entries, and a lookup asks for both.
    #[inline]
    pub const fn with_ifindex(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        port: u16,
        ifindex: u32,
        dst: [u8; 16],
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex,
            port,
            dst,
        }
    }

    /// The LPM prefix length for a rule whose destination is a `/cidr_bits` block.
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::FIXED_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for a lookup.
    pub const FULL_PREFIX: u32 = Self::FIXED_BITS + 128;
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedDstPortKey6 {}

/// Key for the `DST_RULES` LPM trie: the mirror of [`ScopedSrcPortKey`] with the
/// **destination** address as the longest-prefix-matched tail.
///
/// A second trie rather than a second dimension of the first: an LPM prefix is
/// contiguous from the front of the key, so one trie can rank exactly one address
/// field. Constraining a destination in the source trie would require every
/// source bit to be fixed first, which would break every existing `from any` rule.
/// A rule therefore constrains a source or a destination, never both, and the two
/// tries hold disjoint rule sets ranked against each other by the prefix length
/// packed into the value (`port_rule_bits`).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedDstPortKey {
    /// Policy id, matched exactly.
    pub policy_id: PolicyId,
    /// IP protocol number.
    pub proto: u8,
    /// The ICMP type this rule matches, or `0` for "any type" — and for every
    /// protocol that has no types at all, which is why it is exactly the byte
    /// that used to be padding. It sits inside the exactly-matched head, so a
    /// typed rule and an untyped one are different entries in the same trie and
    /// no key grew by a byte to get here.
    ///
    /// A lookup therefore asks twice on the ICMP path: once with the packet's
    /// own type, once with `0`. The first that answers wins, which is what makes
    /// `icmp type echo-request` beat a plain `icmp` rule.
    pub icmp_type: u8,
    /// Destination port, host byte order.
    pub port: u16,
    /// The interface this rule is scoped to, or `0` for "any interface".
    ///
    /// In the exactly-matched head, so a rule scoped to one link is a different
    /// entry from one that is not — and a lookup therefore asks twice, with this
    /// packet's own ifindex and then with `0`. That is the same shape the ICMP
    /// type uses, and the reason is the same: an LPM prefix is contiguous from
    /// byte zero, so a wildcard cannot sit in the middle of a key.
    pub ifindex: u32,
    /// Destination address in [`lpm_key_addr`] form, matched longest-prefix.
    pub dst: u32,
}

impl ScopedDstPortKey {
    /// Prefix bits covering the exactly-matched head (`policy_id` + `proto` +
    /// `_pad` + `port` = 32 + 8 + 8 + 16).
    pub const FIXED_BITS: u32 = 96;

    /// Build a scoped destination/port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16, dst: u32) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type: 0,
            ifindex: 0,
            port,
            dst,
        }
    }

    /// The same key for a rule that names an ICMP type. `port` stays `0`:
    /// ICMP has no ports, and keeping the two fields separate means a typed
    /// rule cannot be confused with a port rule that happens to share a number.
    #[inline]
    pub const fn with_icmp_type(policy_id: PolicyId, proto: u8, icmp_type: u8, dst: u32) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex: 0,
            port: 0,
            dst,
        }
    }

    /// The same key, scoped to one interface. `0` means every interface, which
    /// is what a rule that names none has always meant — so an unscoped rule and
    /// a scoped one are different entries, and a lookup asks for both.
    #[inline]
    pub const fn with_ifindex(
        policy_id: PolicyId,
        proto: u8,
        icmp_type: u8,
        port: u16,
        ifindex: u32,
        dst: u32,
    ) -> Self {
        Self {
            policy_id,
            proto,
            icmp_type,
            ifindex,
            port,
            dst,
        }
    }

    /// The LPM prefix length for a rule whose destination is a `/cidr_bits` block.
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::FIXED_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for a lookup (all destination bits known).
    pub const FULL_PREFIX: u32 = Self::FIXED_BITS + 32;
}

// SAFETY: `#[repr(C)]`, integer fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedDstPortKey {}

/// Per-policy IPv6 blocklist LPM key: a policy id (matched exactly) followed by
/// an IPv6 address prefix. IPv6 octets are already network-order (most
/// significant first), so they need no `lpm_key_addr`-style transform.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct ScopedAddr6 {
    /// Policy id, matched exactly (the first [`Self::POLICY_BITS`] prefix bits).
    pub policy_id: PolicyId,
    /// IPv6 address, network-order octets.
    pub addr: [u8; 16],
}

impl ScopedAddr6 {
    /// Prefix bits that cover the (exactly-matched) policy id.
    pub const POLICY_BITS: u32 = 32;

    /// Build a scoped IPv6 address.
    #[inline]
    pub const fn new(policy_id: PolicyId, addr: [u8; 16]) -> Self {
        Self { policy_id, addr }
    }

    /// The LPM prefix length to insert a `/cidr_bits` IPv6 prefix in a policy.
    #[inline]
    pub const fn prefix_len(cidr_bits: u8) -> u32 {
        Self::POLICY_BITS + cidr_bits as u32
    }

    /// The LPM prefix length for an exact (`/128`) lookup.
    pub const FULL_PREFIX: u32 = Self::POLICY_BITS + 128;
}

// SAFETY: `#[repr(C)]`, `u32` + `[u8; 16]`, no padding — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for ScopedAddr6 {}

/// Convert IPv4 octets into the `u32` key used by the kernel LPM trie
/// (`BLOCKLIST`).
///
/// The kernel `LPM_TRIE` map matches a prefix against the **raw byte order** of
/// the key's data, walking from the first byte (the most-significant network
/// octet). The key therefore has to be a `u32` whose *in-memory* representation
/// equals the network-order octets `a.b.c.d`. On little-endian hosts — x86-64
/// and aarch64, the only architectures where XDP is deployed in practice —
/// `u32::from_le_bytes` produces exactly that.
///
/// Crucially, the data plane reads the packet's source address as four bytes
/// and calls this very function, so the user-space inserts and the kernel
/// lookups use an identical representation.
#[inline]
pub const fn lpm_key_addr(octets: [u8; 4]) -> u32 {
    u32::from_le_bytes(octets)
}

/// Normalised, decoded view of the packet fields the firewall needs.
///
/// Produced by both the safe reference parser ([`crate::parse::parse_frame`])
/// and the kernel's pointer-based parser, then handed to [`crate::decide`].
/// Addresses stay as raw network-order octets (no host conversion needed for
/// blocklist lookups); ports are normalised to host order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PacketMeta {
    /// Source IPv4 address, network-order octets `a.b.c.d`.
    pub src_addr: [u8; 4],
    /// Destination IPv4 address, network-order octets.
    pub dst_addr: [u8; 4],
    /// IP protocol number (see [`ip_proto`]).
    pub proto: u8,
    /// Source port in host byte order, or `0` for protocols without ports.
    pub src_port: u16,
    /// Destination port in host byte order, or `0` for protocols without ports.
    pub dst_port: u16,
    /// IPv4 total length field (header + payload) in bytes.
    pub total_len: u16,
}

impl PacketMeta {
    /// Construct a [`PacketMeta`]. Mostly used by tests and the parsers.
    #[inline]
    pub const fn new(
        src_addr: [u8; 4],
        dst_addr: [u8; 4],
        proto: u8,
        src_port: u16,
        dst_port: u16,
        total_len: u16,
    ) -> Self {
        Self {
            src_addr,
            dst_addr,
            proto,
            src_port,
            dst_port,
            total_len,
        }
    }

    /// The `(proto, dst_port)` key for a `PORT_RULES` lookup.
    #[inline]
    pub const fn port_key(&self) -> PortKey {
        PortKey::new(self.proto, self.dst_port)
    }

    /// The source address as an LPM trie key for a `BLOCKLIST` lookup.
    #[inline]
    pub const fn blocklist_key(&self) -> u32 {
        lpm_key_addr(self.src_addr)
    }
}

/// What a tenant port is allowed to *be*.
///
/// uRPF (source validation) already asks whether a source address is routable
/// back out of the interface it arrived on. That is a different question from
/// the one multi-tenancy needs answered: two guests on the same subnet both pass
/// uRPF while impersonating each other, because both addresses are perfectly
/// routable there. This binds a port to the identity it was given.
///
/// Keyed by **ingress ifindex** — the tap — because that is the one thing a
/// guest cannot forge. Everything else in the frame is under its control.
///
/// The MAC lives here rather than in a second map so the common case is one
/// lookup: a frame whose port has no binding misses once and pays nothing more.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PortBinding {
    /// The only source hardware address this port may use.
    pub mac: [u8; 6],
    /// Which halves are enforced. A port may have a MAC binding and no address
    /// binding — during a migration, or before IPAM has assigned one — and
    /// enforcing addresses that were never assigned would black-hole the guest
    /// rather than protect anybody from it.
    pub flags: u8,
    /// Explicit padding, always zero: a hash map compares the whole value.
    pub _pad: u8,
}

/// Enforce the source MAC on this port.
pub const PORT_ENFORCE_MAC: u8 = 1 << 0;
/// Enforce the source IPv4 against [`PortAddr4`].
pub const PORT_ENFORCE_V4: u8 = 1 << 1;
/// Enforce the source IPv6 against [`PortAddr6`].
pub const PORT_ENFORCE_V6: u8 = 1 << 2;

impl PortBinding {
    #[inline]
    pub const fn new(mac: [u8; 6], flags: u8) -> Self {
        Self {
            mac,
            flags,
            _pad: 0,
        }
    }

    #[inline]
    pub const fn enforces(&self, what: u8) -> bool {
        self.flags & what != 0
    }
}

/// An address a port is allowed to send from: `(ifindex, address)`.
///
/// A set rather than a single value because one port legitimately has several —
/// an IPv4, a link-local, a floating address that was just attached — and a
/// binding that held only one would break the moment a second was assigned.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PortAddr4 {
    pub ifindex: u32,
    /// Network byte order, exactly as it sits in the header.
    pub addr: u32,
}

impl PortAddr4 {
    #[inline]
    pub const fn new(ifindex: u32, addr: u32) -> Self {
        Self { ifindex, addr }
    }
}

/// The IPv6 half of [`PortAddr4`].
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PortAddr6 {
    pub ifindex: u32,
    /// Explicit padding, always zero, so the 16-byte address is aligned and the
    /// key has no hole in it to compare.
    pub _pad: [u8; 4],
    pub addr: [u8; 16],
}

impl PortAddr6 {
    #[inline]
    pub const fn new(ifindex: u32, addr: [u8; 16]) -> Self {
        Self {
            ifindex,
            _pad: [0; 4],
            addr,
        }
    }
}

// SAFETY: `#[repr(C)]`, integer/byte fields, padding zeroed — POD.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortBinding {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortAddr4 {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortAddr6 {}

#[cfg(test)]
mod tests {
    use super::{RawFraming, ethertype_passes_unfiltered, ipv4_options_refused, raw_ip_framing};

    fn ipv4(src: [u8; 4], dst: [u8; 4], total: u16) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h[8] = 64;
        h[9] = 17;
        h[12..16].copy_from_slice(&src);
        h[16..20].copy_from_slice(&dst);
        let csum = crate::ipv4_checksum(&h);
        h[10..12].copy_from_slice(&csum.to_be_bytes());
        h
    }

    fn head_of(frame: &[u8]) -> [u8; 34] {
        let mut head = [0u8; 34];
        head.copy_from_slice(&frame[..34]);
        head
    }

    /// The DP-36 case: a bare IPv4 packet from 8.0.64.0/12 whose destination's
    /// first two octets equal `len - 14` read as a framed one before.
    #[test]
    fn a_bare_packet_shaped_like_a_framed_one_is_still_bare() {
        let len = 1500usize;
        let dst = [((len - 14) >> 8) as u8, (len - 14) as u8, 1, 2];
        let mut frame = vec![0u8; len];
        frame[..20].copy_from_slice(&ipv4([8, 0, 0x45, 9], dst, len as u16));
        assert_eq!(raw_ip_framing(&head_of(&frame), len), RawFraming::Bare);
    }

    #[test]
    fn an_xfrm_frame_with_its_mac_header_is_framed() {
        let len = 14 + 84;
        let mut frame = vec![0u8; len];
        frame[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14..34].copy_from_slice(&ipv4([10, 1, 0, 2], [10, 2, 0, 1], 84));
        assert_eq!(raw_ip_framing(&head_of(&frame), len), RawFraming::Framed);
        let mut v6 = vec![0u8; 14 + 40 + 16];
        v6[12..14].copy_from_slice(&[0x86, 0xdd]);
        v6[14] = 0x60;
        v6[18..20].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(raw_ip_framing(&head_of(&v6), v6.len()), RawFraming::Framed);
    }

    #[test]
    fn bare_packets_of_both_families_are_bare() {
        let mut v4 = vec![0u8; 60];
        v4[..20].copy_from_slice(&ipv4([192, 0, 2, 1], [198, 51, 100, 7], 60));
        assert_eq!(raw_ip_framing(&head_of(&v4), 60), RawFraming::Bare);
        let mut v6 = vec![0u8; 40 + 20];
        v6[0] = 0x60;
        v6[4..6].copy_from_slice(&20u16.to_be_bytes());
        assert_eq!(raw_ip_framing(&head_of(&v6), 60), RawFraming::Bare);
    }

    /// Both readings self-consistent: only a crafted packet manages it, and it
    /// is refused rather than guessed at.
    #[test]
    fn a_packet_consistent_both_ways_is_ambiguous() {
        let len = 14 + 40;
        let mut frame = vec![0u8; len];
        // Bare IPv6 header whose source bytes also spell a framed IPv6 one.
        frame[0] = 0x60;
        frame[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        frame[12..14].copy_from_slice(&[0x86, 0xdd]);
        frame[14] = 0x60;
        frame[18..20].copy_from_slice(&((len - 14 - 40) as u16).to_be_bytes());
        assert_eq!(raw_ip_framing(&head_of(&frame), len), RawFraming::Ambiguous);
    }

    #[test]
    fn fail_closed_admits_only_link_control_ethertypes() {
        for kept in [
            0x0806u16, 0x8100, 0x88a8, 0x8863, 0x8864, 0x88cc, 0x888e, 0x8809, 0x88e5,
        ] {
            assert!(ethertype_passes_unfiltered(kept), "{kept:#06x}");
        }
        for refused in [0x8847u16, 0x8848, 0x8137, 0x809b, 0x88f7, 0x0000, 0xffff] {
            assert!(!ethertype_passes_unfiltered(refused), "{refused:#06x}");
        }
    }

    #[test]
    fn stateful_policies_refuse_tcp_and_udp_with_ipv4_options() {
        assert!(ipv4_options_refused(true, 6, 24));
        assert!(ipv4_options_refused(true, 17, 60));
        assert!(!ipv4_options_refused(true, 6, 20));
        // Not stateful: nothing depends on the fixed header.
        assert!(!ipv4_options_refused(false, 6, 24));
        // ICMP (ping -R) and IGMP (Router Alert) keep their options.
        assert!(!ipv4_options_refused(true, 1, 24));
        assert!(!ipv4_options_refused(true, 2, 24));
    }

    /// An ICMP conntrack entry has to name the answer it is waiting for.
    ///
    /// With the type left out of the key, a host this box pinged could ping it
    /// back through the same entry — past a `block-icmp` that says otherwise.
    #[test]
    fn an_icmp_entry_expects_the_reply_and_not_another_request() {
        // Probed values are `type + 1` (see `icmp_type_probe`).
        assert_eq!(icmp_reply_probe(icmp_type_probe(8)), icmp_type_probe(0));
        // And what it waits for is not another request: that is the whole
        // point — a host we pinged cannot ping us back through this entry.
        assert_ne!(icmp_reply_probe(icmp_type_probe(8)), icmp_type_probe(8));
        // The request/reply pairs that have one.
        assert_eq!(icmp_reply_probe(icmp_type_probe(13)), icmp_type_probe(14));
        assert_eq!(icmp_reply_probe(icmp_type_probe(15)), icmp_type_probe(16));
        assert_eq!(icmp_reply_probe(icmp_type_probe(17)), icmp_type_probe(18));
        // A type with no reply keeps its own, so a symmetric exchange still
        // works and nothing else is admitted.
        assert_eq!(icmp_reply_probe(icmp_type_probe(3)), icmp_type_probe(3));
    }

    use super::*;

    #[test]
    fn ipv6_ext_headers_are_classified_and_measured() {
        // Walkable extension headers.
        for p in [
            ip_proto::HOPOPT,
            ip_proto::ROUTING,
            ip_proto::FRAGMENT,
            ip_proto::AH,
            ip_proto::DSTOPTS,
            ip_proto::MOBILITY,
            ip_proto::HIP,
            ip_proto::SHIM6,
        ] {
            assert!(is_ipv6_ext(p), "{p} should be walkable");
        }
        // Upper-layer protocols end the walk.
        for p in [
            ip_proto::TCP,
            ip_proto::UDP,
            ip_proto::ICMPV6,
            ip_proto::ICMP,
        ] {
            assert!(!is_ipv6_ext(p), "{p} is upper layer, not an ext header");
        }
        // ESP hides what follows and NO_NEXT_HEADER ends the chain: both must stop
        // the walk rather than be treated as skippable.
        assert!(!is_ipv6_ext(ip_proto::ESP));
        assert!(!is_ipv6_ext(ip_proto::NO_NEXT_HEADER));

        // The common headers count 8-byte units excluding the first 8.
        assert_eq!(ipv6_ext_len(ip_proto::HOPOPT, 0), 8);
        assert_eq!(ipv6_ext_len(ip_proto::DSTOPTS, 1), 16);
        assert_eq!(ipv6_ext_len(ip_proto::ROUTING, 3), 32);
        // The Fragment header is a fixed 8 bytes; its second byte is reserved, so
        // a non-zero value there must not change the length.
        assert_eq!(ipv6_ext_len(ip_proto::FRAGMENT, 0), 8);
        assert_eq!(ipv6_ext_len(ip_proto::FRAGMENT, 0xff), 8);
        // The Authentication Header counts 4-byte units excluding the first 8.
        assert_eq!(ipv6_ext_len(ip_proto::AH, 1), 12);
        assert_eq!(ipv6_ext_len(ip_proto::AH, 4), 24);
        // A non-extension header has no extension length.
        assert_eq!(ipv6_ext_len(ip_proto::TCP, 9), 0);
        assert_eq!(ipv6_ext_len(ip_proto::ESP, 9), 0);

        // The largest header the length byte can describe still fits the bound the
        // data plane clamps its walk to (see MAX_EXT_CHAIN_LEN there).
        assert_eq!(ipv6_ext_len(ip_proto::HOPOPT, u8::MAX), 2048);
        assert_eq!(ipv6_ext_len(ip_proto::AH, u8::MAX), 1028);
    }

    #[test]
    fn port_key_is_four_bytes_no_uninit() {
        assert_eq!(core::mem::size_of::<PortKey>(), 4);
        let k = PortKey::new(ip_proto::TCP, 22);
        assert_eq!(k.proto, ip_proto::TCP);
        assert_eq!(k._pad, 0);
        assert_eq!(k.port, 22);
    }

    #[test]
    fn lpm_key_is_network_order_in_memory() {
        // 10.0.0.1 must serialise to bytes [10, 0, 0, 1] in memory so the trie
        // walks the most-significant octet (10) first.
        let key = lpm_key_addr([10, 0, 0, 1]);
        assert_eq!(key.to_le_bytes(), [10, 0, 0, 1]);
    }

    #[test]
    fn scoped_keys_layout_and_prefixes() {
        assert_eq!(core::mem::size_of::<ScopedAddr>(), 8);
        assert_eq!(core::mem::size_of::<ScopedPortKey>(), 8);
        // A /24 in a policy matches 32 (policy) + 24 (address) = 56 bits.
        assert_eq!(ScopedAddr::prefix_len(24), 56);
        assert_eq!(ScopedAddr::FULL_PREFIX, 64);
        let k = ScopedPortKey::new(7, ip_proto::TCP, 22);
        assert_eq!(
            (k.policy_id, k.proto, k.port, k._pad),
            (7, ip_proto::TCP, 22, 0)
        );
    }

    #[test]
    fn meta_derives_keys() {
        let m = PacketMeta::new([192, 168, 1, 9], [10, 0, 0, 1], ip_proto::UDP, 5353, 53, 48);
        assert_eq!(m.port_key(), PortKey::new(ip_proto::UDP, 53));
        assert_eq!(m.blocklist_key(), lpm_key_addr([192, 168, 1, 9]));
    }
}
