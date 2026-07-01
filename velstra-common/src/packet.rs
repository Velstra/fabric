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
}

/// EtherType for IPv4, in **host** byte order. Compare against the value read
/// from the frame *after* a `u16::from_be`.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6, in host byte order.
pub const ETHERTYPE_IPV6: u16 = 0x86DD;

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
    /// Explicit padding, always zero.
    pub _pad: u8,
    /// Destination port, host byte order.
    pub port: u16,
    /// Source address in [`lpm_key_addr`] form, matched longest-prefix.
    pub src: u32,
}

impl ScopedSrcPortKey {
    /// Prefix bits covering the exactly-matched head (`policy_id` + `proto` +
    /// `_pad` + `port` = 32 + 8 + 8 + 16).
    pub const FIXED_BITS: u32 = 64;

    /// Build a scoped source/port key.
    #[inline]
    pub const fn new(policy_id: PolicyId, proto: u8, port: u16, src: u32) -> Self {
        Self {
            policy_id,
            proto,
            _pad: 0,
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

#[cfg(test)]
mod tests {
    use super::*;

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
