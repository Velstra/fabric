//! Minimal, dependency-free IPv4 CIDR parsing for the blocklist.
//!
//! Lives in the shared crate (rather than the control plane) so it is `no_std`,
//! reuses [`core::net::Ipv4Addr`], and is unit tested alongside the rest of the
//! policy logic.

use core::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

/// A parsed IPv4 CIDR block, normalised so host bits below the prefix are zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cidr4 {
    /// Network address octets, with host bits masked off.
    pub octets: [u8; 4],
    /// Prefix length in bits, `0..=32`.
    pub prefix: u8,
}

impl Cidr4 {
    /// The blocklist LPM key (`prefix`, `data`) for this block. `data` is the
    /// network address as a [`crate::lpm_key_addr`] value.
    #[inline]
    pub const fn lpm_key(&self) -> (u32, u32) {
        (self.prefix as u32, crate::lpm_key_addr(self.octets))
    }
}

impl fmt::Display for Cidr4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets;
        write!(f, "{a}.{b}.{c}.{d}/{}", self.prefix)
    }
}

/// Why [`parse_cidr_v4`] rejected an input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CidrError {
    /// The address part was not a valid dotted-quad IPv4 address.
    BadAddress,
    /// The prefix after `/` was not a number.
    BadPrefix,
    /// The prefix was greater than 32.
    PrefixTooLong,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            CidrError::BadAddress => "invalid IPv4 address",
            CidrError::BadPrefix => "invalid CIDR prefix",
            CidrError::PrefixTooLong => "CIDR prefix must be 0..=32",
        };
        f.write_str(msg)
    }
}

// `core::error::Error` is available even in `no_std`, and `std` re-exports the
// very same trait, so this also satisfies `anyhow`/`?` in the control plane.
impl core::error::Error for CidrError {}

/// Mask off the host bits of `octets` below `prefix`.
///
/// `prefix` is clamped to `0..=32`; a prefix of `0` yields `0.0.0.0`.
#[inline]
pub const fn mask_v4(octets: [u8; 4], prefix: u8) -> [u8; 4] {
    let bits = u32::from_be_bytes(octets);
    // A shift of 32 is undefined, so special-case the /0 catch-all.
    let mask = if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    (bits & mask).to_be_bytes()
}

/// Parse a `"a.b.c.d"` or `"a.b.c.d/prefix"` string into a normalised
/// [`Cidr4`]. A bare address is treated as a `/32` host route.
///
/// ```
/// use velstra_common::parse_cidr_v4;
/// let c = parse_cidr_v4("10.20.30.40/24").unwrap();
/// assert_eq!(c.octets, [10, 20, 30, 0]); // host bits masked
/// assert_eq!(c.prefix, 24);
/// assert_eq!(parse_cidr_v4("1.2.3.4").unwrap().prefix, 32);
/// ```
pub fn parse_cidr_v4(input: &str) -> Result<Cidr4, CidrError> {
    let (addr_str, prefix) = match input.split_once('/') {
        Some((addr, pfx)) => {
            let prefix: u8 = pfx.parse().map_err(|_| CidrError::BadPrefix)?;
            (addr, prefix)
        }
        None => (input, 32u8),
    };

    if prefix > 32 {
        return Err(CidrError::PrefixTooLong);
    }
    let addr: Ipv4Addr = addr_str.parse().map_err(|_| CidrError::BadAddress)?;
    Ok(Cidr4 {
        octets: mask_v4(addr.octets(), prefix),
        prefix,
    })
}

/// A parsed IPv6 CIDR block, normalised so host bits below the prefix are zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cidr6 {
    /// Network address octets (network order), with host bits masked off.
    pub octets: [u8; 16],
    /// Prefix length in bits, `0..=128`.
    pub prefix: u8,
}

impl Cidr6 {
    /// The blocklist LPM `(prefix, data)` for this block. The data is the raw
    /// network-order octets, which is exactly what the kernel trie walks and
    /// what [`crate::ScopedAddr6`] stores.
    #[inline]
    pub const fn lpm_key(&self) -> (u32, [u8; 16]) {
        (self.prefix as u32, self.octets)
    }
}

impl fmt::Display for Cidr6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", Ipv6Addr::from(self.octets), self.prefix)
    }
}

/// Mask off the host bits of a 16-byte IPv6 address below `prefix`.
#[inline]
pub const fn mask_v6(mut octets: [u8; 16], prefix: u8) -> [u8; 16] {
    let prefix = prefix as u32;
    let mut i = 0;
    while i < 16 {
        let bit = (i as u32) * 8;
        if bit >= prefix {
            octets[i] = 0; // wholly beyond the prefix
        } else if bit + 8 > prefix {
            // partial byte: keep the top `prefix - bit` bits.
            let keep = prefix - bit;
            octets[i] &= (0xffu16 << (8 - keep)) as u8;
        }
        i += 1;
    }
    octets
}

/// Parse a `"addr"` or `"addr/prefix"` IPv6 string into a normalised [`Cidr6`].
/// A bare address is a `/128` host route.
///
/// ```
/// use velstra_common::parse_cidr_v6;
/// let c = parse_cidr_v6("2001:db8::1/32").unwrap();
/// assert_eq!(c.prefix, 32);
/// assert_eq!(&c.octets[..4], &[0x20, 0x01, 0x0d, 0xb8]);
/// assert_eq!(&c.octets[4..], &[0u8; 12]); // host bits masked
/// ```
pub fn parse_cidr_v6(input: &str) -> Result<Cidr6, CidrError> {
    let (addr_str, prefix) = match input.split_once('/') {
        Some((addr, pfx)) => (addr, pfx.parse::<u8>().map_err(|_| CidrError::BadPrefix)?),
        None => (input, 128u8),
    };
    if prefix > 128 {
        return Err(CidrError::PrefixTooLong);
    }
    let addr: Ipv6Addr = addr_str.parse().map_err(|_| CidrError::BadAddress)?;
    Ok(Cidr6 {
        octets: mask_v6(addr.octets(), prefix),
        prefix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_address_is_host_route() {
        let c = parse_cidr_v4("192.0.2.1").unwrap();
        assert_eq!(c.octets, [192, 0, 2, 1]);
        assert_eq!(c.prefix, 32);
    }

    #[test]
    fn parses_ipv6_cidr_and_masks() {
        let c = parse_cidr_v6("2001:db8:abcd:1234::1/48").unwrap();
        assert_eq!(c.prefix, 48);
        // /48 keeps the first 6 bytes, zeroes the rest.
        assert_eq!(&c.octets[..6], &[0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd]);
        assert_eq!(&c.octets[6..], &[0u8; 10]);

        // Bare address is a /128 host route.
        assert_eq!(parse_cidr_v6("::1").unwrap().prefix, 128);
        // Partial-byte prefix (/4) keeps the top nibble.
        assert_eq!(parse_cidr_v6("f000::/4").unwrap().octets[0], 0xf0);
        assert!(parse_cidr_v6("2001:db8::/129").is_err());
        assert!(parse_cidr_v6("not-an-ipv6").is_err());
    }

    #[test]
    fn masks_host_bits() {
        assert_eq!(parse_cidr_v4("10.1.2.3/8").unwrap().octets, [10, 0, 0, 0]);
        assert_eq!(
            parse_cidr_v4("172.16.5.9/12").unwrap().octets,
            [172, 16, 0, 0]
        );
        assert_eq!(
            parse_cidr_v4("198.51.100.200/26").unwrap().octets,
            [198, 51, 100, 192]
        );
    }

    #[test]
    fn zero_prefix_is_catch_all() {
        let c = parse_cidr_v4("8.8.8.8/0").unwrap();
        assert_eq!(c.octets, [0, 0, 0, 0]);
        assert_eq!(c.prefix, 0);
        assert_eq!(c.lpm_key(), (0, 0));
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse_cidr_v4("not-an-ip"), Err(CidrError::BadAddress));
        assert_eq!(parse_cidr_v4("10.0.0.0/x"), Err(CidrError::BadPrefix));
        assert_eq!(parse_cidr_v4("10.0.0.0/33"), Err(CidrError::PrefixTooLong));
        assert_eq!(parse_cidr_v4("10.0.0.0/999"), Err(CidrError::BadPrefix)); // 999 > u8
    }

    #[test]
    fn display_roundtrips() {
        let c = parse_cidr_v4("10.0.0.0/8").unwrap();
        assert_eq!(c.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn lpm_key_is_network_order() {
        let c = parse_cidr_v4("10.0.0.0/8").unwrap();
        let (prefix, data) = c.lpm_key();
        assert_eq!(prefix, 8);
        assert_eq!(data.to_le_bytes(), [10, 0, 0, 0]);
    }
}
