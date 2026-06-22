//! Dependency-free parsing of `aa:bb:cc:dd:ee:ff`-style MAC addresses.
//!
//! Used by the control plane to turn route next-hop / source MACs from the
//! config file (and from `/sys/class/net/*/address`) into the `[u8; 6]` the
//! `ROUTES` map stores. Kept in the shared crate so it is `no_std` and unit
//! tested alongside the rest of the parsing.

use core::fmt;

/// Why [`parse_mac`] rejected an input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacError {
    /// Wrong number of `:`-separated octets (six are required).
    WrongLength,
    /// An octet was not a two-digit hex byte.
    BadOctet,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            MacError::WrongLength => "MAC address must have six colon-separated octets",
            MacError::BadOctet => "MAC octet must be two hex digits",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for MacError {}

/// Parse `"aa:bb:cc:dd:ee:ff"` (case-insensitive) into six bytes.
///
/// ```
/// use velstra_common::parse_mac;
/// assert_eq!(parse_mac("02:00:00:00:00:0a").unwrap(), [2, 0, 0, 0, 0, 10]);
/// assert_eq!(parse_mac("AA:BB:CC:DD:EE:FF").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
/// assert!(parse_mac("zz:00:00:00:00:00").is_err());
/// ```
pub fn parse_mac(input: &str) -> Result<[u8; 6], MacError> {
    let mut out = [0u8; 6];
    let mut octets = input.split(':');
    for slot in &mut out {
        let octet = octets.next().ok_or(MacError::WrongLength)?;
        if octet.len() != 2 {
            return Err(MacError::BadOctet);
        }
        *slot = u8::from_str_radix(octet, 16).map_err(|_| MacError::BadOctet)?;
    }
    // Reject trailing octets (e.g. seven groups).
    if octets.next().is_some() {
        return Err(MacError::WrongLength);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_macs() {
        assert_eq!(parse_mac("00:00:00:00:00:00").unwrap(), [0; 6]);
        assert_eq!(
            parse_mac("de:ad:be:ef:13:37").unwrap(),
            [0xde, 0xad, 0xbe, 0xef, 0x13, 0x37]
        );
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse_mac("00:00:00:00:00"), Err(MacError::WrongLength)); // 5 octets
        assert_eq!(
            parse_mac("00:00:00:00:00:00:00"),
            Err(MacError::WrongLength)
        ); // 7
        assert_eq!(parse_mac("0:00:00:00:00:00"), Err(MacError::BadOctet)); // 1 digit
        assert_eq!(parse_mac("gg:00:00:00:00:00"), Err(MacError::BadOctet)); // non-hex
        assert_eq!(parse_mac(""), Err(MacError::BadOctet));
    }
}
