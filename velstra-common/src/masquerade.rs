//! The `MASQUERADE` map's contract: egress ifindex → the address to translate to.
//!
//! An uplink that masquerades and has lost its address (a DHCP lease that
//! lapsed, a PPPoE session that dropped) used to lose its entry. Without one, a
//! packet leaving it is not masqueraded at all — it falls through to the plain
//! egress policy, which passes by default, and a LAN host's private source
//! address goes out onto the provider's wire whenever a route out of the uplink
//! survives the lease. So the entry stays, holding [`UNADDRESSED`], and the data
//! plane reads that as "nothing may leave here but the box asking for an address".

/// The value an uplink's `MASQUERADE` entry holds while it has no IPv4 address.
///
/// The unspecified address, because it is the one value that can never be a
/// real translation target — and because it is exactly the source a DHCP client
/// sends from before it has a lease, which is the traffic that must still leave.
pub const UNADDRESSED: [u8; 4] = [0; 4];

/// Whether an IPv4 packet with source `src` must be dropped leaving an uplink
/// whose `MASQUERADE` entry is `nat_ip`.
///
/// Only an unaddressed masquerade uplink drops, and it drops everything except
/// what is itself unaddressed: a forwarded packet would leave with an internal
/// source, and the box's own packet — from some other interface's address —
/// would leave un-translated the same way. What remains is the DHCP client's
/// DISCOVER/REQUEST, sent from `0.0.0.0`, which is how the uplink gets an
/// address back.
#[inline(always)]
pub fn unaddressed_uplink_drops(nat_ip: Option<[u8; 4]>, src: [u8; 4]) -> bool {
    matches!(nat_ip, Some(ip) if ip == UNADDRESSED) && src != UNADDRESSED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unaddressed_uplink_carries_only_its_own_address_request() {
        // A LAN host's forwarded packet, and the box's own from another link.
        assert!(unaddressed_uplink_drops(
            Some(UNADDRESSED),
            [192, 168, 1, 10]
        ));
        assert!(unaddressed_uplink_drops(Some(UNADDRESSED), [10, 0, 0, 1]));
        // The DHCP client asking for a lease.
        assert!(!unaddressed_uplink_drops(Some(UNADDRESSED), [0, 0, 0, 0]));
    }

    #[test]
    fn an_addressed_or_ordinary_link_is_not_this_rule_s_business() {
        assert!(!unaddressed_uplink_drops(
            Some([203, 0, 113, 9]),
            [192, 168, 1, 10]
        ));
        assert!(!unaddressed_uplink_drops(None, [192, 168, 1, 10]));
    }
}
