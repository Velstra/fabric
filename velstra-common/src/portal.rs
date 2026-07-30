//! C20 — the **captive portal gate**: a zone whose clients must be admitted one
//! at a time, at run time.
//!
//! Every other verdict this firewall reaches is a property of the *packet* — its
//! addresses, its ports, the connection it belongs to. A portal is the one place
//! where the verdict is a property of **who is sending**, decided minutes ago by
//! a person clicking a button, and it has to change without the configuration
//! changing. Recompiling and re-applying a ruleset per login is not a mechanism;
//! it is an outage waiting for a busy evening.
//!
//! So the gate is two maps and nothing else:
//!
//! * `PORTAL_GATES` — which policies are gated, and the appliance's own address
//!   in each. Written when the configuration is applied, like everything else.
//! * `PORTAL_CLIENTS` — who is currently admitted. Written by the portal, at run
//!   time, one client at a time, and every entry carries a deadline enforced in
//!   user space.
//!
//! ## Why the key is a MAC and not an address
//!
//! A session belongs to a **device**, not to an address, and on the kind of
//! network that has a portal the address is the least stable thing about the
//! client: the DHCP lease turns over, the laptop sleeps and comes back on a new
//! one, and every modern IPv6 stack rotates a temporary address through the day
//! by design (RFC 8981). Keying on the address would end the session each time,
//! which the guest experiences as the portal asking again for no reason.
//!
//! The MAC is stable for as long as the device is on the link, and — this is
//! what makes it worth the extra six bytes — it is *the same key on both address
//! families*. A client who logged in over IPv4 is admitted for IPv6 by the same
//! entry, with no second allow-set and no second login.
//!
//! It is also spoofable. So is an address on the same link, and by the same
//! neighbour, so this trades nothing away: a portal on an open guest network
//! bounds what an unauthenticated device may reach, and it has never been an
//! authentication of the device itself.
//!
//! ## What an unadmitted client may still do
//!
//! Enough to become admitted, and nothing more: talk to the appliance itself
//! (the portal page, DNS, everything the ordinary rules then judge on their own
//! merits), and configure an address — DHCP on IPv4, and ICMPv6 on IPv6, where
//! Neighbor Discovery is not optional and cannot be told apart from the rest of
//! ICMPv6 cheaply enough to be worth doing in the hot path.
//!
//! Note what is *not* on that list: no HTTP interception. The portal is
//! announced by RFC 8910 (DHCP option 114), not by rewriting somebody's
//! connection into ours. That is the same position taken on ALGs and on
//! MITM proxying elsewhere in this appliance, and it is also the only one that
//! still works when the connection is TLS — which, on the web a guest actually
//! visits, is all of them.

/// The appliance's own addresses in one gated policy.
///
/// A packet addressed here is let through the gate and judged by the ordinary
/// rules — the gate answers "may this client talk *past* us", never "may this
/// client talk *to* us", which is the firewall's own question and already has an
/// answer.
///
/// `#[repr(C)]`, plain old data, no padding: 4 + 16 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalGate {
    /// The appliance's IPv4 address in this zone, in network byte order.
    /// All-zero when the zone has no IPv4 portal address.
    pub portal4: [u8; 4],
    /// The appliance's IPv6 address in this zone. All-zero when unset.
    pub portal6: [u8; 16],
}

impl PortalGate {
    /// A gate that admits nothing but DHCP and Neighbor Discovery.
    pub const CLOSED: Self = Self {
        portal4: [0; 4],
        portal6: [0; 16],
    };

    /// Construct a gate from the appliance's addresses in the gated zone.
    #[inline]
    pub const fn new(portal4: [u8; 4], portal6: [u8; 16]) -> Self {
        Self { portal4, portal6 }
    }

    /// Whether `addr` is this zone's portal address.
    ///
    /// An unset (all-zero) portal address matches nothing: `0.0.0.0` is not a
    /// destination, and treating "unset" as "matches" would open the gate
    /// entirely on a half-written configuration.
    #[inline]
    pub const fn is_portal4(&self, addr: [u8; 4]) -> bool {
        u32::from_ne_bytes(self.portal4) != 0
            && u32::from_ne_bytes(self.portal4) == u32::from_ne_bytes(addr)
    }

    /// Whether `addr` is this zone's IPv6 portal address. See [`Self::is_portal4`].
    #[inline]
    pub fn is_portal6(&self, addr: [u8; 16]) -> bool {
        self.portal6 != [0u8; 16] && self.portal6 == addr
    }
}

/// The key of one admitted device: a MAC, scoped to the policy it was admitted
/// in.
///
/// Scoped because a device admitted to the guest zone has been admitted *there*
/// — carrying that session into another zone's policy because the same laptop
/// turned up on a different link would be handing out access nobody granted.
///
/// `#[repr(C)]` with the padding written out, so both sides agree on all 12
/// bytes and the two spare ones are always zero rather than whatever was on the
/// stack. A key with uninitialised padding hashes to a different bucket than the
/// one the other side wrote, which is the sort of bug that looks like "the
/// session sometimes doesn't take".
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortalClientKey {
    /// The policy (zone) this device was admitted in.
    pub policy_id: u32,
    /// The device's MAC address, as it appears in the Ethernet source field.
    pub mac: [u8; 6],
    /// Explicit padding, always zero. See the type's own documentation.
    pub _pad: [u8; 2],
}

impl PortalClientKey {
    /// Construct a key for `mac` in `policy_id`.
    #[inline]
    pub const fn new(policy_id: u32, mac: [u8; 6]) -> Self {
        Self {
            policy_id,
            mac,
            _pad: [0; 2],
        }
    }
}

/// The key of the **seen table**: an address that reached the portal, and the
/// policy it reached it from.
///
/// The portal server knows its visitor by address — that is all an HTTP
/// connection carries — while the gate is keyed by MAC. Something has to join
/// the two, and the honest place is the data plane: it is the only party that
/// sees both at once, on the very packets that carry the login. Reading the
/// kernel's neighbour table instead would answer from a cache that may be stale,
/// may have been poisoned by another device on the link, and does not exist at
/// all for an IPv6 client the appliance has not itself talked to.
///
/// IPv4 addresses occupy the first four bytes with the rest zero, so one table
/// serves both families.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortalSeenKey {
    /// The policy the packet arrived under.
    pub policy_id: u32,
    /// The sender's address: 16 bytes for IPv6, or 4 followed by zeros for IPv4.
    pub addr: [u8; 16],
}

impl PortalSeenKey {
    /// A key for an IPv4 sender.
    #[inline]
    pub const fn v4(policy_id: u32, addr: [u8; 4]) -> Self {
        Self {
            policy_id,
            addr: [
                addr[0], addr[1], addr[2], addr[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        }
    }

    /// A key for an IPv6 sender.
    #[inline]
    pub const fn v6(policy_id: u32, addr: [u8; 16]) -> Self {
        Self { policy_id, addr }
    }
}

/// Whether an unadmitted packet may pass the gate on its own merits.
///
/// Pure and family-agnostic, so the same three questions are asked by the IPv4
/// path, the IPv6 path and the test suite:
///
/// * is it addressed to the appliance (the portal page, the resolver, anything
///   else the ordinary rules will judge);
/// * is it DHCP (a client that cannot get an address cannot reach a portal
///   either), or
/// * is it ICMPv6 (Neighbor Discovery — see the module header).
///
/// Everything else is the traffic the portal exists to hold back.
#[inline]
pub const fn gate_admits_unauthenticated(
    to_portal: bool,
    proto: u8,
    src_port: u16,
    dst_port: u16,
    is_v6: bool,
) -> bool {
    if to_portal {
        return true;
    }
    // ICMPv6 carries Neighbor Discovery, Router Solicitation and PMTU, none of
    // which are optional and none of which are addressed to us — RS and NS go to
    // multicast. Telling ND apart from an ICMPv6 echo costs another packet read
    // in the hot path to hold back a channel that carries no useful payload.
    if is_v6 && proto == 58 {
        return true;
    }
    // DHCPv4 (68 ↔ 67, usually via the broadcast address) and DHCPv6 (546 ↔ 547,
    // via a link-local multicast group). **Both** ends must be DHCP ports, which
    // costs nothing — the protocol has always used a fixed pair, in both
    // directions and including a relay's 547 → 547 — and closes the hole that
    // matching one end leaves: a client that may send from port 68 to anywhere
    // has a UDP tunnel out of the zone the portal is supposed to be holding it
    // in.
    if proto == 17 && (is_dhcp4_port(src_port) && is_dhcp4_port(dst_port))
        || proto == 17 && (is_dhcp6_port(src_port) && is_dhcp6_port(dst_port))
    {
        return true;
    }
    false
}

/// A DHCPv4 endpoint port — client or server.
#[inline]
const fn is_dhcp4_port(port: u16) -> bool {
    port == 67 || port == 68
}

/// A DHCPv6 endpoint port — client, server, or a relay talking to another relay.
#[inline]
const fn is_dhcp6_port(port: u16) -> bool {
    port == 546 || port == 547
}

// SAFETY: both types are `#[repr(C)]` aggregates of `u32`/`u8` arrays with the
// padding written out as a field, so they are plain old data with no invalid bit
// patterns or pointers — exactly what `aya::Pod` requires for copying to and
// from BPF maps.
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortalGate {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortalClientKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PortalSeenKey {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layouts both sides index the maps with. A silent change here is a
    /// gate that admits the wrong device, or nobody.
    #[test]
    fn the_layouts_are_pinned() {
        assert_eq!(core::mem::size_of::<PortalGate>(), 20);
        assert_eq!(core::mem::size_of::<PortalClientKey>(), 12);
        assert_eq!(core::mem::align_of::<PortalClientKey>(), 4);
        // The padding is a field precisely so it is never whatever the stack
        // last held: two keys for the same device must be the same 12 bytes.
        let a = PortalClientKey::new(7, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let b = PortalClientKey::new(7, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        assert_eq!(a, b);
        assert_eq!(a._pad, [0, 0]);
    }

    /// One seen-table for both families: an IPv4 address is the same 16 bytes
    /// with zeros after it, and can never collide with a real IPv6 address (no
    /// global v6 address begins with a v4 address and ends in twelve zero
    /// bytes — that pattern is the unspecified address with a prefix).
    #[test]
    fn one_seen_table_serves_both_families() {
        assert_eq!(core::mem::size_of::<PortalSeenKey>(), 20);
        let v4 = PortalSeenKey::v4(1, [192, 168, 50, 33]);
        assert_eq!(&v4.addr[..4], &[192, 168, 50, 33]);
        assert_eq!(&v4.addr[4..], &[0u8; 12]);
        assert_ne!(v4, PortalSeenKey::v4(2, [192, 168, 50, 33]));
    }

    /// A session is scoped to the zone it was granted in — the same device on
    /// another link is another client.
    #[test]
    fn a_session_does_not_travel_between_zones() {
        let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x11];
        assert_ne!(PortalClientKey::new(1, mac), PortalClientKey::new(2, mac));
    }

    /// An unset portal address must match nothing. Treating all-zero as a match
    /// would open a half-configured gate completely.
    #[test]
    fn an_unset_portal_address_matches_nothing() {
        let closed = PortalGate::CLOSED;
        assert!(!closed.is_portal4([0, 0, 0, 0]));
        assert!(!closed.is_portal4([192, 168, 50, 1]));
        assert!(!closed.is_portal6([0; 16]));

        let gate = PortalGate::new([192, 168, 50, 1], [0; 16]);
        assert!(gate.is_portal4([192, 168, 50, 1]));
        assert!(!gate.is_portal4([192, 168, 50, 2]));
        // Configuring v4 alone must not admit every v6 destination.
        assert!(!gate.is_portal6([0; 16]));
    }

    /// What an unadmitted client is allowed to do is exactly: reach us, get an
    /// address, and find its neighbours.
    #[test]
    fn an_unadmitted_client_may_only_become_one() {
        // To the appliance: allowed, and then judged by the ordinary rules.
        assert!(gate_admits_unauthenticated(true, 6, 44000, 443, false));
        // DHCPv4 in both directions of the exchange.
        assert!(gate_admits_unauthenticated(false, 17, 68, 67, false));
        assert!(gate_admits_unauthenticated(false, 17, 67, 68, false));
        // DHCPv6.
        assert!(gate_admits_unauthenticated(false, 17, 546, 547, true));
        // ICMPv6 — Neighbor Discovery is not optional.
        assert!(gate_admits_unauthenticated(false, 58, 0, 0, true));

        // And the traffic the portal exists to hold back.
        assert!(!gate_admits_unauthenticated(false, 6, 44000, 443, false));
        assert!(!gate_admits_unauthenticated(false, 17, 44000, 53, false));
        assert!(!gate_admits_unauthenticated(false, 1, 0, 0, false));
        // ICMP**v4** is not ND and gets no exemption.
        assert!(!gate_admits_unauthenticated(false, 1, 0, 0, false));
        // …nor does IPv4 protocol 58 on a v4 packet.
        assert!(!gate_admits_unauthenticated(false, 58, 0, 0, false));
    }

    /// One DHCP port is not a DHCP exchange. Matching a single end would hand an
    /// unadmitted client a UDP channel to anywhere it liked, which is precisely
    /// what the gate exists to prevent.
    #[test]
    fn a_dhcp_port_at_one_end_is_not_dhcp() {
        // The real exchanges, both ways round, plus relay-to-relay on v6.
        assert!(gate_admits_unauthenticated(false, 17, 68, 67, false));
        assert!(gate_admits_unauthenticated(false, 17, 67, 68, false));
        assert!(gate_admits_unauthenticated(false, 17, 547, 547, true));

        // …and the tunnel that a one-ended match would open.
        assert!(!gate_admits_unauthenticated(false, 17, 68, 53, false));
        assert!(!gate_admits_unauthenticated(false, 17, 68, 51820, false));
        assert!(!gate_admits_unauthenticated(false, 17, 546, 53, true));
        // Nor may the families be mixed to smuggle one through.
        assert!(!gate_admits_unauthenticated(false, 17, 68, 547, false));
    }
}
