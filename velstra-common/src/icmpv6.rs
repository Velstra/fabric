//! ICMPv6 that a firewall must not treat as ordinary traffic.
//!
//! Two kinds, and both are pure functions of header bytes so the data plane and
//! the host tests run the same code:
//!
//! * **Link control** ([`icmpv6_link_control`]): Neighbour Discovery (RFC 4861)
//!   and Multicast Listener Discovery (RFC 2710/3810). These are what ARP is to
//!   IPv4. RFC 4890 §4.4.1 lists them as traffic a firewall must not drop, and a
//!   deny-by-default zone that drops them leaves the box unable to resolve a
//!   single neighbour on that link: no global IPv6 leaves it at all. They are
//!   identified by the property that makes them safe to admit — a hop limit
//!   that proves the sender is on the link (255 for ND, 1 for MLD) — plus the
//!   source scope the RFCs require. Nothing that crossed a router can carry it.
//! * **Related errors** ([`related_icmpv6_error`], [`related_icmpv6_key`]):
//!   destination-unreachable, packet-too-big, time-exceeded and
//!   parameter-problem about a connection the firewall already tracks. Without
//!   them IPv6 path-MTU discovery black-holes behind a deny-by-default zone,
//!   because IPv6 routers never fragment: Packet Too Big is the only way a
//!   sender learns the path is narrower.

use crate::{FirewallKey, PolicyId, ip_proto, ipv6_ext_len, is_ipv6_ext};

/// ICMPv6 message types this module classifies (RFC 4443, 4861, 2710, 3810).
pub mod icmpv6_type {
    /// Destination unreachable.
    pub const DEST_UNREACHABLE: u8 = 1;
    /// Packet too big — the PMTUD signal.
    pub const PACKET_TOO_BIG: u8 = 2;
    /// Time exceeded (hop limit or reassembly).
    pub const TIME_EXCEEDED: u8 = 3;
    /// Parameter problem.
    pub const PARAMETER_PROBLEM: u8 = 4;
    /// Echo request.
    pub const ECHO_REQUEST: u8 = 128;
    /// Echo reply.
    pub const ECHO_REPLY: u8 = 129;
    /// MLD listener query.
    pub const MLD_QUERY: u8 = 130;
    /// MLDv1 listener report.
    pub const MLD_REPORT: u8 = 131;
    /// MLDv1 listener done.
    pub const MLD_DONE: u8 = 132;
    /// Router solicitation.
    pub const ROUTER_SOLICIT: u8 = 133;
    /// Router advertisement.
    pub const ROUTER_ADVERT: u8 = 134;
    /// Neighbour solicitation.
    pub const NEIGHBOR_SOLICIT: u8 = 135;
    /// Neighbour advertisement.
    pub const NEIGHBOR_ADVERT: u8 = 136;
    /// Redirect.
    pub const REDIRECT: u8 = 137;
    /// MLDv2 listener report.
    pub const MLD2_REPORT: u8 = 143;
}

/// The hop limit every Neighbour Discovery message is sent with. A receiver
/// discards ND with any other value (RFC 4861 §6.1, §7.1), so a router can
/// never have forwarded one that still carries it.
pub const ND_HOP_LIMIT: u8 = 255;

/// The hop limit MLD is sent with (RFC 2710 §3, RFC 3810 §5): link-scoped.
pub const MLD_HOP_LIMIT: u8 = 1;

#[inline(always)]
const fn link_local(src: &[u8; 16]) -> bool {
    src[0] == 0xfe && src[1] & 0xc0 == 0x80
}

#[inline(always)]
const fn unspecified(src: &[u8; 16]) -> bool {
    let mut i = 0;
    while i < 16 {
        if src[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether an ICMPv6 message is link control the firewall must always admit,
/// in either direction, whatever the zone's default, its rules or
/// `block-icmp` say.
///
/// `kind`/`code` are the ICMPv6 type and code, `hop_limit` the IPv6 hop limit
/// and `src` the IPv6 source. Each message is admitted only in the exact shape
/// its RFC prescribes:
///
/// | type | message | hop limit | source |
/// |---|---|---|---|
/// | 133 | router solicitation | 255 | link-local or `::` |
/// | 134 | router advertisement | 255 | link-local |
/// | 135 | neighbour solicitation | 255 | any (`::` is DAD) |
/// | 136 | neighbour advertisement | 255 | any but `::` |
/// | 137 | redirect | 255 | link-local |
/// | 130, 132 | MLD query, done | 1 | link-local |
/// | 131, 143 | MLD reports | 1 | link-local or `::` |
///
/// Code must be 0 for all of them. Anything else — including an "NS" with a
/// hop limit of 254, which by definition crossed a router — is ordinary ICMPv6
/// and faces the policy like any other packet.
///
/// What an admitted message cannot do: it creates no connection state, and a
/// hop-limit-255 message addressed to some other host and forwarded anyway
/// arrives with 254, which every receiver discards (RFC 4861 §7.1.1).
#[inline(always)]
pub const fn icmpv6_link_control(kind: u8, code: u8, hop_limit: u8, src: &[u8; 16]) -> bool {
    use icmpv6_type::*;
    if code != 0 {
        return false;
    }
    match kind {
        ROUTER_SOLICIT => hop_limit == ND_HOP_LIMIT && (link_local(src) || unspecified(src)),
        ROUTER_ADVERT | REDIRECT => hop_limit == ND_HOP_LIMIT && link_local(src),
        NEIGHBOR_SOLICIT => hop_limit == ND_HOP_LIMIT,
        NEIGHBOR_ADVERT => hop_limit == ND_HOP_LIMIT && !unspecified(src),
        MLD_QUERY | MLD_DONE => hop_limit == MLD_HOP_LIMIT && link_local(src),
        MLD_REPORT | MLD2_REPORT => {
            hop_limit == MLD_HOP_LIMIT && (link_local(src) || unspecified(src))
        }
        _ => false,
    }
}

/// Whether an ICMPv6 message is an error that may be RELATED to a tracked
/// connection: the RFC 4443 error types with their defined codes. Unknown codes
/// are not promoted into a permission, the same rule the IPv4 path keeps.
#[inline(always)]
pub const fn related_icmpv6_error(kind: u8, code: u8) -> bool {
    use icmpv6_type::*;
    match kind {
        DEST_UNREACHABLE => code <= 6,
        PACKET_TOO_BIG => code == 0,
        TIME_EXCEEDED => code <= 1,
        PARAMETER_PROBLEM => code <= 3,
        _ => false,
    }
}

/// Where the quoted ("invoking") packet starts, relative to the ICMPv6 header:
/// type, code, checksum and four bytes of type-specific data come first.
pub const ICMPV6_ERROR_QUOTE: usize = 8;

/// Build the firewall-state key an ICMPv6 error is about into `key`, returning
/// `false` (and leaving `key` unspecified) when the error cannot be about a
/// connection this box tracks. An out-parameter rather than an `Option`, so the
/// data plane builds the key in a map slot instead of on its 512-byte stack.
///
/// `outer_dst` is the error's own IPv6 destination; `quoted` the first 40 bytes
/// of the invoking packet (its IPv6 header), `upper` the protocol its
/// extension-header chain ends in (walked with [`quote_ext_step`]; `quoted[6]`
/// when there is none) and `transport` the 8 bytes where that protocol starts. The key is built in exactly the convention the state machine records
/// flows in — host-order ports for TCP/UDP; for echo, the identifier in
/// `src_port` and the type in `dst_port` — so the caller looks it up as it
/// stands and, failing that, its [`FirewallKey::reverse`].
///
/// Refused, so that an error can only ever reach the host that caused it:
/// * a quote that is not IPv6, or whose source is not the error's destination —
///   an error goes back to the sender of the packet it quotes, and one aimed
///   anywhere else is somebody using a live flow as a pass;
/// * a quoted protocol other than TCP, UDP or ICMPv6 echo — in particular an
///   error about an error, which would loop, and an extension header the walk
///   did not get past.
#[inline(always)]
pub fn related_icmpv6_key(
    policy: PolicyId,
    outer_dst: &[u8; 16],
    quoted: &[u8; 40],
    upper: u8,
    transport: &[u8; 8],
    key: &mut FirewallKey,
) -> bool {
    if quoted[0] >> 4 != 6 {
        return false;
    }
    let mut i = 0;
    while i < 16 {
        if quoted[8 + i] != outer_dst[i] {
            return false;
        }
        key.src[i] = quoted[8 + i];
        key.dst[i] = quoted[24 + i];
        i += 1;
    }
    let proto = upper;
    let (src_port, dst_port) = match proto {
        ip_proto::TCP | ip_proto::UDP => (
            u16::from_be_bytes([transport[0], transport[1]]),
            u16::from_be_bytes([transport[2], transport[3]]),
        ),
        ip_proto::ICMPV6
            if transport[0] == icmpv6_type::ECHO_REQUEST
                || transport[0] == icmpv6_type::ECHO_REPLY =>
        {
            (
                u16::from_be_bytes([transport[4], transport[5]]),
                transport[0] as u16,
            )
        }
        _ => return false,
    };
    key.policy = policy;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.proto = proto;
    key.family = 6;
    key._pad = [0; 2];
    true
}

/// How many extension headers of a quoted packet the data plane walks to find
/// the transport header an ICMPv6 error is about. Four covers what a real
/// sender emits (hop-by-hop, destination options, routing, fragment).
pub const QUOTE_EXT_MAX: usize = 4;

/// One step through the extension headers of the packet an ICMPv6 error quotes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuoteStep {
    /// `proto` is not an extension header: the transport header starts here.
    Upper,
    /// Skip `len` bytes; the next header is `proto`.
    Next {
        /// The header that follows.
        proto: u8,
        /// The length of the header being skipped.
        len: u32,
    },
    /// The quote cannot be about a tracked connection: it is a later fragment,
    /// which carries no transport header to name one.
    Refuse,
}

/// The step past the extension header `proto` whose first four bytes are
/// `head` (next header, length, and for a fragment its offset field).
///
/// Before this, any quote whose next header was an extension header was
/// refused outright (audit follow-up to DP-21): a Packet Too Big about a
/// connection that carried a hop-by-hop or destination-options header never
/// reached its sender behind a deny-by-default zone.
#[inline(always)]
pub const fn quote_ext_step(proto: u8, head: &[u8; 4]) -> QuoteStep {
    if !is_ipv6_ext(proto) {
        return QuoteStep::Upper;
    }
    if proto == ip_proto::FRAGMENT && u16::from_be_bytes([head[2], head[3]]) & 0xFFF8 != 0 {
        return QuoteStep::Refuse;
    }
    QuoteStep::Next {
        proto: head[0],
        len: ipv6_ext_len(proto, head[1]) as u32,
    }
}

#[cfg(test)]
mod tests {
    use icmpv6_type::*;

    use super::*;

    const LL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    const GLOBAL: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
    const UNSPEC: [u8; 16] = [0; 16];

    /// The messages the box's own neighbour resolution depends on, in the shape
    /// the RFCs send them, are admitted. This is the live DP-10 failure: an NA
    /// answering the box's own NS, arriving on a default-drop zone.
    #[test]
    fn neighbour_discovery_in_its_rfc_shape_is_link_control() {
        assert!(icmpv6_link_control(NEIGHBOR_ADVERT, 0, 255, &GLOBAL));
        assert!(icmpv6_link_control(NEIGHBOR_ADVERT, 0, 255, &LL));
        assert!(icmpv6_link_control(NEIGHBOR_SOLICIT, 0, 255, &GLOBAL));
        assert!(icmpv6_link_control(NEIGHBOR_SOLICIT, 0, 255, &LL));
        // Duplicate-address detection solicits from the unspecified address.
        assert!(icmpv6_link_control(NEIGHBOR_SOLICIT, 0, 255, &UNSPEC));
        assert!(icmpv6_link_control(ROUTER_SOLICIT, 0, 255, &LL));
        assert!(icmpv6_link_control(ROUTER_SOLICIT, 0, 255, &UNSPEC));
        assert!(icmpv6_link_control(ROUTER_ADVERT, 0, 255, &LL));
        assert!(icmpv6_link_control(REDIRECT, 0, 255, &LL));
    }

    /// A hop limit other than 255 means a router forwarded it, so it is not
    /// ND at all, whatever its type byte says — and it must face the policy.
    #[test]
    fn nd_that_crossed_a_router_is_not_link_control() {
        for kind in [
            ROUTER_SOLICIT,
            ROUTER_ADVERT,
            NEIGHBOR_SOLICIT,
            NEIGHBOR_ADVERT,
            REDIRECT,
        ] {
            for hop in [0u8, 1, 64, 128, 254] {
                assert!(!icmpv6_link_control(kind, 0, hop, &LL), "{kind}/{hop}");
            }
        }
    }

    #[test]
    fn nd_with_a_source_the_rfc_forbids_is_not_link_control() {
        // RA and redirect come only from a router's link-local address.
        assert!(!icmpv6_link_control(ROUTER_ADVERT, 0, 255, &GLOBAL));
        assert!(!icmpv6_link_control(REDIRECT, 0, 255, &GLOBAL));
        assert!(!icmpv6_link_control(ROUTER_SOLICIT, 0, 255, &GLOBAL));
        // An advertisement always names a real address.
        assert!(!icmpv6_link_control(NEIGHBOR_ADVERT, 0, 255, &UNSPEC));
        // A nonzero code is not an ND message.
        assert!(!icmpv6_link_control(NEIGHBOR_ADVERT, 1, 255, &LL));
    }

    #[test]
    fn mld_is_link_control_only_at_hop_limit_one_from_link_local() {
        for kind in [MLD_QUERY, MLD_REPORT, MLD_DONE, MLD2_REPORT] {
            assert!(icmpv6_link_control(kind, 0, 1, &LL), "{kind}");
            assert!(!icmpv6_link_control(kind, 0, 2, &LL), "{kind}");
            assert!(!icmpv6_link_control(kind, 0, 255, &LL), "{kind}");
            assert!(!icmpv6_link_control(kind, 0, 1, &GLOBAL), "{kind}");
        }
        assert!(icmpv6_link_control(MLD2_REPORT, 0, 1, &UNSPEC));
        assert!(!icmpv6_link_control(MLD_QUERY, 0, 1, &UNSPEC));
    }

    /// Echo and errors are never link control: `block-icmp` and the rules still
    /// decide those.
    #[test]
    fn echo_and_errors_are_not_link_control() {
        for kind in [
            DEST_UNREACHABLE,
            PACKET_TOO_BIG,
            TIME_EXCEEDED,
            PARAMETER_PROBLEM,
            ECHO_REQUEST,
            ECHO_REPLY,
            0,
            255,
        ] {
            assert!(!icmpv6_link_control(kind, 0, 255, &LL), "{kind}");
            assert!(!icmpv6_link_control(kind, 0, 1, &LL), "{kind}");
        }
    }

    #[test]
    fn rfc_4443_errors_are_related_candidates_and_nothing_else_is() {
        assert!(related_icmpv6_error(PACKET_TOO_BIG, 0));
        assert!(!related_icmpv6_error(PACKET_TOO_BIG, 1));
        for code in 0..=6 {
            assert!(related_icmpv6_error(DEST_UNREACHABLE, code));
        }
        assert!(!related_icmpv6_error(DEST_UNREACHABLE, 7));
        assert!(related_icmpv6_error(TIME_EXCEEDED, 0));
        assert!(related_icmpv6_error(TIME_EXCEEDED, 1));
        assert!(!related_icmpv6_error(TIME_EXCEEDED, 2));
        assert!(related_icmpv6_error(PARAMETER_PROBLEM, 3));
        assert!(!related_icmpv6_error(PARAMETER_PROBLEM, 4));
        for kind in [0u8, 5, 127, ECHO_REQUEST, ECHO_REPLY, NEIGHBOR_ADVERT, 255] {
            assert!(!related_icmpv6_error(kind, 0), "{kind}");
        }
    }

    const CLIENT: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x50,
    ];
    const SERVER: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfe,
    ];

    fn related(
        outer_dst: &[u8; 16],
        quoted: &[u8; 40],
        transport: &[u8; 8],
    ) -> Option<FirewallKey> {
        let mut key = FirewallKey {
            policy: 0,
            src: [0xaa; 16],
            dst: [0xaa; 16],
            src_port: 0xaaaa,
            dst_port: 0xaaaa,
            proto: 0xaa,
            family: 0xaa,
            _pad: [0xaa; 2],
        };
        related_icmpv6_key(7, outer_dst, quoted, quoted[6], transport, &mut key).then_some(key)
    }

    fn quote(src: [u8; 16], dst: [u8; 16], next: u8) -> [u8; 40] {
        let mut q = [0u8; 40];
        q[0] = 0x60;
        q[6] = next;
        q[7] = 64;
        q[8..24].copy_from_slice(&src);
        q[24..40].copy_from_slice(&dst);
        q
    }

    /// A Packet Too Big quoting the client's UDP datagram names exactly the key
    /// the state machine recorded for that datagram.
    #[test]
    fn a_quoted_udp_datagram_names_its_recorded_flow() {
        let quoted = quote(CLIENT, SERVER, ip_proto::UDP);
        let transport = [0x47, 0x6c, 0x46, 0xa1, 0, 0, 0, 0]; // 18284 -> 18081
        let key = related(&CLIENT, &quoted, &transport).expect("related");
        assert_eq!(key.policy, 7);
        assert_eq!(key.src, CLIENT);
        assert_eq!(key.dst, SERVER);
        assert_eq!(key.src_port, 18284);
        assert_eq!(key.dst_port, 18081);
        assert_eq!(key.proto, ip_proto::UDP);
        assert_eq!(key.family, 6);
        // The other end of the same flow is its reverse, so either recorded
        // orientation is found.
        let reverse = key.reverse();
        assert_eq!(reverse.src, SERVER);
        assert_eq!(reverse.src_port, 18081);
    }

    #[test]
    fn a_quoted_echo_request_uses_the_echo_key_convention() {
        let quoted = quote(CLIENT, SERVER, ip_proto::ICMPV6);
        let transport = [ECHO_REQUEST, 0, 0xab, 0xcd, 0x12, 0x34, 0, 1];
        let key = related(&CLIENT, &quoted, &transport).expect("related");
        assert_eq!(key.src_port, 0x1234);
        assert_eq!(key.dst_port, ECHO_REQUEST as u16);
        assert_eq!(key.reverse().dst_port, ECHO_REPLY as u16);
    }

    /// An error only ever goes back to whoever sent the quoted packet.
    #[test]
    fn an_error_not_addressed_to_the_quoted_sender_is_not_related() {
        let quoted = quote(CLIENT, SERVER, ip_proto::TCP);
        let transport = [0x9c, 0x40, 0, 80, 0, 0, 0, 0];
        assert!(related(&SERVER, &quoted, &transport).is_none());
        let mut elsewhere = CLIENT;
        elsewhere[15] ^= 1;
        assert!(related(&elsewhere, &quoted, &transport).is_none());
    }

    #[test]
    fn unsupported_quotes_are_not_related() {
        let transport = [0x9c, 0x40, 0, 80, 0, 0, 0, 0];
        // Not IPv6.
        let mut v4 = quote(CLIENT, SERVER, ip_proto::TCP);
        v4[0] = 0x45;
        assert!(related(&CLIENT, &v4, &transport).is_none());
        // An error about an error, and non-echo ICMPv6.
        let icmp = quote(CLIENT, SERVER, ip_proto::ICMPV6);
        for kind in [PACKET_TOO_BIG, DEST_UNREACHABLE, NEIGHBOR_SOLICIT] {
            let t = [kind, 0, 0, 0, 0, 0, 0, 0];
            assert!(related(&CLIENT, &icmp, &t).is_none(), "{kind}");
        }
        // An extension header the walk did not get past, and other protocols.
        for next in [0u8, 43, 44, 50, 132] {
            let q = quote(CLIENT, SERVER, next);
            assert!(related(&CLIENT, &q, &transport).is_none(), "{next}");
        }
    }

    /// The walked protocol, not the quote's first next-header byte, names the
    /// transport: a UDP datagram behind a destination-options header.
    #[test]
    fn a_quote_behind_extension_headers_names_its_flow() {
        let quoted = quote(CLIENT, SERVER, ip_proto::DSTOPTS);
        let transport = [0x47, 0x6c, 0x46, 0xa1, 0, 0, 0, 0];
        assert!(related(&CLIENT, &quoted, &transport).is_none(), "unwalked");
        let mut key = FirewallKey {
            policy: 0,
            src: [0; 16],
            dst: [0; 16],
            src_port: 0,
            dst_port: 0,
            proto: 0,
            family: 0,
            _pad: [0; 2],
        };
        assert!(related_icmpv6_key(
            7,
            &CLIENT,
            &quoted,
            ip_proto::UDP,
            &transport,
            &mut key
        ));
        assert_eq!(
            (key.src_port, key.dst_port, key.proto),
            (18284, 18081, ip_proto::UDP)
        );
    }

    #[test]
    fn the_quote_walk_skips_each_extension_header_by_its_own_length() {
        // Destination options, one 8-byte unit beyond the first: 16 bytes.
        assert_eq!(
            quote_ext_step(ip_proto::DSTOPTS, &[ip_proto::UDP, 1, 0, 0]),
            QuoteStep::Next {
                proto: ip_proto::UDP,
                len: 16
            }
        );
        // Hop-by-hop then routing.
        assert_eq!(
            quote_ext_step(ip_proto::HOPOPT, &[ip_proto::ROUTING, 0, 0, 0]),
            QuoteStep::Next {
                proto: ip_proto::ROUTING,
                len: 8
            }
        );
        // AH counts 4-byte units beyond the first eight (RFC 4302).
        assert_eq!(
            quote_ext_step(ip_proto::AH, &[ip_proto::TCP, 4, 0, 0]),
            QuoteStep::Next {
                proto: ip_proto::TCP,
                len: 24
            }
        );
        // A first fragment is walked past; it still carries the transport.
        assert_eq!(
            quote_ext_step(ip_proto::FRAGMENT, &[ip_proto::TCP, 0, 0, 1]),
            QuoteStep::Next {
                proto: ip_proto::TCP,
                len: 8
            }
        );
    }

    #[test]
    fn the_quote_walk_stops_at_the_transport_and_refuses_later_fragments() {
        for proto in [ip_proto::TCP, ip_proto::UDP, ip_proto::ICMPV6, 50] {
            assert_eq!(quote_ext_step(proto, &[0; 4]), QuoteStep::Upper, "{proto}");
        }
        // Offset 8 bytes: a later fragment, no transport header in it.
        assert_eq!(
            quote_ext_step(ip_proto::FRAGMENT, &[ip_proto::UDP, 0, 0, 8]),
            QuoteStep::Refuse
        );
    }
}
