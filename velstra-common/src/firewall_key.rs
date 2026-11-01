//! Canonical dual-stack firewall keys and incarnation-bound translation aliases.
//!
//! PolicyId/VNI is a routing identifier and must not be used as a logical flow
//! identity. The controller supplies a stable scope identity and its lifecycle
//! generation, shared by an HA pair. Deleting/recreating a policy changes the
//! generation; unrelated ordinal/VNI changes do not transfer return grants.

use crate::{FlowDirection, ip_proto};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowScope {
    pub identity: u64,
    pub generation: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FirewallFlowKey {
    pub scope: FlowScope,
    pub low_addr: [u8; 16],
    pub high_addr: [u8; 16],
    pub low_port: u16,
    pub high_port: u16,
    pub protocol: u8,
    pub family: u8,
    /// Canonical request type for ICMP queries; zero for TCP/UDP.
    pub query_type: u8,
    pub _pad: u8,
}

#[inline(always)]
fn word(addr: &[u8; 16], second: bool) -> u64 {
    if second {
        u64::from_be_bytes([
            addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
        ])
    } else {
        u64::from_be_bytes([
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
        ])
    }
}

impl FirewallFlowKey {
    /// Canonicalize caller-owned storage without a second 56-byte key copy.
    /// Useful for guarded BPF map scratch buffers on deep packet call chains.
    #[inline(never)]
    pub fn canonicalize(&mut self) -> FlowDirection {
        let a = word(&self.low_addr, false);
        let b = word(&self.high_addr, false);
        let c = word(&self.low_addr, true);
        let d = word(&self.high_addr, true);
        if a < b || a == b && (c < d || c == d && self.low_port <= self.high_port) {
            return FlowDirection::Forward;
        }
        core::mem::swap(&mut self.low_addr, &mut self.high_addr);
        core::mem::swap(&mut self.low_port, &mut self.high_port);
        FlowDirection::Reverse
    }
    /// Zeroed control-message storage. valid() rejects it.
    pub const ZERO: Self = Self {
        scope: FlowScope {
            identity: 0,
            generation: 0,
        },
        low_addr: [0; 16],
        high_addr: [0; 16],
        low_port: 0,
        high_port: 0,
        protocol: 0,
        family: 0,
        query_type: 0,
        _pad: 0,
    };

    /// Validate canonical control-plane input before admitting state.
    #[inline(always)]
    pub fn valid(&self) -> bool {
        if self.scope.identity == 0 || self.scope.generation == 0 || self._pad != 0 {
            return false;
        }
        let transport = self.protocol == ip_proto::TCP || self.protocol == ip_proto::UDP;
        if self.family == 4 {
            for i in 0..12 {
                if self.low_addr[i] != 0 || self.high_addr[i] != 0 {
                    return false;
                }
            }
            if !transport && self.protocol != ip_proto::ICMP {
                return false;
            }
        } else if self.family == 6 {
            if !transport && self.protocol != ip_proto::ICMPV6 {
                return false;
            }
        } else {
            return false;
        }
        if transport {
            if self.query_type != 0 {
                return false;
            }
        } else if self.query_type != (if self.family == 4 { 8 } else { 128 })
            || self.low_port != self.high_port
        {
            return false;
        }
        let a = word(&self.low_addr, false);
        let b = word(&self.high_addr, false);
        let c = word(&self.low_addr, true);
        let d = word(&self.high_addr, true);
        a < b || a == b && (c < d || c == d && self.low_port <= self.high_port)
    }

    #[inline(always)]
    fn canonical(
        scope: FlowScope,
        family: u8,
        source: ([u8; 16], u16),
        destination: ([u8; 16], u16),
        protocol: u8,
        query_type: u8,
    ) -> (Self, FlowDirection) {
        let (src, sport) = source;
        let (dst, dport) = destination;
        let a = word(&src, false);
        let b = word(&dst, false);
        let c = word(&src, true);
        let d = word(&dst, true);
        let forward = a < b || a == b && (c < d || c == d && sport <= dport);
        let (low_addr, high_addr, low_port, high_port, direction) = if forward {
            (src, dst, sport, dport, FlowDirection::Forward)
        } else {
            (dst, src, dport, sport, FlowDirection::Reverse)
        };
        (
            Self {
                scope,
                low_addr,
                high_addr,
                low_port,
                high_port,
                protocol,
                family,
                query_type,
                _pad: 0,
            },
            direction,
        )
    }

    #[inline(always)]
    pub fn transport_v4(
        scope: FlowScope,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        protocol: u8,
    ) -> Option<(Self, FlowDirection)> {
        if protocol != ip_proto::TCP && protocol != ip_proto::UDP {
            return None;
        }
        Some(Self::canonical(
            scope,
            4,
            (v4_addr(src), sport),
            (v4_addr(dst), dport),
            protocol,
            0,
        ))
    }
    #[inline(always)]
    pub fn transport_v6(
        scope: FlowScope,
        src: [u8; 16],
        dst: [u8; 16],
        sport: u16,
        dport: u16,
        protocol: u8,
    ) -> Option<(Self, FlowDirection)> {
        if protocol != ip_proto::TCP && protocol != ip_proto::UDP {
            return None;
        }
        Some(Self::canonical(
            scope,
            6,
            (src, sport),
            (dst, dport),
            protocol,
            0,
        ))
    }
    #[inline(always)]
    pub fn echo_v4(
        scope: FlowScope,
        src: [u8; 4],
        dst: [u8; 4],
        identifier: u16,
    ) -> (Self, FlowDirection) {
        Self::canonical(
            scope,
            4,
            (v4_addr(src), identifier),
            (v4_addr(dst), identifier),
            ip_proto::ICMP,
            8,
        )
    }
    #[inline(always)]
    pub fn echo_v6(
        scope: FlowScope,
        src: [u8; 16],
        dst: [u8; 16],
        identifier: u16,
    ) -> (Self, FlowDirection) {
        Self::canonical(
            scope,
            6,
            (src, identifier),
            (dst, identifier),
            ip_proto::ICMPV6,
            128,
        )
    }
}

#[inline(always)]
fn v4_addr(addr: [u8; 4]) -> [u8; 16] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, addr[0], addr[1], addr[2], addr[3],
    ]
}

/// A translated/cross-zone tuple points at one shared protocol state. It never
/// carries an independent boolean grant or lifetime. Resolve must also compare
/// incarnation with the primary state while holding that state's lock.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallFlowAlias {
    pub target: FirewallFlowKey,
    pub incarnation: u64,
    flip: u32,
    _pad: u32,
}
impl FirewallFlowAlias {
    #[inline(always)]
    pub fn new(
        target: FirewallFlowKey,
        incarnation: u64,
        alias_direction: FlowDirection,
        primary_direction: FlowDirection,
    ) -> Option<Self> {
        if incarnation == 0 {
            return None;
        }
        Some(Self {
            target,
            incarnation,
            flip: (alias_direction != primary_direction) as u32,
            _pad: 0,
        })
    }
    #[inline(always)]
    pub fn direction(
        &self,
        direction: FlowDirection,
        primary_incarnation: u64,
    ) -> Option<FlowDirection> {
        if self.incarnation == 0 || self.incarnation != primary_incarnation || self.flip > 1 {
            return None;
        }
        let reverse = direction.index() as u32 ^ self.flip;
        Some(if reverse == 0 {
            FlowDirection::Forward
        } else {
            FlowDirection::Reverse
        })
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowScope {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallFlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallFlowAlias {}

#[cfg(test)]
mod tests {
    use super::*;
    const S: FlowScope = FlowScope {
        identity: 7,
        generation: 19,
    };
    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [198, 51, 100, 9];
    #[test]
    fn reverse_tuples_share_one_key_and_invert_direction() {
        let (f, fd) = FirewallFlowKey::transport_v4(S, A, B, 45001, 443, ip_proto::TCP).unwrap();
        let (r, rd) = FirewallFlowKey::transport_v4(S, B, A, 443, 45001, ip_proto::TCP).unwrap();
        assert_eq!(f, r);
        assert_ne!(fd, rd);
        let mut a = [0u8; 16];
        a[0] = 0x20;
        a[15] = 1;
        let mut b = a;
        b[8] = 1;
        let (f, fd) = FirewallFlowKey::transport_v6(S, a, b, 45001, 443, ip_proto::TCP).unwrap();
        let (r, rd) = FirewallFlowKey::transport_v6(S, b, a, 443, 45001, ip_proto::TCP).unwrap();
        assert_eq!(f, r);
        assert_ne!(fd, rd);
    }
    #[test]
    fn address_ties_are_ordered_by_ports() {
        let (f, fd) = FirewallFlowKey::transport_v4(S, A, A, 1200, 1300, ip_proto::TCP).unwrap();
        let (r, rd) = FirewallFlowKey::transport_v4(S, A, A, 1300, 1200, ip_proto::TCP).unwrap();
        assert_eq!(f, r);
        assert_ne!(fd, rd);
    }
    #[test]
    fn scopes_generations_families_and_protocols_cannot_collide() {
        let (key, _) = FirewallFlowKey::transport_v4(S, A, B, 45001, 443, ip_proto::TCP).unwrap();
        for scope in [
            FlowScope { identity: 8, ..S },
            FlowScope {
                generation: 20,
                ..S
            },
        ] {
            assert_ne!(
                key,
                FirewallFlowKey::transport_v4(scope, A, B, 45001, 443, ip_proto::TCP)
                    .unwrap()
                    .0
            );
        }
        assert_ne!(
            key,
            FirewallFlowKey::transport_v4(S, A, B, 45001, 443, ip_proto::UDP)
                .unwrap()
                .0
        );
        assert_ne!(
            key,
            FirewallFlowKey::transport_v6(S, v4_addr(A), v4_addr(B), 45001, 443, ip_proto::TCP)
                .unwrap()
                .0
        );
        assert!(FirewallFlowKey::transport_v4(S, A, B, 0, 0, ip_proto::ICMP).is_none());
    }
    #[test]
    fn echo_identifier_is_required_in_both_directions_and_families() {
        let (f, fd) = FirewallFlowKey::echo_v4(S, A, B, 17);
        let (r, rd) = FirewallFlowKey::echo_v4(S, B, A, 17);
        assert_eq!(f, r);
        assert_ne!(fd, rd);
        assert_ne!(f, FirewallFlowKey::echo_v4(S, A, B, 18).0);
        let (f, fd) = FirewallFlowKey::echo_v6(S, v4_addr(A), v4_addr(B), 17);
        let (r, rd) = FirewallFlowKey::echo_v6(S, v4_addr(B), v4_addr(A), 17);
        assert_eq!(f, r);
        assert_ne!(fd, rd);
    }
    #[test]
    fn nat_alias_maps_direction_and_cannot_reopen_a_reused_tuple() {
        let (key, _) = FirewallFlowKey::transport_v4(S, A, B, 45001, 443, ip_proto::TCP).unwrap();
        for alias_direction in [FlowDirection::Forward, FlowDirection::Reverse] {
            for primary_direction in [FlowDirection::Forward, FlowDirection::Reverse] {
                let alias =
                    FirewallFlowAlias::new(key, 42, alias_direction, primary_direction).unwrap();
                assert_eq!(
                    alias.direction(alias_direction, 42),
                    Some(primary_direction)
                );
                assert_eq!(alias.direction(alias_direction, 43), None);
            }
        }
        assert!(
            FirewallFlowAlias::new(key, 0, FlowDirection::Forward, FlowDirection::Forward)
                .is_none()
        );
    }
    #[test]
    fn admission_rejects_noncanonical_family_protocol_and_scope_fields() {
        let key = FirewallFlowKey::transport_v4(S, A, B, 45001, 443, ip_proto::TCP)
            .unwrap()
            .0;
        assert!(key.valid());
        for field in 0..8 {
            let mut invalid = key;
            match field {
                0 => invalid.family = 5,
                1 => invalid.protocol = ip_proto::ICMPV6,
                2 => invalid.query_type = 8,
                3 => invalid.low_addr[0] = 1,
                4 => core::mem::swap(&mut invalid.low_addr, &mut invalid.high_addr),
                5 => invalid.scope.identity = 0,
                6 => invalid.scope.generation = 0,
                _ => invalid._pad = 1,
            }
            assert!(!invalid.valid(), "field {field}");
        }
        for v6 in [false, true] {
            let mut echo = if v6 {
                FirewallFlowKey::echo_v6(S, v4_addr(A), v4_addr(B), 17).0
            } else {
                FirewallFlowKey::echo_v4(S, A, B, 17).0
            };
            assert!(echo.valid());
            echo.high_port += 1;
            assert!(!echo.valid());
        }
    }
    #[test]
    fn layouts_have_explicit_padding_only() {
        assert_eq!(core::mem::size_of::<FlowScope>(), 16);
        assert_eq!(core::mem::size_of::<FirewallFlowKey>(), 56);
        assert_eq!(core::mem::size_of::<FirewallFlowAlias>(), 72);
    }
}
