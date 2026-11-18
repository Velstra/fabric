//! Lossless storage of two directional firewall rows under one canonical key.
//!
//! This is a storage/migration contract, not yet the live FW_FLOWS map format.
//! Unlike a shared phase/timestamp, two states preserve asymmetric imported
//! activity and permissions exactly. Never merge policies or NAT identities.
//! A kernel HASH can publish this value in one operation, but read/modify/write
//! still needs writer serialization; this module provides no compare-and-swap.

use crate::{ConntrackTimeouts, FirewallKey, FirewallState, ip_proto};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    UnsupportedKey,
    AmbiguousDirection,
    NotReversePair,
    InvalidState,
    ConflictingDirection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionDirection {
    Canonical,
    Reverse,
}

impl SessionDirection {
    #[inline(always)]
    const fn index(self) -> usize {
        match self {
            Self::Canonical => 0,
            Self::Reverse => 1,
        }
    }
}

/// Distinct type prevents accidental use in the existing directional map.
/// TCP/UDP endpoints are ordered by address, then numeric port. Echo requests
/// are canonical, keeping simultaneous opposite echo requests independent.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallSessionKey(FirewallKey);

impl FirewallSessionKey {
    #[inline(always)]
    pub fn from_direction(key: FirewallKey) -> Result<(Self, SessionDirection), SessionError> {
        if key._pad != [0; 2]
            || !matches!(key.family, 4 | 6)
            || (key.family == 4
                && (key.src[4..].iter().any(|byte| *byte != 0)
                    || key.dst[4..].iter().any(|byte| *byte != 0)))
        {
            return Err(SessionError::UnsupportedKey);
        }
        let canonical = match (key.family, key.proto) {
            (_, ip_proto::TCP | ip_proto::UDP) => {
                // A symmetric tuple cannot encode initiator versus responder.
                // Refuse it rather than turning a SYN into its own SYN-ACK row.
                if key.src == key.dst && key.src_port == key.dst_port {
                    return Err(SessionError::AmbiguousDirection);
                }
                key.src < key.dst || (key.src == key.dst && key.src_port < key.dst_port)
            }
            (4, ip_proto::ICMP) if matches!(key.dst_port, 0 | 8) => key.dst_port == 8,
            (6, 58) if matches!(key.dst_port, 128 | 129) => key.dst_port == 128,
            _ => return Err(SessionError::UnsupportedKey),
        };
        if canonical {
            Ok((Self(key), SessionDirection::Canonical))
        } else {
            Ok((Self(key.reverse()), SessionDirection::Reverse))
        }
    }

    /// Directional key used by diagnostics and the existing replication wire
    /// format. Conversion does not itself authorize an HA import.
    #[inline(always)]
    pub fn directional(self, direction: SessionDirection) -> FirewallKey {
        match direction {
            SessionDirection::Canonical => self.0,
            SessionDirection::Reverse => self.0.reverse(),
        }
    }

    #[inline(always)]
    pub fn direction_of(self, key: FirewallKey) -> Option<SessionDirection> {
        let (canonical, direction) = Self::from_direction(key).ok()?;
        (canonical == self).then_some(direction)
    }
}

/// Both directional states are independently retained (48 bytes, no padding).
/// Removing the duplicate 44-byte key reduces logical pair payload from 136
/// to 92 bytes. Kernel allocation overhead is not included in those figures.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallSession {
    states: [FirewallState; 2],
}

impl FirewallSession {
    /// Pack an existing complete pair without refreshing, choosing a newer
    /// direction, rebasing clocks, or synthesizing an absent permission.
    pub fn from_rows(
        first: (FirewallKey, FirewallState),
        second: (FirewallKey, FirewallState),
    ) -> Result<(FirewallSessionKey, Self), SessionError> {
        let (key, direction) = FirewallSessionKey::from_direction(first.0)?;
        let (other, other_direction) = FirewallSessionKey::from_direction(second.0)?;
        if key != other || direction == other_direction || first.0.reverse() != second.0 {
            return Err(SessionError::NotReversePair);
        }
        for state in [first.1, second.1] {
            if !(FirewallState::NEW..=FirewallState::RESET).contains(&state.phase)
                || state.reply > 1
            {
                return Err(SessionError::InvalidState);
            }
        }
        if first.1.reply == second.1.reply {
            return Err(SessionError::ConflictingDirection);
        }
        let states = match direction {
            SessionDirection::Canonical => [first.1, second.1],
            SessionDirection::Reverse => [second.1, first.1],
        };
        Ok((key, Self { states }))
    }

    /// A fresh, already-policy-authorized opener can seed both directions.
    /// An ACK, reply echo, or invalid SYN cannot manufacture established state.
    pub fn opener(
        key: FirewallKey,
        control: u8,
        now: u64,
    ) -> Result<Option<(FirewallSessionKey, Self)>, SessionError> {
        FirewallSessionKey::from_direction(key)?;
        // Echo type is part of the key, so it must agree with packet control.
        if matches!(key.proto, ip_proto::ICMP | 58) && key.dst_port != u16::from(control) {
            return Ok(None);
        }
        let Some(state) = FirewallState::new(key.proto, control, now) else {
            return Ok(None);
        };
        Self::from_rows((key, state), (key.reverse(), state.reverse())).map(Some)
    }

    #[inline(always)]
    pub fn state(self, direction: SessionDirection) -> FirewallState {
        self.states[direction.index()]
    }

    /// Lossless export; callers must hold their migration/snapshot fence.
    pub fn rows(self, key: FirewallSessionKey) -> [(FirewallKey, FirewallState); 2] {
        [
            (key.directional(SessionDirection::Canonical), self.states[0]),
            (key.directional(SessionDirection::Reverse), self.states[1]),
        ]
    }

    /// Reclaim only when neither direction is live, after excluding writers.
    /// This predicate is not permission to delete a concurrently refreshed key.
    pub fn expired(self, key: FirewallSessionKey, now: u64, timeouts: ConntrackTimeouts) -> bool {
        self.states
            .iter()
            .all(|state| state.expired(key.0.proto, now, timeouts))
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallSessionKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallSession {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlowKey, tcp_flags};

    fn key(proto: u8, family: u8, descending: bool) -> FirewallKey {
        let mut key = FirewallKey::ipv4(FlowKey::new(
            7,
            [192, 0, 2, 9],
            [198, 51, 100, 7],
            41000,
            443,
            proto,
        ));
        key.family = family;
        if family == 6 {
            key.src[15] = 8;
            key.dst[15] = 9;
        }
        if matches!(proto, 1 | 58) {
            key.dst_port = if family == 4 { 8 } else { 128 };
        }
        if descending { key.reverse() } else { key }
    }

    fn state(phase: u32, reply: u32, last_seen_ns: u64, age_ns: u64) -> FirewallState {
        FirewallState {
            phase,
            reply,
            last_seen_ns,
            age_ns,
        }
    }

    #[test]
    fn stable_layout_saves_one_key_without_losing_directional_values() {
        use core::mem::{align_of, size_of};
        assert_eq!(size_of::<FirewallSessionKey>(), 44);
        assert_eq!(align_of::<FirewallSessionKey>(), 4);
        assert_eq!(size_of::<FirewallSession>(), 48);
        assert_eq!(align_of::<FirewallSession>(), 8);
        assert_eq!(
            2 * (size_of::<FirewallKey>() + size_of::<FirewallState>()),
            136
        );
        assert_eq!(
            size_of::<FirewallSessionKey>() + size_of::<FirewallSession>(),
            92
        );
    }

    #[test]
    fn both_directions_select_one_key_and_opposite_slots() {
        for (proto, family) in [(6, 4), (17, 4), (6, 6), (17, 6), (1, 4), (58, 6)] {
            for descending in [false, true] {
                let original = key(proto, family, descending);
                let (a, d) = FirewallSessionKey::from_direction(original).unwrap();
                let (b, r) = FirewallSessionKey::from_direction(original.reverse()).unwrap();
                assert_eq!(a, b);
                assert_ne!(d, r);
                assert_eq!(a.directional(d), original);
                assert_eq!(a.directional(r), original.reverse());
            }
        }
    }

    #[test]
    fn lossless_conversion_is_independent_of_import_order() {
        for (proto, family) in [(6, 4), (17, 4), (6, 6), (17, 6), (1, 4), (58, 6)] {
            let forward = key(proto, family, true);
            for phase in 1..=5 {
                for reply in 0..=1 {
                    let a = (forward, state(phase, reply, 10, u64::MAX));
                    let b = (forward.reverse(), state(6 - phase, reply ^ 1, u64::MAX, 0));
                    let packed = FirewallSession::from_rows(a, b).unwrap();
                    assert_eq!(packed, FirewallSession::from_rows(b, a).unwrap());
                    let rows = packed.1.rows(packed.0);
                    assert!(rows.contains(&a) && rows.contains(&b));
                }
            }
        }
    }

    #[test]
    fn every_flag_phase_direction_and_expiry_classifies_identically() {
        let timeouts = ConntrackTimeouts::DEFAULT;
        for (proto, family) in [(6, 4), (17, 4), (6, 6), (17, 6), (1, 4), (58, 6)] {
            for phase in 1..=5 {
                let k = key(proto, family, false);
                let a = (k, state(phase, 0, 10, 0));
                let b = (k.reverse(), state(6 - phase, 1, 20, 19));
                let (canonical, pair) = FirewallSession::from_rows(a, b).unwrap();
                for (directional, expected) in [a, b] {
                    let actual = pair.state(canonical.direction_of(directional).unwrap());
                    for now in [0, 10, 30, 30_000_000_000, u64::MAX] {
                        for flags in 0..=u8::MAX {
                            assert_eq!(
                                actual.classify(proto, flags, now, timeouts),
                                expected.classify(proto, flags, now, timeouts)
                            );
                            assert_eq!(
                                actual.is_routed_reply(proto, flags, now, timeouts),
                                expected.is_routed_reply(proto, flags, now, timeouts)
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn fresh_reverse_prevents_pair_reclamation() {
        let k = key(6, 4, false);
        let a = (k, state(3, 0, 0, u64::MAX));
        let b = (k.reverse(), state(3, 1, u64::MAX, 0));
        let (canonical, pair) = FirewallSession::from_rows(a, b).unwrap();
        assert!(!pair.expired(canonical, 100, ConntrackTimeouts::DEFAULT));
        let (canonical, pair) =
            FirewallSession::from_rows(a, (b.0, state(3, 1, 0, u64::MAX))).unwrap();
        assert!(pair.expired(canonical, 100, ConntrackTimeouts::DEFAULT));
    }

    #[test]
    fn policy_family_ports_identifiers_and_addresses_do_not_alias() {
        let k = key(6, 4, false);
        let (canonical, _) = FirewallSessionKey::from_direction(k).unwrap();
        let mut alternatives = [k; 6];
        alternatives[0].policy += 1;
        alternatives[1].family = 6;
        alternatives[2].src_port += 1;
        alternatives[3].dst_port += 1;
        alternatives[4].src[3] += 1;
        alternatives[5].proto = 17;
        for other in alternatives {
            assert_ne!(
                FirewallSessionKey::from_direction(other).unwrap().0,
                canonical
            );
            assert_eq!(canonical.direction_of(other), None);
        }
        let echo = key(1, 4, false);
        let (canonical, _) = FirewallSessionKey::from_direction(echo).unwrap();
        assert_ne!(
            canonical,
            FirewallSessionKey::from_direction(FirewallKey {
                src_port: 2,
                ..echo
            })
            .unwrap()
            .0
        );
        let opposite_request = FirewallKey {
            src: echo.dst,
            dst: echo.src,
            ..echo
        };
        assert_ne!(
            canonical,
            FirewallSessionKey::from_direction(opposite_request)
                .unwrap()
                .0
        );
    }

    #[test]
    fn endpoint_port_tiebreak_and_symmetric_tuple_refusal() {
        let mut k = key(6, 4, false);
        k.dst = k.src;
        let (canonical, direction) = FirewallSessionKey::from_direction(k).unwrap();
        assert_eq!(direction, SessionDirection::Reverse);
        assert_eq!(
            canonical,
            FirewallSessionKey::from_direction(k.reverse()).unwrap().0
        );
        k.dst_port = k.src_port;
        assert_eq!(
            FirewallSessionKey::from_direction(k),
            Err(SessionError::AmbiguousDirection)
        );
    }

    #[test]
    fn ipv6_final_address_byte_and_equal_port_still_define_direction() {
        let mut k = key(6, 6, false);
        k.dst = k.src;
        k.dst[15] += 1;
        k.dst_port = k.src_port;
        let (canonical, direction) = FirewallSessionKey::from_direction(k).unwrap();
        assert_eq!(direction, SessionDirection::Canonical);
        assert_eq!(
            canonical.direction_of(k.reverse()),
            Some(SessionDirection::Reverse)
        );
        let other = FirewallKey {
            policy: u32::MAX,
            ..k
        };
        assert_eq!(canonical.direction_of(other), None);
    }

    #[test]
    fn udp_and_both_echo_families_preserve_opener_permissions() {
        for family in [4, 6] {
            for descending in [false, true] {
                let k = key(17, family, descending);
                let (canonical, pair) = FirewallSession::opener(k, 0, 10).unwrap().unwrap();
                assert_eq!(pair.state(canonical.direction_of(k).unwrap()).reply, 0);
                assert_eq!(
                    pair.state(canonical.direction_of(k.reverse()).unwrap())
                        .reply,
                    1
                );
            }
            let proto = if family == 4 { 1 } else { 58 };
            let mut k = key(proto, family, false);
            // A local echo has distinct request/reply type even at one address.
            k.dst = k.src;
            let control = if family == 4 { 8 } else { 128 };
            let reply = if family == 4 { 0 } else { 129 };
            let (canonical, pair) = FirewallSession::opener(k, control, 10).unwrap().unwrap();
            assert_eq!(pair.state(canonical.direction_of(k).unwrap()).reply, 0);
            assert_eq!(
                pair.state(canonical.direction_of(k.reverse()).unwrap())
                    .reply,
                1
            );
            assert!(
                FirewallSession::opener(k.reverse(), reply, 10)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn malformed_keys_and_incomplete_or_conflicting_pairs_are_rejected() {
        let k = key(6, 4, false);
        let s = state(1, 0, 10, 0);
        for malformed in [
            FirewallKey { family: 3, ..k },
            FirewallKey { proto: 50, ..k },
            FirewallKey { proto: 58, ..k },
            FirewallKey { _pad: [1, 0], ..k },
            FirewallKey { src: [1; 16], ..k },
            FirewallKey {
                proto: 1,
                dst_port: 3,
                ..k
            },
        ] {
            assert_eq!(
                FirewallSessionKey::from_direction(malformed),
                Err(SessionError::UnsupportedKey)
            );
        }
        assert_eq!(
            FirewallSession::from_rows((k, s), (k, s)),
            Err(SessionError::NotReversePair)
        );
        assert_eq!(
            FirewallSession::from_rows((k, s), (k.reverse(), s)),
            Err(SessionError::ConflictingDirection)
        );
        for bad in [state(0, 0, 1, 0), state(6, 0, 1, 0), state(1, 2, 1, 0)] {
            assert_eq!(
                FirewallSession::from_rows((k, bad), (k.reverse(), s.reverse())),
                Err(SessionError::InvalidState)
            );
        }
        let other = FirewallKey {
            policy: 999,
            ..k.reverse()
        };
        assert_eq!(
            FirewallSession::from_rows((k, s), (other, s.reverse())),
            Err(SessionError::NotReversePair)
        );
    }

    #[test]
    fn packing_does_not_admit_non_openers_or_precomplete_handshakes() {
        for descending in [false, true] {
            let k = key(6, 4, descending);
            for flags in 0..=u8::MAX {
                assert_eq!(
                    FirewallSession::opener(k, flags, 10).unwrap().is_some(),
                    FirewallState::is_opener(6, flags)
                );
            }
            let (canonical, pair) = FirewallSession::opener(k, tcp_flags::SYN, 10)
                .unwrap()
                .unwrap();
            let original = pair.state(canonical.direction_of(k).unwrap());
            let reply = pair.state(canonical.direction_of(k.reverse()).unwrap());
            assert_eq!(original.reply, 0);
            assert_eq!(reply.reply, 1);
            assert_eq!(
                original.classify(6, tcp_flags::ACK, 11, ConntrackTimeouts::DEFAULT),
                2
            );
            assert_eq!(
                reply.classify(
                    6,
                    tcp_flags::SYN | tcp_flags::ACK,
                    11,
                    ConntrackTimeouts::DEFAULT
                ),
                1
            );
        }
        let echo = key(1, 4, false);
        assert!(FirewallSession::opener(echo, 0, 1).unwrap().is_none());
        assert!(
            FirewallSession::opener(echo.reverse(), 8, 1)
                .unwrap()
                .is_none()
        );
        assert!(FirewallSession::opener(echo, 8, 1).unwrap().is_some());
    }
}
