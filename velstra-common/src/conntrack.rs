//! Bounded firewall connection state, shared by XDP, TC and HA replication.
//! Times are monotonic nanoseconds local to a node; replication carries age,
//! never an absolute timestamp from another machine.

use crate::{FlowKey, ip_proto, tcp_flags};

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConntrackTimeouts {
    pub tcp_syn: u32,
    pub tcp_established: u32,
    pub tcp_closing: u32,
    pub udp: u32,
    pub udp_stream: u32,
    pub icmp: u32,
}

impl ConntrackTimeouts {
    pub const DEFAULT: Self = Self {
        tcp_syn: 30,
        tcp_established: 86400,
        tcp_closing: 30,
        udp: 30,
        udp_stream: 180,
        icmp: 10,
    };
}

impl Default for ConntrackTimeouts {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Address-family tagged key. IPv4 uses the first four address bytes and zeros
/// the rest. Echo identifiers occupy src_port, echo types occupy dst_port.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallKey {
    pub policy: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub family: u8,
    pub _pad: [u8; 2],
}

impl FirewallKey {
    #[inline(always)]
    pub fn ipv4(key: FlowKey) -> Self {
        let mut src = [0; 16];
        let mut dst = [0; 16];
        src[..4].copy_from_slice(&key.src_ip);
        dst[..4].copy_from_slice(&key.dst_ip);
        Self {
            policy: key.policy,
            src,
            dst,
            src_port: key.src_port,
            dst_port: key.dst_port,
            proto: key.proto,
            family: 4,
            _pad: [0; 2],
        }
    }

    pub fn as_ipv4(&self) -> Option<FlowKey> {
        if self.family != 4 {
            return None;
        }
        Some(FlowKey::new(
            self.policy,
            self.src[..4].try_into().ok()?,
            self.dst[..4].try_into().ok()?,
            self.src_port,
            self.dst_port,
            self.proto,
        ))
    }

    #[inline(always)]
    pub fn reverse(self) -> Self {
        let (src_port, dst_port) = if self.proto == ip_proto::ICMP || self.proto == 58 {
            // Only echo is tracked. Other ICMP messages must face policy; they
            // must never create an unrestricted reverse permission.
            (
                self.src_port,
                match self.dst_port {
                    8 => 0,
                    0 => 8,
                    128 => 129,
                    129 => 128,
                    n => n,
                },
            )
        } else {
            (self.dst_port, self.src_port)
        };
        Self {
            src: self.dst,
            dst: self.src,
            src_port,
            dst_port,
            ..self
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallState {
    pub last_seen_ns: u64,
    /// Activity age carried from a peer with a different monotonic uptime.
    pub age_ns: u64,
    pub phase: u32,
    /// 1 for the responder's direction, 0 for the initiator's.
    pub reply: u32,
}

impl FirewallState {
    pub const NEW: u32 = 1;
    pub const SYN_RECV: u32 = 2;
    pub const ESTABLISHED: u32 = 3;
    pub const CLOSING: u32 = 4;
    pub const RESET: u32 = 5;

    #[inline(always)]
    pub fn timeout_ns(&self, proto: u8, timeouts: ConntrackTimeouts) -> u64 {
        let seconds = if proto == ip_proto::TCP {
            match self.phase {
                Self::ESTABLISHED => timeouts.tcp_established,
                Self::CLOSING | Self::RESET => timeouts.tcp_closing,
                _ => timeouts.tcp_syn,
            }
        } else if proto == ip_proto::UDP {
            if self.phase == Self::ESTABLISHED {
                timeouts.udp_stream
            } else {
                timeouts.udp
            }
        } else {
            timeouts.icmp
        };
        seconds as u64 * 1_000_000_000
    }

    #[inline(always)]
    pub fn expired(&self, proto: u8, now: u64, timeouts: ConntrackTimeouts) -> bool {
        self.idle_ns(now) >= self.timeout_ns(proto, timeouts)
    }

    #[inline(always)]
    pub fn idle_ns(&self, now: u64) -> u64 {
        if now < self.last_seen_ns {
            return u64::MAX;
        }
        (now - self.last_seen_ns).saturating_add(self.age_ns)
    }

    /// `control` is TCP flags or the ICMP type. Unknown protocols are never
    /// tracked. TCP requires a SYN opener; echo replies cannot open state.
    #[inline(always)]
    pub fn is_opener(proto: u8, control: u8) -> bool {
        match proto {
            ip_proto::TCP => {
                control & (tcp_flags::SYN | tcp_flags::ACK | tcp_flags::FIN | tcp_flags::RST)
                    == tcp_flags::SYN
            }
            ip_proto::UDP => true,
            ip_proto::ICMP => control == 8,
            58 => control == 128,
            _ => false,
        }
    }

    #[inline(always)]
    pub fn new(proto: u8, control: u8, now: u64) -> Option<Self> {
        if !Self::is_opener(proto, control) {
            return None;
        }
        Some(Self {
            last_seen_ns: now,
            age_ns: 0,
            phase: Self::NEW,
            reply: 0,
        })
    }

    #[inline(always)]
    pub fn observe(
        self,
        proto: u8,
        control: u8,
        now: u64,
        timeouts: ConntrackTimeouts,
    ) -> Option<Self> {
        if self.expired(proto, now, timeouts) {
            return None;
        }
        let phase = self.next_phase(proto, control)?;
        Some(Self {
            last_seen_ns: now,
            age_ns: 0,
            phase,
            ..self
        })
    }

    /// Validate a protocol transition without materializing a second full
    /// state. eBPF uses this scalar result with map-backed working state.
    #[inline(always)]
    pub fn next_phase(&self, proto: u8, control: u8) -> Option<u32> {
        let mut phase = self.phase;
        if proto == ip_proto::TCP {
            let syn = control & tcp_flags::SYN != 0;
            let ack = control & tcp_flags::ACK != 0;
            let fin = control & tcp_flags::FIN != 0;
            let rst = control & tcp_flags::RST != 0;
            if (syn && (fin || rst)) || self.phase == Self::RESET {
                return None;
            }
            if rst {
                phase = Self::RESET;
            } else {
                match self.phase {
                    Self::NEW if self.reply == 0 && syn && !ack => {}
                    Self::NEW if self.reply == 1 && syn && ack => phase = Self::SYN_RECV,
                    Self::SYN_RECV if self.reply == 1 && syn && ack => {}
                    Self::SYN_RECV if self.reply == 0 && syn && !ack => {}
                    Self::SYN_RECV if self.reply == 0 && ack && !syn && !fin => {
                        phase = Self::ESTABLISHED
                    }
                    Self::ESTABLISHED | Self::CLOSING if ack && !syn => {
                        if fin {
                            phase = Self::CLOSING;
                        }
                    }
                    _ => return None,
                }
            }
        } else if proto == ip_proto::UDP {
            if self.reply == 1 {
                phase = Self::ESTABLISHED;
            }
        } else if !matches!(
            (proto, control, self.reply),
            (1, 8, 0) | (1, 0, 1) | (58, 128, 0) | (58, 129, 1)
        ) {
            return None;
        }
        Some(phase)
    }

    #[inline(always)]
    pub fn reverse(self) -> Self {
        Self {
            reply: self.reply ^ 1,
            ..self
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FirewallState {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for ConntrackTimeouts {}

#[cfg(test)]
mod tests {
    use super::*;
    const T: ConntrackTimeouts = ConntrackTimeouts::DEFAULT;
    const SYN: u8 = tcp_flags::SYN;
    const ACK: u8 = tcp_flags::ACK;

    #[test]
    fn imported_age_is_preserved_even_on_a_peer_that_has_just_booted() {
        let t = ConntrackTimeouts { icmp: 5, ..T };
        let state = FirewallState {
            last_seen_ns: 1,
            age_ns: 4_000_000_000,
            phase: 1,
            reply: 1,
        };
        assert_eq!(state.idle_ns(1), 4_000_000_000);
        assert!(!state.expired(1, 999_999_999, t));
        assert!(state.expired(1, 1_000_000_001, t));
        let active = state.observe(1, 0, 2, t).unwrap();
        assert_eq!(active.age_ns, 0);
    }

    #[test]
    fn tcp_handshake_retransmission_close_and_reset() {
        let syn = FirewallState::new(6, SYN, 1).unwrap();
        assert!(syn.observe(6, ACK, 2, T).is_none());
        assert!(syn.reverse().observe(6, ACK, 2, T).is_none());
        let retransmit = syn.observe(6, SYN, 2, T).unwrap();
        let synack = retransmit.reverse().observe(6, SYN | ACK, 3, T).unwrap();
        assert_eq!(synack.phase, FirewallState::SYN_RECV);
        assert!(synack.observe(6, SYN | ACK, 4, T).is_some());
        let established = synack.reverse().observe(6, ACK, 5, T).unwrap();
        assert_eq!(established.phase, FirewallState::ESTABLISHED);
        let fin = established.observe(6, tcp_flags::FIN | ACK, 6, T).unwrap();
        assert_eq!(fin.phase, FirewallState::CLOSING);
        assert!(fin.reverse().observe(6, ACK, 7, T).is_some());
        let rst = established
            .reverse()
            .observe(6, tcp_flags::RST | ACK, 8, T)
            .unwrap();
        assert_eq!(rst.phase, FirewallState::RESET);
        assert!(rst.observe(6, ACK, 9, T).is_none());
    }

    #[test]
    fn unsolicited_tcp_and_invalid_flag_combinations_do_not_create_state() {
        for flags in [
            0,
            ACK,
            SYN | ACK,
            tcp_flags::RST,
            SYN | tcp_flags::FIN,
            SYN | tcp_flags::RST,
        ] {
            assert!(FirewallState::new(6, flags, 1).is_none(), "{flags}");
        }
    }

    #[test]
    fn each_protocol_expires_at_its_configured_deadline() {
        let custom = ConntrackTimeouts {
            tcp_syn: 2,
            tcp_established: 3,
            tcp_closing: 4,
            udp: 5,
            udp_stream: 6,
            icmp: 7,
        };
        for (proto, phase, seconds) in [
            (6, 1, 2),
            (6, 3, 3),
            (6, 4, 4),
            (17, 1, 5),
            (17, 3, 6),
            (1, 1, 7),
            (58, 1, 7),
        ] {
            let state = FirewallState {
                last_seen_ns: 100,
                age_ns: 0,
                phase,
                reply: 0,
            };
            let end = 100 + seconds * 1_000_000_000;
            assert!(!state.expired(proto, end - 1, custom));
            assert!(state.expired(proto, end, custom));
            assert!(state.expired(proto, 99, custom));
        }
    }

    #[test]
    fn udp_reply_extends_state_and_echo_reply_cannot_open_a_flow() {
        let udp = FirewallState::new(17, 0, 1).unwrap();
        let reply = udp.reverse().observe(17, 0, 2, T).unwrap();
        assert_eq!(reply.phase, FirewallState::ESTABLISHED);
        assert!(reply.timeout_ns(17, T) > udp.timeout_ns(17, T));
        for (proto, request, answer) in [(1, 8, 0), (58, 128, 129)] {
            assert!(FirewallState::new(proto, answer, 1).is_none());
            let req = FirewallState::new(proto, request, 1).unwrap();
            assert!(req.reverse().observe(proto, request, 2, T).is_none());
            assert!(req.reverse().observe(proto, answer, 2, T).is_some());
        }
    }

    #[test]
    fn keys_isolate_family_policy_and_echo_identifier() {
        let a = FirewallKey::ipv4(FlowKey::new(7, [192, 0, 2, 1], [192, 0, 2, 2], 123, 8, 1));
        assert_eq!(a.reverse().dst_port, 0);
        assert_eq!(a.reverse().src_port, 123);
        assert_eq!(a.reverse().reverse(), a);
        assert_ne!(a, FirewallKey { policy: 8, ..a });
        assert_ne!(a, FirewallKey { family: 6, ..a });
        assert_ne!(a, FirewallKey { src_port: 124, ..a });
        assert_eq!(core::mem::size_of::<FirewallKey>(), 44);
        assert_eq!(core::mem::size_of::<FirewallState>(), 24);
    }
}
