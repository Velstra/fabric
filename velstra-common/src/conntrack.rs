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
    /// Last cumulative ACK SENT by the initiator (`[0]`) and the responder
    /// (`[1]`): what that peer expects the other one to send next. Indexed by
    /// absolute direction, so both keys of a pair carry identical values.
    /// Meaningful only while the matching `TRACK_ACK` bit is set.
    pub acks: [u32; 2],
    /// Last raw (unscaled) TCP window advertised by initiator / responder.
    pub windows: [u16; 2],
    /// Node-local TCP tracking bits (`TRACK_*`). Never replicated: an entry
    /// imported from a peer, or written by an older datapath, has zero here and
    /// means "sequence unknown", which keeps the historical reset behaviour
    /// until both directions have been observed again.
    pub track: u32,
}

/// What a TCP reset's sequence number says about the connection it names,
/// judged against the receiver's last cumulative ACK (RFC 5961 section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResetCheck {
    /// The receiver's ACK was never observed: no sequence evidence either way.
    Unknown,
    /// Exactly the next expected sequence number: the connection really ends.
    Exact,
    /// Plausible but not exact. Forward it (the endpoint answers with a
    /// challenge ACK) and change no state.
    InWindow,
    /// Outside any window the receiver could have advertised: a blind forgery.
    Invalid,
}

/// The largest receive window a peer can advertise: 65535 scaled by the RFC
/// 7323 maximum shift of 14. Without parsing the SYN's window-scale option the
/// reset window is bounded by assuming the maximum shift. That only decides
/// whether a NON-exact reset is forwarded to the endpoint (which checks its own
/// exact window again); state is torn down only by an exact match.
pub const RESET_WINDOW_MAX: u32 = 65535 << 14;

/// Half-closed TCP (one FIN seen) keeps at least Linux's FIN_WAIT/CLOSE_WAIT
/// order of idle time. The configured closing timeout applies once both sides
/// have sent FIN, or after a reset.
pub const HALF_CLOSE_MIN_S: u32 = 120;

impl FirewallState {
    pub const NEW: u32 = 1;
    pub const SYN_RECV: u32 = 2;
    pub const ESTABLISHED: u32 = 3;
    pub const CLOSING: u32 = 4;
    pub const RESET: u32 = 5;

    /// `acks[0]` / `acks[1]` hold an observed ACK.
    pub const TRACK_ACK0: u32 = 1;
    pub const TRACK_ACK1: u32 = 2;
    /// The initiator / responder has sent a FIN.
    pub const TRACK_FIN0: u32 = 4;
    pub const TRACK_FIN1: u32 = 8;
    /// The initiator sent a fresh SYN on this established tuple. Only a SYN-ACK
    /// from the responder turns that into a new connection; any other answer
    /// (a challenge ACK from a live endpoint) cancels it.
    pub const TRACK_REOPEN: u32 = 16;

    /// Base value for struct-update syntax: no tracking evidence at all.
    pub const UNTRACKED: Self = Self {
        last_seen_ns: 0,
        age_ns: 0,
        phase: 0,
        reply: 0,
        acks: [0; 2],
        windows: [0; 2],
        track: 0,
    };

    /// A state with the four replicated fields and no local tracking.
    #[inline(always)]
    pub const fn untracked(last_seen_ns: u64, age_ns: u64, phase: u32, reply: u32) -> Self {
        Self {
            last_seen_ns,
            age_ns,
            phase,
            reply,
            acks: [0; 2],
            windows: [0; 2],
            track: 0,
        }
    }

    #[inline(always)]
    fn both_fins(&self) -> bool {
        self.track & (Self::TRACK_FIN0 | Self::TRACK_FIN1) == Self::TRACK_FIN0 | Self::TRACK_FIN1
    }

    #[inline(always)]
    fn one_fin(&self) -> bool {
        self.track & (Self::TRACK_FIN0 | Self::TRACK_FIN1) != 0 && !self.both_fins()
    }

    #[inline(always)]
    pub fn timeout_ns(&self, proto: u8, timeouts: ConntrackTimeouts) -> u64 {
        let seconds = if proto == ip_proto::TCP {
            match self.phase {
                Self::ESTABLISHED => timeouts.tcp_established,
                // A half-closed connection may legitimately idle while the
                // other side still sends. Legacy/imported CLOSING state has no
                // FIN bits and keeps the configured closing timeout.
                Self::CLOSING if self.one_fin() => {
                    if timeouts.tcp_closing > HALF_CLOSE_MIN_S {
                        timeouts.tcp_closing
                    } else {
                        HALF_CLOSE_MIN_S
                    }
                }
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
        // A shared map can be refreshed on CPU B after CPU A sampled `now`.
        // That is recent activity, NOT an invalid clock epoch. Expiring it here
        // deletes live TCP state under load. Peer timestamps are never copied:
        // conntrack sync imports a relative age rebased onto our local clock.
        now.saturating_sub(self.last_seen_ns)
            .saturating_add(self.age_ns)
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

    /// Linux `tcp_valid_flags`: the only TCP flag combinations (ignoring PSH,
    /// ECE and CWR) a real stack sends. NULL, XMAS, FIN without ACK, SYN+FIN
    /// and SYN+RST are scans or attacks, never part of a connection.
    #[inline(always)]
    pub fn tcp_flags_plausible(control: u8) -> bool {
        const URG: u8 = 0x20;
        let core =
            control & (tcp_flags::FIN | tcp_flags::SYN | tcp_flags::RST | tcp_flags::ACK | URG);
        matches!(
            core,
            tcp_flags::SYN
                | 0x22 // SYN|URG
                | 0x12 // SYN|ACK
                | tcp_flags::RST
                | 0x14 // RST|ACK
                | 0x11 // FIN|ACK
                | 0x31 // FIN|ACK|URG
                | tcp_flags::ACK
                | 0x30 // ACK|URG
        )
    }

    #[inline(always)]
    pub fn new(proto: u8, control: u8, now: u64) -> Option<Self> {
        if !Self::is_opener(proto, control) {
            return None;
        }
        Some(Self::untracked(now, 0, Self::NEW, 0))
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

    /// 0 needs normal new-flow policy, 1 is a valid tracked packet, 2 is invalid.
    /// A fresh opener may reuse a closing tuple, but is NOT established traffic:
    /// policy must admit it before ct_record replaces the old paired state.
    #[inline(always)]
    pub fn classify(&self, proto: u8, control: u8, now: u64, timeouts: ConntrackTimeouts) -> u8 {
        if self.expired(proto, now, timeouts)
            || (proto == ip_proto::TCP
                && matches!(self.phase, Self::CLOSING | Self::RESET)
                && Self::is_opener(proto, control))
        {
            0
        } else if self.next_phase(proto, control).is_some() {
            1
        } else {
            2
        }
    }

    /// Ordinary routed responder traffic must retain its original tuple even
    /// when leaving a masquerading interface. Only live valid reply-direction
    /// state establishes this exemption; an untracked/expired/invalid packet
    /// cannot acquire it merely by looking like an ACK or UDP response.
    #[inline(always)]
    pub fn is_routed_reply(
        &self,
        proto: u8,
        control: u8,
        now: u64,
        timeouts: ConntrackTimeouts,
    ) -> bool {
        matches!(proto, ip_proto::TCP | ip_proto::UDP)
            && self.reply == 1
            && self.classify(proto, control, now, timeouts) == 1
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
                    // A SYN-ACK after ESTABLISHED is the responder retransmitting
                    // because the initiator's final ACK was lost (DP-25a). It
                    // starts a new connection only after a reopening SYN.
                    Self::ESTABLISHED if self.reply == 1 && syn && ack && !fin => {
                        if self.track & Self::TRACK_REOPEN != 0 {
                            phase = Self::SYN_RECV;
                        }
                    }
                    // The initiator reusing a tuple whose old connection died
                    // silently (DP-25b). Forwarded without a state change: only
                    // the responder's SYN-ACK proves the old connection is gone,
                    // so a spoofed SYN cannot tear down a live one.
                    Self::ESTABLISHED if self.reply == 0 && syn && !ack && !fin => {}
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

    /// Judge a reset travelling in this entry's direction (`reply` names its
    /// sender) by its sequence number. See [`ResetCheck`].
    #[inline(always)]
    pub fn reset_check(&self, seq: u32) -> ResetCheck {
        // Explicit branches instead of indexing keep bounds-check panics out of
        // the eBPF object.
        let (known, expected, window) = if self.reply & 1 == 0 {
            (
                self.track & Self::TRACK_ACK1 != 0,
                self.acks[1],
                self.windows[1],
            )
        } else {
            (
                self.track & Self::TRACK_ACK0 != 0,
                self.acks[0],
                self.windows[0],
            )
        };
        if !known {
            return ResetCheck::Unknown;
        }
        if seq == expected {
            return ResetCheck::Exact;
        }
        let scaled = (window as u32) << 14;
        let bound = if scaled > RESET_WINDOW_MAX {
            RESET_WINDOW_MAX
        } else {
            scaled
        };
        // Either side of the last ACK: reordering can leave the recorded ACK
        // slightly behind or ahead of the endpoint's real RCV.NXT.
        if seq.wrapping_sub(expected) <= bound || expected.wrapping_sub(seq) <= bound {
            ResetCheck::InWindow
        } else {
            ResetCheck::Invalid
        }
    }

    /// Record the sequence evidence of one admitted segment sent in this
    /// entry's direction. `old_phase` is the phase before the transition this
    /// segment caused. Resets never move the evidence: a forged one must not
    /// teach the tracker a sequence number.
    #[inline(always)]
    pub fn track_segment(&mut self, old_phase: u32, control: u8, ack: u32, window: u16) {
        if control & tcp_flags::RST != 0 {
            return;
        }
        let syn = control & tcp_flags::SYN != 0;
        let has_ack = control & tcp_flags::ACK != 0;
        if old_phase == Self::ESTABLISHED && self.phase == Self::SYN_RECV {
            // The responder accepted a reopening SYN: a new sequence space.
            self.track = 0;
        }
        let initiator = self.reply & 1 == 0;
        if initiator {
            self.windows[0] = window;
            if has_ack {
                self.acks[0] = ack;
                self.track |= Self::TRACK_ACK0;
            }
            if control & tcp_flags::FIN != 0 {
                self.track |= Self::TRACK_FIN0;
            }
            if syn && !has_ack && self.phase == Self::ESTABLISHED {
                self.track |= Self::TRACK_REOPEN;
            }
        } else {
            self.windows[1] = window;
            if has_ack {
                self.acks[1] = ack;
                self.track |= Self::TRACK_ACK1;
            }
            if control & tcp_flags::FIN != 0 {
                self.track |= Self::TRACK_FIN1;
            }
            if !syn {
                self.track &= !Self::TRACK_REOPEN;
            }
        }
    }
}

/// NAT binding (`FlowState`) TCP lifetime bits, kept in `FlowState::_pad`. The
/// field never crosses the HA wire (sync encodes it as zero), so an imported
/// or legacy binding reads as "established", exactly its previous lifetime.
pub mod nat_lifetime {
    /// Created by a SYN; no non-SYN segment has been accounted to it yet.
    pub const EMBRYONIC: u16 = 1;
    /// A FIN has been accounted to this binding.
    pub const FIN: u16 = 2;
    /// A reset has been accounted to this binding.
    pub const RESET: u16 = 4;
    const KNOWN: u16 = EMBRYONIC | FIN | RESET;

    /// Lifetime bits after one TCP segment with `control` flags was translated
    /// through the binding. Non-TCP bindings never carry bits.
    #[inline(always)]
    pub fn observe(bits: u16, proto: u8, control: u8) -> u16 {
        if proto != crate::ip_proto::TCP {
            return bits;
        }
        let mut bits = bits & KNOWN;
        if control & crate::tcp_flags::RST != 0 {
            bits |= RESET;
        } else if control & crate::tcp_flags::SYN == 0 {
            bits &= !EMBRYONIC;
        }
        if control & crate::tcp_flags::FIN != 0 {
            bits |= FIN;
        }
        bits
    }

    /// Bits for a binding a packet with `control` is about to create.
    #[inline(always)]
    pub fn opening(proto: u8, control: u8) -> u16 {
        if proto == crate::ip_proto::TCP && control & crate::tcp_flags::SYN != 0 {
            EMBRYONIC
        } else {
            0
        }
    }

    /// Idle timeout of a NAT binding. UDP/ICMP and bits-free TCP keep the
    /// historical "established" timeout.
    #[inline(always)]
    pub fn timeout_ns(bits: u16, proto: u8, timeouts: crate::ConntrackTimeouts) -> u64 {
        let seconds = if proto == crate::ip_proto::TCP {
            if bits & RESET != 0 {
                timeouts.tcp_closing
            } else if bits & FIN != 0 {
                if timeouts.tcp_closing > super::HALF_CLOSE_MIN_S {
                    timeouts.tcp_closing
                } else {
                    super::HALF_CLOSE_MIN_S
                }
            } else if bits & EMBRYONIC != 0 {
                timeouts.tcp_syn
            } else {
                timeouts.tcp_established
            }
        } else if proto == crate::ip_proto::UDP {
            timeouts.udp_stream
        } else {
            timeouts.icmp
        };
        seconds as u64 * 1_000_000_000
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
            ..FirewallState::UNTRACKED
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
                ..FirewallState::UNTRACKED
            };
            let end = 100 + seconds * 1_000_000_000;
            assert!(!state.expired(proto, end - 1, custom));
            assert!(state.expired(proto, end, custom));
            assert!(!state.expired(proto, 99, custom));
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
        assert_eq!(core::mem::size_of::<FirewallState>(), 40);
    }

    fn closing() -> FirewallState {
        FirewallState {
            last_seen_ns: 1,
            age_ns: 0,
            phase: FirewallState::CLOSING,
            reply: 0,
            ..FirewallState::UNTRACKED
        }
    }

    #[test]
    fn a_closing_tuple_opener_needs_new_policy_not_established_admission() {
        assert_eq!(closing().classify(6, tcp_flags::SYN, 2, T), 0);
        assert!(closing().next_phase(6, tcp_flags::SYN).is_none());
        assert_eq!(
            FirewallState {
                reply: 1,
                ..closing()
            }
            .classify(6, tcp_flags::SYN, 2, T),
            0
        );
        assert_eq!(closing().classify(6, tcp_flags::ACK, 2, T), 1);
    }

    #[test]
    fn active_connections_forward_an_initiator_syn_without_changing_state() {
        let state = FirewallState {
            phase: FirewallState::ESTABLISHED,
            reply: 0,
            ..closing()
        };
        // DP-25b: a SYN reusing a silently dead tuple is forwarded, but the
        // established state stays until the responder answers with a SYN-ACK.
        assert_eq!(state.classify(6, tcp_flags::SYN, 2, T), 1);
        assert_eq!(
            state.next_phase(6, tcp_flags::SYN),
            Some(FirewallState::ESTABLISHED)
        );
        // The responder never opens with a bare SYN on a live tuple.
        let responder = FirewallState { reply: 1, ..state };
        assert_eq!(responder.classify(6, tcp_flags::SYN, 2, T), 2);
    }

    #[test]
    fn malformed_syn_flags_cannot_reopen_closing_or_reset_state() {
        for phase in [FirewallState::CLOSING, FirewallState::RESET] {
            let state = FirewallState { phase, ..closing() };
            for flags in [
                tcp_flags::SYN | tcp_flags::FIN,
                tcp_flags::SYN | tcp_flags::RST,
                tcp_flags::SYN | tcp_flags::ACK,
            ] {
                assert_eq!(state.classify(6, flags, 2, T), 2);
            }
            assert_eq!(state.classify(6, tcp_flags::SYN, 2, T), 0);
        }
    }

    #[test]
    fn live_routed_tcp_responder_keeps_its_tuple_from_synack_to_close() {
        let state = FirewallState {
            phase: FirewallState::NEW,
            reply: 1,
            ..closing()
        };
        assert!(state.is_routed_reply(6, tcp_flags::SYN | tcp_flags::ACK, 2, T));
        assert!(!FirewallState { reply: 0, ..state }.is_routed_reply(6, tcp_flags::SYN, 2, T));
        for phase in [FirewallState::ESTABLISHED, FirewallState::CLOSING] {
            let state = FirewallState { phase, ..state };
            assert!(state.is_routed_reply(6, tcp_flags::ACK, 2, T));
            assert!(!state.is_routed_reply(6, tcp_flags::SYN, 2, T));
        }
    }

    #[test]
    fn invalid_or_untracked_looking_response_does_not_gain_nat_exemption() {
        let state = FirewallState {
            phase: FirewallState::NEW,
            reply: 1,
            ..closing()
        };
        for flags in [
            tcp_flags::ACK,
            tcp_flags::SYN,
            tcp_flags::SYN | tcp_flags::FIN,
        ] {
            assert!(!state.is_routed_reply(6, flags, 2, T));
        }
        assert!(!state.is_routed_reply(1, 0, 2, T));
        assert!(!FirewallState { reply: 2, ..state }.is_routed_reply(17, 0, 2, T));
    }

    #[test]
    fn reply_exemption_expires_but_survives_a_concurrent_refresh() {
        let state = FirewallState {
            phase: FirewallState::ESTABLISHED,
            reply: 1,
            ..closing()
        };
        let deadline = 1 + T.tcp_established as u64 * 1_000_000_000;
        assert!(state.is_routed_reply(6, tcp_flags::ACK, deadline - 1, T));
        assert!(!state.is_routed_reply(6, tcp_flags::ACK, deadline, T));
        assert!(state.is_routed_reply(6, tcp_flags::ACK, 0, T));
    }

    #[test]
    fn a_newer_cpu_refresh_does_not_expire_a_live_connection() {
        let state = FirewallState {
            last_seen_ns: 1_000_000_001,
            age_ns: 0,
            phase: FirewallState::ESTABLISHED,
            reply: 0,
            ..FirewallState::UNTRACKED
        };
        // Deterministic interleaving: A reads the clock, B refreshes the map,
        // then A reads the map. The old subtraction expired/deleted this flow.
        let sampled_before_refresh = 1_000_000_000;
        assert_eq!(state.idle_ns(sampled_before_refresh), 0);
        assert_eq!(state.classify(6, ACK, sampled_before_refresh, T), 1);
        assert!(state.observe(6, ACK, sampled_before_refresh, T).is_some());
        // Carried peer age still applies, including at the timeout boundary.
        assert!(
            FirewallState {
                age_ns: T.tcp_established as u64 * 1_000_000_000,
                ..state
            }
            .expired(6, sampled_before_refresh, T)
        );
    }

    #[test]
    fn udp_response_metadata_is_directional_and_time_bounded() {
        let state = FirewallState {
            phase: FirewallState::NEW,
            reply: 1,
            ..closing()
        };
        assert!(state.is_routed_reply(17, 0, 2, T));
        assert!(!FirewallState { reply: 0, ..state }.is_routed_reply(17, 0, 2, T));
        assert!(!state.is_routed_reply(17, 0, 1 + T.udp as u64 * 1_000_000_000, T));
    }

    fn established(reply: u32) -> FirewallState {
        FirewallState {
            last_seen_ns: 1,
            phase: FirewallState::ESTABLISHED,
            reply,
            acks: [1_000, 5_000],
            windows: [512, 64],
            track: FirewallState::TRACK_ACK0 | FirewallState::TRACK_ACK1,
            ..FirewallState::UNTRACKED
        }
    }

    #[test]
    fn state_layout_appends_tracking_after_the_replicated_fields() {
        assert_eq!(core::mem::size_of::<FirewallState>(), 40);
        assert_eq!(core::mem::offset_of!(FirewallState, phase), 16);
        assert_eq!(core::mem::offset_of!(FirewallState, reply), 20);
        assert_eq!(core::mem::offset_of!(FirewallState, acks), 24);
        assert_eq!(core::mem::offset_of!(FirewallState, windows), 32);
        assert_eq!(core::mem::offset_of!(FirewallState, track), 36);
    }

    #[test]
    fn a_reset_is_exact_only_at_the_receivers_last_ack() {
        // Responder (reply 1) resets: judged against the initiator's ACK.
        let server = established(1);
        assert_eq!(server.reset_check(1_000), ResetCheck::Exact);
        assert_eq!(server.reset_check(1_001), ResetCheck::InWindow);
        assert_eq!(server.reset_check(999), ResetCheck::InWindow);
        assert_eq!(
            server.reset_check(1_000 + (512 << 14)),
            ResetCheck::InWindow
        );
        assert_eq!(
            server.reset_check(1_000 + (512 << 14) + 1),
            ResetCheck::Invalid
        );
        // The tcp-reset-validation fixture's blind displacement.
        assert_eq!(
            server.reset_check(1_000u32.wrapping_add(0x4000_0000)),
            ResetCheck::Invalid
        );
        // Initiator (reply 0) resets: judged against the responder's ACK/window.
        let client = established(0);
        assert_eq!(client.reset_check(5_000), ResetCheck::Exact);
        assert_eq!(client.reset_check(5_000 + (64 << 14)), ResetCheck::InWindow);
        assert_eq!(client.reset_check(5_001 + (64 << 14)), ResetCheck::Invalid);
    }

    #[test]
    fn reset_window_is_capped_and_wraps_serially() {
        let mut state = established(1);
        state.windows[0] = u16::MAX;
        state.acks[0] = u32::MAX - 10;
        assert_eq!(state.reset_check(5), ResetCheck::InWindow);
        assert_eq!(
            state.reset_check((u32::MAX - 10).wrapping_add(RESET_WINDOW_MAX + 1)),
            ResetCheck::Invalid
        );
        state.windows[0] = 0;
        assert_eq!(state.reset_check(u32::MAX - 10), ResetCheck::Exact);
        assert_eq!(state.reset_check(u32::MAX - 9), ResetCheck::Invalid);
    }

    #[test]
    fn an_unobserved_receiver_ack_gives_no_sequence_evidence() {
        let mut state = established(1);
        state.track = FirewallState::TRACK_ACK1;
        assert_eq!(state.reset_check(12_345), ResetCheck::Unknown);
        // Imported/legacy state carries no tracking at all.
        let legacy = FirewallState::untracked(1, 0, FirewallState::ESTABLISHED, 0);
        assert_eq!(legacy.reset_check(0), ResetCheck::Unknown);
    }

    #[test]
    fn tracking_records_ack_window_and_fin_per_direction_but_never_from_reset() {
        let mut state = FirewallState::untracked(1, 0, FirewallState::ESTABLISHED, 0);
        state.track_segment(FirewallState::ESTABLISHED, ACK, 77, 9);
        assert_eq!((state.acks, state.windows), ([77, 0], [9, 0]));
        assert_eq!(state.track, FirewallState::TRACK_ACK0);
        let mut reverse = state.reverse();
        reverse.track_segment(FirewallState::ESTABLISHED, ACK | tcp_flags::FIN, 88, 3);
        assert_eq!((reverse.acks, reverse.windows), ([77, 88], [9, 3]));
        assert_eq!(
            reverse.track,
            FirewallState::TRACK_ACK0 | FirewallState::TRACK_ACK1 | FirewallState::TRACK_FIN1
        );
        let before = reverse;
        reverse.track_segment(FirewallState::ESTABLISHED, tcp_flags::RST | ACK, 1, 1);
        assert_eq!(reverse, before);
    }

    #[test]
    fn retransmitted_synack_after_established_is_valid_and_keeps_state() {
        let server = established(1);
        assert_eq!(server.classify(6, SYN | ACK, 2, T), 1);
        assert_eq!(
            server.next_phase(6, SYN | ACK),
            Some(FirewallState::ESTABLISHED)
        );
    }

    #[test]
    fn a_reopening_syn_becomes_a_new_connection_only_after_the_synack() {
        let mut client = established(0);
        let old = client.phase;
        client.phase = client.next_phase(6, SYN).unwrap();
        client.track_segment(old, SYN, 0, 100);
        assert_ne!(client.track & FirewallState::TRACK_REOPEN, 0);
        // A live endpoint answers with a challenge ACK: reopen is cancelled.
        let mut live = client.reverse();
        live.phase = live.next_phase(6, ACK).unwrap();
        live.track_segment(FirewallState::ESTABLISHED, ACK, 5_000, 64);
        assert_eq!(live.track & FirewallState::TRACK_REOPEN, 0);
        assert_eq!(live.phase, FirewallState::ESTABLISHED);
        // A dead endpoint's replacement answers SYN-ACK: new sequence space.
        let mut fresh = client.reverse();
        let old = fresh.phase;
        fresh.phase = fresh.next_phase(6, SYN | ACK).unwrap();
        assert_eq!(fresh.phase, FirewallState::SYN_RECV);
        fresh.track_segment(old, SYN | ACK, 4242, 10);
        assert_eq!(fresh.track, FirewallState::TRACK_ACK1);
        assert_eq!(fresh.reset_check(1), ResetCheck::Unknown);
    }

    #[test]
    fn half_close_outlives_the_closing_timeout_but_full_close_does_not() {
        let mut state = established(0);
        state.phase = FirewallState::CLOSING;
        state.track |= FirewallState::TRACK_FIN0;
        assert_eq!(
            state.timeout_ns(6, T),
            HALF_CLOSE_MIN_S as u64 * 1_000_000_000
        );
        state.track |= FirewallState::TRACK_FIN1;
        assert_eq!(state.timeout_ns(6, T), T.tcp_closing as u64 * 1_000_000_000);
        // Legacy CLOSING without FIN evidence keeps the configured timeout.
        let legacy = FirewallState::untracked(1, 0, FirewallState::CLOSING, 0);
        assert_eq!(
            legacy.timeout_ns(6, T),
            T.tcp_closing as u64 * 1_000_000_000
        );
        let long = ConntrackTimeouts {
            tcp_closing: 600,
            ..T
        };
        state.track &= !FirewallState::TRACK_FIN1;
        assert_eq!(state.timeout_ns(6, long), 600 * 1_000_000_000);
    }

    #[test]
    fn only_real_stack_flag_combinations_are_plausible() {
        const PSH: u8 = 0x08;
        const URG: u8 = 0x20;
        for valid in [
            SYN,
            SYN | ACK,
            SYN | URG,
            ACK,
            ACK | PSH,
            ACK | URG | PSH,
            tcp_flags::RST,
            tcp_flags::RST | ACK,
            tcp_flags::FIN | ACK,
            tcp_flags::FIN | ACK | PSH,
            SYN | 0x40 | 0x80,
        ] {
            assert!(FirewallState::tcp_flags_plausible(valid), "{valid:#x}");
        }
        for invalid in [
            0,
            tcp_flags::FIN,
            tcp_flags::FIN | PSH | URG,
            SYN | tcp_flags::FIN,
            SYN | tcp_flags::RST,
            tcp_flags::RST | tcp_flags::FIN | ACK,
            PSH,
            SYN | ACK | tcp_flags::FIN,
        ] {
            assert!(!FirewallState::tcp_flags_plausible(invalid), "{invalid:#x}");
        }
    }

    #[test]
    fn nat_bindings_get_lifetimes_from_what_crossed_them() {
        use super::nat_lifetime::{EMBRYONIC, FIN, RESET, observe, opening, timeout_ns};
        let s = |n: u32| n as u64 * 1_000_000_000;
        assert_eq!(opening(6, SYN), EMBRYONIC);
        assert_eq!(opening(6, ACK), 0);
        assert_eq!(opening(17, 0), 0);
        assert_eq!(timeout_ns(EMBRYONIC, 6, T), s(T.tcp_syn));
        assert_eq!(
            timeout_ns(observe(EMBRYONIC, 6, SYN | ACK), 6, T),
            s(T.tcp_syn)
        );
        let established = observe(EMBRYONIC, 6, ACK);
        assert_eq!(established, 0);
        assert_eq!(timeout_ns(established, 6, T), s(T.tcp_established));
        assert_eq!(
            timeout_ns(observe(0, 6, tcp_flags::FIN | ACK), 6, T),
            s(HALF_CLOSE_MIN_S)
        );
        assert_eq!(
            timeout_ns(observe(FIN, 6, tcp_flags::RST), 6, T),
            s(T.tcp_closing)
        );
        assert_eq!(observe(0, 6, tcp_flags::RST) & RESET, RESET);
        // Legacy/imported (zero) bits keep the historical lifetime.
        assert_eq!(timeout_ns(0, 6, T), s(T.tcp_established));
        assert_eq!(timeout_ns(0, 17, T), s(T.udp_stream));
        assert_eq!(timeout_ns(0, 1, T), s(T.icmp));
        // Unknown bits are discarded, non-TCP never gains bits.
        assert_eq!(observe(0xff00, 6, ACK), 0);
        assert_eq!(observe(0, 17, tcp_flags::FIN), 0);
    }
}
