//! Sequence-aware TCP tracking primitives, not an endpoint implementation.
//!
//! This module is deliberately independent of maps, packet parsers and policy.
//! Callers must parse the complete segment, verify its checksum/options/length,
//! and apply their real policy before committing a transition. It does not
//! currently replace the deployed flags-only firewall state machine.
//!
//! Direction 0 is ALWAYS the admitted SYN initiator; direction 1 is its peer.
//! Reversing a lookup key must not reverse these stored records. Sequence
//! comparisons use RFC 9293 serial arithmetic; cumulative ACK evidence is never
//! inferred from the largest sequence seen or from SACK blocks. RFC 5961's
//! challenge-ACK case is `Preserve`, not a state deletion or idle refresh.

use crate::{ConntrackTimeouts, tcp_flags};

const HALF: u32 = 1 << 31;
const MAX_WINDOW: u32 = 65535 << 14;
const MAX_AGE: u64 = 604_800_000_000_000;

/// ABI of the plain snapshot, NOT the existing VCS2 firewall wire format.
pub const TCP_STATE_ABI: u32 = 1;
/// A normalized absent window-scale option; zero is a real offered scale.
pub const TCP_SCALE_ABSENT: u32 = 255;
/// Full-segment checksum, declared length, and option parsing proved by caller.
pub const TCP_SEGMENT_VALIDATED: u32 = 7;

/// All numeric fields permit zero; flags distinguish initialized sequence zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpPeer {
    pub syn_seq: u32,
    /// Highest observed, window-admissible send end, including SYN/FIN.
    pub end: u32,
    /// ACK OF this peer's bytes, observed in the opposite peer's segment.
    pub max_ack: u32,
    pub window_raw: u32,
    /// Sequence of this peer's most recent accepted window advertisement.
    pub window_seq: u32,
    /// Current cumulative ACK freshness floor SENT by this peer; equal to the
    /// opposite peer's initialized max_ack, not a lifetime-old advertisement.
    pub window_ack: u32,
    pub max_window: u32,
    pub fin_seq: u32,
    pub flags: u32,
    pub scale: u32,
}

impl TcpPeer {
    pub const SYN_SEEN: u32 = 1;
    pub const SYN_ACKED: u32 = 2;
    pub const ACK_SEEN: u32 = 4;
    pub const WS_OFFERED: u32 = 8;
    pub const FIN_SEEN: u32 = 16;
    pub const FIN_ACKED: u32 = 32;
    pub const WINDOW_SEEN: u32 = 64;
    pub const WINDOW_ACK_VALID: u32 = 128;
    /// The current advertised window came from a SYN and remains unscaled.
    pub const WINDOW_SYN: u32 = 256;
    const KNOWN: u32 = 511;

    #[inline(always)]
    pub fn has(&self, bits: u32) -> bool {
        self.flags & bits == bits
    }

    fn valid(&self) -> bool {
        if self.flags == 0 {
            return *self == Self::default();
        }
        if self.flags & !Self::KNOWN != 0
            || !self.has(Self::SYN_SEEN | Self::WINDOW_SEEN)
            || self.window_raw > 65535
            || self.max_window > MAX_WINDOW
            || self.max_window < self.window_raw
            || self.scale > 14
            || (!self.has(Self::WS_OFFERED) && self.scale != 0)
            || (!self.has(Self::ACK_SEEN) && self.max_ack != 0)
            || (self.has(Self::SYN_ACKED) != self.has(Self::ACK_SEEN))
            || (!self.has(Self::FIN_SEEN) && self.fin_seq != 0)
            || (self.has(Self::FIN_ACKED) && !self.has(Self::FIN_SEEN | Self::ACK_SEEN))
            || (!self.has(Self::WINDOW_ACK_VALID) && self.window_ack != 0)
            || (self.has(Self::WINDOW_SYN) && self.window_seq != self.syn_seq)
        {
            return false;
        }
        if self.has(Self::ACK_SEEN)
            && (before(self.end, self.max_ack) || self.end.wrapping_sub(self.max_ack) >= HALF)
        {
            return false;
        }
        if self.has(Self::FIN_SEEN)
            && (self.end != self.fin_seq.wrapping_add(1)
                || (self.has(Self::FIN_ACKED)
                    && before(self.max_ack, self.fin_seq.wrapping_add(1))))
        {
            return false;
        }
        true
    }
}

/// Portable, lock-free snapshot. No node-local clock or local revision occurs
/// here. `policy_epoch` identifies a shared admission domain under an already
/// authenticated FULL policy fingerprint; it is not a node's config counter.
/// A caller must additionally check HA authority, ordering and incarnation.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSnapshot {
    /// Owner-allocated nonzero identity, never reused while old packet/HA/GC
    /// references could survive. This model cannot implement that allocator.
    pub incarnation: u64,
    pub policy_epoch: u64,
    pub age_ns: u64,
    pub abi: u32,
    pub phase: u32,
    pub terminal_flags: u32,
    pub reserved: u32,
    pub peers: [TcpPeer; 2],
}

/// Lock belongs to a future top-level BPF HASH value, not to this pure model.
/// All classify/commit/reopen/GC operations must be serialized by that owner.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSession {
    pub snapshot: TcpSnapshot,
    pub last_seen_ns: u64,
    pub revision: u64,
}

/// Trusted parser output, not wire bytes. `validated` must equal 7 only after
/// complete checksum, declared-length and option validation. Window scale is
/// normalized to 0..14 or 255(absent), and occurs only on SYN segments. SACK
/// cannot substitute for the cumulative ACK. TCP segmentation offload requires
/// a separately proven parser/checksum boundary before this contract is usable.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    pub seq: u32,
    pub ack: u32,
    pub payload_len: u32,
    pub window: u32,
    pub flags: u32,
    pub scale: u32,
    pub validated: u32,
    pub reserved: u32,
}

impl TcpSegment {
    #[inline(always)]
    fn has(&self, flags: u8) -> bool {
        self.flags & flags as u32 == flags as u32
    }

    fn valid(&self) -> bool {
        self.validated == TCP_SEGMENT_VALIDATED
            && self.reserved == 0
            && self.flags <= 255
            && self.payload_len <= 65535
            && self.window <= 65535
            && (self.scale == TCP_SCALE_ABSENT || (self.has(tcp_flags::SYN) && self.scale <= 14))
    }

    #[inline(always)]
    fn end(&self) -> u32 {
        self.seq
            .wrapping_add(self.payload_len)
            .wrapping_add(self.has(tcp_flags::SYN) as u32)
            .wrapping_add(self.has(tcp_flags::FIN) as u32)
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpDisposition {
    Invalid = 0,
    Advance = 1,
    /// May be forwarded under the existing policy, but changes NO state.
    Preserve = 2,
    /// Caller must still deliver the validated reset/final ACK through every
    /// required policy hook; this is not a generic terminal reply permission.
    Retire = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpReason {
    Valid = 0,
    Input = 1,
    State = 2,
    Expired = 3,
    Terminal = 4,
    Sequence = 5,
    Acknowledgment = 6,
    Handshake = 7,
    ResetExact = 8,
    ResetChallenge = 9,
    ResetUncertain = 10,
    ZeroWindowProbe = 11,
    OldSyn = 12,
    Closed = 13,
    Revision = 14,
    FinUncertain = 15,
}

/// Local compare-and-commit token. It is NOT a packet authorization, wire
/// record, cross-CPU scratch receipt or substitute for holding the session lock.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpDecision {
    pub incarnation: u64,
    pub policy_epoch: u64,
    pub revision: u64,
    pub disposition: TcpDisposition,
    pub reason: TcpReason,
}

#[inline(always)]
fn before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

#[inline(always)]
fn between(value: u32, first: u32, last: u32) -> bool {
    last.wrapping_sub(first) < HALF && value.wrapping_sub(first) <= last.wrapping_sub(first)
}

impl TcpSnapshot {
    /// Structural validation only; authenticity, policy and replay are external.
    pub fn valid(&self) -> bool {
        if self.abi != TCP_STATE_ABI
            || self.incarnation == 0
            || self.policy_epoch == 0
            || self.age_ns > MAX_AGE
            || self.reserved != 0
            || !matches!(self.phase, 1..=6)
            || !self.peers[0].has(TcpPeer::SYN_SEEN)
            || !self.peers.iter().all(TcpPeer::valid)
        {
            return false;
        }
        let scaled = self.peers.iter().all(|p| p.has(TcpPeer::WS_OFFERED));
        for i in 0..2 {
            let peer = self.peers[i];
            let opposite = self.peers[1 - i];
            let max = 65535 << if scaled { peer.scale } else { 0 };
            let current = peer.window_raw
                << if scaled && !peer.has(TcpPeer::WINDOW_SYN) {
                    peer.scale
                } else {
                    0
                };
            if (peer.has(TcpPeer::ACK_SEEN) && !opposite.has(TcpPeer::SYN_SEEN))
                || (peer.has(TcpPeer::WINDOW_ACK_VALID) && !opposite.has(TcpPeer::ACK_SEEN))
                || peer.has(TcpPeer::WINDOW_ACK_VALID) != opposite.has(TcpPeer::ACK_SEEN)
                || (peer.has(TcpPeer::WINDOW_ACK_VALID) && peer.window_ack != opposite.max_ack)
                || peer.max_window > max
                || peer.max_window < current
            {
                return false;
            }
        }
        let both_acked = self.peers.iter().all(|p| p.has(TcpPeer::SYN_ACKED));
        match self.phase {
            TcpSession::SYN_SENT => {
                self.terminal_flags == 0
                    && self.peers[1] == TcpPeer::default()
                    && !self.peers[0].has(TcpPeer::ACK_SEEN)
                    && !self.peers[0].has(TcpPeer::FIN_SEEN)
                    && self.peers[0].has(TcpPeer::WINDOW_SYN)
                    && between(
                        self.peers[0].end,
                        self.peers[0].syn_seq.wrapping_add(1),
                        self.peers[0].syn_seq.wrapping_add(65536),
                    )
            }
            TcpSession::SYN_RECV => {
                self.terminal_flags == 0
                    && self.peers[1].has(TcpPeer::SYN_SEEN)
                    && !both_acked
                    && self.peers.iter().all(|p| {
                        between(
                            p.end,
                            p.syn_seq.wrapping_add(1),
                            p.syn_seq.wrapping_add(HALF - 1),
                        ) && (!p.has(TcpPeer::ACK_SEEN)
                            || between(p.max_ack, p.syn_seq.wrapping_add(1), p.end))
                    })
            }
            TcpSession::ESTABLISHED => {
                self.terminal_flags == 0
                    && both_acked
                    && self.peers.iter().all(|p| !p.has(TcpPeer::FIN_SEEN))
            }
            TcpSession::CLOSING => {
                self.terminal_flags == 0
                    && both_acked
                    && self.peers.iter().any(|p| p.has(TcpPeer::FIN_SEEN))
                    && !self.peers.iter().all(|p| p.has(TcpPeer::FIN_ACKED))
            }
            TcpSession::RETIRED => {
                self.terminal_flags == TcpSession::BY_RST
                    || (self.terminal_flags == TcpSession::BY_FIN
                        && both_acked
                        && self.peers.iter().all(|p| p.has(TcpPeer::FIN_ACKED)))
            }
            TcpSession::GC_PENDING => {
                matches!(self.terminal_flags, 0 | TcpSession::BY_RST)
                    || (self.terminal_flags == TcpSession::BY_FIN
                        && both_acked
                        && self.peers.iter().all(|p| p.has(TcpPeer::FIN_ACKED)))
            }
            _ => false,
        }
    }
}

impl TcpSession {
    pub const SYN_SENT: u32 = 1;
    pub const SYN_RECV: u32 = 2;
    pub const ESTABLISHED: u32 = 3;
    pub const CLOSING: u32 = 4;
    pub const RETIRED: u32 = 5;
    pub const GC_PENDING: u32 = 6;
    pub const BY_RST: u32 = 1;
    pub const BY_FIN: u32 = 2;

    /// Call ONLY after an actual new-flow policy decision; this API does not
    /// confer permission. SYN payload (including TFO) consumes sequence space.
    pub fn open_admitted(
        segment: TcpSegment,
        incarnation: u64,
        policy_epoch: u64,
        now: u64,
    ) -> Option<Self> {
        if !segment.valid()
            || incarnation == 0
            || policy_epoch == 0
            || segment.flags
                & (tcp_flags::SYN | tcp_flags::ACK | tcp_flags::FIN | tcp_flags::RST) as u32
                != tcp_flags::SYN as u32
        {
            return None;
        }
        Some(Self {
            snapshot: TcpSnapshot {
                incarnation,
                policy_epoch,
                age_ns: 0,
                abi: TCP_STATE_ABI,
                phase: Self::SYN_SENT,
                terminal_flags: 0,
                reserved: 0,
                peers: [Self::first_syn(segment), TcpPeer::default()],
            },
            last_seen_ns: now,
            revision: 1,
        })
    }

    fn first_syn(segment: TcpSegment) -> TcpPeer {
        TcpPeer {
            syn_seq: segment.seq,
            end: segment.end(),
            window_raw: segment.window,
            window_seq: segment.seq,
            max_window: segment.window,
            flags: TcpPeer::SYN_SEEN
                | TcpPeer::WINDOW_SEEN
                | TcpPeer::WINDOW_SYN
                | if segment.scale == TCP_SCALE_ABSENT {
                    0
                } else {
                    TcpPeer::WS_OFFERED
                },
            scale: if segment.scale == TCP_SCALE_ABSENT {
                0
            } else {
                segment.scale
            },
            ..TcpPeer::default()
        }
    }

    #[inline(always)]
    pub fn idle_ns(&self, now: u64) -> u64 {
        now.saturating_sub(self.last_seen_ns)
            .saturating_add(self.snapshot.age_ns)
    }

    pub fn expired(&self, now: u64, timeouts: ConntrackTimeouts) -> bool {
        let seconds = match self.snapshot.phase {
            Self::ESTABLISHED => timeouts.tcp_established,
            Self::CLOSING | Self::RETIRED | Self::GC_PENDING => timeouts.tcp_closing,
            _ => timeouts.tcp_syn,
        };
        self.idle_ns(now) >= seconds as u64 * 1_000_000_000
    }

    /// Export a plain relative-age snapshot. No remote absolute clock is used.
    pub fn export(&self, now: u64) -> Option<TcpSnapshot> {
        if self.revision == 0 {
            return None;
        }
        let mut snapshot = self.snapshot;
        snapshot.age_ns = self.idle_ns(now);
        snapshot.valid().then_some(snapshot)
    }

    /// Constructs a FRESH, fenced local object only, never an in-place update
    /// of a live same-incarnation session (which would reset its revision).
    /// Caller authenticates authority/order/full policy fingerprint FIRST.
    /// A local config epoch must not be silently substituted for this domain.
    pub fn import(snapshot: TcpSnapshot, expected_policy_epoch: u64, now: u64) -> Option<Self> {
        (snapshot.valid() && snapshot.policy_epoch == expected_policy_epoch).then_some(Self {
            snapshot,
            last_seen_ns: now,
            revision: 1,
        })
    }

    /// New admission and a different incarnation are compulsory. GC_PENDING
    /// cannot be reused: deletion must finish before any new map insertion.
    pub fn reopen_admitted(
        &self,
        segment: TcpSegment,
        incarnation: u64,
        policy_epoch: u64,
        now: u64,
        timeouts: ConntrackTimeouts,
    ) -> Option<Self> {
        if !self.snapshot.valid()
            || self.revision == 0
            || self.snapshot.phase == Self::GC_PENDING
            || (self.snapshot.phase != Self::RETIRED && !self.expired(now, timeouts))
            || incarnation == self.snapshot.incarnation
        {
            return None;
        }
        Self::open_admitted(segment, incarnation, policy_epoch, now)
    }

    /// Mark an expired/terminal entry for deletion WHILE holding its lock.
    /// All later users must reject GC_PENDING; owner may then delete that exact
    /// incarnation after unlock. This method performs no deletion/reclamation.
    pub fn begin_gc(
        &mut self,
        incarnation: u64,
        revision: u64,
        now: u64,
        t: ConntrackTimeouts,
    ) -> bool {
        if !self.snapshot.valid()
            || self.snapshot.incarnation != incarnation
            || self.revision != revision
            || self.revision == 0
            || self.revision == u64::MAX
            || self.snapshot.phase == Self::GC_PENDING
            || (self.snapshot.phase != Self::RETIRED && !self.expired(now, t))
        {
            return false;
        }
        self.snapshot.phase = Self::GC_PENDING;
        self.revision += 1;
        true
    }

    pub fn evaluate(
        &self,
        segment: TcpSegment,
        direction: u32,
        now: u64,
        t: ConntrackTimeouts,
    ) -> TcpDecision {
        let mut candidate = *self;
        let (disposition, reason) = candidate.step(segment, direction, now, t);
        TcpDecision {
            incarnation: self.snapshot.incarnation,
            policy_epoch: self.snapshot.policy_epoch,
            revision: self.revision,
            disposition,
            reason,
        }
    }

    /// Must run under the SAME session lock as competing writers. Revalidates
    /// the complete transition, never trusts a stale classification alone.
    /// Preserve returns true but leaves every byte, including lifetime, intact.
    pub fn commit(
        &mut self,
        decision: TcpDecision,
        segment: TcpSegment,
        direction: u32,
        now: u64,
        t: ConntrackTimeouts,
    ) -> bool {
        if decision.incarnation != self.snapshot.incarnation
            || decision.policy_epoch != self.snapshot.policy_epoch
            || decision.revision != self.revision
            || decision.disposition == TcpDisposition::Invalid
        {
            return false;
        }
        let mut candidate = *self;
        let result = candidate.step(segment, direction, now, t);
        if result != (decision.disposition, decision.reason) {
            return false;
        }
        if decision.disposition != TcpDisposition::Preserve {
            candidate.last_seen_ns = now.max(self.last_seen_ns);
            candidate.snapshot.age_ns = 0;
            candidate.revision += 1;
            if !candidate.snapshot.valid() {
                return false;
            }
            *self = candidate;
        }
        true
    }

    fn scaled_window(&self, peer: usize, syn: bool) -> u32 {
        let p = self.snapshot.peers[peer];
        let negotiated = self
            .snapshot
            .peers
            .iter()
            .all(|p| p.has(TcpPeer::WS_OFFERED));
        p.window_raw
            << if negotiated && !syn && !p.has(TcpPeer::WINDOW_SYN) {
                p.scale
            } else {
                0
            }
    }

    fn step(
        &mut self,
        segment: TcpSegment,
        direction: u32,
        now: u64,
        t: ConntrackTimeouts,
    ) -> (TcpDisposition, TcpReason) {
        use TcpDisposition::{Advance, Invalid, Preserve, Retire};
        if !segment.valid() || direction > 1 {
            return (Invalid, TcpReason::Input);
        }
        if !self.snapshot.valid() || self.revision == 0 {
            return (Invalid, TcpReason::State);
        }
        if self.revision == u64::MAX {
            return (Invalid, TcpReason::Revision);
        }
        if matches!(self.snapshot.phase, Self::RETIRED | Self::GC_PENDING) {
            return (Invalid, TcpReason::Terminal);
        }
        if self.expired(now, t) {
            return (Invalid, TcpReason::Expired);
        }
        let i = direction as usize;
        let j = 1 - i;
        let sender = self.snapshot.peers[i];
        let receiver = self.snapshot.peers[j];

        // Reset validation precedes ordinary ACK/FIN processing. A synchronized
        // endpoint checks reset SEQ, not a forged ACK used to poison max_ack.
        if segment.has(tcp_flags::RST) {
            if self.snapshot.phase == Self::SYN_SENT && i == 1 {
                if !segment.has(tcp_flags::ACK)
                    || !between(segment.ack, receiver.syn_seq.wrapping_add(1), receiver.end)
                {
                    return (Invalid, TcpReason::Acknowledgment);
                }
            } else if sender.has(TcpPeer::ACK_SEEN) {
                if segment.seq != sender.max_ack {
                    let window = self.scaled_window(j, false);
                    return if window != 0
                        && between(
                            segment.seq,
                            sender.max_ack,
                            sender.max_ack.wrapping_add(window - 1),
                        ) {
                        (Preserve, TcpReason::ResetChallenge)
                    } else {
                        (Invalid, TcpReason::Sequence)
                    };
                }
                if sender.end != sender.max_ack {
                    // The receiver may already have accepted these observed
                    // bytes but delayed/lost its ACK. Even exact LAST OBSERVED
                    // ACK is then not proof of the endpoint's current RCV.NXT.
                    return (Preserve, TcpReason::ResetUncertain);
                }
            } else {
                // No authenticated receive frontier is known. Let the actual
                // endpoint decide, but do not invent one from observed end.
                return (Preserve, TcpReason::ResetUncertain);
            }
            self.snapshot.phase = Self::RETIRED;
            self.snapshot.terminal_flags = Self::BY_RST;
            return (Retire, TcpReason::ResetExact);
        }

        if segment.has(tcp_flags::SYN) {
            if segment.has(tcp_flags::FIN) {
                return (Invalid, TcpReason::Handshake);
            }
            if sender.has(TcpPeer::SYN_SEEN) {
                if segment.seq != sender.syn_seq
                    || before(sender.end, segment.end())
                    || (segment.scale != TCP_SCALE_ABSENT) != sender.has(TcpPeer::WS_OFFERED)
                    || (segment.scale != TCP_SCALE_ABSENT && segment.scale != sender.scale)
                {
                    return (Invalid, TcpReason::Handshake);
                }
                if matches!(self.snapshot.phase, Self::ESTABLISHED | Self::CLOSING) {
                    return (Preserve, TcpReason::OldSyn);
                }
            } else if i != 1 || !receiver.has(TcpPeer::SYN_SEEN) {
                return (Invalid, TcpReason::Handshake);
            } else {
                self.snapshot.peers[i] = Self::first_syn(segment);
            }
            if segment.has(tcp_flags::ACK) && !self.acknowledge(i, segment.ack, true) {
                return (Invalid, TcpReason::Acknowledgment);
            }
            self.window(i, segment, true);
            if self.snapshot.peers[1].has(TcpPeer::SYN_SEEN) {
                self.snapshot.phase = if self
                    .snapshot
                    .peers
                    .iter()
                    .all(|p| p.has(TcpPeer::SYN_ACKED))
                {
                    Self::ESTABLISHED
                } else {
                    Self::SYN_RECV
                };
            }
            return (Advance, TcpReason::Valid);
        }

        if !segment.has(tcp_flags::ACK)
            || !sender.has(TcpPeer::SYN_SEEN)
            || !receiver.has(TcpPeer::SYN_SEEN)
        {
            return (Invalid, TcpReason::Handshake);
        }
        let left = if sender.has(TcpPeer::ACK_SEEN) {
            sender.max_ack
        } else {
            sender.syn_seq.wrapping_add(1)
        };
        let window = self.scaled_window(j, false);
        let handshake = matches!(self.snapshot.phase, Self::SYN_SENT | Self::SYN_RECV);
        if (handshake && before(segment.seq, left))
            || (segment.payload_len == 0
                && !segment.has(tcp_flags::FIN)
                && before(sender.end, segment.seq))
        {
            // A pure ACK cannot prove that unobserved payload was sent, and an
            // old/out-of-window sequence cannot complete the handshake.
            return (Invalid, TcpReason::Sequence);
        }
        if sender.has(TcpPeer::FIN_SEEN)
            && ((!segment.has(tcp_flags::FIN)
                && segment.payload_len != 0
                && before(sender.fin_seq, segment.end()))
                || before(sender.fin_seq.wrapping_add(1), segment.end()))
        {
            return (Invalid, TcpReason::Sequence);
        }
        if window == 0 {
            if segment.payload_len <= 1
                && !segment.has(tcp_flags::FIN)
                && (segment.seq == left.wrapping_sub(1)
                    || (segment.payload_len == 1 && segment.seq == left))
            {
                // Zero-window/keepalive probe is not evidence that data arrived.
                return if self.acknowledge(i, segment.ack, false) {
                    (Preserve, TcpReason::ZeroWindowProbe)
                } else {
                    (Invalid, TcpReason::Acknowledgment)
                };
            }
            if segment.seq != left || segment.payload_len != 0 || segment.has(tcp_flags::FIN) {
                return (Invalid, TcpReason::Sequence);
            }
        } else {
            let low = left.wrapping_sub(receiver.max_window.max(1));
            let right = left.wrapping_add(window);
            let length = segment.payload_len + segment.has(tcp_flags::FIN) as u32;
            let sequence_ok = if length == 0 {
                between(segment.seq, low, right.wrapping_sub(1))
            } else {
                (between(segment.seq, low, right.wrapping_sub(1)) && !before(segment.end(), low))
                    || (between(segment.end().wrapping_sub(1), left, right.wrapping_sub(1))
                        && !before(segment.seq, low))
            };
            if !sequence_ok {
                return (Invalid, TcpReason::Sequence);
            }
        }
        if !self.acknowledge(i, segment.ack, handshake) {
            return (Invalid, TcpReason::Acknowledgment);
        }
        if segment.has(tcp_flags::FIN)
            && !sender.has(TcpPeer::FIN_SEEN)
            && before(segment.end(), sender.end)
        {
            // We already observed bytes after this purported end of stream.
            // They may have arrived at the endpoint. Do not shorten lifetime
            // or manufacture a contradictory FIN/end snapshot.
            return (Preserve, TcpReason::FinUncertain);
        }
        let mut end = segment.end();
        if window != 0 && before(left.wrapping_add(window), end) {
            // Data past the peer's advertised right edge is not delivery/ACK
            // evidence. An endpoint may trim a partially overlapping segment.
            end = left.wrapping_add(window);
        }
        if before(self.snapshot.peers[i].end, end) {
            self.snapshot.peers[i].end = end;
        }
        if segment.has(tcp_flags::FIN) {
            let fin = segment.seq.wrapping_add(segment.payload_len);
            let in_window = window != 0 && between(fin, left, left.wrapping_add(window - 1));
            if sender.has(TcpPeer::FIN_SEEN) {
                if sender.fin_seq != fin {
                    return (Invalid, TcpReason::Sequence);
                }
            } else if in_window {
                self.snapshot.peers[i].flags |= TcpPeer::FIN_SEEN;
                self.snapshot.peers[i].fin_seq = fin;
            }
        }
        self.window(i, segment, false);
        let both_acked = self
            .snapshot
            .peers
            .iter()
            .all(|p| p.has(TcpPeer::SYN_ACKED));
        if !both_acked {
            self.snapshot.phase = Self::SYN_RECV;
        } else if self
            .snapshot
            .peers
            .iter()
            .all(|p| p.has(TcpPeer::FIN_ACKED))
        {
            self.snapshot.phase = Self::RETIRED;
            self.snapshot.terminal_flags = Self::BY_FIN;
            return (Retire, TcpReason::Closed);
        } else if self.snapshot.peers.iter().any(|p| p.has(TcpPeer::FIN_SEEN)) {
            self.snapshot.phase = Self::CLOSING;
        } else {
            self.snapshot.phase = Self::ESTABLISHED;
        }
        (Advance, TcpReason::Valid)
    }

    fn acknowledge(&mut self, i: usize, ack: u32, handshake: bool) -> bool {
        let j = 1 - i;
        let sender = self.snapshot.peers[i];
        let peer = &mut self.snapshot.peers[j];
        if !peer.has(TcpPeer::SYN_SEEN)
            || before(peer.end, ack)
            || peer.end.wrapping_sub(ack) >= HALF
            || (handshake && !between(ack, peer.syn_seq.wrapping_add(1), peer.end))
            || (peer.has(TcpPeer::ACK_SEEN)
                && before(ack, peer.max_ack.wrapping_sub(sender.max_window.max(1))))
        {
            return false;
        }
        if !peer.has(TcpPeer::ACK_SEEN) || before(peer.max_ack, ack) {
            peer.max_ack = ack;
        }
        peer.flags |= TcpPeer::ACK_SEEN | TcpPeer::SYN_ACKED;
        if peer.has(TcpPeer::FIN_SEEN) && !before(ack, peer.fin_seq.wrapping_add(1)) {
            peer.flags |= TcpPeer::FIN_ACKED;
        }
        let floor = peer.max_ack;
        self.snapshot.peers[i].window_ack = floor;
        self.snapshot.peers[i].flags |= TcpPeer::WINDOW_ACK_VALID;
        true
    }

    fn window(&mut self, i: usize, segment: TcpSegment, syn: bool) {
        let scaled = segment.window
            << if !syn
                && self
                    .snapshot
                    .peers
                    .iter()
                    .all(|p| p.has(TcpPeer::WS_OFFERED))
            {
                self.snapshot.peers[i].scale
            } else {
                0
            };
        let peer = &mut self.snapshot.peers[i];
        let fresh_ack = if segment.has(tcp_flags::ACK) {
            !peer.has(TcpPeer::WINDOW_ACK_VALID) || !before(segment.ack, peer.window_ack)
        } else {
            !peer.has(TcpPeer::WINDOW_ACK_VALID)
        };
        let fresh =
            fresh_ack && (before(peer.window_seq, segment.seq) || peer.window_seq == segment.seq);
        if fresh {
            peer.window_raw = segment.window;
            peer.window_seq = segment.seq;
            if syn {
                peer.flags |= TcpPeer::WINDOW_SYN;
            } else {
                peer.flags &= !TcpPeer::WINDOW_SYN;
            }
            peer.max_window = peer.max_window.max(scaled);
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpPeer {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpSnapshot {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpSession {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for TcpSegment {}

#[cfg(test)]
mod tests {
    use tcp_flags::{ACK, FIN, RST, SYN};

    use super::*;

    const T: ConntrackTimeouts = ConntrackTimeouts::DEFAULT;

    fn seg(seq: u32, ack: u32, flags: u8) -> TcpSegment {
        TcpSegment {
            seq,
            ack,
            payload_len: 0,
            window: 4096,
            flags: flags as u32,
            scale: TCP_SCALE_ABSENT,
            validated: TCP_SEGMENT_VALIDATED,
            reserved: 0,
        }
    }

    fn apply(session: &mut TcpSession, packet: TcpSegment, direction: u32) -> TcpDecision {
        let now = session.last_seen_ns + 1;
        let decision = session.evaluate(packet, direction, now, T);
        assert_ne!(
            decision.disposition,
            TcpDisposition::Invalid,
            "{decision:?} {packet:?}"
        );
        assert!(session.commit(decision, packet, direction, now, T));
        assert!(session.snapshot.valid());
        decision
    }

    fn established_at(client: u32, server: u32) -> TcpSession {
        let mut session = TcpSession::open_admitted(seg(client, 0, SYN), 11, 17, 100).unwrap();
        apply(
            &mut session,
            seg(server, client.wrapping_add(1), SYN | ACK),
            1,
        );
        apply(
            &mut session,
            seg(client.wrapping_add(1), server.wrapping_add(1), ACK),
            0,
        );
        assert_eq!(session.snapshot.phase, TcpSession::ESTABLISHED);
        session
    }

    fn established() -> TcpSession {
        established_at(100, 1000)
    }

    fn invalid_unchanged(session: &mut TcpSession, packet: TcpSegment, direction: u32) {
        let before = *session;
        let decision = session.evaluate(packet, direction, session.last_seen_ns + 1, T);
        assert_eq!(
            decision.disposition,
            TcpDisposition::Invalid,
            "{decision:?} {packet:?}"
        );
        assert!(!session.commit(decision, packet, direction, session.last_seen_ns + 1, T));
        assert_eq!(*session, before);
    }

    #[test]
    fn fixed_abi_has_no_implicit_padding_or_local_clock_in_snapshot() {
        assert_eq!(core::mem::size_of::<TcpPeer>(), 40);
        assert_eq!(core::mem::size_of::<TcpSnapshot>(), 120);
        assert_eq!(core::mem::size_of::<TcpSession>(), 136);
        assert_eq!(core::mem::size_of::<TcpSegment>(), 32);
        assert_eq!(core::mem::size_of::<TcpDecision>(), 32);
        assert_eq!(core::mem::offset_of!(TcpSnapshot, peers), 40);
        assert_eq!(core::mem::offset_of!(TcpSession, last_seen_ns), 120);
    }

    #[test]
    fn all_flag_openers_require_syn_without_ack_fin_or_rst() {
        for flags in 0..=255 {
            let opened = TcpSession::open_admitted(seg(0, 0, flags), 1, 1, 0);
            let expected = flags & (SYN | ACK | FIN | RST) == SYN;
            assert_eq!(opened.is_some(), expected, "flags={flags}");
            if let Some(state) = opened {
                assert!(state.snapshot.valid());
                assert_eq!(state.snapshot.peers[0].end, 1);
            }
        }
        assert!(TcpSession::open_admitted(seg(0, 0, SYN), 0, 1, 0).is_none());
        assert!(TcpSession::open_admitted(seg(0, 0, SYN), 1, 0, 0).is_none());
    }

    #[test]
    fn rfc5961_reset_boundaries_keep_challenge_authority() {
        // ACK frontier1001, peer receive window4096. No generated expected
        // values from the state machine: these are literal RFC boundary cases.
        for (seq, expected) in [
            (0, TcpDisposition::Invalid),
            (1000, TcpDisposition::Invalid),
            (1001, TcpDisposition::Retire),
            (1002, TcpDisposition::Preserve),
            (5096, TcpDisposition::Preserve),
            (5097, TcpDisposition::Invalid),
            (0x400003e9, TcpDisposition::Invalid),
        ] {
            let mut state = established();
            let before = state;
            // RST ACK deliberately nonsensical: it must never poison ACK state.
            let packet = seg(seq, 0x12345678, RST | ACK);
            let decision = state.evaluate(packet, 1, 110, T);
            assert_eq!(decision.disposition, expected, "seq={seq}");
            if expected == TcpDisposition::Invalid {
                assert!(!state.commit(decision, packet, 1, 110, T));
            } else {
                assert!(state.commit(decision, packet, 1, 110, T));
            }
            if expected != TcpDisposition::Retire {
                assert_eq!(state, before);
            } else {
                assert_eq!(state.snapshot.phase, TcpSession::RETIRED);
                assert_eq!(state.snapshot.terminal_flags, TcpSession::BY_RST);
                invalid_unchanged(&mut state, seg(101, 1001, ACK), 0);
            }
        }
    }

    #[test]
    fn observed_data_end_is_not_receiver_ack_frontier() {
        let mut state = established();
        let mut data = seg(1001, 101, ACK);
        data.payload_len = 200;
        apply(&mut state, data, 1);
        assert_eq!(state.snapshot.peers[1].end, 1201);
        assert_eq!(state.snapshot.peers[1].max_ack, 1001);
        let before = state;
        assert_eq!(
            apply(&mut state, seg(1001, 101, RST | ACK), 1).reason,
            TcpReason::ResetUncertain
        );
        assert_eq!(state, before); // Delayed ACK or lost data: cannot tell which.
        assert_eq!(
            apply(&mut state, seg(1201, 101, RST | ACK), 1).disposition,
            TcpDisposition::Preserve
        );
        assert_eq!(state, before);
        apply(&mut state, seg(101, 1201, ACK), 0);
        assert_eq!(state.snapshot.peers[1].max_ack, 1201);
        assert_eq!(
            apply(&mut state, seg(1201, 101, RST | ACK), 1).disposition,
            TcpDisposition::Retire
        );
    }

    #[test]
    fn handshake_ack_must_ack_actual_syn_bytes_and_reject_wrong_sequence() {
        let mut state = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 0).unwrap();
        for ack in [0, 100, 102, u32::MAX] {
            invalid_unchanged(&mut state, seg(1000, ack, SYN | ACK), 1);
        }
        apply(&mut state, seg(1000, 101, SYN | ACK), 1);
        invalid_unchanged(&mut state, seg(100, 1001, ACK), 0);
        invalid_unchanged(&mut state, seg(102, 1001, ACK), 0);
        invalid_unchanged(&mut state, seg(50000, 1001, ACK), 0);
        invalid_unchanged(&mut state, seg(101, 1002, ACK), 0);
        apply(&mut state, seg(101, 1001, ACK), 0);
        assert_eq!(state.snapshot.phase, TcpSession::ESTABLISHED);
    }

    #[test]
    fn syn_sent_reset_and_fast_open_ack_range() {
        let mut syn = seg(u32::MAX - 2, 0, SYN);
        syn.payload_len = 5;
        for ack in [u32::MAX - 1, u32::MAX, 0, 1, 2, 3] {
            let mut state = TcpSession::open_admitted(syn, 1, 1, 0).unwrap();
            assert_eq!(
                apply(&mut state, seg(777, ack, RST | ACK), 1).disposition,
                TcpDisposition::Retire
            );
        }
        let mut state = TcpSession::open_admitted(syn, 1, 1, 0).unwrap();
        for ack in [u32::MAX - 2, 4, 0x40000000] {
            invalid_unchanged(&mut state, seg(777, ack, RST | ACK), 1);
        }
        invalid_unchanged(&mut state, seg(777, 0, RST), 1);
    }

    #[test]
    fn retransmits_reordering_duplicate_acks_and_window_updates() {
        let mut state = established();
        let mut data = seg(151, 1001, ACK);
        data.payload_len = 50;
        apply(&mut state, data, 0); // Out of order, receiver has not ACKed gap.
        assert_eq!(state.snapshot.peers[0].max_ack, 101);
        data.seq = 101;
        apply(&mut state, data, 0);
        apply(&mut state, data, 0); // Duplicate segment cannot reduce end.
        assert_eq!(state.snapshot.peers[0].end, 201);
        apply(&mut state, seg(1001, 201, ACK), 1);
        apply(&mut state, seg(1001, 151, ACK), 1); // Old ACK cannot roll back.
        assert_eq!(state.snapshot.peers[0].max_ack, 201);
        let mut changed = seg(1001, 201, ACK);
        changed.window = 1024;
        apply(&mut state, changed, 1);
        assert_eq!(state.snapshot.peers[1].window_raw, 1024);
        changed.ack = 151;
        changed.window = 0;
        apply(&mut state, changed, 1);
        assert_eq!(state.snapshot.peers[1].window_raw, 1024);
    }

    #[test]
    fn ack_or_sequence_forgery_cannot_extend_bounds_or_expiry() {
        let mut state = established();
        for seq in [10000, 0x80000065, u32::MAX - 10000] {
            invalid_unchanged(&mut state, seg(seq, 1001, ACK), 0);
        }
        invalid_unchanged(&mut state, seg(102, 1001, ACK), 0);
        for ack in [1002, 0x800003e9, u32::MAX - 10000] {
            invalid_unchanged(&mut state, seg(101, ack, ACK), 0);
        }
        let mut fin = seg(10000, 1001, FIN | ACK);
        invalid_unchanged(&mut state, fin, 0);
        fin.seq = 101;
        fin.ack = 99999;
        invalid_unchanged(&mut state, fin, 0);
    }

    #[test]
    fn sequence_wrap_and_zero_initialized_ack_are_lossless() {
        for client in [0, 1, 100, u32::MAX - 4, u32::MAX] {
            for server in [0, 1, 1000, u32::MAX - 4, u32::MAX] {
                let mut state = established_at(client, server);
                let mut data = seg(client.wrapping_add(1), server.wrapping_add(1), ACK);
                data.payload_len = 32;
                apply(&mut state, data, 0);
                apply(
                    &mut state,
                    seg(server.wrapping_add(1), client.wrapping_add(33), ACK),
                    1,
                );
                assert_eq!(state.snapshot.peers[0].max_ack, client.wrapping_add(33));
                assert_eq!(
                    apply(&mut state, seg(client.wrapping_add(33), 0, RST), 0).disposition,
                    TcpDisposition::Retire
                );
            }
        }
    }

    #[test]
    fn established_snapshot_frontiers_are_not_limited_by_lifetime_isn_span() {
        let mut snapshot = established_at(0, 0).snapshot;
        // A long-lived connection has advanced more than half the sequence
        // space since its SYN. Only CURRENT bounded distances remain ordered.
        snapshot.peers[0].end = 0x90000001;
        snapshot.peers[0].max_ack = 0x90000001;
        snapshot.peers[0].window_seq = 0x90000001;
        snapshot.peers[1].window_ack = 0x90000001;
        assert!(snapshot.valid());
        let mut state = TcpSession::import(snapshot, 17, 5000).unwrap();
        apply(&mut state, seg(0x90000001, 1, ACK), 0);
        assert_eq!(
            apply(&mut state, seg(0x90000001, 1, RST), 0).disposition,
            TcpDisposition::Retire
        );
    }

    #[test]
    fn all_scales_require_bilateral_offer_and_syn_windows_are_unscaled() {
        for client_scale in 0..=14 {
            for server_scale in 0..=14 {
                let mut syn = seg(100, 0, SYN);
                syn.scale = client_scale;
                syn.window = 100;
                let mut state = TcpSession::open_admitted(syn, 1, 1, 0).unwrap();
                let mut synack = seg(1000, 101, SYN | ACK);
                synack.window = 200;
                synack.scale = server_scale;
                apply(&mut state, synack, 1);
                assert_eq!(state.scaled_window(1, true), 200);
                assert_eq!(state.scaled_window(1, false), 200);
                let mut ack = seg(101, 1001, ACK);
                ack.window = 100;
                apply(&mut state, ack, 0);
                assert_eq!(state.scaled_window(0, false), 100 << client_scale);
                assert_eq!(state.snapshot.peers[0].max_window, 100 << client_scale);
                let mut advertised = seg(1001, 101, ACK);
                advertised.window = 200;
                apply(&mut state, advertised, 1);
                assert_eq!(state.scaled_window(1, false), 200 << server_scale);
            }
        }
        let mut syn = seg(100, 0, SYN);
        syn.scale = 14;
        let mut state = TcpSession::open_admitted(syn, 1, 1, 0).unwrap();
        apply(&mut state, seg(1000, 101, SYN | ACK), 1);
        apply(&mut state, seg(101, 1001, ACK), 0);
        assert_eq!(state.scaled_window(0, false), 4096);
    }

    #[test]
    fn zero_window_probes_preserve_and_window_recovery_works() {
        let mut state = established();
        let mut zero = seg(1001, 101, ACK);
        zero.window = 0;
        apply(&mut state, zero, 1);
        for seq in [100, 101] {
            let mut probe = seg(seq, 1001, ACK);
            probe.payload_len = 1;
            let before = state;
            assert_eq!(
                apply(&mut state, probe, 0).disposition,
                TcpDisposition::Preserve
            );
            assert_eq!(state, before);
        }
        let mut data = seg(101, 1001, ACK);
        data.payload_len = 2;
        invalid_unchanged(&mut state, data, 0);
        assert_eq!(
            apply(&mut state, seg(101, 0, RST), 0).disposition,
            TcpDisposition::Retire
        );
        let mut state = established();
        apply(&mut state, zero, 1);
        zero.window = 100;
        apply(&mut state, zero, 1);
        apply(&mut state, data, 0);
    }

    #[test]
    fn fin_consumes_one_sequence_and_requires_both_actual_acknowledgments() {
        let mut state = established();
        apply(&mut state, seg(101, 1001, FIN | ACK), 0);
        assert_eq!(state.snapshot.phase, TcpSession::CLOSING);
        assert_eq!(state.snapshot.peers[0].fin_seq, 101);
        apply(&mut state, seg(101, 1001, FIN | ACK), 0); // Same FIN retransmit.
        invalid_unchanged(&mut state, seg(102, 1001, FIN | ACK), 0);
        let mut late_data = seg(101, 1001, ACK);
        late_data.payload_len = 1; // Cannot overwrite the already seen FIN.
        invalid_unchanged(&mut state, late_data, 0);
        apply(&mut state, seg(1001, 102, ACK), 1);
        assert!(state.snapshot.peers[0].has(TcpPeer::FIN_ACKED));
        apply(&mut state, seg(1001, 102, FIN | ACK), 1);
        assert_eq!(
            apply(&mut state, seg(102, 1002, ACK), 0).disposition,
            TcpDisposition::Retire
        );
        assert_eq!(state.snapshot.terminal_flags, TcpSession::BY_FIN);
        invalid_unchanged(&mut state, seg(102, 1002, ACK), 0);
    }

    #[test]
    fn partial_right_window_overlap_cannot_fabricate_fin_or_send_end() {
        let mut state = established();
        let mut window = seg(1001, 101, ACK);
        window.window = 10;
        apply(&mut state, window, 1);
        let mut data = seg(106, 1001, FIN | ACK);
        data.payload_len = 20;
        apply(&mut state, data, 0);
        assert_eq!(state.snapshot.peers[0].end, 111);
        assert!(!state.snapshot.peers[0].has(TcpPeer::FIN_SEEN));
        invalid_unchanged(&mut state, seg(1001, 127, ACK), 1);
    }

    #[test]
    fn simultaneous_open_and_old_syn_retransmit_do_not_reopen_established() {
        let mut state = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 0).unwrap();
        apply(&mut state, seg(1000, 0, SYN), 1);
        apply(&mut state, seg(100, 1001, SYN | ACK), 0);
        apply(&mut state, seg(1000, 101, SYN | ACK), 1);
        assert_eq!(state.snapshot.phase, TcpSession::ESTABLISHED);
        let before = state;
        assert_eq!(
            apply(&mut state, seg(100, 0, SYN), 0).disposition,
            TcpDisposition::Preserve
        );
        assert_eq!(state, before);
        invalid_unchanged(&mut state, seg(101, 0, SYN), 0);
    }

    #[test]
    fn bad_parser_proofs_options_fields_and_directions_never_mutate() {
        let good = seg(101, 1001, ACK);
        for validated in 0..=15 {
            if validated != TCP_SEGMENT_VALIDATED {
                let mut packet = good;
                packet.validated = validated;
                invalid_unchanged(&mut established(), packet, 0);
            }
        }
        for packet in [
            TcpSegment { flags: 256, ..good },
            TcpSegment {
                payload_len: 65536,
                ..good
            },
            TcpSegment {
                window: 65536,
                ..good
            },
            TcpSegment { scale: 0, ..good },
            TcpSegment {
                reserved: 1,
                ..good
            },
        ] {
            invalid_unchanged(&mut established(), packet, 0);
        }
        for scale in 15..=254 {
            assert!(
                TcpSession::open_admitted(
                    TcpSegment {
                        scale,
                        ..seg(100, 0, SYN)
                    },
                    1,
                    1,
                    0
                )
                .is_none()
            );
        }
        for direction in [2, 3, u32::MAX] {
            invalid_unchanged(&mut established(), good, direction);
        }
    }

    #[test]
    fn stale_revision_incarnation_epoch_or_changed_packet_cannot_commit() {
        let mut state = established();
        let packet = seg(101, 1001, ACK);
        let decision = state.evaluate(packet, 0, 110, T);
        apply(&mut state, packet, 0);
        assert!(!state.commit(decision, packet, 0, 111, T));
        let good = state.evaluate(packet, 0, 112, T);
        for bad in [
            TcpDecision {
                incarnation: 12,
                ..good
            },
            TcpDecision {
                policy_epoch: 18,
                ..good
            },
            TcpDecision {
                revision: 0,
                ..good
            },
            TcpDecision {
                disposition: TcpDisposition::Retire,
                ..good
            },
        ] {
            let before = state;
            assert!(!state.commit(bad, packet, 0, 112, T));
            assert_eq!(state, before);
        }
        assert!(!state.commit(good, seg(101, 1002, ACK), 0, 112, T));
        state.revision = u64::MAX;
        invalid_unchanged(&mut state, packet, 0);
    }

    #[test]
    fn relative_age_import_expiry_new_incarnation_and_gc_are_explicit() {
        let mut state = established();
        let snapshot = state.export(1000).unwrap();
        let imported = TcpSession::import(snapshot, 17, 5000).unwrap();
        assert_eq!(imported.idle_ns(5020), state.idle_ns(1020));
        assert!(TcpSession::import(snapshot, 18, 5000).is_none());
        assert!(
            state
                .reopen_admitted(seg(7, 0, SYN), 12, 17, 110, T)
                .is_none()
        );
        apply(&mut state, seg(1001, 101, RST | ACK), 1);
        assert!(
            state
                .reopen_admitted(seg(7, 0, SYN), 11, 17, 110, T)
                .is_none()
        );
        let reopened = state
            .reopen_admitted(seg(7, 0, SYN), 12, 17, 110, T)
            .unwrap();
        assert_eq!(reopened.snapshot.incarnation, 12);
        assert_eq!(reopened.snapshot.phase, TcpSession::SYN_SENT);
        assert!(!state.begin_gc(12, state.revision, 110, T));
        assert!(state.begin_gc(11, state.revision, 110, T));
        assert!(
            state
                .reopen_admitted(seg(7, 0, SYN), 12, 17, 110, T)
                .is_none()
        );
        let mut expired = established();
        let now = expired.last_seen_ns + 86400 * 1_000_000_000;
        let packet = seg(101, 1001, ACK);
        assert_eq!(
            expired.evaluate(packet, 0, now, T).reason,
            TcpReason::Expired
        );
        assert!(
            expired
                .reopen_admitted(seg(7, 0, SYN), 12, 17, now, T)
                .is_some()
        );
        assert!(expired.begin_gc(11, expired.revision, now, T));
    }

    #[test]
    fn snapshot_validation_rejects_unknown_or_contradictory_metadata() {
        let good = established().snapshot;
        for snapshot in [
            TcpSnapshot { abi: 0, ..good },
            TcpSnapshot {
                incarnation: 0,
                ..good
            },
            TcpSnapshot {
                policy_epoch: 0,
                ..good
            },
            TcpSnapshot { phase: 0, ..good },
            TcpSnapshot {
                reserved: 1,
                ..good
            },
            TcpSnapshot {
                terminal_flags: 1,
                ..good
            },
            TcpSnapshot {
                phase: TcpSession::RETIRED,
                ..good
            },
            TcpSnapshot {
                age_ns: MAX_AGE + 1,
                ..good
            },
        ] {
            assert!(!snapshot.valid(), "{snapshot:?}");
        }
        for bit in 9..32 {
            let mut snapshot = good;
            snapshot.peers[0].flags |= 1 << bit;
            assert!(!snapshot.valid());
        }
        for peer in [
            TcpPeer {
                scale: 15,
                ..good.peers[0]
            },
            TcpPeer {
                scale: 1,
                ..good.peers[0]
            },
            TcpPeer {
                window_raw: 65536,
                ..good.peers[0]
            },
            TcpPeer {
                max_window: MAX_WINDOW + 1,
                ..good.peers[0]
            },
            TcpPeer {
                flags: good.peers[0].flags | TcpPeer::FIN_ACKED,
                ..good.peers[0]
            },
            TcpPeer {
                flags: good.peers[0].flags & !TcpPeer::ACK_SEEN,
                ..good.peers[0]
            },
            TcpPeer {
                flags: good.peers[0].flags & !TcpPeer::SYN_SEEN,
                ..good.peers[0]
            },
            TcpPeer {
                max_ack: 102,
                ..good.peers[0]
            },
            TcpPeer {
                fin_seq: 1,
                ..good.peers[0]
            },
        ] {
            let mut snapshot = good;
            snapshot.peers[0] = peer;
            assert!(!snapshot.valid(), "{snapshot:?}");
        }
    }

    #[test]
    fn exhaustive_small_window_reset_oracle_including_wrap_and_outstanding_data() {
        // Independent integer-distance oracle: exact current receive evidence,
        // strictly inside the offered window, and everywhere outside it.
        for base in [0u32, 1001, 0x80000000, u32::MAX - 16] {
            for width in 0..=64 {
                for outstanding in 0..=2 {
                    for distance in -2i32..=66 {
                        let mut state = established();
                        state.snapshot.peers[1].max_ack = base;
                        state.snapshot.peers[1].end = base.wrapping_add(outstanding);
                        state.snapshot.peers[0].window_ack = base;
                        state.snapshot.peers[0].window_raw = width;
                        assert!(state.snapshot.valid());
                        let seq = base.wrapping_add(distance as u32);
                        let packet = seg(seq, 0, RST);
                        let expected = if distance == 0 {
                            if outstanding == 0 {
                                TcpDisposition::Retire
                            } else {
                                TcpDisposition::Preserve
                            }
                        } else if distance > 0 && (distance as u32) < width {
                            TcpDisposition::Preserve
                        } else {
                            TcpDisposition::Invalid
                        };
                        let before = state;
                        let decision = state.evaluate(packet, 1, 110, T);
                        assert_eq!(
                            decision.disposition, expected,
                            "base={base} width={width} outstanding={outstanding} distance={distance}"
                        );
                        assert_eq!(
                            state.commit(decision, packet, 1, 110, T),
                            expected != TcpDisposition::Invalid
                        );
                        if expected != TcpDisposition::Retire {
                            assert_eq!(state, before);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn exhaustive_established_flag_priority_never_uses_flag_only_retirement() {
        for flags in 0..=255 {
            let state = established();
            let packet = seg(101, 1001, flags);
            let expected = if flags & RST != 0 {
                TcpDisposition::Retire
            } else if flags & SYN != 0 || flags & ACK == 0 {
                TcpDisposition::Invalid
            } else {
                TcpDisposition::Advance
            };
            assert_eq!(
                state.evaluate(packet, 0, 110, T).disposition,
                expected,
                "flags={flags}"
            );
            let wrong = TcpSegment {
                seq: 0x40000065,
                ..packet
            };
            assert_eq!(
                state.evaluate(wrong, 0, 110, T).disposition,
                TcpDisposition::Invalid,
                "wrong sequence flags={flags}"
            );
        }
    }

    #[test]
    fn snapshot_phase_and_fin_inconsistencies_are_rejected() {
        let mut syn = TcpSession::open_admitted(seg(0, 0, SYN), 1, 1, 0)
            .unwrap()
            .snapshot;
        syn.peers[0].flags |= TcpPeer::ACK_SEEN | TcpPeer::SYN_ACKED;
        syn.peers[0].max_ack = 1;
        assert!(!syn.valid());
        let mut state = established();
        apply(&mut state, seg(101, 1001, FIN | ACK), 0);
        let mut snapshot = state.snapshot;
        snapshot.peers[0].end = 103;
        assert!(!snapshot.valid());
        snapshot = established().snapshot;
        snapshot.phase = TcpSession::GC_PENDING;
        snapshot.terminal_flags = TcpSession::BY_FIN;
        assert!(!snapshot.valid());
    }

    #[test]
    fn fin_inside_observed_unacknowledged_data_is_preserved_without_closing() {
        let mut state = established();
        let mut data = seg(101, 1001, ACK);
        data.payload_len = 100;
        apply(&mut state, data, 0);
        let before = state;
        let decision = apply(&mut state, seg(150, 1001, FIN | ACK), 0);
        assert_eq!(decision.reason, TcpReason::FinUncertain);
        assert_eq!(state, before);
    }

    #[test]
    fn snapshots_enforce_negotiated_effective_window_bounds() {
        let mut state = established().snapshot;
        state.peers[0].max_window = MAX_WINDOW;
        assert!(!state.valid()); // No bilateral offer, impossible huge history.
        let mut state = established().snapshot;
        for peer in &mut state.peers {
            peer.flags |= TcpPeer::WS_OFFERED;
            peer.flags &= !TcpPeer::WINDOW_SYN;
            peer.scale = 14;
            peer.window_raw = 65535;
            peer.max_window = 65535;
        }
        assert!(!state.valid()); // Raw window is not its effective scaled size.
        for peer in &mut state.peers {
            peer.max_window = MAX_WINDOW;
        }
        assert!(state.valid());
        let mut invalid = established().snapshot;
        invalid.peers[0].window_ack = 1002;
        assert!(!invalid.valid());
        let mut syn = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 0)
            .unwrap()
            .snapshot;
        syn.peers[0].flags |= TcpPeer::WINDOW_ACK_VALID;
        syn.peers[0].window_ack = 123;
        assert!(!syn.valid());
    }

    #[test]
    fn evaluate_and_commit_agree_across_bounded_transition_matrix() {
        let syn = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 100).unwrap();
        let mut synrecv = syn;
        apply(&mut synrecv, seg(1000, 101, SYN | ACK), 1);
        let mut closing = established();
        apply(&mut closing, seg(101, 1001, FIN | ACK), 0);
        for initial in [syn, synrecv, established(), closing] {
            for direction in 0..=1 {
                for seq in [0, 100, 101, 102, 150, 1000, 1001, 1002, u32::MAX] {
                    for ack in [0, 100, 101, 102, 1000, 1001, 1002, u32::MAX] {
                        for flags in [
                            0,
                            SYN,
                            SYN | ACK,
                            ACK,
                            FIN | ACK,
                            RST,
                            RST | ACK,
                            ACK | 0x20,
                        ] {
                            for payload_len in [0, 1, 20, 100] {
                                let packet = TcpSegment {
                                    payload_len,
                                    ..seg(seq, ack, flags)
                                };
                                let now = initial.last_seen_ns + 1;
                                let decision = initial.evaluate(packet, direction, now, T);
                                let mut next = initial;
                                assert_eq!(
                                    next.commit(decision, packet, direction, now, T),
                                    decision.disposition != TcpDisposition::Invalid,
                                    "phase={} direction={direction} {packet:?} {decision:?}",
                                    initial.snapshot.phase
                                );
                                assert!(next.snapshot.valid());
                                if matches!(
                                    decision.disposition,
                                    TcpDisposition::Invalid | TcpDisposition::Preserve
                                ) {
                                    assert_eq!(next, initial);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn early_fin_waits_for_both_handshake_acknowledgments() {
        let mut state = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 100).unwrap();
        apply(&mut state, seg(1000, 101, SYN | ACK), 1);
        apply(&mut state, seg(1001, 101, FIN | ACK), 1);
        assert_eq!(state.snapshot.phase, TcpSession::SYN_RECV);
        apply(&mut state, seg(101, 1002, ACK), 0);
        assert_eq!(state.snapshot.phase, TcpSession::CLOSING);
        assert!(state.snapshot.peers[1].has(TcpPeer::FIN_ACKED));
    }

    #[test]
    fn current_ack_floor_survives_wrap_and_old_ack_at_new_sequence() {
        let mut state = established_at(u32::MAX - 4, 1000);
        let mut data = seg(u32::MAX - 3, 1001, ACK);
        data.payload_len = 20;
        apply(&mut state, data, 0);
        apply(&mut state, seg(1001, 16, ACK), 1);
        assert_eq!(state.snapshot.peers[0].max_ack, 16);
        assert_eq!(state.snapshot.peers[1].window_ack, 16);
        let mut response = seg(1001, 16, ACK);
        response.payload_len = 10;
        apply(&mut state, response, 1);
        let previous = state.snapshot.peers[1].window_raw;
        let mut stale_ack = seg(1011, 10, ACK);
        stale_ack.window = 0;
        apply(&mut state, stale_ack, 1);
        assert_eq!(state.snapshot.peers[1].window_raw, previous);
        assert_eq!(state.snapshot.peers[1].window_ack, 16);
        let mut simultaneous = TcpSession::open_admitted(seg(100, 0, SYN), 1, 1, 100).unwrap();
        apply(&mut simultaneous, seg(1000, 0, SYN), 1);
        apply(&mut simultaneous, seg(100, 1001, SYN | ACK), 0);
        let before = simultaneous.snapshot.peers[0];
        let mut old_syn = seg(100, 0, SYN);
        old_syn.window = 0;
        apply(&mut simultaneous, old_syn, 0);
        assert_eq!(simultaneous.snapshot.peers[0], before);
    }
}
