//! Protocol-aware firewall state, shared by host and kernel code.
//!
//! The caller validates header lengths, holds the map value's lock, checks
//! explicit policy denials first, and binds this state to a canonical key and
//! incarnation. All rejected/uncertain observations leave the value unchanged.
//! This is a passive tracker, not an endpoint TCP implementation: in particular
//! an RST that cannot be validated from observed acknowledgements may reach the
//! endpoint for challenge-ACK processing without modifying our state or timer.

use crate::{ip_proto, tcp_flags};

pub const MAX_FLOW_TIMEOUT_MS: u32 = 7 * 24 * 60 * 60 * 1_000;
pub const TCP_NO_WINDOW_SCALE: u8 = 255;
/// Includes the TCP header. Aggregated skb segments may exceed the wire IP
/// length field, but must stay below the sequence comparison half-space.
pub const MAX_TCP_SEGMENT_LEN: usize = (1 << 30) - 1;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowTimeouts {
    pub tcp_pending_ms: u32,
    pub tcp_established_ms: u32,
    pub tcp_closed_ms: u32,
    pub udp_unreplied_ms: u32,
    pub udp_replied_ms: u32,
    pub echo_ms: u32,
}

impl FlowTimeouts {
    pub const DEFAULT: Self = Self {
        tcp_pending_ms: 60_000,
        tcp_established_ms: 7_200_000,
        tcp_closed_ms: 10_000,
        udp_unreplied_ms: 30_000,
        udp_replied_ms: 180_000,
        echo_ms: 10_000,
    };

    #[inline(always)]
    pub const fn valid(self) -> bool {
        self.tcp_pending_ms > 0
            && self.tcp_pending_ms <= MAX_FLOW_TIMEOUT_MS
            && self.tcp_established_ms > 0
            && self.tcp_established_ms <= MAX_FLOW_TIMEOUT_MS
            && self.tcp_closed_ms > 0
            && self.tcp_closed_ms <= MAX_FLOW_TIMEOUT_MS
            && self.udp_unreplied_ms > 0
            && self.udp_unreplied_ms <= MAX_FLOW_TIMEOUT_MS
            && self.udp_replied_ms > 0
            && self.udp_replied_ms <= MAX_FLOW_TIMEOUT_MS
            && self.echo_ms > 0
            && self.echo_ms <= MAX_FLOW_TIMEOUT_MS
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowDirection {
    Forward,
    Reverse,
}
impl FlowDirection {
    #[inline(always)]
    pub const fn index(self) -> usize {
        match self {
            Self::Forward => 0,
            Self::Reverse => 1,
        }
    }
}

/// Parsed TCP metadata. Window scaling is negotiated only in SYNs. The parser
/// supplies TCP_NO_WINDOW_SCALE if the option is absent, and rejects malformed
/// options before this model. Sequence numbers stay in host byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    pub sequence: u32,
    pub acknowledgement: u32,
    pub payload_len: u32,
    pub window: u16,
    pub flags: u8,
    pub window_scale: u8,
}
/// Incremental TCP header validation shared by host parsing and BPF's bounded
/// loop helper. Each step consumes at most one option byte; completion is
/// explicit so partial scans cannot authorize a packet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpHeaderParser {
    packet: TcpSegment,
    header_len: u8,
    position: u8,
    remaining: u8,
    window_scale_option: bool,
    done: bool,
    failed: bool,
}
impl TcpHeaderParser {
    #[inline(always)]
    pub fn new(head: &[u8; 20], segment_len: usize) -> Option<Self> {
        let header_len = (head[12] >> 4) * 4;
        if !(20..=MAX_TCP_SEGMENT_LEN).contains(&segment_len)
            || header_len < 20
            || header_len as usize > segment_len
        {
            return None;
        }
        let packet = TcpSegment {
            sequence: u32::from_be_bytes([head[4], head[5], head[6], head[7]]),
            acknowledgement: u32::from_be_bytes([head[8], head[9], head[10], head[11]]),
            payload_len: (segment_len - header_len as usize) as u32,
            window: u16::from_be_bytes([head[14], head[15]]),
            flags: head[13],
            window_scale: TCP_NO_WINDOW_SCALE,
        };
        if !packet.valid() {
            return None;
        }
        Some(Self {
            packet,
            header_len,
            position: 20,
            remaining: 0,
            window_scale_option: false,
            done: false,
            failed: false,
        })
    }

    /// Return true while more bytes may be needed. The reader receives only
    /// offsets inside the declared header; ignored option bodies need no reads.
    #[inline(always)]
    pub fn step(&mut self, mut byte: impl FnMut(usize) -> Option<u8>) -> bool {
        if self.done || self.failed {
            return false;
        }
        let offset = self.position as usize;
        if offset >= self.header_len as usize {
            self.done = true;
            return false;
        }
        self.position += 1;
        if self.remaining == 255 {
            let Some(length) = byte(offset) else {
                self.failed = true;
                return false;
            };
            if length < 2
                || offset - 1 + length as usize > self.header_len as usize
                || self.window_scale_option
                    && (self.packet.flags & tcp_flags::SYN == 0
                        || length != 3
                        || self.packet.window_scale != TCP_NO_WINDOW_SCALE)
            {
                self.failed = true;
                return false;
            }
            self.remaining = length - 2;
        } else if self.remaining != 0 {
            if self.window_scale_option {
                let Some(scale) = byte(offset) else {
                    self.failed = true;
                    return false;
                };
                self.packet.window_scale = scale.min(14);
                self.window_scale_option = false;
            }
            self.remaining -= 1;
        } else {
            let Some(kind) = byte(offset) else {
                self.failed = true;
                return false;
            };
            match kind {
                0 => {
                    self.done = true;
                    return false;
                }
                1 => {}
                _ => {
                    self.window_scale_option = kind == 3;
                    self.remaining = 255;
                }
            }
        }
        true
    }

    #[inline(always)]
    pub fn finish(self) -> Option<TcpSegment> {
        if !self.failed
            && (self.done || self.position == self.header_len)
            && self.remaining == 0
            && self.packet.valid()
        {
            Some(self.packet)
        } else {
            None
        }
    }
}

impl TcpSegment {
    /// Parse exactly the IP-declared TCP bytes, excluding any Ethernet padding.
    /// The enclosing IP parser must reject non-initial fragments before calling.
    /// Unknown well-formed options are ignored; malformed or duplicate window
    /// scale options cannot seed a connection with ambiguous metadata.
    #[inline(always)]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let head: &[u8; 20] = bytes.get(..20)?.try_into().ok()?;
        Self::parse_header(head, bytes.len(), |offset| bytes.get(offset).copied())
    }

    /// Share option/metadata validation with BPF readers that must explicitly
    /// bounds-check every packet access for the verifier. `segment_len` is the
    /// IP-declared transport length, already checked against the actual frame.
    /// The reader only receives offsets within the declared TCP header.
    #[inline(always)]
    pub fn parse_header(
        head: &[u8; 20],
        segment_len: usize,
        mut byte: impl FnMut(usize) -> Option<u8>,
    ) -> Option<Self> {
        let mut parser = TcpHeaderParser::new(head, segment_len)?;
        for _ in 0..40 {
            if !parser.step(&mut byte) {
                break;
            }
        }
        parser.finish()
    }
    #[inline(always)]
    const fn valid(self) -> bool {
        let syn = self.flags & tcp_flags::SYN != 0;
        let fin = self.flags & tcp_flags::FIN != 0;
        let rst = self.flags & tcp_flags::RST != 0;
        !(syn && (fin || rst) || fin && rst)
            && (syn || rst || self.flags & tcp_flags::ACK != 0)
            && self.payload_len <= (MAX_TCP_SEGMENT_LEN - 20) as u32
            && (self.window_scale == TCP_NO_WINDOW_SCALE || syn && self.window_scale <= 14)
    }
    #[inline(always)]
    const fn end(self) -> u32 {
        self.sequence
            .wrapping_add(self.payload_len)
            .wrapping_add((self.flags & tcp_flags::SYN != 0) as u32)
            .wrapping_add((self.flags & tcp_flags::FIN != 0) as u32)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowPacket {
    Tcp(TcpSegment),
    Udp,
    EchoRequest,
    EchoReply,
}

impl FlowPacket {
    /// Single admission predicate shared by allocation and model construction.
    #[inline(always)]
    pub fn eligible_opener(self, proto: u8) -> bool {
        match (proto, self) {
            (ip_proto::TCP, Self::Tcp(p)) => {
                p.valid()
                    && p.flags & (tcp_flags::SYN | tcp_flags::ACK | tcp_flags::RST | tcp_flags::FIN)
                        == tcp_flags::SYN
            }
            (ip_proto::UDP, Self::Udp) | (ip_proto::ICMP | ip_proto::ICMPV6, Self::EchoRequest) => {
                true
            }
            _ => false,
        }
    }
}

const ORIGIN: u32 = 1;
const SYN_SHIFT: usize = 1;
const ACK_SHIFT: usize = 3;
const FIN_SHIFT: usize = 5;
const FIN_ACK_SHIFT: usize = 7;
const RESET: u32 = 1 << 9;
const REPLIED: u32 = 1 << 10;
const FLAGS_MASK: u32 = (1 << 11) - 1;
const SYN_BOTH: u32 = 3 << SYN_SHIFT;
const ACK_BOTH: u32 = 3 << ACK_SHIFT;
const FIN_BOTH: u32 = 3 << FIN_SHIFT;
const FIN_ACK_BOTH: u32 = 3 << FIN_ACK_SHIFT;

/// Sequence comparisons are meaningful within a half sequence space. All
/// admitted windows are bounded below 2^30, including RFC 7323 scaling.
#[inline(always)]
const fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}
#[inline(always)]
const fn between(value: u32, low: u32, high: u32) -> bool {
    let width = high.wrapping_sub(low);
    width < (1 << 31) && value.wrapping_sub(low) <= width
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TcpEnd {
    initial_sequence: u32,
    end_sequence: u32,
    acknowledged_sequence: u32,
    fin_end_sequence: u32,
    max_window: u32,
    scale: u32,
}
impl TcpEnd {
    const EMPTY: Self = Self {
        initial_sequence: 0,
        end_sequence: 0,
        acknowledged_sequence: 0,
        fin_end_sequence: 0,
        max_window: 0,
        scale: TCP_NO_WINDOW_SCALE as u32,
    };
    #[inline(always)]
    const fn syn(packet: TcpSegment) -> Self {
        Self {
            initial_sequence: packet.sequence,
            end_sequence: packet.end(),
            acknowledged_sequence: packet.sequence,
            fin_end_sequence: 0,
            max_window: packet.window as u32,
            scale: packet.window_scale as u32,
        }
    }
}

/// Owned protocol state; updates must be serialized as one transaction. Copying
/// only expiry or flags independently is not a coherent snapshot for HA or GC.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallFlow {
    pub expires_at_ms: u64,
    pub incarnation: u64,
    pub last_seen_ms: u64,
    flags: u32,
    // Imported inactivity can predate this boot. Preserve that age without
    // copying a peer's absolute clock or pretending last_seen=0 means new.
    idle_bias_ms: u32,
    tcp: [TcpEnd; 2],
}

/// Relative lifetime and protocol metadata for a coherent HA snapshot. Neither
/// node's absolute monotonic timestamps cross the link. The authenticated sync
/// transport must reject replay and supply a conservative packet transit bound.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirewallFlowTransfer {
    pub incarnation: u64,
    pub remaining_ms: u32,
    pub idle_ms: u32,
    flags: u32,
    _pad: u32,
    tcp: [TcpEnd; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowObservation {
    /// An existing allowed flow was observed; its state/timer was updated.
    Tracked,
    /// Forward under the existing grant, without changing state or expiry.
    /// Used for uncertain resets and terminal retransmissions.
    Unchanged,
    PolicyRequired,
    Invalid,
}

impl FirewallFlow {
    /// Zeroed local control-message storage, never a valid admitted flow.
    pub const ZERO: Self = Self {
        expires_at_ms: 0,
        incarnation: 0,
        last_seen_ms: 0,
        flags: 0,
        idle_bias_ms: 0,
        tcp: [TcpEnd {
            initial_sequence: 0,
            end_sequence: 0,
            acknowledged_sequence: 0,
            fin_end_sequence: 0,
            max_window: 0,
            scale: 0,
        }; 2],
    };

    #[inline(always)]
    pub fn begin(
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        incarnation: u64,
        timeouts: FlowTimeouts,
    ) -> Option<Self> {
        let mut state = Self::ZERO;
        state
            .begin_into(packet, direction, now_ms, incarnation, timeouts)
            .then_some(state)
    }

    /// Initialize a reserved slot in place, without an 80-byte temporary on
    /// the packet stack. Invalid input leaves the destination unchanged.
    #[inline(always)]
    pub fn begin_into(
        &mut self,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        incarnation: u64,
        timeouts: FlowTimeouts,
    ) -> bool {
        if incarnation == 0 || !timeouts.valid() {
            return false;
        }
        let timeout = match packet {
            FlowPacket::Tcp(packet) => {
                if !FlowPacket::Tcp(packet).eligible_opener(ip_proto::TCP) {
                    return false;
                }
                timeouts.tcp_pending_ms
            }
            FlowPacket::Udp => timeouts.udp_unreplied_ms,
            FlowPacket::EchoRequest => timeouts.echo_ms,
            FlowPacket::EchoReply => return false,
        };
        let i = direction.index();
        self.expires_at_ms = now_ms.saturating_add(timeout as u64);
        self.incarnation = incarnation;
        self.last_seen_ms = now_ms;
        self.flags = i as u32;
        self.idle_bias_ms = 0;
        self.tcp[0] = TcpEnd::EMPTY;
        self.tcp[1] = TcpEnd::EMPTY;
        if let FlowPacket::Tcp(packet) = packet {
            self.flags |= 1 << (SYN_SHIFT + i);
            self.tcp[i] = TcpEnd::syn(packet);
        }
        true
    }

    #[inline(always)]
    pub const fn tcp_established(&self) -> bool {
        self.flags & SYN_BOTH == SYN_BOTH && self.flags & ACK_BOTH == ACK_BOTH
    }
    #[inline(always)]
    pub const fn tcp_closed(&self) -> bool {
        self.flags & RESET != 0 || self.flags & FIN_ACK_BOTH == FIN_ACK_BOTH
    }
    #[inline(always)]
    fn has(&self, shift: usize, i: usize) -> bool {
        self.flags & (1 << (shift + i)) != 0
    }

    #[inline(always)]
    fn timeout(&self, proto: u8, timeouts: FlowTimeouts) -> Option<u32> {
        match proto {
            ip_proto::TCP => Some(if self.tcp_closed() {
                timeouts.tcp_closed_ms
            } else if self.tcp_established() {
                timeouts.tcp_established_ms
            } else {
                timeouts.tcp_pending_ms
            }),
            ip_proto::UDP => Some(if self.flags & REPLIED != 0 {
                timeouts.udp_replied_ms
            } else {
                timeouts.udp_unreplied_ms
            }),
            ip_proto::ICMP | ip_proto::ICMPV6 => Some(timeouts.echo_ms),
            _ => None,
        }
    }

    #[inline(always)]
    fn effective_expiry(&self, proto: u8, timeouts: FlowTimeouts) -> Option<u64> {
        let current_limit = self
            .last_seen_ms
            .saturating_add(self.timeout(proto, timeouts)? as u64)
            .saturating_sub(self.idle_bias_ms as u64);
        Some(self.expires_at_ms.min(current_limit))
    }

    /// Check a complete snapshot before trusting peer-supplied state. Protocol
    /// and logical scope come from the separately validated canonical key.
    #[inline(always)]
    pub fn valid_for(&self, proto: u8) -> bool {
        if self.incarnation == 0
            || self.idle_bias_ms > MAX_FLOW_TIMEOUT_MS
            || self.idle_bias_ms != 0 && self.last_seen_ms != 0
            || self.flags & !FLAGS_MASK != 0
            || self.last_seen_ms > self.expires_at_ms
            || self.expires_at_ms - self.last_seen_ms
                > (MAX_FLOW_TIMEOUT_MS - self.idle_bias_ms) as u64
        {
            return false;
        }
        if proto != ip_proto::TCP {
            return matches!(proto, ip_proto::UDP | ip_proto::ICMP | ip_proto::ICMPV6)
                && self.flags & !(ORIGIN | REPLIED) == 0
                && self.tcp == [TcpEnd::EMPTY; 2];
        }
        let origin = (self.flags & ORIGIN) as usize;
        if !self.has(SYN_SHIFT, origin) || self.flags & REPLIED != 0 {
            return false;
        }
        for i in 0..2 {
            if !self.has(SYN_SHIFT, i) {
                if self.tcp[i] != TcpEnd::EMPTY
                    || self.has(ACK_SHIFT, i)
                    || self.has(FIN_SHIFT, i)
                    || self.has(FIN_ACK_SHIFT, i)
                {
                    return false;
                }
            } else {
                if self.tcp[i].scale > 14 && self.tcp[i].scale != TCP_NO_WINDOW_SCALE as u32 {
                    return false;
                }
                if self.tcp[i].max_window > 65535 << 14 {
                    return false;
                }
                if self.has(FIN_SHIFT, i) {
                    if !self.tcp_established()
                        || self.tcp[i].fin_end_sequence != self.tcp[i].end_sequence
                        || self.has(FIN_ACK_SHIFT, i)
                            && self.tcp[i].acknowledged_sequence != self.tcp[i].fin_end_sequence
                    {
                        return false;
                    }
                } else if self.tcp[i].fin_end_sequence != 0 || self.has(FIN_ACK_SHIFT, i) {
                    return false;
                }
            }
        }
        true
    }

    #[inline(always)]
    pub fn export(
        &self,
        proto: u8,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> Option<FirewallFlowTransfer> {
        if !timeouts.valid() || !self.valid_for(proto) || now_ms < self.last_seen_ms {
            return None;
        }
        let timeout = self.timeout(proto, timeouts)? as u64;
        let idle = (now_ms - self.last_seen_ms).checked_add(self.idle_bias_ms as u64)?;
        let expiry = self.effective_expiry(proto, timeouts)?;
        if now_ms >= expiry {
            return None;
        }
        let remaining = expiry - now_ms;
        // A shortened configuration cannot export an old, longer permission.
        if idle + remaining > timeout {
            return None;
        }
        Some(FirewallFlowTransfer {
            incarnation: self.incarnation,
            remaining_ms: remaining as u32,
            idle_ms: idle as u32,
            flags: self.flags,
            _pad: 0,
            tcp: self.tcp,
        })
    }

    #[inline(always)]
    pub fn import(
        transfer: FirewallFlowTransfer,
        proto: u8,
        now_ms: u64,
        transit_ms: u32,
        timeouts: FlowTimeouts,
    ) -> Option<Self> {
        if !timeouts.valid()
            || transfer._pad != 0
            || transfer.remaining_ms == 0
            || transfer.remaining_ms > MAX_FLOW_TIMEOUT_MS
            || transfer.idle_ms > MAX_FLOW_TIMEOUT_MS
        {
            return None;
        }
        let remaining = transfer.remaining_ms.saturating_sub(transit_ms);
        if remaining == 0 {
            return None;
        }
        let idle = transfer.idle_ms as u64 + transit_ms as u64;
        if idle > MAX_FLOW_TIMEOUT_MS as u64 {
            return None;
        }
        let candidate = Self {
            incarnation: transfer.incarnation,
            last_seen_ms: now_ms.saturating_sub(idle),
            expires_at_ms: now_ms.checked_add(remaining as u64)?,
            flags: transfer.flags,
            idle_bias_ms: idle.saturating_sub(now_ms) as u32,
            tcp: transfer.tcp,
        };
        if transfer.remaining_ms as u64 + transfer.idle_ms as u64
            > candidate.timeout(proto, timeouts)? as u64
            || !candidate.valid_for(proto)
        {
            return None;
        }
        Some(candidate)
    }

    #[inline(always)]
    fn observe_tcp(&mut self, p: TcpSegment, i: usize) -> FlowObservation {
        if !p.valid() {
            return FlowObservation::Invalid;
        }
        let j = i ^ 1;
        let syn = p.flags & tcp_flags::SYN != 0;
        let ack = p.flags & tcp_flags::ACK != 0;
        let rst = p.flags & tcp_flags::RST != 0;
        let fin = p.flags & tcp_flags::FIN != 0;
        let seen_i = self.has(SYN_SHIFT, i);
        let seen_j = self.has(SYN_SHIFT, j);
        // A new SYN never inherits an established/closing incarnation. During
        // the handshake only an exact ISN retransmission reuses its grant.
        if syn
            && !ack
            && (self.tcp_established()
                || self.flags & (FIN_BOTH | RESET) != 0
                || seen_i && p.sequence != self.tcp[i].initial_sequence)
        {
            return FlowObservation::PolicyRequired;
        }
        if rst {
            let valid = if !seen_i && seen_j {
                // SYN-SENT: an ACK must acknowledge the outstanding SYN, with
                // an upper bound that also permits partial TFO acknowledgement.
                ack && between(
                    p.acknowledgement,
                    self.tcp[j].initial_sequence.wrapping_add(1),
                    self.tcp[j].end_sequence,
                )
            } else if seen_i && seen_j {
                let expected = if self.has(ACK_SHIFT, i) {
                    self.tcp[i].acknowledged_sequence
                } else {
                    self.tcp[i].initial_sequence.wrapping_add(1)
                };
                p.sequence == expected && (!ack || self.ack_valid(p.acknowledgement, i, j))
            } else {
                false
            };
            if !valid || self.tcp_closed() {
                return FlowObservation::Unchanged;
            }
            self.flags |= RESET;
            return FlowObservation::Tracked;
        }
        if self.tcp_closed() {
            if syn {
                return FlowObservation::PolicyRequired;
            }
            return if p.payload_len == 0 {
                FlowObservation::Unchanged
            } else {
                FlowObservation::Invalid
            };
        }
        if syn
            && seen_i
            && (p.sequence != self.tcp[i].initial_sequence
                || p.window_scale as u32 != self.tcp[i].scale)
        {
            return FlowObservation::PolicyRequired;
        }
        if !syn && !seen_i {
            return FlowObservation::Invalid;
        }
        if ack {
            if !seen_j || !self.ack_valid(p.acknowledgement, i, j) {
                return if self.tcp_established() {
                    FlowObservation::Unchanged
                } else {
                    FlowObservation::Invalid
                };
            }
            if syn
                && !between(
                    p.acknowledgement,
                    self.tcp[j].initial_sequence.wrapping_add(1),
                    self.tcp[j].end_sequence,
                )
            {
                return FlowObservation::Invalid;
            }
        }
        if fin && !self.tcp_established() {
            return FlowObservation::Invalid;
        }
        if !syn && seen_j {
            let credit = self.tcp[j].max_window.max(1);
            let low = self.tcp[i].acknowledged_sequence.wrapping_sub(credit);
            let high = self.tcp[i].acknowledged_sequence.wrapping_add(credit);
            if !between(p.sequence, low, high) && !between(p.end(), low, high) {
                return FlowObservation::Unchanged;
            }
        }
        if self.has(FIN_SHIFT, i) {
            if fin && p.end() != self.tcp[i].fin_end_sequence {
                return FlowObservation::Unchanged;
            }
            if !fin
                && p.payload_len != 0
                && after(p.end(), self.tcp[i].fin_end_sequence.wrapping_sub(1))
            {
                return FlowObservation::Invalid;
            }
        } else if fin && after(self.tcp[i].end_sequence, p.end()) {
            return FlowObservation::Unchanged;
        }
        // No failure exits beyond here: all related metadata changes commit
        // together while the caller holds the complete map-value lock.
        if syn && !seen_i {
            self.tcp[i] = TcpEnd::syn(p);
            self.flags |= 1 << (SYN_SHIFT + i);
        }
        if after(p.end(), self.tcp[i].end_sequence) {
            self.tcp[i].end_sequence = p.end();
        }
        let scaled = !syn && self.tcp[0].scale <= 14 && self.tcp[1].scale <= 14;
        let shift = if scaled { self.tcp[i].scale } else { 0 };
        let window = (p.window as u32) << shift;
        if window > self.tcp[i].max_window {
            self.tcp[i].max_window = window;
        }
        if ack && seen_j {
            if after(p.acknowledgement, self.tcp[j].acknowledged_sequence) {
                self.tcp[j].acknowledged_sequence = p.acknowledgement;
            }
            if after(p.acknowledgement, self.tcp[j].initial_sequence) {
                self.flags |= 1 << (ACK_SHIFT + j);
            }
            if self.has(FIN_SHIFT, j) && !after(self.tcp[j].fin_end_sequence, p.acknowledgement) {
                self.flags |= 1 << (FIN_ACK_SHIFT + j);
            }
        }
        if fin {
            self.flags |= 1 << (FIN_SHIFT + i);
            self.tcp[i].fin_end_sequence = p.end();
        }
        FlowObservation::Tracked
    }

    #[inline(always)]
    fn ack_valid(&self, ack: u32, i: usize, j: usize) -> bool {
        let credit = self.tcp[i].max_window.max(1);
        between(
            ack,
            self.tcp[j].acknowledged_sequence.wrapping_sub(credit),
            self.tcp[j].end_sequence,
        )
    }

    /// Invalid and uncertain observations never renew expiry or mutate flags.
    /// A new allowed opener must receive a new incarnation through begin().
    #[inline(always)]
    pub fn observe(
        &mut self,
        proto: u8,
        packet: FlowPacket,
        direction: FlowDirection,
        now_ms: u64,
        timeouts: FlowTimeouts,
    ) -> FlowObservation {
        if !timeouts.valid() || self.incarnation == 0 || self.flags & !FLAGS_MASK != 0 {
            return FlowObservation::Invalid;
        }
        let Some(expiry) = self.effective_expiry(proto, timeouts) else {
            return FlowObservation::Invalid;
        };
        if now_ms >= expiry {
            return FlowObservation::PolicyRequired;
        }
        let i = direction.index();
        let reverse = i as u32 != self.flags & ORIGIN;
        let timeout = match (proto, packet) {
            (ip_proto::TCP, FlowPacket::Tcp(p)) => {
                let result = self.observe_tcp(p, i);
                if result != FlowObservation::Tracked {
                    return result;
                }
                if self.tcp_closed() {
                    timeouts.tcp_closed_ms
                } else if self.tcp_established() {
                    timeouts.tcp_established_ms
                } else {
                    timeouts.tcp_pending_ms
                }
            }
            (ip_proto::UDP, FlowPacket::Udp) => {
                if reverse {
                    self.flags |= REPLIED;
                }
                if self.flags & REPLIED != 0 {
                    timeouts.udp_replied_ms
                } else {
                    timeouts.udp_unreplied_ms
                }
            }
            (ip_proto::ICMP | ip_proto::ICMPV6, FlowPacket::EchoRequest) if !reverse => {
                timeouts.echo_ms
            }
            (ip_proto::ICMP | ip_proto::ICMPV6, FlowPacket::EchoReply) if reverse => {
                self.flags |= REPLIED;
                timeouts.echo_ms
            }
            _ => return FlowObservation::Invalid,
        };
        self.last_seen_ms = self.last_seen_ms.max(now_ms);
        self.idle_bias_ms = 0;
        self.expires_at_ms = self.last_seen_ms.saturating_add(timeout as u64);
        FlowObservation::Tracked
    }
}

#[cfg(test)]
#[path = "firewall_flow_tests.rs"]
mod tests;
