//! C15 — **SYN proxy**: completing a TCP handshake on a server's behalf, so a
//! SYN flood never reaches it.
//!
//! A SYN flood costs the attacker one small packet and costs the victim a
//! half-open connection: kernel memory, a slot in the accept backlog, and a
//! retransmit timer, all held for tens of seconds against a source address that
//! was never real. The defence is to **not believe a SYN**. The firewall answers
//! it itself with a SYN-ACK whose sequence number is a keyed hash of the
//! connection's own identity — a *cookie* — and keeps **no state at all**. A
//! flood therefore costs the firewall one reply packet and nothing else.
//!
//! Only a client that actually receives that SYN-ACK can produce the matching
//! ACK, and only then does the firewall open the real connection to the server.
//! Spoofed sources cannot, because the reply goes to the address they forged.
//!
//! ## The splice, and why the sequence numbers must be translated
//!
//! The firewall picked the server's initial sequence number (the cookie) before
//! the server had any say. When the real server is finally asked, it picks its
//! own. From then on the two ends disagree about the sequence space by a fixed
//! amount, and every packet has to be corrected in flight:
//!
//! ```text
//! client                     firewall                        server
//!   -- SYN(c_isn) --------->  |   (no state created)
//!   <-- SYN-ACK(cookie) ----  |
//!   -- ACK(cookie+1) ------>  |   cookie valid ⇒ this client is real
//!                             |  -- SYN(c_isn) ------------->
//!                             |  <-- SYN-ACK(s_isn) ---------
//!                             |  -- ACK(s_isn+1) ----------->   established
//!   ====== established, with delta = s_isn - cookie applied ======
//!   -- seq=…, ack=A ------->  |  -- ack = A + delta -------->
//!   <-- seq = S - delta ----  |  <-- seq=S -------------------
//! ```
//!
//! [`seq_delta`] computes that offset once; [`translate_to_server`] and
//! [`translate_to_client`] apply it. Both are wrapping 32-bit arithmetic, which
//! is what TCP sequence space is.
//!
//! ## What a proxied connection gives up
//!
//! The firewall has to answer the SYN before it can ask the server what options
//! it would have agreed to, so the SYN-ACK it invents can only offer what it is
//! prepared to guarantee itself. It offers an **MSS and nothing else**: no
//! window scaling, no selective acknowledgement, no timestamps. The SYN sent on
//! to the server is likewise bare, so both halves of the connection agree.
//!
//! The consequences are worth stating plainly, because they are the price of
//! the protection and not a bug to be found later:
//!
//! * **No window scaling** caps the receive window at 64 KiB, so a single
//!   connection's throughput is bounded by 64 KiB per round trip. On a 10 ms
//!   path that is about 6 MB/s.
//! * **No SACK** makes recovery from multiple losses in one window slower.
//! * **No timestamps** removes PAWS and RTT measurement.
//!
//! Linux's own cookie fallback makes exactly the first of these trades when
//! timestamps are unavailable. Because the options are dropped symmetrically,
//! nothing is inconsistent between the two ends — the connection is ordinary,
//! just conservative. Turn the protection on where a flood is the bigger risk
//! than the throughput, which is what "per protected port" is for.
//!
//! ## The cookie
//!
//! ```text
//! bits 31..27  epoch     the ~68 s window the cookie was minted in (mod 32)
//! bits 26..24  mss index into MSS_TABLE — what to offer the server
//! bits 23..0   mac       keyed hash of (addresses, ports, epoch, mss index)
//! ```
//!
//! A cookie is accepted in the epoch it was minted in **or the one before**, so
//! it stays valid for between 68 and 137 seconds — comfortably longer than a
//! client's first SYN-ACK retransmit and far shorter than a replay is useful
//! for. The 24-bit MAC leaves a forger a one-in-sixteen-million chance per
//! attempt, the same margin Linux accepts.
//!
//! Everything here is pure arithmetic and is unit-tested without a kernel.

use crate::{forward::ipv4_checksum, reject::tcp_checksum};

/// The MSS values a cookie can encode, since only three bits survive in it.
///
/// Descending, so [`mss_index`] can pick the largest entry that does not exceed
/// what the client asked for: offering a client *more* than it advertised is the
/// one direction that breaks, because the server would then send segments the
/// client's path cannot carry.
pub const MSS_TABLE: [u16; 8] = [1460, 1440, 1400, 1360, 1300, 1220, 1100, 536];

/// The index of the largest [`MSS_TABLE`] entry that fits in `mss`.
///
/// A client advertising less than the smallest entry gets the smallest entry;
/// 536 is the IPv4 minimum every implementation must accept, so there is no
/// case below it worth encoding.
#[inline(always)]
pub fn mss_index(mss: u16) -> u8 {
    let mut i = 0;
    while i < MSS_TABLE.len() - 1 {
        if mss >= MSS_TABLE[i] {
            return i as u8;
        }
        i += 1;
    }
    (MSS_TABLE.len() - 1) as u8
}

/// The MSS an index stands for. Out-of-range indices cannot occur (three bits,
/// eight entries) but are mapped to the safe minimum rather than panicking —
/// this runs in a context where a panic is not an option.
#[inline(always)]
pub fn mss_for_index(index: u8) -> u16 {
    let i = index as usize;
    if i < MSS_TABLE.len() {
        MSS_TABLE[i]
    } else {
        MSS_TABLE[MSS_TABLE.len() - 1]
    }
}

/// Nanoseconds per cookie epoch: 2^36 ns ≈ 68.7 s.
///
/// The shift is what makes this cheap in the data plane — the epoch is a shift
/// of the monotonic clock, not a division.
pub const EPOCH_SHIFT: u32 = 36;

/// The epoch a monotonic nanosecond timestamp falls in, reduced to the five
/// bits the cookie carries.
#[inline]
pub const fn epoch_of(now_ns: u64) -> u32 {
    ((now_ns >> EPOCH_SHIFT) & 0x1f) as u32
}

/// Mint a cookie for a connection.
///
/// `mss` is what the *client* advertised; the cookie records the largest
/// [`MSS_TABLE`] entry that fits, which is what the firewall will later offer
/// the server. The cookie is the sequence number the SYN-ACK carries, so the
/// client returns it (plus one) in its ACK and the firewall can recompute and
/// compare it without having stored anything.
#[inline(always)]
pub fn make_cookie(
    secret: [u64; 2],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    epoch: u32,
    mss: u16,
) -> u32 {
    let idx = mss_index(mss);
    let mac = cookie_mac(secret, src, dst, sport, dport, epoch, idx);
    ((epoch & 0x1f) << 27) | ((idx as u32 & 0x7) << 24) | mac
}

/// Check a cookie taken from a client's ACK, returning the MSS it recorded.
///
/// `epoch_now` is the current epoch; the epoch before it is accepted too, so a
/// cookie survives the boundary it happened to be minted next to. Returns
/// `None` for any cookie this appliance did not mint for exactly this
/// connection within that window — which is every forged ACK an off-path
/// attacker can produce, and every replay of an old one.
#[inline(always)]
pub fn check_cookie(
    secret: [u64; 2],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    epoch_now: u32,
    cookie: u32,
) -> Option<u16> {
    let epoch = (cookie >> 27) & 0x1f;
    let idx = ((cookie >> 24) & 0x7) as u8;
    let mac = cookie & 0x00ff_ffff;

    // The epoch counter wraps at 32, so "the one before" is modular.
    let previous = (epoch_now + 0x1f) & 0x1f;
    if epoch != (epoch_now & 0x1f) && epoch != previous {
        return None;
    }
    if cookie_mac(secret, src, dst, sport, dport, epoch, idx) != mac {
        return None;
    }
    Some(mss_for_index(idx))
}

/// The 24-bit authenticator inside a cookie.
///
/// Note the epoch and the MSS index are *inputs* to the MAC as well as being
/// carried in the clear: without that, an attacker could take a valid cookie
/// and flip those bits to widen its lifetime or change what the server is told.
#[inline(always)]
fn cookie_mac(
    secret: [u64; 2],
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    epoch: u32,
    mss_index: u8,
) -> u32 {
    let a = u64::from(u32::from_be_bytes(src)) << 32 | u64::from(u32::from_be_bytes(dst));
    let b = u64::from(sport) << 48
        | u64::from(dport) << 32
        | u64::from(epoch) << 8
        | u64::from(mss_index);
    (siphash(secret, a, b) as u32) & 0x00ff_ffff
}

/// A keyed pseudo-random function over two 64-bit words, in the SipHash-2-4
/// construction.
///
/// Two words is all a cookie ever hashes, so the message loop is unrolled away
/// entirely — no loop for the verifier to reject, and no length handling to get
/// wrong. Only this appliance ever mints or checks its own cookies, so nothing
/// interoperates with this and the requirement is simply that it be a strong
/// keyed mix: an attacker who can see cookies for connections they open must
/// not be able to produce one for a connection they cannot receive.
#[inline(always)]
fn siphash(key: [u64; 2], m0: u64, m1: u64) -> u64 {
    let mut v0 = key[0] ^ 0x736f_6d65_7073_6575;
    let mut v1 = key[1] ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = key[0] ^ 0x6c79_6765_6e65_7261;
    let mut v3 = key[1] ^ 0x7465_6462_7974_6573;

    macro_rules! round {
        () => {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        };
    }

    for m in [m0, m1] {
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }
    // The final block of a 16-byte message: length in the top byte, nothing else.
    let tail = 16u64 << 56;
    v3 ^= tail;
    round!();
    round!();
    v0 ^= tail;

    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}

/// How far the server's sequence space sits from the one the client was told.
///
/// Wrapping subtraction, because TCP sequence numbers wrap: the difference
/// between two points in a 32-bit circular space is itself a 32-bit value, and
/// adding it back is exact for every pair.
#[inline]
pub const fn seq_delta(server_isn: u32, cookie: u32) -> u32 {
    server_isn.wrapping_sub(cookie)
}

/// Correct a client's acknowledgement number into the server's sequence space.
#[inline]
pub const fn translate_to_server(client_ack: u32, delta: u32) -> u32 {
    client_ack.wrapping_add(delta)
}

/// Correct a server's sequence number into the space the client was given.
#[inline]
pub const fn translate_to_client(server_seq: u32, delta: u32) -> u32 {
    server_seq.wrapping_sub(delta)
}

/// A synthesised TCP segment: what the data plane must write, already
/// checksummed. The addresses and ports are the caller's to place, since it
/// either swaps the incoming packet's or keeps them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TcpSynth {
    /// Sequence number, host order.
    pub seq: u32,
    /// Acknowledgement number, host order.
    pub ack: u32,
    /// Flags byte.
    pub flags: u8,
    /// TCP data offset in 32-bit words (5 with no options, 6 with an MSS one).
    pub data_offset: u8,
    /// Advertised window.
    pub window: u16,
    /// The MSS to write into the option, or `None` when `data_offset` is 5.
    pub mss: Option<u16>,
    /// IPv4 header checksum for the segment's own total length.
    pub ip_checksum: u16,
    /// TCP checksum over the pseudo-header and the synthesised header.
    pub tcp_checksum: u16,
    /// IPv4 total length to write (20 + the TCP header).
    pub total_len: u16,
}

/// The window a synthesised segment advertises.
///
/// Without window scaling this is the ceiling anyway, and it is the firewall's
/// promise on behalf of a server it has not spoken to yet. 64 KiB minus a
/// little keeps it a legal 16-bit value with room to spare.
pub const SYNTH_WINDOW: u16 = 65_160;

/// Plan the SYN-ACK the firewall answers a client's SYN with.
///
/// `src`/`dst` and `sport`/`dport` are the **incoming SYN's**, so the response
/// swaps them. `client_isn` is the SYN's sequence number and `cookie` the value
/// [`make_cookie`] produced; `mss` is what to advertise back to the client.
#[inline(always)]
pub fn plan_syn_ack(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    client_isn: u32,
    cookie: u32,
    mss: u16,
) -> TcpSynth {
    synth(
        dst,
        src,
        dport,
        sport,
        cookie,
        client_isn.wrapping_add(1),
        crate::tcp_flags::SYN | crate::tcp_flags::ACK,
        Some(mss),
    )
}

/// Plan the SYN the firewall sends on to the server once a cookie checked out.
///
/// It carries the **client's own** initial sequence number, so the server's view
/// of the client's sequence space is the real one and only the server's own
/// direction ever needs translating. Addresses and ports stay as they were —
/// this segment continues towards the original destination and is subject to
/// whatever forwarding and translation the rest of the pipeline applies.
#[inline(always)]
pub fn plan_server_syn(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    client_isn: u32,
    mss: u16,
) -> TcpSynth {
    synth(
        src,
        dst,
        sport,
        dport,
        client_isn,
        0,
        crate::tcp_flags::SYN,
        Some(mss),
    )
}

/// Plan the ACK that completes the handshake with the server.
///
/// `src`/`dst`/`sport`/`dport` are the **server's SYN-ACK's**, so this swaps
/// them to face the server again. Carries no options: the negotiation is over.
#[inline(always)]
pub fn plan_server_ack(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    server_isn: u32,
    client_isn: u32,
) -> TcpSynth {
    synth(
        dst,
        src,
        dport,
        sport,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        crate::tcp_flags::ACK,
        None,
    )
}

/// Build a synthesised segment and its two checksums.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn synth(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    mss: Option<u16>,
) -> TcpSynth {
    let tcp_len: u16 = if mss.is_some() { 24 } else { 20 };
    let total_len = 20 + tcp_len;

    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[8] = 64; // TTL
    ip[9] = crate::ip_proto::TCP;
    ip[12..16].copy_from_slice(&src);
    ip[16..20].copy_from_slice(&dst);

    let mut tcp = [0u8; 24];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    let data_offset = (tcp_len / 4) as u8;
    tcp[12] = data_offset << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&SYNTH_WINDOW.to_be_bytes());
    // 16..18 checksum stays zero for the computation, 18..20 urgent stays zero.
    if let Some(m) = mss {
        tcp[20] = 2; // kind: maximum segment size
        tcp[21] = 4; // length
        tcp[22..24].copy_from_slice(&m.to_be_bytes());
    }

    TcpSynth {
        seq,
        ack,
        flags,
        data_offset,
        window: SYNTH_WINDOW,
        mss,
        ip_checksum: ipv4_checksum(&ip),
        tcp_checksum: tcp_checksum(src, dst, &tcp[..tcp_len as usize]),
        total_len,
    }
}

/// Repair a TCP checksum after a 32-bit field changed, per RFC 1624.
///
/// Two 16-bit replacements, because a checksum is a sum of 16-bit words and a
/// sequence number spans two of them. Recomputing the whole checksum instead
/// would mean walking the payload — unbounded work in a context that forbids
/// it, and needless when the change is this local.
#[inline]
pub const fn csum_replace_u32(check: u16, old: u32, new: u32) -> u16 {
    let c = crate::forward::csum_replace_u16(check, (old >> 16) as u16, (new >> 16) as u16);
    crate::forward::csum_replace_u16(c, old as u16, new as u16)
}

/// Key of the map naming the ports a SYN proxy stands in front of.
///
/// A port, not a zone-scoped rule: what is being protected is *a service*, and
/// a service answers on a port regardless of which zone a client arrives from.
/// Scoping this by zone as well would mean a flood arriving on a zone nobody
/// thought to list reaches the server — the failure the feature exists to
/// prevent, reintroduced as a configuration mistake.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct SynProxyKey {
    /// The protected TCP port, host order.
    pub port: u16,
    /// IP protocol; only TCP is meaningful, but it keeps the key honest.
    pub proto: u8,
    /// Explicit padding, always zero.
    pub _pad: u8,
}

impl SynProxyKey {
    /// A key for a protected TCP port.
    #[inline]
    pub const fn tcp(port: u16) -> Self {
        Self {
            port,
            proto: crate::ip_proto::TCP,
            _pad: 0,
        }
    }
}

/// What a protected port's proxy offers.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SynProxyCfg {
    /// The MSS the synthesised SYN-ACK advertises to the client. What is
    /// offered to the *server* comes from the client's own advertisement,
    /// carried through the cookie.
    pub mss: u16,
    /// Explicit padding, always zero.
    pub _pad: [u16; 3],
}

impl SynProxyCfg {
    /// A proxy advertising `mss`.
    #[inline]
    pub const fn new(mss: u16) -> Self {
        Self { mss, _pad: [0; 3] }
    }
}

/// Per-connection proxy state, created only **after** a cookie checked out.
///
/// This is the whole memory cost of the feature, and it is worth being precise
/// about when it is paid: never for a SYN, only for a client that proved it can
/// receive. A flood of a million spoofed SYNs allocates none of these.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SynFlow {
    /// The cookie this connection's client was given as the server's ISN.
    pub cookie: u32,
    /// `server_isn - cookie`, valid once [`SynFlow::SPLICED`] is set.
    pub delta: u32,
    /// The client's initial sequence number, needed to complete the handshake
    /// with the server when its SYN-ACK arrives.
    pub client_isn: u32,
    /// Bit flags; see [`SynFlow::SPLICED`].
    pub flags: u16,
    /// Explicit padding, always zero.
    pub _pad: u16,
}

impl SynFlow {
    /// The server has answered and [`SynFlow::delta`] is valid. Until this is
    /// set the connection exists only towards the client, and traffic from it
    /// has nowhere to go yet.
    pub const SPLICED: u16 = 1 << 0;

    /// State for a client whose cookie checked out, before the server replies.
    #[inline]
    pub const fn pending(cookie: u32, client_isn: u32) -> Self {
        Self {
            cookie,
            delta: 0,
            client_isn,
            flags: 0,
            _pad: 0,
        }
    }

    /// Whether the server has answered and translation can proceed.
    #[inline]
    pub const fn is_spliced(&self) -> bool {
        self.flags & Self::SPLICED != 0
    }

    /// Record the server's initial sequence number, completing the splice.
    #[inline]
    pub fn splice(&mut self, server_isn: u32) {
        self.delta = seq_delta(server_isn, self.cookie);
        self.flags |= Self::SPLICED;
    }
}

// SAFETY: both are `#[repr(C)]` POD with explicit padding — safe to copy to and
// from BPF maps.
#[cfg(feature = "user")]
unsafe impl aya::Pod for SynProxyKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SynProxyCfg {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for SynFlow {}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u64; 2] = [0x0f0e_0d0c_0b0a_0908, 0x0706_0504_0302_0100];
    const CLIENT: [u8; 4] = [198, 51, 100, 7];
    const SERVER: [u8; 4] = [10, 0, 0, 9];

    fn cookie_for(epoch: u32, mss: u16) -> u32 {
        make_cookie(SECRET, CLIENT, SERVER, 40000, 443, epoch, mss)
    }

    /// The whole point: a cookie is verifiable without having stored anything,
    /// so a flood costs the firewall no memory at all.
    #[test]
    fn a_cookie_verifies_against_the_connection_that_minted_it() {
        let c = cookie_for(7, 1460);
        assert_eq!(
            check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 7, c),
            Some(1460)
        );
    }

    /// An attacker who cannot receive the SYN-ACK has to guess, and every part
    /// of the connection's identity is inside the MAC.
    #[test]
    fn a_cookie_is_bound_to_every_part_of_the_connection() {
        let c = cookie_for(7, 1460);
        let other = [198, 51, 100, 8];
        assert_eq!(check_cookie(SECRET, other, SERVER, 40000, 443, 7, c), None);
        assert_eq!(check_cookie(SECRET, CLIENT, other, 40000, 443, 7, c), None);
        assert_eq!(check_cookie(SECRET, CLIENT, SERVER, 40001, 443, 7, c), None);
        assert_eq!(check_cookie(SECRET, CLIENT, SERVER, 40000, 444, 7, c), None);
        let wrong_key = [SECRET[0] ^ 1, SECRET[1]];
        assert_eq!(
            check_cookie(wrong_key, CLIENT, SERVER, 40000, 443, 7, c),
            None
        );
    }

    /// A cookie has to outlive the client's first retransmit but not much more.
    /// The epoch counter wraps at 32, so "the epoch before 0" is 31 — a modular
    /// comparison, not a subtraction that would underflow.
    #[test]
    fn a_cookie_survives_one_epoch_boundary_and_no_more() {
        let c = cookie_for(7, 1460);
        assert!(check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 8, c).is_some());
        assert!(check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 9, c).is_none());

        let wrapped = cookie_for(31, 1460);
        assert!(
            check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 0, wrapped).is_some(),
            "a cookie minted just before the counter wrapped was rejected"
        );
    }

    /// Both fields carried in the clear are also inside the MAC, so neither can
    /// be edited to extend a cookie's life or change what the server is told.
    #[test]
    fn the_clear_text_fields_cannot_be_tampered_with() {
        let c = cookie_for(7, 1460);
        let restamped = (c & 0x07ff_ffff) | (8 << 27);
        assert_eq!(
            check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 8, restamped),
            None,
            "a cookie's epoch was edited and it still verified"
        );
        let regraded = (c & 0xf8ff_ffff) | (7 << 24);
        assert_eq!(
            check_cookie(SECRET, CLIENT, SERVER, 40000, 443, 7, regraded),
            None,
            "a cookie's MSS was edited and it still verified"
        );
    }

    /// Offering a client more than it asked for is the one direction that
    /// breaks: the server would send segments its path cannot carry.
    #[test]
    fn an_mss_is_never_rounded_up() {
        for advertised in [1460u16, 1452, 1400, 1380, 900, 536, 300] {
            let recovered = mss_for_index(mss_index(advertised));
            assert!(
                recovered <= advertised.max(MSS_TABLE[MSS_TABLE.len() - 1]),
                "{advertised} was encoded as {recovered}"
            );
        }
        assert_eq!(mss_for_index(mss_index(1460)), 1460);
        assert_eq!(mss_for_index(mss_index(1452)), 1440);
        assert_eq!(mss_for_index(mss_index(300)), 536);
    }

    /// The splice's arithmetic has to be exact across the wrap, because a busy
    /// connection reaches it and a connection that breaks at 4 GiB is worse
    /// than one that never worked.
    #[test]
    fn sequence_translation_round_trips_across_the_wrap() {
        for (server_isn, cookie) in [
            (0x1000_0000u32, 0x2000_0000u32),
            (0x0000_0005, 0xffff_fff0),
            (0xffff_fff0, 0x0000_0005),
        ] {
            let delta = seq_delta(server_isn, cookie);
            assert_eq!(
                translate_to_client(server_isn, delta),
                cookie,
                "the server's ISN did not map to the cookie the client was given"
            );
            for k in [0u32, 1, 4096, 0xffff_ffff] {
                let s = server_isn.wrapping_add(k);
                assert_eq!(translate_to_server(translate_to_client(s, delta), delta), s);
            }
        }
    }

    /// The SYN-ACK is what the client's whole stack reacts to; every field has
    /// to be the one a real server would have sent.
    #[test]
    fn the_synthesised_syn_ack_answers_the_syn_it_replies_to() {
        let cookie = cookie_for(7, 1460);
        let sa = plan_syn_ack(CLIENT, SERVER, 40000, 443, 0x1111_2222, cookie, 1460);
        assert_eq!(sa.flags, crate::tcp_flags::SYN | crate::tcp_flags::ACK);
        assert_eq!(sa.seq, cookie, "the cookie must be the ISN the client sees");
        assert_eq!(sa.ack, 0x1111_2223, "a SYN occupies one sequence number");
        assert_eq!(sa.data_offset, 6);
        assert_eq!(sa.total_len, 44);
        assert_eq!(sa.mss, Some(1460));
    }

    /// The server must see the client's real sequence space, or the client's
    /// own direction would need translating too.
    #[test]
    fn the_server_syn_carries_the_clients_own_sequence_number() {
        let syn = plan_server_syn(CLIENT, SERVER, 40000, 443, 0x1111_2222, 1440);
        assert_eq!(syn.flags, crate::tcp_flags::SYN);
        assert_eq!(syn.seq, 0x1111_2222);
        assert_eq!(syn.ack, 0);
        assert_eq!(syn.mss, Some(1440));
    }

    #[test]
    fn the_server_ack_completes_the_handshake_it_was_offered() {
        // The server answered our SYN, so its SYN-ACK travels server → client.
        let ack = plan_server_ack(SERVER, CLIENT, 443, 40000, 0xaaaa_0000, 0x1111_2222);
        assert_eq!(ack.flags, crate::tcp_flags::ACK);
        assert_eq!(ack.seq, 0x1111_2223);
        assert_eq!(ack.ack, 0xaaaa_0001);
        assert_eq!(ack.data_offset, 5, "the negotiation is over; no options");
        assert_eq!(ack.total_len, 40);
    }

    /// A receiver validates the checksum over the pseudo-header and the segment;
    /// summing a correct segment including its checksum yields zero. That is the
    /// property the wire actually tests, so it is the one asserted here.
    #[test]
    fn a_synthesised_segment_checksums_as_a_receiver_would_check_it() {
        let cookie = cookie_for(3, 1460);
        let sa = plan_syn_ack(CLIENT, SERVER, 40000, 443, 0x1111_2222, cookie, 1460);

        // Rebuild the segment exactly as the data plane writes it, checksum
        // included, and verify it sums to zero.
        let mut tcp = [0u8; 24];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&sa.seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&sa.ack.to_be_bytes());
        tcp[12] = sa.data_offset << 4;
        tcp[13] = sa.flags;
        tcp[14..16].copy_from_slice(&sa.window.to_be_bytes());
        tcp[16..18].copy_from_slice(&sa.tcp_checksum.to_be_bytes());
        tcp[20] = 2;
        tcp[21] = 4;
        tcp[22..24].copy_from_slice(&1460u16.to_be_bytes());
        assert_eq!(
            tcp_checksum(SERVER, CLIENT, &tcp),
            0,
            "a receiver would discard the synthesised SYN-ACK"
        );

        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&sa.total_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = crate::ip_proto::TCP;
        ip[10..12].copy_from_slice(&sa.ip_checksum.to_be_bytes());
        ip[12..16].copy_from_slice(&SERVER);
        ip[16..20].copy_from_slice(&CLIENT);
        // Summed the way a receiver does — every word including the checksum
        // field. `ipv4_checksum` cannot be used for this: it treats that field
        // as zero by contract, so it recomputes rather than validates.
        let mut sum: u32 = 0;
        for w in ip.chunks(2) {
            sum += u16::from_be_bytes([w[0], w[1]]) as u32;
        }
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        assert_eq!(
            !(sum as u16),
            0,
            "a receiver would discard the synthesised IP header"
        );
    }

    /// The splice is recorded once, from the server's SYN-ACK, and every later
    /// packet reads it. Getting `delta` backwards here would corrupt every
    /// connection the proxy admits, so it is asserted against both directions.
    #[test]
    fn a_spliced_flow_translates_both_directions() {
        let cookie = cookie_for(2, 1460);
        let mut flow = SynFlow::pending(cookie, 0x1111_2222);
        assert!(!flow.is_spliced(), "a pending flow must not translate yet");

        let server_isn = 0x9999_0000;
        flow.splice(server_isn);
        assert!(flow.is_spliced());

        // The client acknowledges in cookie space; the server must see its own.
        assert_eq!(
            translate_to_server(cookie.wrapping_add(1), flow.delta),
            server_isn.wrapping_add(1)
        );
        // The server sends in its own space; the client must see the cookie's.
        assert_eq!(
            translate_to_client(server_isn.wrapping_add(4096), flow.delta),
            cookie.wrapping_add(4096)
        );
    }

    /// Translation rewrites a sequence number on every packet of a proxied
    /// connection, so its checksum repair has to be exact — a receiver silently
    /// discards a segment with a bad checksum, and the connection would stall
    /// with nothing logged anywhere.
    #[test]
    fn a_translated_sequence_number_keeps_the_checksum_valid() {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&0xaaaa_0010u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0x1111_2223u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = crate::tcp_flags::ACK;
        let check = tcp_checksum(SERVER, CLIENT, &tcp);
        tcp[16..18].copy_from_slice(&check.to_be_bytes());
        assert_eq!(tcp_checksum(SERVER, CLIENT, &tcp), 0);

        // Now translate the sequence number the way the data plane does, and
        // repair rather than recompute.
        let old = 0xaaaa_0010u32;
        let new = translate_to_client(old, seq_delta(0xaaaa_0000, 0x1234_5678));
        let repaired = csum_replace_u32(check, old, new);
        tcp[4..8].copy_from_slice(&new.to_be_bytes());
        tcp[16..18].copy_from_slice(&repaired.to_be_bytes());
        assert_eq!(
            tcp_checksum(SERVER, CLIENT, &tcp),
            0,
            "the repaired checksum would be rejected by a receiver"
        );
    }

    /// These are eBPF map keys and values; a size that shifts silently changes
    /// what the kernel stores.
    #[test]
    fn the_map_types_are_pod_sized() {
        assert_eq!(core::mem::size_of::<SynProxyKey>(), 4);
        assert_eq!(core::mem::size_of::<SynProxyCfg>(), 8);
        assert_eq!(core::mem::size_of::<SynFlow>(), 16);
    }

    /// Different connections must not collide into the same cookie, or one
    /// client's handshake would admit another's forgery.
    #[test]
    fn distinct_connections_get_distinct_cookies() {
        let mut seen = std::collections::HashSet::new();
        for port in 40000u16..40200 {
            let c = make_cookie(SECRET, CLIENT, SERVER, port, 443, 4, 1460);
            assert!(seen.insert(c), "two source ports minted the same cookie");
        }
    }
}
