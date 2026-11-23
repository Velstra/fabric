//! RELATED ICMPv4 errors. Every hook recomputes association from the packet and
//! existing, live, physical-policy state. Errors never create or refresh a flow.
//! Source NAT of the envelope is deferred to TC, after Linux source validation.
use core::ffi::c_void;

use aya_ebpf::{
    helpers::{bpf_csum_diff, bpf_ktime_get_ns, bpf_loop, bpf_skb_load_bytes, bpf_xdp_load_bytes},
    macros::map,
    maps::PerCpuArray,
    programs::{TcContext, XdpContext},
};
use velstra_common::{
    CgnatLayout, FirewallKey, FirewallState, FlowKey, ICMPV6_ERROR_QUOTE, QUOTE_EXT_MAX, QuoteStep,
    RelatedChecksums, csum_replace_u16, ip_proto, is_ipv6_ext, legacy_napt_seed,
    napt_binding_matches, napt_port, napt_seed, quote_ext_step, related_checksum_copy_length,
    related_checksums, related_hairpin_firewall_candidate, related_icmp_error,
    related_icmpv6_error, related_icmpv6_key,
};

use super::{
    CGNAT, CONNTRACK, FW_FLOWS, IFACE_POLICY, MASQUERADE, NPTV6, ROUTER_NAT_POLICY,
    conntrack::timeouts, existing_napt_port,
};

#[repr(C)]
struct Scratch {
    original: FlowKey,
    restored: FlowKey,
    lookup: FlowKey,
    firewall: FirewallKey,
    outer: [u8; 20],
    quoted: [u8; 20],
    transport: [u8; 8],
    header: [u8; 8],
    new_source: [u8; 4],
    new_destination: [u8; 4],
    icmp_offset: u32,
    quote_offset: u32,
    transport_offset: u32,
    transport_checksum_offset: u32,
    quoted_checksum: u16,
    error_checksum: u16,
    transport_checksum: u16,
    outer_checksum: u16,
    checksum_buffer: [u8; 64],
    has_transport_checksum: u8,
    valid: u8,
}

#[map]
static RELATED_SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

/// Single-use, synchronous tail-call handoff, never authorization across hooks.
/// The attached dispatcher clears its own receipt for EVERY new packet. The
/// consumer clears phase before checking anything, then checks the original
/// generation, physical interface, length and the exact error/header identity.
#[repr(C)]
struct Receipt {
    epoch: u64,
    ifindex: u32,
    length: u32,
    outer: [u8; 20],
    header: [u8; 8],
    phase: u8,
    related: u8,
}

#[map]
static RELATED_XDP_RECEIPT: PerCpuArray<Receipt> = PerCpuArray::with_max_entries(1, 0);
#[map]
static RELATED_TC_RECEIPT: PerCpuArray<Receipt> = PerCpuArray::with_max_entries(1, 0);

pub(super) const CLASSIFIED: u8 = 1;
pub(super) const ADMITTED: u8 = 2;

/// Working set for an ICMPv6 RELATED check. A map slot, not the stack: the
/// IPv6 state stage already carries a full-width tuple.
#[repr(C)]
struct Scratch6 {
    key: FirewallKey,
    outer_dst: [u8; 16],
    quoted: [u8; 40],
    transport: [u8; 8],
    header: [u8; 8],
    ext: [u8; 4],
}

#[map]
static RELATED6_SCRATCH: PerCpuArray<Scratch6> = PerCpuArray::with_max_entries(1, 0);

/// Whether the ICMPv6 message at `off` (the walked upper-layer offset) is an
/// error about a connection live under `policy` (audit DP-21: without this a
/// Packet Too Big never reached a sender behind a deny-by-default zone, and
/// IPv6 path-MTU discovery black-holed).
///
/// Admission only: the error creates no state and refreshes none. The quoted
/// packet's extension headers are walked ([`quote_ext_step`]) to the transport
/// header the error is about. On an NPTv6 boundary (`ifindex` carries a rule)
/// the quote names the inside host by its EXTERNAL address while the flow is
/// recorded under the internal one, so the quoted source is translated before
/// the lookup; [`super::npt66_related_quote_in`] rewrites it in the packet once
/// the error is admitted. See `related_icmpv6_key` for what is refused. Helper
/// loads only, so the walked offset never becomes a packet pointer the
/// verifier must bound.
#[inline(never)]
pub(super) fn related_v6_xdp(ctx: &XdpContext, policy: u32, off: u32, ifindex: u32) -> bool {
    related_v6::<false>(ctx.ctx.cast(), policy, off, ifindex)
}

/// The TC-egress form of [`related_v6_xdp`], for a guest-bound error on a
/// tenant tap whose egress face is its deny-by-default inbound side.
#[inline(never)]
pub(super) fn related_v6_tc(ctx: &TcContext, policy: u32, off: u32, ifindex: u32) -> bool {
    related_v6::<true>(ctx.skb.skb.cast(), policy, off, ifindex)
}

#[inline(always)]
fn related_v6<const TC: bool>(context: *mut c_void, policy: u32, off: u32, ifindex: u32) -> bool {
    let Some(s) = RELATED6_SCRATCH.get_ptr_mut(0) else {
        return false;
    };
    let s = unsafe { &mut *s };
    if read::<TC, 8>(context, off, &mut s.header).is_err()
        || !related_icmpv6_error(s.header[0], s.header[1])
        || read::<TC, 16>(context, 14 + 24, &mut s.outer_dst).is_err()
        || read::<TC, 40>(context, off + ICMPV6_ERROR_QUOTE as u32, &mut s.quoted).is_err()
    {
        return false;
    }
    let Some((upper, transport_off)) =
        quote_upper::<TC>(context, s, off + ICMPV6_ERROR_QUOTE as u32 + 40)
    else {
        return false;
    };
    if read::<TC, 8>(context, transport_off, &mut s.transport).is_err()
        || !related_icmpv6_key(
            policy,
            &s.outer_dst,
            &s.quoted,
            upper,
            &s.transport,
            &mut s.key,
        )
    {
        return false;
    }
    // NPTv6: the flow was recorded before the egress hook translated its
    // source, i.e. under the internal address.
    if let Some(rule) = unsafe { NPTV6.get(&ifindex) }
        && rule.matches_external(&s.key.src)
    {
        s.key.src = rule.translate_in(s.key.src);
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = timeouts();
    let proto = s.key.proto;
    if let Some(state) = unsafe { FW_FLOWS.get(&s.key) }
        && state.phase != FirewallState::RESET
        && !state.expired(proto, now, timeouts)
    {
        return true;
    }
    s.key = s.key.reverse();
    unsafe { FW_FLOWS.get(&s.key) }.is_some_and(|state| {
        state.phase != FirewallState::RESET && !state.expired(proto, now, timeouts)
    })
}

/// Walk the quoted packet's extension headers, starting with the quote's own
/// next header at `start`, to the protocol the error is about and the offset
/// its header starts at. `None` for a later fragment or a chain longer than
/// [`QUOTE_EXT_MAX`].
#[inline(always)]
fn quote_upper<const TC: bool>(
    context: *mut c_void,
    s: &mut Scratch6,
    start: u32,
) -> Option<(u8, u32)> {
    let mut proto = s.quoted[6];
    let mut at = start;
    for _ in 0..QUOTE_EXT_MAX {
        if !is_ipv6_ext(proto) {
            return Some((proto, at));
        }
        read::<TC, 4>(context, at, &mut s.ext).ok()?;
        match quote_ext_step(proto, &s.ext) {
            QuoteStep::Next { proto: next, len } => {
                proto = next;
                at += len;
            }
            QuoteStep::Upper | QuoteStep::Refuse => return None,
        }
    }
    (!is_ipv6_ext(proto)).then_some((proto, at))
}

#[inline(always)]
pub(super) fn reset_xdp() {
    if let Some(receipt) = RELATED_XDP_RECEIPT.get_ptr_mut(0) {
        unsafe { (*receipt).phase = 0 };
    }
}

#[inline(always)]
pub(super) fn reset_tc() {
    if let Some(receipt) = RELATED_TC_RECEIPT.get_ptr_mut(0) {
        unsafe { (*receipt).phase = 0 };
    }
}

#[inline(always)]
fn receipt<const TC: bool>() -> Option<*mut Receipt> {
    if TC {
        RELATED_TC_RECEIPT.get_ptr_mut(0)
    } else {
        RELATED_XDP_RECEIPT.get_ptr_mut(0)
    }
}

#[inline(always)]
fn identity<const TC: bool>(context: *mut c_void, s: &mut Scratch) -> bool {
    if read::<TC, 20>(context, 14, &mut s.outer).is_err() {
        return false;
    }
    let ihl = ((s.outer[0] & 15) as u32) * 4;
    s.outer[0] >> 4 == 4
        && (20..=60).contains(&ihl)
        && s.outer[9] == 1
        && read::<TC, 8>(context, 14 + ihl, &mut s.header).is_ok()
        && related_icmp_error(s.header[0], s.header[1])
}

#[inline(never)]
fn record<const TC: bool>(
    context: *mut c_void,
    epoch: u64,
    packed: u64,
    phase: u8,
    related: bool,
) -> bool {
    let Some(receipt) = receipt::<TC>() else {
        return false;
    };
    let receipt = unsafe { &mut *receipt };
    receipt.phase = 0;
    receipt.related = 0;
    if !super::epoch::unchanged(epoch) {
        return false;
    }
    if related {
        let Some(s) = RELATED_SCRATCH.get_ptr_mut(0) else {
            return false;
        };
        let s = unsafe { &mut *s };
        if !identity::<TC>(context, s) {
            return false;
        }
        receipt.outer = s.outer;
        receipt.header = s.header;
        receipt.related = 1;
    }
    receipt.epoch = epoch;
    receipt.ifindex = (packed >> 32) as u32;
    receipt.length = packed as u32;
    receipt.phase = phase;
    true
}

#[inline(never)]
fn take<const TC: bool>(context: *mut c_void, epoch: u64, packed: u64, phase: u8) -> bool {
    let Some(receipt) = receipt::<TC>() else {
        return false;
    };
    let receipt = unsafe { &mut *receipt };
    let ready = receipt.phase;
    receipt.phase = 0; // Cannot be replayed even after a refused identity check.
    if ready != phase
        || receipt.related != 1
        || receipt.epoch != epoch
        || !super::epoch::unchanged(epoch)
        || receipt.ifindex != (packed >> 32) as u32
        || receipt.length != packed as u32
    {
        return false;
    }
    let Some(s) = RELATED_SCRATCH.get_ptr_mut(0) else {
        return false;
    };
    let s = unsafe { &mut *s };
    identity::<TC>(context, s) && receipt.outer == s.outer && receipt.header == s.header
}

#[inline(always)]
pub(super) fn record_xdp(ctx: &XdpContext, epoch: u64, related: bool) -> bool {
    record::<false>(
        ctx.ctx.cast(),
        epoch,
        ((ctx.ingress_ifindex() as u64) << 32) | (ctx.data_end() - ctx.data()) as u64,
        CLASSIFIED,
        related,
    )
}

#[inline(always)]
pub(super) fn take_xdp(ctx: &XdpContext, epoch: u64) -> bool {
    take::<false>(
        ctx.ctx.cast(),
        epoch,
        ((ctx.ingress_ifindex() as u64) << 32) | (ctx.data_end() - ctx.data()) as u64,
        CLASSIFIED,
    )
}

#[inline(always)]
pub(super) fn record_tc(ctx: &TcContext, epoch: u64, phase: u8, related: bool) -> bool {
    record::<true>(
        ctx.skb.skb.cast(),
        epoch,
        ((unsafe { (*ctx.skb.skb).ifindex } as u64) << 32) | ctx.len() as u64,
        phase,
        related,
    )
}

#[inline(always)]
pub(super) fn take_tc(ctx: &TcContext, epoch: u64, phase: u8) -> bool {
    take::<true>(
        ctx.skb.skb.cast(),
        epoch,
        ((unsafe { (*ctx.skb.skb).ifindex } as u64) << 32) | ctx.len() as u64,
        phase,
    )
}

#[inline(always)]
unsafe fn load<const TC: bool>(
    context: *mut c_void,
    offset: u32,
    output: *mut c_void,
    length: u32,
) -> i64 {
    if TC {
        unsafe { bpf_skb_load_bytes(context, offset, output, length) }
    } else {
        unsafe { bpf_xdp_load_bytes(context.cast(), offset, output, length) }
    }
}

#[inline(always)]
fn read<const TC: bool, const N: usize>(
    context: *mut c_void,
    offset: u32,
    output: &mut [u8; N],
) -> Result<(), ()> {
    if offset > 256
        || unsafe { load::<TC>(context, offset, output.as_mut_ptr().cast(), N as u32) } < 0
    {
        return Err(());
    }
    Ok(())
}

/// Older verifiers lose scalar bounds across LLVM's endian instruction. A
/// volatile, widened reload followed by an explicit mask preserves the actual
/// 16-bit wire value while emitting a bound the verifier can establish itself.
#[inline(always)]
fn bounded_wire_u16(bytes: [u8; 2]) -> u32 {
    let value = u16::from_be_bytes(bytes) as u32;
    unsafe { core::ptr::read_volatile(&value) & 0xffff }
}

#[repr(C)]
struct ChecksumLoop {
    context: *mut c_void,
    buffer: *mut [u8; 64],
    offset: u32,
    length: u32,
    sum: u32,
    failed: u32,
}

/// Each iteration uses a constant-size, zero-padded scratch buffer, never a
/// variable readable range into a packet pointer. The copy helpers also handle
/// non-linear skb data and reject any short packet. Sixty-four-byte chunks
/// preserve checksum word alignment, including an odd final payload byte.
#[inline(never)]
unsafe extern "C" fn checksum_chunk<const TC: bool>(index: u32, opaque: *mut c_void) -> i64 {
    let state = unsafe { &mut *opaque.cast::<ChecksumLoop>() };
    let position = index * 64;
    if index >= 1024 || position >= state.length {
        return 1;
    }
    let length = (state.length - position).min(64);
    // The verifier does not retain the u32 subtraction relation across the
    // callback. Force a real local guard rather than letting LLVM remove it
    // using the earlier `position < state.length` proof.
    let length = unsafe { core::ptr::read_volatile(&length) };
    unsafe { core::ptr::write_bytes(state.buffer.cast::<u8>(), 0, 64) };
    // Linux 6.6 keeps zero in the abstract unsigned range after JEQ zero's
    // nonzero branch. Preserve the refusal above, then emit an explicit 1..64
    // arithmetic bound; the volatile local prevents LLVM folding it back to
    // the original scalar using that branch's stronger language-level proof.
    let Some(length) = related_checksum_copy_length(length) else {
        state.failed = 1;
        return 1;
    };
    if unsafe {
        load::<TC>(
            state.context,
            state.offset + position,
            state.buffer.cast(),
            length,
        )
    } < 0
    {
        state.failed = 1;
        return 1;
    }
    let sum =
        unsafe { bpf_csum_diff(core::ptr::null_mut(), 0, state.buffer.cast(), 64, state.sum) };
    if sum < 0 {
        state.failed = 1;
        return 1;
    }
    state.sum = sum as u32;
    0
}

#[inline(never)]
fn valid_checksum<const TC: bool>(
    context: *mut c_void,
    buffer: &mut [u8; 64],
    offset: u32,
    length: u32,
) -> bool {
    if offset > 256 || length > 65535 || length == 0 {
        return false;
    }
    let mut state = ChecksumLoop {
        context,
        buffer,
        offset,
        length,
        sum: 0,
        failed: 0,
    };
    let result = unsafe {
        bpf_loop(
            (length + 63) / 64,
            checksum_chunk::<TC> as *mut c_void,
            (&mut state as *mut ChecksumLoop).cast(),
            0,
        )
    };
    if result < 0 || state.failed != 0 {
        return false;
    }
    let mut sum = state.sum as u64;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum == 0xffff
}

#[inline(always)]
fn live_firewall(s: &mut Scratch, policy: u32, candidate: u8) -> bool {
    s.lookup = if candidate == 1 {
        s.restored
    } else {
        s.original
    };
    if candidate == 2
        && !related_hairpin_firewall_candidate(&s.original, &s.restored, &mut s.lookup)
    {
        return false;
    }
    s.lookup.policy = policy;
    s.firewall = FirewallKey::ipv4(s.lookup);
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = timeouts();
    if let Some(state) = unsafe { FW_FLOWS.get(&s.firewall) }
        && state.phase != FirewallState::RESET
        && !state.expired(s.lookup.proto, now, timeouts)
    {
        return true;
    }
    s.firewall = s.firewall.reverse();
    unsafe { FW_FLOWS.get(&s.firewall) }.is_some_and(|state| {
        state.phase != FirewallState::RESET && !state.expired(s.lookup.proto, now, timeouts)
    })
}

#[inline(always)]
fn inverse_nat(s: &mut Scratch, policy: u32) -> bool {
    s.lookup = FlowKey::new(
        policy,
        s.original.dst_ip,
        s.original.src_ip,
        s.original.dst_port,
        s.original.src_port,
        s.original.proto,
    );
    if s.original.proto == ip_proto::ICMP {
        // Echo request identifiers occupy FW source-port, NAT reply dst-port.
        if s.original.dst_port != 8 {
            return false;
        }
        s.lookup.src_port = 0;
        s.lookup.dst_port = s.original.src_port;
    }
    let Some(state) = (unsafe { CONNTRACK.get(&s.lookup) }) else {
        return false;
    };
    if state.expired(s.lookup.proto, unsafe { bpf_ktime_get_ns() }, timeouts()) {
        return false;
    }
    if state.is_reverse() {
        s.restored.dst_ip = state.nat_ip;
        if state.nat_port != 0 {
            s.restored.dst_port = state.nat_port;
        }
        if state.has_second() {
            s.restored.src_ip = state.nat2_ip;
            if state.nat2_port != 0 {
                s.restored.src_port = state.nat2_port;
            }
        }
    } else {
        s.restored.src_ip = state.nat_ip;
        if state.nat_port != 0 || s.original.proto == ip_proto::ICMP {
            s.restored.src_port = state.nat_port;
        }
        if state.has_second() {
            s.restored.dst_ip = state.nat2_ip;
            if state.nat2_port != 0 {
                s.restored.dst_port = state.nat2_port;
            }
        }
    }
    true
}

/// Private-origin error about an already un-SNAT'd response. The inverse
/// map is keyed on the public reply tuple, so recover its EXISTING allocated
/// port using the same bounded allocator window; never allocate a new port.
#[inline(always)]
fn forward_masquerade(s: &mut Scratch, policy: u32, ifindex: u32) -> bool {
    let Some(public) = (unsafe { MASQUERADE.get(&ifindex) }).copied() else {
        return false;
    };
    if public == [0; 4] {
        return false;
    }
    s.lookup = FlowKey::new(
        policy,
        s.original.dst_ip,
        s.original.src_ip,
        s.original.dst_port,
        s.original.src_port,
        s.original.proto,
    );
    let mapped = if s.original.proto == ip_proto::ICMP {
        if s.original.dst_port != 0 {
            return false;
        }
        let seed = napt_seed(s.original.dst_ip, s.original.src_ip, s.original.src_port, 0);
        let mut port = 0;
        for probe in 0..8 {
            let candidate = napt_port(seed, probe);
            s.lookup = FlowKey::new(
                policy,
                s.original.src_ip,
                public,
                0,
                candidate,
                ip_proto::ICMP,
            );
            if let Some(state) = unsafe { CONNTRACK.get(&s.lookup) }
                && napt_binding_matches(state, s.original.dst_ip, s.original.src_port)
                && !state.expired(ip_proto::ICMP, unsafe { bpf_ktime_get_ns() }, timeouts())
            {
                port = candidate;
                break;
            }
        }
        port
    } else {
        let layout = (unsafe { CGNAT.get(&ifindex) })
            .copied()
            .unwrap_or(CgnatLayout::default());
        let seed = napt_seed(
            s.lookup.src_ip,
            s.lookup.dst_ip,
            s.lookup.src_port,
            s.lookup.dst_port,
        );
        let mut port = existing_napt_port(&s.lookup, s.lookup.src_ip, public, &layout, seed);
        if port == 0 {
            let legacy = legacy_napt_seed(
                s.lookup.src_ip,
                s.lookup.dst_ip,
                s.lookup.src_port,
                s.lookup.dst_port,
            );
            port = existing_napt_port(&s.lookup, s.lookup.src_ip, public, &layout, legacy);
        }
        if port == 0 && crate::napt_domain::enabled() {
            port = crate::napt_domain::existing(&s.lookup, public, &layout);
        }
        port
    };
    if mapped == 0 {
        return false;
    }
    s.restored.dst_ip = public;
    if s.original.proto == ip_proto::ICMP {
        s.restored.src_port = mapped;
    } else {
        s.restored.dst_port = mapped;
    }
    true
}

#[inline(always)]
fn parse<const TC: bool>(s: &mut Scratch, context: *mut c_void, policy: u32) -> Result<(), ()> {
    s.valid = 0;
    read::<TC, 20>(context, 14, &mut s.outer)?;
    let outer_ihl = ((s.outer[0] & 15) as u32) * 4;
    let total = bounded_wire_u16([s.outer[2], s.outer[3]]);
    if s.outer[0] >> 4 != 4
        || !(20..=60).contains(&outer_ihl)
        || s.outer[9] != 1
        || u16::from_be_bytes([s.outer[6], s.outer[7]]) & 0x3fff != 0
        || total < outer_ihl + 8 + 20 + 8
    {
        return Err(());
    }
    s.icmp_offset = 14 + outer_ihl;
    read::<TC, 8>(context, s.icmp_offset, &mut s.header)?;
    if !related_icmp_error(s.header[0], s.header[1]) {
        return Err(());
    }
    s.quote_offset = s.icmp_offset + 8;
    read::<TC, 20>(context, s.quote_offset, &mut s.quoted)?;
    let inner_ihl = ((s.quoted[0] & 15) as u32) * 4;
    let inner_total = bounded_wire_u16([s.quoted[2], s.quoted[3]]);
    if s.quoted[0] >> 4 != 4
        || !(20..=60).contains(&inner_ihl)
        || inner_total < inner_ihl + 8
        || u16::from_be_bytes([s.quoted[6], s.quoted[7]]) & 0x1fff != 0
        || s.quote_offset + inner_ihl + 8 > 14 + total
        || !valid_checksum::<TC>(context, &mut s.checksum_buffer, 14, outer_ihl)
        || !valid_checksum::<TC>(
            context,
            &mut s.checksum_buffer,
            s.icmp_offset,
            total - outer_ihl,
        )
    {
        return Err(());
    }
    // Linux conntrack treats the quoted header as data, not a second received
    // IPv4 packet. Its checksum may already be corrupt: preserve that residual
    // during incremental inverse NAT, while the full OUTER IPv4/ICMP checksums
    // above and all tuple/live-state/policy proofs below remain mandatory.
    // This intentionally follows Linux parity instead of RFC5508's SHOULD
    // discard recommendation for an invalid embedded IPv4 checksum.
    s.transport_offset = s.quote_offset + inner_ihl;
    read::<TC, 8>(context, s.transport_offset, &mut s.transport)?;
    let proto = s.quoted[9];
    let (sport, dport, check) = match proto {
        ip_proto::TCP => (
            u16::from_be_bytes([s.transport[0], s.transport[1]]),
            u16::from_be_bytes([s.transport[2], s.transport[3]]),
            16,
        ),
        ip_proto::UDP if u16::from_be_bytes([s.transport[4], s.transport[5]]) >= 8 => (
            u16::from_be_bytes([s.transport[0], s.transport[1]]),
            u16::from_be_bytes([s.transport[2], s.transport[3]]),
            6,
        ),
        ip_proto::ICMP if matches!(s.transport[0], 0 | 8) && s.transport[1] == 0 => (
            u16::from_be_bytes([s.transport[4], s.transport[5]]),
            s.transport[0] as u16,
            2,
        ),
        _ => return Err(()),
    };
    s.original = FlowKey::new(
        policy,
        [s.quoted[12], s.quoted[13], s.quoted[14], s.quoted[15]],
        [s.quoted[16], s.quoted[17], s.quoted[18], s.quoted[19]],
        sport,
        dport,
        proto,
    );
    // Error destination must identify the quoted sender, never an unrelated host.
    if s.outer[16..20] != s.original.src_ip {
        return Err(());
    }
    s.restored = s.original;
    s.new_source = [s.outer[12], s.outer[13], s.outer[14], s.outer[15]];
    s.new_destination = s.original.src_ip;
    s.outer_checksum = u16::from_be_bytes([s.outer[10], s.outer[11]]);
    s.quoted_checksum = u16::from_be_bytes([s.quoted[10], s.quoted[11]]);
    s.error_checksum = u16::from_be_bytes([s.header[2], s.header[3]]);
    s.transport_checksum_offset = s.transport_offset + check;
    s.has_transport_checksum = (s.transport_checksum_offset + 2 <= 14 + total
        && check + 2 <= inner_total - inner_ihl) as u8;
    s.transport_checksum = 0;
    if s.has_transport_checksum != 0 {
        let mut bytes = [0u8; 2];
        read::<TC, 2>(context, s.transport_checksum_offset, &mut bytes)?;
        s.transport_checksum = u16::from_be_bytes(bytes);
    }
    Ok(())
}

#[inline(never)]
fn prepare<const TC: bool>(context: *mut c_void, policy: u32, egress_ifindex: u32) -> bool {
    let Some(s) = RELATED_SCRATCH.get_ptr_mut(0) else {
        return false;
    };
    let s = unsafe { &mut *s };
    s.valid = 0; // A refused/truncated packet can never reuse the last CPU's plan.
    if parse::<TC>(s, context, policy).is_err() {
        return false;
    }
    let physical = live_firewall(s, policy, 0);
    let egress = egress_ifindex != 0;
    let nat = inverse_nat(s, policy)
        || (policy != ROUTER_NAT_POLICY && inverse_nat(s, ROUTER_NAT_POLICY))
        || (egress && forward_masquerade(s, policy, egress_ifindex));
    // Deferred source NAT runs AFTER TC's ordinary physical-policy tracking.
    // A hairpin quote therefore contains router->backend, while that hook
    // recorded client->backend. Derive ONLY that exact intermediate tuple from
    // the existing live dual mapping; never substitute global canonical state.
    let physical = physical || (nat && live_firewall(s, policy, 2));
    // XDP must have physical wire-state proof before using the global router
    // namespace. TC may instead prove the restored original tuple: locally
    // generated errors have not visited XDP with their untranslated quote.
    if !physical && !(egress && nat && live_firewall(s, policy, 1)) {
        return false;
    }
    s.new_destination = s.restored.src_ip;
    if egress {
        if nat && s.original.dst_ip != s.restored.dst_ip {
            s.new_source = s.restored.dst_ip;
        } else {
            // XDP already restored a DNAT/hairpin quote. Re-read its original
            // forward binding, but never allocate/refresh a translation here.
            s.lookup = s.restored;
            s.lookup.policy = ROUTER_NAT_POLICY;
            if let Some(state) = unsafe { CONNTRACK.get(&s.lookup) }
                && !state.is_reverse()
                && !state.is_origin()
                && !state.expired(s.lookup.proto, unsafe { bpf_ktime_get_ns() }, timeouts())
            {
                s.new_source = s.restored.dst_ip;
            }
        }
    }
    let checks = related_checksums(
        &s.original,
        &s.restored,
        RelatedChecksums {
            ip: s.quoted_checksum,
            transport: if s.has_transport_checksum != 0 {
                Some(s.transport_checksum)
            } else {
                None
            },
            error: s.error_checksum,
        },
    );
    s.quoted_checksum = checks.ip;
    s.error_checksum = checks.error;
    s.transport_checksum = checks.transport.unwrap_or(0);
    let mut i = 0;
    while i < 4 {
        s.outer_checksum = csum_replace_u16(
            s.outer_checksum,
            u16::from_be_bytes([s.outer[12 + i], s.outer[13 + i]]),
            u16::from_be_bytes([s.new_source[i], s.new_source[i + 1]]),
        );
        s.outer_checksum = csum_replace_u16(
            s.outer_checksum,
            u16::from_be_bytes([s.outer[16 + i], s.outer[17 + i]]),
            u16::from_be_bytes([s.new_destination[i], s.new_destination[i + 1]]),
        );
        i += 2;
    }
    s.valid = 1;
    true
}

#[inline(always)]
pub(super) fn classify_xdp(ctx: &XdpContext, policy: u32) -> bool {
    prepare::<false>(ctx.ctx.cast(), policy, 0)
}

#[inline(always)]
pub(super) fn classify_tc(ctx: &TcContext, policy: u32) -> bool {
    prepare::<true>(ctx.skb.skb.cast(), policy, unsafe {
        (*ctx.skb.skb).ifindex
    })
}

/// The firewall rule key biases ICMP types by one (zero means any type).
#[inline(always)]
pub(super) const fn error_probe(probe: u8) -> bool {
    matches!(probe, 4 | 12 | 13)
}

// As for `read`, the checked pointer must remain local to this subprogram.
#[inline(never)]
unsafe fn put<const N: usize>(
    data: usize,
    end: usize,
    offset: usize,
    bytes: [u8; N],
) -> Result<(), ()> {
    if offset > 256 || data + offset + N > end {
        return Err(());
    }
    unsafe { core::ptr::write_volatile((data + offset) as *mut [u8; N], bytes) };
    Ok(())
}

/// Called only after the ingress policy has allowed the error.
#[inline(never)]
pub(super) fn translate_xdp(ctx: &XdpContext, policy: u32) -> Result<(), ()> {
    if !prepare::<false>(ctx.ctx.cast(), policy, 0) {
        return Err(());
    }
    let s = RELATED_SCRATCH.get(0).ok_or(())?;
    if s.valid != 1 {
        return Err(());
    }
    let (data, end) = (ctx.data(), ctx.data_end());
    unsafe {
        put(data, end, 30, s.new_destination)?;
        put(data, end, 24, s.outer_checksum.to_be_bytes())?;
        put(data, end, s.quote_offset as usize + 12, s.restored.src_ip)?;
        put(data, end, s.quote_offset as usize + 16, s.restored.dst_ip)?;
        put(
            data,
            end,
            s.quote_offset as usize + 10,
            s.quoted_checksum.to_be_bytes(),
        )?;
        let port = s.transport_offset as usize;
        if s.original.proto == 1 {
            put(data, end, port + 4, s.restored.src_port.to_be_bytes())?;
        } else {
            put(data, end, port, s.restored.src_port.to_be_bytes())?;
            put(data, end, port + 2, s.restored.dst_port.to_be_bytes())?;
        }
        if s.has_transport_checksum != 0 {
            put(
                data,
                end,
                s.transport_checksum_offset as usize,
                s.transport_checksum.to_be_bytes(),
            )?;
        }
        put(
            data,
            end,
            s.icmp_offset as usize + 2,
            s.error_checksum.to_be_bytes(),
        )?;
    }
    Ok(())
}

/// TC re-parses after routing; never trust a per-CPU XDP decision across hooks.
#[inline(never)]
pub(super) fn translate_tc(ctx: &TcContext) -> Result<(), ()> {
    let index = unsafe { (*ctx.skb.skb).ifindex };
    let policy = unsafe { IFACE_POLICY.get(&index) }.copied().unwrap_or(0);
    if !prepare::<true>(ctx.skb.skb.cast(), policy, index) {
        return Err(());
    }
    let s = RELATED_SCRATCH.get(0).ok_or(())?;
    if s.valid != 1 {
        return Err(());
    }
    // RECOMPUTE_CSUM updates CHECKSUM_COMPLETE metadata for every nested edit;
    // wire checksum fields are supplied explicitly from the RFC1624 plan.
    const RECOMPUTE: u64 = 1;
    ctx.store(26, &s.new_source, RECOMPUTE).map_err(|_| ())?;
    ctx.store(30, &s.new_destination, RECOMPUTE)
        .map_err(|_| ())?;
    ctx.store(24, &s.outer_checksum.to_be_bytes(), RECOMPUTE)
        .map_err(|_| ())?;
    ctx.store(s.quote_offset as usize + 12, &s.restored.src_ip, RECOMPUTE)
        .map_err(|_| ())?;
    ctx.store(s.quote_offset as usize + 16, &s.restored.dst_ip, RECOMPUTE)
        .map_err(|_| ())?;
    ctx.store(
        s.quote_offset as usize + 10,
        &s.quoted_checksum.to_be_bytes(),
        RECOMPUTE,
    )
    .map_err(|_| ())?;
    if s.original.proto == 1 {
        ctx.store(
            s.transport_offset as usize + 4,
            &s.restored.src_port.to_be_bytes(),
            RECOMPUTE,
        )
        .map_err(|_| ())?;
    } else {
        ctx.store(
            s.transport_offset as usize,
            &s.restored.src_port.to_be_bytes(),
            RECOMPUTE,
        )
        .map_err(|_| ())?;
        ctx.store(
            s.transport_offset as usize + 2,
            &s.restored.dst_port.to_be_bytes(),
            RECOMPUTE,
        )
        .map_err(|_| ())?;
    }
    if s.has_transport_checksum != 0 {
        ctx.store(
            s.transport_checksum_offset as usize,
            &s.transport_checksum.to_be_bytes(),
            RECOMPUTE,
        )
        .map_err(|_| ())?;
    }
    ctx.store(
        s.icmp_offset as usize + 2,
        &s.error_checksum.to_be_bytes(),
        RECOMPUTE,
    )
    .map_err(|_| ())?;
    Ok(())
}
