//! Address translation of forwarded IPv4 fragments (DP-05).
//!
//! Only a datagram's first fragment carries its L4 header, so only it can be
//! matched against NAT state and have its ports and L4 checksum rewritten. When
//! such a first fragment is translated, the rewrite of its IPv4 addresses is
//! recorded under the datagram's identity (RFC 791: source, destination,
//! protocol, identification) as it looked before translation. Later fragments
//! then receive exactly that address rewrite and an IPv4 header checksum
//! update; their payload is never touched. A later fragment without a record
//! that would otherwise leave a masquerade uplink with a source the box does
//! not own is refused, never sent untranslated.
//!
//! Limits, stated rather than hidden: fragments that overtake their first
//! fragment are dropped (no reassembly); two inside hosts that pick the same
//! identification toward the same server collide after source translation
//! exactly as with Linux NAT without defragmentation.
//!
//! BPF functions take at most five register arguments, so the small scalars of
//! a call are packed into one `u64` ([`meta`]) and keys are built in per-CPU
//! scratch, not on the callers' nearly full stacks.

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{LruHashMap, PerCpuArray},
    programs::{TcContext, XdpContext},
};
use velstra_common::{
    Counter, FRAGMENT_HOOK_EGRESS, FRAGMENT_HOOK_INGRESS, FragmentKey, FragmentNat,
    FragmentPosition,
};

use super::{O_IP_CSUM, O_IP_DST, O_IP_ID, O_IP_SRC, bump};

pub(super) const HOOK_EGRESS: u8 = FRAGMENT_HOOK_EGRESS;
pub(super) const HOOK_INGRESS: u8 = FRAGMENT_HOOK_INGRESS;

#[map]
static FRAG_NAT: LruHashMap<FragmentKey, FragmentNat> = LruHashMap::with_max_entries(8192, 0);

#[repr(C)]
struct Scratch {
    key: FragmentKey,
    value: FragmentNat,
}
#[map]
static FRAG_SCRATCH: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

/// Pack a call's scalars: protocol, hook (or a flag), the IPv4 flags/offset
/// word, the identification and (ingress only) the header checksum.
#[inline(always)]
pub(super) fn meta(proto: u8, hook: u8, fragment_word: u16, id: u16, checksum: u16) -> u64 {
    proto as u64
        | (hook as u64) << 8
        | (fragment_word as u64) << 16
        | (id as u64) << 32
        | (checksum as u64) << 48
}

#[inline(always)]
fn addr(word: u32) -> [u8; 4] {
    word.to_ne_bytes()
}

/// Write the datagram key for (`src`, `dst`, `meta`) into scratch.
#[inline(always)]
fn scratch_key(src: u32, dst: u32, meta: u64, hook: u8) -> Option<*mut Scratch> {
    let scratch = FRAG_SCRATCH.get_ptr_mut(0)?;
    unsafe {
        (*scratch).key = FragmentKey {
            src: addr(src),
            dst: addr(dst),
            id: (meta >> 32) as u16,
            proto: meta as u8,
            hook,
        };
    }
    Some(scratch)
}

/// Remember how a translated FIRST fragment's addresses were rewritten.
/// Unfragmented packets and later fragments record nothing. Addresses are the
/// wire bytes as native-endian words (`u32::from_ne_bytes`).
#[inline(never)]
pub(super) fn note_first(src: u32, dst: u32, meta: u64, new_src: u32, new_dst: u32) {
    record(src, dst, meta, new_src, new_dst);
}

/// Shared body, inlined into each recording subprogram: one call level only,
/// because the forwarding tail has no stack left for a nested frame.
#[inline(always)]
fn record(src: u32, dst: u32, meta: u64, new_src: u32, new_dst: u32) {
    if FragmentPosition::of((meta >> 16) as u16) != FragmentPosition::First {
        return;
    }
    let Some(scratch) = scratch_key(src, dst, meta, (meta >> 8) as u8) else {
        return;
    };
    unsafe {
        (*scratch).value = FragmentNat {
            src: addr(new_src),
            dst: addr(new_dst),
            created_ns: bpf_ktime_get_ns(),
        };
        // Best effort: a failed insert leaves the later fragments unrecorded,
        // which the egress hook refuses rather than leaks.
        let _ = FRAG_NAT.insert(&(*scratch).key, &(*scratch).value, 0);
    }
}

/// [`note_first`] for XDP ingress, reading identification and fragment word
/// from the packet itself so the forwarding tail keeps them off its stack.
/// `src_proto` is the source address word with the protocol in bits 32..40.
#[inline(never)]
pub(super) fn note_first_xdp(
    ctx: &XdpContext,
    src_proto: u64,
    dst: u32,
    new_src: u32,
    new_dst: u32,
) {
    let data = ctx.data();
    if data + O_IP_ID + 4 > ctx.data_end() {
        return;
    }
    let ident = unsafe { *((data + O_IP_ID) as *const [u8; 4]) };
    record(
        src_proto as u32,
        dst,
        meta(
            (src_proto >> 32) as u8,
            HOOK_INGRESS,
            u16::from_be_bytes([ident[2], ident[3]]),
            u16::from_be_bytes([ident[0], ident[1]]),
            0,
        ),
        new_src,
        new_dst,
    );
}

#[inline(always)]
fn lookup(src: u32, dst: u32, meta: u64, hook: u8) -> Option<FragmentNat> {
    let scratch = scratch_key(src, dst, meta, hook)?;
    let nat = unsafe { FRAG_NAT.get(&(*scratch).key) }.copied()?;
    if !nat.live(unsafe { bpf_ktime_get_ns() }) {
        return None;
    }
    Some(nat)
}

/// TC egress, LATER fragments only. `TC_ACT_OK` after translating one,
/// `TC_ACT_SHOT` for one that would leak its source (`must_translate`), and
/// `-1` to continue with the ordinary egress path.
#[inline(never)]
pub(super) fn egress_later(ctx: &TcContext, src: u32, dst: u32, meta: u64) -> i32 {
    let must_translate = (meta >> 8) as u8 != 0;
    let Some(nat) = lookup(src, dst, meta, HOOK_EGRESS) else {
        if must_translate {
            bump(Counter::EgressDropped);
            bump(Counter::EgressNatFragmentDropped);
            return TC_ACT_SHOT as i32;
        }
        return -1;
    };
    if rewrite_tc(ctx, addr(src), nat.src, O_IP_SRC).is_err()
        || rewrite_tc(ctx, addr(dst), nat.dst, O_IP_DST).is_err()
    {
        bump(Counter::EgressDropped);
        return TC_ACT_SHOT as i32;
    }
    bump(Counter::FragmentNatTranslated);
    TC_ACT_OK as i32
}

#[inline(always)]
fn rewrite_tc(ctx: &TcContext, old: [u8; 4], new: [u8; 4], offset: usize) -> Result<(), ()> {
    if old == new {
        return Ok(());
    }
    // The address is not covered by any L4 checksum in a later fragment.
    ctx.l3_csum_replace(
        O_IP_CSUM,
        u32::from_ne_bytes(old) as u64,
        u32::from_ne_bytes(new) as u64,
        4,
    )
    .map_err(|_| ())?;
    ctx.store(offset, &new, 0).map_err(|_| ())
}

/// XDP ingress, LATER fragments only: true after translating one, which the
/// caller then passes to the kernel for routing. A miss changes nothing.
/// `meta` carries the packet's IPv4 header checksum.
#[inline(never)]
pub(super) fn ingress_later(ctx: &XdpContext, src: u32, dst: u32, meta: u64) -> bool {
    let Some(nat) = lookup(src, dst, meta, HOOK_INGRESS) else {
        return false;
    };
    let data = ctx.data();
    if data + O_IP_DST + 4 > ctx.data_end() {
        return false;
    }
    let checksum = nat.header_checksum((meta >> 48) as u16, addr(src), addr(dst));
    // Constant offsets from one freshly bounds-checked packet pointer.
    unsafe {
        *((data + O_IP_SRC) as *mut [u8; 4]) = nat.src;
        *((data + O_IP_DST) as *mut [u8; 4]) = nat.dst;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = checksum.to_be_bytes();
    }
    bump(Counter::FragmentNatTranslated);
    true
}
