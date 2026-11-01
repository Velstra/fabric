//! Validate before state lookup, independently of linear skb payload layout.
use core::sync::atomic::{AtomicU32, Ordering};

use aya_ebpf::{
    helpers::bpf_loop,
    macros::map,
    maps::PerCpuArray,
    programs::{TcContext, XdpContext},
};
use velstra_common::{
    Counter, FirewallPacketFlow, FirewallPacketReader, FlowScope, MAX_TCP_SEGMENT_LEN,
    SynMssParser, TcpHeaderParser, TcpSegment, firewall_packet_flow_v6, firewall_packet_valid,
};

/// Keep option parsing independent of variable packet-pointer ranges. Logical
/// headers remain limited to 60 bytes; padding accommodates verifier coarsening.
#[repr(C)]
struct Scratch {
    busy: u32,
    transport_len: u32,
    parser: TcpHeaderParser,
    mss_parser: SynMssParser,
    header: [u8; 128],
}
#[map]
static FW_PKT_BUF: PerCpuArray<Scratch> = PerCpuArray::with_max_entries(1, 0);

trait ScratchReader: FirewallPacketReader {
    fn scratch(&self) -> *mut Scratch;
}
struct XdpReader {
    start: *const u8,
    end: *const u8,
    scratch: *mut Scratch,
    boundary_if: u32,
}
impl FirewallPacketReader for XdpReader {
    #[inline(always)]
    fn frame_len(&self) -> usize {
        self.end as usize - self.start as usize
    }
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if offset > 65589 || self.start.wrapping_add(offset + N) > self.end {
            return None;
        }
        // SAFETY: current hook's packet pointers, full read bounds checked.
        Some(unsafe { *self.start.wrapping_add(offset).cast::<[u8; N]>() })
    }
    #[inline(always)]
    fn tcp_valid(&self, offset: usize, len: usize) -> Option<bool> {
        // SAFETY: validation owns the buffer's non-reentrant per-CPU guard.
        Some(unsafe { stage_tcp(self, offset, len) })
    }
    #[inline(always)]
    fn tcp_segment(&self, offset: usize, len: usize) -> Option<TcpSegment> {
        unsafe {
            stage_tcp(self, offset, len)
                .then(|| (*self.scratch).parser.finish())
                .flatten()
        }
    }
    #[inline(always)]
    fn normalize_v6_destination(&self, destination: [u8; 16]) -> [u8; 16] {
        if self.boundary_if == 0 {
            return destination;
        }
        unsafe { super::NPTV6.get(&self.boundary_if) }
            .filter(|rule| rule.matches_external(&destination))
            .map(|rule| rule.translate_in(destination))
            .unwrap_or(destination)
    }
}
impl ScratchReader for XdpReader {
    #[inline(always)]
    fn scratch(&self) -> *mut Scratch {
        self.scratch
    }
}
struct TcReader<'a> {
    ctx: &'a TcContext,
    scratch: *mut Scratch,
}
impl FirewallPacketReader for TcReader<'_> {
    #[inline(always)]
    fn segmentation_offload(&self) -> bool {
        // Kernel skb metadata, never inferred from an untrusted IP header.
        unsafe { (*self.ctx.skb.skb).gso_size != 0 }
    }
    #[inline(always)]
    fn frame_len(&self) -> usize {
        self.ctx.len() as usize
    }
    #[inline(always)]
    fn read<const N: usize>(&self, offset: usize) -> Option<[u8; N]> {
        if offset > 65589 || offset + N > self.frame_len() {
            return None;
        }
        self.ctx.load(offset).ok()
    }
    #[inline(always)]
    fn tcp_valid(&self, offset: usize, len: usize) -> Option<bool> {
        // SAFETY: validation owns the buffer's non-reentrant per-CPU guard.
        Some(unsafe { stage_tcp(self, offset, len) })
    }
    #[inline(always)]
    fn tcp_segment(&self, offset: usize, len: usize) -> Option<TcpSegment> {
        unsafe {
            stage_tcp(self, offset, len)
                .then(|| (*self.scratch).parser.finish())
                .flatten()
        }
    }
}
impl ScratchReader for TcReader<'_> {
    #[inline(always)]
    fn scratch(&self) -> *mut Scratch {
        self.scratch
    }
}

#[inline(never)]
unsafe fn stage_tcp(reader: &impl ScratchReader, offset: usize, len: usize) -> bool {
    let Some([data_offset]) = reader.read::<1>(offset + 12) else {
        return false;
    };
    let header_len = ((data_offset >> 4) as usize) * 4;
    if header_len < 20 || header_len > len || len > MAX_TCP_SEGMENT_LEN {
        return false;
    }
    let scratch = reader.scratch();
    // SAFETY: caller holds the guard. Only initialized logical bytes are parsed.
    unsafe {
        (*scratch).transport_len = len as u32;
        for index in 0..15 {
            let part = index * 4;
            if part >= header_len {
                break;
            }
            let Some(word) = reader.read::<4>(offset + part) else {
                return false;
            };
            let Some(target) = (&mut (*scratch).header).get_mut(part..part + 4) else {
                return false;
            };
            target.copy_from_slice(&word);
        }
        parse_options(&mut *scratch)
    }
}
#[repr(C)]
struct OptionContext {
    scratch: *mut Scratch,
}
#[inline(never)]
unsafe extern "C" fn option_step(_index: u64, context: *mut OptionContext) -> i64 {
    // SAFETY: bpf_loop receives this invocation's live stack context, and the
    // caller owns the map buffer until the helper returns synchronously.
    let scratch = unsafe { &mut *(*context).scratch };
    let header = &scratch.header;
    if scratch.parser.step(|offset| {
        if offset >= 60 {
            return None;
        }
        header.get(offset).copied()
    }) {
        0
    } else {
        1
    }
}
#[inline(never)]
fn parse_options(scratch: &mut Scratch) -> bool {
    let Some(head) = scratch.header.get(..20).and_then(|v| v.try_into().ok()) else {
        return false;
    };
    let Some(parser) = TcpHeaderParser::new(head, scratch.transport_len as usize) else {
        return false;
    };
    scratch.parser = parser;
    let mut context = OptionContext { scratch };
    // The kernel verifies one bounded callback, rather than exploring every
    // combination of up to 40 untrusted option bytes in each forwarding path.
    let result = unsafe {
        bpf_loop(
            40,
            option_step as *mut _,
            (&mut context as *mut OptionContext).cast(),
            0,
        )
    };
    result >= 0 && scratch.parser.finish().is_some()
}
#[inline(always)]
fn acquire() -> Option<*mut Scratch> {
    let ptr = FW_PKT_BUF.get_ptr_mut(0)?;
    // SAFETY: aligned u32 in the live per-CPU map; only this guard mutates it.
    let lock = unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() };
    lock.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .ok()?;
    Some(ptr)
}
#[inline(always)]
fn finish(ptr: *mut Scratch, valid: bool) -> bool {
    // SAFETY: this invocation acquired the guard and has finished all reads.
    let lock = unsafe { &*core::ptr::addr_of!((*ptr).busy).cast::<AtomicU32>() };
    lock.swap(0, Ordering::Release);
    if !valid {
        super::bump(Counter::Malformed);
    }
    valid
}
#[inline(always)]
pub fn xdp_valid(ctx: &XdpContext) -> bool {
    let Some(scratch) = acquire() else {
        super::bump(Counter::PacketValidationContention);
        return false;
    };
    // SAFETY: current packet region and exclusive per-CPU buffer ownership.
    let valid = unsafe {
        xdp_region_valid(
            ctx.data() as *const u8,
            ctx.data_end() as *const u8,
            scratch,
        )
    };
    finish(scratch, valid)
}
#[inline(never)]
unsafe fn xdp_region_valid(start: *const u8, end: *const u8, scratch: *mut Scratch) -> bool {
    firewall_packet_valid(&XdpReader {
        start,
        end,
        scratch,
        boundary_if: 0,
    })
}
#[inline(always)]
pub fn tc_valid(ctx: &TcContext) -> bool {
    let Some(scratch) = acquire() else {
        super::bump(Counter::PacketValidationContention);
        return false;
    };
    let valid = tc_region_valid(ctx, scratch);
    finish(scratch, valid)
}
#[inline(never)]
fn tc_region_valid(ctx: &TcContext, scratch: *mut Scratch) -> bool {
    firewall_packet_valid(&TcReader { ctx, scratch })
}

/// The caller owns `out` independently of the option-parser buffer. Nested
/// packet execution cannot reuse either guarded per-CPU allocation.
#[inline(never)]
pub fn xdp_flow_v6(
    ctx: &XdpContext,
    scope: FlowScope,
    boundary_if: u32,
    out: &mut FirewallPacketFlow,
) -> Option<bool> {
    let scratch = acquire()?;
    let result = firewall_packet_flow_v6(
        &XdpReader {
            start: ctx.data() as *const u8,
            end: ctx.data_end() as *const u8,
            scratch,
            boundary_if,
        },
        scope,
        out,
    );
    finish(scratch, result.is_some());
    result
}

#[inline(never)]
pub fn tc_flow_v6(ctx: &TcContext, scope: FlowScope, out: &mut FirewallPacketFlow) -> Option<bool> {
    let scratch = acquire()?;
    let result = firewall_packet_flow_v6(&TcReader { ctx, scratch }, scope, out);
    finish(scratch, result.is_some());
    result
}

/// Read the peer's MSS from the complete validated SYN header. This path is
/// independent of stateful tracking: stateless SYN protection needs the same
/// length/option checks before it can mint a cookie.
#[inline(never)]
pub fn xdp_syn_mss(ctx: &XdpContext) -> Option<u16> {
    let scratch = acquire()?;
    let result = unsafe {
        region_syn_mss(
            ctx.data() as *const u8,
            ctx.data_end() as *const u8,
            scratch,
        )
    };
    finish(scratch, result.is_some());
    result
}

#[inline(never)]
unsafe fn region_syn_mss(start: *const u8, end: *const u8, scratch: *mut Scratch) -> Option<u16> {
    let reader = XdpReader {
        start,
        end,
        scratch,
        boundary_if: 0,
    };
    let ip = reader.read::<20>(14)?;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ip[0] != 0x45
        || ip[9] != velstra_common::ip_proto::TCP
        || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
        || total < 40
        || total + 14 > reader.frame_len()
    {
        return None;
    }
    let [data_offset] = reader.read::<1>(46)?;
    let header_len = (data_offset >> 4) as usize * 4;
    let [flags] = reader.read::<1>(47)?;
    if header_len < 20
        || header_len > total - 20
        || flags
            & (velstra_common::tcp_flags::SYN
                | velstra_common::tcp_flags::ACK
                | velstra_common::tcp_flags::FIN
                | velstra_common::tcp_flags::RST)
            != velstra_common::tcp_flags::SYN
    {
        return None;
    }
    // Only options are needed for a stateless challenge. Validate their full
    // declared range, without nesting the protocol-state parser's stack frames
    // under the IPv4 forwarding program. No protocol state is created here.
    unsafe {
        (*scratch).mss_parser = SynMssParser::new(header_len as u8)?;
        for index in 5..15 {
            let part = index * 4;
            if part >= header_len {
                break;
            }
            let word = reader.read::<4>(34 + part)?;
            (&mut (*scratch).header)
                .get_mut(part..part + 4)?
                .copy_from_slice(&word);
        }
    }
    let mut context = OptionContext { scratch };
    let result = unsafe {
        bpf_loop(
            40,
            mss_step as *mut _,
            (&mut context as *mut OptionContext).cast(),
            0,
        )
    };
    if result < 0 {
        return None;
    }
    unsafe { (*scratch).mss_parser.finish() }
}

#[inline(never)]
unsafe extern "C" fn mss_step(_index: u64, context: *mut OptionContext) -> i64 {
    let scratch = unsafe { &mut *(*context).scratch };
    let header = &scratch.header;
    if scratch.mss_parser.step(|offset| {
        if offset >= 60 {
            return None;
        }
        header.get(offset).copied()
    }) {
        0
    } else {
        1
    }
}
