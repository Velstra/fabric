//! Plain IPv6 reject: a TCP RST, or an ICMPv6 port-unreachable for UDP.
//! Extension-header/fragment rejects remain unsupported; never reinterpret
//! their payload at fixed L4 offsets or answer them.
use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_xdp_adjust_head, bpf_xdp_adjust_tail},
    programs::XdpContext,
};
use velstra_common::{
    Counter, ICMPV6_UNREACH_FRAME, ICMPV6_UNREACH_PREPEND, ICMPV6_UNREACH_QUOTE,
    icmpv6_error_allowed, ip_proto, plan_icmpv6_port_unreachable, plan_tcp_rst_v6, tcp_flags,
};

use super::{bump, ptr_at};

#[inline(never)]
pub(super) fn tcp(ctx: &XdpContext, off: usize) -> u32 {
    try_tcp(ctx, off).unwrap_or(xdp_action::XDP_DROP)
}

#[inline(always)]
fn try_tcp(ctx: &XdpContext, off: usize) -> Result<u32, ()> {
    if off != 54 {
        return Ok(xdp_action::XDP_DROP);
    }
    let ip = unsafe { *ptr_at::<[u8; 40]>(ctx, 14)? };
    let tcp = unsafe { *ptr_at::<[u8; 20]>(ctx, 54)? };
    let flags = tcp[13];
    let header_len = (tcp[12] >> 4) as u16 * 4;
    let payload_len = u16::from_be_bytes([ip[4], ip[5]]);
    let frame_len = ctx.data_end() - ctx.data();
    if ip[0] >> 4 != 6
        || ip[6] != ip_proto::TCP
        || flags & tcp_flags::RST != 0
        || header_len < 20
        || header_len > payload_len
        || frame_len < 54 + payload_len as usize
        || frame_len > 65589
        || ip[8] == 0xff
        || ip[24] == 0xff
        || ip[8..24] == [0; 16]
    {
        return Ok(xdp_action::XDP_DROP);
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    dst.copy_from_slice(&ip[24..40]);
    let rst = plan_tcp_rst_v6(
        src,
        dst,
        u16::from_be_bytes([tcp[0], tcp[1]]),
        u16::from_be_bytes([tcp[2], tcp[3]]),
        u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags,
        (payload_len - header_len) as u32
            + (flags & tcp_flags::SYN != 0) as u32
            + (flags & tcp_flags::FIN != 0) as u32,
    );
    let eth = unsafe { *ptr_at::<[u8; 14]>(ctx, 0)? };
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, 74 - frame_len as i32) } != 0 {
        return Err(());
    }
    // Resizing invalidated packet pointers. Reacquire and prove the entire
    // response before any write; no stale options, payload or pseudo-header.
    let data = ctx.data();
    if data + 74 > ctx.data_end() {
        return Err(());
    }
    let mut reply_ip = [0u8; 40];
    reply_ip[0] = 0x60;
    reply_ip[4..6].copy_from_slice(&20u16.to_be_bytes());
    reply_ip[6] = ip_proto::TCP;
    reply_ip[7] = 64;
    reply_ip[8..24].copy_from_slice(&dst);
    reply_ip[24..40].copy_from_slice(&src);
    let mut reply_tcp = [0u8; 20];
    reply_tcp[..2].copy_from_slice(&tcp[2..4]);
    reply_tcp[2..4].copy_from_slice(&tcp[..2]);
    reply_tcp[4..8].copy_from_slice(&rst.seq.to_be_bytes());
    reply_tcp[8..12].copy_from_slice(&rst.ack.to_be_bytes());
    reply_tcp[12] = 5 << 4;
    reply_tcp[13] = rst.flags;
    reply_tcp[16..18].copy_from_slice(&rst.tcp_checksum.to_be_bytes());
    unsafe {
        *((data) as *mut [u8; 6]) = eth[6..12].try_into().map_err(|_| ())?;
        *((data + 6) as *mut [u8; 6]) = eth[..6].try_into().map_err(|_| ())?;
        *((data + 14) as *mut [u8; 40]) = reply_ip;
        *((data + 54) as *mut [u8; 20]) = reply_tcp;
    }
    bump(Counter::Rejected);
    Ok(xdp_action::XDP_TX)
}

/// Answer a rejected IPv6 UDP datagram with an ICMPv6 port-unreachable bounced
/// out the ingress interface (DP-35: it used to be dropped, so a rejected UDP
/// port looked like a filtered one and the sender waited for its timeout).
///
/// The frame grows by a fresh IPv6 + ICMPv6 header at the head, which leaves the
/// datagram's own IPv6 and UDP headers exactly where the 48-byte quote belongs,
/// and is trimmed behind the quote. Anything RFC 4443 says must not be answered
/// is dropped instead (see `icmpv6_error_allowed`).
#[inline(never)]
pub(super) fn udp(ctx: &XdpContext, off: usize) -> u32 {
    try_udp(ctx, off).unwrap_or(xdp_action::XDP_DROP)
}

#[inline(always)]
fn try_udp(ctx: &XdpContext, off: usize) -> Result<u32, ()> {
    if off != 54 {
        return Ok(xdp_action::XDP_DROP);
    }
    let quote = unsafe { *ptr_at::<[u8; ICMPV6_UNREACH_QUOTE]>(ctx, 14)? };
    let eth = unsafe { *ptr_at::<[u8; 14]>(ctx, 0)? };
    let frame_len = ctx.data_end() - ctx.data();
    if quote[6] != ip_proto::UDP || !icmpv6_error_allowed(&quote, eth[0]) || frame_len > 65535 {
        return Ok(xdp_action::XDP_DROP);
    }
    let plan = plan_icmpv6_port_unreachable(&quote);
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(ICMPV6_UNREACH_PREPEND as i32)) } != 0 {
        return Err(());
    }
    // `frame_len` is at least the 62 bytes the quote read proved, so the grown
    // frame is never shorter than the error and this only ever trims.
    let grown = frame_len + ICMPV6_UNREACH_PREPEND;
    if unsafe { bpf_xdp_adjust_tail(ctx.ctx, ICMPV6_UNREACH_FRAME as i32 - grown as i32) } != 0 {
        return Err(());
    }
    // Both helpers invalidated packet pointers: prove the whole reply again
    // before any write.
    let data = ctx.data();
    if data + ICMPV6_UNREACH_FRAME > ctx.data_end() {
        return Err(());
    }
    unsafe {
        *((data) as *mut [u8; 6]) = eth[6..12].try_into().map_err(|_| ())?;
        *((data + 6) as *mut [u8; 6]) = eth[..6].try_into().map_err(|_| ())?;
        *((data + 12) as *mut [u8; 2]) = [0x86, 0xdd];
        *((data + 14) as *mut [u8; 40]) = plan.ip;
        *((data + 54) as *mut [u8; 8]) = plan.icmp;
        *((data + 62) as *mut [u8; ICMPV6_UNREACH_QUOTE]) = quote;
    }
    bump(Counter::Rejected);
    Ok(xdp_action::XDP_TX)
}
