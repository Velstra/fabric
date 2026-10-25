//! Raw-IP links (WireGuard, PPP and IP tunnels) have no Ethernet header.
//! Give the shared classifier a temporary header, then remove it before the
//! kernel sees the packet. Nothing synthetic is transmitted on the tunnel.
use aya_ebpf::{
    bindings::{
        BPF_F_ADJ_ROOM_FIXED_GSO, BPF_F_ADJ_ROOM_NO_CSUM_RESET, TC_ACT_OK, TC_ACT_SHOT,
        bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, xdp_action,
    },
    helpers::bpf_xdp_adjust_head,
    macros::map,
    maps::HashMap,
    programs::{TcContext, XdpContext},
};

#[map]
static IFACE_L3: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

#[inline(always)]
pub fn raw_ip(index: u32) -> bool {
    unsafe { IFACE_L3.get(&index) }.is_some()
}

#[inline(always)]
fn header(data: usize, end: usize) -> Option<[u8; 14]> {
    if data + 4 > end {
        return None;
    }
    match (unsafe { core::ptr::read_volatile(data as *const u32) } as u8) >> 4 {
        4 => Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0]),
        6 => Some([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x86, 0xdd]),
        _ => None,
    }
}

#[inline(always)]
pub fn enter_xdp(ctx: &XdpContext) -> bool {
    if !raw_ip(ctx.ingress_ifindex() as u32) {
        return true;
    }
    let Some(header) = header(ctx.data(), ctx.data_end()) else {
        return false;
    };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -14) } != 0 {
        return false;
    }
    let data = ctx.data();
    if data + 14 > ctx.data_end() {
        return false;
    }
    unsafe {
        *(data as *mut [u8; 14]) = header;
    }
    true
}

#[inline(always)]
pub fn finish_xdp(ctx: &XdpContext, action: u32) -> u32 {
    if !raw_ip(ctx.ingress_ifindex() as u32) {
        return action;
    }
    // Raw-IP links use kernel FIB forwarding and TC egress. Ethernet redirect
    // and active Ethernet rejects cannot be transmitted on these devices.
    if action != xdp_action::XDP_PASS {
        return xdp_action::XDP_DROP;
    }
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 14) } != 0 {
        return xdp_action::XDP_DROP;
    }
    action
}

const FLAGS: u64 = (BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_NO_CSUM_RESET) as u64;

#[inline(always)]
pub fn enter_tc(ctx: &TcContext) -> bool {
    let index = unsafe { (*ctx.skb.skb).ifindex };
    if !raw_ip(index) {
        return true;
    }
    let Some(header) = header(ctx.data(), ctx.data_end()) else {
        return false;
    };
    if ctx.adjust_room(14, BPF_ADJ_ROOM_MAC, FLAGS).is_err() {
        return false;
    }
    ctx.store(0, &header, 0).is_ok()
}

#[inline(always)]
pub fn finish_tc(ctx: &TcContext, action: i32) -> i32 {
    let index = unsafe { (*ctx.skb.skb).ifindex };
    if raw_ip(index)
        && action == TC_ACT_OK as i32
        && ctx.adjust_room(-14, BPF_ADJ_ROOM_MAC, FLAGS).is_err()
    {
        return TC_ACT_SHOT as i32;
    }
    action
}
