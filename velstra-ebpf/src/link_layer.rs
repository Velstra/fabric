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
    maps::{HashMap, PerCpuArray},
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

/// Whether the frame at `data` already starts with an Ethernet-shaped header
/// for the IP packet behind it: an EtherType of IPv4/IPv6 at bytes 12..14, the
/// matching version at byte 14, and an IP length that accounts for exactly the
/// rest of the frame — the last is what tells a real header from a bare packet
/// whose source address happens to read like one.
///
/// A raw-IP link can still hand generic XDP a MAC header: a packet decrypted
/// by IPsec tunnel mode and delivered on an XFRM interface keeps the Ethernet
/// header of the frame the ESP arrived in (`skb_mac_header_rebuild`), and
/// generic XDP starts the packet at the MAC header. That frame is already what
/// the classifier expects; pushing another header in front of it parsed MAC
/// bytes as an IP version and dropped every packet the tunnel delivered.
#[inline(always)]
fn carries_ethernet(data: usize, end: usize) -> bool {
    if data + 34 > end {
        return false;
    }
    let head = unsafe { core::ptr::read_volatile(data as *const [u8; 20]) };
    let ip_len = match (head[12], head[13], head[14] >> 4) {
        (0x08, 0x00, 4) => u16::from_be_bytes([head[16], head[17]]) as usize,
        (0x86, 0xdd, 6) => u16::from_be_bytes([head[18], head[19]]) as usize + 40,
        _ => return false,
    };
    ip_len == end - data - 14
}

/// How the packet this CPU is classifying entered: [`ETHERNET`] (an Ethernet
/// link), [`RAW_PUSHED`] (a raw-IP link, temporary header pushed) or
/// [`RAW_FRAMED`] (a raw-IP link that delivered a MAC header of its own).
/// Written by [`enter_xdp`] for every packet and read by [`finish_xdp`] at the
/// end of the same tail-call chain, which runs on one CPU uninterrupted.
///
#[map]
static XDP_FRAMING: PerCpuArray<u32> = PerCpuArray::with_max_entries(1, 0);

const ETHERNET: u32 = 0;
const RAW_PUSHED: u32 = 1;
const RAW_FRAMED: u32 = 2;

#[inline(always)]
fn set_framing(framing: u32) -> bool {
    match XDP_FRAMING.get_ptr_mut(0) {
        Some(slot) => {
            unsafe { *slot = framing };
            true
        }
        None => false,
    }
}

#[inline(always)]
pub fn enter_xdp(ctx: &XdpContext) -> bool {
    if !raw_ip(ctx.ingress_ifindex() as u32) {
        return set_framing(ETHERNET);
    }
    // A frame that arrived Ethernet-shaped (see `carries_ethernet`) is left
    // as it is.
    if carries_ethernet(ctx.data(), ctx.data_end()) {
        return set_framing(RAW_FRAMED);
    }
    let Some(header) = header(ctx.data(), ctx.data_end()) else {
        return false;
    };
    if !set_framing(RAW_PUSHED) {
        return false;
    }
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

/// Out of line: inlined into the forwarding program, even the framing check
/// tipped LLVM's register allocation there into code the verifier refuses.
#[inline(never)]
pub fn finish_xdp(ctx: &XdpContext, action: u32) -> u32 {
    let framing = match XDP_FRAMING.get(0) {
        Some(framing) => *framing,
        None => ETHERNET,
    };
    if framing == ETHERNET {
        return action;
    }
    // Raw-IP links use kernel FIB forwarding and TC egress. Ethernet redirect
    // and active Ethernet rejects cannot be transmitted on these devices.
    if action != xdp_action::XDP_PASS {
        return xdp_action::XDP_DROP;
    }
    // Remove only a header `enter_xdp` added; a frame that arrived with its
    // own goes back to the kernel as it came.
    if framing == RAW_PUSHED && unsafe { bpf_xdp_adjust_head(ctx.ctx, 14) } != 0 {
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
