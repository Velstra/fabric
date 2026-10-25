//! Identifier-aware ICMP echo SNAT. Separate tails keep NAT and conntrack
//! processing within the kernel's per-call-chain stack limit.
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT, xdp_action},
    helpers::bpf_ktime_get_ns,
    macros::{classifier, xdp},
    programs::{TcContext, XdpContext},
};
use velstra_common::{Counter, FlowKey, FlowState, ip_proto, plan_icmp_echo_nat};

use super::{
    CONNTRACK, IFACE_POLICY, MASQUERADE, O_IP_CSUM, O_IP_DST, O_IP_SRC, SCRATCH, VELSTRA_PROGS,
    account_flow, bump,
    conntrack::{ct_control, ct_key4, ct_record, timeouts},
    epoch, insert_nat, link_layer, napt_port, napt_seed, ptr_at,
};

const ICMP: usize = 34;
const CHECK: usize = ICMP + 2;
const ID: usize = ICMP + 4;

#[xdp]
pub fn velstra_icmp_nat(ctx: XdpContext) -> u32 {
    let before = epoch::snapshot();
    let action = reply(&ctx).unwrap_or(xdp_action::XDP_DROP);
    if epoch::unchanged(before) {
        link_layer::finish_xdp(&ctx, action)
    } else {
        xdp_action::XDP_DROP
    }
}

#[inline(always)]
fn reply(ctx: &XdpContext) -> Result<u32, ()> {
    let scratch = SCRATCH.get(0).ok_or(())?;
    if scratch.ihl_bytes != 20 {
        return forward(ctx);
    }
    let echo = unsafe { *ptr_at::<[u8; 8]>(ctx, ICMP)? };
    if echo[0] != 0 || echo[1] != 0 {
        return forward(ctx);
    }
    let id = u16::from_be_bytes([echo[4], echo[5]]);
    let key = FlowKey::new(
        scratch.policy_id,
        scratch.src_addr,
        scratch.dst_addr,
        0,
        id,
        ip_proto::ICMP,
    );
    let Some(state) = account_flow(&key, (ctx.data_end() - ctx.data()) as u64) else {
        return forward(ctx);
    };
    let nat = plan_icmp_echo_nat(
        scratch.dst_addr,
        state.nat_ip,
        id,
        state.nat_port,
        scratch.checksum,
        u16::from_be_bytes([echo[2], echo[3]]),
    );
    let data = ctx.data();
    if data + ICMP + 8 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        *((data + O_IP_DST) as *mut [u8; 4]) = nat.new_ip;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = nat.new_ip_checksum.to_be_bytes();
        *((data + CHECK) as *mut [u8; 2]) = nat.new_l4_checksum.to_be_bytes();
        *((data + ID) as *mut [u8; 2]) = nat.new_port.to_be_bytes();
    }
    bump(Counter::from_u32(scratch.fw_counter).unwrap_or(Counter::PassedRule));
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn forward(ctx: &XdpContext) -> Result<u32, ()> {
    // Ordinary ICMP still needs overlay/local-port/routing transforms. Only a
    // matching SNAT reply terminates here. A missing forwarding tail fails closed.
    let _ = unsafe { VELSTRA_PROGS.tail_call(ctx, 0) };
    Ok(xdp_action::XDP_DROP)
}

#[classifier]
pub fn velstra_egress_icmp(ctx: TcContext) -> i32 {
    let before = epoch::egress_snapshot();
    let action = request(&ctx).unwrap_or(TC_ACT_SHOT as i32);
    if epoch::unchanged(before) {
        link_layer::finish_tc(&ctx, action)
    } else {
        TC_ACT_SHOT as i32
    }
}

#[inline(always)]
fn request(ctx: &TcContext) -> Result<i32, ()> {
    let ip: [u8; 20] = ctx.load(14).map_err(|_| ())?;
    if ip[0] != 0x45 || ip[9] != ip_proto::ICMP || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0
    {
        return Ok(TC_ACT_OK as i32);
    }
    let echo: [u8; 8] = ctx.load(ICMP).map_err(|_| ())?;
    if echo[0] != 8 || echo[1] != 0 {
        return Ok(TC_ACT_OK as i32);
    }
    let index = unsafe { (*ctx.skb.skb).ifindex };
    let policy = unsafe { IFACE_POLICY.get(&index) }.copied().unwrap_or(0);
    let Some(public) = (unsafe { MASQUERADE.get(&index) }).copied() else {
        return Err(());
    };
    let source = [ip[12], ip[13], ip[14], ip[15]];
    let remote = [ip[16], ip[17], ip[18], ip[19]];
    let original_id = u16::from_be_bytes([echo[4], echo[5]]);
    if source != public {
        let seed = napt_seed(source, remote, original_id, 0);
        let mut mapped = 0;
        for probe in 0..8 {
            let candidate = napt_port(seed, probe);
            let key = FlowKey::new(policy, remote, public, 0, candidate, ip_proto::ICMP);
            match unsafe { CONNTRACK.get(&key) } {
                None => {
                    mapped = candidate;
                    break;
                }
                Some(state)
                    if state.expired(ip_proto::ICMP, unsafe { bpf_ktime_get_ns() }, timeouts())
                        || (state.nat_ip == source && state.nat_port == original_id) =>
                {
                    mapped = candidate;
                    break;
                }
                _ => {}
            }
        }
        if mapped == 0 {
            return Err(());
        }
        let key = FlowKey::new(policy, remote, public, 0, mapped, ip_proto::ICMP);
        if account_flow(&key, (ctx.data_end() - ctx.data()) as u64).is_none() {
            let mut state = FlowState::masquerade(source, original_id);
            state.account((ctx.data_end() - ctx.data()) as u64);
            if !insert_nat(&key, &state) {
                return Err(());
            }
        }
        let from = u32::from_ne_bytes(source) as u64;
        let to = u32::from_ne_bytes(public) as u64;
        ctx.l3_csum_replace(O_IP_CSUM, from, to, 4)
            .map_err(|_| ())?;
        ctx.l4_csum_replace(
            CHECK,
            u16::from_ne_bytes(original_id.to_be_bytes()) as u64,
            u16::from_ne_bytes(mapped.to_be_bytes()) as u64,
            2,
        )
        .map_err(|_| ())?;
        ctx.store(O_IP_SRC, &public, 0).map_err(|_| ())?;
        ctx.store(ID, &mapped.to_be_bytes(), 0).map_err(|_| ())?;
        bump(Counter::EgressMasqueraded);
    }
    let key = ct_key4(
        FlowKey::new(policy, public, remote, 0, 0, ip_proto::ICMP),
        ctx.data(),
        ctx.data_end(),
        ICMP,
    );
    ct_record(
        &key,
        ct_control(ctx.data(), ctx.data_end(), ICMP, ip_proto::ICMP),
    );
    Ok(TC_ACT_OK as i32)
}
