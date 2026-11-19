//! Address-only masquerade for protocols without ports (DP-04): GRE, ESP,
//! SCTP, 6in4 and the like, as Linux's generic conntrack NAT does.
//!
//! One inside host owns a (remote, protocol) pair on the uplink address at a
//! time: the binding is the ordinary masquerade `CONNTRACK` entry keyed on the
//! reply tuple with both ports zero. A second inside host talking the same
//! protocol to the same remote is refused while the first one's binding is
//! live, never given the first one's replies. AH is refused outright: it
//! authenticates the very source address translation changes. None of these
//! protocols checksum an IP pseudo-header, so only the IPv4 header checksum
//! changes.

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    programs::{TcContext, XdpContext},
};
use velstra_common::{Counter, FlowKey, FlowState, FragmentPosition, napt_binding_matches};

use super::{
    CONNTRACK, IFACE_POLICY, O_IP_CSUM, O_IP_DST, O_IP_SRC, account_flow, bump, conntrack,
    frag_nat, masquerade_source_exempt, nat_meta, nat_ports, publish_nat,
};

const AH: u8 = 51;

/// TC egress on a masquerade uplink for a protocol other than TCP/UDP/ICMP.
#[inline(never)]
pub(super) fn egress(ctx: &TcContext, ifindex: u32, wan_ip: [u8; 4]) -> i32 {
    let Ok(ip) = ctx.load::<[u8; 20]>(14) else {
        return TC_ACT_SHOT as i32;
    };
    let source = [ip[12], ip[13], ip[14], ip[15]];
    if masquerade_source_exempt(ifindex, source, wan_ip) {
        return TC_ACT_OK as i32;
    }
    let proto = ip[9];
    let fragment_word = u16::from_be_bytes([ip[6], ip[7]]);
    if proto == AH || FragmentPosition::of(fragment_word) == FragmentPosition::Later {
        // Later fragments were translated (or refused) before this tail.
        return refuse();
    }
    let remote = [ip[16], ip[17], ip[18], ip[19]];
    let policy = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
    let key = FlowKey::new(policy, remote, wan_ip, 0, 0, proto);
    let bytes = (ctx.data_end() - ctx.data()) as u64;
    if !claim(&key, source, bytes) {
        bump(Counter::EgressNatNoCandidate);
        bump(Counter::EgressDropped);
        return TC_ACT_SHOT as i32;
    }
    if ctx
        .l3_csum_replace(
            O_IP_CSUM,
            u32::from_ne_bytes(source) as u64,
            u32::from_ne_bytes(wan_ip) as u64,
            4,
        )
        .is_err()
        || ctx.store(O_IP_SRC, &wan_ip, 0).is_err()
    {
        bump(Counter::EgressDropped);
        return TC_ACT_SHOT as i32;
    }
    frag_nat::note_first(
        u32::from_ne_bytes(source),
        u32::from_ne_bytes(remote),
        frag_nat::meta(
            proto,
            frag_nat::HOOK_EGRESS,
            fragment_word,
            u16::from_be_bytes([ip[4], ip[5]]),
            0,
        ),
        u32::from_ne_bytes(wan_ip),
        u32::from_ne_bytes(remote),
    );
    bump(Counter::EgressMasqueraded);
    TC_ACT_OK as i32
}

#[inline(always)]
fn refuse() -> i32 {
    bump(Counter::EgressDropped);
    bump(Counter::EgressNatUnsupportedDropped);
    TC_ACT_SHOT as i32
}

/// Own or take the (remote, protocol) binding for `origin`. A live binding of
/// another inside host is never displaced; an expired one may be.
#[inline(always)]
fn claim(key: &FlowKey, origin: [u8; 4], bytes: u64) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    let timeouts = conntrack::timeouts();
    if let Some(entry) = CONNTRACK.get_ptr_mut(key) {
        unsafe {
            if !(*entry).expired(key.proto, now, timeouts) {
                if !napt_binding_matches(&*entry, origin, 0) {
                    return false;
                }
                (*entry).account(bytes);
                (*entry).last_seen_ns = now;
                (*entry).age_ns = 0;
                return true;
            }
        }
    }
    publish_nat(
        key,
        u32::from_ne_bytes(origin),
        nat_ports(0, 0),
        0,
        nat_meta(FlowState::ORIGIN, 0, bytes),
    )
}

/// XDP ingress: the reply of a translated portless flow, addressed to the
/// uplink, is un-NATed to its inside host and handed to the kernel to route.
/// Only an existing live binding admits it, exactly as established state
/// would; nothing is created here. `meta` = proto | ip checksum << 16.
#[inline(never)]
pub(super) fn ingress(ctx: &XdpContext, src: u32, dst: u32, meta: u32) -> bool {
    let proto = meta as u8;
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
    let key = FlowKey::new(policy, src.to_ne_bytes(), dst.to_ne_bytes(), 0, 0, proto);
    let Some(state) = account_flow(&key, (ctx.data_end() - ctx.data()) as u64, 0) else {
        return false;
    };
    if !napt_binding_matches(&state, state.nat_ip, 0) {
        return false;
    }
    let data = ctx.data();
    if data + O_IP_DST + 4 > ctx.data_end() {
        return false;
    }
    let ident = unsafe { *((data + 18) as *const [u8; 4]) };
    let nat = velstra_common::FragmentNat {
        src: src.to_ne_bytes(),
        dst: state.nat_ip,
        created_ns: 0,
    };
    let checksum = nat.header_checksum((meta >> 16) as u16, src.to_ne_bytes(), dst.to_ne_bytes());
    unsafe {
        *((data + O_IP_DST) as *mut [u8; 4]) = state.nat_ip;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = checksum.to_be_bytes();
    }
    frag_nat::note_first(
        src,
        dst,
        frag_nat::meta(
            proto,
            frag_nat::HOOK_INGRESS,
            u16::from_be_bytes([ident[2], ident[3]]),
            u16::from_be_bytes([ident[0], ident[1]]),
            0,
        ),
        src,
        u32::from_ne_bytes(state.nat_ip),
    );
    bump(Counter::EstablishedAllowed);
    true
}
