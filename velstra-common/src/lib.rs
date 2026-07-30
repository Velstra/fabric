//! # velstra-common
//!
//! Shared, dependency-light building blocks for the Velstra SDN stack.
//!
//! This crate is the contract between the **data plane** (`velstra-ebpf`,
//! compiled to eBPF/XDP and running in kernel space) and the **control plane**
//! (`velstra`, the user-space daemon). Everything that both sides must agree
//! on lives here:
//!
//! * the **binary layout of every BPF map key/value** ([`GlobalConfig`],
//!   [`PortKey`], the per-CPU statistics indexed by [`Counter`]),
//! * the **firewall policy** itself ([`decide`]), expressed as a pure function
//!   so the exact same verdict logic runs in the kernel *and* in the unit-test
//!   suite, and
//! * a **reference packet parser** ([`parse::parse_frame`]) that mirrors, on a
//!   safe `&[u8]`, what the XDP program does on raw packet pointers.
//!
//! ## `no_std`
//!
//! The crate is `#![no_std]` for normal builds so it can be linked into the
//! eBPF object, but switches to `std` under `cfg(test)` so the logic can be
//! exercised with the regular test harness (`cargo test -p velstra-common`).
//! It pulls in **no** external dependencies in its default configuration; the
//! optional `user` feature only adds `aya` to provide the [`aya::Pod`] marker
//! impls the user-space map API requires.
//!
//! ## Feature flags
//!
//! * `user` — enable [`aya::Pod`] implementations for the map types. The
//!   control-plane crate turns this on; the eBPF crate does not need it.
#![cfg_attr(not(test), no_std)]

mod cgnat;
mod cidr;
mod config;
mod forward;
mod lb;
mod mac;
mod npt;
mod overlay;
mod packet;
pub mod parse;
mod policy;
mod portal;
mod ratelimit;
mod reject;
pub mod srv6;
mod synproxy;

pub use cgnat::CgnatLayout;
pub use cidr::{Cidr4, Cidr6, CidrError, mask_v4, mask_v6, parse_cidr_v4, parse_cidr_v6};
pub use config::{ConfigFlags, GlobalConfig, SourceValidation};
pub use forward::{
    ForwardOutcome, Rewrite, RouteEntry, csum_replace_u16, decrement_ttl, ipv4_checksum,
    plan_forward,
};
pub use lb::{
    Backend, FlowKey, FlowState, Nat, PortFwd, ServiceKey, ServiceValue, plan_dnat, plan_nat,
    select_backend, session_hash,
};
pub use mac::{MacError, parse_mac};
pub use npt::{Npt66, npt66_rewrite, oc_add};
pub use overlay::{
    ARP_REPLY, ARP_REQUEST, ArpEntry, ArpKey, ArpReply, ETHERTYPE_ARP, Encap, FloodSet,
    GENEVE_PORT, ICMPV6_NEIGHBOR_ADVERT, ICMPV6_NEIGHBOR_SOLICIT, IrbEndpoint, IrbRewrite,
    LocalMac, LocalMacKey, MAX_FLOOD_VTEPS, MacFdbKey, ND_NA_MSG_LEN, NaReply, NdKey,
    OVERLAY_OUTER_LEN, OverlayConfig, TunnelEndpoint, TunnelKey, VXLAN_PORT, build_encap,
    decode_vni, encap_kind, icmpv6_checksum, is_overlay_dport, overlay_src_port, plan_arp_reply,
    plan_irb, plan_na_reply,
};
pub use packet::{
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, PacketMeta, PolicyId, PortKey, ScopedAddr, ScopedAddr6,
    ScopedDstPortKey, ScopedPortKey, ScopedSrcPortKey, ip_proto, ipv6_ext_len, is_ipv6_ext,
    lpm_key_addr,
};
pub use parse::{ParseResult, parse_frame};
pub use policy::{
    Action, Counter, MAX_BLOCKLIST, MAX_RULE_LIMITS, PORT_RULE_LOG, PORT_RULE_PRESENT, Verdict,
    decide, port_rule_action, port_rule_bits, port_rule_limit, port_rule_logs, port_rule_present,
    port_rule_value, port_rule_winner, port_rule_with_limit,
};
pub use portal::{PortalClientKey, PortalGate, PortalSeenKey, gate_admits_unauthenticated};
pub use ratelimit::RateBucket;
pub use reject::{
    ICMP_UNREACH_PREPEND, ICMP_UNREACH_TOTAL_LEN, IcmpUnreach, TcpRst, icmp, icmp_checksum,
    plan_icmp_unreachable, plan_tcp_rst, tcp_flags,
};
pub use srv6::{
    SRV6_L2_OUTER_LEN, Srv6Config, Srv6Encap, Srv6Endpoint, Srv6LocalSid, Srv6Sid, Srv6SidKey,
    build_service_sid, build_srv6_encap, decode_service_sid,
};
pub use synproxy::{
    EPOCH_SHIFT, MSS_TABLE, SYNTH_WINDOW, SynFlow, SynProxyCfg, SynProxyKey, TcpSynth,
    check_cookie, csum_replace_u32, epoch_of, make_cookie, mss_index, plan_server_ack,
    plan_server_syn, plan_syn_ack, seq_delta, translate_to_client, translate_to_server,
};
