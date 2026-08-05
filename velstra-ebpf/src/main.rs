#![no_std]
#![no_main]

//! # Velstra data plane (XDP)
//!
//! The kernel-space half of Velstra: a single XDP program, attached at the
//! earliest possible point in the receive path (the NIC driver, before the
//! kernel allocates an `sk_buff`), that decides the fate of every incoming
//! packet in a handful of instructions.
//!
//! ## What it does
//!
//! For each frame it parses Ethernet → IPv4 → (TCP/UDP ports) with strict bounds
//! checks, then runs three stages, each driven by maps the control plane fills:
//!
//! 1. **Firewall (Phase 1):** [`velstra_common::decide`] → `XDP_DROP` or pass.
//! 2. **Load balancer + NAT (Phase 3):** a tracked flow (`CONNTRACK`) or a new
//!    connection to a `SERVICES` VIP is NAT-rewritten ([`plan_nat`]) — DNAT to a
//!    backend on the way in, SNAT back to the VIP on the reply path — and passed
//!    for the kernel to route.
//! 3. **Router/switch (Phase 2):** a matching `ROUTES` entry rewrites the L2
//!    header ([`plan_forward`]) and `XDP_REDIRECT`s it out another interface.
//!
//! Each stage either takes over the verdict or falls through to the next; a
//! packet that survives all three is passed to the kernel stack.
//!
//! ## Maps (the control-plane interface)
//!
//! | Map            | Type            | Purpose                                    |
//! |----------------|-----------------|--------------------------------------------|
//! | `IFACE_POLICY` | `HashMap`       | ingress ifindex → policy id (per-tenant)   |
//! | `CONFIG`       | `HashMap`       | policy id → [`GlobalConfig`]               |
//! | `BLOCKLIST`    | `LpmTrie`       | `(policy, src CIDR)` drop list (DDoS lever)|
//! | `BLOCKLIST6`   | `LpmTrie`       | `(policy, src IPv6 CIDR)` drop list        |
//! | `PORT_RULES`   | `LpmTrie`       | `(policy, proto, dport, src CIDR)` → action |
//! | `ROUTES`      | `LpmTrie`        | Dest-IP prefix → [`RouteEntry`] (Phase 2)  |
//! | `TX_PORTS`    | `DevMap`         | Redirect device map (Phase 2)              |
//! | `SERVICES`    | `HashMap`        | `ServiceKey` → backend window (Phase 3)    |
//! | `BACKENDS`    | `Array`          | Flat backend pool (Phase 3)                |
//! | `CONNTRACK`   | `LruHashMap`     | Flow 5-tuple → NAT target/direction (Ph 3) |
//! | `STATS`       | `PerCpuArray`    | Lock-free counters indexed by [`Counter`]  |
//!
//! Per-CPU stats mean the hot path never contends a lock or a shared cache
//! line; the control plane sums across CPUs when it reports.
//!
//! All the *decision logic* — the firewall policy, the forwarding plan, the DNAT
//! arithmetic — lives in `velstra-common` and is unit tested there, so the
//! kernel and the tests can never disagree.

use aya_ebpf::{
    bindings::{
        BPF_F_PSEUDO_HDR, BPF_FIB_LKUP_RET_FWD_DISABLED, BPF_FIB_LKUP_RET_NO_NEIGH,
        BPF_FIB_LKUP_RET_SUCCESS, TC_ACT_OK, TC_ACT_SHOT, bpf_adj_room_mode::BPF_ADJ_ROOM_MAC,
        bpf_fib_lookup, xdp_action,
    },
    helpers::{
        bpf_fib_lookup as fib_lookup, bpf_ktime_get_ns, bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    },
    macros::{classifier, map, xdp},
    maps::{Array, DevMap, HashMap, LpmTrie, LruHashMap, PerCpuArray, ProgramArray, lpm_trie::Key},
    programs::{TcContext, XdpContext},
};
use aya_log_ebpf::info;
use network_types::{
    eth::EthHdr,
    ip::{Ipv4Hdr, Ipv6Hdr},
};
use velstra_common::{
    ARP_REPLY, ARP_REQUEST, Action, ArpEntry, ArpKey, Backend, CgnatLayout, ConfigFlags, Counter,
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, FloodSet, FlowKey, FlowState, ForwardOutcome,
    GlobalConfig, ICMP_UNREACH_PREPEND, ICMP_UNREACH_TOTAL_LEN, ICMPV6_NEIGHBOR_SOLICIT,
    IrbEndpoint, IrbRewrite, LocalMac, LocalMacKey, MAX_BLOCKLIST, MAX_FLOOD_VTEPS,
    MAX_RULE_LIMITS, MacFdbKey, ND_NA_MSG_LEN, Nat, NdKey, Npt66, OVERLAY_OUTER_LEN, OverlayConfig,
    PORT_RULE_IN_ONLY, PORT_RULE_OUT_ONLY, PORT_RULE_V4_ONLY, PORT_RULE_V6_ONLY, PacketMeta,
    PolicyId, PortFwd, PortalClientKey, PortalGate, PortalSeenKey, RateBucket, Rewrite, RouteEntry,
    SRV6_L2_OUTER_LEN, ScopedAddr, ScopedAddr6, ScopedDstPortKey, ScopedDstPortKey6, ScopedPortKey,
    ScopedSrcPortKey, ScopedSrcPortKey6, ServiceKey, ServiceValue, SourceValidation, Srv6Config,
    Srv6Endpoint, Srv6LocalSid, Srv6SidKey, SynFlow, SynProxyCfg, SynProxyKey, TcpSynth,
    TunnelEndpoint, TunnelKey, build_encap, build_srv6_encap, check_cookie, csum_replace_u32,
    decide, decode_vni, epoch_of, gate_admits_unauthenticated, icmp, icmp_checksum, ip_proto,
    ipv6_ext_len, is_ipv6_ext, is_overlay_dport, lpm_key_addr, make_cookie, plan_arp_reply,
    plan_forward, plan_icmp_unreachable, plan_irb, plan_na_reply, plan_nat, plan_server_ack,
    plan_server_syn, plan_syn_ack, plan_tcp_rst, port_rule_action, port_rule_excluded,
    port_rule_limit, port_rule_logs, port_rule_present, port_rule_winner, select_backend,
    session_hash, tcp_flags, translate_to_client, translate_to_server,
};

/// Maps an ingress interface index to its policy id, so one XDP program can
/// enforce a different firewall per interface/tenant. Interfaces absent here use
/// policy `0` (the default), so a single-tenant deployment needs no entries.
#[map]
static IFACE_POLICY: HashMap<u32, PolicyId> = HashMap::with_max_entries(1024, 0);

/// Maps an ingress interface index to its overlay segment (VNI), independent of
/// its firewall policy. Absent / `0` means the interface is local-only and its
/// traffic is never encapsulated.
#[map]
static IFACE_VNI: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// The set of overlay segments (VNIs) this host actually serves — one entry per
/// distinct VNI a local tenant port lives on. Consulted at overlay **decap**: an
/// inbound tunnel frame is only admitted when its inner VNI is present here, so a
/// (trusted-or-spoofed) peer VTEP cannot inject an inner frame under an arbitrary
/// VNI into whatever local segment its inner MAC happens to match. The value is a
/// reserved per-VNI bridge ifindex for a future dedicated-bridge demux (`0` today
/// ⇒ hand the decapsulated frame to the kernel bridge as before).
#[map]
static LOCAL_VNIS: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

/// Per-policy global configuration (`policy_id` → default action + flags).
#[map]
static CONFIG: HashMap<PolicyId, GlobalConfig> = HashMap::with_max_entries(1024, 0);

/// Host-wide fail-closed switch: a single-slot flag (`0` / absent = fail **open**,
/// non-zero = fail **closed**). It governs only what happens when the data plane
/// cannot parse a packet at all — a `ptr_at` bounds failure — which is decided
/// before any policy is known, so it cannot live in the per-policy [`CONFIG`].
///
/// Fail-open (the default, and the historical behaviour) lets an unparseable
/// packet through: a firewall should not black-hole traffic because of its own
/// parsing limits. Under a deny-by-default posture that is the wrong trade — a
/// packet the filter cannot understand is exactly the one it must not admit — so
/// an operator can flip this to drop instead.
#[map]
static FAIL_CLOSED: Array<u32> = Array::with_max_entries(1, 0);

/// Per-policy source-IP CIDR blocklist, keyed by [`ScopedAddr`] (policy id +
/// address prefix).
///
/// Sized for **whole-country blocking** and threat feeds, not just the handful of
/// addresses an operator types: one country is thousands of prefixes (China is
/// ~8k, Russia ~13k), and a list capped in the hundreds would make the feature
/// impossible rather than merely limited. An LPM trie allocates its nodes on
/// insert, so a large `max_entries` costs nothing until it is used — it is a
/// ceiling, not a reservation.
#[map]
static BLOCKLIST: LpmTrie<ScopedAddr, u32> = LpmTrie::with_max_entries(MAX_BLOCKLIST, 0);

/// Per-policy source-IPv6 CIDR blocklist, keyed by [`ScopedAddr6`] (policy id +
/// IPv6 address prefix). The IPv4 ([`BLOCKLIST`]) and IPv6 lists are separate
/// maps because the LPM key widths differ, but they share the same `policy_id`
/// space and the same `[[policy]]` config — one blocklist, two address families.
#[map]
static BLOCKLIST6: LpmTrie<ScopedAddr6, u32> = LpmTrie::with_max_entries(MAX_BLOCKLIST, 0);

/// Per-policy `(proto, destination port)` → [`Action`] allow/deny rules. Shared
/// across address families: a port rule applies to IPv4 *and* IPv6 alike.
#[map]
static PORT_RULES: LpmTrie<ScopedSrcPortKey, u32> = LpmTrie::with_max_entries(8192, 0);

/// The destination-address counterpart of [`PORT_RULES`]: per-policy
/// `(proto, destination port, destination CIDR)` → [`Action`]. IPv4 only, exactly
/// like the source constraint. See [`ScopedDstPortKey`] for why this is a second
/// trie rather than a second dimension of the first.
#[map]
static DST_RULES: LpmTrie<ScopedDstPortKey, u32> = LpmTrie::with_max_entries(8192, 0);

/// The IPv6 counterparts of [`PORT_RULES`] and [`DST_RULES`].
///
/// Separate tries rather than wider keys: an LPM trie matches a prefix that is
/// contiguous from byte zero, so a 32-bit and a 128-bit address cannot be ranked
/// in one trie without one of them carrying dead bits every lookup still has to
/// walk. Splitting them also leaves the v4 key — and the v4 path's stack use
/// inside this program — untouched.
///
/// Until these existed an address-scoped rule simply did not apply to IPv6: the
/// v6 path looked the tries up with the address as `0`, so only rules with no
/// address constraint could ever match. On a dual-stacked network that is a rule
/// which reads as enforced and is not.
#[map]
static PORT_RULES6: LpmTrie<ScopedSrcPortKey6, u32> = LpmTrie::with_max_entries(8192, 0);

#[map]
static DST_RULES6: LpmTrie<ScopedDstPortKey6, u32> = LpmTrie::with_max_entries(8192, 0);

/// Per-rule token buckets (roadmap C15), indexed by the 1-based slot a rule's
/// packed value carries. Slot 0 is never used, so an unlimited rule — nearly all
/// of them — costs no lookup here at all.
#[map]
static RULE_LIMITS: Array<RateBucket> = Array::with_max_entries(MAX_RULE_LIMITS + 1, 0);

/// Deterministic CGNAT port blocks (roadmap C16), per masquerade egress ifindex.
/// Absent (or a disabled layout) leaves the plain hash-spread NAPT in place, so a
/// box that is not a carrier NAT pays nothing.
#[map]
static CGNAT: HashMap<u32, CgnatLayout> = HashMap::with_max_entries(64, 0);

/// Per-policy 1:1 DNAT port-forwards: `(policy, proto, destination port)` → the
/// internal `(ip, port)` an inbound connection is rewritten to. Empty by default
/// (port-forwarding is opt-in). A match also implicitly opens the firewall for
/// that destination port; the reply is SNAT'd back via a `CONNTRACK` reverse
/// entry, exactly like the load-balancer path.
#[map]
static PORT_FORWARDS: HashMap<ScopedPortKey, PortFwd> = HashMap::with_max_entries(1024, 0);

/// Per-interface masquerade (source NAT) targets: egress ifindex → that
/// interface's public IPv4. A packet leaving an interface present here has its
/// source rewritten to this address at the TC egress hook — the classic WAN
/// masquerade — and the reply is un-NAT'd on ingress via the shared `CONNTRACK`
/// map. Empty by default; masquerade is opt-in per interface. Populated by the
/// control plane (`program_masquerade`), which reads the live interface address.
#[map]
static MASQUERADE: HashMap<u32, [u8; 4]> = HashMap::with_max_entries(64, 0);

/// Egress interface index → the largest TCP MSS a SYN may advertise on it.
///
/// A tunnel takes bytes out of every packet, and a host that never learns this
/// keeps sending full-size segments that cannot fit. Path MTU discovery is
/// supposed to tell it; on a link where the ICMP that carries that news is
/// filtered — which is most of the internet — the connection carries small
/// traffic perfectly and hangs on anything large. Clamping the option as the SYN
/// leaves is the fix that does not depend on anybody else's ICMP.
///
/// Empty by default. This used to be an nftables table rendered next to the data
/// plane; it is the last packet-touching thing that was not eBPF.
#[map]
static MSS_CLAMP: HashMap<u32, u16> = HashMap::with_max_entries(64, 0);

/// Per-interface NPTv6 (RFC 6296) prefix translation: boundary ifindex → the
/// stateless mapping between an internal and an external IPv6 prefix. On TC egress
/// of this interface an internal source is rewritten to the external prefix; on
/// XDP ingress an external destination is rewritten back to the internal prefix.
/// Checksum-neutral (the [`Npt66`] adjustment keeps the L4 checksum valid with no
/// recompute). Empty by default; opt-in per interface via `program_npt66`.
#[map]
static NPTV6: HashMap<u32, Npt66> = HashMap::with_max_entries(64, 0);

/// Phase 2 forwarding table: `(policy, destination-IP prefix)` → [`RouteEntry`].
/// The FIB is scoped by policy (C3) so two tenants with overlapping prefixes
/// each resolve to their own next hop — the same [`ScopedAddr`] key the
/// blocklist uses. Empty by default, so routing is entirely opt-in and never
/// interferes with a firewall-only deployment.
#[map]
static ROUTES: LpmTrie<ScopedAddr, RouteEntry> = LpmTrie::with_max_entries(4096, 0);

/// Redirect target devices, indexed by interface index. Required by
/// `bpf_redirect_map`; the control plane mirrors each route's egress ifindex
/// into it.
#[map]
static TX_PORTS: DevMap = DevMap::with_max_entries(256, 0);

/// Phase 3 load-balancer services: `(VIP, port, proto)` → a window into
/// [`BACKENDS`]. Empty by default, so load balancing is opt-in.
#[map]
static SERVICES: HashMap<ServiceKey, ServiceValue> = HashMap::with_max_entries(1024, 0);

/// Phase 3 flat backend table, indexed by `ServiceValue::backend_start + offset`.
#[map]
static BACKENDS: Array<Backend> = Array::with_max_entries(4096, 0);

/// Phase 3 connection tracking: a flow's 5-tuple → its NAT target/direction.
/// An LRU map so it self-evicts under pressure without any user-space pruning.
/// Populated by the data plane itself (forward + reverse entries per new flow);
/// shared across every interface the program is attached to.
#[map]
static CONNTRACK: LruHashMap<FlowKey, FlowState> = LruHashMap::with_max_entries(65536, 0);

/// The policy namespace router-style DNAT (port-forward) records its `CONNTRACK`
/// entries under. A tenant load-balancer flow is scoped to its own policy so the
/// same VIP can exist in different tenants without crossing — but a router's
/// DNAT inherently bridges zones: the forward packet enters through the *ingress*
/// zone's policy while the reply enters through the *internal* zone's policy, so
/// a policy-scoped reverse entry can never be found on the reply. Router NAT
/// therefore keys its conntrack under this single, policy-independent namespace
/// (`0`, the default policy — never a real tenant, and unused by a zoned
/// firewall/router config); the reply path in [`try_load_balance`] falls back to
/// it after the policy-scoped miss. LB tenant isolation is untouched.
const ROUTER_NAT_POLICY: PolicyId = 0;

/// C15 **SYN proxy**: the TCP ports a proxy stands in front of, and what it
/// offers. Small on purpose — this names services, not connections.
#[map]
static SYNPROXY: HashMap<SynProxyKey, SynProxyCfg> = HashMap::with_max_entries(256, 0);

/// Per-connection SYN-proxy state, created only once a client has proved itself.
/// An LRU, so a client that vanishes between its ACK and the server's answer
/// costs a slot that is reclaimed rather than leaked.
#[map]
static SYN_FLOWS: LruHashMap<FlowKey, SynFlow> = LruHashMap::with_max_entries(65536, 0);

/// The key the SYN cookies are minted with, installed by user space at load.
///
/// A per-boot random value, and it must be: an attacker who knew it could mint
/// cookies for connections they cannot receive, which is precisely the property
/// the proxy rests on. Zero means "no key installed" and the proxy stays out of
/// the way rather than issuing forgeable cookies.
#[map]
static SYN_SECRET: Array<u64> = Array::with_max_entries(2, 0);

/// Read the cookie key, or `None` when user space has not installed one.
#[inline(always)]
fn syn_secret() -> Option<[u64; 2]> {
    let lo = *SYN_SECRET.get(0)?;
    let hi = *SYN_SECRET.get(1)?;
    if lo == 0 && hi == 0 {
        return None;
    }
    Some([lo, hi])
}

/// The key a proxied connection's state lives under.
///
/// Deliberately **not** the full 5-tuple: the server's address is zeroed, so the
/// key is identical on both sides of a destination NAT. A port-forward that
/// rewrites the address is therefore transparent here, and the same lookup
/// serves the client's packets (where the protected port is the destination) and
/// the server's (where it is the source). The namespace is the policy-independent
/// one for the same reason conntrack's router-NAT entries are — the two
/// directions arrive through different zones.
#[inline(always)]
fn syn_flow_key(client: [u8; 4], client_port: u16, service_port: u16) -> FlowKey {
    FlowKey::new(
        ROUTER_NAT_POLICY,
        client,
        [0; 4],
        client_port,
        service_port,
        ip_proto::TCP,
    )
}

/// Look a flow up in `CONNTRACK` and, on a hit, **account this packet to it**.
///
/// Accounting has to happen here rather than in a pass of its own: the value is
/// already being fetched, and the packet's size is knowledge only the data plane
/// holds — by the time user space reads the table, the traffic it wants to
/// measure has been gone for a while.
///
/// The update goes through `get_ptr_mut` and is plain (non-atomic) 64-bit
/// arithmetic; [`FlowState`]'s *Accounting* section states why an entry has a
/// single writer in practice and what it costs when it does not. The value is
/// copied out afterwards, so every caller keeps working on a snapshot exactly as
/// it did when this was a bare `get`.
#[inline(always)]
fn account_flow(key: &FlowKey, bytes: u64) -> Option<FlowState> {
    let entry = CONNTRACK.get_ptr_mut(key)?;
    // SAFETY: `get_ptr_mut` yields a pointer to this CPU's view of the map value,
    // valid until the next map operation on it; we write and copy immediately.
    unsafe {
        (*entry).account(bytes);
        Some(*entry)
    }
}

/// Stateful-firewall connection table: a flow (both directions) that the
/// firewall allowed, so replies are permitted even under deny-by-default. An LRU
/// map, populated and read entirely by the data plane.
#[map]
static FW_FLOWS: LruHashMap<FlowKey, u8> = LruHashMap::with_max_entries(65536, 0);

/// C20 captive portal: which policies are gated, and the appliance's own address
/// in each. Written when the configuration is applied. An entry only *matters*
/// for a policy whose [`ConfigFlags::PORTAL`] bit is set — the flag is what keeps
/// every ungated policy from paying for this lookup.
#[map]
static PORTAL_GATES: HashMap<PolicyId, PortalGate> = HashMap::with_max_entries(64, 0);

/// C20 captive portal: the devices currently admitted, keyed by
/// `(policy, MAC)`.
///
/// This is the one map in the data plane written by an *event* rather than by a
/// configuration — a person logging in — and it is deliberately a plain
/// `HashMap` rather than an LRU: an admitted session must end because its
/// deadline passed and the agent removed it, never because the table filled up
/// and evicted somebody mid-download. A full table refuses new logins, which is
/// visible and correct, instead of ending old ones invisibly.
#[map]
static PORTAL_CLIENTS: HashMap<PortalClientKey, u8> = HashMap::with_max_entries(4096, 0);

/// C20: which MAC an address was last seen with, on traffic addressed to the
/// portal.
///
/// The portal server knows its visitor by address; the gate is keyed by MAC.
/// This is where the two are joined, by the only party that sees both — see
/// `velstra_common::portal::PortalSeenKey` for why not the kernel's neighbour
/// table. An LRU, because it is a cache of something re-learned by the next
/// packet: losing an entry costs one retry of a login, never a session.
#[map]
static PORTAL_SEEN: LruHashMap<PortalSeenKey, [u8; 6]> = LruHashMap::with_max_entries(4096, 0);

/// Record the source MAC of a frame addressed to the portal.
///
/// Only ever called on the portal-bound path, which is DNS and a login page —
/// nothing that runs at line rate.
fn portal_learn(ctx: &XdpContext, key: &PortalSeenKey) {
    if let Ok(mac) = unsafe { ptr_at::<[u8; 6]>(ctx, O_ETH_SRC) } {
        let _ = PORTAL_SEEN.insert(key, unsafe { &*mac }, 0);
    }
}

/// Whether the device that sent this frame has been admitted to `policy_id`.
///
/// Split out of [`portal_admits`] so the source-MAC read and the map lookup
/// happen with one live map value and no packet pointer surviving the merge —
/// the shape that has repeatedly compiled, where carrying an `Option` out of a
/// lookup has repeatedly not.
fn portal_client_admitted(ctx: &XdpContext, policy_id: PolicyId) -> bool {
    let Ok(mac) = (unsafe { ptr_at::<[u8; 6]>(ctx, O_ETH_SRC) }) else {
        return false;
    };
    let key = PortalClientKey::new(policy_id, unsafe { *mac });
    unsafe { PORTAL_CLIENTS.get(&key) }.is_some()
}

/// The C20 gate for an IPv4 packet: may this sender talk *past* the appliance?
///
/// A policy whose portal bit is set but which has no gate entry admits
/// everything. The two are written together by one apply, so this only describes
/// the instant between them — and failing *open* there is the right way round: a
/// gate that has not been configured yet must not black-hole a zone.
fn portal_admits(ctx: &XdpContext, policy_id: PolicyId, meta: &PacketMeta) -> bool {
    let Some(gate) = (unsafe { PORTAL_GATES.get(&policy_id) }).copied() else {
        return true;
    };
    let to_portal = gate.is_portal4(meta.dst_addr);
    if to_portal {
        // The login is about to arrive over this very connection; remember which
        // device it came from while both halves are in front of us.
        portal_learn(ctx, &PortalSeenKey::v4(policy_id, meta.src_addr));
    }
    if gate_admits_unauthenticated(to_portal, meta.proto, meta.src_port, meta.dst_port, false) {
        return true;
    }
    portal_client_admitted(ctx, policy_id)
}

/// The C20 gate for an IPv6 packet. Same allow-set, same session — a device
/// admitted over IPv4 is admitted here by the very same `(policy, MAC)` entry,
/// which is the reason the key is a MAC (see `velstra_common::portal`).
fn portal_admits_v6(
    ctx: &XdpContext,
    policy_id: PolicyId,
    hdr: &[u8; Ipv6Hdr::LEN],
    meta: &PacketMeta,
) -> bool {
    let Some(gate) = (unsafe { PORTAL_GATES.get(&policy_id) }).copied() else {
        return true;
    };
    let dst: [u8; 16] = [
        hdr[24], hdr[25], hdr[26], hdr[27], hdr[28], hdr[29], hdr[30], hdr[31], hdr[32], hdr[33],
        hdr[34], hdr[35], hdr[36], hdr[37], hdr[38], hdr[39],
    ];
    let to_portal = gate.is_portal6(dst);
    if to_portal {
        let src: [u8; 16] = [
            hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17],
            hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
        ];
        portal_learn(ctx, &PortalSeenKey::v6(policy_id, src));
    }
    if gate_admits_unauthenticated(to_portal, meta.proto, meta.src_port, meta.dst_port, true) {
        return true;
    }
    portal_client_admitted(ctx, policy_id)
}

/// Phase 4 overlay endpoint for this host — a single-entry array holding the
/// [`OverlayConfig`]. Absent/disabled by default, so encap/decap never trigger
/// until the control plane writes it.
#[map]
static OVERLAY_CONFIG: Array<OverlayConfig> = Array::with_max_entries(1, 0);

/// Phase 4 ARP suppression table: `(vni, tenant IP)` → the MAC that answers for
/// it. Pushed by the controller; lets the host reply to a tenant's ARP locally
/// instead of flooding the overlay.
#[map]
static ARP_TABLE: HashMap<ArpKey, ArpEntry> = HashMap::with_max_entries(8192, 0);

/// B3 IPv6 Neighbor-Discovery suppression table: `(vni, tenant IPv6)` → the MAC
/// that answers for it (the value shape is the same [`ArpEntry`] the ARP table
/// uses). Pushed by the controller; lets the host reply to a tenant's Neighbor
/// Solicitation locally instead of flooding the overlay.
#[map]
static ND_TABLE: HashMap<NdKey, ArpEntry> = HashMap::with_max_entries(8192, 0);

/// Phase 4 overlay forwarding database: an **LPM trie** keyed by [`TunnelKey`]
/// (`vni` exact + inner-destination prefix) → the remote [`TunnelEndpoint`].
/// Longest-prefix matching lets one entry cover a whole remote subnet. Pushed by
/// the controller (Andromeda-style); a miss means the destination is local, so
/// the packet falls through to normal switching/routing.
#[map]
static OVERLAY_FDB: LpmTrie<TunnelKey, TunnelEndpoint> = LpmTrie::with_max_entries(8192, 0);

/// B1 per-MAC forwarding DB: exact-match `(vni, inner dst MAC)` → remote
/// [`TunnelEndpoint`]. Consulted before the L3 `OVERLAY_FDB` so a true L2
/// overlay bridges by destination MAC; a miss falls through to the L3 path.
#[map]
static MAC_FDB: HashMap<MacFdbKey, TunnelEndpoint> = HashMap::with_max_entries(8192, 0);

/// B7 **symmetric IRB** routing table: an LPM trie keyed by the *ingress* segment
/// plus an inner-destination prefix → the [`IrbEndpoint`] that says which remote
/// PE owns it, how to rewrite the inner Ethernet header and which **L3** VNI to
/// encapsulate with. Populated from the BGP EVPN type-5 (IP Prefix) routes the
/// controller learned, expanded to one entry per L2 segment of the tenant.
///
/// Consulted **before** the bridging FDBs and only for frames addressed to the
/// tenant's anycast gateway MAC: an IRB entry routes, the FDBs bridge.
#[map]
static IRB_ROUTES: LpmTrie<TunnelKey, IrbEndpoint> = LpmTrie::with_max_entries(8192, 0);

/// B9 per-host **SRv6** configuration: this node's tunnel-source identity (its
/// SRv6 source address + underlay MAC + MTU). One entry (index `0`); absent /
/// disabled means the SRv6 overlay is off. SRv6 and VXLAN/Geneve are mutually
/// exclusive per host — when this is enabled the `OVERLAY_CONFIG` is not.
#[map]
static SRV6_CONFIG: Array<Srv6Config> = Array::with_max_entries(1, 0);

/// B9 SRv6 per-MAC forwarding DB: exact-match `(vni, inner dst MAC)` → the remote
/// [`Srv6Endpoint`] (which `End.DT2U` service SID to encapsulate toward). The
/// SRv6 analogue of [`MAC_FDB`]; a miss means the destination is local or must be
/// flooded (`End.DT2M`, not yet head-end replicated), so the frame falls through.
#[map]
static SRV6_FDB: HashMap<MacFdbKey, Srv6Endpoint> = HashMap::with_max_entries(8192, 0);

/// B9 SRv6 **local-SID** table: every 128-bit service SID this node has
/// instantiated → the `(vni, behaviour)` it terminates into ([`Srv6LocalSid`]).
/// An arriving packet whose outer IPv6 destination is an exact-match key here is
/// decapsulated and its inner Ethernet frame bridged into the tenant. Pushed by
/// the control plane; a miss means the packet is not for one of our SIDs and
/// falls through to the ordinary IPv6 firewall path.
#[map]
static SRV6_LOCAL_SIDS: HashMap<Srv6SidKey, Srv6LocalSid> = HashMap::with_max_entries(8192, 0);

/// B9 SRv6 **trusted decap-peer set** (C2 analogue of [`VTEP_PEERS`]): the outer
/// IPv6 **source** (network order) of every remote peer this host accepts an
/// `End.DT2U` decap from — each peer's own `local_src`. A packet addressed to one
/// of our SIDs is decapsulated only when its outer source is in this set;
/// otherwise a host on the underlay could forge a frame to our SID and have its
/// inner Ethernet frame bridged into a tenant, past the firewall. Empty ⇒ no
/// source is trusted (fail-closed decap). Pushed by the control plane alongside
/// `SRV6_LOCAL_SIDS`.
#[map]
static SRV6_PEERS: HashMap<[u8; 16], u8> = HashMap::with_max_entries(8192, 0);

/// B2 per-VNI **flood set**: `vni` → the [`FloodSet`] of remote VTEPs a
/// broadcast/unknown-unicast/multicast (BUM) frame on that segment must be
/// head-end replicated to. Consulted by the TC ingress `velstra_bum` classifier
/// (XDP can only emit one action per packet, so BUM replication lives at the TC
/// layer where `bpf_clone_redirect` can fan a frame out to N underlay copies).
/// A miss or an empty set means "no remote flood targets" — the frame is left
/// for local delivery only. Pushed by the control plane (`program_overlay`).
#[map]
static FLOOD_LIST: HashMap<u32, FloodSet> = HashMap::with_max_entries(4096, 0);

/// B4b **local-MAC learning** table: `(vni, tenant source MAC)` → the tenant's
/// [`LocalMac`] (its bound IPv4). Populated **by the data plane itself** on the
/// firewall-allowed path for tenant ports (`vni != 0`), so the co-located agent
/// can read it out and advertise each local tenant MAC/IP to the Wren routing
/// daemon (which re-advertises them as type-2 EVPN routes to remote VTEPs). An
/// LRU map so it self-evicts silent MACs without any user-space pruning.
#[map]
static LOCAL_MACS: LruHashMap<LocalMacKey, LocalMac> = LruHashMap::with_max_entries(8192, 0);

/// Phase 4 **trusted VTEP set** (C2): the outer source IPv4 (network order) of
/// every remote peer VTEP this host tunnels with. A UDP datagram on the tunnel
/// port is only decapsulated when its outer source is in this set **and** its
/// outer destination is our own VTEP — otherwise a tenant VM on a tap, or any
/// host on the underlay, could forge an encapsulated frame under an arbitrary
/// VNI and have it injected past the firewall. Pushed by the control plane
/// alongside `OVERLAY_FDB` (one entry per distinct remote VTEP).
#[map]
static VTEP_PEERS: HashMap<[u8; 4], u8> = HashMap::with_max_entries(8192, 0);

/// Per-CPU statistics, one slot per [`Counter`] variant.
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(Counter::COUNT, 0);

/// Scratch space for the reverse-path [`bpf_fib_lookup`] parameter block.
///
/// The struct is 64 bytes, and holding it on the stack pushed the XDP program
/// past the verifier's 512-byte combined-frame limit — the program simply
/// stopped loading. A per-CPU slot costs no stack at all and is safe without
/// locking: an XDP program runs to completion on one CPU without preemption, so
/// the slot is filled and read within a single run.
#[map]
static FIB_SCRATCH: PerCpuArray<bpf_fib_lookup> = PerCpuArray::with_max_entries(1, 0);

/// This CPU's zeroed [`bpf_fib_lookup`] slot, or `None` if the map is somehow
/// missing (in which case the caller must not claim the packet is spoofed).
#[inline(always)]
fn fib_scratch() -> Option<*mut bpf_fib_lookup> {
    let params = FIB_SCRATCH.get_ptr_mut(0)?;
    // The slot is reused every packet, so stale fields would leak from the last
    // lookup into this one.
    unsafe { core::ptr::write_bytes(params, 0, 1) };
    Some(params)
}

/// Everything the tail-called [`velstra_forward`] program needs from
/// [`try_velstra`]'s post-firewall state. A tail call replaces the running
/// program without passing arguments and does **not** carry the stack, so the
/// main program stashes this in the per-CPU [`SCRATCH`] slot and the forward
/// program reads it straight back.
///
/// Field order is large→small so the natural `#[repr(C)]` layout has **no
/// implicit padding**: the two `[u8; 4]`s (offsets 0..8), the four `u16`s
/// (8..16), the three `u32`s on 4-byte offsets (16, 20, 24), then the four `u8`s
/// filling 28..32. The value is copied in and out wholesale, so no padding byte
/// is ever read uninitialised.
///
/// The port-forward **target** is deliberately NOT carried here: the main program
/// only needs to know a forward *exists* (`has_port_forward`, to open the
/// firewall), while `try_port_forward` — which runs in [`velstra_forward`] — looks
/// the `PortFwd` up again from the same `(policy, proto, dport)`. Keeping a
/// `PortFwd` (an `Option`) live in the main program is what made LLVM emit the
/// fragile niche codegen the verifier rejected (`R3 !read_ok` on the None path);
/// reducing the main program to a bool eliminates it and shrinks the slot.
#[repr(C)]
#[derive(Clone, Copy)]
struct ForwardScratch {
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    checksum: u16,
    src_port: u16,
    dst_port: u16,
    /// The IPv4 header length in bytes; stored as `u16`, used back as `usize`.
    ihl_bytes: u16,
    policy_id: PolicyId,
    vni: u32,
    /// The firewall verdict's counter index ([`Counter::index`]); reconstructed
    /// with [`Counter::from_u32`] for the fall-through `bump`, so the exact
    /// counter `try_velstra` would have bumped is preserved.
    fw_counter: u32,
    proto: u8,
    ttl: u8,
    /// A `bool` as `u8` (a plain `bool` across the scratch copy is avoided).
    has_port_forward: u8,
    /// A `bool` as `u8`.
    log: u8,
}

/// Per-CPU scratch carrying [`try_velstra`]'s post-firewall state across the tail
/// call into [`velstra_forward`] — a tail call cannot pass the stack, so this
/// single-slot per-CPU array is the hand-off. Per-CPU means no cross-CPU race:
/// the fill and the read run on the same CPU within one packet's processing.
#[map]
static SCRATCH: PerCpuArray<ForwardScratch> = PerCpuArray::with_max_entries(1, 0);

/// Tail-call jump table. Slot [`PROG_FORWARD`] holds [`velstra_forward`]; the
/// control plane populates it at load time (see `firewall.rs`).
#[map]
static VELSTRA_PROGS: ProgramArray = ProgramArray::with_max_entries(1, 0);

/// Index of [`velstra_forward`] in [`VELSTRA_PROGS`].
const PROG_FORWARD: u32 = 0;

/// XDP entry point. Kept tiny: it delegates to [`try_velstra`] and turns a parse
/// failure into `XDP_PASS` (fail-open) or `XDP_DROP` (fail-closed), per the
/// host-wide [`FAIL_CLOSED`] flag, rather than aborting.
#[xdp]
pub fn velstra(ctx: XdpContext) -> u32 {
    match try_velstra(&ctx) {
        Ok(action) => action,
        // A `ptr_at` bounds failure lands here. Count it, then either let the
        // packet through — a firewall should not black-hole traffic because of its
        // own parsing limits — or, when the operator has chosen a deny-by-default
        // posture, drop it: a packet the filter cannot parse is precisely the one
        // it must not admit. The `Malformed` counter records the event either way,
        // so the flag alone says which of the two happened.
        Err(()) => {
            bump(Counter::Malformed);
            if fail_closed() {
                xdp_action::XDP_DROP
            } else {
                xdp_action::XDP_PASS
            }
        }
    }
}

/// TC **egress** entry point (Phase B). Where the XDP hook above filters traffic
/// arriving at a NIC, this filters traffic *leaving* one — closing the gap XDP
/// can't reach: host-originated egress, and the receive side of a tenant tap.
/// Delegates to [`try_egress`]; a parse failure fails open (`TC_ACT_OK`) or, when
/// the host-wide [`FAIL_CLOSED`] flag is set, closed (`TC_ACT_SHOT`) — the same
/// trade the XDP hook above makes, counted the same way.
#[classifier]
pub fn velstra_egress(ctx: TcContext) -> i32 {
    match try_egress(&ctx) {
        Ok(action) => action,
        Err(()) => {
            bump(Counter::Malformed);
            if fail_closed() {
                TC_ACT_SHOT as i32
            } else {
                TC_ACT_OK as i32
            }
        }
    }
}

// ===========================================================================
// B2 — BUM head-end replication (TC ingress classifier)
// ===========================================================================
//
// WHY A NEW TC-INGRESS HOOK (and not the XDP path or `velstra_egress`):
//
// A tenant that sends a broadcast/unknown-unicast/multicast (BUM) frame needs
// ONE VXLAN-encapsulated copy delivered to EACH remote VTEP in its VNI's flood
// set. XDP is 1-packet-in → 1-action-out: it physically cannot fan one frame
// into N copies. The kernel's only clone primitive on the packet path is
// `bpf_clone_redirect`, which is a **TC**-layer helper (`TcContext`), so
// replication has to live at TC.
//
// A tenant frame from the VM traverses, in order: XDP ingress (`velstra` →
// `try_encap`) → TC ingress → the bridge/stack. `try_encap` already consumes
// KNOWN unicast (a MAC_FDB / OVERLAY_FDB hit encapsulates + `XDP_REDIRECT`s the
// single copy, so it never reaches TC). Only BUM and truly-local frames fall
// through XDP to TC ingress — exactly the frames this hook must replicate. So
// the clean seam is a NEW `clsact` **ingress** classifier on the tenant tap
// (`velstra_bum`): it sees the BUM frame, `clone_redirect`s N encapsulated
// copies onto the underlay, and returns `TC_ACT_OK` so the original is still
// delivered locally. (`velstra_egress` is the wrong seam — it is TC *egress*,
// the delivery-*to*-the-VM direction, and it filters, it does not replicate.)
//
// REPLICATION APPROACH (grow-once + full re-store per clone):
//
//   1. Grow skb headroom **once** with `adjust_room(+OVERLAY_OUTER_LEN,
//      BPF_ADJ_ROOM_MAC, 0)` on the first copy.
//   2. For each flood VTEP, `build_encap` (the same pure builder XDP uses)
//      produces the full 50-byte outer stack **with that VTEP's already-correct
//      IPv4 checksum**, so we simply `store()` the whole header at offset 0 —
//      no per-field `l3_csum_replace` patching is needed (simpler and clearer
//      than diffing the dst IP/MAC between iterations, and the checksum is never
//      wrong).
//   3. `clone_redirect(ep.out_ifindex, 0)` sends that copy; the ORIGINAL skb is
//      untouched by the clone.
//   4. After the loop, `adjust_room(-OVERLAY_OUTER_LEN, …)` removes the outer
//      stack again so the original continues to local delivery unmodified.
//
// The loop bound is the CONSTANT `MAX_FLOOD_VTEPS` with an early `break` at
// `flood.count`, so the verifier can bound it; `flood.vteps.get(i)` avoids any
// panic/bounds-check path.
//
// !!! LOAD-VERIFICATION CAVEAT (B2 TODO(load-iterate)) !!!
// This datapath is COMPILE-verified only; it has NOT been kernel-load / verifier
// validated in this environment (that needs root + a live tap/underlay). The
// user will iterate it under load. Specifically unverified:
//   * exact `BPF_ADJ_ROOM_MAC` byte-insertion semantics (does the +room open at
//     offset 0 for a fresh outer L2, and does the store land where intended?);
//   * whether the verifier accepts `store` after `adjust_room` without a
//     `pull_data`/re-check of `data`..`data_end`;
//   * `clone_redirect` interaction with the subsequent room-shrink on the
//     original;
//   * outer UDP entropy (kept coarse below — a BUM frame carries no L4 flow).
// If the verifier rejects a step, that step is where to iterate; the control
// plane (FLOOD_LIST, VTEP_PEERS, TX_PORTS, attach) is already complete.

/// TC **ingress** entry point for B2 BUM head-end replication. Attached on
/// tenant taps (`clsact` ingress). Delegates to [`try_bum`]; any parse/helper
/// failure fails open (`TC_ACT_OK`) so a BUM frame is never black-holed here —
/// worst case it just isn't replicated.
#[classifier]
pub fn velstra_bum(ctx: TcContext) -> i32 {
    match try_bum(&ctx) {
        Ok(action) => action,
        Err(()) => TC_ACT_OK as i32,
    }
}

/// Head-end replicate a tenant BUM frame to every remote VTEP in its VNI's
/// flood set. See the module-level block above for the design and the
/// load-verification caveat. Always returns `TC_ACT_OK` — the clones are extra
/// copies; the original frame is left for normal local delivery.
#[inline(always)]
fn try_bum(ctx: &TcContext) -> Result<i32, ()> {
    // Overlay must be active for any encapsulation to make sense.
    let ocfg = overlay_config();
    if !ocfg.is_enabled() {
        return Ok(TC_ACT_OK as i32);
    }

    // Ingress VNI is the tap's segment — the same `IFACE_VNI` map the XDP encap
    // path keys on. A non-tenant port (vni 0) never floods.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let vni = unsafe { IFACE_VNI.get(&ifindex) }.copied().unwrap_or(0);
    if vni == 0 {
        return Ok(TC_ACT_OK as i32);
    }

    // Classify BUM by the inner destination MAC (frame offset 0):
    //   * broadcast  (ff:ff:ff:ff:ff:ff) — has bit 0 of octet 0 set, so it is
    //     caught by the multicast test;
    //   * multicast  (octet0 & 1 == 1);
    //   * unknown-unicast — a MAC_FDB miss for this (vni, dst MAC).
    // A KNOWN unicast (MAC_FDB hit) is not BUM and was already handled by XDP
    // `try_encap`; leave it alone.
    let dst_mac = unsafe { *ptr_at_tc::<[u8; 6]>(ctx, O_ETH_DST)? };
    let is_multicast = dst_mac[0] & 1 == 1;
    let is_bum = is_multicast || unsafe { MAC_FDB.get(&MacFdbKey::new(vni, dst_mac)) }.is_none();
    if !is_bum {
        return Ok(TC_ACT_OK as i32);
    }

    // The flood set for this segment. A miss or an empty set ⇒ nothing to do.
    // Hold a *reference* into the map value — the whole `FloodSet` is 260 bytes,
    // far too large to copy onto the 512-byte BPF stack; we index it in place and
    // copy out only one 16-byte `TunnelEndpoint` per iteration.
    let flood = match unsafe { FLOOD_LIST.get(&vni) } {
        Some(f) => f,
        None => return Ok(TC_ACT_OK as i32),
    };
    let count = flood.count;
    if count == 0 {
        return Ok(TC_ACT_OK as i32);
    }

    // The inner frame length (whole L2 frame becomes the tunnel payload), read
    // BEFORE any room grow. Drop-silently (leave for local delivery) if encap
    // would exceed the underlay MTU — mirrors the XDP encap MTU guard.
    let inner_len = (ctx.data_end() - ctx.data()) as u16;
    if inner_len > ocfg.max_inner_len() {
        return Ok(TC_ACT_OK as i32);
    }
    // Coarse outer-UDP entropy: a BUM frame carries no single L4 flow to hash,
    // so we spread only by (vni, dst MAC). Refine at load-iterate if underlay
    // ECMP distribution matters for flood traffic.
    let entropy = vni ^ ((dst_mac[4] as u32) << 8) ^ (dst_mac[5] as u32);

    let mut grown = false;
    let mut i: usize = 0;
    while i < MAX_FLOOD_VTEPS {
        if i as u32 >= count {
            break;
        }
        // `.get` (not `[]`) keeps the verifier off any panic/bounds path.
        let ep = match flood.vteps.get(i) {
            Some(e) => *e,
            None => break,
        };

        // Build this VTEP's full outer stack (correct checksum included).
        let encap = build_encap(&ocfg, &ep, vni, inner_len, entropy);

        // Grow the headroom exactly once, on the first copy.
        if !grown {
            if ctx
                .adjust_room(OVERLAY_OUTER_LEN as i32, BPF_ADJ_ROOM_MAC, 0)
                .is_err()
            {
                // Could not make room — abandon replication, deliver locally.
                return Ok(TC_ACT_OK as i32);
            }
            grown = true;
        }

        // Overwrite the outer stack for this VTEP, then clone+redirect the copy
        // onto the underlay. `store`/`clone_redirect` are skb helpers (handle a
        // non-linear skb), so no direct-pointer bounds dance is needed.
        if ctx.store(0, &encap.headers, 0).is_ok() && ctx.clone_redirect(ep.out_ifindex, 0).is_ok()
        {
            bump(Counter::BumReplicated);
        }

        i += 1;
    }

    // Remove the outer stack we prepended so the ORIGINAL frame is delivered
    // locally unchanged (clone_redirect did not consume it).
    if grown {
        let _ = ctx.adjust_room(-(OVERLAY_OUTER_LEN as i32), BPF_ADJ_ROOM_MAC, 0);
    }

    Ok(TC_ACT_OK as i32)
}

/// Increment a per-CPU counter by one. Infallible and lock-free.
#[inline(always)]
fn bump(counter: Counter) {
    add(counter, 1);
}

/// Add `n` to a per-CPU counter.
#[inline(always)]
fn add(counter: Counter, n: u64) {
    if let Some(slot) = STATS.get_ptr_mut(counter.index()) {
        // SAFETY: `get_ptr_mut` returned a valid pointer into this CPU's slot;
        // per-CPU maps are not shared, so no other context races this write.
        unsafe { *slot += n };
    }
}

/// Bounds-checked pointer into the packet at `offset`.
///
/// Returns `Err(())` unless the whole `T` lies within `[data, data_end)`. The
/// explicit check is also what the eBPF verifier requires before any packet
/// dereference.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// [`ptr_at`] for the TC (skb) context. The same bounds-check pattern, against
/// the linear portion of the socket buffer (`data..data_end`) — which always
/// holds the small headers the firewall reads.
#[inline(always)]
unsafe fn ptr_at_tc<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Phase B egress firewall. Mirrors the Phase 1 ingress firewall in
/// [`try_velstra`], but runs at TC **egress** and matches on the **destination**
/// (the source is always "us" on the way out): the per-policy CIDR blocklist is
/// applied to the *destination* address, port rules to the destination port, plus
/// the ICMP filter and default action — all via the shared [`decide`]. The policy
/// is selected by the **egress** interface (`IFACE_POLICY`), so a tap delivering
/// to a tenant VM is filtered against that tenant's rules.
///
/// On a stateful policy an allowed flow is recorded in `FW_FLOWS` (both
/// directions) so the *reply*, arriving at the XDP ingress hook, is permitted —
/// this is what makes replies to **host-originated** connections work, the gap
/// the ingress-only stateful firewall could not cover. IPv4 only for now (IPv6
/// egress and overlay-aware egress are follow-ups).
#[inline(always)]
fn try_egress(ctx: &TcContext) -> Result<i32, ()> {
    bump(Counter::TxPackets);

    let eth: *const EthHdr = unsafe { ptr_at_tc(ctx, 0)? };
    let ethertype = u16::from_be(unsafe { (*eth).ether_type });
    if ethertype != ETHERTYPE_IPV4 {
        // NPTv6 (RFC 6296) source translation happens on the way out: an internal
        // IPv6 source leaving a boundary interface is rewritten to the external
        // prefix. Other v6 traffic (and non-IP) passes untouched.
        if ethertype == ETHERTYPE_IPV6 {
            return npt66_egress_v6(ctx);
        }
        return Ok(TC_ACT_OK as i32);
    }
    let ipv4: *const Ipv4Hdr = unsafe { ptr_at_tc(ctx, EthHdr::LEN)? };
    let ipv4 = unsafe { &*ipv4 };
    let ihl_bytes = ipv4.ihl() as usize;
    if ipv4.version() != 4 || ihl_bytes < Ipv4Hdr::LEN {
        return Ok(TC_ACT_OK as i32);
    }
    let proto = ipv4.proto;
    let src_addr = ipv4.src_addr;
    let dst_addr = ipv4.dst_addr;

    // Ports only from the first fragment; a non-first fragment's bytes there are
    // payload, not L4 (M1 — see the ingress path and `parse_frame`).
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    let mut icmp_type = 0u8;
    if (proto == ip_proto::TCP || proto == ip_proto::UDP) && ipv4.frag_offset() == 0 {
        if let Ok(ports) = unsafe { ptr_at_tc::<[u8; 4]>(ctx, EthHdr::LEN + ihl_bytes) } {
            let ports = unsafe { *ports };
            src_port = u16::from_be_bytes([ports[0], ports[1]]);
            dst_port = u16::from_be_bytes([ports[2], ports[3]]);
        }
    } else if proto == ip_proto::ICMP && ipv4.frag_offset() == 0 {
        // See the ingress path: four bytes, because one does not verify.
        if let Ok(head) = unsafe { ptr_at_tc::<[u8; 4]>(ctx, EthHdr::LEN + ihl_bytes) } {
            icmp_type = unsafe { *head }[0];
        }
    }

    // Egress policy is keyed by the *egress* interface index.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };

    // Clamp before anything else looks at this packet: the MSS is advertised in
    // the SYN, and whether the firewall passes it or the masquerade path takes
    // it over, the option has to be right on the way out. It is not a verdict —
    // nothing below depends on it — so it runs and the packet carries on.
    clamp_mss_egress(ctx, ihl_bytes, proto, ifindex);

    // Masquerade takes over a packet leaving a masquerade (WAN) interface,
    // *before* and *instead of* the egress firewall: a router's outbound traffic
    // must leave even though the WAN zone's ingress posture is deny-by-default,
    // so the egress firewall's drop logic must not apply here.
    if let Some(wan_ip) = unsafe { MASQUERADE.get(&ifindex) }.copied() {
        // The reply arrives on this same (WAN) interface, so its conntrack/
        // firewall entries must be scoped under the WAN interface's policy — the
        // scope the XDP ingress path will look them up under (C3).
        let wan_policy = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
        return masquerade_egress(
            ctx, ihl_bytes, wan_policy, src_addr, dst_addr, src_port, dst_port, proto, wan_ip,
            ifindex,
        );
    }

    let policy_id = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
    let cfg = unsafe { CONFIG.get(&policy_id) }
        .copied()
        .unwrap_or(GlobalConfig::DEFAULT);

    // Blocklist matches the DESTINATION on egress ("don't talk to these").
    let blocklisted = BLOCKLIST
        .get(Key::new(
            ScopedAddr::FULL_PREFIX,
            ScopedAddr::new(policy_id, lpm_key_addr(dst_addr)),
        ))
        .is_some();
    // Both address dimensions, each collapsed to a scalar at the call — see
    // `lookup_port_rule` for why an `Option` must not survive to this merge.
    // The egress hook: a rule scoped to arriving traffic does not apply here, and
    // one scoped to IPv6 cannot — this path is IPv4 only.
    let rule = rule_winner_v4(
        policy_id,
        proto,
        icmp_type,
        dst_port,
        lpm_key_addr(src_addr),
        lpm_key_addr(dst_addr),
        PORT_RULE_IN_ONLY | PORT_RULE_V6_ONLY,
    );
    let rule_action = if port_rule_present(rule) {
        Some(port_rule_action(rule))
    } else {
        None
    };
    let meta = PacketMeta::new(
        src_addr,
        dst_addr,
        proto,
        src_port,
        dst_port,
        ipv4.tot_len(),
    );
    let verdict = decide(&meta, &cfg, blocklisted, rule_action);

    // On egress we can't bounce a RST back the way the XDP ingress path does, so
    // an active reject degrades to a silent drop here.
    if verdict.action != Action::Pass {
        bump(Counter::EgressDropped);
        // The policy-wide log flag, or this rule's own per-rule log bit.
        let want_log = cfg.has_flag(ConfigFlags::LOG) || port_rule_logs(rule);
        if want_log {
            info!(
                ctx,
                "EGRESS DROP -> {}.{}.{}.{} proto={} dport={} reason={}",
                dst_addr[0],
                dst_addr[1],
                dst_addr[2],
                dst_addr[3],
                proto,
                dst_port,
                verdict.counter.label(),
            );
        }
        return Ok(TC_ACT_SHOT as i32);
    }

    // Allowed: on a stateful policy, record the flow (and its reverse) so the
    // reply is permitted when it arrives at the XDP ingress hook.
    let stateful = cfg.has_flag(ConfigFlags::STATEFUL)
        && (proto == ip_proto::TCP || proto == ip_proto::UDP)
        && ihl_bytes == Ipv4Hdr::LEN;
    if stateful {
        let fkey = FlowKey::new(policy_id, src_addr, dst_addr, src_port, dst_port, proto);
        let _ = FW_FLOWS.insert(&fkey, &1u8, 0);
        let rkey = FlowKey::new(policy_id, dst_addr, src_addr, dst_port, src_port, proto);
        let _ = FW_FLOWS.insert(&rkey, &1u8, 0);
    }

    Ok(TC_ACT_OK as i32)
}

/// How many ephemeral ports the masquerade NAPT probe tries before falling back
/// to the client's own source port. Small and bounded to keep the egress path
/// within the verifier's complexity budget.
const NAPT_PROBES: u16 = 8;

/// The base ephemeral port for a masquerade flow, mixed from its 4-tuple so
/// distinct clients spread across the port range rather than clustering.
#[inline(always)]
fn napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    let h = u32::from_ne_bytes(src)
        ^ u32::from_ne_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ (dport as u32);
    // Knuth multiplicative hash — cheap, no map, and stable across a flow's packets.
    h.wrapping_mul(2654435761)
}

/// The `i`-th NAPT candidate port, in the ephemeral range [32768, 65535]; never 0.
#[inline(always)]
fn napt_port(seed: u32, i: u16) -> u16 {
    32768 + (seed.wrapping_add(i as u32) % 32768) as u16
}

/// Phase 4b **masquerade** (source NAT + NAPT). A packet leaving a masquerade
/// interface has its source rewritten to that interface's public `wan_ip` and its
/// source port to a per-flow-unique WAN port, so a private network reaches the
/// internet behind one address. A reverse `CONNTRACK` entry (keyed on the
/// allocated WAN port) is recorded so the reply — arriving at the XDP ingress hook
/// — is DNAT'd back to the original client:port by [`try_load_balance`]'s conntrack
/// path (shared map), and an `FW_FLOWS` entry lets that reply through the WAN
/// zone's deny-by-default ingress posture. Only TCP/UDP over a 20-byte IPv4 header
/// are masqueraded (the 5-tuple conntrack needs ports + constant L4 offsets);
/// anything else, or a packet whose source is already `wan_ip` (host-originated),
/// passes unchanged.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn masquerade_egress(
    ctx: &TcContext,
    ihl_bytes: usize,
    policy_id: PolicyId,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    wan_ip: [u8; 4],
    egress_ifindex: u32,
) -> Result<i32, ()> {
    // `try_egress` already counted this packet in TxPackets before dispatching
    // here; the masquerade path reports its own outcome via EgressMasqueraded, so
    // it must not bump TxPackets again (that double-counted every masqueraded
    // packet against the plain egress total).
    if (proto != ip_proto::TCP && proto != ip_proto::UDP)
        || ihl_bytes != Ipv4Hdr::LEN
        || src_addr == wan_ip
    {
        return Ok(TC_ACT_OK as i32);
    }

    // NAPT (port address translation). Allocate a WAN source port unique to this
    // client flow so replies to (wan_ip, wan_port) demux back to the right client:
    // two internal hosts sending from the same source port to the same destination
    // would otherwise share one reverse conntrack key and misroute each other's
    // replies (pure SNAT without PAT). Probe a small window of ephemeral ports
    // seeded by the flow hash — reuse the slot already recording THIS flow (a
    // retransmit reuses the same port), take the first free slot, else fall back to
    // the client's own port (the pre-NAPT behaviour) on exhaustion.
    // `masquerade` rather than `forward`: the rewrite is identical (restore the
    // destination on the reply), but the entry additionally records that its NAT
    // target is the client that *originated* the connection — the only place that
    // fact exists, since the entry is keyed on the reply's addresses.
    let fwd = FlowState::masquerade(src_addr, src_port);
    let seed = napt_seed(src_addr, dst_addr, src_port, dst_port);
    // Deterministic CGNAT: when this egress carries a port-block layout, every
    // candidate stays inside the block that belongs to `src_addr`. That is what
    // lets an operator attribute a WAN port to an internal address by arithmetic
    // instead of by logging every translation. Copied out of the map immediately —
    // a disabled default keeps the plain spread.
    let layout = match unsafe { CGNAT.get(&egress_ifindex) } {
        Some(l) => *l,
        None => CgnatLayout::default(),
    };
    let mut wan_port = src_port;
    for i in 0..NAPT_PROBES {
        let cand = match layout.candidate(src_addr, seed, i) {
            Some(p) => p,
            None => napt_port(seed, i),
        };
        let pkey = FlowKey::new(policy_id, dst_addr, wan_ip, dst_port, cand, proto);
        match unsafe { CONNTRACK.get(&pkey) }.copied() {
            None => {
                wan_port = cand;
                break;
            }
            Some(s) if s.nat_ip == src_addr && s.nat_port == src_port => {
                wan_port = cand;
                break;
            }
            _ => {}
        }
    }

    // The reply (remote -> wan_ip:wan_port) seen at XDP ingress: DNAT its
    // destination back to the original client:client_port. The conntrack key is
    // that reply 5-tuple (keyed on the allocated wan_port); the stored forward
    // state carries the client address+port the reply is restored to.
    let rkey = FlowKey::new(policy_id, dst_addr, wan_ip, dst_port, wan_port, proto);
    // A masqueraded connection has exactly one conntrack entry — this one — so it
    // is also the only place its *outbound* traffic can be accounted. Rewriting
    // the entry is now conditional on it not already being this flow's: the old
    // unconditional insert would have reset the counters on every packet, and a
    // lookup refreshes the LRU just as an insert did.
    let bytes = (ctx.data_end() - ctx.data()) as u64;
    match CONNTRACK.get_ptr_mut(&rkey) {
        // SAFETY: as in `account_flow` — a pointer into this CPU's map value,
        // read and written before any other operation on the map.
        Some(entry) if unsafe { (*entry).nat_ip == src_addr && (*entry).nat_port == src_port } => unsafe {
            (*entry).account(bytes)
        },
        // No entry, or a slot the port probe had to take from another flow on
        // exhaustion: this flow starts the accounting over, as it must.
        _ => {
            let mut first = fwd;
            first.account(bytes);
            let _ = CONNTRACK.insert(&rkey, &first, 0);
        }
    }
    // …and let that reply pass the WAN zone's deny-by-default stateful firewall.
    let _ = FW_FLOWS.insert(&rkey, &1u8, 0);

    if snat_tc(ctx, src_addr, wan_ip, src_port, wan_port, proto).is_err() {
        // Too short to rewrite — let it out un-NAT'd rather than black-hole it.
        return Ok(TC_ACT_OK as i32);
    }
    bump(Counter::EgressMasqueraded);
    Ok(TC_ACT_OK as i32)
}

/// NPTv6 (RFC 6296) **egress** source translation on the TC egress hook: if this
/// egress interface carries an NPTv6 rule and the packet's IPv6 source matches the
/// internal prefix, rewrite it to the external prefix in place. Checksum-neutral —
/// the [`Npt66`] adjustment keeps the one's-complement address sum invariant, so
/// the L4 checksum (and `skb->csum`) stay valid with a plain store (no
/// `BPF_F_RECOMPUTE_CSUM`). Fails open (`TC_ACT_OK`) so non-NPTv6 v6 traffic and a
/// too-short frame pass untouched.
#[inline(always)]
fn npt66_egress_v6(ctx: &TcContext) -> Result<i32, ()> {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let Some(rule) = (unsafe { NPTV6.get(&ifindex) }).copied() else {
        return Ok(TC_ACT_OK as i32);
    };
    // The IPv6 source sits at a constant offset (Ethernet + 8 bytes into the v6
    // header). Read it, and bail out cleanly on a truncated frame.
    let src_off = EthHdr::LEN + 8;
    let src: [u8; 16] = match ctx.load(src_off) {
        Ok(s) => s,
        Err(_) => return Ok(TC_ACT_OK as i32),
    };
    if !rule.matches_internal(&src) {
        return Ok(TC_ACT_OK as i32);
    }
    let new_src = rule.translate_out(src);
    if ctx.store(src_off, &new_src, 0).is_err() {
        return Ok(TC_ACT_OK as i32);
    }
    Ok(TC_ACT_OK as i32)
}

/// Rewrite the IPv4 **source** address to `new_src` in the skb and repair the
/// IPv4 + L4 checksums via the kernel's incremental csum helpers (which also fix
/// `skb->csum`, the correct way to mutate a forwarded packet at TC). Assumes a
/// 20-byte IPv4 header, so the L4 checksum offset is a constant — the caller
/// guarantees it.
#[inline(always)]
fn snat_tc(
    ctx: &TcContext,
    old_src: [u8; 4],
    new_src: [u8; 4],
    old_port: u16,
    new_port: u16,
    proto: u8,
) -> Result<(), ()> {
    // `bpf_l3/l4_csum_replace` take the changed field as a native-endian integer
    // whose in-memory bytes are the on-the-wire (network-order) bytes — i.e. the
    // packet's address/port bytes read in native order. `from_ne_bytes` of the
    // on-wire bytes does exactly that; `from_be_bytes` would byte-swap and corrupt
    // the checksum.
    let from = u32::from_ne_bytes(old_src) as u64;
    let to = u32::from_ne_bytes(new_src) as u64;
    let l4_csum_off = if proto == ip_proto::TCP {
        O_TCP_CSUM
    } else {
        O_UDP_CSUM
    };

    // A UDP datagram with a zero checksum has L4 checksums disabled — leave it.
    let cur_l4: [u8; 2] = ctx.load(l4_csum_off).map_err(|_| ())?;
    let l4_active = !(proto == ip_proto::UDP && cur_l4 == [0, 0]);
    if l4_active {
        // BPF_F_PSEUDO_HDR | size(4): the L4 checksum covers the IP pseudo-header,
        // so a source-address change must update it too.
        ctx.l4_csum_replace(l4_csum_off, from, to, (BPF_F_PSEUDO_HDR as u64) | 4)
            .map_err(|_| ())?;
    }
    ctx.l3_csum_replace(O_IP_CSUM, from, to, 4)
        .map_err(|_| ())?;
    ctx.store(O_IP_SRC, &new_src, 0).map_err(|_| ())?;
    // NAPT source-port rewrite. The port is part of the L4 segment the checksum
    // covers but NOT the pseudo-header, so its delta is a plain 2-byte update (no
    // BPF_F_PSEUDO_HDR). Pass the on-wire (big-endian) port bytes as a native int,
    // mirroring the address handling above.
    if old_port != new_port {
        if l4_active {
            let pfrom = u16::from_ne_bytes(old_port.to_be_bytes()) as u64;
            let pto = u16::from_ne_bytes(new_port.to_be_bytes()) as u64;
            ctx.l4_csum_replace(l4_csum_off, pfrom, pto, 2)
                .map_err(|_| ())?;
        }
        ctx.store(O_L4_SPORT, &new_port.to_be_bytes(), 0)
            .map_err(|_| ())?;
    }
    Ok(())
}

// Constant byte offsets into an Ethernet + 20-byte-IPv4 (+ TCP/UDP) frame. The
// forwarding/NAT paths write through these so the verifier sees *constant*
// offsets from a single, freshly bounds-checked `data` pointer — the only
// pattern the eBPF verifier reliably accepts for packet writes.
const O_ETH_DST: usize = 0; //                 Ethernet destination MAC
const O_ETH_SRC: usize = 6; //                 Ethernet source MAC
const O_IP: usize = EthHdr::LEN; //         14: IPv4 header start
const O_IP_TOTLEN: usize = O_IP + 2; //     16: IPv4 total length
const O_IP_ID: usize = O_IP + 4; //         18: IPv4 identification
const O_IP_FRAG: usize = O_IP + 6; //       20: IPv4 flags + fragment offset
const O_IP_TTL: usize = O_IP + 8; //        22: IPv4 TTL
const O_IP_PROTO: usize = O_IP + 9; //      23: IPv4 protocol
const O_IP_CSUM: usize = O_IP + 10; //      24: IPv4 header checksum
const O_IP_SRC: usize = O_IP + 12; //       26: IPv4 source address
const O_IP_DST: usize = O_IP + 16; //       30: IPv4 destination address
const O_L4: usize = O_IP + Ipv4Hdr::LEN; // 34: L4 header start (requires IHL=20)
const O_L4_SPORT: usize = O_L4; //          34: TCP/UDP source port
const O_L4_DPORT: usize = O_L4 + 2; //      36: TCP/UDP destination port
const O_TCP_SEQ: usize = O_L4 + 4; //       38: TCP sequence number
const O_TCP_ACK: usize = O_L4 + 8; //       42: TCP acknowledgement number
const O_TCP_OFF: usize = O_L4 + 12; //      46: TCP data offset + reserved
const O_TCP_FLAGS: usize = O_L4 + 13; //    47: TCP flags
const O_TCP_WIN: usize = O_L4 + 14; //      48: TCP window
const O_TCP_CSUM: usize = O_L4 + 16; //     50: TCP checksum
const O_TCP_URG: usize = O_L4 + 18; //      52: TCP urgent pointer
const O_UDP_CSUM: usize = O_L4 + 6; //      40: UDP checksum

// Constant byte offsets for the B3 IPv6 Neighbor-Discovery suppression writes
// (Ethernet + fixed 40-byte IPv6 header). The ICMPv6 Neighbor Advertisement is
// written over the solicitation body in place.
const O_IP6_PLEN: usize = O_IP + 4; //      18: IPv6 payload length
const O_IP6_SRC: usize = O_IP + 8; //       22: IPv6 source address
const O_IP6_DST: usize = O_IP + 24; //      38: IPv6 destination address
const O_ND_MSG: usize = EthHdr::LEN + Ipv6Hdr::LEN; // 54: ICMPv6 message start

/// Write a [`Nat`] rewrite's IPv4 address/port and repaired IPv4 checksum at
/// their constant offsets. `reverse` selects the **source** fields (SNAT) over
/// the **destination** fields (DNAT). The L4 checksum is written separately by
/// the caller (its offset is protocol-specific). `data` must already be
/// bounds-checked by the caller to cover the L4 header.
#[inline(always)]
unsafe fn write_l3_nat(data: usize, nat: &Nat, reverse: bool) {
    unsafe {
        *((data + O_IP_CSUM) as *mut [u8; 2]) = nat.new_ip_checksum.to_be_bytes();
        if reverse {
            *((data + O_IP_SRC) as *mut [u8; 4]) = nat.new_ip;
            if nat.rewrite_port {
                *((data + O_L4_SPORT) as *mut [u8; 2]) = nat.new_port.to_be_bytes();
            }
        } else {
            *((data + O_IP_DST) as *mut [u8; 4]) = nat.new_ip;
            if nat.rewrite_port {
                *((data + O_L4_DPORT) as *mut [u8; 2]) = nat.new_port.to_be_bytes();
            }
        }
    }
}

/// Apply a [`Nat`] to the packet: one fresh bounds check (per protocol, so the
/// furthest byte is a constant) followed by constant-offset writes. Returns
/// `Err` if the packet is too short to carry the L4 checksum.
#[inline(always)]
fn apply_nat(ctx: &XdpContext, nat: &Nat, reverse: bool, proto: u8) -> Result<(), ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();
    unsafe {
        if proto == ip_proto::TCP {
            if data + O_TCP_CSUM + 2 > data_end {
                return Err(());
            }
            write_l3_nat(data, nat, reverse);
            if nat.rewrite_l4_checksum {
                *((data + O_TCP_CSUM) as *mut [u8; 2]) = nat.new_l4_checksum.to_be_bytes();
            }
        } else {
            if data + O_UDP_CSUM + 2 > data_end {
                return Err(());
            }
            write_l3_nat(data, nat, reverse);
            if nat.rewrite_l4_checksum {
                *((data + O_UDP_CSUM) as *mut [u8; 2]) = nat.new_l4_checksum.to_be_bytes();
            }
        }
    }
    Ok(())
}

/// Parse and classify one packet. Mirrors `velstra_common::parse::parse_frame`
/// (its unit-tested reference implementation) but on raw, verifier-friendly
/// pointers.
fn try_velstra(ctx: &XdpContext) -> Result<u32, ()> {
    let frame_len = (ctx.data_end() - ctx.data()) as u64;
    bump(Counter::RxPackets);
    add(Counter::RxBytes, frame_len);

    // --- Ethernet -----------------------------------------------------------
    let eth: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    // `EtherType` constants in `network-types` are stored already byte-swapped,
    // so we normalise the wire value to host order and compare against our own
    // host-order constant. (The previous code double-swapped and never matched.)
    let ethertype = u16::from_be(unsafe { (*eth).ether_type });
    if ethertype != ETHERTYPE_IPV4 {
        // IPv6 gets its own stateless firewall path (blocklist + ICMPv6 + port
        // rules + default).
        if ethertype == ETHERTYPE_IPV6 {
            return try_velstra_v6(ctx);
        }
        // ARP on a tenant port may be answered locally (overlay suppression).
        if ethertype == ETHERTYPE_ARP {
            return try_arp(ctx);
        }
        bump(Counter::NonIpv4);
        return Ok(xdp_action::XDP_PASS);
    }

    // --- IPv4 ---------------------------------------------------------------
    let ipv4: *const Ipv4Hdr = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let ipv4 = unsafe { &*ipv4 };
    // `network_types::Ipv4Hdr::ihl()` already returns the header length in
    // *bytes* (it does the `* 4` internally) — do NOT multiply again.
    let ihl_bytes = ipv4.ihl() as usize;
    if ipv4.version() != 4 || ihl_bytes < Ipv4Hdr::LEN {
        bump(Counter::Malformed);
        return Ok(xdp_action::XDP_PASS);
    }

    let proto = ipv4.proto;
    let src_addr = ipv4.src_addr;
    let dst_addr = ipv4.dst_addr;
    let ttl = ipv4.ttl;
    let checksum = ipv4.checksum();

    // --- L4 ports (TCP/UDP, best effort, first fragment only) ---------------
    // Only the first fragment (offset 0) carries the L4 header; a non-first
    // fragment's bytes there are payload, so reading them as ports would allow
    // fragmentation firewall evasion and NAT payload corruption. Leaving ports
    // at 0 means no `(proto, port)` rule, service, port-forward or conntrack
    // entry can match, so the fragment is neither misclassified nor rewritten
    // (M1 — mirrors `velstra_common::parse::parse_frame`).
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    // ICMP's first header byte is its type, where TCP and UDP carry a source
    // port. A rule may name one, so it is read here under the same first-fragment
    // guard: a later fragment's bytes are payload, and treating them as a type
    // would let a rule be evaded by fragmenting.
    let mut icmp_type = 0u8;
    if (proto == ip_proto::TCP || proto == ip_proto::UDP) && ipv4.frag_offset() == 0 {
        // The L4 header begins after the variable-length IPv4 header. We only
        // need the first four bytes (source + destination port).
        if let Ok(ports) = unsafe { ptr_at::<[u8; 4]>(ctx, EthHdr::LEN + ihl_bytes) } {
            let ports = unsafe { *ports };
            src_port = u16::from_be_bytes([ports[0], ports[1]]);
            dst_port = u16::from_be_bytes([ports[2], ports[3]]);
        }
    } else if proto == ip_proto::ICMP && ipv4.frag_offset() == 0 {
        // The same four bytes the ports path reads, of which only the first is
        // the type. A one-byte read is refused here: the bounds check the
        // compiler emits for it establishes no readable *range* on a pointer
        // whose offset is variable ("invalid access to packet, off=0 size=1,
        // r=0"), while the four-byte form the ports already use does. An ICMP
        // header is eight bytes, so four is always there — and when it is not,
        // `ptr_at` fails and the type stays 0, which means "any type", exactly
        // as a truncated TCP header leaves the ports at 0.
        if let Ok(head) = unsafe { ptr_at::<[u8; 4]>(ctx, EthHdr::LEN + ihl_bytes) } {
            icmp_type = unsafe { *head }[0];
        }
    }

    // --- Phase 4: overlay decapsulation -------------------------------------
    // A UDP datagram addressed to our tunnel port is one of our own
    // encapsulated frames. Strip the outer headers and let the kernel deliver
    // the inner frame (e.g. to a local tenant tap via the host bridge).
    let ocfg = overlay_config();
    if proto == ip_proto::UDP && is_overlay_dport(&ocfg, dst_port) {
        // C2: authenticate the tunnel BEFORE stripping any header. Decap only a
        // datagram that is (a) actually addressed to our own VTEP and (b) sourced
        // from a known peer VTEP. Without this, a tenant VM on a tap or any host
        // on the underlay could forge an encapsulated frame under an arbitrary
        // VNI and have the kernel bridge inject its inner frame past the firewall
        // — a full multi-tenant + firewall bypass.
        let from_known_vtep = unsafe { VTEP_PEERS.get(&src_addr) }.is_some();
        if dst_addr != ocfg.local_vtep_ip || !from_known_vtep {
            bump(Counter::OverlayDropUntrusted);
            return Ok(xdp_action::XDP_DROP);
        }
        return try_decap(ctx, ihl_bytes);
    }

    let meta = PacketMeta::new(
        src_addr,
        dst_addr,
        proto,
        src_port,
        dst_port,
        ipv4.tot_len(),
    );

    // --- Per-policy firewall lookups ----------------------------------------
    // The packet's ingress interface selects its policy (tenant); absent any
    // mapping it falls into policy 0, the default. All firewall lookups are then
    // scoped by that policy id, so one program enforces many tenants' rules.
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy_id = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
    // The overlay segment is independent of the firewall policy (a port's
    // security group vs. its virtual network). `0` ⇒ local-only, no encap.
    let vni = unsafe { IFACE_VNI.get(&ifindex) }.copied().unwrap_or(0);

    let cfg = unsafe { CONFIG.get(&policy_id) }
        .copied()
        .unwrap_or(GlobalConfig::DEFAULT);

    // --- Source validation (uRPF, RFC 3704) ---------------------------------
    // Runs ahead of every other verdict: a packet whose source cannot be the
    // sender is not worth matching rules against, and the answer does not depend
    // on any of them.
    let rpf = cfg.source_validation();
    if rpf != SourceValidation::Disabled
        && source_is_spoofed(ctx, &meta, ifindex, rpf == SourceValidation::Strict)
    {
        bump(Counter::DroppedSpoofed);
        if cfg.has_flag(ConfigFlags::LOG) {
            info!(ctx, "DROP spoofed source proto={}", proto);
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // --- C20: the captive portal gate ---------------------------------------
    // Ahead of the rules, because on a gated zone the question "has this device
    // logged in" precedes every question the rules ask, and behind source
    // validation, because a packet whose source cannot be the sender is not
    // worth asking about at all.
    if cfg.has_flag(ConfigFlags::PORTAL) && !portal_admits(ctx, policy_id, &meta) {
        bump(Counter::DroppedPortal);
        if cfg.has_flag(ConfigFlags::LOG) {
            info!(
                ctx,
                "DROP portal {}.{}.{}.{} proto={} dport={}",
                src_addr[0],
                src_addr[1],
                src_addr[2],
                src_addr[3],
                proto,
                dst_port,
            );
        }
        return Ok(xdp_action::XDP_DROP);
    }

    let blocklisted = BLOCKLIST
        .get(Key::new(
            ScopedAddr::FULL_PREFIX,
            ScopedAddr::new(policy_id, lpm_key_addr(src_addr)),
        ))
        .is_some();
    let rule = rule_winner_v4(
        policy_id,
        proto,
        icmp_type,
        dst_port,
        lpm_key_addr(src_addr),
        lpm_key_addr(dst_addr),
        PORT_RULE_OUT_ONLY | PORT_RULE_V6_ONLY,
    );
    let rule_action = if port_rule_present(rule) {
        Some(port_rule_action(rule))
    } else {
        None
    };
    // A configured port-forward for this destination port implicitly opens the
    // firewall (the DNAT + reply SNAT run in `velstra_forward` / the conntrack
    // path). The main program only needs to know one *exists* — a bare `bool`,
    // never the `PortFwd` value. Materialising the `Option<PortFwd>` here and
    // carrying it to the consumer kept a map-value pointer niche live across a
    // merge point; under this function's register pressure LLVM lowered it to a
    // bitwise-OR on that pointer ("R1 |= on pointer") and, after the tail-call
    // split changed register allocation, to an uninitialised read on the None
    // path ("R3 !read_ok"). `port_forward_exists` returns a plain bool from the
    // map-lookup discriminant, so no map-value pointer is ever live here;
    // `try_port_forward` re-looks-up the target with a fresh stack downstream.
    let has_port_forward = port_forward_exists(policy_id, proto, dst_port);

    let verdict = decide(&meta, &cfg, blocklisted, rule_action);
    // Per-rule logging: this rule's own log bit, and the effective flag combining
    // it with the policy-wide log. `rule_log` alone gates logging of *allowed*
    // traffic so a globally-logging policy doesn't start logging every pass.
    let rule_log = port_rule_logs(rule);
    let want_log = cfg.has_flag(ConfigFlags::LOG) || rule_log;

    // Stateful firewall: track allowed TCP/UDP flows so replies are permitted in
    // either direction, even under deny-by-default. The blocklist still wins.
    let stateful = cfg.has_flag(ConfigFlags::STATEFUL)
        && (proto == ip_proto::TCP || proto == ip_proto::UDP)
        && ihl_bytes == Ipv4Hdr::LEN;
    let fkey = FlowKey::new(policy_id, src_addr, dst_addr, src_port, dst_port, proto);
    // Only the tenant-scoped namespace is consulted here, and that is a deliberate
    // limit rather than an oversight. A router-NAT reply — from a port-forward's
    // internal host or a cross-zone load-balanced backend — arrives under a
    // different policy than the request did, so the entry the NAT path wrote in the
    // policy-independent namespace is invisible to this lookup. Consulting both was
    // tried and **cannot be compiled for the verifier**: with a 1-byte map value
    // LLVM folds two lookups of the *same* map into one pointer (`r1 |= r0`) and
    // null-checks once, which is rejected as arithmetic on a `map_value_or_null` —
    // three formulations (borrowed, value-read, owned `Option<u8>`) all fold. The
    // fix without a second lookup is for the NAT path to record its reply under the
    // policy that reply will actually arrive on, which the *config* knows (the zone
    // owning the target's subnet) and the data plane does not.
    //
    // Until then, a NAT'd reply is admitted by the internal zone's own outbound
    // posture, which every ordinary configuration permits. Only an internal zone
    // that denies by default drops it.
    let established = stateful && unsafe { FW_FLOWS.get(&fkey) }.is_some();

    // Per-rule rate limit (C15). Consulted only for a rule that carries a slot and
    // only for a NEW flow: an established connection whose packets each cost a
    // token would stall mid-transfer, which is throttling the wrong thing — the
    // limit exists to bound how fast new connections are *accepted*. A blocklisted
    // or already-denied packet never reaches the bucket, so a flood of traffic the
    // firewall drops anyway cannot spend another rule's budget.
    let limit_slot = port_rule_limit(rule);
    let rate_limited = limit_slot != 0
        && !established
        && !blocklisted
        && verdict.action == Action::Pass
        && !rate_limits_allow(limit_slot);

    // The firewall's final action, and the counter explaining it.
    let (action, fw_counter) = if blocklisted {
        (Action::Drop, Counter::DroppedBlocklist)
    } else if rate_limited {
        // Over its rule's budget. Dropped rather than rejected: a reject answers
        // every excess packet with one of our own, which turns a flood aimed at us
        // into a flood aimed at whoever the source claims to be.
        (Action::Drop, Counter::DroppedRateLimit)
    } else if established {
        (Action::Pass, Counter::EstablishedAllowed)
    } else if has_port_forward {
        // The blocklist still wins (checked first); otherwise a port-forward
        // destination port is allowed inbound.
        (Action::Pass, Counter::PassedRule)
    } else {
        (verdict.action, verdict.counter)
    };

    // Phase 1: a firewall drop is final.
    if action == Action::Drop {
        bump(fw_counter);
        if want_log {
            info!(
                ctx,
                "DROP {}.{}.{}.{} proto={} dport={} reason={}",
                src_addr[0],
                src_addr[1],
                src_addr[2],
                src_addr[3],
                proto,
                dst_port,
                fw_counter.label(),
            );
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // Phase 3: an active reject answers the sender — a TCP RST (or a drop for
    // non-TCP) bounced back out the ingress interface — instead of black-holing.
    if action == Action::Reject {
        if want_log {
            info!(
                ctx,
                "REJECT {}.{}.{}.{} proto={} dport={}",
                src_addr[0],
                src_addr[1],
                src_addr[2],
                src_addr[3],
                proto,
                dst_port,
            );
        }
        return reject_packet(
            ctx, ihl_bytes, src_addr, dst_addr, src_port, dst_port, proto,
        );
    }

    // Allowed. On a stateful policy, remember a new flow (and its reverse) so the
    // reply is permitted regardless of the reverse direction's policy.
    if stateful && !established {
        let _ = FW_FLOWS.insert(&fkey, &1u8, 0);
        let rkey = FlowKey::new(policy_id, dst_addr, src_addr, dst_port, src_port, proto);
        let _ = FW_FLOWS.insert(&rkey, &1u8, 0);
    }

    // Per-rule logging of allowed traffic: a rule with `log = true` records each
    // new (non-established) flow it admits. Gated on the rule's own bit so a
    // policy that logs globally still only logs drops/rejects, not every pass.
    if rule_log && action == Action::Pass && !established {
        info!(
            ctx,
            "ALLOW {}.{}.{}.{} proto={} dport={} reason={}",
            src_addr[0],
            src_addr[1],
            src_addr[2],
            src_addr[3],
            proto,
            dst_port,
            fw_counter.label(),
        );
    }

    let log = cfg.has_flag(ConfigFlags::LOG);

    // B4b: learn this tenant's source MAC → IPv4 on the firewall-allowed path so
    // the agent can advertise it to the local routing daemon (EVPN type-2). Only
    // on a tenant segment (`vni != 0`); the overlay/underlay port (`vni == 0`) is
    // never learned, and decapped tunnel traffic already returned via `try_decap`
    // above, so it can't reach here either. IPv4 only — `src_addr` is the parsed
    // v4 source (v6 learning is out of scope for now). Verifier-simple: one
    // constant-offset read at `O_ETH_SRC` (== 6, freshly bounds-checked by
    // `ptr_at`) followed by a single LRU map insert — no loops, no data-dependent
    // offsets. Refresh-on-every-frame is fine: the LRU keeps active MACs and ages
    // out silent ones.
    if vni != 0
        && let Ok(src_mac) = unsafe { ptr_at::<[u8; 6]>(ctx, O_ETH_SRC) }
    {
        let key = LocalMacKey::new(vni, unsafe { *src_mac });
        // Anti-spoof: the first port to claim a `(vni, MAC)` owns it. Without this
        // any tenant could source-spoof a neighbour's MAC and the agent would
        // advertise the neighbour's address as reachable via the attacker —
        // poisoning EVPN across the fabric. Refuse the *binding* only; the frame
        // still forwards, so this cannot black-hole traffic. A refused frame never
        // refreshes the LRU, so a workload that genuinely moved ports is re-learned
        // once the stale owner ages out.
        match unsafe { LOCAL_MACS.get(&key) } {
            Some(bound) if bound.ifindex != ifindex => bump(Counter::MacLearnSpoof),
            _ => {
                let _ = LOCAL_MACS.insert(&key, &LocalMac::new(src_addr, ifindex), 0);
            }
        }
    }

    // Hand the forwarding transforms (encap / DNAT / LB / route) to a tail-called
    // program so they run with a fresh 512-byte stack — the main program is at the
    // BPF stack ceiling, leaving no room to grow the datapath (e.g. SRv6). Carry
    // the post-firewall state through a per-CPU scratch slot; a tail call cannot
    // pass the stack. Behaviour is identical to running the phases inline.
    let scratch = ForwardScratch {
        src_addr,
        dst_addr,
        checksum,
        src_port,
        dst_port,
        ihl_bytes: ihl_bytes as u16,
        policy_id,
        vni,
        fw_counter: fw_counter.index(),
        proto,
        ttl,
        has_port_forward: has_port_forward as u8,
        log: log as u8,
    };
    if let Some(dst) = SCRATCH.get_ptr_mut(0) {
        // SAFETY: `get_ptr_mut` returned a valid pointer into this CPU's slot;
        // per-CPU maps are not shared, so nothing else races this write.
        unsafe { *dst = scratch };
    }
    // `tail_call` does not return on success — control jumps into `velstra_forward`
    // and never comes back (this aya build types it as returning `()`, not a
    // `Result`). It falls through to the lines below only if the slot is
    // unpopulated: a load-time misconfiguration, since userspace always sets it.
    // Degrade safely by honouring the firewall PASS without overlay/LB/route.
    unsafe {
        VELSTRA_PROGS.tail_call(ctx, PROG_FORWARD);
    }
    bump(fw_counter);
    Ok(xdp_action::XDP_PASS)
}

/// Tail-call target for the IPv4 forwarding transforms — Phase 4 overlay encap,
/// Phase 3a port-forward DNAT, Phase 3 load-balancer DNAT/SNAT, and Phase 2
/// routing. Split out of [`try_velstra`] so it runs with a fresh 512-byte BPF
/// stack: the main program (parse + decap-auth + firewall + MAC-learn) already
/// sits at the stack ceiling, leaving no headroom to grow the datapath. Behaviour
/// is byte-for-byte identical to running these phases inline; only the stack
/// frame is fresh. All inputs arrive via the per-CPU [`SCRATCH`] slot the main
/// program filled immediately before tail-calling.
#[xdp]
pub fn velstra_forward(ctx: XdpContext) -> u32 {
    match try_velstra_forward(&ctx) {
        Ok(action) => action,
        // Preserve the pre-split fail-open behaviour exactly. When these phases
        // ran inline in `try_velstra`, a helper `?` bounds failure propagated to
        // the `velstra` entry wrapper, which counts it and PASSes (a firewall must
        // never black-hole traffic over its own parse error). Keep that verdict
        // here rather than aborting.
        Err(()) => {
            bump(Counter::Malformed);
            xdp_action::XDP_PASS
        }
    }
}

fn try_velstra_forward(ctx: &XdpContext) -> Result<u32, ()> {
    let s = match SCRATCH.get_ptr(0) {
        // SAFETY: a valid pointer into this CPU's private scratch slot, just
        // written by `try_velstra` before the tail call.
        Some(p) => unsafe { *p },
        // Only reachable if the per-CPU scratch map is absent (it never is).
        None => return Ok(xdp_action::XDP_PASS),
    };
    let ihl_bytes = s.ihl_bytes as usize;
    let ocfg = overlay_config();
    let log = s.log != 0;

    // C15: SYN proxy. Runs before every transform below, because the client's
    // handshake is answered here without the server ever hearing about it, and
    // because the ACK that admits a connection leaves as a SYN which the
    // port-forward and routing phases below then treat as any other new flow.
    if let Some(action) = try_synproxy(
        ctx, ihl_bytes, s.src_addr, s.dst_addr, s.src_port, s.dst_port, s.proto,
    )? {
        return Ok(action);
    }

    // Phase 4 (B9): SRv6 overlay encapsulation. When the host runs the SRv6 wire
    // format, a tenant frame whose inner destination MAC resolves to a remote
    // End.DT2U service SID is encapsulated in outer Ethernet + IPv6 and redirected
    // onto the underlay. Mutually exclusive with the VXLAN/Geneve path below (one
    // overlay wire format per host); a miss falls through unchanged.
    let scfg = srv6_config();
    if let Some(action) = try_srv6_encap(
        ctx, &scfg, s.vni, s.src_addr, s.src_port, s.dst_port, s.proto, log,
    )? {
        return Ok(action);
    }

    // Phase 4: overlay encapsulation. If this tenant's (vni == policy) inner
    // destination lives on another host, wrap the frame in a VXLAN/Geneve tunnel
    // and redirect it onto the underlay. A miss means "local" — fall through to
    // ordinary switching/routing.
    if let Some(action) = try_encap(
        ctx, &ocfg, s.vni, s.src_addr, s.dst_addr, s.src_port, s.dst_port, s.proto, s.ttl,
        s.checksum, log,
    )? {
        return Ok(action);
    }

    // Phase 3a: DNAT port-forward. A new inbound flow to a forwarded port is
    // rewritten to its internal host here; established flows and the reply path
    // are handled by the conntrack path in try_load_balance below (shared
    // CONNTRACK map), so this only fires once per connection. The main program
    // only stashed a bool (that a forward exists); the target itself is re-looked
    // up here with a fresh stack — see [`ForwardScratch`] for why it isn't carried.
    if s.has_port_forward != 0
        && let Some(target) = lookup_port_forward(s.policy_id, s.proto, s.dst_port)
    {
        if let Some(action) = try_port_forward(
            ctx, ihl_bytes, s.src_addr, s.dst_addr, s.src_port, s.dst_port, s.proto, s.checksum,
            target,
        )? {
            return Ok(action);
        }
    }

    // Phase 3: load balancer / DNAT. A matching service rewrites the packet to a
    // backend and we PASS it for the kernel to route there.
    if let Some(action) = try_load_balance(
        ctx,
        ihl_bytes,
        s.policy_id,
        s.src_addr,
        s.dst_addr,
        s.src_port,
        s.dst_port,
        s.proto,
        s.checksum,
        log,
    )? {
        return Ok(action);
    }

    // Phase 2: routing. A matching route takes over; otherwise fall through.
    let route = ROUTES
        .get(Key::new(
            ScopedAddr::FULL_PREFIX,
            ScopedAddr::new(s.policy_id, lpm_key_addr(s.dst_addr)),
        ))
        .copied();
    match plan_forward(s.ttl, s.checksum, s.proto, route) {
        ForwardOutcome::Pass => {}
        ForwardOutcome::TtlExceeded => {
            bump(Counter::ForwardTtlExceeded);
            return Ok(xdp_action::XDP_DROP);
        }
        ForwardOutcome::Redirect(rewrite) => return forward(ctx, rewrite, log),
    }

    // Nothing took over: honour the firewall's pass decision. Reconstruct the
    // exact counter `try_velstra` resolved from its firewall verdict; the sentinel
    // fallback is unreachable (the stored value is always a real `Counter`).
    bump(Counter::from_u32(s.fw_counter).unwrap_or(Counter::PassedRule));
    Ok(xdp_action::XDP_PASS)
}

/// How many IPv6 extension headers the firewall walks before giving up. RFC 8200
/// §4.1 expects each header to occur once (Destination Options at most twice), so a
/// legitimate packet needs a handful — and the cap is what makes this a *bounded*
/// loop the eBPF verifier will accept.
const MAX_IPV6_EXT_HDRS: usize = 8;

/// Where an IPv6 extension-header walk ended up.
struct Ipv6Upper {
    /// The upper-layer protocol the chain resolves to — or, if the walk could not
    /// finish, the extension header it stopped on.
    proto: u8,
    /// Offset of that header within the frame.
    off: usize,
    /// Whether an L4 header really sits at `off`. False behind a non-first fragment,
    /// where those bytes are payload rather than ports.
    l4_present: bool,
}

/// Walk the extension-header chain from the fixed header's `first` next-header to
/// the upper-layer protocol.
///
/// This is what keeps extension headers from being a firewall bypass. Classifying a
/// packet by the *fixed* header's next-header means a Hop-by-Hop or
/// Destination-Options header placed in front of TCP reads as an unknown protocol
/// with no ports — so no port rule and no ICMPv6 rule matches, and under a
/// `default-action accept` policy the packet is passed on that basis alone.
///
/// A chain this cannot resolve — deeper than [`MAX_IPV6_EXT_HDRS`], or truncated —
/// returns the extension header the walk stopped on. That matches no rule, so the
/// packet falls to the policy's **default action** rather than being classified as
/// something harmless: a drop under `default-action drop`, and under
/// `default-action accept` a pass, which is that posture's own choice.
#[inline(always)]
fn walk_ipv6_ext(ctx: &XdpContext, first: u8) -> Ipv6Upper {
    let mut proto = first;
    let mut off = EthHdr::LEN + Ipv6Hdr::LEN;
    let mut l4_present = true;
    for _ in 0..MAX_IPV6_EXT_HDRS {
        if !is_ipv6_ext(proto) {
            break;
        }
        // Every walkable header starts with its next-header and length bytes; for the
        // Fragment header the two after those hold the fragment offset.
        let Ok(h) = (unsafe { ptr_at::<[u8; 4]>(ctx, off) }) else {
            break;
        };
        let h = unsafe { *h };
        // The offset is the top 13 bits of that field; a non-zero one means this is
        // not the first fragment, so it carries no L4 header. Keep resolving the
        // protocol — a proto rule still applies — but never read ports out of
        // payload. This is the IPv6 twin of the IPv4 path's `frag_offset()` guard.
        if proto == ip_proto::FRAGMENT && u16::from_be_bytes([h[2], h[3]]) & 0xFFF8 != 0 {
            l4_present = false;
        }
        off += ipv6_ext_len(proto, h[1]);
        proto = h[0];
    }
    Ipv6Upper {
        proto,
        off,
        l4_present,
    }
}

/// IPv6 firewall path: a dual-stack mirror of the IPv4 firewall in
/// [`try_velstra`], covering the **blocklist, ICMPv6 filter, port rules and
/// default policy** — scoped by the same per-interface `policy_id`.
///
/// It is deliberately **stateless** and never routes or load-balances: Phase 2/3
/// stay IPv4-only for now, so any IPv6 packet the firewall allows is `XDP_PASS`ed
/// to the kernel stack. The extension-header chain **is** walked
/// ([`walk_ipv6_ext`]), so rules see the real upper-layer protocol rather than
/// whatever header happens to come first.
#[inline(always)]
fn try_velstra_v6(ctx: &XdpContext) -> Result<u32, ()> {
    // The fixed 40-byte IPv6 header, copied out in one bounds-checked read. We
    // read raw bytes rather than `Ipv6Hdr` to sidestep its `in6_addr` unions.
    let hdr: *const [u8; Ipv6Hdr::LEN] = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let hdr = unsafe { *hdr };

    // B9: SRv6 decapsulation (End.DT2U). If this packet's IPv6 destination is a
    // service SID we instantiated, strip the outer Ethernet+IPv6 and hand the
    // inner Ethernet frame to the kernel bridge (deliver by inner MAC). Runs
    // before the firewall — the SID match is the authorization (we only ever
    // instantiate our own SIDs). A miss falls through to the IPv6 firewall below.
    if let Some(action) = try_srv6_decap(ctx, &hdr)? {
        return Ok(action);
    }

    // payload length @4..6 (big-endian), next-header @6, addresses @8 and @24.
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]);
    let next_hdr = hdr[6];

    // B3: on a tenant port, a Neighbor Solicitation for a known address is
    // answered locally (ND suppression). A miss / non-NS falls through to the
    // firewall below, so ICMPv6 is still filtered and policed as before.
    if next_hdr == ip_proto::ICMPV6 {
        if let Some(action) = try_nd(ctx)? {
            return Ok(action);
        }
    }
    let src_addr: [u8; 16] = [
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17],
        hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
    ];

    // --- Upper layer: walk the extension-header chain, then read L4 ports ----
    // `proto` from here on is the RESOLVED upper-layer protocol, not the fixed
    // header's next-header — that distinction is the whole point of the walk.
    let upper = walk_ipv6_ext(ctx, next_hdr);
    let proto = upper.proto;
    let (mut src_port, mut dst_port) = (0u16, 0u16);
    // ICMPv6's type byte sits where TCP's source port would: same read, same
    // reason, and `l4_present` is what says the chain ended in a real header
    // rather than in a fragment.
    let mut icmp_type = 0u8;
    if upper.l4_present && (proto == ip_proto::TCP || proto == ip_proto::UDP) {
        if let Ok(ports) = unsafe { ptr_at::<[u8; 4]>(ctx, upper.off) } {
            let ports = unsafe { *ports };
            src_port = u16::from_be_bytes([ports[0], ports[1]]);
            dst_port = u16::from_be_bytes([ports[2], ports[3]]);
        }
    } else if upper.l4_present && proto == ip_proto::ICMPV6 {
        // Four bytes, not one — and on this path it is not a preference: the
        // offset is walked, so its `var_off` is wide, and a one-byte read there
        // is exactly what the verifier refused.
        if let Ok(head) = unsafe { ptr_at::<[u8; 4]>(ctx, upper.off) } {
            icmp_type = unsafe { *head }[0];
        }
    }

    // IPv6 addresses do not fit `PacketMeta`'s IPv4 fields, but `decide` only
    // reads `proto`/`dst_port` plus the `blocklisted`/`rule` inputs computed
    // below, so zero placeholders are harmless. The blocklist verdict comes from
    // the real IPv6 source, and source validation reads the real header.
    let meta = PacketMeta::new([0; 4], [0; 4], proto, src_port, dst_port, payload_len);

    // --- Per-policy firewall lookups (same policy space as IPv4) -------------
    let ifindex = ctx.ingress_ifindex() as u32;
    let policy_id = unsafe { IFACE_POLICY.get(&ifindex) }.copied().unwrap_or(0);
    let cfg = unsafe { CONFIG.get(&policy_id) }
        .copied()
        .unwrap_or(GlobalConfig::DEFAULT);
    // Source validation, ahead of every other verdict (see the IPv4 path).
    let rpf = cfg.source_validation();
    if rpf != SourceValidation::Disabled
        && source_is_spoofed_v6(ctx, &hdr, &meta, ifindex, rpf == SourceValidation::Strict)
    {
        bump(Counter::DroppedSpoofed);
        if cfg.has_flag(ConfigFlags::LOG) {
            info!(ctx, "DROP6 spoofed source proto={}", proto);
        }
        return Ok(xdp_action::XDP_DROP);
    }

    // C20: the same gate and the same session as the IPv4 path. Without this a
    // dual-stacked guest zone would hand every unadmitted device a working IPv6
    // path around the portal, which is not a gap in the feature — it is the
    // feature not existing.
    if cfg.has_flag(ConfigFlags::PORTAL) && !portal_admits_v6(ctx, policy_id, &hdr, &meta) {
        bump(Counter::DroppedPortal);
        if cfg.has_flag(ConfigFlags::LOG) {
            info!(ctx, "DROP6 portal proto={} dport={}", proto, dst_port);
        }
        return Ok(xdp_action::XDP_DROP);
    }

    let blocklisted = BLOCKLIST6
        .get(Key::new(
            ScopedAddr6::FULL_PREFIX,
            ScopedAddr6::new(policy_id, src_addr),
        ))
        .is_some();
    // Both address dimensions in the v6 tries, with the packet's real addresses
    // — and the v4 tries too, looked up with the address as `0`, so a rule that
    // names a protocol and a port but no address still applies to both families
    // exactly as it reads.
    let rule = port_rule_winner(
        rule_winner_v6(
            policy_id,
            proto,
            icmp_type,
            dst_port,
            &hdr,
            PORT_RULE_OUT_ONLY | PORT_RULE_V4_ONLY,
        ),
        // The v4 tries with no address, for a rule that names a protocol and a
        // port but no address — which applies to both families unless it says
        // otherwise, and `PORT_RULE_V4_ONLY` is how it says otherwise.
        rule_winner_v4(
            policy_id,
            proto,
            icmp_type,
            dst_port,
            0,
            0,
            PORT_RULE_OUT_ONLY | PORT_RULE_V4_ONLY,
        ),
    );
    let rule_action = if port_rule_present(rule) {
        Some(port_rule_action(rule))
    } else {
        None
    };

    let verdict = decide(&meta, &cfg, blocklisted, rule_action);

    bump(verdict.counter);
    // Reject has no IPv6 RST path yet, so it drops here like Drop.
    if verdict.action != Action::Pass {
        let want_log = cfg.has_flag(ConfigFlags::LOG) || port_rule_logs(rule);
        if want_log {
            info!(
                ctx,
                "DROP6 proto={} dport={} reason={}",
                proto,
                dst_port,
                verdict.counter.label(),
            );
        }
        return Ok(xdp_action::XDP_DROP);
    }
    // NPTv6 (RFC 6296) ingress: on a boundary interface, an inbound packet whose
    // destination matches the external prefix is rewritten back to the internal
    // prefix (checksum-neutral). A no-op when this interface has no rule or the
    // destination doesn't match.
    npt66_ingress_v6(ctx, ifindex)?;
    Ok(xdp_action::XDP_PASS)
}

/// NPTv6 (RFC 6296) **ingress** destination translation on the XDP hook: if this
/// interface carries an NPTv6 rule and the packet's IPv6 destination matches the
/// external prefix, rewrite it back to the internal prefix in place (constant
/// offset, one freshly bounds-checked write). Checksum-neutral, so no L4 fix-up.
///
/// Kept out of line (`inline(never)`) so its 36-byte rule copy + address locals
/// live in their own BPF stack frame rather than inflating the main program's.
#[inline(never)]
fn npt66_ingress_v6(ctx: &XdpContext, ifindex: u32) -> Result<(), ()> {
    let Some(rule) = (unsafe { NPTV6.get(&ifindex) }) else {
        return Ok(());
    };
    // IPv6 destination @ Ethernet + 24 bytes into the v6 header.
    let off = EthHdr::LEN + 24;
    let dst: [u8; 16] = unsafe { *ptr_at::<[u8; 16]>(ctx, off)? };
    if !rule.matches_external(&dst) {
        return Ok(());
    }
    let new_dst = rule.translate_in(dst);
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + off + 16 > data_end {
        return Err(());
    }
    unsafe {
        *((data + off) as *mut [u8; 16]) = new_dst;
    }
    Ok(())
}

/// `family` values for [`bpf_fib_lookup`] (`AF_INET` / `AF_INET6` — the kernel's
/// own numbers, which no header exports to a BPF program).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Source-address validation (uRPF, RFC 3704) for IPv4. Returns `true` when the
/// packet should be dropped as spoofed.
///
/// The question is answered by the **kernel's own FIB**, not a table of our own:
/// `bpf_fib_lookup` is handed the packet's addresses swapped, so its answer is
/// "if we replied to this sender, which interface would the reply leave by?".
/// Strict validation requires that to be the interface the packet arrived on —
/// the BCP 38 rule, which stops a neighbour on one link from claiming an address
/// that belongs to another. Loose validation only requires that an answer exists.
///
/// Two things are deliberately *not* treated as spoofed:
///
/// * **A `0.0.0.0` source**, which is how a DHCP client asks for its first
///   address. Linux's own `rp_filter` exempts it, and validating it here would
///   make a DHCP server unreachable the moment an operator turned this on — the
///   sort of breakage that gets a security feature switched back off. Nothing is
///   lost: a source that cannot be replied to cannot be used to reflect anything.
/// * **A packet the helper could not answer for** (a negative return). Failing
///   closed on a question we failed to *ask* would drop traffic for a reason no
///   counter could explain.
///
/// Kept out of line so the 64-byte `bpf_fib_lookup` parameter block gets its own
/// BPF stack frame rather than inflating the main program's, which is already
/// close to the verifier's 512-byte limit.
#[inline(never)]
fn source_is_spoofed(ctx: &XdpContext, meta: &PacketMeta, ifindex: u32, strict: bool) -> bool {
    let src = meta.src_addr;
    if src == [0, 0, 0, 0] {
        return false;
    }
    // Addresses that can never legitimately *send*: loopback, multicast
    // (224.0.0.0/4) and the limited broadcast. A route back to them may well
    // exist, so the FIB alone would let them through.
    if src[0] == 127 || src[0] & 0xf0 == 0xe0 || src == [255, 255, 255, 255] {
        return true;
    }

    let Some(params) = fib_scratch() else {
        return false;
    };
    unsafe {
        (*params).family = AF_INET;
        (*params).l4_protocol = meta.proto;
        // Ports are swapped with the addresses: policy routing rules and
        // multipath hashing both look at them, and we are asking about the
        // *reply*.
        (*params).sport = meta.dst_port.to_be();
        (*params).dport = meta.src_port.to_be();
        (*params).__bindgen_anon_1.tot_len = meta.total_len;
        (*params).ifindex = ifindex;
        (*params).__bindgen_anon_3.ipv4_src = u32::from_ne_bytes(meta.dst_addr);
        (*params).__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes(src);
    }

    fib_says_spoofed(ctx, params, ifindex, strict)
}

/// Source-address validation for IPv6 — the mirror of [`source_is_spoofed`],
/// reading the addresses straight out of the fixed header (`src` at 8, `dst` at
/// 24) so the caller need not lift two 16-byte addresses into its own frame.
///
/// **Link-local sources (`fe80::/10`) are exempt.** They are not routable by
/// definition, so uRPF has nothing to say about them, and Neighbor Discovery,
/// Router Advertisement and DHCPv6 all speak from one — validating them would
/// take the interface down rather than protect it. The unspecified address
/// (`::`) is exempt for the same reason `0.0.0.0` is: duplicate-address
/// detection sends from it.
///
/// Takes the `PacketMeta` the IPv6 path already builds purely for its
/// `proto`/port fields — its address fields are zero there and unused here. A
/// BPF function may take at most five arguments, which is exactly what is left
/// once the header and the context are passed.
#[inline(never)]
fn source_is_spoofed_v6(
    ctx: &XdpContext,
    hdr: &[u8; Ipv6Hdr::LEN],
    meta: &PacketMeta,
    ifindex: u32,
    strict: bool,
) -> bool {
    // The packet's source address, as the four words the helper wants.
    let src = [
        u32::from_ne_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]),
        u32::from_ne_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]),
        u32::from_ne_bytes([hdr[16], hdr[17], hdr[18], hdr[19]]),
        u32::from_ne_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]),
    ];
    // fe80::/10 — link-local, exempt (see above).
    if hdr[8] == 0xfe && hdr[9] & 0xc0 == 0x80 {
        return false;
    }
    if src[0] == 0 && src[1] == 0 && src[2] == 0 {
        // `::` is duplicate-address detection and passes; `::1` is loopback and
        // can never legitimately send.
        return src[3] != 0;
    }
    // ff00::/8 — multicast is a destination, never a source.
    if hdr[8] == 0xff {
        return true;
    }

    let Some(params) = fib_scratch() else {
        return false;
    };
    unsafe {
        (*params).family = AF_INET6;
        (*params).l4_protocol = meta.proto;
        (*params).sport = meta.dst_port.to_be();
        (*params).dport = meta.src_port.to_be();
        (*params).ifindex = ifindex;
        // Swapped: the lookup's source is the packet's destination (offset 24)
        // and its destination is the packet's source (offset 8).
        (*params).__bindgen_anon_3.ipv6_src = [
            u32::from_ne_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]),
            u32::from_ne_bytes([hdr[28], hdr[29], hdr[30], hdr[31]]),
            u32::from_ne_bytes([hdr[32], hdr[33], hdr[34], hdr[35]]),
            u32::from_ne_bytes([hdr[36], hdr[37], hdr[38], hdr[39]]),
        ];
        (*params).__bindgen_anon_4.ipv6_dst = src;
    }

    fib_says_spoofed(ctx, params, ifindex, strict)
}

/// Run a prepared reverse-path [`bpf_fib_lookup`] and turn its answer into a
/// verdict. Shared by both address families so the "what counts as routable"
/// rule is written down once.
#[inline(always)]
fn fib_says_spoofed(
    ctx: &XdpContext,
    params: *mut bpf_fib_lookup,
    ifindex: u32,
    strict: bool,
) -> bool {
    let rc = unsafe {
        fib_lookup(
            ctx.ctx as *mut _,
            params,
            core::mem::size_of::<bpf_fib_lookup>() as i32,
            0,
        )
    };
    // Negative means the helper itself refused the question (unsupported family,
    // bad length). Fail open — see the note on [`source_is_spoofed`].
    if rc < 0 {
        return false;
    }
    // `FWD_DISABLED` is the FIB declining the question, not answering it: the
    // helper does a *forwarding* lookup and refuses one on an interface where IP
    // forwarding is off. Reading that as "spoofed" would black-hole every packet
    // on a box that only terminates traffic — the worst possible way for a
    // security feature to fail, so it fails open like any other refusal.
    if rc as u32 == BPF_FIB_LKUP_RET_FWD_DISABLED {
        return false;
    }
    // `NO_NEIGH` means the route was found but its next hop has no resolved
    // neighbour yet. An unresolved ARP/ND entry says nothing about whether the
    // source is routable, and the egress interface is filled in either way.
    let ret = rc as u32;
    if ret != BPF_FIB_LKUP_RET_SUCCESS && ret != BPF_FIB_LKUP_RET_NO_NEIGH {
        return true;
    }
    strict && unsafe { (*params).ifindex } != ifindex
}

/// Phase 4 **ARP suppression**: answer a tenant's ARP request locally from
/// `ARP_TABLE` (pushed by the controller) and bounce the reply back out the same
/// interface (`XDP_TX`), so the broadcast never floods the overlay.
///
/// Only requests on a tenant port (its `IFACE_VNI != 0`) for a *known* address
/// are answered; anything else (unknown target, non-tenant port, a reply) is
/// passed through untouched, preserving normal ARP as a fallback.
#[inline(always)]
fn try_arp(ctx: &XdpContext) -> Result<u32, ()> {
    if !overlay_config().is_enabled() {
        return Ok(xdp_action::XDP_PASS);
    }
    let ifindex = ctx.ingress_ifindex() as u32;
    let vni = unsafe { IFACE_VNI.get(&ifindex) }.copied().unwrap_or(0);
    if vni == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // The 28-byte ARP payload sits right after the 14-byte Ethernet header.
    let arp: *const [u8; 28] = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let arp = unsafe { *arp };
    // oper @6, sender hw @8, sender proto @14, target proto @24 (see RFC 826).
    if u16::from_be_bytes([arp[6], arp[7]]) != ARP_REQUEST {
        return Ok(xdp_action::XDP_PASS);
    }
    let sha = [arp[8], arp[9], arp[10], arp[11], arp[12], arp[13]];
    let spa = [arp[14], arp[15], arp[16], arp[17]];
    let tpa = [arp[24], arp[25], arp[26], arp[27]];

    // Only answer addresses the controller told us about; else let it flood.
    let entry = match unsafe { ARP_TABLE.get(&ArpKey::new(vni, tpa)) } {
        Some(entry) => *entry,
        None => return Ok(xdp_action::XDP_PASS),
    };
    let reply = plan_arp_reply(sha, spa, tpa, entry.mac);

    // Rewrite the request into its reply in place, then bounce it (XDP_TX). All
    // writes go through one freshly bounds-checked pointer at constant offsets.
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + EthHdr::LEN + 28 > data_end {
        return Err(());
    }
    const O_ARP: usize = EthHdr::LEN;
    unsafe {
        *((data + O_ETH_DST) as *mut [u8; 6]) = reply.eth_dst;
        *((data + O_ETH_SRC) as *mut [u8; 6]) = reply.eth_src;
        *((data + O_ARP + 6) as *mut [u8; 2]) = (ARP_REPLY).to_be_bytes();
        *((data + O_ARP + 8) as *mut [u8; 6]) = reply.sha;
        *((data + O_ARP + 14) as *mut [u8; 4]) = reply.spa;
        *((data + O_ARP + 18) as *mut [u8; 6]) = reply.tha;
        *((data + O_ARP + 24) as *mut [u8; 4]) = reply.tpa;
    }
    bump(Counter::ArpSuppressed);
    Ok(xdp_action::XDP_TX)
}

/// B3 **IPv6 Neighbor-Discovery suppression**: the IPv6 mirror of [`try_arp`].
/// Answer a tenant's ICMPv6 Neighbor Solicitation locally from `ND_TABLE`
/// (pushed by the controller) with a synthesised Neighbor Advertisement bounced
/// back out the same interface (`XDP_TX`), so the solicitation never floods the
/// overlay.
///
/// Returns `Ok(Some(XDP_TX))` when a Neighbor Advertisement was synthesised, and
/// `Ok(None)` for anything not suppressible here (overlay off, non-tenant port,
/// not an NS, an unknown target, or too small) so the caller falls through to
/// the normal IPv6 firewall path.
///
/// **Size discipline:** the NA needs a 32-byte ICMPv6 message (24-byte NA header
/// + an 8-byte Target-Link-Layer-Address option). A solicited NS from a real
/// host always carries a Source-Link-Layer-Address option, so its ICMPv6 payload
/// is already ≥ 32 bytes — we therefore answer **in place** only when the IPv6
/// payload length is ≥ 32, overwriting that region with the 32-byte NA and never
/// growing the packet (no `bpf_xdp_adjust_tail`), which keeps the write
/// verifier-simple. A shorter NS (no SLLA option) is passed through untouched.
#[inline(always)]
fn try_nd(ctx: &XdpContext) -> Result<Option<u32>, ()> {
    if !overlay_config().is_enabled() {
        return Ok(None);
    }
    let ifindex = ctx.ingress_ifindex() as u32;
    let vni = unsafe { IFACE_VNI.get(&ifindex) }.copied().unwrap_or(0);
    if vni == 0 {
        return Ok(None);
    }

    // The fixed 40-byte IPv6 header: payload length @4..6, next-header @6, the
    // soliciting host's source address @8..24.
    let hdr: *const [u8; Ipv6Hdr::LEN] = unsafe { ptr_at(ctx, EthHdr::LEN)? };
    let hdr = unsafe { *hdr };
    if hdr[6] != ip_proto::ICMPV6 {
        return Ok(None);
    }
    // Only answer in place when the NS body (with its SLLA option) is ≥ 32 bytes,
    // so the 32-byte NA fits exactly where it was — see the size note above.
    let payload_len = u16::from_be_bytes([hdr[4], hdr[5]]);
    if (payload_len as usize) < ND_NA_MSG_LEN {
        return Ok(None);
    }
    let ns_src_ip: [u8; 16] = [
        hdr[8], hdr[9], hdr[10], hdr[11], hdr[12], hdr[13], hdr[14], hdr[15], hdr[16], hdr[17],
        hdr[18], hdr[19], hdr[20], hdr[21], hdr[22], hdr[23],
    ];

    // The ICMPv6 message begins right after the fixed IPv6 header. We need the
    // type (@0) and, for an NS, the target address (@8..24 — a 4-byte ICMPv6
    // header + 4 reserved bytes, then the 16-byte target).
    let icmp6: *const [u8; 24] = unsafe { ptr_at(ctx, EthHdr::LEN + Ipv6Hdr::LEN)? };
    let icmp6 = unsafe { *icmp6 };
    if icmp6[0] != ICMPV6_NEIGHBOR_SOLICIT {
        return Ok(None);
    }
    let target: [u8; 16] = [
        icmp6[8], icmp6[9], icmp6[10], icmp6[11], icmp6[12], icmp6[13], icmp6[14], icmp6[15],
        icmp6[16], icmp6[17], icmp6[18], icmp6[19], icmp6[20], icmp6[21], icmp6[22], icmp6[23],
    ];

    // Only answer addresses the controller told us about; else let it flood.
    let entry = match unsafe { ND_TABLE.get(&NdKey::new(vni, target)) } {
        Some(entry) => *entry,
        None => return Ok(None),
    };

    // The requester's Ethernet source becomes the NA's L2 destination.
    let eth_src: *const [u8; 6] = unsafe { ptr_at(ctx, O_ETH_SRC)? };
    let ns_src_mac = unsafe { *eth_src };
    let reply = plan_na_reply(target, entry.mac, ns_src_mac, ns_src_ip);

    // Rewrite the solicitation into its advertisement in place, then bounce it
    // (XDP_TX). All writes go through one freshly bounds-checked pointer at
    // constant offsets. `payload_len ≥ 32` guarantees the frame covers @54..86.
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + O_ND_MSG + ND_NA_MSG_LEN > data_end {
        return Err(());
    }
    unsafe {
        *((data + O_ETH_DST) as *mut [u8; 6]) = reply.eth_dst;
        *((data + O_ETH_SRC) as *mut [u8; 6]) = reply.eth_src;
        // Pin the IPv6 payload length to the 32-byte NA so a longer NS body can't
        // leave trailing bytes outside the (checksummed) advertisement.
        *((data + O_IP6_PLEN) as *mut [u8; 2]) = (ND_NA_MSG_LEN as u16).to_be_bytes();
        *((data + O_IP6_SRC) as *mut [u8; 16]) = reply.ipv6_src;
        *((data + O_IP6_DST) as *mut [u8; 16]) = reply.ipv6_dst;
        *((data + O_ND_MSG) as *mut [u8; ND_NA_MSG_LEN]) = reply.na_msg;
    }
    bump(Counter::NdSuppressed);
    Ok(Some(xdp_action::XDP_TX))
}

/// Whether this host runs **fail-closed**: an unparseable packet is dropped rather
/// than passed. Reads the single-slot [`FAIL_CLOSED`] flag; absent (the control
/// plane never wrote it) means fail-open, preserving the historical behaviour.
#[inline(always)]
fn fail_closed() -> bool {
    FAIL_CLOSED.get(0).copied().unwrap_or(0) != 0
}

/// Read this host's [`OverlayConfig`] from the single-entry array map, falling
/// back to the disabled default when the control plane has not written one.
#[inline(always)]
fn overlay_config() -> OverlayConfig {
    OVERLAY_CONFIG
        .get(0)
        .copied()
        .unwrap_or(OverlayConfig::DISABLED)
}

/// Read this host's [`Srv6Config`] out of the single-slot `SRV6_CONFIG` map,
/// falling back to the disabled default when the control plane has not written
/// one.
#[inline(always)]
fn srv6_config() -> Srv6Config {
    SRV6_CONFIG.get(0).copied().unwrap_or(Srv6Config::DISABLED)
}

/// B9 SRv6 **decapsulation** (`End.DT2U`): if the outer IPv6 destination of an
/// arriving packet is a service SID this node instantiated, strip the outer
/// Ethernet + IPv6 stack and `XDP_PASS` the inner Ethernet frame to the kernel
/// bridge (which delivers it by inner MAC).
///
/// Returns `Ok(Some(action))` when it took over the packet, or `Ok(None)` to
/// fall through (SRv6 disabled / not one of our SIDs / a non-`End.DT2U` SID / a
/// tenant ingress port).
#[inline(always)]
fn try_srv6_decap(ctx: &XdpContext, hdr: &[u8; Ipv6Hdr::LEN]) -> Result<Option<u32>, ()> {
    // Cheap gate first, reading the enabled flag *through* the map pointer so the
    // 28-byte `Srv6Config` is never copied onto this (already deep) stack frame.
    if !SRV6_CONFIG.get(0).map(|c| c.is_enabled()).unwrap_or(false) {
        return Ok(None);
    }
    // Only decapsulate on a non-tenant (underlay) ingress port: a tenant tap
    // (`vni != 0`) must never be able to forge a packet addressed to one of our
    // SIDs and have its inner frame injected past tenant isolation. (Trusted-source
    // auth against `SRV6_PEERS` — the C2 analogue of `VTEP_PEERS` — is enforced
    // below, once the packet is confirmed to be a decap candidate.)
    let ifindex = ctx.ingress_ifindex() as u32;
    if unsafe { IFACE_VNI.get(&ifindex) }.copied().unwrap_or(0) != 0 {
        return Ok(None);
    }
    // The 16-byte outer IPv6 destination is already contiguous in `hdr` at offset
    // 24; view it as the `Srv6SidKey` *in place* (both are `[u8; 16]`, align 1) so
    // the map lookup needs no on-stack key buffer at all — critical for staying
    // under the verifier's combined-stack limit when this leaf is reached from the
    // deep IPv6 firewall frame. Only the behaviour field is read back through the
    // value pointer (no `Srv6LocalSid` copy).
    // SAFETY: `hdr` is a live 40-byte array; bytes 24..40 are in bounds, and the
    // byte-array key has alignment 1 so the reinterpret is always well-aligned.
    let key = unsafe { &*(hdr.as_ptr().add(24) as *const Srv6SidKey) };
    let behavior = match unsafe { SRV6_LOCAL_SIDS.get(key) } {
        Some(l) => l.behavior,
        None => return Ok(None),
    };
    // Only the L2 unicast behaviour is decapsulated in this fast path; End.DT2M
    // (BUM flood) needs head-end replication at the TC layer and is not here.
    if behavior != velstra_common::srv6::behavior::END_DT2U {
        return Ok(None);
    }
    // Reduced End.DT2U encap carries the inner Ethernet frame directly after the
    // outer IPv6 header, flagged by IPv6 Next Header 143 (Ethernet). Refuse to decap
    // a packet to our SID whose outer next-header is anything else (an SRH, or an
    // upper-layer protocol) — stripping the fixed outer stack off such a packet
    // would hand a corrupt "inner" frame to the bridge. The next-header sits at
    // offset 6 of the already-bounds-checked 40-byte outer IPv6 header.
    if hdr[6] != velstra_common::srv6::IPPROTO_ETHERNET {
        return Ok(None);
    }
    // C2 source auth: this is now a confirmed End.DT2U decap candidate for one of
    // our SIDs. Decapsulate only when its outer IPv6 source is a trusted peer —
    // otherwise a host on the underlay could forge a frame to our SID and have its
    // inner Ethernet frame bridged into a tenant, past the firewall (the SRv6
    // analogue of the VTEP_PEERS gate on the VXLAN path). The 16-byte outer source
    // sits at offset 8 of the bounds-checked outer IPv6 header; view it in place
    // (byte array, align 1) so no key is built on this already-deep stack frame.
    // SAFETY: `hdr` is a live 40-byte array; bytes 8..24 are in bounds.
    let outer_src = unsafe { &*(hdr.as_ptr().add(8) as *const [u8; 16]) };
    if unsafe { SRV6_PEERS.get(outer_src) }.is_none() {
        bump(Counter::Srv6DropUntrusted);
        return Ok(Some(xdp_action::XDP_DROP));
    }
    // Strip outer Ethernet (14) + IPv6 (40) = SRV6_L2_OUTER_LEN. The inner frame
    // is an Ethernet frame, left for the kernel bridge to deliver by inner MAC.
    // SAFETY: `ctx.ctx` is the live `xdp_md`; a positive delta only shrinks the
    // packet. A non-zero return means the kernel refused — pass the frame as-is.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, SRV6_L2_OUTER_LEN as i32) } != 0 {
        bump(Counter::Malformed);
        return Ok(Some(xdp_action::XDP_PASS));
    }
    bump(Counter::Srv6Decap);
    Ok(Some(xdp_action::XDP_PASS))
}

/// B9 SRv6 **encapsulation** (headend, `End.DT2U`): if the inner destination MAC
/// of a tenant frame resolves to a remote service SID, prepend the outer
/// Ethernet + IPv6 stack (reduced encap — a single SID in the IPv6 destination,
/// no SRH) and redirect it onto the underlay.
///
/// Returns `Ok(Some(action))` when it took over the packet, or `Ok(None)` to
/// fall through (no SRv6 FDB entry / SRv6 disabled — treated as local).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_srv6_encap(
    ctx: &XdpContext,
    scfg: &Srv6Config,
    vni: u32,
    src_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    log: bool,
) -> Result<Option<u32>, ()> {
    // No SRv6 overlay configured, or the ingress port is not on a tenant segment.
    if !scfg.is_enabled() || vni == 0 {
        return Ok(None);
    }
    // Bridge by the inner destination MAC (End.DT2U unicast). Read it now, before
    // any `bpf_xdp_adjust_head` grows the head. A miss means local delivery or a
    // BUM frame (End.DT2M flood, handled elsewhere) — fall through unchanged.
    let inner_dst_mac = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_DST)? };
    let ep = match unsafe { SRV6_FDB.get(&MacFdbKey::new(vni, inner_dst_mac)) } {
        Some(ep) => *ep,
        None => return Ok(None),
    };

    // Entropy for the outer IPv6 flow label: hash the inner flow so the underlay
    // spreads tunnels across ECMP paths while pinning each flow to one path.
    let entropy = session_hash(src_addr, src_port, proto) ^ ((dst_port as u32) << 16);
    let inner_len = (ctx.data_end() - ctx.data()) as u16;

    // MTU guard: the outer IPv6 header adds 40 bytes; if the result would exceed
    // the underlay MTU, drop loudly rather than emit a frame the underlay silently
    // black-holes. Size the tenant MTU to `underlay_mtu - 40`.
    if inner_len > scfg.max_inner_len() {
        bump(Counter::OverlayTooBig);
        return Ok(Some(xdp_action::XDP_DROP));
    }

    let encap = build_srv6_encap(&scfg.local_src, &scfg.local_mac, &ep, inner_len, entropy);

    // Grow the head by exactly the outer stack length.
    // SAFETY: negative delta adds headroom; checked for failure below.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(SRV6_L2_OUTER_LEN as i32)) } != 0 {
        bump(Counter::Malformed);
        return Ok(Some(xdp_action::XDP_PASS));
    }

    // Write the outer headers as one fixed-size store at constant offset 0,
    // through a freshly bounds-checked pointer (the verifier-friendly pattern).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + SRV6_L2_OUTER_LEN > data_end {
        return Err(());
    }
    // SAFETY: the bounds check above proves all `SRV6_L2_OUTER_LEN` bytes from
    // `data` are within the (now larger) packet.
    unsafe {
        *(data as *mut [u8; SRV6_L2_OUTER_LEN]) = encap.headers;
    }

    bump(Counter::Srv6Encap);
    if log {
        info!(
            ctx,
            "SRV6 ENCAP vni={} -> ifindex {}", vni, encap.out_ifindex
        );
    }
    // Redirect onto the underlay; an absent devmap entry aborts (the control
    // plane mirrors every overlay egress ifindex into `TX_PORTS`).
    Ok(Some(
        TX_PORTS
            .redirect(encap.out_ifindex, 0)
            .unwrap_or(xdp_action::XDP_ABORTED),
    ))
}

/// Phase 4 **decapsulation**: validate the inner VNI, then strip the outer
/// Ethernet/IPv4/UDP/shim headers of a tunnel packet and `XDP_PASS` the inner
/// frame to the kernel stack.
///
/// The shim's 24-bit VNI is read (and enforced) BEFORE anything is stripped:
/// tenant isolation at the decap boundary requires that a peer VTEP may only
/// inject into a segment this host actually serves. VTEP authentication upstream
/// (`local_vtep_ip` + `VTEP_PEERS`) proves the outer source is a known peer, but
/// its outer IPv4 is spoofable and a trusted peer serves many tenants; without
/// this check any such sender could push an inner frame under an arbitrary VNI
/// and have the kernel bridge deliver it into whatever local segment its inner
/// MAC matched. So an inner VNI absent from [`LOCAL_VNIS`] is dropped.
///
/// `bpf_xdp_adjust_head` with a positive delta removes `delta` bytes from the
/// front of the packet. We remove exactly the outer stack — `eth + ihl + udp +
/// shim` — which for our own (option-less) encapsulation equals
/// [`OVERLAY_OUTER_LEN`].
#[inline(always)]
fn try_decap(ctx: &XdpContext, ihl_bytes: usize) -> Result<u32, ()> {
    // The VXLAN/Geneve shim follows eth + IPv4(ihl) + UDP(8); its VNI is bytes 4..7
    // (`decode_vni`). Read it through a bounds-checked pointer before any header is
    // stripped.
    let shim = unsafe { *ptr_at::<[u8; 8]>(ctx, EthHdr::LEN + ihl_bytes + 8)? };
    let vni = decode_vni(shim);
    // Admit the inner frame only into a segment this host serves. (The looked-up
    // value reserves a per-VNI bridge ifindex for a future dedicated-bridge demux;
    // today every served VNI shares the kernel bridge, so the value is unused.)
    if unsafe { LOCAL_VNIS.get(&vni) }.is_none() {
        bump(Counter::OverlayDropVni);
        return Ok(xdp_action::XDP_DROP);
    }

    let delta = (EthHdr::LEN + ihl_bytes + 8 + 8) as i32;
    // SAFETY: `ctx.ctx` is the live `xdp_md`; a positive delta only shrinks the
    // packet. A non-zero return means the kernel refused — pass the frame as-is.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, delta) } != 0 {
        bump(Counter::Malformed);
        return Ok(xdp_action::XDP_PASS);
    }
    bump(Counter::OverlayDecap);
    Ok(xdp_action::XDP_PASS)
}

/// Phase 4 **encapsulation**: if the inner destination of a tenant frame lives on
/// a remote VTEP, prepend the VXLAN/Geneve outer stack and redirect it onto the
/// underlay.
///
/// B7: a frame a tenant addressed to its **anycast gateway MAC** is *routed*
/// here rather than bridged — the inner Ethernet header is rewritten toward the
/// remote PE's Router's MAC, the TTL is decremented and the frame is
/// encapsulated with the tenant's **L3** VNI (symmetric IRB).
///
/// Returns `Ok(Some(action))` when it took over the packet (redirected, or passed
/// after a failed head-grow), or `Ok(None)` to fall through (no FDB entry / the
/// overlay is disabled — the destination is treated as local).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_encap(
    ctx: &XdpContext,
    ocfg: &OverlayConfig,
    vni: u32,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    ttl: u8,
    ip_checksum: u16,
    log: bool,
) -> Result<Option<u32>, ()> {
    // No overlay configured, or the ingress port is not on a tenant segment.
    if !ocfg.is_enabled() || vni == 0 {
        return Ok(None);
    }
    // Read the inner dst MAC now, before any `bpf_xdp_adjust_head` grows the
    // head: both the IRB gate and the MAC FDB need it, and after the head grows
    // its offset moves.
    let inner_dst_mac = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_DST)? };

    // B7 symmetric IRB, ahead of both bridging FDBs: an inner destination that
    // matches a routed prefix of this tenant **and** is addressed at L2 to the
    // tenant's anycast gateway is inter-subnet traffic. The gateway-MAC gate is
    // what keeps ordinary bridged traffic that merely happens to match a remote
    // prefix on the bridging path — without it a frame between two hosts of the
    // same segment could be routed, arriving with the wrong MACs.
    let irb = match IRB_ROUTES.get(&Key::new(
        TunnelKey::FULL_PREFIX,
        TunnelKey::new(vni, lpm_key_addr(dst_addr)),
    )) {
        Some(irb) if irb.gateway_mac == inner_dst_mac => Some(*irb),
        _ => None,
    };

    // Either route (IRB) or bridge (MAC FDB, then the L3 FDB) — and in the routed
    // case encapsulate with the tenant's L3 VNI instead of the ingress segment's.
    let (ep, encap_vni, rewrite): (TunnelEndpoint, u32, Option<IrbRewrite>) = match irb {
        Some(irb) => {
            // Routing decrements the TTL, so a packet that cannot survive the hop
            // is dropped here — before anything is rewritten or encapsulated.
            let Some(rw) = plan_irb(&irb, ttl, ip_checksum, proto) else {
                bump(Counter::ForwardTtlExceeded);
                return Ok(Some(xdp_action::XDP_DROP));
            };
            (irb.tunnel_endpoint(), irb.l3_vni, Some(rw))
        }
        None => {
            // B1: a true L2 overlay bridges by the inner destination MAC. Try the
            // MAC FDB first; on a miss fall through to the L3 (inner-IP) FDB.
            let ep = match unsafe { MAC_FDB.get(&MacFdbKey::new(vni, inner_dst_mac)) } {
                Some(ep) => *ep,
                None => {
                    // Longest-prefix match on `(vni, inner dst)`: one entry can
                    // cover a whole remote subnet. A miss means it is local.
                    let key = Key::new(
                        TunnelKey::FULL_PREFIX,
                        TunnelKey::new(vni, lpm_key_addr(dst_addr)),
                    );
                    match OVERLAY_FDB.get(&key) {
                        Some(ep) => *ep,
                        None => return Ok(None),
                    }
                }
            };
            (ep, vni, None)
        }
    };

    // Entropy for the outer UDP source port: hash the inner flow so the underlay
    // spreads tunnels across ECMP paths while pinning each flow to one path.
    let entropy = session_hash(src_addr, src_port, proto) ^ ((dst_port as u32) << 16);
    let inner_len = (ctx.data_end() - ctx.data()) as u16;

    // MTU guard: encapsulating would add the outer headers; if the result would
    // exceed the underlay MTU, drop loudly (a counter) rather than emit a frame
    // the underlay silently black-holes. Operators must size the tenant MTU to
    // `underlay_mtu - 36` (or enable jumbo frames on the underlay).
    if inner_len > ocfg.max_inner_len() {
        bump(Counter::OverlayTooBig);
        return Ok(Some(xdp_action::XDP_DROP));
    }

    let encap = build_encap(ocfg, &ep, encap_vni, inner_len, entropy);

    // Grow the head by exactly the outer stack length.
    // SAFETY: negative delta adds headroom; checked for failure below.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(OVERLAY_OUTER_LEN as i32)) } != 0 {
        bump(Counter::Malformed);
        return Ok(Some(xdp_action::XDP_PASS));
    }

    // Write the outer headers as one fixed-size store at constant offset 0,
    // through a freshly bounds-checked pointer (the verifier-friendly pattern).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + OVERLAY_OUTER_LEN > data_end {
        return Err(());
    }
    // SAFETY: the bounds check above proves all `OVERLAY_OUTER_LEN` bytes from
    // `data` are within the (now larger) packet.
    unsafe {
        *(data as *mut [u8; OVERLAY_OUTER_LEN]) = encap.headers;
    }

    // B7: apply the routed rewrite to the *inner* frame, which the head grow just
    // shifted `OVERLAY_OUTER_LEN` bytes further in — the offsets stay compile-time
    // constants, which is what the verifier needs to accept the writes. Doing it
    // here rather than before the grow means a refused grow (handled above) never
    // leaves a locally-passed frame with a half-applied rewrite.
    if let Some(rw) = rewrite {
        const I_ETH_DST: usize = OVERLAY_OUTER_LEN + O_ETH_DST;
        const I_ETH_SRC: usize = OVERLAY_OUTER_LEN + O_ETH_SRC;
        const I_IP_TTL: usize = OVERLAY_OUTER_LEN + O_IP_TTL;
        const I_IP_CSUM: usize = OVERLAY_OUTER_LEN + O_IP_CSUM;
        // Furthest byte touched is the inner IPv4 checksum at I_IP_CSUM..+2.
        if data + I_IP_CSUM + 2 > data_end {
            return Err(());
        }
        // SAFETY: the bounds check above proves every byte written below is
        // inside the packet; all four offsets are compile-time constants.
        unsafe {
            *((data + I_ETH_DST) as *mut [u8; 6]) = rw.inner_dst_mac;
            *((data + I_ETH_SRC) as *mut [u8; 6]) = rw.inner_src_mac;
            *((data + I_IP_TTL) as *mut u8) = rw.new_ttl;
            *((data + I_IP_CSUM) as *mut [u8; 2]) = rw.new_checksum.to_be_bytes();
        }
        bump(Counter::IrbRouted);
    }

    bump(Counter::OverlayEncap);
    if log {
        info!(
            ctx,
            "ENCAP vni={} -> ifindex {}", encap_vni, encap.out_ifindex
        );
    }
    // Redirect onto the underlay; an absent devmap entry aborts (the control
    // plane mirrors every overlay egress ifindex into `TX_PORTS`).
    Ok(Some(
        TX_PORTS
            .redirect(encap.out_ifindex, 0)
            .unwrap_or(xdp_action::XDP_ABORTED),
    ))
}

/// Phase 3 load balancer. Looks the packet's `(dst, dport, proto)` up in
/// [`SERVICES`], picks a backend by source hash, and DNAT-rewrites the packet in
/// place. Returns `Ok(Some(XDP_PASS))` when it rewrote the packet (the kernel
/// then routes it to the backend), or `Ok(None)` to fall through to routing.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_load_balance(
    ctx: &XdpContext,
    ihl_bytes: usize,
    policy_id: PolicyId,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    ip_checksum: u16,
    log: bool,
) -> Result<Option<u32>, ()> {
    // Only L4 protocols with ports are load balanced.
    if proto != ip_proto::TCP && proto != ip_proto::UDP {
        return Ok(None);
    }
    // The NAT fast path requires a standard 20-byte IPv4 header (no options) so
    // every L4 offset is a compile-time constant — which is what lets the eBPF
    // verifier accept the packet writes. Real XDP load balancers make the same
    // assumption; option-bearing packets simply fall through to routing.
    if ihl_bytes != Ipv4Hdr::LEN {
        return Ok(None);
    }

    // The current L4 checksum (constant offset, header is fixed at 20 bytes).
    let l4_csum_off = if proto == ip_proto::TCP {
        O_TCP_CSUM
    } else {
        O_UDP_CSUM
    };
    let old_l4 = {
        let ptr: *const [u8; 2] = unsafe { ptr_at(ctx, l4_csum_off)? };
        u16::from_be_bytes(unsafe { *ptr })
    };

    // 1. Established flow? Conntrack tells us the NAT target and direction.
    // The lookup also *accounts* the packet to the entry it hit, which is the
    // only place that can: by the time userspace reads the table the packet is
    // long gone. See `account_flow`.
    let bytes = (ctx.data_end() - ctx.data()) as u64;
    let fkey = FlowKey::new(policy_id, src_addr, dst_addr, src_port, dst_port, proto);
    let mut ct_state = account_flow(&fkey, bytes);
    // Router NAT (port-forward) records its conntrack under the policy-independent
    // namespace, since its forward and reply enter through different zones' policies
    // (see [`ROUTER_NAT_POLICY`]). Fall back to it after the tenant-scoped miss —
    // skipped when the packet is already in that namespace (the lookup above was it).
    if ct_state.is_none() && policy_id != ROUTER_NAT_POLICY {
        let gkey = FlowKey::new(
            ROUTER_NAT_POLICY,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            proto,
        );
        ct_state = account_flow(&gkey, bytes);
    }
    if let Some(state) = ct_state {
        let reverse = state.is_reverse();
        let (old_ip, old_port) = if reverse {
            (src_addr, src_port)
        } else {
            (dst_addr, dst_port)
        };
        let nat = plan_nat(
            old_ip,
            old_port,
            state.nat_ip,
            state.nat_port,
            ip_checksum,
            old_l4,
            proto,
        );
        apply_nat(ctx, &nat, reverse, proto)?;
        // Hairpin (NAT reflection): a second rewrite on the OPPOSITE address of the
        // same packet — SNAT the source on a forward flow, un-DNAT the destination
        // on the reply — chaining its checksum onto the primary rewrite's. Ordinary
        // single-NAT flows have `has_second() == false`, so the common path pays one
        // predictable branch.
        if state.has_second() {
            let (old2_ip, old2_port) = if reverse {
                (dst_addr, dst_port)
            } else {
                (src_addr, src_port)
            };
            let nat2 = plan_nat(
                old2_ip,
                old2_port,
                state.nat2_ip,
                state.nat2_port,
                nat.new_ip_checksum,
                nat.new_l4_checksum,
                proto,
            );
            apply_nat(ctx, &nat2, !reverse, proto)?;
        }
        bump(if reverse {
            Counter::LbReverse
        } else {
            Counter::LbEstablished
        });
        if log {
            info!(
                ctx,
                "NAT(ct) reverse={} -> {}.{}.{}.{}:{}",
                reverse as u8,
                nat.new_ip[0],
                nat.new_ip[1],
                nat.new_ip[2],
                nat.new_ip[3],
                nat.new_port
            );
        }
        return Ok(Some(xdp_action::XDP_PASS));
    }

    // 2. New connection to a service VIP?
    let Some(service) =
        (unsafe { SERVICES.get(ServiceKey::new(policy_id, dst_addr, dst_port, proto)) }).copied()
    else {
        return Ok(None);
    };
    if service.backend_count == 0 {
        bump(Counter::LbNoBackend);
        return Ok(None);
    }

    let hash = session_hash(src_addr, src_port, proto);
    let index = service.backend_start + select_backend(hash, service.backend_count);
    let Some(backend) = BACKENDS.get(index).copied() else {
        return Ok(None);
    };

    // Record both directions so this and the reply path stay consistent. The
    // reverse key is what a reply looks like: backend -> client.
    //
    // The two inserts can't be one atomic operation (they are two independent
    // BPF-map keys), so we order them to self-heal a partial failure (M2):
    // insert the **reverse** entry first and only create the **forward** entry —
    // which is what makes step 1 above take the established fast path — once the
    // reverse insert succeeded. If the reverse insert fails (a full LRU), the
    // forward entry is not written either, so the next packet of this flow still
    // falls through to this "new connection" branch and retries *both*. Because
    // `session_hash` is deterministic the retry picks the same backend, so the
    // pair stays consistent — the flow self-heals within a retransmit instead of
    // waiting for LRU eviction. A stray reverse entry with no forward is inert
    // (nothing sends backend -> client until a forward flow exists).
    let backend_port = if backend.port == 0 {
        dst_port
    } else {
        backend.port
    };
    // Which conntrack namespace this flow is tracked in. A router service's pool
    // answers through a different zone than the VIP was reached from, so its reply
    // arrives under another policy and would never find a policy-scoped entry; it
    // uses the policy-independent namespace port-forwards already use. A
    // multi-tenant service keeps the ingress policy, which is what stops two
    // tenants' identical 5-tuples from sharing state. See
    // [`service_flags::ROUTER_NAT`].
    let router_nat = service.is_router_nat();
    let ct_policy = if router_nat {
        ROUTER_NAT_POLICY
    } else {
        policy_id
    };
    let rkey = FlowKey::new(
        ct_policy,
        backend.ip,
        src_addr,
        backend_port,
        src_port,
        proto,
    );
    if CONNTRACK
        .insert(&rkey, &FlowState::reverse(dst_addr, dst_port), 0)
        .is_ok()
    {
        // The forward key differs from the lookup key at the top of this function
        // only in its namespace (that lookup already falls back to the router-NAT
        // one, so it finds this entry on the next packet either way).
        let mut fwd_key = fkey;
        fwd_key.policy = ct_policy;
        // The packet in hand is this flow's first, and it is a forward one — so
        // the forward entry starts at one packet rather than at zero. Without
        // this every flow's count is short by its own opening packet, which is
        // exactly the packet an operator looks for when a connection fails.
        let mut fwd_state = FlowState::forward(backend.ip, backend.port);
        fwd_state.account(bytes);
        let _ = CONNTRACK.insert(&fwd_key, &fwd_state, 0);
    }
    // Clear the backend's reply through its own zone's stateful firewall, which on
    // a deny-by-default internal zone would otherwise drop it before the rewrite
    // above is ever reached. The entry goes under the policy that reply *arrives*
    // on — supplied by the control plane, which knows which zone owns the pool's
    // segment — because "is this flow admitted" is a per-policy question, unlike
    // the direction-agnostic "what rewrite does it need" that conntrack answers.
    // `0` means the control plane could not derive it; the reply then depends on the
    // internal zone's outbound posture, which an ordinary configuration permits.
    if router_nat && service.reply_policy != 0 {
        let mut akey = rkey;
        akey.policy = service.reply_policy;
        let _ = FW_FLOWS.insert(&akey, &1u8, 0);
    }

    // DNAT this first packet to the chosen backend.
    let nat = plan_nat(
        dst_addr,
        dst_port,
        backend.ip,
        backend.port,
        ip_checksum,
        old_l4,
        proto,
    );
    apply_nat(ctx, &nat, false, proto)?;
    bump(Counter::LoadBalanced);
    if log {
        info!(
            ctx,
            "DNAT {}.{}.{}.{}:{} -> {}.{}.{}.{}:{}",
            dst_addr[0],
            dst_addr[1],
            dst_addr[2],
            dst_addr[3],
            dst_port,
            nat.new_ip[0],
            nat.new_ip[1],
            nat.new_ip[2],
            nat.new_ip[3],
            nat.new_port,
        );
    }

    Ok(Some(xdp_action::XDP_PASS))
}

/// DNAT a **new** inbound flow to its configured port-forward target. Mirrors the
/// new-connection branch of [`try_load_balance`] but for a 1:1 forward (no
/// backend pool): rewrite the destination to the internal host, and record a
/// `CONNTRACK` forward entry (so later packets DNAT) plus a reverse entry (so the
/// internal host's reply SNATs its source back to us). The reverse flow is also
/// recorded in `FW_FLOWS` so it passes a deny-by-default internal zone. Returns
/// `None` for a flow already in conntrack (handled by [`try_load_balance`]).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_port_forward(
    ctx: &XdpContext,
    ihl_bytes: usize,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    ip_checksum: u16,
    target: PortFwd,
) -> Result<Option<u32>, ()> {
    if (proto != ip_proto::TCP && proto != ip_proto::UDP) || ihl_bytes != Ipv4Hdr::LEN {
        return Ok(None);
    }
    // Hairpin (NAT reflection) guard: a reflection entry programmed under an
    // internal zone's policy carries `match_dst` = the box's public address, so it
    // must only fire for an internal client dialling the public IP — never for
    // internal-to-internal traffic to the same port. A plain WAN forward leaves
    // `match_dst` zero (the ingress policy + port already scope it).
    if target.match_dst != [0u8; 4] && dst_addr != target.match_dst {
        return Ok(None);
    }
    // When set, also SNAT the source to `snat_ip` so the internal server's reply
    // routes back through the box (else it would answer the client directly with
    // its real address and the client would drop the unexpected source).
    let hairpin = target.snat_ip != [0u8; 4];
    // Router NAT keys its conntrack under the policy-independent namespace so the
    // reply — which enters through the internal zone's (different) policy — still
    // matches. See [`ROUTER_NAT_POLICY`].
    let fkey = FlowKey::new(
        ROUTER_NAT_POLICY,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        proto,
    );
    // Already tracked? The conntrack path in try_load_balance handles it.
    if (unsafe { CONNTRACK.get(&fkey) }).is_some() {
        return Ok(None);
    }

    let l4_csum_off = if proto == ip_proto::TCP {
        O_TCP_CSUM
    } else {
        O_UDP_CSUM
    };
    let old_l4 = {
        let ptr: *const [u8; 2] = unsafe { ptr_at(ctx, l4_csum_off)? };
        u16::from_be_bytes(unsafe { *ptr })
    };
    let target_port = if target.port == 0 {
        dst_port
    } else {
        target.port
    };

    // Reverse first, then forward — a partial-failure self-heal (M2, see
    // try_load_balance): the forward entry (which makes the conntrack fast path
    // in try_load_balance fire) is only created once the reverse entry exists, so
    // a full-table failure leaves neither and the next packet retries both.
    // Reverse: the reply (internal host -> client) SNATs its source back to the
    // original destination (our public ip:port).
    // The reply's destination is the original client for a plain forward, but the
    // SNAT address for a hairpin flow (we rewrote the source to snat_ip inbound, so
    // the server answers to snat_ip, not the client).
    let reply_dst = if hairpin { target.snat_ip } else { src_addr };
    let rkey = FlowKey::new(
        ROUTER_NAT_POLICY,
        target.ip,
        reply_dst,
        target_port,
        src_port,
        proto,
    );
    // A hairpin flow tracks a dual rewrite in each direction; a plain forward keeps
    // the single-rewrite entries.
    let (fwd_state, rev_state) = if hairpin {
        (
            // Forward: DNAT dst -> server, SNAT src -> snat_ip.
            FlowState::forward2(target.ip, target.port, target.snat_ip, 0),
            // Reverse: SNAT src (server) -> public (dst_addr:dst_port), un-DNAT dst
            // (snat_ip) -> the client (src_addr, port kept).
            FlowState::reverse2(dst_addr, dst_port, src_addr, 0),
        )
    } else {
        (
            FlowState::forward(target.ip, target.port),
            FlowState::reverse(dst_addr, dst_port),
        )
    };
    if CONNTRACK.insert(&rkey, &rev_state, 0).is_ok() {
        // Forward: rewrite subsequent packets of this flow. The packet in hand is
        // this flow's first and travels forward, so the entry opens with it
        // already accounted rather than losing it.
        let mut fwd_state = fwd_state;
        fwd_state.account((ctx.data_end() - ctx.data()) as u64);
        let _ = CONNTRACK.insert(&fkey, &fwd_state, 0);
    }
    // Clear the reply through the internal zone's stateful firewall. The entry goes
    // under the policy that reply *arrives* on, not the router-NAT namespace the
    // conntrack entries use: the firewall asks a per-policy question ("is this flow
    // admitted here"), so it looks the flow up under the arriving packet's own
    // policy and cannot search a second namespace — see the comment on
    // `established` in `try_velstra`. `0` means the control plane could not derive
    // the zone owning `target.ip`; the reply then relies on the internal zone's
    // outbound posture, which an ordinary configuration permits.
    if target.reply_policy != 0 {
        let mut akey = rkey;
        akey.policy = target.reply_policy;
        let _ = FW_FLOWS.insert(&akey, &1u8, 0);
    }

    // DNAT this first packet; a hairpin flow additionally SNATs the source, its
    // checksum chained onto the DNAT's repaired checksums.
    let nat = plan_nat(
        dst_addr,
        dst_port,
        target.ip,
        target.port,
        ip_checksum,
        old_l4,
        proto,
    );
    apply_nat(ctx, &nat, false, proto)?;
    if hairpin {
        let nat2 = plan_nat(
            src_addr,
            src_port,
            target.snat_ip,
            0,
            nat.new_ip_checksum,
            nat.new_l4_checksum,
            proto,
        );
        apply_nat(ctx, &nat2, true, proto)?;
    }
    bump(Counter::LoadBalanced);
    Ok(Some(xdp_action::XDP_PASS))
}

/// Offset of the first TCP option byte, valid only for a 20-byte TCP header.
const O_TCP_OPT: usize = O_TCP_URG + 2; // 54

/// The MSS a client advertised, read at a **fixed** offset.
///
/// A SYN's options are a variable-length list, and walking one means a loop the
/// verifier has to bound and a chain of data-dependent offsets — the pattern
/// this program deliberately avoids everywhere else. It is also unnecessary:
/// every mainstream stack puts the MSS option first, immediately after the
/// twenty fixed bytes, because it is the option that must not be missed. So the
/// probe looks exactly there and nowhere else.
///
/// A SYN that puts something else first simply reads as "no MSS advertised" and
/// gets the conservative default. That is a throughput choice for an unusual
/// client, never a correctness one — which is what makes the shortcut safe.
#[inline(always)]
fn client_mss(ctx: &XdpContext) -> Option<u16> {
    let data_off = unsafe { *ptr_at::<u8>(ctx, O_TCP_OFF).ok()? };
    if (data_off >> 4) < 6 {
        return None;
    }
    let opt = unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_OPT).ok()? };
    // Kind 2 (maximum segment size), length 4.
    if opt[0] != 2 || opt[1] != 4 {
        return None;
    }
    Some(u16::from_be_bytes([opt[2], opt[3]]))
}

/// Write a synthesised TCP segment over the packet in hand.
///
/// The addresses and ports are the ones to *write*, so the caller decides
/// whether the segment faces back the way the packet came or continues onward.
/// `reflect` additionally swaps the Ethernet addresses, which is what makes an
/// `XDP_TX` land back at the sender.
///
/// The frame is never shortened: the IP total length is set to the synthesised
/// segment's, and any trailing bytes of a longer original are ignored by the
/// receiver — the same trick [`reject_packet`] uses. It *is* grown when a
/// four-byte MSS option will not fit, which is the ordinary case for a bare ACK.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn write_synth(
    ctx: &XdpContext,
    plan: TcpSynth,
    new_src: [u8; 4],
    new_dst: [u8; 4],
    new_sport: u16,
    new_dport: u16,
    reflect: bool,
) -> Result<(), ()> {
    let want_mss = plan.mss.is_some();
    // A bare ACK is 54 bytes and an MSS option needs four more. Growing the tail
    // invalidates every packet pointer, so it happens before anything is read.
    if want_mss && ctx.data() + O_TCP_OPT + 4 > ctx.data_end() {
        let grow = (O_TCP_OPT + 4).saturating_sub(ctx.data_end() - ctx.data()) as i32;
        if unsafe { bpf_xdp_adjust_tail(ctx.ctx, grow) } != 0 {
            return Err(());
        }
    }

    let (eth_dst, eth_src) = if reflect {
        (unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_DST)? }, unsafe {
            *ptr_at::<[u8; 6]>(ctx, O_ETH_SRC)?
        })
    } else {
        ([0u8; 6], [0u8; 6])
    };

    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + O_TCP_OPT + 4 > data_end {
        return Err(());
    }
    // SAFETY: the check above proves every byte through the first option word is
    // in bounds; all writes below are at constant offsets from one pointer.
    unsafe {
        if reflect {
            *((data + O_ETH_DST) as *mut [u8; 6]) = eth_src;
            *((data + O_ETH_SRC) as *mut [u8; 6]) = eth_dst;
        }
        *((data + O_IP_SRC) as *mut [u8; 4]) = new_src;
        *((data + O_IP_DST) as *mut [u8; 4]) = new_dst;
        *((data + O_IP_TOTLEN) as *mut [u8; 2]) = plan.total_len.to_be_bytes();
        *((data + O_IP_ID) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_FRAG) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_TTL) as *mut u8) = 64;
        *((data + O_IP_PROTO) as *mut u8) = ip_proto::TCP;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = plan.ip_checksum.to_be_bytes();
        *((data + O_L4_SPORT) as *mut [u8; 2]) = new_sport.to_be_bytes();
        *((data + O_L4_DPORT) as *mut [u8; 2]) = new_dport.to_be_bytes();
        *((data + O_TCP_SEQ) as *mut [u8; 4]) = plan.seq.to_be_bytes();
        *((data + O_TCP_ACK) as *mut [u8; 4]) = plan.ack.to_be_bytes();
        *((data + O_TCP_OFF) as *mut u8) = plan.data_offset << 4;
        *((data + O_TCP_FLAGS) as *mut u8) = plan.flags;
        *((data + O_TCP_WIN) as *mut [u8; 2]) = plan.window.to_be_bytes();
        *((data + O_TCP_CSUM) as *mut [u8; 2]) = plan.tcp_checksum.to_be_bytes();
        *((data + O_TCP_URG) as *mut [u8; 2]) = [0, 0];
        // The option area is written whether or not it is used: leaving a
        // stale four bytes there would be read as an option by the receiver
        // when `data_offset` says six, and as padding when it says five.
        let opt: [u8; 4] = match plan.mss {
            Some(m) => [2, 4, (m >> 8) as u8, m as u8],
            None => [0; 4],
        };
        *((data + O_TCP_OPT) as *mut [u8; 4]) = opt;
    }
    Ok(())
}

/// Rewrite a 32-bit TCP header field (sequence or acknowledgement) and repair
/// the segment's checksum, both at constant offsets.
#[inline(always)]
fn write_tcp_u32(ctx: &XdpContext, offset: usize, old: u32, new: u32) -> Result<(), ()> {
    if old == new {
        return Ok(());
    }
    let check = u16::from_be_bytes(unsafe { *ptr_at::<[u8; 2]>(ctx, O_TCP_CSUM)? });
    let repaired = csum_replace_u32(check, old, new);
    let data = ctx.data();
    if data + O_TCP_URG + 2 > ctx.data_end() {
        return Err(());
    }
    // SAFETY: bounds proved above; both offsets are constants inside the header.
    unsafe {
        *((data + offset) as *mut [u8; 4]) = new.to_be_bytes();
        *((data + O_TCP_CSUM) as *mut [u8; 2]) = repaired.to_be_bytes();
    }
    Ok(())
}

/// C15 **SYN proxy**. Returns `Ok(Some(action))` when the segment was handled
/// here, or `Ok(None)` to continue through the ordinary forwarding path — the
/// latter possibly after having rewritten the segment.
///
/// Both directions of a proxied connection pass through here, distinguished by
/// which end of the packet carries the protected port. Everything else is
/// untouched: a port with no proxy configured costs one failed hash lookup.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_synproxy(
    ctx: &XdpContext,
    ihl_bytes: usize,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
) -> Result<Option<u32>, ()> {
    // Only TCP over a plain 20-byte IPv4 header: every offset below is a
    // compile-time constant, which is what the verifier accepts.
    if proto != ip_proto::TCP || ihl_bytes != Ipv4Hdr::LEN {
        return Ok(None);
    }
    let Some(secret) = syn_secret() else {
        return Ok(None);
    };

    // The two directions are resolved one after the other, never together, and
    // each result is copied out of the map before the next lookup happens. Two
    // live lookups of the *same* map across a merge point is precisely what LLVM
    // folds into a bitwise-OR on a map-value pointer — which the verifier
    // rejects outright (`R7 pointer |= pointer prohibited`). The same trap is
    // documented on `port_forward_exists`, and the same discipline answers it.
    if let Some(cfg) = synproxy_cfg(dst_port) {
        let flags = unsafe { *ptr_at::<u8>(ctx, O_TCP_FLAGS)? };
        let seq = u32::from_be_bytes(unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_SEQ)? });
        let ack = u32::from_be_bytes(unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_ACK)? });
        return synproxy_client(
            ctx, secret, cfg, src_addr, dst_addr, src_port, dst_port, flags, seq, ack,
        );
    }
    if !synproxy_protects(src_port) {
        return Ok(None);
    }
    let flags = unsafe { *ptr_at::<u8>(ctx, O_TCP_FLAGS)? };
    let seq = u32::from_be_bytes(unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_SEQ)? });
    synproxy_server(ctx, src_addr, dst_addr, src_port, dst_port, flags, seq)
}

/// The proxy configured for a port, copied out of the map immediately.
#[inline(always)]
fn synproxy_cfg(port: u16) -> Option<SynProxyCfg> {
    unsafe { SYNPROXY.get(&SynProxyKey::tcp(port)) }.copied()
}

/// Whether a port is proxied at all — a plain bool from the lookup
/// discriminant, so no map-value pointer outlives the call. See the note in
/// [`try_synproxy`] for why that matters.
#[inline(always)]
fn synproxy_protects(port: u16) -> bool {
    unsafe { SYNPROXY.get(&SynProxyKey::tcp(port)) }.is_some()
}

/// The client-facing half: answer a SYN with a cookie, admit an ACK that
/// returns a valid one, and translate the acknowledgements of an admitted
/// connection into the server's sequence space.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn synproxy_client(
    ctx: &XdpContext,
    secret: [u64; 2],
    cfg: SynProxyCfg,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
    ack: u32,
) -> Result<Option<u32>, ()> {
    let epoch = epoch_of(unsafe { bpf_ktime_get_ns() });

    // A bare SYN is answered, never forwarded, and costs no state at all. This
    // is the entire defence: a flood of these buys the attacker one reply each.
    if flags & tcp_flags::SYN != 0 && flags & tcp_flags::ACK == 0 {
        let advertised = client_mss(ctx).unwrap_or(cfg.mss);
        let cookie = make_cookie(
            secret, src_addr, dst_addr, src_port, dst_port, epoch, advertised,
        );
        let plan = plan_syn_ack(src_addr, dst_addr, src_port, dst_port, seq, cookie, cfg.mss);
        write_synth(ctx, plan, dst_addr, src_addr, dst_port, src_port, true)?;
        bump(Counter::SynproxyChallenged);
        return Ok(Some(xdp_action::XDP_TX));
    }

    let key = syn_flow_key(src_addr, src_port, dst_port);
    if let Some(flow) = unsafe { SYN_FLOWS.get(&key) }.copied() {
        if !flow.is_spliced() {
            // The server has not answered yet, so there is no sequence space to
            // translate into. Dropping is right: TCP retransmits, and by then
            // the splice is done. Forwarding untranslated would corrupt it.
            return Ok(Some(xdp_action::XDP_DROP));
        }
        let translated = translate_to_server(ack, flow.delta);
        write_tcp_u32(ctx, O_TCP_ACK, ack, translated)?;
        return Ok(None);
    }

    // No state: this must be the ACK that completes the handshake we faked.
    if flags & tcp_flags::ACK == 0 || flags & tcp_flags::SYN != 0 {
        bump(Counter::SynproxyRejected);
        return Ok(Some(xdp_action::XDP_DROP));
    }
    let cookie = ack.wrapping_sub(1);
    let Some(mss) = check_cookie(
        secret, src_addr, dst_addr, src_port, dst_port, epoch, cookie,
    ) else {
        bump(Counter::SynproxyRejected);
        return Ok(Some(xdp_action::XDP_DROP));
    };

    // The client is real. Open the connection to the server by turning this very
    // ACK into the SYN it stands for — carrying the client's own initial
    // sequence number, so only the server's direction ever needs translating.
    let client_isn = seq.wrapping_sub(1);
    let _ = SYN_FLOWS.insert(&key, &SynFlow::pending(cookie, client_isn), 0);
    let plan = plan_server_syn(src_addr, dst_addr, src_port, dst_port, client_isn, mss);
    write_synth(ctx, plan, src_addr, dst_addr, src_port, dst_port, false)?;
    bump(Counter::SynproxyAdmitted);
    // Fall through: the ordinary path forwards this SYN, applying whatever
    // destination NAT and routing the configuration calls for.
    Ok(None)
}

/// The server-facing half: complete the handshake the server thinks it is
/// having, and translate its sequence numbers back into the space the client
/// was promised.
#[inline(always)]
fn synproxy_server(
    ctx: &XdpContext,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
) -> Result<Option<u32>, ()> {
    // Here the client is the packet's *destination*.
    let key = syn_flow_key(dst_addr, dst_port, src_port);
    let Some(mut flow) = unsafe { SYN_FLOWS.get(&key) }.copied() else {
        return Ok(None);
    };

    if flags & tcp_flags::SYN != 0 && flags & tcp_flags::ACK != 0 {
        // The server chose its own initial sequence number; record how far it
        // sits from the cookie the client was given, and finish the handshake
        // on the client's behalf. The SYN-ACK itself goes no further — the
        // client was answered long ago.
        if !flow.is_spliced() {
            flow.splice(seq);
            let _ = SYN_FLOWS.insert(&key, &flow, 0);
            bump(Counter::SynproxySpliced);
        }
        let plan = plan_server_ack(src_addr, dst_addr, src_port, dst_port, seq, flow.client_isn);
        write_synth(ctx, plan, dst_addr, src_addr, dst_port, src_port, true)?;
        return Ok(Some(xdp_action::XDP_TX));
    }

    if flow.is_spliced() {
        let translated = translate_to_client(seq, flow.delta);
        write_tcp_u32(ctx, O_TCP_SEQ, seq, translated)?;
    }
    Ok(None)
}

/// Phase 3 **reject**: actively refuse a packet. For a TCP segment, rewrite the
/// frame in place into a RST aimed back at the sender and `XDP_TX` it, so the
/// peer gets an immediate "connection refused" instead of a timeout. Non-TCP (or
/// option-bearing) packets drop instead — an ICMP destination-unreachable
/// response is a follow-up. A packet that is itself a RST is dropped without
/// reply, to avoid two rejecting firewalls trading RSTs forever.
///
/// The RST's sequence/ack/flags and checksums come from the pure, unit-tested
/// [`plan_tcp_rst`]; this only swaps the L2/L3/L4 endpoints and writes the
/// computed fields at constant offsets through one freshly bounds-checked
/// pointer. The IP total length is set to 40, so any trailing bytes of a longer
/// original segment are ignored by the receiver (no tail trim needed).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn reject_packet(
    ctx: &XdpContext,
    ihl_bytes: usize,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto: u8,
) -> Result<u32, ()> {
    // Reject needs a standard 20-byte IPv4 header (no options) to rewrite.
    if ihl_bytes != Ipv4Hdr::LEN {
        bump(Counter::Rejected);
        return Ok(xdp_action::XDP_DROP);
    }
    // Non-TCP is answered with an ICMP port-unreachable (UDP only; ICMP and other
    // protocols drop, to avoid ICMP-error-to-error loops and amplification).
    if proto != ip_proto::TCP {
        return reject_icmp_unreachable(ctx, src_addr, dst_addr, proto);
    }

    // Read the incoming TCP fields + IP total length (each bounds-checked).
    let in_seq = u32::from_be_bytes(unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_SEQ)? });
    let in_ack = u32::from_be_bytes(unsafe { *ptr_at::<[u8; 4]>(ctx, O_TCP_ACK)? });
    let data_off = unsafe { *ptr_at::<u8>(ctx, O_TCP_OFF)? };
    let in_flags = unsafe { *ptr_at::<u8>(ctx, O_TCP_FLAGS)? };
    let total_len = u16::from_be_bytes(unsafe { *ptr_at::<[u8; 2]>(ctx, O_IP_TOTLEN)? });

    // Never answer a RST with a RST.
    if in_flags & tcp_flags::RST != 0 {
        bump(Counter::Rejected);
        return Ok(xdp_action::XDP_DROP);
    }

    // Sequence space the sender consumed: payload + 1 per SYN/FIN.
    let tcp_hdr_len = ((data_off >> 4) as u16) * 4;
    let payload_len = total_len.saturating_sub(Ipv4Hdr::LEN as u16 + tcp_hdr_len) as u32;
    let syn = (in_flags & tcp_flags::SYN != 0) as u32;
    let fin = (in_flags & tcp_flags::FIN != 0) as u32;
    let seg_len = payload_len + syn + fin;

    let rst = plan_tcp_rst(
        src_addr, dst_addr, src_port, dst_port, in_seq, in_ack, in_flags, seg_len,
    );

    // The original MACs, to swap them on the response.
    let eth_dst = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_DST)? };
    let eth_src = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_SRC)? };

    // Rewrite the frame in place into the RST, through one freshly bounds-checked
    // pointer at constant offsets (the verifier-friendly packet-write pattern).
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + O_TCP_URG + 2 > data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    // SAFETY: the check above proves all bytes through the TCP urgent pointer
    // (offset 54) are in-bounds; every write below is at a constant offset.
    unsafe {
        // Ethernet: swap source/destination.
        *((data + O_ETH_DST) as *mut [u8; 6]) = eth_src;
        *((data + O_ETH_SRC) as *mut [u8; 6]) = eth_dst;
        // IPv4: swap addresses, fix length/ttl/proto/checksum, clear id+frag.
        *((data + O_IP_SRC) as *mut [u8; 4]) = dst_addr;
        *((data + O_IP_DST) as *mut [u8; 4]) = src_addr;
        *((data + O_IP_TOTLEN) as *mut [u8; 2]) = 40u16.to_be_bytes();
        *((data + O_IP_ID) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_FRAG) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_TTL) as *mut u8) = 64;
        *((data + O_IP_PROTO) as *mut u8) = ip_proto::TCP;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = rst.ip_checksum.to_be_bytes();
        // TCP: swap ports, new seq/ack/flags, zero window/urgent, data offset 5.
        *((data + O_L4_SPORT) as *mut [u8; 2]) = dst_port.to_be_bytes();
        *((data + O_L4_DPORT) as *mut [u8; 2]) = src_port.to_be_bytes();
        *((data + O_TCP_SEQ) as *mut [u8; 4]) = rst.seq.to_be_bytes();
        *((data + O_TCP_ACK) as *mut [u8; 4]) = rst.ack.to_be_bytes();
        *((data + O_TCP_OFF) as *mut u8) = 5 << 4;
        *((data + O_TCP_FLAGS) as *mut u8) = rst.flags;
        *((data + O_TCP_WIN) as *mut [u8; 2]) = [0, 0];
        *((data + O_TCP_CSUM) as *mut [u8; 2]) = rst.tcp_checksum.to_be_bytes();
        *((data + O_TCP_URG) as *mut [u8; 2]) = [0, 0];
    }
    bump(Counter::Rejected);
    Ok(xdp_action::XDP_TX)
}

/// Answer a rejected **UDP** packet with an ICMP destination-unreachable /
/// port-unreachable (type 3, code 3), reflected back out the ingress interface.
///
/// The response embeds the offending packet's IP header + first 8 bytes in the
/// ICMP body. We grow the frame by [`ICMP_UNREACH_PREPEND`] (= new IP header 20 +
/// ICMP header 8) bytes at the head: that shifts the offending packet forward by
/// exactly 28 bytes, so its IP header lands at offset 42 — precisely the ICMP body
/// position — and we only have to write the fresh Ethernet + IP + ICMP headers
/// over the first 42 bytes, never touching the embedded body. Non-UDP protocols
/// (including ICMP, to avoid error-to-error loops) drop.
#[inline(always)]
fn reject_icmp_unreachable(
    ctx: &XdpContext,
    src_addr: [u8; 4],
    dst_addr: [u8; 4],
    proto: u8,
) -> Result<u32, ()> {
    if proto != ip_proto::UDP {
        bump(Counter::Rejected);
        return Ok(xdp_action::XDP_DROP);
    }

    // The original MACs, read before we grow/overwrite the head.
    let eth_dst = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_DST)? };
    let eth_src = unsafe { *ptr_at::<[u8; 6]>(ctx, O_ETH_SRC)? };
    let plan = plan_icmp_unreachable(src_addr, dst_addr);
    let (new_src, new_dst) = (dst_addr, src_addr);

    // Grow the head by IP(20)+ICMP(8). Negative delta adds headroom; a non-zero
    // return means the kernel refused (no headroom) — drop rather than send junk.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(ICMP_UNREACH_PREPEND as i32)) } != 0 {
        bump(Counter::Malformed);
        return Ok(xdp_action::XDP_DROP);
    }

    // Full response: eth(14) + IP(20) + ICMP(8) + embedded(28) = 70 bytes. One
    // bounds check, then every write is at a constant offset through `data`.
    let data = ctx.data();
    let data_end = ctx.data_end();
    if data + O_L4 + 36 > data_end {
        return Ok(xdp_action::XDP_DROP);
    }
    // SAFETY: the check proves all 70 bytes from `data` are in-bounds; the writes
    // below stop at offset 42 and never disturb the embedded body at [42..70].
    unsafe {
        // Ethernet [0..14]: swap the original MACs; IPv4 ethertype.
        *((data + O_ETH_DST) as *mut [u8; 6]) = eth_src;
        *((data + O_ETH_SRC) as *mut [u8; 6]) = eth_dst;
        *((data + O_IP - 2) as *mut [u8; 2]) = ETHERTYPE_IPV4.to_be_bytes();
        // IPv4 [14..34]: version/IHL, zeroed DSCP/len/id/frag, TTL, ICMP, csum,
        // swapped addresses.
        *((data + O_IP) as *mut u8) = 0x45;
        *((data + O_IP + 1) as *mut u8) = 0;
        *((data + O_IP_TOTLEN) as *mut [u8; 2]) = ICMP_UNREACH_TOTAL_LEN.to_be_bytes();
        *((data + O_IP_ID) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_FRAG) as *mut [u8; 2]) = [0, 0];
        *((data + O_IP_TTL) as *mut u8) = 64;
        *((data + O_IP_PROTO) as *mut u8) = ip_proto::ICMP;
        *((data + O_IP_CSUM) as *mut [u8; 2]) = plan.ip_checksum.to_be_bytes();
        *((data + O_IP_SRC) as *mut [u8; 4]) = new_src;
        *((data + O_IP_DST) as *mut [u8; 4]) = new_dst;
        // ICMP [34..42]: type, code, checksum placeholder, unused.
        *((data + O_L4) as *mut u8) = icmp::DEST_UNREACHABLE;
        *((data + O_L4 + 1) as *mut u8) = icmp::PORT_UNREACHABLE;
        *((data + O_L4 + 2) as *mut [u8; 2]) = [0, 0];
        *((data + O_L4 + 4) as *mut [u8; 4]) = [0, 0, 0, 0];
    }
    // ICMP checksum over its 8-byte header + the 28-byte embedded body [34..70].
    // SAFETY: [34..70] is within the 70 bytes proven in-bounds above.
    let message = unsafe { *((data + O_L4) as *const [u8; 36]) };
    let csum = icmp_checksum(&message);
    // SAFETY: the checksum field [36..38] is within the same proven bounds.
    unsafe {
        *((data + O_L4 + 2) as *mut [u8; 2]) = csum.to_be_bytes();
    }

    bump(Counter::Rejected);
    Ok(xdp_action::XDP_TX)
}

/// Apply a [`Rewrite`] to the packet in place and redirect it out of the target
/// interface. Writes go through one freshly bounds-checked `data` pointer at
/// constant offsets (the verifier-friendly packet-write pattern).
#[inline(always)]
fn forward(ctx: &XdpContext, rewrite: Rewrite, log: bool) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    unsafe {
        if let Some(new_ttl) = rewrite.new_ttl {
            // Router mode: rewrite L2 addresses + IPv4 TTL + header checksum.
            // Furthest byte touched is the IPv4 checksum at O_IP_CSUM..+2.
            if data + O_IP_CSUM + 2 > data_end {
                return Err(());
            }
            *((data + O_ETH_DST) as *mut [u8; 6]) = rewrite.dst_mac;
            *((data + O_ETH_SRC) as *mut [u8; 6]) = rewrite.src_mac;
            *((data + O_IP_TTL) as *mut u8) = new_ttl;
            *((data + O_IP_CSUM) as *mut [u8; 2]) = rewrite.new_checksum.to_be_bytes();
        } else {
            // Switch mode: rewrite the L2 addresses only (bytes 0..12).
            if data + O_ETH_SRC + 6 > data_end {
                return Err(());
            }
            *((data + O_ETH_DST) as *mut [u8; 6]) = rewrite.dst_mac;
            *((data + O_ETH_SRC) as *mut [u8; 6]) = rewrite.src_mac;
        }
    }

    bump(Counter::Forwarded);
    if log {
        info!(ctx, "FWD -> ifindex {}", rewrite.out_ifindex);
    }
    // `redirect` returns `XDP_REDIRECT` on success; if the devmap has no entry
    // for this ifindex we abort (the control plane always mirrors live routes).
    Ok(TX_PORTS
        .redirect(rewrite.out_ifindex, 0)
        .unwrap_or(xdp_action::XDP_ABORTED))
}

/// Look up the packed `PORT_RULES` value for `(policy, proto, dst_port)` and the
/// packet's `src` address ([`lpm_key_addr`] form). The trie matches the fixed
/// `(policy, proto, dport)` head exactly and the source longest-prefix, so a rule
/// with a specific source outranks a `from any` rule on the same port; pass `src`
/// as `0` to match only source-less (`/0`) rules. Decode with `port_rule_action`
/// (low byte), `port_rule_logs` (bit 8) and `port_rule_bits`.
///
/// Returns `0` — not `Option` — for a miss, which `port_rule_present` distinguishes
/// from a real all-zero rule. A plain scalar is what makes it safe to consult this
/// **and** [`lookup_dst_rule`] for the same packet: two `Option`s carried from two
/// map lookups to a merge point let LLVM fold their map-value pointers into one
/// and null-check once, which the verifier rejects (see [`lookup_port_forward`]).
#[inline(always)]
fn lookup_port_rule(policy_id: PolicyId, proto: u8, icmp_type: u8, dst_port: u16, src: u32) -> u32 {
    match PORT_RULES.get(Key::new(
        ScopedSrcPortKey::FULL_PREFIX,
        if icmp_type == 0 {
            ScopedSrcPortKey::new(policy_id, proto, dst_port, src)
        } else {
            ScopedSrcPortKey::with_icmp_type(policy_id, proto, icmp_type, src)
        },
    )) {
        Some(value) => *value,
        None => 0,
    }
}

/// Scratch slots for the IPv6 rule keys.
///
/// A `Key<ScopedSrcPortKey6>` is 28 bytes, and two of them on the stack push the
/// IPv6 path's frame past what the verifier will accept once the bpf-to-bpf call
/// chain is summed:
///
///   combined stack size of 2 calls is 592. Too large
///   stack depth 480+32+0+0+0+112+40
///
/// The v4 keys are 16 bytes and fit; the v6 ones do not. Building them in a
/// per-CPU map instead takes them off the stack entirely — the same escape
/// hatch `FIB_SCRATCH` uses, and the reason `get` taking `impl Borrow<Key<K>>`
/// matters here.
#[map]
static RULE6_SRC_SCRATCH: PerCpuArray<Key<ScopedSrcPortKey6>> = PerCpuArray::with_max_entries(1, 0);

#[map]
static RULE6_DST_SCRATCH: PerCpuArray<Key<ScopedDstPortKey6>> = PerCpuArray::with_max_entries(1, 0);

/// The IPv6 counterpart of [`lookup_port_rule`]. `0` for a miss, for the same
/// reason: two `Option`s carried to one merge point let LLVM fold their map-value
/// pointers together, which the verifier rejects.
#[inline(always)]
fn lookup_port_rule6(
    policy_id: PolicyId,
    proto: u8,
    icmp_type: u8,
    dst_port: u16,
    hdr: &[u8; 40],
) -> u32 {
    let Some(slot) = RULE6_SRC_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: `get_ptr_mut` gave us this CPU's own slot for the duration of the
    // program run; it is written in full before it is read.
    let key = unsafe { &mut *slot };
    key.prefix_len = ScopedSrcPortKey6::FULL_PREFIX;
    key.data.policy_id = policy_id;
    key.data.proto = proto;
    key.data.icmp_type = icmp_type;
    key.data.port = dst_port;
    key.data.src.copy_from_slice(&hdr[8..24]);
    match PORT_RULES6.get(&*key) {
        Some(value) => *value,
        None => 0,
    }
}

/// The IPv6 counterpart of [`lookup_dst_rule`].
///
/// Takes the fixed header rather than an address: materialising the destination
/// as a `[u8; 16]` local costs 16 bytes of the caller's frame, and on this path
/// that is the difference between a program the verifier loads and one it does
/// not. Copied straight from the header into the map slot instead.
#[inline(always)]
fn lookup_dst_rule6(
    policy_id: PolicyId,
    proto: u8,
    icmp_type: u8,
    dst_port: u16,
    hdr: &[u8; 40],
) -> u32 {
    let Some(slot) = RULE6_DST_SCRATCH.get_ptr_mut(0) else {
        return 0;
    };
    // SAFETY: as above.
    let key = unsafe { &mut *slot };
    key.prefix_len = ScopedDstPortKey6::FULL_PREFIX;
    key.data.policy_id = policy_id;
    key.data.proto = proto;
    key.data.icmp_type = icmp_type;
    key.data.port = dst_port;
    key.data.dst.copy_from_slice(&hdr[24..40]);
    match DST_RULES6.get(&*key) {
        Some(value) => *value,
        None => 0,
    }
}

/// The furthest into the options the MSS is looked for. TCP allows 40 bytes of
/// options; every sender in practice puts the MSS first, and a bound is what the
/// verifier requires in any case.
const MAX_TCP_OPTS: usize = 10;

/// Clamp the MSS a departing SYN advertises, if this interface has a limit.
///
/// Only a SYN carries the option, and only the first IPv4 fragment carries the
/// TCP header at all. `ihl` is required to be 20 for the same reason the NAT path
/// requires it — the offsets below are computed from a fixed header, and an IPv4
/// option would move everything. Packets with IP options keep their MSS; they are
/// vanishingly rare and silently rewriting the wrong bytes would be worse.
///
/// Written with `bpf_skb_store_bytes` rather than a pointer, so the variable
/// option offset never becomes a packet-pointer the verifier has to bound, and
/// the checksum is fixed with `bpf_l4_csum_replace` from the two values.
#[inline(always)]
fn clamp_mss_egress(ctx: &TcContext, ihl_bytes: usize, proto: u8, ifindex: u32) {
    if proto != ip_proto::TCP || ihl_bytes != Ipv4Hdr::LEN {
        return;
    }
    let Some(limit) = (unsafe { MSS_CLAMP.get(&ifindex) }).copied() else {
        return;
    };
    // Byte 13 of the TCP header holds the flags; byte 12's top nibble is the data
    // offset in 32-bit words, which is where the options end.
    let Ok(head) = (unsafe { ptr_at_tc::<[u8; 2]>(ctx, O_L4 + 12) }) else {
        return;
    };
    let head = unsafe { *head };
    const TCP_SYN: u8 = 0x02;
    if head[1] & TCP_SYN == 0 {
        return;
    }
    let doff = (head[0] >> 4) as usize * 4;
    if doff <= Ipv4Hdr::LEN {
        return; // no options at all
    }
    let opts_end = O_L4 + doff;
    let mut off = O_L4 + 20;
    for _ in 0..MAX_TCP_OPTS {
        if off + 1 > opts_end {
            return;
        }
        let Ok(kind) = (unsafe { ptr_at_tc::<u8>(ctx, off) }) else {
            return;
        };
        match unsafe { *kind } {
            // End of option list.
            0 => return,
            // A single-byte no-op pad; step one and keep looking.
            1 => {
                off += 1;
                continue;
            }
            // Maximum Segment Size: kind 2, length 4, then the value.
            2 => {
                let Ok(opt) = (unsafe { ptr_at_tc::<[u8; 4]>(ctx, off) }) else {
                    return;
                };
                let opt = unsafe { *opt };
                if opt[1] != 4 {
                    return;
                }
                let current = u16::from_be_bytes([opt[2], opt[3]]);
                // Only ever downward. A clamp that raised the MSS would be
                // advertising room the path does not have.
                if current <= limit {
                    return;
                }
                if ctx.store(off + 2, &limit.to_be_bytes(), 0).is_err() {
                    return;
                }
                // The option is part of the TCP payload for checksum purposes,
                // so this is an L4 replace with the old and new values as
                // native-endian integers — the same shape the NAT path uses.
                let _ = ctx.l4_csum_replace(O_L4 + 16, current as u64, limit as u64, 2);
                bump(Counter::MssClamped);
                return;
            }
            _ => {
                // Every other option is length-prefixed. A length below two would
                // not advance, and a walk that does not advance is a loop the
                // verifier is right to refuse.
                let Ok(len) = (unsafe { ptr_at_tc::<u8>(ctx, off + 1) }) else {
                    return;
                };
                let len = unsafe { *len } as usize;
                if len < 2 {
                    return;
                }
                off += len;
            }
        }
    }
}

/// The winning rule for a packet, asking the typed tries first.
///
/// ICMP carries a type where TCP carries ports, and a rule may name one. A typed
/// rule is a different entry in the same trie — the type lives in the byte that
/// used to be padding — so finding it needs its own lookup, and a plain `icmp`
/// rule still has to be found when no typed one matches. Hence twice, and only
/// on the ICMP path: `icmp_type` is `0` for everything else, and the first
/// lookup pair is then skipped entirely.
///
/// Returns a plain `u32` rather than an `Option` for the reason
/// [`lookup_port_rule`] gives: two map-value pointers reaching one merge point
/// is what the verifier refuses.
#[inline(always)]
fn rule_winner_v4(
    policy_id: PolicyId,
    proto: u8,
    icmp_type: u8,
    dst_port: u16,
    src: u32,
    dst: u32,
    exclude: u32,
) -> u32 {
    if icmp_type != 0 {
        let typed = port_rule_winner(
            lookup_port_rule(policy_id, proto, icmp_type, 0, src),
            lookup_dst_rule(policy_id, proto, icmp_type, 0, dst),
        );
        if port_rule_present(typed) && !port_rule_excluded(typed, exclude) {
            return typed;
        }
    }
    let found = port_rule_winner(
        lookup_port_rule(policy_id, proto, 0, dst_port, src),
        lookup_dst_rule(policy_id, proto, 0, dst_port, dst),
    );
    // A rule scoped to the other family or the other direction is not a match
    // here. Zero is what "no rule" already means, so nothing downstream changes.
    if port_rule_excluded(found, exclude) {
        0
    } else {
        found
    }
}

/// The IPv6 counterpart of [`rule_winner_v4`].
#[inline(always)]
fn rule_winner_v6(
    policy_id: PolicyId,
    proto: u8,
    icmp_type: u8,
    dst_port: u16,
    hdr: &[u8; 40],
    exclude: u32,
) -> u32 {
    if icmp_type != 0 {
        let typed = port_rule_winner(
            lookup_port_rule6(policy_id, proto, icmp_type, 0, hdr),
            lookup_dst_rule6(policy_id, proto, icmp_type, 0, hdr),
        );
        if port_rule_present(typed) && !port_rule_excluded(typed, exclude) {
            return typed;
        }
    }
    let found = port_rule_winner(
        lookup_port_rule6(policy_id, proto, 0, dst_port, hdr),
        lookup_dst_rule6(policy_id, proto, 0, dst_port, hdr),
    );
    if port_rule_excluded(found, exclude) {
        0
    } else {
        found
    }
}

/// Spend one token from the rule's rate bucket, returning whether the packet may
/// proceed. `slot` is the 1-based index from the rule's packed value; `0` (no
/// limit) must not reach here.
///
/// All the arithmetic lives in [`RateBucket::take`], which is unit-tested on the
/// host — this only turns the map slot into a `&mut` and reads the clock. A slot
/// the control plane never programmed reads as all-zero, whose `rate == 0` allows,
/// so a half-applied config cannot black-hole traffic.
#[inline(always)]
fn rate_limits_allow(slot: u32) -> bool {
    let Some(ptr) = RULE_LIMITS.get_ptr_mut(slot) else {
        return true;
    };
    // SAFETY: `get_ptr_mut` returned a valid, exclusive pointer to this array
    // slot's value for the duration of this program run. The bucket is shared
    // across CPUs and updated without synchronisation: two packets racing may
    // each spend the same token, which costs a small overshoot of the configured
    // rate and never an under-count. A per-CPU map would remove the race at the
    // price of multiplying every limit by the core count — i.e. a limit that
    // silently means something else on every machine.
    let bucket = unsafe { &mut *ptr };
    let now = unsafe { bpf_ktime_get_ns() };
    bucket.take(now)
}

/// The destination-address counterpart of [`lookup_port_rule`]: the packed
/// `DST_RULES` value for `(policy, proto, dst_port)` and the packet's `dst`
/// address. Pass `dst` as `0` on a non-IPv4 packet to match only rules with no
/// destination constraint. `0` for a miss, for the reason given above.
#[inline(always)]
fn lookup_dst_rule(policy_id: PolicyId, proto: u8, icmp_type: u8, dst_port: u16, dst: u32) -> u32 {
    match DST_RULES.get(Key::new(
        ScopedDstPortKey::FULL_PREFIX,
        if icmp_type == 0 {
            ScopedDstPortKey::new(policy_id, proto, dst_port, dst)
        } else {
            ScopedDstPortKey::with_icmp_type(policy_id, proto, icmp_type, dst)
        },
    )) {
        Some(value) => *value,
        None => 0,
    }
}

/// The DNAT target for an inbound `(policy, proto, dport)`, if a port-forward is
/// configured for it. SAFETY as in [`lookup_port_rule`] — copied out at once.
///
/// The explicit `match ... Some(v) => Some(*v)` (instead of `.copied()`) forces
/// the map value to be loaded out of `PORT_FORWARDS` into an owned `PortFwd`
/// here, so the raw `Option<&PortFwd>` map-value pointer dies at this `match`.
/// The caller (`try_velstra`) must then *immediately* collapse the returned
/// `Option<PortFwd>` into plain scalars (`unwrap_or` + a `bool`) rather than
/// carrying the `Option` across its long live range — see the note there. That
/// combination stops LLVM, under the register pressure `try_velstra` carries
/// after the added `MAC_FDB`/`LOCAL_MACS` map work, from keeping the pointer
/// niche live and lowering the `Option<&PortFwd>` -> `Option<PortFwd>` niche
/// transition to a bitwise-OR on the map-value pointer, which the kernel
/// verifier rejects ("R1 bitwise operator |= on pointer prohibited"). This must
/// stay `#[inline(always)]`: a separate BPF sub-program frame would push the
/// combined bpf-to-bpf stack past the 512-byte `MAX_BPF_STACK` ceiling.
#[inline(always)]
fn lookup_port_forward(policy_id: PolicyId, proto: u8, dst_port: u16) -> Option<PortFwd> {
    let key = ScopedPortKey::new(policy_id, proto, dst_port);
    match unsafe { PORT_FORWARDS.get(key) } {
        Some(v) => Some(*v),
        None => None,
    }
}

/// Whether a port-forward is configured for `(policy, proto, dst_port)` — the
/// bool the main program needs to open the firewall, without materialising the
/// `PortFwd` value. Returning a plain bool from the lookup discriminant keeps any
/// map-value pointer from being live at a merge point in `try_velstra`, which is
/// what triggered the verifier's pointer-OR / `R3 !read_ok` rejections; the
/// actual target is fetched by [`lookup_port_forward`] in `velstra_forward`.
#[inline(always)]
fn port_forward_exists(policy_id: PolicyId, proto: u8, dst_port: u16) -> bool {
    let key = ScopedPortKey::new(policy_id, proto, dst_port);
    unsafe { PORT_FORWARDS.get(key) }.is_some()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // XDP programs cannot unwind; the verifier also rejects real panics. This
    // is unreachable in practice but required to satisfy `no_std`.
    loop {}
}

/// Dual licence marker required by the kernel to load programs that call
/// GPL-only BPF helpers (e.g. those behind `aya-log`).
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
