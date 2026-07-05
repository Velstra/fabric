//! # velstra-orchestrator
//!
//! The control plane's **brain**: a high-level model of the virtual fabric —
//! *networks*, *hosts*, and *ports* — from which it **derives** each host's
//! concrete Velstra config.
//!
//! This is the leap from "a powerful data plane you configure by hand" to "a
//! platform you declare intent to". Instead of writing per-host TOML (which tap
//! is on which VNI, which remote IPs need a tunnel + ARP entry, …), an operator
//! says *"create a port for VM-B on network blue, on host-2"* and the
//! orchestrator:
//!
//! * allocates the port an IP (IPAM) and a MAC,
//! * records it against its network and host,
//! * and recomputes every host's config — the host running the port gets a tap
//!   binding; every *other* host with a port on that network gets a tunnel
//!   ([`OVERLAY_FDB`]) and an ARP entry ([`ARP_TABLE`]) pointing at it.
//!
//! Crucially this layer emits the **exact same** [`FileConfig`] the agent
//! already consumes (via `file_config_to_proto`), so neither the data plane nor
//! the agent changes — the Andromeda model, where a central brain holds the
//! topology and pushes each host only what it needs. The whole module is pure,
//! synchronous, and unit-tested; the controller wraps it with gRPC + storage.
//!
//! [`OVERLAY_FDB`]: velstra_common::TunnelKey
//! [`ARP_TABLE`]: velstra_common::ArpKey

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Result, bail};
use velstra_common::{Cidr4, Cidr6, PolicyId, mask_v4, mask_v6};
use velstra_config::{
    ActionName, EncapName, FileConfig, InterfaceFile, NeighborCfg, OverlayCfg, PolicyFile,
    PortRule, TunnelCfg,
};

/// A physical host that terminates tunnels (a VTEP).
#[derive(Debug, Clone)]
pub struct Host {
    /// Node id — matches the agent's `--node-id` and its served-config key.
    pub id: String,
    /// Underlay VTEP IPv4 (the outer source address for tunnels to this host).
    pub vtep_ip: Ipv4Addr,
    /// Underlay egress interface name on this host.
    pub underlay_iface: String,
    /// Underlay MAC — used as the next-hop `via_mac` when *other* hosts tunnel
    /// to this one (assumes a flat L2 underlay; a routed underlay would resolve
    /// the gateway MAC instead).
    pub underlay_mac: [u8; 6],
    /// Encapsulation this host uses.
    pub encap: EncapName,
    /// Override UDP port, or `None` for the encap default.
    pub udp_port: Option<u16>,
    /// Underlay MTU, or `None` for the default (1500).
    pub underlay_mtu: Option<u16>,
}

/// Map-ownership convention between the two writers of `OVERLAY_FDB` /
/// `ARP_TABLE` (M5), fixed **before** an EVPN/FPM path exists so the ranges can
/// never be retrofitted after callers depend on them:
///
/// * **Orchestrator ("controller-FDB")** — statically derived tunnel/neighbour
///   entries — owns VNIs `1 .. EVPN_RESERVED_VNI_BASE`.
/// * **Reserved** — VNIs `>= EVPN_RESERVED_VNI_BASE` (the top 64K of the 24-bit
///   space) are reserved for a future EVPN/FPM control-plane that learns FDB/ARP
///   entries dynamically. Reserving them now guarantees a learned entry can
///   never collide with a controller-derived one on the same map key.
///
/// The orchestrator therefore refuses to define a network in the reserved range
/// (see [`Topology::add_network`]).
pub const EVPN_RESERVED_VNI_BASE: u32 = 0xFF_0000;

/// A virtual network (a tenant L2 segment), identified by its VNI.
#[derive(Debug, Clone)]
pub struct Network {
    /// VXLAN Network Identifier (also the firewall policy id the orchestrator
    /// assigns to the network's ports). Must be non-zero and ≤ 24 bits.
    pub vni: u32,
    /// Human-readable name (becomes the policy name).
    pub name: String,
    /// Tenant subnet that IPAM allocates port addresses from.
    pub subnet: Cidr4,
    /// Default firewall action for the network's policy.
    pub default_action: ActionName,
    /// Whether the network's policy drops ICMP.
    pub drop_icmp: bool,
}

/// A dual-stack CIDR: a subnet is either IPv4 or IPv6. Wraps the shared
/// [`Cidr4`]/[`Cidr6`] so one [`Subnet`] type carries either family — a network
/// can therefore hold both a v4 and a v6 subnet (dual stack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubnetCidr {
    /// An IPv4 subnet.
    V4(Cidr4),
    /// An IPv6 subnet.
    V6(Cidr6),
}

impl SubnetCidr {
    /// Whether this is an IPv6 subnet.
    #[inline]
    pub fn is_v6(&self) -> bool {
        matches!(self, SubnetCidr::V6(_))
    }

    /// The prefix length in bits.
    #[inline]
    pub fn prefix(&self) -> u8 {
        match self {
            SubnetCidr::V4(c) => c.prefix,
            SubnetCidr::V6(c) => c.prefix,
        }
    }

    /// Whether `addr` falls within this CIDR. A family mismatch (a v6 address
    /// against a v4 subnet, or vice versa) is never contained.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (SubnetCidr::V4(c), IpAddr::V4(a)) => mask_v4(a.octets(), c.prefix) == c.octets,
            (SubnetCidr::V6(c), IpAddr::V6(a)) => mask_v6(a.octets(), c.prefix) == c.octets,
            _ => false,
        }
    }

    /// The network address as a numeric value (a v4 address in the low 32 bits).
    fn base(&self) -> u128 {
        match self {
            SubnetCidr::V4(c) => u32::from_be_bytes(c.octets) as u128,
            SubnetCidr::V6(c) => u128::from_be_bytes(c.octets),
        }
    }

    /// The number of addresses the block spans (saturating at the whole space
    /// for a `/0`).
    fn span(&self) -> u128 {
        let total = if self.is_v6() { 128 } else { 32 };
        let host = total - self.prefix() as u32;
        if host >= 128 {
            u128::MAX
        } else {
            1u128 << host
        }
    }

    /// The default `[lo, hi]` numeric allocation range when a subnet declares no
    /// explicit pool. IPv4 skips the network and broadcast addresses; IPv6 skips
    /// only the subnet-router anycast (the base). A range that yields no usable
    /// host addresses returns `lo > hi` (an empty pool), so allocation reports
    /// exhaustion rather than handing out a reserved address.
    fn default_pool(&self) -> (u128, u128) {
        let base = self.base();
        let span = self.span();
        if self.is_v6() {
            (
                base.saturating_add(1),
                base.saturating_add(span.saturating_sub(1)),
            )
        } else if span < 3 {
            (1, 0) // /31 and /32 have no usable host range: empty pool
        } else {
            (base + 1, base + span - 2)
        }
    }
}

/// An inclusive `[start, end]` address range within a [`Subnet`]'s CIDR — the
/// pool IPAM hands addresses out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRange {
    /// First allocatable address (inclusive).
    pub start: IpAddr,
    /// Last allocatable address (inclusive).
    pub end: IpAddr,
}

/// A first-class subnet under a [`Network`] (roadmap D2). A network is addressed
/// by its VNI; a subnet is a concrete address space *within* it, so a network can
/// hold several — e.g. a v4 and a v6 subnet for a dual-stack tenant, or multiple
/// ranges. Subnets are held on the [`Topology`] (keyed by [`id`](Self::id) and
/// tagged with their [`vni`](Self::vni)), mirroring how B5 security groups live
/// on the topology rather than being embedded in another object — see
/// [`Topology::add_subnet`] / [`Topology::network_subnets`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    /// Stable, fabric-unique subnet id.
    pub id: String,
    /// The network (VNI) this subnet belongs to.
    pub vni: u32,
    /// The subnet's CIDR (v4 or v6).
    pub cidr: SubnetCidr,
    /// Optional gateway address — must lie within [`cidr`](Self::cidr); reserved
    /// from allocation (IPAM never hands it to a port).
    pub gateway: Option<IpAddr>,
    /// Optional explicit allocation pool; `None` derives one from the CIDR (first
    /// usable .. last usable, skipping network/broadcast for v4).
    pub pool: Option<AllocRange>,
    /// Whether DHCP is enabled on this subnet. A pure model flag today — the
    /// datapath that would serve leases is deferred to the maintainer's eBPF work.
    pub enable_dhcp: bool,
}

/// An IPAM-allocated address bound to a [`Port`] from a [`Subnet`]. A port may
/// hold several (typically one v4 and one v6 — a dual-stack NIC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortAddr {
    /// The subnet the address came from.
    pub subnet_id: String,
    /// The allocated address.
    pub addr: IpAddr,
}

/// Who holds an IPAM allocation. The single source of truth for a subnet's used
/// addresses (see [`Topology::allocate`]); persisted in the snapshot so a live
/// address is never re-handed-out after a Raft failover or restart.
#[derive(Debug, Clone, PartialEq, Eq)]
enum IpAllocOwner {
    /// Bound to a port's NIC (the port id).
    Port(String),
    /// A standalone reservation made via [`Topology::allocate`].
    Reserved,
    /// The subnet's gateway, auto-reserved when the subnet is added.
    Gateway,
    /// Held by a floating IP (B6) — the floating IP's id. Keeps a floating
    /// address out of the port-allocation pool while it exists.
    Floating(String),
}

/// A workload's virtual NIC, attached to a [`Network`] and bound to a [`Host`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    /// Stable port id.
    pub id: String,
    /// The network (VNI) this port lives on.
    pub vni: u32,
    /// Firewall policy (security group) applied to this port, **decoupled** from
    /// its VNI (M4): `None` means "use the VNI as the policy id" — the
    /// single-tenant default where one number names both the segment and the
    /// ruleset. A distinct `Some(id)` lets several ports share one overlay
    /// segment while enforcing different rules (per-port security groups), or one
    /// ruleset span several segments. The eBPF map layer already keeps
    /// `IFACE_POLICY` and `IFACE_VNI` separate; this is the model catching up.
    pub policy: Option<u32>,
    /// The host id this port currently runs on.
    pub host: String,
    /// Allocated inner IPv4 address.
    pub ip: Ipv4Addr,
    /// Allocated MAC address.
    pub mac: [u8; 6],
    /// The tap/veth interface name on the host that carries this port.
    pub tap: String,
}

impl Port {
    /// The effective firewall policy id: the explicit security-group policy if
    /// set, else the VNI (the single-tenant default).
    #[inline]
    pub fn effective_policy(&self) -> u32 {
        self.policy.unwrap_or(self.vni)
    }
}

/// Base of the policy-id band reserved for named [`SecurityGroup`]s (roadmap
/// B5): `2^24`. It sits entirely **above** the 24-bit VNI space, and therefore
/// above every network-derived policy id (which equals a ≤ 24-bit VNI) *and*
/// above the [`EVPN_RESERVED_VNI_BASE`] VNI reservation. A security group's
/// `policy_id` is derived by hashing its name into `[BASE, u32::MAX]`, so it can
/// never collide with a VNI-derived policy id, is independent of creation order,
/// and stays fixed across rule edits — the property that keeps a group's
/// conntrack and firewall-map keys stable when only its rules change.
pub const SECURITY_GROUP_POLICY_BASE: PolicyId = 1 << 24;

/// Deterministically derive a security group's fabric `policy_id` from its name.
///
/// A 32-bit FNV-1a hash (small, stable, dependency-free) folded into the
/// [`SECURITY_GROUP_POLICY_BASE`] band. Purely a function of the name: the same
/// name always maps to the same id, on any host and across restarts, so two
/// controllers derive identical map keys and editing a group's rules never moves
/// its id.
pub fn security_group_policy_id(name: &str) -> PolicyId {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in name.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let span = u32::MAX - SECURITY_GROUP_POLICY_BASE + 1;
    SECURITY_GROUP_POLICY_BASE + (hash % span)
}

/// A named, reusable firewall rule set (roadmap B5) — a *security group*.
///
/// It carries exactly the same firewall shape as a `[[policy]]` block (a default
/// action, the ICMP/stateful toggles, a source blocklist, and per-`(proto,
/// port)` rules), but is addressed by **name** and assigned a deterministic
/// fabric [`policy_id`](Self::policy_id). A [`Port`] binds to one via
/// [`Topology::set_port_security_group`]; [`Topology::derive`] then emits the
/// group as a `[[policy]]` block on every host that has a bound local port, so
/// the data plane enforces its rules under the group's stable `policy_id`.
///
/// The rules reuse the existing [`velstra_config::PortRule`] schema — there is
/// no second rule model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityGroup {
    /// Unique group name; also the sole input to its `policy_id`.
    pub name: String,
    /// Verdict for traffic matching no rule.
    pub default_action: ActionName,
    /// Drop all ICMP under this group.
    pub drop_icmp: bool,
    /// Track connections and allow established flows (stateful firewall).
    pub stateful: bool,
    /// Source-IP CIDR blocks to drop unconditionally.
    pub blocklist: Vec<String>,
    /// Per-`(proto, port)` rules (reuses [`velstra_config::PortRule`]).
    pub rules: Vec<PortRule>,
}

impl SecurityGroup {
    /// This group's deterministic fabric `policy_id` (a pure function of its
    /// name — see [`security_group_policy_id`]).
    #[inline]
    pub fn policy_id(&self) -> PolicyId {
        security_group_policy_id(&self.name)
    }
}

/// A 1:1 association of a [`FloatingIp`] to a port's fixed address (roadmap B6).
/// The datapath will DNAT inbound traffic destined to the floating address onto
/// `fixed_addr` and SNAT the return path; that enforcement is **deferred** to the
/// maintainer's eBPF work — this layer only models the mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloatingAssociation {
    /// The port whose fixed address the floating IP maps to.
    pub port_id: String,
    /// The port's fixed address the floating IP is bound to — validated to be one
    /// the port actually holds (its [`Port::ip`] or an IPAM-bound [`PortAddr`]).
    pub fixed_addr: IpAddr,
}

/// A first-class floating / secondary address (roadmap B6): an address allocated
/// from a designated floating/external [`Subnet`] via the shared IPAM, with an
/// optional 1:1 association to a port's fixed address. Held on the [`Topology`]
/// keyed by [`id`](Self::id) and tagged with the floating subnet's
/// [`vni`](Self::vni), mirroring how B5 security groups and D2 subnets live on
/// the topology rather than being embedded in another object.
///
/// While allocated, the address is reserved in its subnet's IPAM under an
/// [`IpAllocOwner::Floating`] owner, so it can never be handed to a port. When
/// associated, the datapath DNAT/SNATs between the floating address and the
/// port's fixed address — see [`FloatingAssociation`] (deferred to eBPF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloatingIp {
    /// Stable, fabric-unique floating-IP id (`fip-{vni}-{addr}`).
    pub id: String,
    /// The floating subnet's network (VNI) — the tag this floating IP carries.
    pub vni: u32,
    /// The floating/external subnet the address was allocated from.
    pub subnet_id: String,
    /// The allocated floating address.
    pub addr: IpAddr,
    /// The current 1:1 association to a port's fixed address, or `None` when the
    /// floating IP is allocated but unassociated.
    pub association: Option<FloatingAssociation>,
}

/// The whole virtual fabric: networks, hosts, and the ports binding them.
/// Holds no I/O — the controller owns persistence and distribution.
#[derive(Debug, Default, Clone)]
pub struct Topology {
    networks: HashMap<u32, Network>,
    hosts: HashMap<String, Host>,
    ports: Vec<Port>,
    /// Named security groups (B5), keyed by name. A port references one by
    /// `policy_id` (stored in [`Port::policy`]).
    security_groups: HashMap<String, SecurityGroup>,
    /// First-class subnets (D2), keyed by subnet id; each is tagged with its VNI.
    subnets: HashMap<String, Subnet>,
    /// IPAM allocations: subnet id -> (numeric address -> owner). The durable
    /// record of which addresses are in use; the ordered [`BTreeMap`] makes
    /// "next free address" deterministic across replicas.
    ipam: HashMap<String, BTreeMap<u128, IpAllocOwner>>,
    /// First-class floating / secondary IPs (B6), keyed by id. Each is tagged
    /// with its floating subnet's VNI and holds an IPAM address under an
    /// [`IpAllocOwner::Floating`] owner.
    floating_ips: HashMap<String, FloatingIp>,
}

/// Derive a locally-administered, deterministic MAC for an inner IPv4: `02:00`
/// then the four address octets. Unique per address, stable across recomputes.
fn mac_for(ip: Ipv4Addr) -> [u8; 6] {
    let o = ip.octets();
    [0x02, 0x00, o[0], o[1], o[2], o[3]]
}

fn fmt_mac(mac: [u8; 6]) -> String {
    let [a, b, c, d, e, f] = mac;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// An IP address as a numeric value (a v4 address in the low 32 bits), the key
/// space IPAM allocates over.
fn ip_to_u128(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v) => u32::from(v) as u128,
        IpAddr::V6(v) => u128::from(v),
    }
}

/// Reconstruct an address from its numeric value, in the family the subnet fixes.
fn u128_to_ip(n: u128, is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(Ipv6Addr::from(n))
    } else {
        IpAddr::V4(Ipv4Addr::from(n as u32))
    }
}

/// A family-agnostic 16-byte encoding of an address for the snapshot (a v4
/// address occupies the first four bytes). Paired with an `is_v6` flag on the
/// record so it round-trips losslessly and infallibly (no string parsing).
fn ip_to_bytes16(a: IpAddr) -> [u8; 16] {
    match a {
        IpAddr::V4(v) => {
            let mut b = [0u8; 16];
            b[..4].copy_from_slice(&v.octets());
            b
        }
        IpAddr::V6(v) => v.octets(),
    }
}

/// Inverse of [`ip_to_bytes16`], given the family recorded alongside it.
fn bytes16_to_ip(b: [u8; 16], is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(Ipv6Addr::from(b))
    } else {
        let mut o = [0u8; 4];
        o.copy_from_slice(&b[..4]);
        IpAddr::V4(Ipv4Addr::from(o))
    }
}

/// The effective `[lo, hi]` numeric allocation pool for a subnet: its explicit
/// pool if set, else the CIDR-derived default.
fn effective_pool(cidr: &SubnetCidr, pool: Option<AllocRange>) -> (u128, u128) {
    match pool {
        Some(r) => (ip_to_u128(r.start), ip_to_u128(r.end)),
        None => cidr.default_pool(),
    }
}

impl Topology {
    /// An empty fabric.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a host (VTEP). Replaces any existing host with the same id.
    pub fn add_host(&mut self, host: Host) {
        self.hosts.insert(host.id.clone(), host);
    }

    /// Define a network. Fails for a zero VNI, a VNI in the reserved EVPN range
    /// (see [`EVPN_RESERVED_VNI_BASE`]), or a duplicate.
    pub fn add_network(&mut self, network: Network) -> Result<()> {
        if network.vni == 0 {
            bail!("network vni must be non-zero");
        }
        if network.vni >= EVPN_RESERVED_VNI_BASE {
            bail!(
                "network vni {:#x} is reserved for the EVPN/FPM control-plane path \
                 (>= {:#x}); orchestrator-managed networks must use 1..{:#x}",
                network.vni,
                EVPN_RESERVED_VNI_BASE,
                EVPN_RESERVED_VNI_BASE
            );
        }
        if self.networks.contains_key(&network.vni) {
            bail!("network vni {} already exists", network.vni);
        }
        self.networks.insert(network.vni, network);
        Ok(())
    }

    /// Retire a host. Fails while any port is still bound to it, so a caller
    /// must migrate or remove those ports first — otherwise `derive()` would keep
    /// generating dead tunnels/ARP entries toward a gone VTEP. Returns whether
    /// the host existed.
    pub fn remove_host(&mut self, id: &str) -> Result<bool> {
        if let Some(p) = self.ports.iter().find(|p| p.host == id) {
            bail!(
                "host {id:?} still has port {:?}; migrate or remove it first",
                p.id
            );
        }
        Ok(self.hosts.remove(id).is_some())
    }

    /// Decommission a network. Fails while any port is still on it. Returns
    /// whether the network existed.
    pub fn remove_network(&mut self, vni: u32) -> Result<bool> {
        if let Some(p) = self.ports.iter().find(|p| p.vni == vni) {
            bail!("network {vni} still has port {:?}; remove it first", p.id);
        }
        if let Some(s) = self.subnets.values().find(|s| s.vni == vni) {
            bail!("network {vni} still has subnet {:?}; remove it first", s.id);
        }
        Ok(self.networks.remove(&vni).is_some())
    }

    /// All hosts, in no particular order.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// All networks, in no particular order.
    pub fn networks(&self) -> impl Iterator<Item = &Network> {
        self.networks.values()
    }

    /// All ports.
    pub fn ports(&self) -> &[Port] {
        &self.ports
    }

    /// Register a named security group (B5). Fails on an empty name, a duplicate
    /// name, or the (vanishingly rare) case of its derived `policy_id` colliding
    /// with an already-registered group's — mirroring the "reject rather than
    /// silently overwrite" stance of [`add_network`](Self::add_network).
    pub fn add_security_group(&mut self, sg: SecurityGroup) -> Result<()> {
        if sg.name.is_empty() {
            bail!("security group name must not be empty");
        }
        if self.security_groups.contains_key(&sg.name) {
            bail!("security group {:?} already exists", sg.name);
        }
        let pid = sg.policy_id();
        if let Some(existing) = self.security_groups.values().find(|g| g.policy_id() == pid) {
            bail!(
                "security group {:?} hashes to the same policy_id {pid} as {:?}; rename one",
                sg.name,
                existing.name
            );
        }
        self.security_groups.insert(sg.name.clone(), sg);
        Ok(())
    }

    /// All security groups, in no particular order.
    pub fn security_groups(&self) -> impl Iterator<Item = &SecurityGroup> {
        self.security_groups.values()
    }

    /// Look up a security group by name.
    pub fn security_group(&self, name: &str) -> Option<&SecurityGroup> {
        self.security_groups.get(name)
    }

    /// Remove a security group by name. Fails while any port is still bound to it
    /// (the caller must rebind or remove those ports first — otherwise `derive()`
    /// would emit interfaces pointing at a policy with no rule set). Returns
    /// whether the group existed.
    pub fn remove_security_group(&mut self, name: &str) -> Result<bool> {
        let Some(sg) = self.security_groups.get(name) else {
            return Ok(false);
        };
        let pid = sg.policy_id();
        if let Some(p) = self.ports.iter().find(|p| p.policy == Some(pid)) {
            bail!(
                "security group {name:?} still bound by port {:?}; rebind or remove it first",
                p.id
            );
        }
        self.security_groups.remove(name);
        Ok(true)
    }

    /// Bind a port to a security group by name (`Some`), or clear its binding
    /// back to the VNI-as-policy default (`None`). Setting a binding resolves the
    /// group's deterministic `policy_id` into [`Port::policy`], so the port's
    /// traffic is evaluated against that group's rules. Fails on an unknown port
    /// or an unknown group.
    pub fn set_port_security_group(&mut self, port_id: &str, group: Option<&str>) -> Result<Port> {
        let policy = match group {
            Some(name) => Some(
                self.security_groups
                    .get(name)
                    .ok_or_else(|| anyhow::anyhow!("unknown security group {name:?}"))?
                    .policy_id(),
            ),
            None => None,
        };
        let port = self
            .ports
            .iter_mut()
            .find(|p| p.id == port_id)
            .ok_or_else(|| anyhow::anyhow!("unknown port {port_id:?}"))?;
        port.policy = policy;
        Ok(port.clone())
    }

    /// Create a port on `vni`/`host`, allocating an IP (the next free address in
    /// the network's subnet unless `requested_ip` is given) and a MAC.
    pub fn create_port(
        &mut self,
        vni: u32,
        host: &str,
        tap: &str,
        requested_ip: Option<Ipv4Addr>,
        policy: Option<u32>,
    ) -> Result<Port> {
        if !self.networks.contains_key(&vni) {
            bail!("unknown network vni {vni}");
        }
        if !self.hosts.contains_key(host) {
            bail!("unknown host {host:?}");
        }
        // A (host, tap) pair maps to exactly one host interface. Two ports bound
        // to the same tap would resolve to the same ifindex on the agent, where
        // the second silently overwrites the first's IFACE_POLICY/IFACE_VNI — one
        // port left unfirewalled/mis-VNI'd with no error. Reject it here.
        if self.ports.iter().any(|p| p.host == host && p.tap == tap) {
            bail!("tap {tap:?} on host {host:?} is already bound to another port");
        }
        let ip = match requested_ip {
            Some(ip) => {
                if !self.subnet_contains(vni, ip) {
                    bail!("ip {ip} is outside network {vni}'s subnet");
                }
                if self.ports.iter().any(|p| p.vni == vni && p.ip == ip) {
                    bail!("ip {ip} is already allocated on network {vni}");
                }
                ip
            }
            None => self.alloc_ip(vni)?,
        };
        let port = Port {
            id: format!("port-{vni}-{ip}"),
            vni,
            policy,
            host: host.to_string(),
            ip,
            mac: mac_for(ip),
            tap: tap.to_string(),
        };
        self.ports.push(port.clone());
        Ok(port)
    }

    /// Remove a port by id, releasing any IPAM addresses bound to it back to
    /// their subnets' pools. Returns whether it existed.
    pub fn remove_port(&mut self, id: &str) -> bool {
        let before = self.ports.len();
        self.ports.retain(|p| p.id != id);
        let removed = self.ports.len() != before;
        if removed {
            for allocs in self.ipam.values_mut() {
                allocs.retain(|_, o| !matches!(o, IpAllocOwner::Port(p) if p == id));
            }
            // Any floating IP associated to this port loses its association (the
            // floating IP itself stays allocated, free to re-associate elsewhere).
            for fip in self.floating_ips.values_mut() {
                if fip.association.as_ref().is_some_and(|a| a.port_id == id) {
                    fip.association = None;
                }
            }
        }
        removed
    }

    /// Move an existing port to `new_host`, binding it to `new_tap` there. The
    /// port keeps its identity — id, VNI, IP, and MAC — so a live-migrated
    /// workload stays reachable at the same address. `derive()` then re-points
    /// every peer's tunnel/ARP entry at the new host's VTEP, the old host loses
    /// the local interface binding (and gains a tunnel back to the port), and the
    /// new host gains it. A no-op host move still updates the tap.
    pub fn migrate_port(&mut self, id: &str, new_host: &str, new_tap: &str) -> Result<Port> {
        if !self.hosts.contains_key(new_host) {
            bail!("unknown host {new_host:?}");
        }
        // The destination tap must be free (ignoring this port itself), for the
        // same ifindex-collision reason as create_port.
        if self
            .ports
            .iter()
            .any(|p| p.id != id && p.host == new_host && p.tap == new_tap)
        {
            bail!("tap {new_tap:?} on host {new_host:?} is already bound to another port");
        }
        let port = self
            .ports
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown port {id:?}"))?;
        port.host = new_host.to_string();
        port.tap = new_tap.to_string();
        Ok(port.clone())
    }

    // === D2: first-class subnets + IPAM =====================================

    /// Define a [`Subnet`] under an existing network. Fails on an empty or
    /// duplicate id, an unknown VNI, a gateway or pool endpoint outside the CIDR
    /// (or of the wrong family), or an inverted pool (`start > end`). On success
    /// the gateway (if any) is auto-reserved in IPAM so it is never handed out.
    pub fn add_subnet(&mut self, subnet: Subnet) -> Result<()> {
        if subnet.id.is_empty() {
            bail!("subnet id must not be empty");
        }
        if self.subnets.contains_key(&subnet.id) {
            bail!("subnet {:?} already exists", subnet.id);
        }
        if !self.networks.contains_key(&subnet.vni) {
            bail!("unknown network vni {}", subnet.vni);
        }
        if let Some(gw) = subnet.gateway
            && !subnet.cidr.contains(gw)
        {
            bail!(
                "gateway {gw} is not in subnet {:?}'s CIDR (or wrong family)",
                subnet.id
            );
        }
        if let Some(pool) = subnet.pool {
            if !subnet.cidr.contains(pool.start) || !subnet.cidr.contains(pool.end) {
                bail!(
                    "pool {}..{} is not within subnet {:?}'s CIDR (or wrong family)",
                    pool.start,
                    pool.end,
                    subnet.id
                );
            }
            if ip_to_u128(pool.start) > ip_to_u128(pool.end) {
                bail!(
                    "pool start {} is above end {} in subnet {:?}",
                    pool.start,
                    pool.end,
                    subnet.id
                );
            }
        }
        let id = subnet.id.clone();
        let gateway = subnet.gateway;
        self.subnets.insert(id.clone(), subnet);
        let allocs = self.ipam.entry(id).or_default();
        if let Some(gw) = gateway {
            allocs.insert(ip_to_u128(gw), IpAllocOwner::Gateway);
        }
        Ok(())
    }

    /// Remove a subnet by id. Fails while any address (a port binding or a
    /// standalone reservation) is still allocated from it — the auto-reserved
    /// gateway does not block removal and is cleaned up. Returns whether it
    /// existed.
    pub fn remove_subnet(&mut self, id: &str) -> Result<bool> {
        if !self.subnets.contains_key(id) {
            return Ok(false);
        }
        if let Some(allocs) = self.ipam.get(id)
            && allocs.values().any(|o| !matches!(o, IpAllocOwner::Gateway))
        {
            bail!("subnet {id:?} still has allocated addresses; release them first");
        }
        self.subnets.remove(id);
        self.ipam.remove(id);
        Ok(true)
    }

    /// All subnets, in no particular order.
    pub fn subnets(&self) -> impl Iterator<Item = &Subnet> {
        self.subnets.values()
    }

    /// Look up a subnet by id.
    pub fn subnet(&self, id: &str) -> Option<&Subnet> {
        self.subnets.get(id)
    }

    /// The subnets belonging to a network (VNI) — the "a network has subnets"
    /// view. In no particular order.
    pub fn network_subnets(&self, vni: u32) -> impl Iterator<Item = &Subnet> {
        self.subnets.values().filter(move |s| s.vni == vni)
    }

    /// Allocate an address from a subnet's pool (a standalone reservation), or a
    /// specific `requested` one. Deterministic: with no request it returns the
    /// lowest free address in the pool. Fails on an unknown subnet, a request
    /// outside the CIDR/pool, an already-allocated request, or exhaustion.
    pub fn allocate(&mut self, subnet_id: &str, requested: Option<IpAddr>) -> Result<IpAddr> {
        self.alloc_in(subnet_id, requested, IpAllocOwner::Reserved)
    }

    /// Release an address back to a subnet's pool. Returns whether an allocation
    /// was actually freed (an unknown subnet or unallocated address is `false`).
    pub fn release(&mut self, subnet_id: &str, addr: IpAddr) -> bool {
        self.ipam
            .get_mut(subnet_id)
            .map(|a| a.remove(&ip_to_u128(addr)).is_some())
            .unwrap_or(false)
    }

    /// Bind a port to a subnet, giving it an IPAM-allocated address (or a
    /// specific `requested` one, validated in-range and free). The subnet must
    /// belong to the port's network. Returns the resulting [`PortAddr`]. Bind a
    /// port to both a v4 and a v6 subnet to make it dual-stack.
    pub fn bind_port_subnet(
        &mut self,
        port_id: &str,
        subnet_id: &str,
        requested: Option<IpAddr>,
    ) -> Result<PortAddr> {
        let port_vni = self
            .ports
            .iter()
            .find(|p| p.id == port_id)
            .ok_or_else(|| anyhow::anyhow!("unknown port {port_id:?}"))?
            .vni;
        let subnet_vni = self
            .subnets
            .get(subnet_id)
            .ok_or_else(|| anyhow::anyhow!("unknown subnet {subnet_id:?}"))?
            .vni;
        if subnet_vni != port_vni {
            bail!(
                "subnet {subnet_id:?} is on network {subnet_vni}, but port {port_id:?} is on {port_vni}"
            );
        }
        let addr = self.alloc_in(
            subnet_id,
            requested,
            IpAllocOwner::Port(port_id.to_string()),
        )?;
        Ok(PortAddr {
            subnet_id: subnet_id.to_string(),
            addr,
        })
    }

    /// Release one of a port's bound addresses. Returns whether that address was
    /// actually bound to this port (a mismatched owner is left untouched).
    pub fn unbind_port_address(&mut self, port_id: &str, subnet_id: &str, addr: IpAddr) -> bool {
        let Some(allocs) = self.ipam.get_mut(subnet_id) else {
            return false;
        };
        let key = ip_to_u128(addr);
        if matches!(allocs.get(&key), Some(IpAllocOwner::Port(p)) if p == port_id) {
            allocs.remove(&key);
            true
        } else {
            false
        }
    }

    /// Every IPAM address currently bound to a port, sorted by `(subnet id,
    /// address)` for a deterministic order. A dual-stack port returns both its v4
    /// and v6 address.
    pub fn port_addrs(&self, port_id: &str) -> Vec<PortAddr> {
        let mut out = Vec::new();
        for (sid, allocs) in &self.ipam {
            let is_v6 = self.subnets.get(sid).is_some_and(|s| s.cidr.is_v6());
            for (key, owner) in allocs {
                if matches!(owner, IpAllocOwner::Port(p) if p == port_id) {
                    out.push(PortAddr {
                        subnet_id: sid.clone(),
                        addr: u128_to_ip(*key, is_v6),
                    });
                }
            }
        }
        out.sort_by(|a, b| {
            (&a.subnet_id, ip_to_u128(a.addr)).cmp(&(&b.subnet_id, ip_to_u128(b.addr)))
        });
        out
    }

    // === B6: floating IPs ===================================================

    /// Allocate a [`FloatingIp`] from a designated floating/external subnet via
    /// IPAM — the lowest free address, or a specific `requested` one. The floating
    /// IP starts unassociated. Deterministic and dup-free: the address is reserved
    /// in the subnet's IPAM under an [`IpAllocOwner::Floating`] owner, so it can
    /// never be handed to a port. Fails on an unknown subnet, an out-of-pool /
    /// already-allocated request, or exhaustion.
    pub fn allocate_floating_ip(
        &mut self,
        subnet_id: &str,
        requested: Option<IpAddr>,
    ) -> Result<FloatingIp> {
        let vni = self
            .subnets
            .get(subnet_id)
            .ok_or_else(|| anyhow::anyhow!("unknown subnet {subnet_id:?}"))?
            .vni;
        // Reserve the address through the shared IPAM path (which enforces the
        // pool / dup / exhaustion rules), then re-tag it as Floating-owned once the
        // address — and hence the derived id — is known.
        let addr = self.alloc_in(subnet_id, requested, IpAllocOwner::Reserved)?;
        let id = format!("fip-{vni}-{addr}");
        if self.floating_ips.contains_key(&id) {
            // Undo the reservation so a failed allocate leaves no orphaned entry.
            self.release(subnet_id, addr);
            bail!("floating ip {id:?} already exists");
        }
        if let Some(allocs) = self.ipam.get_mut(subnet_id) {
            allocs.insert(ip_to_u128(addr), IpAllocOwner::Floating(id.clone()));
        }
        let fip = FloatingIp {
            id: id.clone(),
            vni,
            subnet_id: subnet_id.to_string(),
            addr,
            association: None,
        };
        self.floating_ips.insert(id, fip.clone());
        Ok(fip)
    }

    /// Associate a floating IP to a port's fixed address (a 1:1 mapping). Fails on
    /// an unknown floating IP or port, if the floating IP is already associated
    /// (disassociate it first), if the port does not actually hold `fixed_addr`,
    /// or if another floating IP already maps that fixed address.
    pub fn associate_floating_ip(
        &mut self,
        fip_id: &str,
        port_id: &str,
        fixed_addr: IpAddr,
    ) -> Result<FloatingIp> {
        match self.floating_ips.get(fip_id) {
            None => bail!("unknown floating ip {fip_id:?}"),
            Some(f) if f.association.is_some() => {
                bail!("floating ip {fip_id:?} is already associated; disassociate it first")
            }
            Some(_) => {}
        }
        if !self.port_holds_addr(port_id, fixed_addr) {
            // Covers both an unknown port and a port that doesn't hold the address.
            bail!("port {port_id:?} does not hold fixed address {fixed_addr}");
        }
        if let Some(other) = self.floating_ips.values().find(|f| {
            f.id != fip_id
                && f.association
                    .as_ref()
                    .is_some_and(|a| a.fixed_addr == fixed_addr)
        }) {
            bail!(
                "fixed address {fixed_addr} is already mapped by floating ip {:?}",
                other.id
            );
        }
        let fip = self.floating_ips.get_mut(fip_id).unwrap();
        fip.association = Some(FloatingAssociation {
            port_id: port_id.to_string(),
            fixed_addr,
        });
        Ok(fip.clone())
    }

    /// Clear a floating IP's association, leaving it allocated but unbound. Fails
    /// only on an unknown floating IP; clearing an already-unassociated one is a
    /// no-op. Returns the resulting [`FloatingIp`].
    pub fn disassociate_floating_ip(&mut self, fip_id: &str) -> Result<FloatingIp> {
        let fip = self
            .floating_ips
            .get_mut(fip_id)
            .ok_or_else(|| anyhow::anyhow!("unknown floating ip {fip_id:?}"))?;
        fip.association = None;
        Ok(fip.clone())
    }

    /// Release a floating IP, freeing its IPAM address back to the floating
    /// subnet's pool. Blocked while it is still associated (disassociate first) —
    /// mirroring how a bound security group blocks its own removal. Returns
    /// whether the floating IP existed.
    pub fn release_floating_ip(&mut self, fip_id: &str) -> Result<bool> {
        let Some(fip) = self.floating_ips.get(fip_id) else {
            return Ok(false);
        };
        if fip.association.is_some() {
            bail!("floating ip {fip_id:?} is still associated; disassociate it first");
        }
        let subnet_id = fip.subnet_id.clone();
        let addr = fip.addr;
        self.floating_ips.remove(fip_id);
        self.release(&subnet_id, addr);
        Ok(true)
    }

    /// All floating IPs, in no particular order.
    pub fn floating_ips(&self) -> impl Iterator<Item = &FloatingIp> {
        self.floating_ips.values()
    }

    /// Look up a floating IP by id.
    pub fn floating_ip(&self, id: &str) -> Option<&FloatingIp> {
        self.floating_ips.get(id)
    }

    /// Every floating IP currently associated to a port, sorted by id for a
    /// deterministic order.
    pub fn port_floating_ips(&self, port_id: &str) -> Vec<&FloatingIp> {
        let mut out: Vec<&FloatingIp> = self
            .floating_ips
            .values()
            .filter(|f| f.association.as_ref().is_some_and(|a| a.port_id == port_id))
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// Whether a port holds `addr` as a fixed address — either its legacy inner
    /// IPv4 ([`Port::ip`]) or an IPAM-bound [`PortAddr`]. Returns `false` for an
    /// unknown port.
    fn port_holds_addr(&self, port_id: &str, addr: IpAddr) -> bool {
        let Some(port) = self.ports.iter().find(|p| p.id == port_id) else {
            return false;
        };
        if IpAddr::V4(port.ip) == addr {
            return true;
        }
        self.port_addrs(port_id).iter().any(|pa| pa.addr == addr)
    }

    /// Core IPAM allocation, shared by [`allocate`](Self::allocate) and
    /// [`bind_port_subnet`](Self::bind_port_subnet): reserve `requested` (or the
    /// lowest free address in the pool) under `owner`.
    fn alloc_in(
        &mut self,
        subnet_id: &str,
        requested: Option<IpAddr>,
        owner: IpAllocOwner,
    ) -> Result<IpAddr> {
        let subnet = self
            .subnets
            .get(subnet_id)
            .ok_or_else(|| anyhow::anyhow!("unknown subnet {subnet_id:?}"))?;
        let cidr = subnet.cidr;
        let is_v6 = cidr.is_v6();
        let (lo, hi) = effective_pool(&cidr, subnet.pool);
        let allocs = self.ipam.entry(subnet_id.to_string()).or_default();
        let key = match requested {
            Some(req) => {
                if !cidr.contains(req) {
                    bail!("address {req} is not in subnet {subnet_id:?} (or wrong family)");
                }
                let k = ip_to_u128(req);
                if !(lo..=hi).contains(&k) {
                    bail!("address {req} is outside subnet {subnet_id:?}'s allocation pool");
                }
                if allocs.contains_key(&k) {
                    bail!("address {req} is already allocated in subnet {subnet_id:?}");
                }
                k
            }
            None => (lo..=hi)
                .find(|k| !allocs.contains_key(k))
                .ok_or_else(|| anyhow::anyhow!("subnet {subnet_id:?} has no free addresses"))?,
        };
        allocs.insert(key, owner);
        Ok(u128_to_ip(key, is_v6))
    }

    fn subnet_contains(&self, vni: u32, ip: Ipv4Addr) -> bool {
        let Some(net) = self.networks.get(&vni) else {
            return false;
        };
        let base = u32::from_be_bytes(net.subnet.octets);
        let host_bits = 32 - net.subnet.prefix as u32;
        let mask = if host_bits >= 32 {
            0
        } else {
            u32::MAX << host_bits
        };
        (u32::from(ip) & mask) == base
    }

    /// Allocate the lowest free host address in a network's subnet (skipping the
    /// network and broadcast addresses).
    fn alloc_ip(&self, vni: u32) -> Result<Ipv4Addr> {
        let net = &self.networks[&vni];
        let base = u32::from_be_bytes(net.subnet.octets);
        let host_bits = 32 - net.subnet.prefix as u32;
        // /31 and /32 have no usable host range under this scheme.
        let span = if host_bits >= 32 {
            u32::MAX
        } else {
            1u32 << host_bits
        };
        if span < 3 {
            bail!("network {vni} subnet is too small for a host address");
        }
        let taken: HashSet<u32> = self
            .ports
            .iter()
            .filter(|p| p.vni == vni)
            .map(|p| u32::from(p.ip))
            .collect();
        for off in 1..(span - 1) {
            let cand = base + off;
            if !taken.contains(&cand) {
                return Ok(Ipv4Addr::from(cand));
            }
        }
        bail!("network {vni} has no free addresses");
    }

    /// Derive host `host_id`'s complete [`FileConfig`] from the model, or `None`
    /// if the host is unknown.
    ///
    /// The host gets:
    /// * its `[overlay]` endpoint,
    /// * a `[[policy]]` for every network it has at least one local port on,
    /// * an `[[interface]]` binding (tap → policy/vni) for each **local** port,
    /// * a `[[tunnel]]` + `[[neighbor]]` for every **remote** port on a network
    ///   this host participates in — so its VMs can reach, and ARP-resolve,
    ///   their peers on other hosts.
    pub fn derive(&self, host_id: &str) -> Option<FileConfig> {
        let host = self.hosts.get(host_id)?;

        // VNIs this host participates in (has ≥1 local port on).
        let local_vnis: HashSet<u32> = self
            .ports
            .iter()
            .filter(|p| p.host == host_id)
            .map(|p| p.vni)
            .collect();

        let mut cfg = FileConfig {
            default_action: ActionName::Pass,
            overlay: Some(OverlayCfg {
                local_vtep: host.vtep_ip.to_string(),
                underlay_iface: host.underlay_iface.clone(),
                encap: host.encap,
                udp_port: host.udp_port,
                local_mac: None,
                underlay_mtu: host.underlay_mtu,
            }),
            ..FileConfig::default()
        };

        // One policy per participating network (id == vni).
        let mut vnis: Vec<u32> = local_vnis.iter().copied().collect();
        vnis.sort_unstable(); // deterministic output
        for vni in &vnis {
            let net = &self.networks[vni];
            cfg.policies.push(PolicyFile {
                id: *vni,
                name: Some(net.name.clone()),
                default_action: net.default_action,
                drop_icmp: net.drop_icmp,
                log: false,
                stateful: false,
                blocklist: Vec::new(),
                port_rules: Vec::new(),
            });
        }

        // Security groups (B5): every group a *local* port binds (its
        // `effective_policy` is a security-group policy id, not the VNI) becomes
        // a `[[policy]]` block carrying that group's rules, so the interface the
        // port loop emits below resolves to a real rule set under the group's
        // stable policy id. Collected and sorted by policy id for deterministic
        // output; a group is emitted once no matter how many ports bind it.
        let mut sg_pids: Vec<PolicyId> = self
            .ports
            .iter()
            .filter(|p| p.host == host_id)
            .filter_map(|p| p.policy)
            .filter(|pid| !local_vnis.contains(pid))
            .collect();
        sg_pids.sort_unstable();
        sg_pids.dedup();
        for pid in sg_pids {
            if let Some(sg) = self.security_groups.values().find(|g| g.policy_id() == pid) {
                cfg.policies.push(PolicyFile {
                    id: pid,
                    name: Some(sg.name.clone()),
                    default_action: sg.default_action,
                    drop_icmp: sg.drop_icmp,
                    log: false,
                    stateful: sg.stateful,
                    blocklist: sg.blocklist.clone(),
                    port_rules: sg.rules.clone(),
                });
            }
        }

        // Ports: local → interface; remote on a hosted VNI → tunnel + neighbour.
        for port in &self.ports {
            if port.host == host_id {
                cfg.interfaces.push(InterfaceFile {
                    name: port.tap.clone(),
                    // Decoupled from the VNI (M4): a port's security-group policy
                    // if set, else the VNI as the default single-tenant policy id.
                    policy: port.effective_policy(),
                    vni: Some(port.vni),
                    // Orchestrator-managed tap ports are tenant overlay endpoints,
                    // never a WAN uplink, so they are not masqueraded.
                    masquerade: false,
                });
            } else if local_vnis.contains(&port.vni) {
                let remote = &self.hosts[&port.host];
                cfg.tunnels.push(TunnelCfg {
                    vni: port.vni,
                    inner_dst: format!("{}/32", port.ip),
                    remote_vtep: remote.vtep_ip.to_string(),
                    via_mac: fmt_mac(remote.underlay_mac),
                    out_iface: host.underlay_iface.clone(),
                });
                cfg.neighbors.push(NeighborCfg {
                    vni: port.vni,
                    ip: port.ip.to_string(),
                    mac: fmt_mac(port.mac),
                });
            }
        }

        Some(cfg)
    }
}

// === Serializable snapshot ==================================================
//
// The model's durable form, used by the Raft state machine (and any other
// snapshotter). Built from / restored into a [`Topology`] losslessly, with
// primitive fields so it serialises with plain `serde` (no foreign impls).

/// A serializable point-in-time copy of the whole fabric.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct FabricSnapshot {
    /// All hosts.
    pub hosts: Vec<HostRec>,
    /// All networks.
    pub networks: Vec<NetworkRec>,
    /// All ports.
    pub ports: Vec<PortRec>,
    /// All security groups (B5). `#[serde(default)]` so snapshots written before
    /// B5 deserialize as an empty set (no groups).
    #[serde(default)]
    pub security_groups: Vec<SecurityGroupRec>,
    /// All subnets (D2). `#[serde(default)]` so pre-D2 snapshots restore with no
    /// subnets.
    #[serde(default)]
    pub subnets: Vec<SubnetRec>,
    /// All IPAM allocations (D2) — the durable used-address set, so a live
    /// address is never re-handed-out after a failover. `#[serde(default)]` for
    /// pre-D2 snapshots.
    #[serde(default)]
    pub ip_allocations: Vec<IpAllocRec>,
    /// All floating IPs (B6). `#[serde(default)]` so pre-B6 snapshots restore
    /// with no floating IPs.
    #[serde(default)]
    pub floating_ips: Vec<FloatingIpRec>,
}

/// Serializable mirror of a [`Host`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HostRec {
    pub id: String,
    pub vtep_ip: [u8; 4],
    pub underlay_iface: String,
    pub underlay_mac: [u8; 6],
    pub encap: EncapName,
    pub udp_port: Option<u16>,
    pub underlay_mtu: Option<u16>,
}

/// Serializable mirror of a [`Network`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NetworkRec {
    pub vni: u32,
    pub name: String,
    pub subnet_octets: [u8; 4],
    pub subnet_prefix: u8,
    pub default_action: ActionName,
    pub drop_icmp: bool,
}

/// Serializable mirror of a [`SecurityGroup`] (B5). The `policy_id` is *not*
/// stored — it is recomputed from `name` on restore, keeping the name the single
/// source of truth for the id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityGroupRec {
    pub name: String,
    pub default_action: ActionName,
    pub drop_icmp: bool,
    pub stateful: bool,
    pub blocklist: Vec<String>,
    pub rules: Vec<PortRule>,
}

/// Serializable mirror of a [`Subnet`] (D2). The CIDR, gateway, and pool are
/// stored as an `is_v6` flag plus 16-byte address encodings (a v4 address in the
/// first four bytes), so the record round-trips losslessly and infallibly — no
/// string parsing on restore, matching the byte-oriented style of the other recs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SubnetRec {
    pub id: String,
    pub vni: u32,
    pub is_v6: bool,
    pub cidr_octets: [u8; 16],
    pub cidr_prefix: u8,
    pub gateway: Option<[u8; 16]>,
    pub pool_start: Option<[u8; 16]>,
    pub pool_end: Option<[u8; 16]>,
    pub enable_dhcp: bool,
}

/// The owner of a serialized IPAM allocation ([`IpAllocRec`]).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum IpAllocOwnerRec {
    Port(String),
    Reserved,
    Gateway,
    Floating(String),
}

/// Serializable mirror of one IPAM allocation (D2): the subnet, the allocated
/// address (16-byte encoded, family from `is_v6`), and its owner.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IpAllocRec {
    pub subnet_id: String,
    pub is_v6: bool,
    pub addr: [u8; 16],
    pub owner: IpAllocOwnerRec,
}

/// Serializable mirror of a [`FloatingIp`] (B6). The floating address and any
/// associated fixed address are stored as an `is_v6` flag plus 16-byte encodings
/// (a v4 address in the first four bytes), matching the byte-oriented style of
/// [`SubnetRec`] / [`IpAllocRec`] so the record — and the association that must
/// survive a Raft failover — round-trips losslessly and infallibly. The fixed
/// address carries its own family flag, since it may differ from the floating
/// address's family.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FloatingIpRec {
    pub id: String,
    pub vni: u32,
    pub subnet_id: String,
    pub is_v6: bool,
    pub addr: [u8; 16],
    /// The associated port id, or `None` when unassociated.
    pub assoc_port: Option<String>,
    /// The associated fixed address (present iff `assoc_port` is).
    pub assoc_fixed: Option<[u8; 16]>,
    /// The family of `assoc_fixed`.
    pub assoc_fixed_is_v6: bool,
}

/// Serializable mirror of a [`Port`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PortRec {
    pub id: String,
    pub vni: u32,
    /// Explicit security-group policy, or `None` to default to the VNI (M4).
    /// `#[serde(default)]` so snapshots written before this field deserialize as
    /// `None` (the pre-M4 policy-equals-VNI behaviour).
    #[serde(default)]
    pub policy: Option<u32>,
    pub host: String,
    pub ip: [u8; 4],
    pub mac: [u8; 6],
    pub tap: String,
}

impl Topology {
    /// Capture the whole fabric as a serializable [`FabricSnapshot`].
    pub fn to_snapshot(&self) -> FabricSnapshot {
        FabricSnapshot {
            hosts: self
                .hosts
                .values()
                .map(|h| HostRec {
                    id: h.id.clone(),
                    vtep_ip: h.vtep_ip.octets(),
                    underlay_iface: h.underlay_iface.clone(),
                    underlay_mac: h.underlay_mac,
                    encap: h.encap,
                    udp_port: h.udp_port,
                    underlay_mtu: h.underlay_mtu,
                })
                .collect(),
            networks: self
                .networks
                .values()
                .map(|n| NetworkRec {
                    vni: n.vni,
                    name: n.name.clone(),
                    subnet_octets: n.subnet.octets,
                    subnet_prefix: n.subnet.prefix,
                    default_action: n.default_action,
                    drop_icmp: n.drop_icmp,
                })
                .collect(),
            ports: self
                .ports
                .iter()
                .map(|p| PortRec {
                    id: p.id.clone(),
                    vni: p.vni,
                    policy: p.policy,
                    host: p.host.clone(),
                    ip: p.ip.octets(),
                    mac: p.mac,
                    tap: p.tap.clone(),
                })
                .collect(),
            security_groups: self
                .security_groups
                .values()
                .map(|g| SecurityGroupRec {
                    name: g.name.clone(),
                    default_action: g.default_action,
                    drop_icmp: g.drop_icmp,
                    stateful: g.stateful,
                    blocklist: g.blocklist.clone(),
                    rules: g.rules.clone(),
                })
                .collect(),
            subnets: self
                .subnets
                .values()
                .map(|s| {
                    let (cidr_octets, cidr_prefix) = match s.cidr {
                        SubnetCidr::V4(c) => {
                            let mut b = [0u8; 16];
                            b[..4].copy_from_slice(&c.octets);
                            (b, c.prefix)
                        }
                        SubnetCidr::V6(c) => (c.octets, c.prefix),
                    };
                    SubnetRec {
                        id: s.id.clone(),
                        vni: s.vni,
                        is_v6: s.cidr.is_v6(),
                        cidr_octets,
                        cidr_prefix,
                        gateway: s.gateway.map(ip_to_bytes16),
                        pool_start: s.pool.map(|p| ip_to_bytes16(p.start)),
                        pool_end: s.pool.map(|p| ip_to_bytes16(p.end)),
                        enable_dhcp: s.enable_dhcp,
                    }
                })
                .collect(),
            ip_allocations: self
                .ipam
                .iter()
                .flat_map(|(sid, allocs)| {
                    let is_v6 = self.subnets.get(sid).is_some_and(|s| s.cidr.is_v6());
                    allocs.iter().map(move |(key, owner)| IpAllocRec {
                        subnet_id: sid.clone(),
                        is_v6,
                        addr: ip_to_bytes16(u128_to_ip(*key, is_v6)),
                        owner: match owner {
                            IpAllocOwner::Port(p) => IpAllocOwnerRec::Port(p.clone()),
                            IpAllocOwner::Reserved => IpAllocOwnerRec::Reserved,
                            IpAllocOwner::Gateway => IpAllocOwnerRec::Gateway,
                            IpAllocOwner::Floating(f) => IpAllocOwnerRec::Floating(f.clone()),
                        },
                    })
                })
                .collect(),
            floating_ips: self
                .floating_ips
                .values()
                .map(|f| {
                    let (assoc_port, assoc_fixed, assoc_fixed_is_v6) = match &f.association {
                        Some(a) => (
                            Some(a.port_id.clone()),
                            Some(ip_to_bytes16(a.fixed_addr)),
                            a.fixed_addr.is_ipv6(),
                        ),
                        None => (None, None, false),
                    };
                    FloatingIpRec {
                        id: f.id.clone(),
                        vni: f.vni,
                        subnet_id: f.subnet_id.clone(),
                        is_v6: f.addr.is_ipv6(),
                        addr: ip_to_bytes16(f.addr),
                        assoc_port,
                        assoc_fixed,
                        assoc_fixed_is_v6,
                    }
                })
                .collect(),
        }
    }

    /// Rebuild a [`Topology`] from a snapshot (verbatim — ports keep their stored
    /// id/ip/mac, no re-allocation).
    pub fn from_snapshot(snap: &FabricSnapshot) -> Self {
        let mut t = Topology::new();
        for h in &snap.hosts {
            t.hosts.insert(
                h.id.clone(),
                Host {
                    id: h.id.clone(),
                    vtep_ip: Ipv4Addr::from(h.vtep_ip),
                    underlay_iface: h.underlay_iface.clone(),
                    underlay_mac: h.underlay_mac,
                    encap: h.encap,
                    udp_port: h.udp_port,
                    underlay_mtu: h.underlay_mtu,
                },
            );
        }
        for n in &snap.networks {
            t.networks.insert(
                n.vni,
                Network {
                    vni: n.vni,
                    name: n.name.clone(),
                    subnet: Cidr4 {
                        octets: n.subnet_octets,
                        prefix: n.subnet_prefix,
                    },
                    default_action: n.default_action,
                    drop_icmp: n.drop_icmp,
                },
            );
        }
        for p in &snap.ports {
            t.ports.push(Port {
                id: p.id.clone(),
                vni: p.vni,
                policy: p.policy,
                host: p.host.clone(),
                ip: Ipv4Addr::from(p.ip),
                mac: p.mac,
                tap: p.tap.clone(),
            });
        }
        for g in &snap.security_groups {
            t.security_groups.insert(
                g.name.clone(),
                SecurityGroup {
                    name: g.name.clone(),
                    default_action: g.default_action,
                    drop_icmp: g.drop_icmp,
                    stateful: g.stateful,
                    blocklist: g.blocklist.clone(),
                    rules: g.rules.clone(),
                },
            );
        }
        for s in &snap.subnets {
            let cidr = if s.is_v6 {
                SubnetCidr::V6(Cidr6 {
                    octets: s.cidr_octets,
                    prefix: s.cidr_prefix,
                })
            } else {
                let mut o = [0u8; 4];
                o.copy_from_slice(&s.cidr_octets[..4]);
                SubnetCidr::V4(Cidr4 {
                    octets: o,
                    prefix: s.cidr_prefix,
                })
            };
            t.subnets.insert(
                s.id.clone(),
                Subnet {
                    id: s.id.clone(),
                    vni: s.vni,
                    cidr,
                    gateway: s.gateway.map(|b| bytes16_to_ip(b, s.is_v6)),
                    pool: match (s.pool_start, s.pool_end) {
                        (Some(start), Some(end)) => Some(AllocRange {
                            start: bytes16_to_ip(start, s.is_v6),
                            end: bytes16_to_ip(end, s.is_v6),
                        }),
                        _ => None,
                    },
                    enable_dhcp: s.enable_dhcp,
                },
            );
        }
        // IPAM is restored verbatim (not re-derived) so allocations survive a
        // failover exactly as they were — including the auto-reserved gateway,
        // which is therefore not re-inserted here.
        for a in &snap.ip_allocations {
            let key = ip_to_u128(bytes16_to_ip(a.addr, a.is_v6));
            let owner = match &a.owner {
                IpAllocOwnerRec::Port(p) => IpAllocOwner::Port(p.clone()),
                IpAllocOwnerRec::Reserved => IpAllocOwner::Reserved,
                IpAllocOwnerRec::Gateway => IpAllocOwner::Gateway,
                IpAllocOwnerRec::Floating(f) => IpAllocOwner::Floating(f.clone()),
            };
            t.ipam
                .entry(a.subnet_id.clone())
                .or_default()
                .insert(key, owner);
        }
        // Floating IPs (B6) are restored verbatim — their address is already in
        // the IPAM set above under a Floating owner, and the association is
        // reconstructed from the record so it survives a failover.
        for f in &snap.floating_ips {
            let association = match (&f.assoc_port, f.assoc_fixed) {
                (Some(port_id), Some(fixed)) => Some(FloatingAssociation {
                    port_id: port_id.clone(),
                    fixed_addr: bytes16_to_ip(fixed, f.assoc_fixed_is_v6),
                }),
                _ => None,
            };
            t.floating_ips.insert(
                f.id.clone(),
                FloatingIp {
                    id: f.id.clone(),
                    vni: f.vni,
                    subnet_id: f.subnet_id.clone(),
                    addr: bytes16_to_ip(f.addr, f.is_v6),
                    association,
                },
            );
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use velstra_common::parse_cidr_v4;

    use super::*;

    fn host(id: &str, vtep: &str, last_mac: u8) -> Host {
        Host {
            id: id.to_string(),
            vtep_ip: vtep.parse::<Ipv4Addr>().unwrap(),
            underlay_iface: "eth0".to_string(),
            underlay_mac: [0x02, 0, 0, 0, 0, last_mac],
            encap: EncapName::Vxlan,
            udp_port: None,
            underlay_mtu: None,
        }
    }

    fn network(vni: u32, name: &str, subnet: &str) -> Network {
        Network {
            vni,
            name: name.to_string(),
            subnet: parse_cidr_v4(subnet).unwrap(),
            default_action: ActionName::Pass,
            drop_icmp: false,
        }
    }

    #[test]
    fn rejects_duplicate_tap_binding() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.create_port(100, "h1", "tap0", None, None).unwrap();
        // Same (host, tap) → rejected, even on a different IP/allocation.
        assert!(t.create_port(100, "h1", "tap0", None, None).is_err());
        // A different tap on the same host is fine.
        assert!(t.create_port(100, "h1", "tap1", None, None).is_ok());
    }

    #[test]
    fn remove_host_and_network_require_no_ports() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        // Both are blocked while the port exists.
        assert!(t.remove_host("h1").is_err());
        assert!(t.remove_network(100).is_err());
        // After removing the port, both succeed and report existence.
        assert!(t.remove_port(&p.id));
        assert!(t.remove_network(100).unwrap());
        assert!(t.remove_host("h1").unwrap());
        // Removing again reports "did not exist".
        assert!(!t.remove_host("h1").unwrap());
    }

    #[test]
    fn ipam_allocates_sequentially_and_skips_taken() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();

        let p1 = t.create_port(100, "h1", "tap0", None, None).unwrap();
        let p2 = t.create_port(100, "h1", "tap1", None, None).unwrap();
        assert_eq!(p1.ip, "192.168.50.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(p2.ip, "192.168.50.2".parse::<Ipv4Addr>().unwrap());
        // MAC is locally-administered + the address octets.
        assert_eq!(p1.mac, [0x02, 0x00, 192, 168, 50, 1]);

        // An explicit IP is honoured and then excluded from future allocations.
        let p3 = t
            .create_port(
                100,
                "h1",
                "tap2",
                Some("192.168.50.9".parse::<Ipv4Addr>().unwrap()),
                None,
            )
            .unwrap();
        assert_eq!(p3.ip, "192.168.50.9".parse::<Ipv4Addr>().unwrap());
        let p4 = t.create_port(100, "h1", "tap3", None, None).unwrap();
        assert_eq!(p4.ip, "192.168.50.3".parse::<Ipv4Addr>().unwrap()); // skips .9
    }

    #[test]
    fn rejects_duplicate_and_out_of_subnet_ips() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.create_port(
            100,
            "h1",
            "tap0",
            Some("192.168.50.5".parse::<Ipv4Addr>().unwrap()),
            None,
        )
        .unwrap();
        assert!(
            t.create_port(
                100,
                "h1",
                "tap1",
                Some("192.168.50.5".parse::<Ipv4Addr>().unwrap()),
                None,
            )
            .is_err()
        );
        assert!(
            t.create_port(
                100,
                "h1",
                "tap2",
                Some("10.0.0.5".parse::<Ipv4Addr>().unwrap()),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unknown_network_or_host_and_bad_vni() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        assert!(t.create_port(100, "h1", "tap0", None, None).is_err()); // no network
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        assert!(t.create_port(100, "ghost", "tap0", None, None).is_err()); // no host
        assert!(t.add_network(network(0, "bad", "10.0.0.0/24")).is_err()); // vni 0
    }

    #[test]
    fn rejects_networks_in_the_reserved_evpn_vni_range() {
        let mut t = Topology::new();
        // The reserved base itself and anything above it are refused so a future
        // EVPN/FPM learning path owns them exclusively (M5 map-ownership).
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE, "evpn", "10.1.0.0/24"))
                .is_err()
        );
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE + 42, "evpn2", "10.2.0.0/24"))
                .is_err()
        );
        // The last orchestrator-owned VNI just below the reserved base is fine.
        assert!(
            t.add_network(network(EVPN_RESERVED_VNI_BASE - 1, "ok", "10.3.0.0/24"))
                .is_ok()
        );
    }

    #[test]
    fn derives_local_interface_and_remote_tunnel_neighbor() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();

        let pa = t.create_port(5000, "h1", "tapA", None, None).unwrap(); // .1 on h1
        let pb = t.create_port(5000, "h2", "tapB", None, None).unwrap(); // .2 on h2

        // --- h1's derived config ---
        let cfg = t.derive("h1").unwrap();
        let rt = cfg.resolve().expect("derived config must be valid");

        // Overlay endpoint is h1's.
        let ov = rt.overlay.as_ref().unwrap();
        assert_eq!(ov.local_vtep_ip, [10, 10, 0, 1]);

        // One policy for the participating network (id == vni).
        assert!(rt.policies.iter().any(|p| p.id == 5000));

        // Local port pa → an interface binding on tapA, vni 5000.
        let iface = rt.interfaces.iter().find(|i| i.name == "tapA").unwrap();
        assert_eq!(iface.policy, 5000);
        assert_eq!(iface.vni, 5000);
        // The remote port (pb on h2) is NOT a local interface here.
        assert!(!rt.interfaces.iter().any(|i| i.name == "tapB"));

        // Remote port pb → a tunnel to h2's VTEP + an ARP neighbour.
        assert_eq!(rt.tunnels.len(), 1);
        let tun = &rt.tunnels[0];
        assert_eq!(tun.vni, 5000);
        assert_eq!(tun.inner_dst.octets, pb.ip.octets());
        assert_eq!(tun.inner_dst.prefix, 32);
        assert_eq!(tun.remote_vtep_ip, [10, 10, 0, 2]);
        assert_eq!(tun.outer_dst_mac, [0x02, 0, 0, 0, 0, 0x22]); // h2's underlay MAC

        assert_eq!(rt.neighbors.len(), 1);
        assert_eq!(rt.neighbors[0].ip, pb.ip.octets());
        assert_eq!(rt.neighbors[0].mac, [0x02, 0x00, 192, 168, 100, 2]);

        // Symmetry: h2 sees pa as the remote tunnel/neighbour, pb as local.
        let cfg2 = t.derive("h2").unwrap().resolve().unwrap();
        assert!(cfg2.interfaces.iter().any(|i| i.name == "tapB"));
        assert_eq!(cfg2.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(cfg2.tunnels[0].remote_vtep_ip, [10, 10, 0, 1]);
    }

    #[test]
    fn host_without_ports_on_a_network_gets_no_tunnel_to_it() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_host(host("h3", "10.10.0.3", 0x33));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        t.create_port(5000, "h1", "tapA", None, None).unwrap();
        t.create_port(5000, "h2", "tapB", None, None).unwrap();

        // h3 has no port on network 5000 → it gets no policy, no tunnels.
        let cfg3 = t.derive("h3").unwrap().resolve().unwrap();
        assert!(cfg3.tunnels.is_empty());
        assert!(cfg3.neighbors.is_empty());
        assert!(cfg3.interfaces.is_empty());
        // Only the implicit default policy 0 remains.
        assert_eq!(cfg3.policies.len(), 1);
        assert_eq!(cfg3.policies[0].id, 0);
    }

    #[test]
    fn snapshot_roundtrip_is_lossless() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        let p = t.create_port(5000, "h1", "tapA", None, None).unwrap();

        let snap = t.to_snapshot();
        let restored = Topology::from_snapshot(&snap);
        // Same derived config and same port identity after a round-trip.
        assert_eq!(derive_configs_str(&t), derive_configs_str(&restored));
        assert_eq!(restored.ports(), &[p]);
    }

    // Small helper: a stable string view of a host's derived config for equality.
    fn derive_configs_str(t: &Topology) -> Vec<String> {
        let mut hosts: Vec<_> = t.hosts().map(|h| h.id.clone()).collect();
        hosts.sort();
        hosts
            .iter()
            .map(|id| format!("{:?}", t.derive(id)))
            .collect()
    }

    #[test]
    fn removing_a_port_withdraws_it_from_peer_configs() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        t.create_port(5000, "h1", "tapA", None, None).unwrap();
        let pb = t.create_port(5000, "h2", "tapB", None, None).unwrap();

        assert_eq!(t.derive("h1").unwrap().resolve().unwrap().tunnels.len(), 1);
        assert!(t.remove_port(&pb.id));
        // h1 no longer tunnels to the removed peer.
        let cfg = t.derive("h1").unwrap().resolve().unwrap();
        assert!(cfg.tunnels.is_empty());
        assert!(cfg.neighbors.is_empty());
    }

    #[test]
    fn migrating_a_port_preserves_identity_and_repoints_peers() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_host(host("h2", "10.10.0.2", 0x22));
        t.add_host(host("h3", "10.10.0.3", 0x33));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        // pa lives on h1; pc gives h3 a port on the network so it tunnels to pa.
        let pa = t.create_port(5000, "h1", "tapA", None, None).unwrap();
        t.create_port(5000, "h3", "tapC", None, None).unwrap();

        // Before: h3 tunnels to pa via h1's VTEP.
        let h3 = t.derive("h3").unwrap().resolve().unwrap();
        assert_eq!(h3.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(h3.tunnels[0].remote_vtep_ip, [10, 10, 0, 1]); // h1

        // Migrate pa from h1 to h2 with a new tap.
        let moved = t.migrate_port(&pa.id, "h2", "tapA2").unwrap();
        // Identity preserved: same id, ip, mac, vni.
        assert_eq!(moved.id, pa.id);
        assert_eq!(moved.ip, pa.ip);
        assert_eq!(moved.mac, pa.mac);
        assert_eq!(moved.host, "h2");
        assert_eq!(moved.tap, "tapA2");

        // After: the port is local on h2 (interface tapA2), and h3's tunnel to it
        // now points at h2's VTEP — same inner IP/MAC.
        let h2 = t.derive("h2").unwrap().resolve().unwrap();
        assert!(h2.interfaces.iter().any(|i| i.name == "tapA2"));
        let h3 = t.derive("h3").unwrap().resolve().unwrap();
        assert_eq!(h3.tunnels[0].inner_dst.octets, pa.ip.octets());
        assert_eq!(h3.tunnels[0].remote_vtep_ip, [10, 10, 0, 2]); // now h2
        // h1 no longer hosts it locally.
        let h1 = t.derive("h1").unwrap().resolve().unwrap();
        assert!(!h1.interfaces.iter().any(|i| i.name == "tapA"));

        // Unknown host / port are errors.
        assert!(t.migrate_port(&pa.id, "ghost", "tap").is_err());
        assert!(t.migrate_port("port-nope", "h2", "tap").is_err());
    }

    #[test]
    fn port_policy_decouples_from_vni() {
        // M4: a port may carry a security-group policy distinct from its VNI. The
        // derived interface then binds that policy while staying on the VNI's
        // overlay segment — the eBPF IFACE_POLICY vs IFACE_VNI split the model now
        // exposes.
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();

        // Explicit security-group policy 42, on VNI 5000.
        let p = t.create_port(5000, "h1", "tapSG", None, Some(42)).unwrap();
        assert_eq!(p.effective_policy(), 42);

        let cfg = t.derive("h1").unwrap();
        let iface = cfg.interfaces.iter().find(|i| i.name == "tapSG").unwrap();
        assert_eq!(
            iface.policy, 42,
            "interface firewall policy == security group"
        );
        assert_eq!(
            iface.vni,
            Some(5000),
            "…while staying on VNI 5000's segment"
        );

        // The default (policy = None) still collapses to the VNI.
        let d = t.create_port(5000, "h1", "tapDef", None, None).unwrap();
        assert_eq!(d.effective_policy(), 5000);

        // Survives a snapshot round-trip.
        let restored = Topology::from_snapshot(&t.to_snapshot());
        let rp = restored.ports().iter().find(|q| q.id == p.id).unwrap();
        assert_eq!(rp.policy, Some(42));
    }

    // === B5: security groups ================================================

    /// A `[[port_rule]]`-shaped rule for tests.
    fn rule(proto: velstra_config::ProtoName, port: u16, action: ActionName) -> PortRule {
        PortRule {
            proto,
            port,
            action,
            log: false,
            src: None,
        }
    }

    fn sg(name: &str, rules: Vec<PortRule>) -> SecurityGroup {
        SecurityGroup {
            name: name.to_string(),
            default_action: ActionName::Drop,
            drop_icmp: false,
            stateful: true,
            blocklist: Vec::new(),
            rules,
        }
    }

    #[test]
    fn security_group_policy_id_is_deterministic_ordered_and_in_band() {
        use velstra_config::ProtoName;

        // Same name → same id, every time and regardless of the rules it carries.
        let a1 = security_group_policy_id("web");
        let a2 = security_group_policy_id("web");
        assert_eq!(a1, a2);
        assert_eq!(
            sg("web", vec![rule(ProtoName::Tcp, 80, ActionName::Pass)]).policy_id(),
            sg("web", vec![]).policy_id(),
            "id depends only on the name, not the rules — stable across edits"
        );

        // Different names → (almost surely) different ids.
        assert_ne!(a1, security_group_policy_id("db"));

        // Every id lands in the reserved band, so it can never collide with a
        // VNI-derived policy id (all ≤ 24 bits, i.e. < the band base).
        for name in ["web", "db", "", "a-very-long-security-group-name-42"] {
            let pid = security_group_policy_id(name);
            assert!(pid >= SECURITY_GROUP_POLICY_BASE);
            assert!(pid > EVPN_RESERVED_VNI_BASE);
            assert!(pid > 0xFF_FFFF, "must sit above the whole 24-bit VNI space");
        }
    }

    #[test]
    fn add_security_group_rejects_empty_and_duplicate_names() {
        let mut t = Topology::new();
        assert!(t.add_security_group(sg("", vec![])).is_err()); // empty name
        t.add_security_group(sg("web", vec![])).unwrap();
        assert!(t.add_security_group(sg("web", vec![])).is_err()); // duplicate
        // A distinct name is accepted and both are retrievable.
        t.add_security_group(sg("db", vec![])).unwrap();
        assert!(t.security_group("web").is_some());
        assert_eq!(t.security_groups().count(), 2);
        assert!(t.security_group("missing").is_none());
    }

    #[test]
    fn bind_and_unbind_port_resolves_security_group_policy_id() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_security_group(sg("web", vec![])).unwrap();
        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        assert_eq!(p.effective_policy(), 100); // defaults to the VNI

        // Bind → the port's policy is the group's deterministic id.
        let bound = t.set_port_security_group(&p.id, Some("web")).unwrap();
        assert_eq!(bound.policy, Some(security_group_policy_id("web")));
        assert_eq!(bound.effective_policy(), security_group_policy_id("web"));

        // Unbind → back to the VNI default.
        let cleared = t.set_port_security_group(&p.id, None).unwrap();
        assert_eq!(cleared.policy, None);
        assert_eq!(cleared.effective_policy(), 100);

        // Unknown port / group are errors.
        assert!(t.set_port_security_group("nope", Some("web")).is_err());
        assert!(t.set_port_security_group(&p.id, Some("ghost")).is_err());
    }

    #[test]
    fn derive_emits_bound_security_group_as_a_resolvable_policy() {
        use velstra_common::ip_proto;
        use velstra_config::ProtoName;

        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        // A "web" group: default-drop, allow tcp/80, block tcp/22.
        t.add_security_group(sg(
            "web",
            vec![
                rule(ProtoName::Tcp, 80, ActionName::Pass),
                rule(ProtoName::Tcp, 22, ActionName::Drop),
            ],
        ))
        .unwrap();

        let p = t.create_port(5000, "h1", "tapW", None, None).unwrap();
        t.set_port_security_group(&p.id, Some("web")).unwrap();
        let pid = security_group_policy_id("web");

        let cfg = t.derive("h1").unwrap();
        // The derived config now RESOLVES — before B5 a decoupled port policy had
        // no `[[policy]]` block and `resolve()` would reject the dangling id.
        let rt = cfg
            .resolve()
            .expect("bound security group makes derive resolvable");

        // The interface binds the group's policy id while staying on the VNI.
        let iface = rt.interfaces.iter().find(|i| i.name == "tapW").unwrap();
        assert_eq!(iface.policy, pid);
        assert_eq!(iface.vni, 5000);

        // A `[[policy]]` for the group carries its rules (stateful, tcp/80 pass,
        // tcp/22 drop) — plus the network's own policy (id == vni).
        let gp = rt.policies.iter().find(|pl| pl.id == pid).unwrap();
        assert!(gp.global.has_flag(velstra_common::ConfigFlags::STATEFUL));
        assert!(gp.port_rules.iter().any(|(k, _, a, _)| {
            *k == velstra_common::PortKey::new(ip_proto::TCP, 80)
                && *a == velstra_common::Action::Pass
        }));
        assert!(gp.port_rules.iter().any(|(k, _, a, _)| {
            *k == velstra_common::PortKey::new(ip_proto::TCP, 22)
                && *a == velstra_common::Action::Drop
        }));
        assert!(rt.policies.iter().any(|pl| pl.id == 5000));
    }

    #[test]
    fn one_group_bound_by_many_ports_emits_a_single_policy_block() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        t.add_security_group(sg("web", vec![])).unwrap();
        for tap in ["tapA", "tapB", "tapC"] {
            let p = t.create_port(5000, "h1", tap, None, None).unwrap();
            t.set_port_security_group(&p.id, Some("web")).unwrap();
        }
        let pid = security_group_policy_id("web");
        let rt = t.derive("h1").unwrap().resolve().unwrap();
        assert_eq!(
            rt.policies.iter().filter(|pl| pl.id == pid).count(),
            1,
            "the group is emitted exactly once, no matter how many ports bind it"
        );
    }

    #[test]
    fn remove_security_group_is_blocked_while_a_port_binds_it() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_security_group(sg("web", vec![])).unwrap();
        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        t.set_port_security_group(&p.id, Some("web")).unwrap();

        // Bound → removal refused.
        assert!(t.remove_security_group("web").is_err());
        // Rebind away, then removal succeeds and reports existence.
        t.set_port_security_group(&p.id, None).unwrap();
        assert!(t.remove_security_group("web").unwrap());
        // Removing a non-existent group reports "did not exist".
        assert!(!t.remove_security_group("web").unwrap());
    }

    #[test]
    fn security_groups_survive_a_snapshot_roundtrip() {
        use velstra_config::ProtoName;

        let mut t = Topology::new();
        t.add_host(host("h1", "10.10.0.1", 0x11));
        t.add_network(network(5000, "blue", "192.168.100.0/24"))
            .unwrap();
        let mut g = sg("web", vec![rule(ProtoName::Tcp, 443, ActionName::Pass)]);
        g.blocklist = vec!["203.0.113.0/24".to_string()];
        t.add_security_group(g.clone()).unwrap();
        let p = t.create_port(5000, "h1", "tapW", None, None).unwrap();
        t.set_port_security_group(&p.id, Some("web")).unwrap();

        let restored = Topology::from_snapshot(&t.to_snapshot());
        // The group came back verbatim…
        assert_eq!(restored.security_group("web"), Some(&g));
        // …the port's binding survived…
        let rp = restored.ports().iter().find(|q| q.id == p.id).unwrap();
        assert_eq!(rp.policy, Some(security_group_policy_id("web")));
        // …and the derived config is byte-identical across the round-trip.
        assert_eq!(
            format!("{:?}", t.derive("h1")),
            format!("{:?}", restored.derive("h1"))
        );
    }

    // === D2: first-class subnets + IPAM =====================================

    use velstra_common::parse_cidr_v6;

    fn v4_subnet(id: &str, vni: u32, cidr: &str) -> Subnet {
        Subnet {
            id: id.to_string(),
            vni,
            cidr: SubnetCidr::V4(parse_cidr_v4(cidr).unwrap()),
            gateway: None,
            pool: None,
            enable_dhcp: false,
        }
    }

    fn v6_subnet(id: &str, vni: u32, cidr: &str) -> Subnet {
        Subnet {
            id: id.to_string(),
            vni,
            cidr: SubnetCidr::V6(parse_cidr_v6(cidr).unwrap()),
            gateway: None,
            pool: None,
            enable_dhcp: false,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn add_subnet_validates_id_network_gateway_and_pool() {
        let mut t = Topology::new();
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();

        // Empty id, unknown network, duplicate id.
        assert!(t.add_subnet(v4_subnet("", 100, "10.0.0.0/24")).is_err());
        assert!(
            t.add_subnet(v4_subnet("s-ghost", 999, "10.0.0.0/24"))
                .is_err()
        );
        t.add_subnet(v4_subnet("s1", 100, "192.168.50.0/24"))
            .unwrap();
        assert!(
            t.add_subnet(v4_subnet("s1", 100, "192.168.50.0/24"))
                .is_err()
        );

        // Gateway outside the CIDR (and wrong-family gateway) are rejected.
        let mut bad_gw = v4_subnet("s2", 100, "192.168.60.0/24");
        bad_gw.gateway = Some(ip("10.9.9.1"));
        assert!(t.add_subnet(bad_gw).is_err());
        let mut wrong_family = v4_subnet("s3", 100, "192.168.60.0/24");
        wrong_family.gateway = Some(ip("2001:db8::1"));
        assert!(t.add_subnet(wrong_family).is_err());

        // Inverted / out-of-CIDR pools are rejected.
        let mut inverted = v4_subnet("s4", 100, "192.168.60.0/24");
        inverted.pool = Some(AllocRange {
            start: ip("192.168.60.100"),
            end: ip("192.168.60.10"),
        });
        assert!(t.add_subnet(inverted).is_err());
        let mut out_of_cidr = v4_subnet("s5", 100, "192.168.60.0/24");
        out_of_cidr.pool = Some(AllocRange {
            start: ip("192.168.60.10"),
            end: ip("192.168.99.10"),
        });
        assert!(t.add_subnet(out_of_cidr).is_err());

        // Listing and per-network views.
        assert!(t.subnet("s1").is_some());
        assert_eq!(t.subnets().count(), 1);
        assert_eq!(t.network_subnets(100).count(), 1);
        assert_eq!(t.network_subnets(999).count(), 0);
    }

    #[test]
    fn ipam_allocates_deterministically_skips_gateway_and_reports_exhaustion() {
        let mut t = Topology::new();
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        // A /29 with a gateway at .1: usable pool is .1..=.6 minus the gateway.
        let mut s = v4_subnet("s1", 100, "192.168.50.0/29");
        s.gateway = Some(ip("192.168.50.1"));
        t.add_subnet(s).unwrap();

        // The gateway (.1) is reserved, so the first hand-out is .2, then .3…
        assert_eq!(t.allocate("s1", None).unwrap(), ip("192.168.50.2"));
        assert_eq!(t.allocate("s1", None).unwrap(), ip("192.168.50.3"));

        // A specific request is honoured, then excluded.
        assert_eq!(
            t.allocate("s1", Some(ip("192.168.50.5"))).unwrap(),
            ip("192.168.50.5")
        );
        // Re-requesting an allocated address fails; so does the gateway and an
        // address outside the pool / subnet.
        assert!(t.allocate("s1", Some(ip("192.168.50.5"))).is_err());
        assert!(t.allocate("s1", Some(ip("192.168.50.1"))).is_err()); // gateway
        assert!(t.allocate("s1", Some(ip("192.168.50.7"))).is_err()); // broadcast (out of pool)
        assert!(t.allocate("s1", Some(ip("10.0.0.9"))).is_err()); // out of subnet

        // Drain the rest of the pool (.4, .6) then exhaust.
        assert_eq!(t.allocate("s1", None).unwrap(), ip("192.168.50.4"));
        assert_eq!(t.allocate("s1", None).unwrap(), ip("192.168.50.6"));
        assert!(t.allocate("s1", None).is_err()); // exhausted

        // Releasing frees the address for re-allocation; a no-op release is false.
        assert!(t.release("s1", ip("192.168.50.4")));
        assert!(!t.release("s1", ip("192.168.50.4")));
        assert_eq!(t.allocate("s1", None).unwrap(), ip("192.168.50.4"));
    }

    #[test]
    fn port_binds_dual_stack_addresses_from_v4_and_v6_subnets() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        let mut s4 = v4_subnet("s4", 100, "192.168.50.0/24");
        s4.gateway = Some(ip("192.168.50.1"));
        let mut s6 = v6_subnet("s6", 100, "2001:db8::/64");
        s6.gateway = Some(ip("2001:db8::1"));
        t.add_subnet(s4).unwrap();
        t.add_subnet(s6).unwrap();

        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();

        // Bind a v4 and a v6 address → a dual-stack port.
        let a4 = t.bind_port_subnet(&p.id, "s4", None).unwrap();
        let a6 = t.bind_port_subnet(&p.id, "s6", None).unwrap();
        assert_eq!(a4.addr, ip("192.168.50.2")); // .1 gateway reserved
        assert_eq!(a6.addr, ip("2001:db8::2")); // ::1 gateway reserved
        assert!(a4.addr.is_ipv4() && a6.addr.is_ipv6());

        // port_addrs returns both, deterministically sorted by (subnet, addr).
        let addrs = t.port_addrs(&p.id);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], a4); // "s4" < "s6"
        assert_eq!(addrs[1], a6);

        // Binding requires the subnet be on the port's network.
        t.add_network(network(200, "red", "10.1.0.0/24")).unwrap();
        t.add_subnet(v4_subnet("s-other", 200, "10.1.0.0/24"))
            .unwrap();
        assert!(t.bind_port_subnet(&p.id, "s-other", None).is_err());
        // Unknown port / subnet are errors.
        assert!(t.bind_port_subnet("nope", "s4", None).is_err());
        assert!(t.bind_port_subnet(&p.id, "ghost", None).is_err());
    }

    #[test]
    fn unbind_and_remove_port_release_ipam_addresses() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("s4", 100, "192.168.50.0/24"))
            .unwrap();
        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        let a = t.bind_port_subnet(&p.id, "s4", None).unwrap();

        // Unbind only succeeds for the owning port; a wrong owner is a no-op.
        assert!(!t.unbind_port_address("someone-else", "s4", a.addr));
        assert!(t.unbind_port_address(&p.id, "s4", a.addr));
        assert!(t.port_addrs(&p.id).is_empty());
        // The address is free again after unbind.
        assert_eq!(t.allocate("s4", Some(a.addr)).unwrap(), a.addr);
        t.release("s4", a.addr);

        // Removing the port releases everything it held.
        let a2 = t.bind_port_subnet(&p.id, "s4", None).unwrap();
        assert!(!t.port_addrs(&p.id).is_empty());
        assert!(t.remove_port(&p.id));
        assert!(t.port_addrs(&p.id).is_empty());
        assert_eq!(t.allocate("s4", Some(a2.addr)).unwrap(), a2.addr); // freed
    }

    #[test]
    fn remove_subnet_blocked_while_allocated_gateway_does_not_block() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        let mut s = v4_subnet("s4", 100, "192.168.50.0/24");
        s.gateway = Some(ip("192.168.50.1"));
        t.add_subnet(s).unwrap();

        // A gateway-only subnet still removes (the reservation doesn't block).
        assert!(t.subnet("s4").is_some());
        // Allocate → removal blocked.
        let addr = t.allocate("s4", None).unwrap();
        assert!(t.remove_subnet("s4").is_err());
        // Release → removal succeeds and reports existence.
        t.release("s4", addr);
        assert!(t.remove_subnet("s4").unwrap());
        // Removing a non-existent subnet reports "did not exist".
        assert!(!t.remove_subnet("s4").unwrap());
    }

    #[test]
    fn remove_network_blocked_while_a_subnet_references_it() {
        let mut t = Topology::new();
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("s4", 100, "192.168.50.0/24"))
            .unwrap();
        // The subnet keeps the network alive.
        assert!(t.remove_network(100).is_err());
        assert!(t.remove_subnet("s4").unwrap());
        assert!(t.remove_network(100).unwrap());
    }

    #[test]
    fn subnets_and_ipam_survive_a_snapshot_roundtrip() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        let mut s4 = v4_subnet("s4", 100, "192.168.50.0/24");
        s4.gateway = Some(ip("192.168.50.1"));
        s4.enable_dhcp = true;
        s4.pool = Some(AllocRange {
            start: ip("192.168.50.10"),
            end: ip("192.168.50.20"),
        });
        let mut s6 = v6_subnet("s6", 100, "2001:db8::/64");
        s6.gateway = Some(ip("2001:db8::1"));
        t.add_subnet(s4.clone()).unwrap();
        t.add_subnet(s6).unwrap();

        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        let a4 = t.bind_port_subnet(&p.id, "s4", None).unwrap(); // .10 (pool start)
        let a6 = t.bind_port_subnet(&p.id, "s6", None).unwrap(); // ::2
        let reserved = t.allocate("s4", Some(ip("192.168.50.15"))).unwrap();
        assert_eq!(a4.addr, ip("192.168.50.10"));

        let restored = Topology::from_snapshot(&t.to_snapshot());

        // Subnet came back verbatim (CIDR, gateway, pool, dhcp flag).
        assert_eq!(restored.subnet("s4"), t.subnet("s4"));
        assert_eq!(restored.subnet("s4").unwrap(), &s4);
        assert!(restored.subnet("s6").unwrap().cidr.is_v6());

        // The port's dual-stack bindings survived.
        let addrs = restored.port_addrs(&p.id);
        assert!(
            addrs
                .iter()
                .any(|x| x.addr == a4.addr && x.subnet_id == "s4")
        );
        assert!(
            addrs
                .iter()
                .any(|x| x.addr == a6.addr && x.subnet_id == "s6")
        );

        // The used-address set is preserved: none of the live addresses (gateway,
        // port bindings, standalone reservation) can be re-handed-out, so the next
        // free v4 address is .11 (pool = .10..=.20, .10 and .15 taken).
        assert!(restored.clone().allocate("s4", Some(a4.addr)).is_err());
        assert!(restored.clone().allocate("s4", Some(reserved)).is_err());
        assert_eq!(
            restored.clone().allocate("s4", None).unwrap(),
            ip("192.168.50.11")
        );
    }

    // === B6: floating IPs ===================================================

    #[test]
    fn floating_ip_allocation_is_ipam_backed_deterministic_and_exhaustible() {
        let mut t = Topology::new();
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        // A /29 external subnet with a gateway at .1 → usable pool .1..=.6 minus
        // the gateway = five free addresses (.2..=.6).
        let mut ext = v4_subnet("ext", 100, "203.0.113.0/29");
        ext.gateway = Some(ip("203.0.113.1"));
        t.add_subnet(ext).unwrap();

        // Lowest free address first (.2; the gateway .1 is reserved), tagged with
        // the floating subnet's vni and its derived id.
        let f1 = t.allocate_floating_ip("ext", None).unwrap();
        assert_eq!(f1.addr, ip("203.0.113.2"));
        assert_eq!(f1.vni, 100);
        assert_eq!(f1.subnet_id, "ext");
        assert_eq!(f1.id, "fip-100-203.0.113.2");
        assert!(f1.association.is_none());

        // A specific request is honoured, then excluded from future hand-outs.
        let f2 = t
            .allocate_floating_ip("ext", Some(ip("203.0.113.5")))
            .unwrap();
        assert_eq!(f2.addr, ip("203.0.113.5"));
        let f3 = t.allocate_floating_ip("ext", None).unwrap();
        assert_eq!(f3.addr, ip("203.0.113.3")); // skips the taken .2 and .5

        // The floating address is reserved in IPAM — a port can't be handed it,
        // and re-requesting it as a floating IP fails.
        assert!(t.allocate("ext", Some(ip("203.0.113.2"))).is_err());
        assert!(
            t.allocate_floating_ip("ext", Some(ip("203.0.113.5")))
                .is_err()
        );
        // An unknown subnet is an error.
        assert!(t.allocate_floating_ip("ghost", None).is_err());

        // Drain the rest of the pool (.4, .6) then exhaust.
        t.allocate_floating_ip("ext", None).unwrap(); // .4
        t.allocate_floating_ip("ext", None).unwrap(); // .6
        assert!(t.allocate_floating_ip("ext", None).is_err()); // exhausted

        // Lookups.
        assert!(t.floating_ip(&f1.id).is_some());
        assert!(t.floating_ip("fip-100-203.0.113.99").is_none());
        assert_eq!(t.floating_ips().count(), 5);
    }

    #[test]
    fn associate_and_disassociate_validate_and_map_one_to_one() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        let mut ext = v4_subnet("ext", 100, "203.0.113.0/29");
        ext.gateway = Some(ip("203.0.113.1"));
        t.add_subnet(ext).unwrap();

        // A port holding the legacy fixed IP .10.
        let p = t
            .create_port(
                100,
                "h1",
                "tap0",
                Some("192.168.50.10".parse().unwrap()),
                None,
            )
            .unwrap();
        let f = t.allocate_floating_ip("ext", None).unwrap(); // .2

        // Associating to an address the port does not hold fails; so do an unknown
        // floating IP and an unknown port.
        assert!(
            t.associate_floating_ip(&f.id, &p.id, ip("192.168.50.99"))
                .is_err()
        );
        assert!(
            t.associate_floating_ip("nope", &p.id, ip("192.168.50.10"))
                .is_err()
        );
        assert!(
            t.associate_floating_ip(&f.id, "ghost", ip("192.168.50.10"))
                .is_err()
        );

        // Associate to the port's fixed address (1:1).
        let assoc = t
            .associate_floating_ip(&f.id, &p.id, ip("192.168.50.10"))
            .unwrap();
        let a = assoc.association.unwrap();
        assert_eq!(a.port_id, p.id);
        assert_eq!(a.fixed_addr, ip("192.168.50.10"));

        // Re-associating an already-associated floating IP fails (must clear it).
        assert!(
            t.associate_floating_ip(&f.id, &p.id, ip("192.168.50.10"))
                .is_err()
        );
        // A second floating IP can't map the same fixed address (1:1).
        let f2 = t.allocate_floating_ip("ext", None).unwrap();
        assert!(
            t.associate_floating_ip(&f2.id, &p.id, ip("192.168.50.10"))
                .is_err()
        );

        // port_floating_ips reflects the mapping.
        let mapped = t.port_floating_ips(&p.id);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].id, f.id);

        // Disassociate → the mapping clears; the floating IP stays allocated.
        let cleared = t.disassociate_floating_ip(&f.id).unwrap();
        assert!(cleared.association.is_none());
        assert!(t.port_floating_ips(&p.id).is_empty());
        assert!(t.floating_ip(&f.id).is_some());
        // Disassociating an unknown floating IP errors; a repeat is a no-op.
        assert!(t.disassociate_floating_ip("nope").is_err());
        assert!(t.disassociate_floating_ip(&f.id).is_ok());
    }

    #[test]
    fn floating_ip_maps_an_ipam_bound_fixed_address() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("tenant", 100, "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("ext", 100, "203.0.113.0/29"))
            .unwrap();

        let p = t.create_port(100, "h1", "tap0", None, None).unwrap();
        let bound = t.bind_port_subnet(&p.id, "tenant", None).unwrap(); // .1
        let f = t.allocate_floating_ip("ext", None).unwrap();

        // A floating IP can map an IPAM-bound fixed address the port holds (not
        // just the legacy Port::ip).
        let assoc = t.associate_floating_ip(&f.id, &p.id, bound.addr).unwrap();
        assert_eq!(assoc.association.unwrap().fixed_addr, bound.addr);
    }

    #[test]
    fn release_floating_ip_blocked_while_associated_then_frees_ipam() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("ext", 100, "203.0.113.0/29"))
            .unwrap();
        let p = t
            .create_port(
                100,
                "h1",
                "tap0",
                Some("192.168.50.10".parse().unwrap()),
                None,
            )
            .unwrap();
        let f = t.allocate_floating_ip("ext", None).unwrap(); // .1
        t.associate_floating_ip(&f.id, &p.id, ip("192.168.50.10"))
            .unwrap();

        // Associated → release refused.
        assert!(t.release_floating_ip(&f.id).is_err());
        // Disassociate, then release frees the IPAM address for re-allocation.
        t.disassociate_floating_ip(&f.id).unwrap();
        assert!(t.release_floating_ip(&f.id).unwrap());
        assert!(t.floating_ip(&f.id).is_none());
        assert_eq!(t.allocate("ext", Some(f.addr)).unwrap(), f.addr);
        // Releasing a non-existent floating IP reports "did not exist".
        assert!(!t.release_floating_ip("nope").unwrap());
    }

    #[test]
    fn remove_port_disassociates_its_floating_ips() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("ext", 100, "203.0.113.0/29"))
            .unwrap();
        let p = t
            .create_port(
                100,
                "h1",
                "tap0",
                Some("192.168.50.10".parse().unwrap()),
                None,
            )
            .unwrap();
        let f = t.allocate_floating_ip("ext", None).unwrap();
        t.associate_floating_ip(&f.id, &p.id, ip("192.168.50.10"))
            .unwrap();
        assert_eq!(t.port_floating_ips(&p.id).len(), 1);

        // Removing the port clears the association but leaves the floating IP
        // allocated (so it can be re-associated to another port).
        assert!(t.remove_port(&p.id));
        assert!(t.floating_ip(&f.id).unwrap().association.is_none());
        assert!(t.port_floating_ips(&p.id).is_empty());
        // The now-free floating IP can be released.
        assert!(t.release_floating_ip(&f.id).unwrap());
    }

    #[test]
    fn floating_ips_survive_a_snapshot_roundtrip() {
        let mut t = Topology::new();
        t.add_host(host("h1", "10.0.0.1", 1));
        t.add_network(network(100, "blue", "192.168.50.0/24"))
            .unwrap();
        t.add_subnet(v4_subnet("ext", 100, "203.0.113.0/29"))
            .unwrap();
        let p = t
            .create_port(
                100,
                "h1",
                "tap0",
                Some("192.168.50.10".parse().unwrap()),
                None,
            )
            .unwrap();
        // One associated floating IP and one free-standing one.
        let f_assoc = t.allocate_floating_ip("ext", None).unwrap(); // .1
        t.associate_floating_ip(&f_assoc.id, &p.id, ip("192.168.50.10"))
            .unwrap();
        let f_free = t.allocate_floating_ip("ext", None).unwrap(); // .2

        let restored = Topology::from_snapshot(&t.to_snapshot());

        // Both floating IPs came back verbatim, association included.
        assert_eq!(
            restored.floating_ip(&f_assoc.id),
            t.floating_ip(&f_assoc.id)
        );
        let ra = restored.floating_ip(&f_assoc.id).unwrap();
        assert_eq!(ra.vni, 100);
        let a = ra.association.as_ref().unwrap();
        assert_eq!(a.port_id, p.id);
        assert_eq!(a.fixed_addr, ip("192.168.50.10"));
        assert!(
            restored
                .floating_ip(&f_free.id)
                .unwrap()
                .association
                .is_none()
        );

        // The used-address set is preserved: neither floating address can be
        // re-handed-out after the failover.
        assert!(
            restored
                .clone()
                .allocate("ext", Some(f_assoc.addr))
                .is_err()
        );
        assert!(restored.clone().allocate("ext", Some(f_free.addr)).is_err());
        // And port_floating_ips still resolves the association post-restore.
        assert_eq!(restored.port_floating_ips(&p.id).len(), 1);
    }
}
