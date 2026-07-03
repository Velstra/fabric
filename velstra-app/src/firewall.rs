//! The control-plane side of the firewall: load the eBPF object, program the
//! maps from a [`RuntimeConfig`], attach the XDP hook, and read back per-CPU
//! statistics.

use std::{collections::HashSet, ffi::CString};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        Array, DevMap, HashMap, PerCpuArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        Xdp, XdpMode,
        tc::{SchedClassifier, TcAttachType, qdisc_add_clsact},
    },
};
use clap::ValueEnum;
use log::warn;
use velstra_common::{
    ArpEntry, ArpKey, Backend, Cidr4, Counter, GlobalConfig, OverlayConfig, PolicyId, PortFwd,
    RouteEntry, ScopedAddr, ScopedAddr6, ScopedPortKey, ScopedSrcPortKey, ServiceKey, ServiceValue,
    TunnelEndpoint, TunnelKey, parse_mac, port_rule_value,
};
use velstra_config::{
    PolicyConfig, ResolvedInterface, ResolvedNeighbor, ResolvedOverlay, ResolvedPortForward,
    ResolvedRoute, ResolvedService, ResolvedTunnel, RuntimeConfig,
};

/// How to attach the XDP program to the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AttachMode {
    /// Try native driver mode, then fall back to the generic SKB path.
    Auto,
    /// Native driver (`XDP_FLAGS_DRV_MODE`) — fast; needs driver support.
    Driver,
    /// Generic / SKB mode — works everywhere, slower (runs after `sk_buff`
    /// allocation). The usual choice for veth, bridges and dev laptops.
    Skb,
    /// Hardware offload (`XDP_FLAGS_HW_MODE`) — rare, SmartNIC only.
    Hw,
}

impl AttachMode {
    /// The ordered list of concrete [`XdpMode`]s to try for this preference.
    fn candidates(self) -> &'static [XdpMode] {
        match self {
            AttachMode::Auto => &[XdpMode::Driver, XdpMode::Skb],
            AttachMode::Driver => &[XdpMode::Driver],
            AttachMode::Skb => &[XdpMode::Skb],
            AttachMode::Hw => &[XdpMode::Hardware],
        }
    }
}

/// A loaded-and-attached Velstra firewall.
///
/// Owns the [`Ebpf`] object; dropping it detaches the program and frees the
/// maps. The XDP program therefore stays attached exactly as long as this value
/// (and hence the daemon) lives.
pub struct Firewall {
    ebpf: Ebpf,
    /// The interfaces the program is attached to and the [`XdpMode`] each
    /// attach succeeded with. Attaching to several interfaces from one process
    /// shares the maps (notably `CONNTRACK`) across them, which is what makes
    /// bidirectional NAT work: requests ingress one NIC, replies another.
    pub attached: Vec<(String, XdpMode)>,
    /// The currently-applied config, kept so a live [`reconfigure`] can remove
    /// the entries that are no longer present before writing the new set.
    ///
    /// [`reconfigure`]: Firewall::reconfigure
    applied: RuntimeConfig,
    /// Interfaces attached dynamically by auto-attach, tracked separately so they
    /// can be dropped again when the interface disappears (a VM tap going away).
    auto_attached: HashSet<String>,
    /// Interfaces attached because the **config** named them (e.g. pod veths the
    /// controller declared). Tracked separately from auto-attach so each is
    /// forgotten when its netdev disappears.
    config_attached: HashSet<String>,
}

impl Firewall {
    /// Load the embedded eBPF object, program the maps from `cfg`, and attach
    /// to every interface in `ifaces`.
    ///
    /// Maps are populated **before** attaching so the very first packet already
    /// sees the full ruleset — there is no window where traffic is processed
    /// against empty maps.
    ///
    /// Requires `CAP_NET_ADMIN` / root and must run inside a Tokio runtime (it
    /// spawns the `aya-log` forwarding task).
    pub fn load_and_attach(
        ifaces: &[String],
        mode: AttachMode,
        cfg: &RuntimeConfig,
        egress: bool,
    ) -> Result<Self> {
        bump_memlock_rlimit();

        // The eBPF object is embedded at compile time by the build script.
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/velstra"
        )))
        .context("loading embedded eBPF object")?;

        spawn_log_forwarder(&mut ebpf);
        apply_config(&mut ebpf, cfg, None)?;

        let program: &mut Xdp = ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        program
            .load()
            .context("loading XDP program into the kernel")?;

        let mut attached = Vec::with_capacity(ifaces.len());
        for iface in ifaces {
            let chosen = attach_with_fallback(program, iface, mode)?;
            attached.push((iface.clone(), chosen));
        }

        // The TC egress hook is needed by two features: the opt-in egress
        // firewall (`--egress`, applied to the `--iface` set) and masquerade
        // (applied to every present `masquerade` interface, which does SNAT
        // there). Attach to the union so a config-driven appliance masquerades
        // without needing `--egress`.
        let mut egress_ifaces: Vec<String> = if egress { ifaces.to_vec() } else { Vec::new() };
        for i in &cfg.interfaces {
            if i.masquerade
                && !egress_ifaces.iter().any(|n| n == &i.name)
                && if_nametoindex(&i.name).is_ok()
            {
                egress_ifaces.push(i.name.clone());
            }
        }
        if !egress_ifaces.is_empty() {
            attach_egress(&mut ebpf, &egress_ifaces)?;
        }

        Ok(Self {
            ebpf,
            attached,
            applied: cfg.clone(),
            auto_attached: HashSet::new(),
            config_attached: HashSet::new(),
        })
    }

    /// Attach the (already-loaded) program to one more interface and assign it a
    /// policy. Used by both startup and auto-attach.
    pub fn attach_iface(
        &mut self,
        iface: &str,
        mode: AttachMode,
        policy_id: PolicyId,
    ) -> Result<XdpMode> {
        {
            let ifindex = if_nametoindex(iface)?;
            let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
                self.ebpf
                    .map_mut("IFACE_POLICY")
                    .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
            )?;
            iface_policy
                .insert(ifindex, policy_id, 0)
                .with_context(|| format!("assigning {iface} to policy {policy_id}"))?;
        }
        let program: &mut Xdp = self
            .ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        let chosen = attach_with_fallback(program, iface, mode)?;
        self.attached.push((iface.to_string(), chosen));
        Ok(chosen)
    }

    /// Reconcile auto-attach against the current set of `present` interfaces:
    /// attach any new interface whose name starts with `prefix`, and drop any
    /// previously auto-attached interface that has since disappeared.
    ///
    /// A newly-attached interface gets the policy from the config's interface
    /// assignments if listed, else `default_policy`.
    pub fn reconcile_auto_attach(
        &mut self,
        present: &[String],
        prefix: &str,
        mode: AttachMode,
        default_policy: PolicyId,
    ) {
        // Collect new candidates first (ends the immutable borrow before we mutate).
        let candidates: Vec<(String, PolicyId)> = present
            .iter()
            .filter(|name| name.starts_with(prefix))
            .filter(|name| !self.attached.iter().any(|(n, _)| n == *name))
            .map(|name| {
                let policy = self
                    .applied
                    .interfaces
                    .iter()
                    .find(|i| i.name == *name)
                    .map(|i| i.policy)
                    .unwrap_or(default_policy);
                (name.clone(), policy)
            })
            .collect();
        for (name, policy) in candidates {
            match self.attach_iface(&name, mode, policy) {
                Ok(chosen) => {
                    self.auto_attached.insert(name.clone());
                    log::info!("auto-attached {name} -> policy {policy} ({chosen:?})");
                }
                Err(e) => warn!("auto-attach {name} failed: {e:#}"),
            }
        }

        // Drop auto-attached interfaces that have gone away (the XDP link
        // detached with the interface; we just forget it so a recreated
        // same-named interface re-attaches).
        let present_set: HashSet<&str> = present.iter().map(String::as_str).collect();
        let gone: Vec<String> = self
            .auto_attached
            .iter()
            .filter(|n| !present_set.contains(n.as_str()))
            .cloned()
            .collect();
        for name in gone {
            self.auto_attached.remove(&name);
            self.attached.retain(|(n, _)| n != &name);
            log::info!("auto-detached {name} (interface gone)");
        }
    }

    /// Attach the (already-loaded) program to one **config-named** interface,
    /// programming its policy AND overlay VNI before attaching so the first
    /// packet already sees both.
    fn attach_config_iface(
        &mut self,
        iface: &str,
        mode: AttachMode,
        policy_id: PolicyId,
        vni: u32,
    ) -> Result<XdpMode> {
        {
            let ifindex = if_nametoindex(iface)?;
            {
                let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
                    self.ebpf
                        .map_mut("IFACE_POLICY")
                        .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
                )?;
                iface_policy
                    .insert(ifindex, policy_id, 0)
                    .with_context(|| format!("assigning {iface} to policy {policy_id}"))?;
            }
            {
                let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
                    self.ebpf
                        .map_mut("IFACE_VNI")
                        .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
                )?;
                iface_vni
                    .insert(ifindex, vni, 0)
                    .with_context(|| format!("assigning {iface} to vni {vni}"))?;
            }
        }
        let program: &mut Xdp = self
            .ebpf
            .program_mut("velstra")
            .ok_or_else(|| anyhow!("eBPF object has no `velstra` program"))?
            .try_into()?;
        let chosen = attach_with_fallback(program, iface, mode)?;
        self.attached.push((iface.to_string(), chosen));
        Ok(chosen)
    }

    /// Reconcile the **config-named** interfaces against `present`: attach (and
    /// program the policy + VNI for) any that have appeared, and forget any whose
    /// netdev has since gone (its XDP link detached with it).
    ///
    /// This is what attaches the XDP firewall/LB to a pod veth the controller
    /// declared — possibly *before* the CNI created it — without relying on an
    /// `--auto-attach` prefix. `program_interfaces` defers a not-yet-present
    /// interface's maps; this loop completes the job when it appears.
    pub fn reconcile_config_interfaces(&mut self, present: &[String], mode: AttachMode) {
        let present_set: HashSet<&str> = present.iter().map(String::as_str).collect();

        // Attach config interfaces that are present but not yet attached.
        let todo: Vec<(String, PolicyId, u32)> = self
            .applied
            .interfaces
            .iter()
            .filter(|i| present_set.contains(i.name.as_str()))
            .filter(|i| !self.attached.iter().any(|(n, _)| n == &i.name))
            .map(|i| (i.name.clone(), i.policy, i.vni))
            .collect();
        for (name, policy, vni) in todo {
            match self.attach_config_iface(&name, mode, policy, vni) {
                Ok(chosen) => {
                    self.config_attached.insert(name.clone());
                    log::info!(
                        "attached config interface {name} -> policy {policy} vni {vni} ({chosen:?})"
                    );
                }
                Err(e) => warn!("attaching config interface {name} failed: {e:#}"),
            }
        }

        // Forget config interfaces whose netdev has gone (link auto-detached).
        let gone: Vec<String> = self
            .config_attached
            .iter()
            .filter(|n| !present_set.contains(n.as_str()))
            .cloned()
            .collect();
        for name in gone {
            self.config_attached.remove(&name);
            self.attached.retain(|(n, _)| n != &name);
            log::info!("detached config interface {name} (interface gone)");
        }
    }

    /// Re-program the policy maps in place with a new config, without detaching.
    ///
    /// Entries from the previously-applied config that are gone in `cfg` are
    /// removed first, then the new set is written. `CONNTRACK` is left alone (it
    /// is owned by the data plane), so existing flows keep working across a
    /// reconfigure. This is what the controller-driven live updates call.
    pub fn reconfigure(&mut self, cfg: &RuntimeConfig) -> Result<()> {
        apply_config(&mut self.ebpf, cfg, Some(&self.applied))?;
        self.applied = cfg.clone();
        Ok(())
    }

    /// Read and sum the per-CPU statistics into a flat [`Stats`] snapshot.
    pub fn read_stats(&self) -> Result<Stats> {
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.ebpf
                .map("STATS")
                .ok_or_else(|| anyhow!("STATS map missing"))?,
        )?;

        let mut rows = Vec::with_capacity(Counter::COUNT as usize);
        for index in 0..Counter::COUNT {
            let per_cpu = map.get(&index, 0)?;
            let total: u64 = per_cpu.iter().copied().sum();
            // `index` is in range by construction, so `from_u32` cannot fail.
            let counter = Counter::from_u32(index).expect("counter index in range");
            rows.push((counter, total));
        }
        Ok(Stats { rows })
    }
}

/// Raise the locked-memory rlimit so map allocation succeeds on older kernels
/// that still account BPF memory against `RLIMIT_MEMLOCK`.
/// LPM `(prefix_len, addr)` for a port rule's optional source constraint. `None`
/// ("from any") becomes a `/0` source — prefix == `FIXED_BITS`, address `0` —
/// which the trie matches for every packet; a `Some` CIDR extends the prefix by
/// the block's bits so a specific source outranks a `from any` rule.
fn port_rule_src_lpm(src: &Option<Cidr4>) -> (u32, u32) {
    match src {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedSrcPortKey::FIXED_BITS + bits, addr)
        }
        None => (ScopedSrcPortKey::prefix_len(0), 0),
    }
}

fn bump_memlock_rlimit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `setrlimit` is a plain syscall wrapper; `limit` is fully
    // initialised and outlives the call.
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if ret != 0 {
        warn!("could not raise RLIMIT_MEMLOCK (ret={ret}); map creation may fail on old kernels");
    }
}

/// Forward `aya-log` messages emitted by the eBPF program to the user-space
/// logger. Best effort: a program with no log statements simply yields no init.
fn spawn_log_forwarder(ebpf: &mut Ebpf) {
    match aya_log::EbpfLogger::init(ebpf) {
        Ok(logger) => {
            let mut logger = match tokio::io::unix::AsyncFd::with_interest(
                logger,
                tokio::io::Interest::READABLE,
            ) {
                Ok(fd) => fd,
                Err(e) => {
                    warn!("could not register eBPF log fd: {e}");
                    return;
                }
            };
            tokio::spawn(async move {
                loop {
                    let Ok(mut guard) = logger.readable_mut().await else {
                        break;
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
        Err(e) => warn!("eBPF logger not initialised: {e}"),
    }
}

/// Remove every map entry that `old` installed, so a reconfigure doesn't leave
/// stale rules behind. Missing keys are ignored (the entry may already be gone).
fn remove_stale(ebpf: &mut Ebpf, old: &RuntimeConfig) -> Result<()> {
    {
        let mut config: HashMap<_, PolicyId, GlobalConfig> = HashMap::try_from(
            ebpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow!("CONFIG map missing"))?,
        )?;
        for policy in &old.policies {
            let _ = config.remove(&policy.id);
        }
    }
    {
        let mut blocklist: LpmTrie<_, ScopedAddr, u32> = LpmTrie::try_from(
            ebpf.map_mut("BLOCKLIST")
                .ok_or_else(|| anyhow!("BLOCKLIST map missing"))?,
        )?;
        for policy in &old.policies {
            for cidr in &policy.blocklist {
                let (prefix, addr) = cidr.lpm_key();
                let key = Key::new(
                    ScopedAddr::POLICY_BITS + prefix,
                    ScopedAddr::new(policy.id, addr),
                );
                let _ = blocklist.remove(&key);
            }
        }
    }
    {
        let mut blocklist6: LpmTrie<_, ScopedAddr6, u32> = LpmTrie::try_from(
            ebpf.map_mut("BLOCKLIST6")
                .ok_or_else(|| anyhow!("BLOCKLIST6 map missing"))?,
        )?;
        for policy in &old.policies {
            for cidr in &policy.blocklist6 {
                let (prefix, addr) = cidr.lpm_key();
                let key = Key::new(
                    ScopedAddr6::POLICY_BITS + prefix,
                    ScopedAddr6::new(policy.id, addr),
                );
                let _ = blocklist6.remove(&key);
            }
        }
    }
    {
        let mut rules: LpmTrie<_, ScopedSrcPortKey, u32> = LpmTrie::try_from(
            ebpf.map_mut("PORT_RULES")
                .ok_or_else(|| anyhow!("PORT_RULES map missing"))?,
        )?;
        for policy in &old.policies {
            for (key, src, _, _) in &policy.port_rules {
                let (prefix, addr) = port_rule_src_lpm(src);
                let _ = rules.remove(&Key::new(
                    prefix,
                    ScopedSrcPortKey::new(policy.id, key.proto, key.port, addr),
                ));
            }
        }
    }
    {
        let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
            ebpf.map_mut("IFACE_POLICY")
                .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
        )?;
        for iface in &old.interfaces {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = iface_policy.remove(&ifindex);
            }
        }
    }
    {
        let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("IFACE_VNI")
                .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
        )?;
        for iface in &old.interfaces {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = iface_vni.remove(&ifindex);
            }
        }
    }
    {
        let mut masq: HashMap<_, u32, [u8; 4]> = HashMap::try_from(
            ebpf.map_mut("MASQUERADE")
                .ok_or_else(|| anyhow!("MASQUERADE map missing"))?,
        )?;
        for iface in old.interfaces.iter().filter(|i| i.masquerade) {
            if let Ok(ifindex) = if_nametoindex(&iface.name) {
                let _ = masq.remove(&ifindex);
            }
        }
    }
    {
        let mut routes: LpmTrie<_, ScopedAddr, RouteEntry> = LpmTrie::try_from(
            ebpf.map_mut("ROUTES")
                .ok_or_else(|| anyhow!("ROUTES map missing"))?,
        )?;
        for route in &old.routes {
            let (prefix, data) = route.dest.lpm_key();
            let _ = routes.remove(&Key::new(
                ScopedAddr::POLICY_BITS + prefix,
                ScopedAddr::new(route.policy, data),
            ));
        }
    }
    {
        let mut services: HashMap<_, ServiceKey, ServiceValue> = HashMap::try_from(
            ebpf.map_mut("SERVICES")
                .ok_or_else(|| anyhow!("SERVICES map missing"))?,
        )?;
        for service in &old.services {
            let _ = services.remove(&service.key);
        }
    }
    {
        // Overlay FDB is an LPM trie keyed by `(vni, inner dst prefix)`; drop the
        // old set. `OVERLAY_CONFIG` needs no cleanup — it is always rewritten.
        let mut fdb: LpmTrie<_, TunnelKey, TunnelEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("OVERLAY_FDB")
                .ok_or_else(|| anyhow!("OVERLAY_FDB map missing"))?,
        )?;
        for tunnel in &old.tunnels {
            let (_, addr) = tunnel.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(tunnel.inner_dst.prefix),
                TunnelKey::new(tunnel.vni, addr),
            );
            let _ = fdb.remove(&key);
        }
    }
    {
        // Trusted-VTEP set (C2): drop the old peers; program_overlay re-adds every
        // still-current one, so a peer shared by another live tunnel survives.
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for tunnel in &old.tunnels {
            let _ = peers.remove(&tunnel.remote_vtep_ip);
        }
    }
    {
        let mut arp: HashMap<_, ArpKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ARP_TABLE")
                .ok_or_else(|| anyhow!("ARP_TABLE map missing"))?,
        )?;
        for n in &old.neighbors {
            let _ = arp.remove(&ArpKey::new(n.vni, n.ip));
        }
    }
    Ok(())
}

/// Write a [`RuntimeConfig`] into the policy maps. When `old` is `Some`, its
/// entries are removed first so a live reconfigure can't leave stale rules.
fn apply_config(ebpf: &mut Ebpf, cfg: &RuntimeConfig, old: Option<&RuntimeConfig>) -> Result<()> {
    if let Some(old) = old {
        remove_stale(ebpf, old)?;
    }

    program_policies(ebpf, &cfg.policies)?;
    program_interfaces(ebpf, &cfg.interfaces)?;
    program_routes(ebpf, &cfg.routes)?;
    program_services(ebpf, &cfg.services)?;
    program_port_forwards(ebpf, &cfg.port_forwards)?;
    program_masquerade(ebpf, &cfg.interfaces)?;
    program_overlay(ebpf, cfg.overlay.as_ref(), &cfg.tunnels, &cfg.neighbors)?;

    Ok(())
}

/// Write every policy's firewall maps (`CONFIG`, `BLOCKLIST`, `PORT_RULES`),
/// scoped by policy id.
fn program_policies(ebpf: &mut Ebpf, policies: &[PolicyConfig]) -> Result<()> {
    {
        let mut config: HashMap<_, PolicyId, GlobalConfig> = HashMap::try_from(
            ebpf.map_mut("CONFIG")
                .ok_or_else(|| anyhow!("CONFIG map missing"))?,
        )?;
        for policy in policies {
            config
                .insert(policy.id, policy.global, 0)
                .with_context(|| format!("writing CONFIG for policy {}", policy.id))?;
        }
    }
    {
        let mut blocklist: LpmTrie<_, ScopedAddr, u32> = LpmTrie::try_from(
            ebpf.map_mut("BLOCKLIST")
                .ok_or_else(|| anyhow!("BLOCKLIST map missing"))?,
        )?;
        for policy in policies {
            for cidr in &policy.blocklist {
                let (prefix, addr) = cidr.lpm_key();
                let key = Key::new(
                    ScopedAddr::POLICY_BITS + prefix,
                    ScopedAddr::new(policy.id, addr),
                );
                blocklist.insert(&key, 1u32, 0).with_context(|| {
                    format!("inserting blocklist {cidr} (policy {})", policy.id)
                })?;
            }
        }
    }
    {
        let mut blocklist6: LpmTrie<_, ScopedAddr6, u32> = LpmTrie::try_from(
            ebpf.map_mut("BLOCKLIST6")
                .ok_or_else(|| anyhow!("BLOCKLIST6 map missing"))?,
        )?;
        for policy in policies {
            for cidr in &policy.blocklist6 {
                let (prefix, addr) = cidr.lpm_key();
                let key = Key::new(
                    ScopedAddr6::POLICY_BITS + prefix,
                    ScopedAddr6::new(policy.id, addr),
                );
                blocklist6.insert(&key, 1u32, 0).with_context(|| {
                    format!("inserting IPv6 blocklist {cidr} (policy {})", policy.id)
                })?;
            }
        }
    }
    {
        let mut rules: LpmTrie<_, ScopedSrcPortKey, u32> = LpmTrie::try_from(
            ebpf.map_mut("PORT_RULES")
                .ok_or_else(|| anyhow!("PORT_RULES map missing"))?,
        )?;
        for policy in policies {
            for (key, src, action, log) in &policy.port_rules {
                let (prefix, addr) = port_rule_src_lpm(src);
                rules
                    .insert(
                        &Key::new(
                            prefix,
                            ScopedSrcPortKey::new(policy.id, key.proto, key.port, addr),
                        ),
                        port_rule_value(*action, *log),
                        0,
                    )
                    .context("inserting port rule")?;
            }
        }
    }
    Ok(())
}

/// Map each configured interface to its policy id (`IFACE_POLICY`) and overlay
/// segment (`IFACE_VNI`). The two are independent: a port's firewall ruleset and
/// its virtual network are separate concerns.
fn program_interfaces(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    if interfaces.is_empty() {
        return Ok(());
    }
    // Resolve names to ifindexes, skipping any interface that doesn't exist yet
    // (e.g. a pod veth the controller named before the CNI created it). The
    // config-interface reconcile programs + attaches it once it appears, so a
    // not-yet-present interface must not fail the whole reconfigure.
    let prepared: Vec<(u32, PolicyId, u32)> = interfaces
        .iter()
        .filter_map(|i| match if_nametoindex(&i.name) {
            Ok(ifindex) => Some((ifindex, i.policy, i.vni)),
            Err(_) => {
                log::debug!("interface {} not present yet; deferring its maps", i.name);
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }

    {
        let mut iface_policy: HashMap<_, u32, PolicyId> = HashMap::try_from(
            ebpf.map_mut("IFACE_POLICY")
                .ok_or_else(|| anyhow!("IFACE_POLICY map missing"))?,
        )?;
        for (ifindex, policy_id, _) in &prepared {
            iface_policy
                .insert(ifindex, policy_id, 0)
                .with_context(|| format!("assigning ifindex {ifindex} to policy {policy_id}"))?;
        }
    }

    let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.map_mut("IFACE_VNI")
            .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
    )?;
    for (ifindex, _, vni) in &prepared {
        iface_vni
            .insert(ifindex, vni, 0)
            .with_context(|| format!("assigning ifindex {ifindex} to vni {vni}"))?;
    }
    Ok(())
}

/// Program the Phase 3 load-balancer maps: `BACKENDS` (a flat pool) and
/// `SERVICES` (`(VIP, port, proto)` → a window into that pool). No-op without
/// services.
fn program_services(ebpf: &mut Ebpf, services: &[ResolvedService]) -> Result<()> {
    if services.is_empty() {
        return Ok(());
    }

    // Flatten every service's pool into one array, recording each service's
    // [start, count) window as we go.
    let mut flat: Vec<Backend> = Vec::new();
    let mut entries: Vec<(ServiceKey, ServiceValue)> = Vec::new();
    for service in services {
        let start = flat.len() as u32;
        flat.extend_from_slice(&service.backends);
        entries.push((
            service.key,
            ServiceValue::new(start, service.backends.len() as u32),
        ));
    }

    {
        let mut backends: Array<_, Backend> = Array::try_from(
            ebpf.map_mut("BACKENDS")
                .ok_or_else(|| anyhow!("BACKENDS map missing"))?,
        )?;
        for (index, backend) in flat.iter().enumerate() {
            backends
                .set(index as u32, backend, 0)
                .context("inserting backend")?;
        }
    }

    let mut svc_map: HashMap<_, ServiceKey, ServiceValue> = HashMap::try_from(
        ebpf.map_mut("SERVICES")
            .ok_or_else(|| anyhow!("SERVICES map missing"))?,
    )?;
    for (key, value) in &entries {
        svc_map.insert(key, value, 0).context("inserting service")?;
    }

    Ok(())
}

/// Write the Phase 4 `PORT_FORWARDS` map: `(policy, proto, dport)` →
/// internal `(ip, port)`. Keyed by [`ScopedPortKey`] like the firewall's port
/// rules, so the data plane looks it up the same way.
fn program_port_forwards(ebpf: &mut Ebpf, forwards: &[ResolvedPortForward]) -> Result<()> {
    if forwards.is_empty() {
        return Ok(());
    }
    let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
        ebpf.map_mut("PORT_FORWARDS")
            .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
    )?;
    for pf in forwards {
        map.insert(
            ScopedPortKey::new(pf.policy, pf.proto, pf.port),
            PortFwd::new(pf.dst_ip, pf.dst_port),
            0,
        )
        .context("inserting port-forward")?;
    }
    Ok(())
}

/// Write the Phase 4b `MASQUERADE` map: egress ifindex → that interface's public
/// IPv4, for every interface marked `masquerade`. The live address is read from
/// the OS here (the data plane can't), so a not-yet-addressed interface (DHCP not
/// up, or absent) is skipped with a warning — a later reconfigure picks it up.
fn program_masquerade(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let prepared: Vec<(u32, [u8; 4])> = interfaces
        .iter()
        .filter(|i| i.masquerade)
        .filter_map(|i| match (if_nametoindex(&i.name), read_iface_ipv4(&i.name)) {
            (Ok(ifindex), Ok(ip)) => Some((ifindex, ip)),
            _ => {
                warn!(
                    "masquerade interface {} has no IPv4 yet; deferring its SNAT",
                    i.name
                );
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }
    let mut map: HashMap<_, u32, [u8; 4]> = HashMap::try_from(
        ebpf.map_mut("MASQUERADE")
            .ok_or_else(|| anyhow!("MASQUERADE map missing"))?,
    )?;
    for (ifindex, ip) in prepared {
        map.insert(ifindex, ip, 0)
            .with_context(|| format!("inserting masquerade ifindex {ifindex}"))?;
    }
    Ok(())
}

/// Read an interface's first IPv4 address via `getifaddrs(3)`. Returns an error
/// if the interface has no IPv4 assigned (e.g. DHCP not up yet).
fn read_iface_ipv4(iface: &str) -> Result<[u8; 4]> {
    use std::os::raw::c_int;
    let mut ifap: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned linked list we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        bail!("getifaddrs failed for {iface}");
    }
    let mut result: Option<[u8; 4]> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node for the duration of this iteration.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() {
            // SAFETY: ifa_addr points at a sockaddr; we only read sa_family then,
            // if AF_INET, reinterpret as sockaddr_in (both kernel-owned).
            let family = unsafe { (*node.ifa_addr).sa_family } as c_int;
            let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) };
            if family == libc::AF_INET && name.to_bytes() == iface.as_bytes() {
                let sin = node.ifa_addr as *const libc::sockaddr_in;
                // s_addr is in network byte order — its native bytes are the octets.
                let octets = unsafe { (*sin).sin_addr.s_addr }.to_ne_bytes();
                result = Some(octets);
                break;
            }
        }
        cur = node.ifa_next;
    }
    // SAFETY: frees the list `getifaddrs` allocated; `ifap` is not used after.
    unsafe { libc::freeifaddrs(ifap) };
    result.ok_or_else(|| anyhow!("interface {iface} has no IPv4 address"))
}

/// Program the Phase 4 overlay maps: `OVERLAY_CONFIG` (this host's VTEP, a single
/// entry) and `OVERLAY_FDB` (`(vni, inner dst)` → remote endpoint). Each tunnel's
/// underlay egress ifindex is also mirrored into `TX_PORTS` so the data plane can
/// redirect after encapsulating.
///
/// Slot `0` of `OVERLAY_CONFIG` is **always** written — with the resolved config
/// or, when the overlay is absent, with the disabled default — so a live
/// reconfigure that drops the overlay correctly turns encap/decap off.
fn program_overlay(
    ebpf: &mut Ebpf,
    overlay: Option<&ResolvedOverlay>,
    tunnels: &[ResolvedTunnel],
    neighbors: &[ResolvedNeighbor],
) -> Result<()> {
    // Resolve the host config (MAC + port) before borrowing any map.
    let config = match overlay {
        Some(o) => {
            let local_mac = match o.local_mac {
                Some(mac) => mac,
                None => read_iface_mac(&o.underlay_iface)?,
            };
            OverlayConfig::new(
                o.local_vtep_ip,
                local_mac,
                o.udp_port,
                o.encap,
                o.underlay_mtu,
            )
        }
        None => OverlayConfig::DISABLED,
    };

    {
        let mut cfg_map: Array<_, OverlayConfig> = Array::try_from(
            ebpf.map_mut("OVERLAY_CONFIG")
                .ok_or_else(|| anyhow!("OVERLAY_CONFIG map missing"))?,
        )?;
        cfg_map
            .set(0, config, 0)
            .context("writing OVERLAY_CONFIG")?;
    }

    // ARP suppression table: `(vni, tenant IP)` → MAC.
    if !neighbors.is_empty() {
        let mut arp: HashMap<_, ArpKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ARP_TABLE")
                .ok_or_else(|| anyhow!("ARP_TABLE map missing"))?,
        )?;
        for n in neighbors {
            arp.insert(ArpKey::new(n.vni, n.ip), ArpEntry::new(n.mac), 0)
                .context("inserting ARP neighbour")?;
        }
    }

    if tunnels.is_empty() {
        return Ok(());
    }

    // Resolve every tunnel's egress ifindex up front (needs the OS), then do the
    // two map-borrow passes. Each tunnel becomes an LPM key `(vni exact, inner
    // dst prefix)` → endpoint. Skip (defer) a tunnel whose out_iface isn't
    // present yet rather than hard-aborting the whole reconfigure — consistent
    // with program_interfaces/program_routes; a hard abort would blackhole
    // overlay traffic after remove_stale already ran.
    let prepared: Vec<(Key<TunnelKey>, TunnelEndpoint)> = tunnels
        .iter()
        .filter_map(|t| match if_nametoindex(&t.out_iface) {
            Ok(ifindex) => {
                let (_, addr) = t.inner_dst.lpm_key();
                let key = Key::new(
                    TunnelKey::prefix_len(t.inner_dst.prefix),
                    TunnelKey::new(t.vni, addr),
                );
                Some((
                    key,
                    TunnelEndpoint::new(ifindex, t.remote_vtep_ip, t.outer_dst_mac),
                ))
            }
            Err(_) => {
                log::debug!(
                    "tunnel egress {} not present yet; deferring its FDB entry",
                    t.out_iface
                );
                None
            }
        })
        .collect();

    {
        let mut fdb: LpmTrie<_, TunnelKey, TunnelEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("OVERLAY_FDB")
                .ok_or_else(|| anyhow!("OVERLAY_FDB map missing"))?,
        )?;
        for (key, endpoint) in &prepared {
            fdb.insert(key, endpoint, 0)
                .context("inserting overlay FDB entry")?;
        }
    }

    {
        // Trusted-VTEP set (C2): every distinct remote VTEP we tunnel with is an
        // authorized decap source. remove_stale dropped the old set first, and we
        // re-add every current peer here, so a still-valid VTEP survives a
        // reconfigure (mirrors the OVERLAY_FDB reconcile).
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for t in tunnels {
            peers
                .insert(t.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    for (_, endpoint) in &prepared {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device")?;
    }

    Ok(())
}

/// A route resolved against the live system: ifindex looked up, source MAC
/// settled, ready to drop straight into the `ROUTES` and `TX_PORTS` maps.
struct PreparedRoute {
    policy: PolicyId,
    prefix: u32,
    data: u32,
    entry: RouteEntry,
}

/// Program the Phase 2 forwarding maps: `ROUTES` (the FIB) and `TX_PORTS` (the
/// redirect devmap). No-op when there are no routes, so a firewall-only
/// deployment never pays for it.
fn program_routes(ebpf: &mut Ebpf, routes: &[ResolvedRoute]) -> Result<()> {
    if routes.is_empty() {
        return Ok(());
    }

    // Resolve everything that needs the OS up front, so the two map-borrow
    // passes below don't each have to (and can't both hold `ebpf` at once).
    // Skip (defer) a route whose out_iface isn't resolvable yet instead of
    // hard-aborting the whole reconfigure — consistent with program_interfaces
    // and program_masquerade. A hard abort here would leave apply_config half
    // applied (remove_stale already ran) and blackhole traffic; the config
    // reconcile re-runs once the interface appears.
    let prepared: Vec<PreparedRoute> = routes
        .iter()
        .filter_map(|r| match prepare_route(r) {
            Ok(p) => Some(p),
            Err(e) => {
                log::debug!(
                    "route via {} not programmable yet ({e}); deferring",
                    r.out_iface
                );
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }

    {
        let mut fib: LpmTrie<_, ScopedAddr, RouteEntry> = LpmTrie::try_from(
            ebpf.map_mut("ROUTES")
                .ok_or_else(|| anyhow!("ROUTES map missing"))?,
        )?;
        for route in &prepared {
            fib.insert(
                &Key::new(
                    ScopedAddr::POLICY_BITS + route.prefix,
                    ScopedAddr::new(route.policy, route.data),
                ),
                route.entry,
                0,
            )
            .context("inserting route")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    for route in &prepared {
        // Index the devmap by ifindex so the data plane can redirect with the
        // ifindex it already has from the route entry.
        tx_ports
            .set(route.entry.out_ifindex, route.entry.out_ifindex, None, 0)
            .context("registering redirect device")?;
    }

    Ok(())
}

/// Resolve a [`ResolvedRoute`]'s egress interface to an ifindex (and, if needed,
/// its MAC) and build the kernel [`RouteEntry`].
fn prepare_route(route: &ResolvedRoute) -> Result<PreparedRoute> {
    let ifindex = if_nametoindex(&route.out_iface)?;
    let src_mac = match route.src_mac {
        Some(mac) => mac,
        None => read_iface_mac(&route.out_iface)?,
    };
    let (prefix, data) = route.dest.lpm_key();
    Ok(PreparedRoute {
        policy: route.policy,
        prefix,
        data,
        entry: RouteEntry::new(ifindex, src_mac, route.dst_mac, route.flags),
    })
}

/// Look up an interface index by name via `if_nametoindex(3)`.
fn if_nametoindex(iface: &str) -> Result<u32> {
    let cstr = CString::new(iface).with_context(|| format!("interface name {iface:?}"))?;
    // SAFETY: `cstr` is a valid NUL-terminated string that outlives the call.
    let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    if index == 0 {
        bail!("interface {iface:?} not found");
    }
    Ok(index)
}

/// Read an interface's MAC address from `/sys/class/net/<iface>/address`.
fn read_iface_mac(iface: &str) -> Result<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    parse_mac(text.trim()).map_err(|e| anyhow!("MAC of {iface}: {e}"))
}

/// Load the `velstra_egress` TC classifier and attach it at **egress** on each
/// interface. Requires a `clsact` qdisc, which we create first (ignoring the
/// "already exists" case so a restart is idempotent).
fn attach_egress(ebpf: &mut Ebpf, ifaces: &[String]) -> Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut("velstra_egress")
        .ok_or_else(|| anyhow!("eBPF object has no `velstra_egress` program"))?
        .try_into()?;
    program
        .load()
        .context("loading TC egress program into the kernel")?;
    for iface in ifaces {
        // Idempotent: a pre-existing clsact qdisc is fine.
        let _ = qdisc_add_clsact(iface);
        program
            .attach(iface, TcAttachType::Egress)
            .with_context(|| format!("attaching TC egress program to {iface}"))?;
        log::info!("attached egress firewall to {iface}");
    }
    Ok(())
}

/// Attach `program`, walking the candidate modes for `mode` until one succeeds.
fn attach_with_fallback(program: &mut Xdp, iface: &str, mode: AttachMode) -> Result<XdpMode> {
    let mut last_err = None;
    for candidate in mode.candidates() {
        match program.attach(iface, *candidate) {
            Ok(_link_id) => return Ok(*candidate),
            Err(e) => {
                warn!("attach to {iface} in {candidate:?} mode failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(match last_err {
        Some(e) => anyhow!("could not attach XDP program to {iface}: {e}"),
        None => anyhow!("no XDP attach mode was attempted for {iface}"),
    })
}

/// A summed snapshot of the per-CPU statistics.
pub struct Stats {
    /// `(counter, total-across-cpus)` for every [`Counter`], in index order.
    pub rows: Vec<(Counter, u64)>,
}

impl Stats {
    /// Look up a single counter's total.
    pub fn get(&self, counter: Counter) -> u64 {
        self.rows
            .get(counter.index() as usize)
            .map(|(_, v)| *v)
            .unwrap_or(0)
    }

    /// Render an aligned, human-readable table.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;

        let rx = self.get(Counter::RxPackets);
        let dropped: u64 = self
            .rows
            .iter()
            .filter(|(c, _)| is_drop_counter(*c))
            .map(|(_, v)| *v)
            .sum();
        let drop_pct = if rx > 0 {
            (dropped as f64 / rx as f64) * 100.0
        } else {
            0.0
        };

        let mut out = String::new();
        let _ = writeln!(out, "  {:<20} {:>14}", "counter", "value");
        let _ = writeln!(out, "  {:-<20} {:->14}", "", "");
        for (counter, value) in &self.rows {
            let _ = writeln!(out, "  {:<20} {:>14}", counter.label(), value);
        }
        let _ = writeln!(out, "  {:-<20} {:->14}", "", "");
        let _ = writeln!(out, "  {:<20} {:>13.2}%", "drop rate", drop_pct);
        out
    }
}

/// Whether a counter records a dropped packet (used for the drop-rate summary).
fn is_drop_counter(counter: Counter) -> bool {
    matches!(
        counter,
        Counter::DroppedDefault
            | Counter::DroppedBlocklist
            | Counter::DroppedRule
            | Counter::DroppedIcmp
            | Counter::ForwardTtlExceeded
            | Counter::EgressDropped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_mode_falls_back_driver_then_skb() {
        assert_eq!(
            AttachMode::Auto.candidates(),
            &[XdpMode::Driver, XdpMode::Skb]
        );
        assert_eq!(AttachMode::Skb.candidates(), &[XdpMode::Skb]);
    }

    #[test]
    fn drop_counters_are_classified() {
        assert!(is_drop_counter(Counter::DroppedBlocklist));
        assert!(is_drop_counter(Counter::DroppedIcmp));
        assert!(!is_drop_counter(Counter::PassedDefault));
        assert!(!is_drop_counter(Counter::RxPackets));
    }

    #[test]
    fn stats_render_and_drop_rate() {
        let mut rows = Vec::new();
        for index in 0..Counter::COUNT {
            let counter = Counter::from_u32(index).unwrap();
            let value = match counter {
                Counter::RxPackets => 100,
                Counter::DroppedBlocklist => 25,
                _ => 0,
            };
            rows.push((counter, value));
        }
        let stats = Stats { rows };
        assert_eq!(stats.get(Counter::RxPackets), 100);
        let rendered = stats.render();
        assert!(rendered.contains("dropped_blocklist"));
        assert!(rendered.contains("25.00%"), "drop rate; got:\n{rendered}");
    }
}
