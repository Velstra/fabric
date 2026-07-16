//! The control-plane side of the firewall: load the eBPF object, program the
//! maps from a [`RuntimeConfig`], attach the XDP hook, and read back per-CPU
//! statistics.

use std::{collections::HashSet, ffi::CString};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        Array, DevMap, HashMap, MapData, PerCpuArray, ProgramArray,
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
    ArpEntry, ArpKey, Backend, Cidr4, Counter, FloodSet, FlowKey, FlowState, GlobalConfig,
    LocalMac, LocalMacKey, MacFdbKey, NdKey, Npt66, OverlayConfig, PolicyId, PortFwd, RouteEntry,
    ScopedAddr, ScopedAddr6, ScopedPortKey, ScopedSrcPortKey, ServiceKey, ServiceValue, Srv6Config,
    Srv6Endpoint, Srv6LocalSid, Srv6SidKey, TunnelEndpoint, TunnelKey, parse_mac, port_rule_value,
};
use velstra_config::{
    PolicyConfig, ResolvedFloodVtep, ResolvedInterface, ResolvedMacRoute, ResolvedNd6,
    ResolvedNeighbor, ResolvedNpt66, ResolvedOverlay, ResolvedPortForward, ResolvedRoute,
    ResolvedService, ResolvedSrv6, ResolvedSrv6LocalSid, ResolvedSrv6Route, ResolvedTunnel,
    RuntimeConfig,
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

        // Load the tail-call target (`velstra_forward`) and register it in the
        // `VELSTRA_PROGS` program array, so the main program's
        // `tail_call(PROG_FORWARD)` resolves. It is loaded but never attached to
        // an interface — it only ever runs via the tail call out of `velstra`.
        // Done before the `velstra` mutable borrow below so the borrows don't
        // overlap, and before attach so the first packet already tail-calls.
        {
            let flow: &mut Xdp = ebpf
                .program_mut("velstra_forward")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_forward` program"))?
                .try_into()?;
            flow.load()
                .context("loading XDP forward program into the kernel")?;
        }
        // Clone the program fd to an owned handle so the immutable borrow on
        // `ebpf` ends before the map is borrowed mutably below.
        let flow_fd = {
            let flow: &Xdp = ebpf
                .program("velstra_forward")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_forward` program"))?
                .try_into()?;
            flow.fd()?.try_clone()?
        };
        {
            let mut prog_array = ProgramArray::try_from(
                ebpf.map_mut("VELSTRA_PROGS")
                    .ok_or_else(|| anyhow!("VELSTRA_PROGS map missing"))?,
            )?;
            prog_array
                .set(0, &flow_fd, 0)
                .context("registering velstra_forward in VELSTRA_PROGS")?;
        }

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
        // C16: an NPTv6 boundary interface also needs the TC egress hook, where the
        // source prefix is translated on the way out (the ingress/destination half
        // rides the XDP hook already attached to every config interface).
        for r in &cfg.npt66 {
            if !egress_ifaces.iter().any(|n| n == &r.interface)
                && if_nametoindex(&r.interface).is_ok()
            {
                egress_ifaces.push(r.interface.clone());
            }
        }
        if !egress_ifaces.is_empty() {
            attach_egress(&mut ebpf, &egress_ifaces)?;
        }

        // B2: attach the BUM head-end replication classifier at TC **ingress**
        // on the tenant taps (config interfaces on a real overlay segment,
        // `vni != 0`, that are present). Best-effort: `velstra_bum` is a
        // compile-verified-only datapath pending kernel-load iteration, so a
        // load/verifier failure is logged and swallowed rather than taking the
        // agent down — the flood-set maps are already programmed either way.
        if cfg.overlay.is_some() {
            let bum_ifaces: Vec<String> = cfg
                .interfaces
                .iter()
                .filter(|i| i.vni != 0 && if_nametoindex(&i.name).is_ok())
                .map(|i| i.name.clone())
                .collect();
            if !bum_ifaces.is_empty()
                && let Err(e) = attach_bum_ingress(&mut ebpf, &bum_ifaces)
            {
                warn!("B2 BUM replication attach failed (load-iterate pending): {e:#}");
            }
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

    /// Take ownership of the `LOCAL_MACS` map handle out of the loaded eBPF
    /// object, for the B4b learn-and-advertise background task.
    ///
    /// The XDP program is already loaded and its map references are resolved, so
    /// moving the userspace handle out of the `Ebpf` collection is safe — the
    /// kernel map lives on (the returned handle owns its fd), the data plane keeps
    /// populating it, and nothing else in the control plane touches `LOCAL_MACS`.
    /// The background task reads through the returned handle; when it is dropped
    /// the map is freed. (aya reads an LRU hash map through the same userspace
    /// `HashMap` type as a regular hash map.)
    pub fn take_local_macs(&mut self) -> Result<HashMap<MapData, LocalMacKey, LocalMac>> {
        let map = self
            .ebpf
            .take_map("LOCAL_MACS")
            .ok_or_else(|| anyhow!("LOCAL_MACS map missing"))?;
        HashMap::try_from(map).context("LOCAL_MACS as a HashMap")
    }

    /// Take ownership of the `CONNTRACK` map handle out of the loaded eBPF object,
    /// for the C9 stateful-HA conntrack-sync background task.
    ///
    /// Same rationale as [`take_local_macs`]: the XDP program's map references are
    /// already resolved, so moving the userspace handle out is safe — the kernel
    /// map lives on, the data plane keeps recording NAT flows into it, and nothing
    /// else in the control plane touches `CONNTRACK` (a live [`reconfigure`] leaves
    /// it alone by design). The sync task both **reads** it (dump-and-push) and
    /// **writes** it (apply a peer's entries) through this one handle. (aya reads
    /// and writes an LRU hash map through the same userspace `HashMap` type.)
    ///
    /// [`take_local_macs`]: Firewall::take_local_macs
    /// [`reconfigure`]: Firewall::reconfigure
    pub fn take_conntrack(&mut self) -> Result<HashMap<MapData, FlowKey, FlowState>> {
        let map = self
            .ebpf
            .take_map("CONNTRACK")
            .ok_or_else(|| anyhow!("CONNTRACK map missing"))?;
        HashMap::try_from(map).context("CONNTRACK as a HashMap")
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
        // B1 MAC-FDB is a HashMap keyed by `(vni, inner dst MAC)`; drop the old
        // set, mirroring the OVERLAY_FDB reconcile above.
        let mut mac_fdb: HashMap<_, MacFdbKey, TunnelEndpoint> = HashMap::try_from(
            ebpf.map_mut("MAC_FDB")
                .ok_or_else(|| anyhow!("MAC_FDB map missing"))?,
        )?;
        for mr in &old.mac_routes {
            let _ = mac_fdb.remove(&MacFdbKey::new(mr.vni, mr.mac));
        }
    }
    {
        // B2 flood set: drop every VNI that had a flood set; program_overlay
        // rebuilds each still-current one from the fresh config. Keyed by a bare
        // VNI, so removing by the old flood entries' distinct VNIs clears it.
        let mut flood: HashMap<_, u32, FloodSet> = HashMap::try_from(
            ebpf.map_mut("FLOOD_LIST")
                .ok_or_else(|| anyhow!("FLOOD_LIST map missing"))?,
        )?;
        for fv in &old.flood_vteps {
            let _ = flood.remove(&fv.vni);
        }
    }
    {
        // Trusted-VTEP set (C2): drop the old peers; program_overlay re-adds every
        // still-current one, so a peer shared by another live tunnel survives.
        // Both tunnels and MAC routes contribute trusted decap peers.
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for tunnel in &old.tunnels {
            let _ = peers.remove(&tunnel.remote_vtep_ip);
        }
        for mr in &old.mac_routes {
            let _ = peers.remove(&mr.remote_vtep_ip);
        }
        // Flood VTEPs are trusted decap peers too (they receive our encapped BUM
        // copies and send their own back).
        for fv in &old.flood_vteps {
            let _ = peers.remove(&fv.remote_vtep_ip);
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
    {
        let mut nd: HashMap<_, NdKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ND_TABLE")
                .ok_or_else(|| anyhow!("ND_TABLE map missing"))?,
        )?;
        for n in &old.nd_neighbors {
            let _ = nd.remove(&NdKey::new(n.vni, n.ip));
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

    program_fail_closed(ebpf, cfg.fail_closed)?;
    program_policies(ebpf, &cfg.policies)?;
    program_interfaces(ebpf, &cfg.interfaces)?;
    program_routes(ebpf, &cfg.routes)?;
    program_services(ebpf, &cfg.services)?;
    program_port_forwards(ebpf, &cfg.port_forwards)?;
    program_masquerade(ebpf, &cfg.interfaces)?;
    program_npt66(ebpf, &cfg.npt66)?;
    program_overlay(
        ebpf,
        cfg.overlay.as_ref(),
        &cfg.tunnels,
        &cfg.mac_routes,
        &cfg.neighbors,
        &cfg.nd_neighbors,
        &cfg.flood_vteps,
    )?;
    program_srv6(
        ebpf,
        cfg.srv6.as_ref(),
        &cfg.srv6_routes,
        &cfg.srv6_local_sids,
    )?;

    Ok(())
}

/// Write the host-wide `FAIL_CLOSED` flag: whether the data plane drops a packet
/// it cannot parse instead of passing it. Slot `0` is always written — including
/// the `false` (fail-open) default — so a `reconfigure` that turns the flag off
/// actually takes it back rather than leaving the old value in the map.
fn program_fail_closed(ebpf: &mut Ebpf, fail_closed: bool) -> Result<()> {
    let mut map: Array<_, u32> = Array::try_from(
        ebpf.map_mut("FAIL_CLOSED")
            .ok_or_else(|| anyhow!("FAIL_CLOSED map missing"))?,
    )?;
    map.set(0, u32::from(fail_closed), 0)
        .context("writing FAIL_CLOSED")?;
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

    {
        let mut iface_vni: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("IFACE_VNI")
                .ok_or_else(|| anyhow!("IFACE_VNI map missing"))?,
        )?;
        for (ifindex, _, vni) in &prepared {
            iface_vni
                .insert(ifindex, vni, 0)
                .with_context(|| format!("assigning ifindex {ifindex} to vni {vni}"))?;
        }
    }

    // The set of segments this host serves, for decap VNI enforcement: a tunnel
    // frame is only decapsulated into a VNI a local tenant port lives on. Value is
    // a reserved per-VNI bridge ifindex (0 today ⇒ shared kernel bridge).
    let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.map_mut("LOCAL_VNIS")
            .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
    )?;
    for (_, _, vni) in &prepared {
        if *vni != 0 {
            local_vnis
                .insert(vni, 0u32, 0)
                .with_context(|| format!("registering local vni {vni}"))?;
        }
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
            PortFwd::new_hairpin(pf.dst_ip, pf.dst_port, pf.match_dst, pf.snat_ip),
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
        .filter_map(
            |i| match (if_nametoindex(&i.name), read_iface_ipv4(&i.name)) {
                (Ok(ifindex), Ok(ip)) => Some((ifindex, ip)),
                _ => {
                    warn!(
                        "masquerade interface {} has no IPv4 yet; deferring its SNAT",
                        i.name
                    );
                    None
                }
            },
        )
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

/// Write the C16 `NPTV6` map: boundary ifindex → its NPTv6 (RFC 6296) prefix
/// translation. The interface name resolves to the live ifindex here (the data
/// plane keys on ifindex); an absent interface is skipped with a warning, so a
/// later reconfigure picks it up once the NIC appears.
fn program_npt66(ebpf: &mut Ebpf, rules: &[ResolvedNpt66]) -> Result<()> {
    let prepared: Vec<(u32, Npt66)> = rules
        .iter()
        .filter_map(|r| match if_nametoindex(&r.interface) {
            Ok(ifindex) => Some((ifindex, r.npt)),
            Err(_) => {
                warn!(
                    "npt66 interface {} not present yet; deferring its translation",
                    r.interface
                );
                None
            }
        })
        .collect();
    if prepared.is_empty() {
        return Ok(());
    }
    let mut map: HashMap<_, u32, Npt66> = HashMap::try_from(
        ebpf.map_mut("NPTV6")
            .ok_or_else(|| anyhow!("NPTV6 map missing"))?,
    )?;
    for (ifindex, npt) in prepared {
        map.insert(ifindex, npt, 0)
            .with_context(|| format!("inserting npt66 ifindex {ifindex}"))?;
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
/// entry), `OVERLAY_FDB` (`(vni, inner dst)` → remote endpoint), the B1
/// `MAC_FDB` (`(vni, inner dst MAC)` → remote endpoint, consulted first for L2
/// bridging), and the B2 `FLOOD_LIST` (`vni` → the [`FloodSet`] of remote VTEPs
/// a BUM frame on that segment head-end replicates to). Each tunnel's, MAC
/// route's and flood VTEP's underlay egress ifindex is also mirrored into
/// `TX_PORTS` so the data plane can redirect after encapsulating, and each
/// remote VTEP is added to the trusted-decap `VTEP_PEERS` set.
///
/// Slot `0` of `OVERLAY_CONFIG` is **always** written — with the resolved config
/// or, when the overlay is absent, with the disabled default — so a live
/// reconfigure that drops the overlay correctly turns encap/decap off.
#[allow(clippy::too_many_arguments)]
fn program_overlay(
    ebpf: &mut Ebpf,
    overlay: Option<&ResolvedOverlay>,
    tunnels: &[ResolvedTunnel],
    mac_routes: &[ResolvedMacRoute],
    neighbors: &[ResolvedNeighbor],
    nd_neighbors: &[ResolvedNd6],
    flood_vteps: &[ResolvedFloodVtep],
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

    // B3 IPv6 ND-suppression table: `(vni, tenant IPv6)` → MAC (same value shape
    // as ARP). The IPv6 mirror of the ARP table above.
    if !nd_neighbors.is_empty() {
        let mut nd: HashMap<_, NdKey, ArpEntry> = HashMap::try_from(
            ebpf.map_mut("ND_TABLE")
                .ok_or_else(|| anyhow!("ND_TABLE map missing"))?,
        )?;
        for n in nd_neighbors {
            nd.insert(NdKey::new(n.vni, n.ip), ArpEntry::new(n.mac), 0)
                .context("inserting ND neighbour")?;
        }
    }

    if tunnels.is_empty() && mac_routes.is_empty() && flood_vteps.is_empty() {
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

    // B1: resolve every MAC route's egress ifindex the same way. Each becomes an
    // exact-match MAC-FDB key `(vni, inner dst MAC)` → endpoint.
    let prepared_mac: Vec<(MacFdbKey, TunnelEndpoint)> = mac_routes
        .iter()
        .filter_map(|m| match if_nametoindex(&m.out_iface) {
            Ok(ifindex) => Some((
                MacFdbKey::new(m.vni, m.mac),
                TunnelEndpoint::new(ifindex, m.remote_vtep_ip, m.outer_dst_mac),
            )),
            Err(_) => {
                log::debug!(
                    "mac_route egress {} not present yet; deferring its MAC-FDB entry",
                    m.out_iface
                );
                None
            }
        })
        .collect();

    // B2: group flood VTEPs by VNI into one FloodSet per segment. Resolve each
    // entry's egress ifindex the same way (deferring an absent one), collecting
    // endpoints per VNI in config order. `flood_groups` feeds both FLOOD_LIST
    // and (via each endpoint's ifindex) TX_PORTS. A plain `Vec` of pairs keeps
    // insertion order and avoids clashing with the `aya` `HashMap` alias in
    // scope here.
    let mut flood_groups: Vec<(u32, Vec<TunnelEndpoint>)> = Vec::new();
    for fv in flood_vteps {
        let ifindex = match if_nametoindex(&fv.out_iface) {
            Ok(i) => i,
            Err(_) => {
                log::debug!(
                    "flood_vtep egress {} not present yet; deferring its flood entry",
                    fv.out_iface
                );
                continue;
            }
        };
        let ep = TunnelEndpoint::new(ifindex, fv.remote_vtep_ip, fv.outer_dst_mac);
        match flood_groups.iter_mut().find(|(v, _)| *v == fv.vni) {
            Some((_, eps)) => eps.push(ep),
            None => flood_groups.push((fv.vni, vec![ep])),
        }
    }

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
        // B1 MAC-FDB: consulted before OVERLAY_FDB so a true L2 overlay bridges
        // by destination MAC.
        let mut mac_fdb: HashMap<_, MacFdbKey, TunnelEndpoint> = HashMap::try_from(
            ebpf.map_mut("MAC_FDB")
                .ok_or_else(|| anyhow!("MAC_FDB map missing"))?,
        )?;
        for (key, endpoint) in &prepared_mac {
            mac_fdb
                .insert(key, endpoint, 0)
                .context("inserting MAC-FDB entry")?;
        }
    }

    {
        // B2 FLOOD_LIST: one FloodSet per VNI, walked by the TC ingress
        // `velstra_bum` classifier to head-end replicate BUM frames.
        let mut flood: HashMap<_, u32, FloodSet> = HashMap::try_from(
            ebpf.map_mut("FLOOD_LIST")
                .ok_or_else(|| anyhow!("FLOOD_LIST map missing"))?,
        )?;
        for (vni, eps) in &flood_groups {
            flood
                .insert(vni, FloodSet::new(eps), 0)
                .with_context(|| format!("inserting flood set for vni {vni}"))?;
        }
    }

    {
        // Trusted-VTEP set (C2): every distinct remote VTEP we tunnel with is an
        // authorized decap source. remove_stale dropped the old set first, and we
        // re-add every current peer here, so a still-valid VTEP survives a
        // reconfigure (mirrors the OVERLAY_FDB reconcile). MAC routes reach the
        // same remote VTEPs, so their VTEPs must be trusted decap peers too.
        let mut peers: HashMap<_, [u8; 4], u8> = HashMap::try_from(
            ebpf.map_mut("VTEP_PEERS")
                .ok_or_else(|| anyhow!("VTEP_PEERS map missing"))?,
        )?;
        for t in tunnels {
            peers
                .insert(t.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer")?;
        }
        for m in mac_routes {
            peers
                .insert(m.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (mac route)")?;
        }
        // B2: flood VTEPs receive our encapped BUM copies (and send their own
        // back), so they are trusted decap peers as well.
        for fv in flood_vteps {
            peers
                .insert(fv.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (flood vtep)")?;
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
    for (_, endpoint) in &prepared_mac {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device (mac route)")?;
    }
    // B2: the TC `velstra_bum` classifier `clone_redirect`s each BUM copy onto a
    // flood VTEP's underlay ifindex, so those ifindexes must be in the devmap too.
    for (_, eps) in &flood_groups {
        for endpoint in eps {
            tx_ports
                .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
                .context("registering overlay redirect device (flood vtep)")?;
        }
    }

    Ok(())
}

/// B9: program this host's SRv6 identity (`SRV6_CONFIG`) and its `End.DT2U`
/// per-MAC forwarding entries (`SRV6_FDB`), plus register each egress ifindex in
/// the `TX_PORTS` devmap so the datapath can redirect encapsulated frames. The
/// SRv6 analogue of the [`program_overlay`] unicast path; SRv6 and VXLAN are
/// mutually exclusive per host, so exactly one of the two configs is enabled.
fn program_srv6(
    ebpf: &mut Ebpf,
    srv6: Option<&ResolvedSrv6>,
    routes: &[ResolvedSrv6Route],
    local_sids: &[ResolvedSrv6LocalSid],
) -> Result<()> {
    // Resolve the host config (source MAC) before borrowing any map.
    let config = match srv6 {
        Some(s) => {
            let local_mac = match s.local_mac {
                Some(mac) => mac,
                None => read_iface_mac(&s.underlay_iface)?,
            };
            Srv6Config::new(s.local_src, local_mac, s.underlay_mtu)
        }
        None => Srv6Config::DISABLED,
    };

    {
        let mut cfg_map: Array<_, Srv6Config> = Array::try_from(
            ebpf.map_mut("SRV6_CONFIG")
                .ok_or_else(|| anyhow!("SRV6_CONFIG map missing"))?,
        )?;
        cfg_map.set(0, config, 0).context("writing SRV6_CONFIG")?;
    }

    // B9 decap: every service SID this host instantiates → its (vni, behaviour).
    // A packet whose outer IPv6 destination matches is decapsulated and bridged.
    if !local_sids.is_empty() {
        let mut sids: HashMap<_, Srv6SidKey, Srv6LocalSid> = HashMap::try_from(
            ebpf.map_mut("SRV6_LOCAL_SIDS")
                .ok_or_else(|| anyhow!("SRV6_LOCAL_SIDS map missing"))?,
        )?;
        for ls in local_sids {
            sids.insert(
                Srv6SidKey::new(ls.sid),
                Srv6LocalSid::new(ls.vni, ls.behavior),
                0,
            )
            .context("inserting SRv6 local SID")?;
        }
    }

    if routes.is_empty() {
        return Ok(());
    }

    // Resolve every route's egress ifindex (needs the OS). Each becomes an
    // exact-match SRv6-FDB key `(vni, inner dst MAC)` → remote-SID endpoint. Skip
    // (defer) a route whose out_iface isn't present yet rather than hard-aborting
    // the whole reconfigure — consistent with program_overlay/program_routes.
    let prepared: Vec<(MacFdbKey, Srv6Endpoint)> = routes
        .iter()
        .filter_map(|r| match if_nametoindex(&r.out_iface) {
            Ok(ifindex) => Some((
                MacFdbKey::new(r.vni, r.mac),
                Srv6Endpoint::new(ifindex, r.remote_sid, r.outer_dst_mac),
            )),
            Err(_) => {
                log::debug!(
                    "srv6_route egress {} not present yet; deferring its SRv6-FDB entry",
                    r.out_iface
                );
                None
            }
        })
        .collect();

    {
        let mut fdb: HashMap<_, MacFdbKey, Srv6Endpoint> = HashMap::try_from(
            ebpf.map_mut("SRV6_FDB")
                .ok_or_else(|| anyhow!("SRV6_FDB map missing"))?,
        )?;
        for (key, endpoint) in &prepared {
            fdb.insert(key, endpoint, 0)
                .context("inserting SRv6-FDB entry")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    for (_, endpoint) in &prepared {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering SRv6 redirect device")?;
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

/// Load the B2 `velstra_bum` TC classifier and attach it at **ingress** on each
/// tenant tap, so a BUM (broadcast/unknown-unicast/multicast) frame from the VM
/// is head-end replicated to the VNI's flood set. Requires a `clsact` qdisc,
/// created first (idempotent, like [`attach_egress`]).
///
/// B2 datapath note: the `velstra_bum` program is COMPILE-verified only and
/// awaits kernel-load iteration, so this attach is called **best-effort** by the
/// caller (a verifier rejection must not take the agent down); the flood-set
/// control plane (`FLOOD_LIST`/`VTEP_PEERS`/`TX_PORTS`) is programmed regardless.
fn attach_bum_ingress(ebpf: &mut Ebpf, ifaces: &[String]) -> Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut("velstra_bum")
        .ok_or_else(|| anyhow!("eBPF object has no `velstra_bum` program"))?
        .try_into()?;
    program
        .load()
        .context("loading TC BUM-replication program into the kernel")?;
    for iface in ifaces {
        // Idempotent: a pre-existing clsact qdisc is fine.
        let _ = qdisc_add_clsact(iface);
        program
            .attach(iface, TcAttachType::Ingress)
            .with_context(|| format!("attaching TC BUM-replication program to {iface}"))?;
        log::info!("attached BUM head-end replication (ingress) to {iface}");
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
