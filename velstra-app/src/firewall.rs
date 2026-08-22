//! The control-plane side of the firewall: load the eBPF object, program the
//! maps from a [`RuntimeConfig`], attach the XDP hook, and read back per-CPU
//! statistics.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::CString,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        Array, DevMap, HashMap, MapData, PerCpuArray, ProgramArray,
        lpm_trie::{Key, LpmTrie},
    },
    programs::{
        ProgramError, Xdp, XdpMode,
        tc::{SchedClassifier, TcAttachType, qdisc_add_clsact},
    },
};
use clap::ValueEnum;
use log::warn;
use tokio::sync::Mutex;
use velstra_common::{
    Action, ArpEntry, ArpKey, Backend, CgnatLayout, Cidr4, Cidr6, ConfigFlags, Counter, FloodSet,
    FlowKey, FlowState, GlobalConfig, IrbEndpoint, LocalMac, LocalMacKey, MAX_RULE_LIMITS,
    MacFdbKey, NdKey, Npt66, OverlayConfig, PORT_RULE_OUT_ONLY, PolicyId, PortAddr4, PortAddr6,
    PortBinding, PortFwd, PortalClientKey, PortalGate, PortalSeenKey, RateBucket, RouteEntry,
    ScopedAddr, ScopedAddr6, ScopedDstPortKey, ScopedDstPortKey6, ScopedMac, ScopedPortKey,
    ScopedSrcPortKey, ScopedSrcPortKey6, ServiceKey, ServiceValue, Srv6Config, Srv6Endpoint,
    Srv6FloodSet, Srv6IrbEndpoint, Srv6LocalSid, Srv6SidKey, SynProxyCfg, SynProxyKey,
    TunnelEndpoint, TunnelKey, parse_cidr_v4, parse_cidr_v6, parse_mac, port_rule_value,
    port_rule_with_limit,
};
use velstra_config::{
    PolicyConfig, PortIdentity, ResolvedFloodVtep, ResolvedInterface, ResolvedIrbRoute,
    ResolvedMacRoute, ResolvedNd6, ResolvedNeighbor, ResolvedNpt66, ResolvedOverlay,
    ResolvedPortForward, ResolvedRoute, ResolvedService, ResolvedSrv6, ResolvedSrv6Flood,
    ResolvedSrv6IrbRoute, ResolvedSrv6LocalSid, ResolvedSrv6Route, ResolvedSynProxy,
    ResolvedTunnel, RuntimeConfig,
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
    /// The configuration as it arrived, before the advertised rules were merged
    /// into it.
    ///
    /// Kept apart from [`Self::applied`] because the two sources change
    /// independently: a config push must not lose the FlowSpec rules in force,
    /// and a FlowSpec update must not re-apply a config the operator has since
    /// replaced. Both paths rebuild the merge from these two, so whichever
    /// arrives last, the answer is the same.
    base: RuntimeConfig,
    /// The rules a BGP peer has asked this box to enforce (roadmap A3), already
    /// translated. Empty unless the FlowSpec task is running.
    flowspec: Vec<velstra_config::ResolvedRule>,
    /// What arrived over the same feed and is **not** being enforced, with the
    /// reason. Kept beside the rules rather than only logged: "a rule was
    /// advertised and is doing nothing" is the question somebody asks during an
    /// attack, and a journal that has rotated cannot answer it.
    flowspec_refused: Vec<(String, String)>,
    /// Tenant taps already carrying the TC BUM-replication classifier. Tracked
    /// because the attach is now re-tried on every reprogram — a tap that appears
    /// after startup has to be picked up — and attaching twice would put two
    /// classifiers on one ingress, replicating every broadcast frame twice.
    bum_attached: HashSet<String>,
    /// Interfaces attached dynamically by auto-attach, tracked separately so they
    /// can be dropped again when the interface disappears (a VM tap going away).
    auto_attached: HashSet<String>,
    /// Interfaces attached because the **config** named them (e.g. pod veths the
    /// controller declared). Tracked separately from auto-attach so each is
    /// forgotten when its netdev disappears.
    config_attached: HashSet<String>,
    /// The `CONNTRACK` handle once it has been moved out of [`Self::ebpf`],
    /// **shared** rather than given away: both the C9 sync task and the flow
    /// query path read it. Keeping it here is what stops enabling HA from taking
    /// the flow table away from every other reader.
    conntrack: Option<Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>>,
    /// Sources blocked at **run time** rather than by configuration, each with the
    /// moment it stops being blocked (roadmap C11: a detector acting on what it
    /// saw).
    ///
    /// Held here so `show`, expiry and the config reconcile all agree on which
    /// entries in `BLOCKLIST` the configuration did *not* put there. Deliberately
    /// **not persisted**: a block nobody wrote down must not outlive the process
    /// that decided on it, or an appliance ends up enforcing a reason no one can
    /// reconstruct. Restarting the agent is therefore always a way out.
    runtime_blocks: BTreeMap<String, Instant>,
    /// C20 captive-portal sessions: `(policy, MAC)` → the moment the device stops
    /// being admitted.
    ///
    /// Held here for the same reason as `runtime_blocks`, and deliberately not
    /// persisted for the mirror-image reason: a block that outlived the process
    /// that decided on it enforces a reason nobody can reconstruct, and an
    /// *admission* that outlived it would let a guest back onto the network after
    /// a restart nobody connected to their login. Restarting the agent ends every
    /// session, which is the correct way round.
    portal_sessions: BTreeMap<(PolicyId, [u8; 6]), Instant>,
    /// C18 port mappings opened at **run time** by a NAT-PMP/PCP request, keyed
    /// by `(policy, proto, external port)` and carrying the internal target and
    /// the moment the mapping closes.
    ///
    /// Not persisted, like the other two run-time tables — and here the reason is
    /// the sharpest of the three: a mapping is a hole a host on the inside asked
    /// for, and one that outlived the process that opened it would be an inbound
    /// port nobody can account for. A host that still wants it asks again, which
    /// is what the protocol has it do anyway.
    runtime_mappings: BTreeMap<MappingKey, MappingValue>,
}

/// Which hole: the zone policy it lives in, the protocol, and the WAN port.
type MappingKey = (PolicyId, u8, u16);

/// Where it points and until when: the inside address, its port, and the
/// deadline after which the hole closes on its own.
type MappingValue = ([u8; 4], u16, Instant);

/// The most run-time port mappings held at once.
///
/// `PORT_FORWARDS` holds 1024 entries and the operator's own forwards live in
/// the same table, so this is deliberately a small fraction of it: the failure
/// this prevents is a LAN host — a misbehaving one, or simply a busy one —
/// filling the map and leaving no room for a forward somebody configured.
const MAX_RUNTIME_MAPPINGS: usize = 256;

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
        // Same again for `velstra_main`, the datapath itself. Only the small
        // port-security gate (`velstra`) is attached to an interface; it tail-
        // calls straight into this one. The split exists because a call chain's
        // stack frames are summed against a single 512-byte limit and the two
        // together came to 528 — a tail call starts a fresh frame.
        {
            let main: &mut Xdp = ebpf
                .program_mut("velstra_main")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_main` program"))?
                .try_into()?;
            main.load()
                .context("loading XDP datapath program into the kernel")?;
        }
        let main_fd = {
            let main: &Xdp = ebpf
                .program("velstra_main")
                .ok_or_else(|| anyhow!("eBPF object has no `velstra_main` program"))?
                .try_into()?;
            main.fd()?.try_clone()?
        };
        {
            let mut prog_array = ProgramArray::try_from(
                ebpf.map_mut("VELSTRA_PROGS")
                    .ok_or_else(|| anyhow!("VELSTRA_PROGS map missing"))?,
            )?;
            prog_array
                .set(0, &flow_fd, 0)
                .context("registering velstra_forward in VELSTRA_PROGS")?;
            // Registered before the gate is attached, so the very first packet
            // already has somewhere to jump.
            prog_array
                .set(1, &main_fd, 0)
                .context("registering velstra_main in VELSTRA_PROGS")?;
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

        // Which interfaces need the TC egress hook, and why — see
        // [`egress_interfaces`]. Kept out of here so the rule can be read and
        // tested without loading an eBPF object.
        let egress_ifaces: Vec<String> = egress_interfaces(cfg, ifaces, egress)
            .into_iter()
            .filter(|n| if_nametoindex(n).is_ok())
            .collect();
        if !egress_ifaces.is_empty() {
            attach_egress(&mut ebpf, &egress_ifaces)?;
        }

        let mut fw = Self {
            ebpf,
            attached,
            applied: cfg.clone(),
            base: cfg.clone(),
            flowspec: Vec::new(),
            flowspec_refused: Vec::new(),
            auto_attached: HashSet::new(),
            config_attached: HashSet::new(),
            bum_attached: HashSet::new(),
            conntrack: None,
            runtime_blocks: BTreeMap::new(),
            portal_sessions: BTreeMap::new(),
            runtime_mappings: BTreeMap::new(),
        };
        fw.sync_bum_attachments(cfg);
        Ok(fw)
    }

    /// Attach the BUM head-end replication classifier to every tenant tap the
    /// config names that is present and not already carrying it.
    ///
    /// **Called on every reprogram, not only at startup**, and that is the whole
    /// point. A config-file agent is restarted by `sentinel commit`, so its taps
    /// are always present when it loads; a controller-driven agent is
    /// reconfigured *live* and its taps arrive minutes later, when a tenant is
    /// placed on it. Attaching only at load therefore left every controller-driven
    /// fabric with its flood set programmed, its counters present, and no
    /// classifier to read them — `bum_replicated` and `srv6_bum_replicated` stuck
    /// at zero for the life of the process, on both overlays.
    ///
    /// That failure is invisible from the box: nothing errors, the maps are
    /// correct, and the only symptom is that broadcast traffic does not cross —
    /// so a tenant cannot ARP or get a DHCP lease, which reads like a tenant
    /// problem rather than an agent one.
    ///
    /// Best-effort by design: a load or attach failure costs replication and
    /// nothing else, where taking the agent down would cost the firewall.
    fn sync_bum_attachments(&mut self, cfg: &RuntimeConfig) {
        // Either overlay: `velstra_bum` dispatches on whichever is enabled, and
        // gating the attach on the VXLAN one alone left an SRv6 host without a
        // classifier at all.
        if cfg.overlay.is_none() && cfg.srv6.is_none() {
            return;
        }
        // Forget taps whose netdev has gone (the TC classifier detached with it).
        // Without this, a VM restart that brings the tap back under the same name
        // leaves the stale name in the set, so the `wanted` filter below skips it
        // and it never gets a classifier again — `bum_replicated`/`srv6_bum_replicated`
        // stall until the agent restarts. Mirrors how `reconcile_auto_attach` and
        // `reconcile_config_interfaces` prune their attach sets.
        self.bum_attached.retain(|n| if_nametoindex(n).is_ok());
        let wanted: Vec<String> = cfg
            .interfaces
            .iter()
            .filter(|i| i.vni != 0 && !self.bum_attached.contains(&i.name))
            .filter(|i| if_nametoindex(&i.name).is_ok())
            .map(|i| i.name.clone())
            .collect();
        if wanted.is_empty() {
            return;
        }
        match attach_bum_ingress(&mut self.ebpf, &wanted) {
            Ok(()) => self.bum_attached.extend(wanted),
            Err(e) => warn!("BUM replication attach failed: {e:#}"),
        }
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
        self.base = cfg.clone();
        self.reprogram()
    }

    /// Replace the advertised (FlowSpec) rules and put the merged set in force.
    ///
    /// Separate from [`Self::reconfigure`] and not a variant of it: the two
    /// sources arrive on their own schedules, and each has to be able to change
    /// without knowing what the other last said.
    pub fn set_flowspec(
        &mut self,
        rules: Vec<velstra_config::ResolvedRule>,
        refused: Vec<(String, String)>,
    ) -> Result<()> {
        self.flowspec_refused = refused;
        // Only when the rules themselves moved. A rule that arrived and cannot
        // be enforced changes what an operator should be told and nothing about
        // the maps, and rewriting the whole policy set to record that would be
        // work for its own sake.
        if self.flowspec == rules {
            return Ok(());
        }
        self.flowspec = rules;
        self.reprogram()?;
        // A rule that only stops flows which have not started yet is not a
        // mitigation: a flood with a stable five-tuple keeps being admitted by
        // the stateful fast path for as long as its entry lives, which is
        // exactly the traffic somebody advertised the rule to stop.
        //
        // Best-effort on purpose. The entries are an optimisation, so failing to
        // clear one costs that flow its mitigation and nothing else — where
        // refusing to program the rules over it would cost every flow theirs.
        if let Err(e) = self.purge_discarded_flows() {
            log::warn!("flowspec: could not clear the flows it discards ({e:#})");
        }
        Ok(())
    }

    /// What the FlowSpec feed has come to: the rules in force and, beside them,
    /// what arrived and is not being enforced.
    pub fn flowspec_state(&self) -> (&[velstra_config::ResolvedRule], &[(String, String)]) {
        (&self.flowspec, &self.flowspec_refused)
    }

    /// Remove the `FW_FLOWS` entries the advertised discards match.
    ///
    /// Narrow by construction — see `crate::flowspec::flow_is_discarded`. The map
    /// may have been taken by the C9 sync task, in which case there is nothing
    /// here to clear and that is not an error.
    fn purge_discarded_flows(&mut self) -> Result<()> {
        let drops: Vec<_> = self
            .flowspec
            .iter()
            .filter(|r| r.action == Action::Drop)
            .cloned()
            .collect();
        if drops.is_empty() {
            return Ok(());
        }
        let Some(map) = self.ebpf.map_mut("FW_FLOWS") else {
            return Ok(());
        };
        // An LRU hash map is read and written through the same userspace handle
        // as an ordinary one; the eviction policy is the kernel's business.
        let mut flows: HashMap<_, FlowKey, u8> = HashMap::try_from(map)?;
        // Collected first: deleting while iterating a BPF map is how a scan
        // silently skips entries.
        let doomed: Vec<FlowKey> = flows
            .keys()
            .flatten()
            .filter(|key| {
                drops
                    .iter()
                    .any(|r| crate::flowspec::flow_is_discarded(r, key))
            })
            .collect();
        let count = doomed.len();
        for key in doomed {
            let _ = flows.remove(&key);
        }
        if count > 0 {
            log::info!("flowspec: cleared {count} flow(s) an advertised rule discards");
        }
        Ok(())
    }

    /// Put `base` + `flowspec` in force as one set.
    ///
    /// The whole policy set is rewritten rather than the changed rules alone,
    /// which is what makes there be exactly one writer of the rule tries — see
    /// `crate::flowspec`. `remove_stale` runs against the previously *merged*
    /// config, so a withdrawn advertised rule is taken out as surely as a
    /// deleted configured one.
    fn reprogram(&mut self) -> Result<()> {
        let merged = if self.flowspec.is_empty() {
            self.base.clone()
        } else {
            crate::flowspec::merge_into(&self.base, &self.flowspec)
        };
        apply_config(&mut self.ebpf, &merged, Some(&self.applied))?;
        // After the maps, not before: a classifier attached to a tap whose flood
        // set has not been written yet would replicate to an empty set, which is
        // harmless but means the first frames after a reconfigure are the ones
        // that go missing.
        self.sync_bum_attachments(&merged);
        self.applied = merged;
        Ok(())
    }

    /// Block `cidr` as a source across every policy, until `ttl` has passed.
    ///
    /// The blocklist the data plane consults is per-policy, but a source blocked
    /// because of what it *did* is not blocked "in zone lan" — it is blocked. So
    /// the entry goes into every policy, and `unblock` takes it out of every one.
    ///
    /// A CIDR the **configuration** already blocks is left alone and reported as
    /// such: adding it here would mean the expiry later removed a permanent entry
    /// the operator wrote, quietly turning their block off.
    ///
    /// Returns `false` when the address was already blocked by configuration.
    pub fn block_source(&mut self, cidr: &str, ttl: Duration) -> Result<bool> {
        if self.blocked_by_config(cidr) {
            return Ok(false);
        }
        self.write_block(cidr, true)?;
        self.runtime_blocks
            .insert(cidr.to_string(), Instant::now() + ttl);
        Ok(true)
    }

    /// Drop a run-time block early. Returns whether there was one.
    pub fn unblock_source(&mut self, cidr: &str) -> Result<bool> {
        if self.runtime_blocks.remove(cidr).is_none() {
            return Ok(false);
        }
        self.write_block(cidr, false)?;
        Ok(true)
    }

    /// Lift every run-time block. Returns how many there were.
    ///
    /// For the false-positive storm: a rule that turned out too broad blocks a
    /// dozen sources in a minute, and undoing that one address at a time is the
    /// wrong thing to be doing while it is happening.
    pub fn unblock_all(&mut self) -> Result<usize> {
        let all: Vec<String> = self.runtime_blocks.keys().cloned().collect();
        for cidr in &all {
            self.runtime_blocks.remove(cidr);
            self.write_block(cidr, false)
                .with_context(|| format!("lifting the block on {cidr}"))?;
        }
        Ok(all.len())
    }

    /// Remove every run-time block whose time is up. Returns how many went.
    ///
    /// This is what makes an automatic block safe to switch on: whatever a
    /// detector decides, it undoes itself. An appliance that could permanently
    /// lock out an address on its own reading of a packet is one nobody should
    /// run.
    pub fn expire_blocks(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<String> = self
            .runtime_blocks
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(cidr, _)| cidr.clone())
            .collect();
        for cidr in &due {
            self.runtime_blocks.remove(cidr);
            if let Err(e) = self.write_block(cidr, false) {
                warn!("could not lift the expired block on {cidr}: {e:#}");
            }
        }
        due.len()
    }

    /// The live run-time blocks as `(cidr, seconds remaining)`.
    pub fn runtime_blocks(&self) -> Vec<(String, u64)> {
        let now = Instant::now();
        self.runtime_blocks
            .iter()
            .map(|(cidr, &expiry)| {
                (
                    cidr.clone(),
                    expiry.saturating_duration_since(now).as_secs(),
                )
            })
            .collect()
    }

    /// Open one port-forward at **run time**, until `ttl` has passed.
    ///
    /// This is what a NAT-PMP/PCP request becomes (roadmap C18). It is the only
    /// other thing besides a portal admission that opens the firewall without a
    /// configuration change, and it is bounded much more tightly, because the
    /// party asking is a host on the inside rather than a person at a page:
    ///
    /// * a `(policy, proto, port)` the **configuration** already forwards is
    ///   refused outright. Overwriting it would silently redirect somebody
    ///   else's service, and — worse — the expiry would later *delete* an entry
    ///   the operator wrote, turning their port-forward off hours after a LAN
    ///   host asked for something unrelated;
    /// * the number of run-time mappings is capped well below the map's size, so
    ///   one host cannot fill the table and starve the operator's own forwards;
    /// * every mapping carries a deadline, like every other run-time opening
    ///   here.
    ///
    /// Returns `false` when the configuration owns that key.
    pub fn map_port(
        &mut self,
        policy: PolicyId,
        proto: u8,
        external_port: u16,
        internal: [u8; 4],
        internal_port: u16,
        ttl: Duration,
    ) -> Result<bool> {
        if external_port == 0 {
            bail!("port 0 is not a port");
        }
        if internal == [0; 4] {
            bail!("0.0.0.0 is not a host to forward to");
        }
        let key = (policy, proto, external_port);
        if self.forwarded_by_config(policy, proto, external_port) {
            return Ok(false);
        }
        if !self.runtime_mappings.contains_key(&key)
            && self.runtime_mappings.len() >= MAX_RUNTIME_MAPPINGS
        {
            bail!(
                "already holding {MAX_RUNTIME_MAPPINGS} run-time mappings; \
                 refusing to crowd out the configured port-forwards"
            );
        }
        let reply = resolve_reply_policy(internal, &self.applied.interfaces);
        let value = PortFwd::new(internal, internal_port).with_reply_policy(reply);
        self.write_mapping(policy, proto, external_port, Some(value))?;
        self.runtime_mappings
            .insert(key, (internal, internal_port, Instant::now() + ttl));
        Ok(true)
    }

    /// Close one run-time mapping early. Returns whether there was one.
    ///
    /// Only a **run-time** mapping: a configured port-forward is not something a
    /// request from the inside may take away, any more than it is something it
    /// may overwrite.
    pub fn unmap_port(&mut self, policy: PolicyId, proto: u8, external_port: u16) -> Result<bool> {
        if self
            .runtime_mappings
            .remove(&(policy, proto, external_port))
            .is_none()
        {
            return Ok(false);
        }
        self.write_mapping(policy, proto, external_port, None)?;
        Ok(true)
    }

    /// Close every run-time mapping. Returns how many there were.
    pub fn unmap_all(&mut self) -> Result<usize> {
        let all: Vec<MappingKey> = self.runtime_mappings.keys().copied().collect();
        for (policy, proto, port) in &all {
            self.runtime_mappings.remove(&(*policy, *proto, *port));
            self.write_mapping(*policy, *proto, *port, None)
                .with_context(|| format!("closing the mapping on {proto}/{port}"))?;
        }
        Ok(all.len())
    }

    /// Remove every mapping whose time is up. Returns how many went.
    pub fn expire_mappings(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<(PolicyId, u8, u16)> = self
            .runtime_mappings
            .iter()
            .filter(|(_, (_, _, expiry))| *expiry <= now)
            .map(|(key, _)| *key)
            .collect();
        for (policy, proto, port) in &due {
            self.runtime_mappings.remove(&(*policy, *proto, *port));
            if let Err(e) = self.write_mapping(*policy, *proto, *port, None) {
                warn!("could not close the expired mapping on {proto}/{port}: {e}");
            }
        }
        due.len()
    }

    /// The live run-time mappings as
    /// `(policy, proto, external port, internal ip, internal port, seconds left)`.
    pub fn runtime_mappings(&self) -> Vec<(PolicyId, u8, u16, [u8; 4], u16, u64)> {
        let now = Instant::now();
        self.runtime_mappings
            .iter()
            .map(|(&(policy, proto, port), &(ip, iport, expiry))| {
                (
                    policy,
                    proto,
                    port,
                    ip,
                    iport,
                    expiry.saturating_duration_since(now).as_secs(),
                )
            })
            .collect()
    }

    /// Whether the applied configuration already forwards this exact key.
    fn forwarded_by_config(&self, policy: PolicyId, proto: u8, port: u16) -> bool {
        self.applied
            .port_forwards
            .iter()
            .any(|pf| pf.policy == policy && pf.proto == proto && pf.port == port)
    }

    /// Insert or remove one `PORT_FORWARDS` entry.
    fn write_mapping(
        &mut self,
        policy: PolicyId,
        proto: u8,
        port: u16,
        value: Option<PortFwd>,
    ) -> Result<()> {
        let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
            self.ebpf
                .map_mut("PORT_FORWARDS")
                .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
        )?;
        let key = ScopedPortKey::new(policy, proto, port);
        match value {
            Some(value) => map
                .insert(key, value, 0)
                .with_context(|| format!("mapping {proto}/{port} in policy {policy}"))?,
            None => {
                let _ = map.remove(&key);
            }
        }
        Ok(())
    }

    /// The policies (zones) that are behind a captive portal, in id order.
    ///
    /// Only these can be admitted into: the `PORTAL_CLIENTS` map is consulted
    /// nowhere else, so an admission is structurally incapable of opening
    /// anything in a zone that has no portal. That is the property that makes a
    /// write verb on the portal socket a bounded thing rather than a hole.
    pub fn portal_policies(&self) -> Vec<PolicyId> {
        let mut ids: Vec<PolicyId> = self
            .applied
            .policies
            .iter()
            .filter(|p| p.portal.is_some())
            .map(|p| p.id)
            .collect();
        ids.sort_unstable();
        ids
    }

    /// The MAC the data plane last saw `addr` use, in `policy`, on traffic
    /// addressed to the portal.
    ///
    /// `None` means that address has not talked to the portal — which is what a
    /// login from an address nobody has seen looks like, and is exactly the case
    /// that must not be admitted.
    pub fn portal_mac_for(
        &mut self,
        policy: PolicyId,
        addr: std::net::IpAddr,
    ) -> Result<Option<[u8; 6]>> {
        let key = match addr {
            std::net::IpAddr::V4(v4) => PortalSeenKey::v4(policy, v4.octets()),
            std::net::IpAddr::V6(v6) => PortalSeenKey::v6(policy, v6.octets()),
        };
        let seen: HashMap<_, PortalSeenKey, [u8; 6]> = HashMap::try_from(
            self.ebpf
                .map_mut("PORTAL_SEEN")
                .ok_or_else(|| anyhow!("PORTAL_SEEN map missing"))?,
        )?;
        Ok(seen.get(&key, 0).ok())
    }

    /// Admit `mac` to `policy` for `ttl`.
    ///
    /// Re-admitting a device that is already admitted **extends** its session
    /// rather than refusing: a guest who logs in again because a page said their
    /// time was nearly up means to keep going, and answering "you are already in"
    /// would let the old deadline end them mid-sentence.
    pub fn portal_admit(&mut self, policy: PolicyId, mac: [u8; 6], ttl: Duration) -> Result<()> {
        if !self.portal_policies().contains(&policy) {
            bail!("policy {policy} has no captive portal, so nothing can be admitted to it");
        }
        self.write_portal(policy, mac, true)?;
        self.portal_sessions
            .insert((policy, mac), Instant::now() + ttl);
        Ok(())
    }

    /// End one session early. Returns whether there was one.
    pub fn portal_revoke(&mut self, policy: PolicyId, mac: [u8; 6]) -> Result<bool> {
        if self.portal_sessions.remove(&(policy, mac)).is_none() {
            return Ok(false);
        }
        self.write_portal(policy, mac, false)?;
        Ok(true)
    }

    /// End every session. Returns how many there were.
    pub fn portal_revoke_all(&mut self) -> Result<usize> {
        let all: Vec<(PolicyId, [u8; 6])> = self.portal_sessions.keys().copied().collect();
        for (policy, mac) in &all {
            self.portal_sessions.remove(&(*policy, *mac));
            self.write_portal(*policy, *mac, false)
                .with_context(|| format!("ending the session for {}", render_mac(*mac)))?;
        }
        Ok(all.len())
    }

    /// Remove every session whose time is up. Returns how many went.
    ///
    /// The deadline lives here rather than in the map because the data plane has
    /// no wall clock — and because it is user space that must survive the
    /// question "why is this device still on the network".
    pub fn expire_portal_sessions(&mut self) -> usize {
        let now = Instant::now();
        let due: Vec<(PolicyId, [u8; 6])> = self
            .portal_sessions
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(key, _)| *key)
            .collect();
        for (policy, mac) in &due {
            self.portal_sessions.remove(&(*policy, *mac));
            if let Err(e) = self.write_portal(*policy, *mac, false) {
                warn!(
                    "could not end the expired session for {}: {e:#}",
                    render_mac(*mac)
                );
            }
        }
        due.len()
    }

    /// The live sessions as `(policy, mac, seconds remaining)`.
    pub fn portal_sessions(&self) -> Vec<(PolicyId, [u8; 6], u64)> {
        let now = Instant::now();
        self.portal_sessions
            .iter()
            .map(|(&(policy, mac), &expiry)| {
                (policy, mac, expiry.saturating_duration_since(now).as_secs())
            })
            .collect()
    }

    /// Insert or remove one `(policy, MAC)` in `PORTAL_CLIENTS`.
    fn write_portal(&mut self, policy: PolicyId, mac: [u8; 6], admit: bool) -> Result<()> {
        let mut clients: HashMap<_, PortalClientKey, u8> = HashMap::try_from(
            self.ebpf
                .map_mut("PORTAL_CLIENTS")
                .ok_or_else(|| anyhow!("PORTAL_CLIENTS map missing"))?,
        )?;
        let key = PortalClientKey::new(policy, mac);
        if admit {
            clients.insert(key, 1u8, 0).with_context(|| {
                format!(
                    "admitting {} to policy {policy} (the table may be full)",
                    render_mac(mac)
                )
            })?;
        } else {
            let _ = clients.remove(&key);
        }
        Ok(())
    }

    /// Whether the applied configuration already blocks this exact CIDR.
    fn blocked_by_config(&self, cidr: &str) -> bool {
        self.applied.policies.iter().any(|p| {
            p.blocklist.iter().any(|c| c.to_string() == cidr)
                || p.blocklist6.iter().any(|c| c.to_string() == cidr)
        })
    }

    /// Insert or remove `cidr` in the blocklist trie of every policy.
    ///
    /// Accepts a bare address as well as a CIDR — a detector reports the host it
    /// saw, not a prefix — and picks the v4 or v6 trie from what parses.
    fn write_block(&mut self, cidr: &str, insert: bool) -> Result<()> {
        let policies: Vec<PolicyId> = self.applied.policies.iter().map(|p| p.id).collect();
        if let Ok(v4) = parse_cidr_v4(cidr) {
            let (prefix, addr) = v4.lpm_key();
            let mut trie: LpmTrie<_, ScopedAddr, u32> = LpmTrie::try_from(
                self.ebpf
                    .map_mut("BLOCKLIST")
                    .ok_or_else(|| anyhow!("BLOCKLIST map missing"))?,
            )?;
            for id in policies {
                let key = Key::new(ScopedAddr::POLICY_BITS + prefix, ScopedAddr::new(id, addr));
                if insert {
                    trie.insert(&key, 1u32, 0)
                        .with_context(|| format!("blocking {cidr} in policy {id}"))?;
                } else {
                    let _ = trie.remove(&key);
                }
            }
            return Ok(());
        }
        let v6 =
            parse_cidr_v6(cidr).map_err(|e| anyhow!("{cidr:?} is not an address or CIDR: {e}"))?;
        let (prefix, addr) = v6.lpm_key();
        let mut trie: LpmTrie<_, ScopedAddr6, u32> = LpmTrie::try_from(
            self.ebpf
                .map_mut("BLOCKLIST6")
                .ok_or_else(|| anyhow!("BLOCKLIST6 map missing"))?,
        )?;
        for id in policies {
            let key = Key::new(
                ScopedAddr6::POLICY_BITS + prefix,
                ScopedAddr6::new(id, addr),
            );
            if insert {
                trie.insert(&key, 1u32, 0)
                    .with_context(|| format!("blocking {cidr} in policy {id}"))?;
            } else {
                let _ = trie.remove(&key);
            }
        }
        Ok(())
    }

    /// The WAN port block `addr` is assigned on each CGNAT-configured egress, as
    /// `(interface, first_port, last_port)`.
    ///
    /// Read from the live map and computed with [`CgnatLayout::range_of`] — the
    /// same call the data plane makes — so the answer an operator reports and the
    /// ports actually handed out cannot disagree. That is the whole point of a
    /// deterministic layout: attribution without a translation log.
    pub fn cgnat_blocks(&self, addr: [u8; 4]) -> Result<Vec<(String, u16, u16)>> {
        let map: HashMap<_, u32, CgnatLayout> = HashMap::try_from(
            self.ebpf
                .map("CGNAT")
                .ok_or_else(|| anyhow!("CGNAT map missing"))?,
        )?;
        let mut out = Vec::new();
        for key in map.keys() {
            let ifindex = key?;
            let Ok(layout) = map.get(&ifindex, 0) else {
                continue;
            };
            if let Some((first, last)) = layout.range_of(addr) {
                out.push((if_indextoname(ifindex), first, last));
            }
        }
        out.sort();
        Ok(out)
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
    /// The handle is **shared**, not surrendered: the first call moves the map out
    /// of the eBPF object and every later call clones the same `Arc`. aya allows
    /// only one owner of a taken map, so handing it to the sync task outright would
    /// mean that turning HA on silently takes the flow table away from everything
    /// else that wants to read it — the diagnostics view included.
    ///
    /// [`take_local_macs`]: Firewall::take_local_macs
    /// [`reconfigure`]: Firewall::reconfigure
    pub fn conntrack_handle(&mut self) -> Result<Arc<Mutex<HashMap<MapData, FlowKey, FlowState>>>> {
        if let Some(handle) = &self.conntrack {
            return Ok(handle.clone());
        }
        let map = self
            .ebpf
            .take_map("CONNTRACK")
            .ok_or_else(|| anyhow!("CONNTRACK map missing"))?;
        let handle = Arc::new(Mutex::new(
            HashMap::try_from(map).context("CONNTRACK as a HashMap")?,
        ));
        self.conntrack = Some(handle.clone());
        Ok(handle)
    }

    /// A snapshot of the live NAT flow table (`CONNTRACK`), for the diagnostics
    /// view. Shares the handle with the C9 sync task via [`conntrack_handle`],
    /// so it works whether or not HA is enabled.
    ///
    /// A miss on an individual key is skipped rather than failing the snapshot: the
    /// map is an LRU the data plane mutates constantly, so an entry can be evicted
    /// between listing the keys and reading its value. A diagnostics view that
    /// errored out on that race would be unusable under load — exactly when it
    /// matters.
    ///
    /// [`conntrack_handle`]: Firewall::conntrack_handle
    pub async fn read_flows(&mut self) -> Result<Vec<(FlowKey, FlowState)>> {
        let handle = self.conntrack_handle()?;
        let map = handle.lock().await;
        let mut out = Vec::new();
        for key in map.keys().flatten() {
            if let Ok(state) = map.get(&key, 0) {
                out.push((key, state));
            }
        }
        Ok(out)
    }

    /// Take ownership of the `FW_FLOWS` map handle for the same C9 conntrack-sync
    /// task. `FW_FLOWS` is the stateful-firewall reply table (`FlowKey → present`,
    /// value a mere presence flag); replicating it alongside `CONNTRACK` is what
    /// lets an established but *non-NAT'd* stateful flow's reply survive a VRRP
    /// failover — without it the reply misses `FW_FLOWS` on the new master and the
    /// deny-by-default zone drops it. Same take-out rationale as [`take_conntrack`]:
    /// the XDP map reference is already resolved, the kernel map lives on, and
    /// nothing else in the control plane touches `FW_FLOWS`.
    ///
    /// [`take_conntrack`]: Firewall::take_conntrack
    pub fn take_fw_flows(&mut self) -> Result<HashMap<MapData, FlowKey, u8>> {
        let map = self
            .ebpf
            .take_map("FW_FLOWS")
            .ok_or_else(|| anyhow!("FW_FLOWS map missing"))?;
        HashMap::try_from(map).context("FW_FLOWS as a HashMap")
    }
}

/// Raise the locked-memory rlimit so map allocation succeeds on older kernels
/// that still account BPF memory against `RLIMIT_MEMLOCK`.
/// LPM `(prefix_len, addr)` for a port rule's optional source constraint. `None`
/// ("from any") becomes a `/0` source — prefix == `FIXED_BITS`, address `0` —
/// which the trie matches for every packet; a `Some` CIDR extends the prefix by
/// the block's bits so a specific source outranks a `from any` rule.
/// The prefix length an address constraint matches on, for the specificity byte
/// packed into the rule value. `None` (any) is `0`.
fn cidr_bits(cidr: &Option<Cidr4>) -> u8 {
    cidr.as_ref().map_or(0, |c| c.prefix)
}

/// The `DST_RULES` LPM prefix + key tail for a destination constraint. Only called
/// for a rule that has one, so the `None` arm is the unreachable-but-total case.
fn port_rule_dst_lpm(dst: &Option<Cidr4>) -> (u32, u32) {
    match dst {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedDstPortKey::FIXED_BITS + bits, addr)
        }
        None => (ScopedDstPortKey::prefix_len(0), 0),
    }
}

/// The prefix length an IPv6 address constraint matches on, for the specificity
/// byte packed into the rule value.
fn cidr6_bits(cidr: &Option<Cidr6>) -> u8 {
    cidr.as_ref().map_or(0, |c| c.prefix)
}

/// The `PORT_RULES6` LPM prefix + key tail for an IPv6 source constraint.
fn port_rule_src6_lpm(src: &Option<Cidr6>) -> (u32, [u8; 16]) {
    match src {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedSrcPortKey6::FIXED_BITS + bits, addr)
        }
        None => (ScopedSrcPortKey6::prefix_len(0), [0; 16]),
    }
}

/// The `DST_RULES6` LPM prefix + key tail for an IPv6 destination constraint.
fn port_rule_dst6_lpm(dst: &Option<Cidr6>) -> (u32, [u8; 16]) {
    match dst {
        Some(c) => {
            let (bits, addr) = c.lpm_key();
            (ScopedDstPortKey6::FIXED_BITS + bits, addr)
        }
        None => (ScopedDstPortKey6::prefix_len(0), [0; 16]),
    }
}

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

/// A MAC address as an operator writes it. Used wherever one appears in a
/// message, so a session, a log line and a diagnostic all name a device the same
/// way.
pub fn render_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
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
        let mut gates: HashMap<_, PolicyId, PortalGate> = HashMap::try_from(
            ebpf.map_mut("PORTAL_GATES")
                .ok_or_else(|| anyhow!("PORTAL_GATES map missing"))?,
        )?;
        for policy in &old.policies {
            let _ = gates.remove(&policy.id);
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
            for rule in policy
                .port_rules
                .iter()
                .filter(|r| r.dst.is_none() && r.src6.is_none() && r.dst6.is_none())
            {
                let (prefix, addr) = port_rule_src_lpm(&rule.src);
                let _ = rules.remove(&Key::new(
                    prefix,
                    ScopedSrcPortKey::with_ifindex(
                        policy.id,
                        rule.key.proto,
                        rule.icmp_type,
                        if rule.icmp_type == 0 {
                            rule.key.port
                        } else {
                            0
                        },
                        stale_ifindex(&rule.in_interface),
                        addr,
                    ),
                ));
            }
        }
    }
    {
        // The v6 tries are cleared the same way: a rule that survives the sweep
        // because nobody looked in its trie is a rule the operator deleted and
        // the data plane still enforces.
        let mut rules: LpmTrie<_, ScopedSrcPortKey6, u32> = LpmTrie::try_from(
            ebpf.map_mut("PORT_RULES6")
                .ok_or_else(|| anyhow!("PORT_RULES6 map missing"))?,
        )?;
        for policy in &old.policies {
            for rule in policy.port_rules.iter().filter(|r| r.src6.is_some()) {
                let (prefix, addr) = port_rule_src6_lpm(&rule.src6);
                let _ = rules.remove(&Key::new(
                    prefix,
                    ScopedSrcPortKey6::with_ifindex(
                        policy.id,
                        rule.key.proto,
                        rule.icmp_type,
                        if rule.icmp_type == 0 {
                            rule.key.port
                        } else {
                            0
                        },
                        stale_ifindex(&rule.in_interface),
                        addr,
                    ),
                ));
            }
        }
    }
    {
        let mut rules: LpmTrie<_, ScopedDstPortKey6, u32> = LpmTrie::try_from(
            ebpf.map_mut("DST_RULES6")
                .ok_or_else(|| anyhow!("DST_RULES6 map missing"))?,
        )?;
        for policy in &old.policies {
            for rule in policy.port_rules.iter().filter(|r| r.dst6.is_some()) {
                let (prefix, addr) = port_rule_dst6_lpm(&rule.dst6);
                let _ = rules.remove(&Key::new(
                    prefix,
                    ScopedDstPortKey6::with_ifindex(
                        policy.id,
                        rule.key.proto,
                        rule.icmp_type,
                        if rule.icmp_type == 0 {
                            rule.key.port
                        } else {
                            0
                        },
                        stale_ifindex(&rule.in_interface),
                        addr,
                    ),
                ));
            }
        }
    }
    {
        let mut rules: LpmTrie<_, ScopedDstPortKey, u32> = LpmTrie::try_from(
            ebpf.map_mut("DST_RULES")
                .ok_or_else(|| anyhow!("DST_RULES map missing"))?,
        )?;
        for policy in &old.policies {
            for rule in policy.port_rules.iter().filter(|r| r.dst.is_some()) {
                let (prefix, addr) = port_rule_dst_lpm(&rule.dst);
                let _ = rules.remove(&Key::new(
                    prefix,
                    ScopedDstPortKey::with_ifindex(
                        policy.id,
                        rule.key.proto,
                        rule.icmp_type,
                        if rule.icmp_type == 0 {
                            rule.key.port
                        } else {
                            0
                        },
                        stale_ifindex(&rule.in_interface),
                        addr,
                    ),
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
        // The set of segments this host admits a decap into. Drop the old set;
        // program_interfaces and program_overlay re-add every still-current VNI,
        // so a segment shared with a surviving port or IRB route is unaffected.
        //
        // Reconciled rather than left to accumulate because this map is a
        // **tenant-isolation** boundary: a VNI that lingers after its last local
        // port and route are gone lets any trusted peer VTEP keep injecting inner
        // frames into a segment this host no longer serves.
        let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("LOCAL_VNIS")
                .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
        )?;
        for vni in admitted_vnis(old) {
            let _ = local_vnis.remove(&vni);
        }
    }
    {
        // B7 IRB_ROUTES is an LpmTrie keyed exactly like OVERLAY_FDB; drop the old
        // set so a prefix the control plane withdrew stops being routed, rather
        // than lingering and sending its traffic to a VTEP that no longer owns it.
        let mut irb: LpmTrie<_, TunnelKey, IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("IRB_ROUTES")
                .ok_or_else(|| anyhow!("IRB_ROUTES map missing"))?,
        )?;
        for r in &old.irb_routes {
            let (_, addr) = r.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(r.inner_dst.prefix),
                TunnelKey::new(r.vni, addr),
            );
            let _ = irb.remove(&key);
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
        for r in &old.irb_routes {
            let _ = peers.remove(&r.remote_vtep_ip);
        }
        // Flood VTEPs are trusted decap peers too (they receive our encapped BUM
        // copies and send their own back).
        for fv in &old.flood_vteps {
            let _ = peers.remove(&fv.remote_vtep_ip);
        }
    }
    {
        // B9 SRV6_IRB_ROUTES is an LpmTrie keyed exactly like IRB_ROUTES, and needs
        // the same treatment for the same reason: a withdrawn prefix that lingers
        // keeps routing a tenant's traffic to a peer that no longer owns it.
        // (`program_srv6` reconciles the flood set by key, but a trie cannot be
        // enumerated, so its stale keys are removed from the *old* config here.)
        let mut irb: LpmTrie<_, TunnelKey, Srv6IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("SRV6_IRB_ROUTES")
                .ok_or_else(|| anyhow!("SRV6_IRB_ROUTES map missing"))?,
        )?;
        for r in &old.srv6_irb_routes {
            let (_, addr) = r.inner_dst.lpm_key();
            let key = Key::new(
                TunnelKey::prefix_len(r.inner_dst.prefix),
                TunnelKey::new(r.vni, addr),
            );
            let _ = irb.remove(&key);
        }
    }
    if let Some(old_srv6) = &old.srv6 {
        // B9 trusted-SRv6-peer set (C2): drop the old peers so a peer removed from
        // the config stops being an authorized decap source on this live
        // reconfigure; program_srv6 re-adds every still-current one. (Unlike the
        // SRv6 SID/FDB maps this security-sensitive set is reconciled, so a
        // de-authorized peer never lingers trusted until the next restart.)
        let mut srv6_peers: HashMap<_, [u8; 16], u8> = HashMap::try_from(
            ebpf.map_mut("SRV6_PEERS")
                .ok_or_else(|| anyhow!("SRV6_PEERS map missing"))?,
        )?;
        for p in &old_srv6.peers {
            let _ = srv6_peers.remove(p);
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
    program_services(ebpf, &cfg.services, &cfg.interfaces)?;
    program_port_forwards(ebpf, &cfg.port_forwards, &cfg.interfaces)?;
    program_synproxy(ebpf, &cfg.synproxy)?;
    program_masquerade(ebpf, &cfg.interfaces)?;
    program_mss_clamp(ebpf, &cfg.interfaces)?;
    program_port_bindings(ebpf, &cfg.interfaces)?;
    program_port_limits(ebpf, &cfg.interfaces)?;
    program_mac_rules(ebpf, &cfg.policies)?;
    program_cgnat(ebpf, &cfg.interfaces)?;
    program_npt66(ebpf, &cfg.npt66)?;
    program_overlay(
        ebpf,
        cfg.overlay.as_ref(),
        &cfg.tunnels,
        &cfg.mac_routes,
        &cfg.irb_routes,
        &cfg.neighbors,
        &cfg.nd_neighbors,
        &cfg.flood_vteps,
    )?;
    program_srv6(
        ebpf,
        cfg.srv6.as_ref(),
        &cfg.srv6_routes,
        &cfg.srv6_local_sids,
        &cfg.srv6_floods,
        &cfg.srv6_irb_routes,
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
/// Assign each rate-limited rule a `RULE_LIMITS` slot and write its bucket.
///
/// Slots are handed out in iteration order and are 1-based, since `0` is what a
/// rule's packed value carries for "unlimited". Returns the slot for each
/// `(policy id, rule index)` so the trie writers can stamp it into the value.
///
/// A config with more limited rules than the value's 7 bits can name gets the
/// excess **left unlimited and logged**, rather than wrapping into another rule's
/// bucket — sharing a limiter with an unrelated rule is a silent, very confusing
/// failure.
fn program_rate_limits(
    ebpf: &mut Ebpf,
    policies: &[PolicyConfig],
) -> Result<std::collections::HashMap<(PolicyId, usize), u32>> {
    let mut slots = std::collections::HashMap::new();
    let mut buckets: Vec<(u32, RateBucket)> = Vec::new();
    for policy in policies {
        for (index, rule) in policy.port_rules.iter().enumerate() {
            let Some((rate, burst)) = rule.limit else {
                continue;
            };
            let slot = buckets.len() as u32 + 1;
            if slot > MAX_RULE_LIMITS {
                warn!(
                    "policy {}: more than {MAX_RULE_LIMITS} rate-limited rules; the rule \
                     on port {} stays unlimited",
                    policy.id, rule.key.port
                );
                continue;
            }
            slots.insert((policy.id, index), slot);
            buckets.push((slot, RateBucket::new(rate, burst)));
        }
    }
    if buckets.is_empty() {
        return Ok(slots);
    }
    let mut map: Array<_, RateBucket> = Array::try_from(
        ebpf.map_mut("RULE_LIMITS")
            .ok_or_else(|| anyhow!("RULE_LIMITS map missing"))?,
    )?;
    for (slot, bucket) in &buckets {
        map.set(*slot, bucket, 0)
            .with_context(|| format!("inserting rate limit slot {slot}"))?;
    }
    Ok(slots)
}

fn program_policies(ebpf: &mut Ebpf, policies: &[PolicyConfig]) -> Result<()> {
    let limit_slots = program_rate_limits(ebpf, policies)?;
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
        // C20: the gate entry and the policy's portal flag are written by the
        // same apply, in this order, so the flag is never set while the gate it
        // reads is missing.
        let mut gates: HashMap<_, PolicyId, PortalGate> = HashMap::try_from(
            ebpf.map_mut("PORTAL_GATES")
                .ok_or_else(|| anyhow!("PORTAL_GATES map missing"))?,
        )?;
        for policy in policies {
            match policy.portal {
                Some(gate) => gates
                    .insert(policy.id, gate, 0)
                    .with_context(|| format!("writing PORTAL_GATES for policy {}", policy.id))?,
                // A policy that lost its portal must lose its gate too, or a
                // later re-gating would inherit yesterday's address.
                None => {
                    let _ = gates.remove(&policy.id);
                }
            }
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
            for (index, rule) in policy
                .port_rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.dst.is_none() && r.src6.is_none() && r.dst6.is_none())
            {
                let (prefix, addr) = port_rule_src_lpm(&rule.src);
                let slot = limit_slots.get(&(policy.id, index)).copied().unwrap_or(0);
                rules
                    .insert(
                        &Key::new(
                            prefix,
                            ScopedSrcPortKey::with_ifindex(
                                policy.id,
                                rule.key.proto,
                                rule.icmp_type,
                                if rule.icmp_type == 0 {
                                    rule.key.port
                                } else {
                                    0
                                },
                                rule_ifindex(&rule.in_interface)?,
                                addr,
                            ),
                        ),
                        port_rule_with_limit(
                            port_rule_value(rule.action, rule.log, cidr_bits(&rule.src))
                                | rule.scope,
                            slot,
                        ),
                        0,
                    )
                    .context("inserting port rule")?;
            }
        }
    }
    {
        // The IPv6 source trie. A rule lands in exactly one of the four tries —
        // the family follows from what the operator wrote, and a rule that named
        // a v6 prefix used to land in none of them at all.
        let mut rules: LpmTrie<_, ScopedSrcPortKey6, u32> = LpmTrie::try_from(
            ebpf.map_mut("PORT_RULES6")
                .ok_or_else(|| anyhow!("PORT_RULES6 map missing"))?,
        )?;
        for policy in policies {
            for (index, rule) in policy
                .port_rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.src6.is_some())
            {
                let (prefix, addr) = port_rule_src6_lpm(&rule.src6);
                let slot = limit_slots.get(&(policy.id, index)).copied().unwrap_or(0);
                rules
                    .insert(
                        &Key::new(
                            prefix,
                            ScopedSrcPortKey6::with_ifindex(
                                policy.id,
                                rule.key.proto,
                                rule.icmp_type,
                                if rule.icmp_type == 0 {
                                    rule.key.port
                                } else {
                                    0
                                },
                                rule_ifindex(&rule.in_interface)?,
                                addr,
                            ),
                        ),
                        port_rule_with_limit(
                            port_rule_value(rule.action, rule.log, cidr6_bits(&rule.src6))
                                | rule.scope,
                            slot,
                        ),
                        0,
                    )
                    .context("inserting IPv6 port rule")?;
            }
        }
    }
    {
        // The IPv6 destination trie.
        let mut rules: LpmTrie<_, ScopedDstPortKey6, u32> = LpmTrie::try_from(
            ebpf.map_mut("DST_RULES6")
                .ok_or_else(|| anyhow!("DST_RULES6 map missing"))?,
        )?;
        for policy in policies {
            for (index, rule) in policy
                .port_rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.dst6.is_some())
            {
                let (prefix, addr) = port_rule_dst6_lpm(&rule.dst6);
                let slot = limit_slots.get(&(policy.id, index)).copied().unwrap_or(0);
                rules
                    .insert(
                        &Key::new(
                            prefix,
                            ScopedDstPortKey6::with_ifindex(
                                policy.id,
                                rule.key.proto,
                                rule.icmp_type,
                                if rule.icmp_type == 0 {
                                    rule.key.port
                                } else {
                                    0
                                },
                                rule_ifindex(&rule.in_interface)?,
                                addr,
                            ),
                        ),
                        port_rule_with_limit(
                            port_rule_value(rule.action, rule.log, cidr6_bits(&rule.dst6))
                                | rule.scope,
                            slot,
                        ),
                        0,
                    )
                    .context("inserting IPv6 destination rule")?;
            }
        }
    }
    {
        // Destination-constrained rules live in their own trie: a longest-prefix
        // match ranks one address field, and it is the *last* one in the key.
        let mut rules: LpmTrie<_, ScopedDstPortKey, u32> = LpmTrie::try_from(
            ebpf.map_mut("DST_RULES")
                .ok_or_else(|| anyhow!("DST_RULES map missing"))?,
        )?;
        for policy in policies {
            for (index, rule) in policy
                .port_rules
                .iter()
                .enumerate()
                .filter(|(_, r)| r.dst.is_some())
            {
                let (prefix, addr) = port_rule_dst_lpm(&rule.dst);
                let slot = limit_slots.get(&(policy.id, index)).copied().unwrap_or(0);
                rules
                    .insert(
                        &Key::new(
                            prefix,
                            ScopedDstPortKey::with_ifindex(
                                policy.id,
                                rule.key.proto,
                                rule.icmp_type,
                                if rule.icmp_type == 0 {
                                    rule.key.port
                                } else {
                                    0
                                },
                                rule_ifindex(&rule.in_interface)?,
                                addr,
                            ),
                        ),
                        port_rule_with_limit(
                            port_rule_value(rule.action, rule.log, cidr_bits(&rule.dst))
                                | rule.scope,
                            slot,
                        ),
                        0,
                    )
                    .context("inserting destination rule")?;
            }
        }
    }
    Ok(())
}

/// Every VNI a config could have admitted a decap into: each tenant port's
/// segment, plus the **routed** VNI of every IRB route (B7), which belongs to no
/// local port and is therefore registered from the routes alone.
///
/// Used to *clear* the old set on a reconfigure. The removal side is deliberately
/// broader than the add side: `program_interfaces` only registers a VNI whose
/// interface actually exists on the host right now, whereas this must name
/// everything the previous config might have registered — anything it misses is
/// a segment that stays decap-admitted after its last local port is gone.
fn admitted_vnis(cfg: &RuntimeConfig) -> BTreeSet<u32> {
    cfg.interfaces
        .iter()
        .map(|i| i.vni)
        .chain(cfg.irb_routes.iter().map(|r| r.l3_vni))
        .filter(|vni| *vni != 0)
        .collect()
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

/// An interface's name from its index, falling back to `if<N>` so a NIC that has
/// gone away still produces a readable line rather than an error.
fn if_indextoname(ifindex: u32) -> String {
    let mut buf = [0i8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes, which is what the call is documented to
    // write at most; a null return means the index is gone and we fall back.
    let ok = unsafe { !libc::if_indextoname(ifindex, buf.as_mut_ptr()).is_null() };
    if ok {
        // SAFETY: on success the kernel wrote a NUL-terminated name into `buf`.
        let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
        if let Ok(s) = name.to_str() {
            return s.to_string();
        }
    }
    format!("if{ifindex}")
}

/// Program the Phase 3 load-balancer maps: `BACKENDS` (a flat pool) and
/// `SERVICES` (`(VIP, port, proto)` → a window into that pool). No-op without
/// services.
fn program_services(
    ebpf: &mut Ebpf,
    services: &[ResolvedService],
    interfaces: &[ResolvedInterface],
) -> Result<()> {
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
        let count = service.backends.len() as u32;
        entries.push((
            service.key,
            if service.router_nat {
                // The pool's reply policy, explicit config first. Resolved from the
                // pool rather than from one member so a pool spread across zones
                // yields none: one entry cannot name two zones, and naming either
                // would leave the other's replies unadmitted.
                let reply = if service.reply_policy != 0 {
                    service.reply_policy
                } else {
                    pool_reply_policy(&service.backends, interfaces)
                };
                ServiceValue::new_router_nat(start, count, reply)
            } else {
                ServiceValue::new(start, count)
            },
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
fn program_port_forwards(
    ebpf: &mut Ebpf,
    forwards: &[ResolvedPortForward],
    interfaces: &[ResolvedInterface],
) -> Result<()> {
    // Deliberately no early return: deleting the last port forward is the case
    // where leaving the map untouched kept forwarding it inward.
    //
    // Resolve each target's reply policy before borrowing the map (the lookup reads
    // the OS). A config that states one explicitly wins: it can name a zone reached
    // over a route, which no interface subnet contains.
    let prepared: Vec<(ScopedPortKey, PortFwd)> = forwards
        .iter()
        .map(|pf| {
            let reply = if pf.reply_policy != 0 {
                pf.reply_policy
            } else {
                resolve_reply_policy(pf.dst_ip, interfaces)
            };
            (
                ScopedPortKey::new(pf.policy, pf.proto, pf.port),
                PortFwd::new_hairpin(pf.dst_ip, pf.dst_port, pf.match_dst, pf.snat_ip)
                    .with_reply_policy(reply),
            )
        })
        .collect();
    let keep: HashSet<ScopedPortKey> = prepared.iter().map(|(k, _)| *k).collect();
    let mut map: HashMap<_, ScopedPortKey, PortFwd> = HashMap::try_from(
        ebpf.map_mut("PORT_FORWARDS")
            .ok_or_else(|| anyhow!("PORT_FORWARDS map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (key, value) in &prepared {
        map.insert(key, value, 0)
            .context("inserting port-forward")?;
    }
    Ok(())
}

/// Write the C15 `SYNPROXY` map and, the first time a proxy is configured, the
/// key its cookies are minted with.
///
/// **The key is generated here, per boot, from the kernel's random source.** It
/// is the whole basis of the defence: anyone who knows it can mint a cookie for
/// a connection they cannot receive, and so walk straight past the proxy. It is
/// therefore never derived from the config, never logged, and never the same
/// twice — a fixed key in a shipped image would protect nothing at all.
///
/// Rotating it on every reconfigure would be worse than useless: every client
/// mid-handshake would have its ACK rejected. So it is written once, when it is
/// still zero.
fn program_synproxy(ebpf: &mut Ebpf, ports: &[ResolvedSynProxy]) -> Result<()> {
    // The cookie key is drawn only when a port actually uses it; the port map is
    // reconciled either way, so unprotecting the last port takes effect.
    if !ports.is_empty() {
        let mut secret: Array<_, u64> = Array::try_from(
            ebpf.map_mut("SYN_SECRET")
                .ok_or_else(|| anyhow!("SYN_SECRET map missing"))?,
        )?;
        let installed = secret.get(&0, 0).unwrap_or(0) | secret.get(&1, 0).unwrap_or(0);
        if installed == 0 {
            // Straight from the kernel's pool. No crate for this: a sixteen-byte
            // read is the whole requirement, and a dependency that could ever be
            // swapped for something deterministic sits under the one secret the
            // feature cannot afford to have guessed.
            let mut bytes = [0u8; 16];
            std::fs::File::open("/dev/urandom")
                .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
                .context("drawing a SYN-cookie key from /dev/urandom")?;
            secret
                .set(0, u64::from_ne_bytes(bytes[..8].try_into().unwrap()), 0)
                .context("installing the SYN-cookie key")?;
            secret
                .set(1, u64::from_ne_bytes(bytes[8..].try_into().unwrap()), 0)
                .context("installing the SYN-cookie key")?;
        }
    }

    let keep: HashSet<SynProxyKey> = ports.iter().map(|p| SynProxyKey::tcp(p.port)).collect();
    let mut map: HashMap<_, SynProxyKey, SynProxyCfg> = HashMap::try_from(
        ebpf.map_mut("SYNPROXY")
            .ok_or_else(|| anyhow!("SYNPROXY map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for port in ports {
        map.insert(SynProxyKey::tcp(port.port), SynProxyCfg::new(port.mss), 0)
            .context("inserting a synproxy port")?;
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

/// The ifindex a rule is scoped to, or `0` for "every interface".
///
/// An interface that is named and absent resolves to `0` rather than to a
/// nonexistent index — which would make the rule match nothing at all. `0` makes
/// it match everywhere, so the failure is a rule that is too broad rather than
/// one that is silently inert, and the reconfigure that follows a NIC appearing
/// narrows it.
/// Resolve a rule's `in-interface` to the ifindex the data plane keys on.
///
/// An empty name is the *unscoped* rule and resolves to `0`, which the data
/// plane reads as "on any interface". That is the whole difficulty: `0` is a
/// meaning, not an absence. This function used to answer `unwrap_or(0)`, so an
/// operator who mistyped an interface name got the unscoped sentinel — and
/// `allow ssh in on mgmt0` silently became `allow ssh in on every interface,
/// WAN included`, with a green apply and nothing in the log.
///
/// There is no safe value to guess. Widening opens a hole on a `pass` rule;
/// dropping the rule opens one on a `deny`. A name that does not resolve cannot
/// be expressed in the map at all, so the honest answer is to refuse the apply
/// and leave the previous configuration in force — the fail-closed direction for
/// a firewall, and the one the operator will notice.
fn rule_ifindex(name: &str) -> Result<u32> {
    if name.is_empty() {
        return Ok(0);
    }
    if_nametoindex(name).map_err(|e| {
        anyhow!(
            "a firewall rule is scoped to interface `{name}`, which does not exist on this \
             host ({e}); refusing the configuration rather than applying the rule to every \
             interface"
        )
    })
}

/// The same resolution during the stale sweep, where a missing interface is
/// expected rather than an error.
///
/// The sweep runs over the *previous* configuration, and an interface named
/// there may since have been removed — that is a normal reconfigure, not an
/// operator mistake, so it must not fail the apply. Falling back to `0` can
/// remove more than it should, which is harmless in this one position:
/// `remove_stale` runs immediately before `program_policies` rewrites every rule
/// of the new configuration, so an over-broad removal is refilled in the same
/// pass. Under-removal is the failure that matters here, and it is why this is a
/// separate function rather than a flag on the one above.
fn stale_ifindex(name: &str) -> u32 {
    if name.is_empty() {
        return 0;
    }
    if_nametoindex(name).unwrap_or(0)
}

/// Write the `MAC_RULES` map: a policy's verdicts on sender hardware addresses.
///
/// One entry per (policy, MAC). Empty on a box with no MAC groups, so the
/// datapath's single lookup misses immediately and costs nothing.
fn program_mac_rules(ebpf: &mut Ebpf, policies: &[PolicyConfig]) -> Result<()> {
    // No early return on an empty set: lifting the last quarantine must clear
    // the map, not skip it and leave the device blocked.
    let keep: HashSet<ScopedMac> = policies
        .iter()
        .flat_map(|p| {
            p.mac_rules
                .iter()
                .map(move |(mac, _)| ScopedMac::new(p.id, *mac))
        })
        .collect();
    let mut map: HashMap<_, ScopedMac, u32> = HashMap::try_from(
        ebpf.map_mut("MAC_RULES")
            .ok_or_else(|| anyhow!("MAC_RULES map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for policy in policies {
        for (mac, action) in &policy.mac_rules {
            map.insert(
                ScopedMac::new(policy.id, *mac),
                port_rule_value(*action, false, 0),
                0,
            )
            .with_context(|| format!("inserting mac rule for policy {}", policy.id))?;
        }
    }
    Ok(())
}

/// Write the `MSS_CLAMP` map: egress ifindex → the largest MSS a departing SYN
/// may advertise. Only interfaces that configure one get an entry, so a box with
/// no tunnels pays nothing and the datapath's lookup misses immediately.
fn program_mss_clamp(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let prepared: Vec<(u32, u16)> = interfaces
        .iter()
        .filter(|i| i.mss != 0)
        .filter_map(|i| if_nametoindex(&i.name).ok().map(|idx| (idx, i.mss)))
        .collect();
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, u16> = HashMap::try_from(
        ebpf.map_mut("MSS_CLAMP")
            .ok_or_else(|| anyhow!("MSS_CLAMP map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, mss) in prepared {
        map.insert(ifindex, mss, 0)
            .with_context(|| format!("inserting mss clamp for ifindex {ifindex}"))?;
    }
    Ok(())
}

/// Delete every key of `map` that the new configuration does not name.
///
/// The writers below used to only ever `insert`, and `remove_stale` — which
/// reconstructs the old keys from the previous configuration — covered 22 of the
/// 41 maps an apply writes. The port-security maps, the port forwards and the
/// MAC verdicts were among the 19 it did not, so *removing* something from the
/// configuration left it in force in the data plane:
///
/// * take an address off a port and the workload keeps sending under it;
/// * delete a port forward and the box keeps forwarding it inward;
/// * lift a MAC quarantine and the device stays blocked.
///
/// Each of those reported a successful apply. Worse, the writers returned early
/// when their input was empty, so removing the *last* entry of a kind skipped
/// the map altogether — the one case where the operator is most certain the rule
/// is gone.
///
/// Reconciling against the desired set is what fixes it, rather than another
/// hand-written sweep beside the existing one. It needs no memory of the
/// previous configuration, so it is also correct after a crash mid-apply and
/// after an agent restart, and there is one list to keep in step instead of two.
fn drop_unlisted<K, V>(map: &mut HashMap<&mut MapData, K, V>, keep: &HashSet<K>) -> Result<()>
where
    K: aya::Pod + Eq + std::hash::Hash,
    V: aya::Pod,
{
    // Collected before removing: the iterator borrows the map.
    let stale: Vec<K> = map.keys().flatten().filter(|k| !keep.contains(k)).collect();
    for key in stale {
        map.remove(&key).context("removing a stale map entry")?;
    }
    Ok(())
}

/// Write the port-security maps (B12): which identity each tenant port is bound
/// to, and which addresses it may send from.
///
/// Only bound interfaces get entries, so a box with no tenant ports pays one
/// missing lookup per frame and nothing else. An interface that has gone away is
/// skipped with a warning rather than failing the whole apply: the rest of the
/// policy is still worth installing, and a port that does not exist cannot be
/// spoofed from.
fn program_port_bindings(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let bound: Vec<(u32, &PortIdentity)> = interfaces
        .iter()
        .filter_map(|i| {
            let identity = i.binding.as_ref()?;
            match if_nametoindex(&i.name) {
                Ok(idx) => Some((idx, identity)),
                Err(_) => {
                    warn!("port binding skipped: no interface named {}", i.name);
                    None
                }
            }
        })
        .collect();

    // No early return on an empty set. Unbinding the last port is exactly when
    // the map must be emptied, and returning here left every binding in force.
    let keep_ports: HashSet<u32> = bound.iter().map(|(idx, _)| *idx).collect();
    let keep_v4: HashSet<PortAddr4> = bound
        .iter()
        .flat_map(|(idx, id)| {
            id.v4
                .iter()
                .map(move |a| PortAddr4::new(*idx, u32::from_ne_bytes(a.octets())))
        })
        .collect();
    let keep_v6: HashSet<PortAddr6> = bound
        .iter()
        .flat_map(|(idx, id)| id.v6.iter().map(move |a| PortAddr6::new(*idx, a.octets())))
        .collect();

    {
        let mut bindings: HashMap<_, u32, PortBinding> = HashMap::try_from(
            ebpf.map_mut("PORT_BINDINGS")
                .ok_or_else(|| anyhow!("PORT_BINDINGS map missing"))?,
        )?;
        drop_unlisted(&mut bindings, &keep_ports)?;
        for (ifindex, identity) in &bound {
            bindings
                .insert(
                    ifindex,
                    PortBinding::new(identity.mac.unwrap_or([0; 6]), identity.flags()),
                    0,
                )
                .with_context(|| format!("binding port {ifindex}"))?;
        }
        // The handle borrows `ebpf` mutably, and the next one cannot be taken until
        // that borrow ends. A block says so; `drop` of a type with no `Drop` impl
        // only looks like it does.
    }

    {
        let mut v4: HashMap<_, PortAddr4, u8> = HashMap::try_from(
            ebpf.map_mut("PORT_ADDRS_V4")
                .ok_or_else(|| anyhow!("PORT_ADDRS_V4 map missing"))?,
        )?;
        drop_unlisted(&mut v4, &keep_v4)?;
        for (ifindex, identity) in &bound {
            for addr in &identity.v4 {
                // Network order, exactly as it sits in the header the data plane
                // reads: converting on one side only is how a binding silently
                // matches nothing.
                v4.insert(
                    PortAddr4::new(*ifindex, u32::from_ne_bytes(addr.octets())),
                    1,
                    0,
                )
                .with_context(|| format!("binding {addr} to port {ifindex}"))?;
            }
        }
    }

    {
        let mut v6: HashMap<_, PortAddr6, u8> = HashMap::try_from(
            ebpf.map_mut("PORT_ADDRS_V6")
                .ok_or_else(|| anyhow!("PORT_ADDRS_V6 map missing"))?,
        )?;
        drop_unlisted(&mut v6, &keep_v6)?;
        for (ifindex, identity) in &bound {
            for addr in &identity.v6 {
                v6.insert(PortAddr6::new(*ifindex, addr.octets()), 1, 0)
                    .with_context(|| format!("binding {addr} to port {ifindex}"))?;
            }
        }
    }
    Ok(())
}

/// Write the C16 `NPTV6` map: boundary ifindex → its NPTv6 (RFC 6296) prefix
/// translation. The interface name resolves to the live ifindex here (the data
/// plane keys on ifindex); an absent interface is skipped with a warning, so a
/// later reconfigure picks it up once the NIC appears.
/// Write the C16 `CGNAT` map: egress ifindex → its deterministic port-block
/// layout, for every masquerade interface that configures one. No entry means the
/// plain hash-spread NAPT, so a box that is not a carrier NAT is untouched.
fn program_cgnat(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    let prepared: Vec<(u32, CgnatLayout)> = interfaces
        .iter()
        .filter(|i| i.masquerade && i.cgnat.is_enabled())
        .filter_map(|i| match if_nametoindex(&i.name) {
            Ok(ifindex) => Some((ifindex, i.cgnat)),
            Err(_) => {
                warn!(
                    "cgnat interface {} not present yet; deferring its port blocks",
                    i.name
                );
                None
            }
        })
        .collect();
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, CgnatLayout> = HashMap::try_from(
        ebpf.map_mut("CGNAT")
            .ok_or_else(|| anyhow!("CGNAT map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, layout) in prepared {
        map.insert(ifindex, layout, 0)
            .with_context(|| format!("inserting cgnat layout for ifindex {ifindex}"))?;
    }
    Ok(())
}

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
    // No early return: removing the last entry must empty the map, not skip it.
    let keep: HashSet<u32> = prepared.iter().map(|(idx, _)| *idx).collect();
    let mut map: HashMap<_, u32, Npt66> = HashMap::try_from(
        ebpf.map_mut("NPTV6")
            .ok_or_else(|| anyhow!("NPTV6 map missing"))?,
    )?;
    drop_unlisted(&mut map, &keep)?;
    for (ifindex, npt) in prepared {
        map.insert(ifindex, npt, 0)
            .with_context(|| format!("inserting npt66 ifindex {ifindex}"))?;
    }
    Ok(())
}

/// Read an interface's first IPv4 address via `getifaddrs(3)`. Returns an error
/// if the interface has no IPv4 assigned (e.g. DHCP not up yet).
/// The policy a reply from `target` will arrive under: the policy bound to the
/// interface whose live IPv4 subnet contains it. `0` when no interface's subnet
/// does (the host is reached over a route, or its segment has no address yet) — or
/// when two interfaces on *different* policies both match, since one entry cannot
/// name two zones and picking either would admit nothing while looking resolved.
///
/// Read from the live OS rather than derived from the config on purpose: an
/// interface may be DHCP-addressed, in which case its subnet is not in the config
/// at all, and a compile-time guess would also go stale when the address moves.
fn resolve_reply_policy(target: [u8; 4], interfaces: &[ResolvedInterface]) -> PolicyId {
    let want = u32::from_be_bytes(target);
    let mut found: Option<PolicyId> = None;
    for iface in interfaces {
        let Ok((addr, mask)) = read_iface_ipv4_net(&iface.name) else {
            continue;
        };
        let mask = u32::from_be_bytes(mask);
        if (want & mask) != (u32::from_be_bytes(addr) & mask) {
            continue;
        }
        match found {
            None => found = Some(iface.policy),
            Some(p) if p == iface.policy => {}
            Some(_) => return 0,
        }
    }
    found.unwrap_or(0)
}

/// The one policy every member of `backends` answers under, or `0` if they do not
/// all agree (or none resolves). See [`resolve_reply_policy`].
fn pool_reply_policy(backends: &[Backend], interfaces: &[ResolvedInterface]) -> PolicyId {
    let mut agreed: Option<PolicyId> = None;
    for backend in backends {
        let policy = resolve_reply_policy(backend.ip, interfaces);
        if policy == 0 {
            return 0;
        }
        match agreed {
            None => agreed = Some(policy),
            Some(p) if p == policy => {}
            Some(_) => return 0,
        }
    }
    agreed.unwrap_or(0)
}

/// An interface's live IPv4 address **and netmask**, both as network-order octets.
/// The netmask is what makes subnet containment answerable; [`read_iface_ipv4`]
/// keeps returning the address alone for callers that only need that.
fn read_iface_ipv4_net(iface: &str) -> Result<([u8; 4], [u8; 4])> {
    use std::os::raw::c_int;
    let mut ifap: *mut libc::ifaddrs = core::ptr::null_mut();
    // SAFETY: `getifaddrs` fills `ifap` with an owned linked list we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        bail!("getifaddrs failed for {iface}");
    }
    let mut result: Option<([u8; 4], [u8; 4])> = None;
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: `cur` is a valid node for the duration of this iteration.
        let node = unsafe { &*cur };
        if !node.ifa_addr.is_null() && !node.ifa_netmask.is_null() {
            // SAFETY: both point at kernel-owned sockaddrs; we read sa_family
            // first and only reinterpret as sockaddr_in when it is AF_INET.
            let family = unsafe { (*node.ifa_addr).sa_family } as c_int;
            let name = unsafe { std::ffi::CStr::from_ptr(node.ifa_name) };
            if family == libc::AF_INET && name.to_bytes() == iface.as_bytes() {
                let sin = node.ifa_addr as *const libc::sockaddr_in;
                let mask = node.ifa_netmask as *const libc::sockaddr_in;
                // s_addr is network byte order — its native bytes are the octets.
                result = Some((
                    unsafe { (*sin).sin_addr.s_addr }.to_ne_bytes(),
                    unsafe { (*mask).sin_addr.s_addr }.to_ne_bytes(),
                ));
                break;
            }
        }
        cur = node.ifa_next;
    }
    // SAFETY: frees the list `getifaddrs` allocated; `ifap` is not used after.
    unsafe { libc::freeifaddrs(ifap) };
    result.ok_or_else(|| anyhow!("interface {iface} has no IPv4 address"))
}

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
    irb_routes: &[ResolvedIrbRoute],
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

    if tunnels.is_empty()
        && mac_routes.is_empty()
        && irb_routes.is_empty()
        && flood_vteps.is_empty()
    {
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

    // B7: resolve every symmetric-IRB route the same way. The LPM key is
    // `(ingress vni exact, remote tenant prefix)` — the *ingress* segment, not the
    // routed one, because that is all the datapath knows about an arriving frame;
    // the routed VNI travels in the value.
    let prepared_irb: Vec<(Key<TunnelKey>, IrbEndpoint)> = irb_routes
        .iter()
        .filter_map(|r| match if_nametoindex(&r.out_iface) {
            Ok(ifindex) => {
                let (_, addr) = r.inner_dst.lpm_key();
                let key = Key::new(
                    TunnelKey::prefix_len(r.inner_dst.prefix),
                    TunnelKey::new(r.vni, addr),
                );
                Some((
                    key,
                    IrbEndpoint::new(
                        ifindex,
                        r.l3_vni,
                        r.remote_vtep_ip,
                        r.outer_dst_mac,
                        r.router_mac,
                        r.gateway_mac,
                    ),
                ))
            }
            Err(_) => {
                log::debug!(
                    "irb_route egress {} not present yet; deferring its IRB entry",
                    r.out_iface
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
        // B7 IRB_ROUTES: consulted before both bridging FDBs, and only for frames
        // addressed to the tenant's anycast gateway MAC.
        let mut irb: LpmTrie<_, TunnelKey, IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("IRB_ROUTES")
                .ok_or_else(|| anyhow!("IRB_ROUTES map missing"))?,
        )?;
        for (key, endpoint) in &prepared_irb {
            irb.insert(key, endpoint, 0)
                .context("inserting IRB route entry")?;
        }
    }

    if !irb_routes.is_empty() {
        // Symmetric IRB is symmetric: whatever we encapsulate into a tenant's L3
        // VNI, the peer sends back into the same one. So a host that routes into
        // an L3 VNI must also *admit* decap from it — the decap path drops any
        // inner VNI absent from `LOCAL_VNIS`, and an L3 VNI belongs to no local
        // tenant port, so `program_interfaces` never registers it.
        //
        // `remove_stale` clears the whole set first, so a tenant dropped from the
        // config stops being decap-admitted on this live reconfigure instead of
        // lingering until the agent restarts.
        let mut local_vnis: HashMap<_, u32, u32> = HashMap::try_from(
            ebpf.map_mut("LOCAL_VNIS")
                .ok_or_else(|| anyhow!("LOCAL_VNIS map missing"))?,
        )?;
        for r in irb_routes {
            local_vnis
                .insert(r.l3_vni, 0u32, 0)
                .with_context(|| format!("registering local l3 vni {}", r.l3_vni))?;
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
        // B7: an IRB route's remote VTEP is where the routed reply comes back
        // from, so it must be an authorized decap source as well.
        for r in irb_routes {
            peers
                .insert(r.remote_vtep_ip, 1, 0)
                .context("inserting trusted VTEP peer (irb route)")?;
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
    for (_, endpoint) in &prepared_irb {
        tx_ports
            .set(endpoint.out_ifindex, endpoint.out_ifindex, None, 0)
            .context("registering overlay redirect device (irb route)")?;
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
    floods: &[ResolvedSrv6Flood],
    irb_routes: &[ResolvedSrv6IrbRoute],
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

    // C2 decap source-auth: every trusted peer's outer IPv6 source → the
    // `SRV6_PEERS` set the datapath checks before decapsulating an End.DT2U frame
    // to one of our SIDs. remove_stale dropped the old set first; an empty set
    // (no peers configured) leaves decap fail-closed. The SRv6 analogue of the
    // VTEP_PEERS population in program_overlay.
    if let Some(s) = srv6 {
        let mut peers: HashMap<_, [u8; 16], u8> = HashMap::try_from(
            ebpf.map_mut("SRV6_PEERS")
                .ok_or_else(|| anyhow!("SRV6_PEERS map missing"))?,
        )?;
        for src in &s.peers {
            peers
                .insert(src, 1, 0)
                .context("inserting trusted SRv6 peer")?;
        }
    }

    // B9 decap: every service SID this host instantiates → its (vni, behaviour).
    // A packet whose outer IPv6 destination matches is decapsulated and bridged.
    {
        // Reconciled unconditionally: a SID left in this map keeps decapsulating
        // traffic addressed to it after the operator withdrew it.
        let keep: HashSet<Srv6SidKey> = local_sids
            .iter()
            .map(|ls| Srv6SidKey::new(ls.sid))
            .collect();
        let mut sids: HashMap<_, Srv6SidKey, Srv6LocalSid> = HashMap::try_from(
            ebpf.map_mut("SRV6_LOCAL_SIDS")
                .ok_or_else(|| anyhow!("SRV6_LOCAL_SIDS map missing"))?,
        )?;
        drop_unlisted(&mut sids, &keep)?;
        for ls in local_sids {
            sids.insert(
                Srv6SidKey::new(ls.sid),
                Srv6LocalSid::new(ls.vni, ls.behavior),
                0,
            )
            .context("inserting SRv6 local SID")?;
        }
    }

    // No early return on an empty route set: withdrawing the last SRv6 route has
    // to empty the FDB, and returning here left every entry forwarding.
    //
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
        let keep: HashSet<MacFdbKey> = prepared.iter().map(|(k, _)| *k).collect();
        let mut fdb: HashMap<_, MacFdbKey, Srv6Endpoint> = HashMap::try_from(
            ebpf.map_mut("SRV6_FDB")
                .ok_or_else(|| anyhow!("SRV6_FDB map missing"))?,
        )?;
        drop_unlisted(&mut fdb, &keep)?;
        for (key, endpoint) in &prepared {
            fdb.insert(key, endpoint, 0)
                .context("inserting SRv6-FDB entry")?;
        }
    }

    // B9 flood sets: group by VNI into one `Srv6FloodSet` per segment, the SRv6
    // twin of the FLOOD_LIST grouping in `program_overlay`. Deferring an
    // unresolvable egress matches every other table here — a tap that appears
    // later is picked up on the next reconcile rather than aborting this one.
    let mut flood_groups: Vec<(u32, Vec<Srv6Endpoint>)> = Vec::new();
    for f in floods {
        let ifindex = match if_nametoindex(&f.out_iface) {
            Ok(i) => i,
            Err(_) => {
                log::debug!(
                    "srv6_flood egress {} not present yet; deferring its flood entry",
                    f.out_iface
                );
                continue;
            }
        };
        let ep = Srv6Endpoint::new(ifindex, f.remote_sid, f.outer_dst_mac);
        match flood_groups.iter_mut().find(|(v, _)| *v == f.vni) {
            Some((_, eps)) => eps.push(ep),
            None => flood_groups.push((f.vni, vec![ep])),
        }
    }

    {
        // Reconciled, not merely written: a VNI whose flood set the control plane
        // withdrew must stop replicating, and a stale set keeps sending every BUM
        // frame to a peer that no longer serves the tenant.
        let keep: HashSet<u32> = flood_groups.iter().map(|(v, _)| *v).collect();
        let mut flood: HashMap<_, u32, Srv6FloodSet> = HashMap::try_from(
            ebpf.map_mut("SRV6_FLOOD_LIST")
                .ok_or_else(|| anyhow!("SRV6_FLOOD_LIST map missing"))?,
        )?;
        drop_unlisted(&mut flood, &keep)?;
        for (vni, eps) in &flood_groups {
            flood
                .insert(vni, Srv6FloodSet::new(eps), 0)
                .with_context(|| format!("inserting SRv6 flood set for vni {vni}"))?;
        }
    }

    // B9 symmetric-IRB routes, keyed exactly like the VXLAN trie: longest-prefix
    // on `(ingress vni, inner dst)`.
    let prepared_irb: Vec<(Key<TunnelKey>, Srv6IrbEndpoint)> = irb_routes
        .iter()
        .filter_map(|r| {
            let ifindex = match if_nametoindex(&r.out_iface) {
                Ok(i) => i,
                Err(_) => {
                    log::debug!(
                        "srv6_irb_route egress {} not present yet; deferring its route",
                        r.out_iface
                    );
                    return None;
                }
            };
            let (_, addr) = r.inner_dst.lpm_key();
            Some((
                Key::new(
                    TunnelKey::prefix_len(r.inner_dst.prefix),
                    TunnelKey::new(r.vni, addr),
                ),
                Srv6IrbEndpoint::new(
                    ifindex,
                    r.l3_vni,
                    r.remote_sid,
                    r.outer_dst_mac,
                    r.router_mac,
                    r.gateway_mac,
                ),
            ))
        })
        .collect();

    {
        let mut irb: LpmTrie<_, TunnelKey, Srv6IrbEndpoint> = LpmTrie::try_from(
            ebpf.map_mut("SRV6_IRB_ROUTES")
                .ok_or_else(|| anyhow!("SRV6_IRB_ROUTES map missing"))?,
        )?;
        for (key, endpoint) in &prepared_irb {
            irb.insert(key, endpoint, 0)
                .context("inserting SRv6 IRB route entry")?;
        }
    }

    let mut tx_ports: DevMap<_> = DevMap::try_from(
        ebpf.map_mut("TX_PORTS")
            .ok_or_else(|| anyhow!("TX_PORTS map missing"))?,
    )?;
    // Every table that can redirect needs its egress in the devmap, not just the
    // unicast FDB: a flood copy and a routed frame leave through the same helper,
    // and an ifindex missing here turns `redirect` into `XDP_ABORTED`.
    for ifindex in prepared
        .iter()
        .map(|(_, e)| e.out_ifindex)
        .chain(
            flood_groups
                .iter()
                .flat_map(|(_, eps)| eps.iter().map(|e| e.out_ifindex)),
        )
        .chain(prepared_irb.iter().map(|(_, e)| e.out_ifindex))
    {
        tx_ports
            .set(ifindex, ifindex, None, 0)
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

/// The interfaces the TC **egress** hook has to be attached to.
///
/// The XDP ingress hook is attached to every configured interface; this one is
/// attached only where something needs it, because it is a second verdict stage
/// in the path of traffic nobody asked us to filter. Five things need it:
///
/// * `--egress`, the opt-in egress firewall, over the `--iface` set;
/// * an interface that **masquerades** (the SNAT happens here) or **clamps MSS**
///   (the option is rewritten here and nowhere else);
/// * a policy carrying a rule scoped to the way **out** — otherwise the rule
///   loads, matches nothing and says nothing, and the operator who wrote
///   `direction out` gets silence;
/// * a **stateful** policy that does not pass by default. The ingress hook
///   records a flow when it admits one, so a reply to something that *arrived*
///   is covered — but a connection the box itself starts never crosses that hook
///   on the way out, so nothing vouches for its reply and the default action
///   drops it. That is the whole of DNS, NTP, ACME, the update channel, dyndns,
///   alert webhooks and config-sync: on real hardware the box could send and
///   never hear an answer, while `stateful = true` said otherwise;
/// * an NPTv6 boundary interface (C16), where the source prefix is translated.
///
/// Names may repeat across the reasons; the result is deduplicated and keeps the
/// order the reasons are listed in.
fn egress_interfaces(cfg: &RuntimeConfig, ifaces: &[String], egress: bool) -> Vec<String> {
    let mut out: Vec<String> = if egress { ifaces.to_vec() } else { Vec::new() };
    let push = |name: &str, out: &mut Vec<String>| {
        if !out.iter().any(|n| n == name) {
            out.push(name.to_string());
        }
    };
    for i in &cfg.interfaces {
        if i.masquerade || i.mss != 0 {
            push(&i.name, &mut out);
        }
    }
    let out_scoped: Vec<PolicyId> = cfg
        .policies
        .iter()
        .filter(|p| {
            p.port_rules
                .iter()
                .any(|r| r.scope & PORT_RULE_OUT_ONLY != 0)
        })
        .map(|p| p.id)
        .collect();
    let needs_reply_state: Vec<PolicyId> = cfg
        .policies
        .iter()
        .filter(|p| {
            p.global.has_flag(ConfigFlags::STATEFUL)
                && p.global.default_action != Action::Pass as u32
        })
        .map(|p| p.id)
        .collect();
    for i in &cfg.interfaces {
        if out_scoped.contains(&i.policy) || needs_reply_state.contains(&i.policy) {
            push(&i.name, &mut out);
        }
    }
    for r in &cfg.npt66 {
        push(&r.interface, &mut out);
    }
    out
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
    // The load is attempted once per call, and an *already-loaded* program is the
    // normal case from the second call onward: a controller-driven agent picks up
    // new tenant taps on every reconfigure, and the program is already in the
    // kernel by then. Aya reports that as `ProgramError::AlreadyLoaded`, which we
    // swallow — treating it as fatal would mean only the taps present at startup
    // ever got a classifier, the bug this routine exists to fix.
    //
    // Any *other* load error is a genuine failure (a verifier rejection on the
    // first real attempt, most importantly) and is surfaced with its full context
    // instead of being lost to a debug line.
    match program.load() {
        Ok(()) | Err(ProgramError::AlreadyLoaded) => {}
        Err(e) => return Err(e).context("loading TC BUM-replication program into the kernel"),
    }
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
            | Counter::DroppedRateLimit
            | Counter::DroppedSpoofed
            | Counter::SynproxyRejected
            | Counter::ForwardTtlExceeded
            | Counter::EgressDropped
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `LOCAL_VNIS` is a tenant-isolation boundary — a VNI left in it lets any
    /// trusted peer VTEP keep injecting frames into a segment this host no longer
    /// serves — so the reconcile has to name every VNI the old config could have
    /// registered, including the routed ones no interface mentions.
    #[test]
    fn admitted_vnis_covers_ports_and_routed_vnis() {
        let mut cfg = RuntimeConfig::passthrough();
        cfg.interfaces.push(ResolvedInterface {
            name: "tap0".into(),
            policy: 100,
            vni: 100,
            masquerade: false,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
        });
        // An uplink with no tenant segment must not register VNI 0.
        cfg.interfaces.push(ResolvedInterface {
            name: "eth0".into(),
            policy: 0,
            vni: 0,
            masquerade: true,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
        });
        cfg.irb_routes.push(ResolvedIrbRoute {
            vni: 100,
            inner_dst: velstra_common::parse_cidr_v4("10.20.0.0/24").unwrap(),
            l3_vni: 50100,
            remote_vtep_ip: [10, 0, 0, 2],
            outer_dst_mac: [0x02, 0, 0, 0, 0, 0x02],
            out_iface: "eth0".into(),
            router_mac: [0x02, 0, 0x5e, 0, 0, 0x01],
            gateway_mac: [0x02, 0, 0x5e, 0, 0, 0xaa],
        });

        let vnis = admitted_vnis(&cfg);
        assert!(vnis.contains(&100), "the port's segment");
        assert!(vnis.contains(&50100), "the tenant's routed VNI");
        assert!(!vnis.contains(&0), "VNI 0 is not a segment");
        assert_eq!(vnis.len(), 2);
    }

    /// A stateful deny-by-default policy has to bring the egress hook with it.
    ///
    /// The ingress hook records a flow when it admits one, so a reply to
    /// something that arrived is covered. A connection the *box* starts never
    /// crosses that hook on the way out — nothing vouches for its reply, and the
    /// default action drops it. On hardware that was DNS, NTP, ACME, the update
    /// channel, webhooks and config-sync all failing while `stateful = true`
    /// claimed otherwise, and nothing in the configuration hinted at why.
    #[test]
    fn a_stateful_deny_by_default_policy_brings_the_egress_hook() {
        let iface = |name: &str, policy: PolicyId| ResolvedInterface {
            name: name.into(),
            policy,
            vni: 0,
            masquerade: false,
            mss: 0,
            cgnat: CgnatLayout::default(),
            binding: None,
            rate_limit_mbit: None,
        };
        let policy = |id: PolicyId, action: Action, stateful: bool| PolicyConfig {
            mac_rules: Vec::new(),
            id,
            global: GlobalConfig::new(action, if stateful { ConfigFlags::STATEFUL } else { 0 }),
            portal: None,
            blocklist: Vec::new(),
            blocklist6: Vec::new(),
            port_rules: Vec::new(),
        };

        // Deny by default and stateful: the hook comes along.
        let mut cfg = RuntimeConfig::passthrough();
        cfg.policies = vec![policy(1, Action::Drop, true)];
        cfg.interfaces = vec![iface("eth0", 1)];
        assert_eq!(egress_interfaces(&cfg, &[], false), ["eth0"]);

        // Deny by default but NOT stateful: nothing is tracked, so there is
        // nothing for the hook to record.
        cfg.policies = vec![policy(1, Action::Drop, false)];
        assert!(egress_interfaces(&cfg, &[], false).is_empty());

        // Stateful but passing by default: the reply gets through on its own, and
        // a hook that is not needed is a verdict stage nobody asked for.
        cfg.policies = vec![policy(1, Action::Pass, true)];
        assert!(egress_interfaces(&cfg, &[], false).is_empty());

        // The other reasons still hold, and a name is listed once however many
        // reasons name it.
        cfg.policies = vec![policy(1, Action::Drop, true)];
        cfg.interfaces = vec![ResolvedInterface {
            masquerade: true,
            ..iface("eth0", 1)
        }];
        assert_eq!(egress_interfaces(&cfg, &["eth0".into()], true), ["eth0"]);
    }

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

/// Write the B13 `PORT_LIMITS` map: ingress ifindex → the port's send ceiling as
/// a byte bucket.
///
/// A port that had a ceiling and no longer does is **removed**, not zeroed: an
/// entry with `rate == 0` allows everything, so either would work, but leaving
/// dead entries behind makes the map's size a function of how often the config
/// changed rather than of how many ports have ceilings.
///
/// The bucket starts full, so a port is not throttled for the first instant
/// after a config apply — a limiter that made the first frames wait would look
/// exactly like packet loss whenever anything was committed.
fn program_port_limits(ebpf: &mut Ebpf, interfaces: &[ResolvedInterface]) -> Result<()> {
    // The loop below clears the ceiling of an interface still in the
    // configuration whose limit was taken away. It cannot see an interface
    // deleted from the configuration outright, which kept its ceiling — hence
    // the reconcile as well.
    let keep: HashSet<u32> = interfaces
        .iter()
        .filter(|i| i.rate_limit_mbit.is_some())
        .filter_map(|i| if_nametoindex(&i.name).ok())
        .collect();
    let mut limits: HashMap<_, u32, RateBucket> = HashMap::try_from(
        ebpf.map_mut("PORT_LIMITS")
            .ok_or_else(|| anyhow!("PORT_LIMITS map missing"))?,
    )?;
    drop_unlisted(&mut limits, &keep)?;
    for iface in interfaces {
        let Ok(ifindex) = if_nametoindex(&iface.name) else {
            // Not present yet — a tap that has not been created. The next apply
            // picks it up; programming a ceiling for an ifindex that does not
            // exist would be a ceiling on whatever gets that number next.
            continue;
        };
        match iface.rate_limit_mbit {
            Some(mbit) => {
                let bucket = port_rate_bucket(mbit);
                limits
                    .insert(ifindex, bucket, 0)
                    .with_context(|| format!("limiting port {} to {mbit} Mbit/s", iface.name))?;
            }
            None => {
                let _ = limits.remove(&ifindex);
            }
        }
    }
    Ok(())
}

/// The byte bucket a megabit ceiling comes to.
///
/// The burst is **one tenth of a second's worth**, floored at a jumbo frame.
/// Both halves matter: a burst smaller than one frame can never pass one, so a
/// ceiling below about 0.7 Mbit would black-hole the port rather than throttle
/// it; and a burst measured in time rather than bytes means the same
/// configuration behaves the same way at 10 Mbit and at 10 Gbit.
fn port_rate_bucket(mbit: u32) -> RateBucket {
    const JUMBO: u32 = 9_216;
    let bytes_per_sec = mbit.saturating_mul(125_000);
    let burst = (bytes_per_sec / 10).max(JUMBO);
    RateBucket::new(bytes_per_sec, burst)
}

#[cfg(test)]
mod port_limit_tests {
    use super::*;

    #[test]
    fn a_megabit_is_a_hundred_and_twenty_five_thousand_bytes() {
        assert_eq!(port_rate_bucket(1).rate, 125_000);
        assert_eq!(port_rate_bucket(1000).rate, 125_000_000);
    }

    #[test]
    fn even_the_smallest_ceiling_can_pass_a_frame() {
        // A burst below one frame is a blackhole, not a limit: the bucket can
        // never hold enough to spend on anything.
        let mut b = port_rate_bucket(1);
        assert!(
            b.take_n(1_000, 9_216),
            "a 1 Mbit port could not pass a jumbo frame"
        );
    }

    #[test]
    fn the_burst_is_a_tenth_of_a_second_once_that_exceeds_a_frame() {
        assert_eq!(port_rate_bucket(1000).burst, 12_500_000);
    }

    #[test]
    fn a_ceiling_actually_bites() {
        // 10 Mbit = 1_250_000 bytes/s, burst 125_000. Spending the burst and one
        // more frame in the same instant must refuse.
        let mut b = port_rate_bucket(10);
        let mut spent = 0;
        while spent < 125_000 {
            assert!(
                b.take_n(1_000, 1_250),
                "the burst refused a frame it could hold"
            );
            spent += 1_250;
        }
        assert!(!b.take_n(1_000, 1_250), "the ceiling did not bite");
    }
}

#[cfg(test)]
mod interface_scoping {
    //! An `in-interface` that does not resolve must not become "every interface".

    use super::*;

    /// The unscoped rule keeps its meaning: no name, index `0`, matches anywhere.
    #[test]
    fn an_unnamed_interface_is_the_unscoped_rule() {
        assert_eq!(rule_ifindex("").expect("the empty name is not an error"), 0);
    }

    /// The loopback exists on every host this ever runs on, so it is the one
    /// name a unit test may resolve for real — and it must not come back as the
    /// unscoped sentinel.
    #[test]
    fn a_real_interface_resolves_to_its_own_index() {
        let idx = rule_ifindex("lo").expect("lo does not resolve on this host");
        assert_ne!(
            idx, 0,
            "a named interface resolved to the any-interface sentinel"
        );
    }

    /// The defect this module exists for. Before the fix this returned `0`, so a
    /// rule scoped to a mistyped interface was applied to every interface —
    /// including the WAN — and the apply reported success.
    #[test]
    fn a_mistyped_interface_is_refused_rather_than_widened() {
        let error =
            rule_ifindex("nosuchif0").expect_err("an interface that does not exist was accepted");
        let text = error.to_string();
        assert!(
            text.contains("nosuchif0"),
            "the refusal must name the interface, got: {text}"
        );
    }

    /// The sweep is deliberately lenient, and this is the asymmetry that makes
    /// the pair correct: an interface removed since the last apply is a normal
    /// reconfigure, and failing there would block the very apply that cleans up.
    #[test]
    fn the_stale_sweep_tolerates_an_interface_that_is_gone() {
        assert_eq!(stale_ifindex("nosuchif0"), 0);
        assert_eq!(stale_ifindex(""), 0);
    }
}

#[cfg(test)]
mod every_map_is_reconciled {
    //! A map an apply writes must also be a map an apply can empty.
    //!
    //! On 2026-08-18 `apply_config` wrote 41 maps and `remove_stale` cleared 22.
    //! The 19 in between were write-only, so *removing* something from the
    //! configuration left it in force: an address taken off a port, a port
    //! forward deleted, a MAC quarantine lifted. Every one of those reported a
    //! successful apply, and nothing in the log said otherwise.
    //!
    //! Counting them by hand is what let it drift that far, so this test counts
    //! them from the source. It reads this very file, pairs each map handle a
    //! `program_*` function takes with the reconcile or sweep that covers it, and
    //! fails on anything left over that is not listed below with a reason.
    //!
    //! It is a source-text test rather than a runtime one because programming a
    //! map needs a loaded eBPF object, and therefore root. That would put the
    //! check in the VM suite, where it would run in ten minutes rather than ten
    //! milliseconds — and this defect is about a map somebody *adds*, which is
    //! exactly the moment a fast test earns its place. The VM suite proves the
    //! behaviour; this proves the coverage.

    const SOURCE: &str = include_str!("firewall.rs");

    /// Maps that need no reconcile, each with the reason it does not.
    ///
    /// Everything here is an `Array` or a `DevMap`: fixed-size and index-keyed,
    /// so there is no key to go stale — only a slot that may hold an old value.
    /// A slot is safe when it is either always rewritten, or only ever reached
    /// through a map that *is* reconciled.
    const EXEMPT: &[(&str, &str)] = &[
        (
            "FAIL_CLOSED",
            "slot 0 is written on every apply, including the false default",
        ),
        (
            "SYN_SECRET",
            "a cookie key, not a rule; keeping the installed one across an apply is the point",
        ),
        (
            "OVERLAY_CONFIG",
            "slot 0 is written on every apply — OverlayConfig::DISABLED when no overlay is \
             configured, so turning it off takes effect",
        ),
        (
            "SRV6_CONFIG",
            "slot 0 is written on every apply — Srv6Config::DISABLED when no SRv6 is \
             configured, so turning it off takes effect",
        ),
        (
            "RULE_LIMITS",
            "slot-indexed token buckets, reachable only from a rule that names the slot; the \
             rules are reconciled, so an unreferenced slot is never read",
        ),
        (
            "BACKENDS",
            "slot-indexed backends, reachable only from a service entry carrying the count; the \
             services are rewritten, so a slot past the count is never read",
        ),
        (
            "TX_PORTS",
            "a DevMap of redirect targets keyed by ifindex, reachable only from a route the \
             datapath resolved out of a map that is reconciled",
        ),
    ];

    /// Every map name a function takes a handle to, in source order.
    fn handles_in(body: &str) -> Vec<&str> {
        body.match_indices("map_mut(\"")
            .filter_map(|(at, _)| {
                let rest = &body[at + "map_mut(\"".len()..];
                rest.find('"').map(|end| &rest[..end])
            })
            .collect()
    }

    /// The body of every function whose name starts with `prefix`.
    fn bodies(prefix: &str) -> Vec<&'static str> {
        SOURCE
            .match_indices(prefix)
            .filter(|(at, _)| *at == 0 || SOURCE.as_bytes()[at - 1] == b'\n')
            .map(|(at, _)| {
                let rest = &SOURCE[at..];
                // A top-level `}` in the first column closes the function.
                let end = rest.find("\n}\n").map(|e| e + 2).unwrap_or(rest.len());
                &rest[..end]
            })
            .collect()
    }

    #[test]
    fn a_map_an_apply_writes_can_also_be_emptied() {
        let mut written: Vec<&str> = Vec::new();
        let mut covered: Vec<&str> = Vec::new();

        for body in bodies("fn program_") {
            let handles = handles_in(body);
            written.extend(&handles);
            // A handle is reconciled when `drop_unlisted` appears after it and
            // before the next handle is taken — the map is borrowed until then,
            // so no other order is even expressible.
            for (i, name) in handles.iter().enumerate() {
                let from = body.match_indices("map_mut(\"").nth(i).map(|(a, _)| a);
                let to = body
                    .match_indices("map_mut(\"")
                    .nth(i + 1)
                    .map(|(a, _)| a)
                    .unwrap_or(body.len());
                if let Some(from) = from
                    && body[from..to].contains("drop_unlisted")
                {
                    covered.push(name);
                }
            }
        }
        for body in bodies("fn remove_stale") {
            covered.extend(handles_in(body));
        }

        let exempt: Vec<&str> = EXEMPT.iter().map(|(n, _)| *n).collect();
        let mut orphans: Vec<&str> = written
            .iter()
            .filter(|n| !covered.contains(n) && !exempt.contains(n))
            .copied()
            .collect();
        orphans.sort_unstable();
        orphans.dedup();

        assert!(
            orphans.is_empty(),
            "these maps are written by an apply and never emptied by one, so removing the \
             configuration that created their entries leaves those entries in force: {orphans:?}. \
             Reconcile the map with `drop_unlisted`, or add it to EXEMPT with the reason it \
             needs none."
        );
    }

    /// The exempt list is a set of claims, and a claim needs a reason attached.
    #[test]
    fn every_exemption_carries_its_reason() {
        for (name, reason) in EXEMPT {
            assert!(
                reason.len() > 30,
                "{name} is exempt without saying why; the next reader has to re-derive it"
            );
        }
    }
}
