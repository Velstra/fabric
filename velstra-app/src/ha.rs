//! Local half of witness-authorized HA. Only fresh coordinator grants bound to
//! THIS agent incarnation may open the pinned kernel lease. Role files contain
//! no secrets and are accepted only from a trusted root-owned runtime directory.
pub mod wireguard;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::{Read, Write},
    net::IpAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use aya::{
    EbpfLoader,
    maps::{Array, HashMap, MapData},
    programs::{RawTracePoint, SchedClassifier, links::FdLink},
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use velstra_config::{HaConfig, RuntimeConfig};

use crate::firewall::{Firewall, timing};

pub const ROLE_PATH: &str = "/run/velstra/ha/role.json";
pub const AGENT_PATH: &str = "/run/velstra/ha/agent.json";
pub const PIN_DIRECTORY: &str = "/sys/fs/bpf/velstra-ha";
pub const DEADLINE_PIN: &str = "/sys/fs/bpf/velstra-ha/deadline";
pub const OWNER_PIN: &str = "/sys/fs/bpf/velstra-ha/owner";
const EXIT_PIN: &str = "/sys/fs/bpf/velstra-ha/exit";
const GUARD_PIN: &str = "/sys/fs/bpf/velstra-ha/guard";
/// How long a standby's replicated state may stay unusable before it is
/// discarded and the member becomes cold (see [`State::track_usable`]). Well
/// past the 1.5 s replica freshness and an ordinary config-sync delivery, far
/// short of the outage an operator would otherwise have to end by hand.
pub const STALE_STATE_DISCARD_NS: u64 = 5_000_000_000;
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub term: u64,
    pub owner: u8,
    pub boot: [u8; 16],
    pub policy: [u8; 32],
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub cluster: String,
    pub node: u8,
    pub coordinator_boot: [u8; 16],
    pub authority: Authority,
    pub deadline_ns: u64,
    pub updated_ns: u64,
    pub vips_ready: bool,
    pub vpn_ready: bool,
    pub claimed_ready_term: u64,
    pub claimed_agent_boot: [u8; 16],
}
#[derive(Serialize)]
struct Agent {
    cluster: String,
    node: u8,
    coordinator_boot: [u8; 16],
    agent_boot: [u8; 16],
    policy: [u8; 32],
    ready_term: u64,
    forwarding_term: u64,
    eligible: bool,
    updated_ns: u64,
}
pub struct State {
    pub config: Option<HaConfig>,
    pub role: Role,
    pub ready_term: u64,
    ready_policy: [u8; 32],
    ready_at: u64,
    retained_owner: u64,
    // Only a new agent with freshly created maps can vote for an empty epoch.
    // Expired or partially installed state is not empty state.
    cold: bool,
    pub active_term: u64,
    agent_boot: [u8; 16],
    /// Why this member could not take over right now, refreshed every poll.
    /// A standby that is merely "Backup" while the witness would refuse it is
    /// the failure an operator otherwise discovers during the outage.
    not_ready: Option<&'static str>,
    /// When this member's replicated state was last seen unusable without a
    /// break, or 0 while it is usable.
    unusable_since: u64,
    /// The unusable state has outlasted [`STALE_STATE_DISCARD_NS`].
    discard_due: bool,
    /// Cold because stale state was discarded, not because the agent is new.
    discarded: bool,
}
pub type Shared = Arc<Mutex<State>>;
impl State {
    pub fn new(config: Option<HaConfig>) -> Result<Shared> {
        let mut boot = [0; 16];
        SystemRandom::new()
            .fill(&mut boot)
            .map_err(|_| anyhow::anyhow!("HA randomness unavailable"))?;
        Ok(Arc::new(Mutex::new(Self {
            config,
            role: Role::default(),
            ready_term: 0,
            ready_policy: [0; 32],
            ready_at: 0,
            retained_owner: 0,
            cold: true,
            active_term: 0,
            agent_boot: boot,
            not_ready: Some("fresh agent has no state snapshot yet"),
            unusable_since: 0,
            discard_due: false,
            discarded: false,
        })))
    }
    /// Revalidate the captured report after acquiring the state lock. A valid
    /// report can age out while the monitor waits; never refresh its timestamp
    /// or replace it with an unrelated observation from another generation.
    fn accept_role(&mut self, config: &HaConfig, role: Option<Role>, now: u64) -> bool {
        if let Some(role) = role.filter(|role| {
            role.cluster == config.cluster
                && role.node == config.node
                && role_fresh(config, role.updated_ns, now)
        }) {
            self.role = role;
            true
        } else {
            self.role.deadline_ns = 0;
            self.role.vips_ready = false;
            self.role.updated_ns = 0;
            false
        }
    }
    /// Whether this node runs leased HA (an enabled `[ha]`), the only mode in
    /// which it knows whether it is the active member.
    pub fn leased(&self) -> bool {
        self.config.as_ref().is_some_and(|config| config.enabled)
    }
    /// Whether this node may end SYN-proxy splices no live connection claims
    /// (the agent's splice sweep): always without leased HA, and with it only
    /// while this node is the fresh lease owner. A standby's copies of the
    /// owner's state arrive record by record, a splice possibly before the
    /// state that claims it; it never sweeps, and the owner's removals reach
    /// it as conntrack-sync deletions.
    pub fn owns_state(&self, now: u64) -> bool {
        let Some(config) = self.config.as_ref().filter(|config| config.enabled) else {
            return true;
        };
        role_fresh(config, self.role.updated_ns, now)
            && self.active_term > 0
            && self.role.authority.owner == config.node
            && self.role.deadline_ns > now
    }
    /// Local forwarding authority and replica freshness, never inferred from
    /// link presence. The active node cannot measure remote apply latency from
    /// the one-way VCS2 feed; report that measurement as unknown, not zero.
    pub fn telemetry(&self, now: u64) -> serde_json::Value {
        let Some(config) = self.config.as_ref().filter(|config| config.enabled) else {
            return serde_json::json!({"role":"standalone","sync_age_ms":null});
        };
        let fresh_role = role_fresh(config, self.role.updated_ns, now);
        let master = self.owns_state(now);
        serde_json::json!({"role":if master {"Master"} else if fresh_role {"Backup"} else {"Fenced"},
            "node":config.node,"cluster":config.cluster,"term":self.role.authority.term,
            "owner":self.role.authority.owner,"lease_remaining_ms":self.role.deadline_ns.saturating_sub(now)/1_000_000,
            "vips_ready":self.role.vips_ready,"vpn_ready":self.role.vpn_ready,
            "replica_ready":self.ready_term>0,
            "ready":master || self.not_ready.is_none(),
            "not_ready":if master {None} else {self.not_ready},
            "sync_age_ms":if !master && self.ready_at>0 {Some(now.saturating_sub(self.ready_at)/1_000_000)}else{None},
            "sync_age_scope":"local standby: time since the latest complete authenticated state update"})
    }
    /// Records the first reason, in the order an operator can act on, that
    /// the witness would refuse this member authority.
    pub fn observe(
        &mut self,
        config: &HaConfig,
        policy: [u8; 32],
        links_ready: bool,
        role_fresh: bool,
        now: u64,
    ) {
        self.not_ready = if !role_fresh {
            Some("coordinator is not reporting")
        } else if !links_ready {
            Some("data links are not ready")
        } else if self.role.authority.term > 0 && self.role.authority.policy != policy {
            // A commit on the owner changes its fingerprint at once; this
            // member stays ineligible until configuration sync delivers it.
            Some("policy differs from the owner's; awaiting configuration sync")
        } else if self.ready_term == 0 && self.cold && self.discarded {
            Some("stale state discarded; awaiting a state snapshot")
        } else if self.ready_term == 0 && self.cold {
            Some("fresh agent has no state snapshot yet")
        } else if self.ready_term == 0 {
            Some("no complete state snapshot from the owner")
        } else if !self.is_ready(config, policy, now) {
            Some("state snapshot is stale")
        } else {
            None
        };
    }
    fn is_ready(&self, config: &HaConfig, policy: [u8; 32], now: u64) -> bool {
        self.ready_term > 0
            && self.ready_policy == policy
            && (self.retained_owner == self.ready_term
                && self.role.authority.owner == config.node
                && (self.role.authority.term == self.retained_owner
                    || self.role.claimed_ready_term == self.retained_owner
                        && self.role.claimed_agent_boot == self.agent_boot)
                || self.role.authority.owner == config.node
                    && self.role.authority.boot == self.role.coordinator_boot
                    && self.role.authority.policy == policy
                    && self.role.claimed_agent_boot == self.agent_boot
                    && self.role.claimed_ready_term == self.ready_term
                || now.saturating_sub(self.ready_at) <= 1_500_000_000)
    }
    fn forwarding_allowed(
        &self,
        config: &HaConfig,
        policy: [u8; 32],
        links_ready: bool,
        now: u64,
    ) -> bool {
        let ready = self.is_ready(config, policy, now);
        config.enabled
            && role_fresh(config, self.role.updated_ns, now)
            && links_ready
            && self.role.vips_ready
            && self.role.authority.owner == config.node
            && self.role.authority.boot == self.role.coordinator_boot
            && self.role.claimed_agent_boot == self.agent_boot
            && self.role.authority.policy == policy
            && self.role.deadline_ns > now
            && (self.role.authority.term > 0
                && self.role.claimed_ready_term == 0
                && self.ready_term == 0
                && self.cold
                || ready
                    && self.ready_term >= self.role.claimed_ready_term
                    && self.role.authority.term >= self.ready_term)
    }
    pub fn authority_for_send(&self, policy: [u8; 32]) -> Result<Option<Authority>> {
        if self.config.is_none() {
            return Ok(None);
        }
        ensure!(
            self.config.as_ref().is_some_and(|c| c.enabled)
                && self.active_term > 0
                && self.role.vpn_ready
                && self.role.deadline_ns > now_ns()
                && self.role.authority.policy == policy,
            "HA is not the forwarding owner"
        );
        Ok(Some(self.role.authority.clone()))
    }
    pub fn receive_authority(
        &self,
        authority: &Option<Authority>,
        policy: [u8; 32],
        _peer: IpAddr,
    ) -> Result<()> {
        match (&self.config, authority) {
            (None, None) => Ok(()),
            (Some(config), Some(a)) => {
                ensure!(config.enabled, "HA is prepared but disabled");
                ensure!(
                    self.active_term == 0
                        && a.term > 0
                        && a.owner == 3 - config.node
                        && *a == self.role.authority
                        && a.policy == policy
                        && role_fresh(config, self.role.updated_ns, now_ns()),
                    "state sender is not the current witness authority"
                );
                Ok(())
            }
            _ => bail!("incompatible HA authority mode"),
        }
    }
    /// Invalidate old readiness before a fallible multi-map installation. A
    /// partial replacement must never be advertised as a complete warm state.
    pub fn begin_install(&mut self) {
        self.cold = false;
        self.discarded = false;
        self.ready_term = 0;
        self.ready_policy = [0; 32];
        self.ready_at = 0;
        self.retained_owner = 0;
    }
    pub fn snapshot_ready(&mut self, authority: &Authority) {
        self.cold = false;
        self.discarded = false;
        self.ready_term = authority.term;
        self.ready_policy = authority.policy;
        self.ready_at = now_ns();
    }
    /// Record whether this member's replicated state can serve a takeover.
    ///
    /// A standby whose state is stale, or was imported under a policy it no
    /// longer holds, is not eligible, and it cannot become eligible until an
    /// owner exports to it. If the owner's agent died meanwhile, that owner
    /// restarts cold — and a cold member is granted only with a second cold
    /// vote (or a long-silent peer). Neither ever arrives: the pair stays dark
    /// until somebody restarts an agent by hand (HA-04). Once the state has
    /// been unusable for [`STALE_STATE_DISCARD_NS`], [`State::flush_due`]
    /// asks for it to be discarded, which makes this member an honest cold
    /// voter. Nothing usable is lost: the witness would never have granted it.
    pub fn track_usable(&mut self, now: u64, usable: bool) {
        if usable {
            self.unusable_since = 0;
            self.discard_due = false;
            return;
        }
        if self.unusable_since == 0 {
            self.unusable_since = now.max(1);
        }
        if now.saturating_sub(self.unusable_since) >= STALE_STATE_DISCARD_NS {
            self.discard_due = true;
        }
    }
    /// Whether replicated state should be discarded now. Never on a member
    /// that is forwarding, nor on one that is already cold (nothing to
    /// discard, and a fresh agent must keep its "fresh" identity).
    pub fn flush_due(&self) -> bool {
        self.discard_due && !self.cold && self.active_term == 0
    }
    /// The replicated tables were emptied: this member is cold again, exactly
    /// like a freshly started agent, until a complete snapshot arrives.
    pub fn discarded_stale_state(&mut self) {
        self.begin_install();
        self.cold = true;
        self.discarded = true;
        self.unusable_since = 0;
        self.discard_due = false;
    }
    pub fn heartbeat(&mut self, authority: &Authority) {
        if self.ready_term == authority.term && self.ready_policy == authority.policy {
            self.ready_at = now_ns();
        }
    }
}
/// Publish `deadline` into the kernel fence. A failed update attempts to clear
/// it before returning the error. If the map refuses both writes, the old
/// bounded lease can only expire; never report that a clear succeeded.
fn publish_kernel_fence(mut write: impl FnMut(u64) -> Result<()>, deadline: u64) -> Result<()> {
    if let Err(error) = write(deadline) {
        let _ = write(0);
        return Err(error);
    }
    Ok(())
}
pub fn now_ns() -> u64 {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
        return u64::MAX;
    }
    (time.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(time.tv_nsec as u64)
}
fn role_fresh(config: &HaConfig, updated: u64, now: u64) -> bool {
    updated <= now && now - updated <= config.role_fresh_ms.saturating_mul(1_000_000)
}
fn read_role() -> Result<Role> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROLE_PATH)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.len() <= 65536,
        "untrusted HA role"
    );
    let parent = std::fs::symlink_metadata("/run/velstra/ha")?;
    ensure!(
        parent.is_dir() && parent.uid() == 0 && parent.mode() & 0o022 == 0,
        "untrusted HA directory"
    );
    let mut bytes = Vec::new();
    file.take(65537).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "oversized HA role");
    Ok(serde_json::from_slice(&bytes)?)
}
fn write_agent(agent: &Agent) -> Result<()> {
    let directory = Path::new("/run/velstra/ha");
    std::fs::create_dir_all(directory)?;
    let meta = std::fs::symlink_metadata(directory)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "untrusted HA directory"
    );
    let mut token = [0; 16];
    SystemRandom::new()
        .fill(&mut token)
        .map_err(|_| anyhow::anyhow!("HA randomness unavailable"))?;
    let name = token.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let stage = directory.join(format!(".agent-{name}"));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&stage)?;
        file.write_all(&serde_json::to_vec(agent)?)?;
        std::fs::rename(&stage, AGENT_PATH)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(stage);
    result
}
fn tool(name: &str, args: &[&str]) -> Result<()> {
    let binary = std::env::var(format!("VELSTRA_{}_BIN", name.to_uppercase()))
        .or_else(|_| std::env::var(format!("SENTINEL_{}_BIN", name.to_uppercase())))
        .unwrap_or_else(|_| name.into());
    let output = Command::new(binary)
        .args(args)
        .output()
        .with_context(|| format!("HA {name}"))?;
    ensure!(
        output.status.success(),
        "HA {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
/// Durable TC filters are attached using netlink (not process-lifetime TCX
/// links). They run before the ordinary classifier and survive a process crash.
pub fn attach_guard(interface: &str) -> Result<()> {
    // EEXIST is acceptable only for clsact; `replace` on the BPF filter below is
    // deliberate and constrained to our reserved priority/handle.
    let _ = tool("tc", &["qdisc", "add", "dev", interface, "clsact"]);
    for direction in ["ingress", "egress"] {
        tool(
            "tc",
            &[
                "filter", "replace", "dev", interface, direction, "pref", "1", "handle", "1",
                "bpf", "da", "pinned", GUARD_PIN,
            ],
        )?;
    }
    Ok(())
}
/// Remove only our reserved filter and verified kernel program from links
/// removed from declarative HA intent. New data links are fenced first.
fn obsolete_guard_ids(filters: &[serde_json::Value], owned: &BTreeSet<u32>) -> bool {
    filters.iter().any(|filter| {
        // iproute2's bpf_dump_prog_info opens an options.prog object. The
        // textual `id N` is not a flat options.id JSON field. Do not guess an
        // ownership ID from malformed or conflicting compatibility fields.
        let options = &filter["options"];
        let id = options["prog"]["id"]
            .as_u64()
            .and_then(|id| u32::try_from(id).ok())
            .filter(|id| *id != 0);
        let unambiguous = options
            .get("id")
            .is_none_or(|legacy| id.is_some_and(|id| legacy.as_u64() == Some(u64::from(id))));
        filter["kind"] == "bpf"
            && filter["chain"] == 0
            && filter["protocol"] == "all"
            && filter["pref"] == 1
            && (options["handle"] == "0x1" || options["handle"] == 1)
            && unambiguous
            && id.is_some_and(|id| owned.contains(&id))
    })
}
fn guard_inventory_args<'a>(name: &'a str, direction: &'a str) -> [&'a str; 6] {
    // tc omits JSON coordinates that already equal a show-command selector.
    // Inventory the whole hook so ownership checks see explicit pref, protocol
    // and chain instead of trusting a missing field to mean the requested one.
    ["-j", "filter", "show", "dev", name, direction]
}
fn remove_obsolete_guards(desired: &[String]) -> Result<()> {
    let owned: BTreeSet<_> = aya::programs::loaded_programs()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|program| program.name() == b"velstra_ha_guar")
        .map(|program| program.id())
        .collect();
    if owned.is_empty() {
        return Ok(());
    }
    let tc = std::env::var("VELSTRA_TC_BIN")
        .or_else(|_| std::env::var("SENTINEL_TC_BIN"))
        .unwrap_or_else(|_| "tc".into());
    for entry in std::fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if desired.iter().any(|wanted| wanted == name) {
            continue;
        }
        for direction in ["ingress", "egress"] {
            let output = Command::new(&tc)
                .args(guard_inventory_args(name, direction))
                .output()?;
            if !output.status.success() && !entry.path().exists() {
                break;
            }
            ensure!(
                output.status.success(),
                "reading HA filters on {name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            ensure!(
                output.stdout.len() <= 1_048_576,
                "oversized HA filter inventory"
            );
            let filters: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
            if obsolete_guard_ids(&filters, &owned) {
                tool(
                    "tc",
                    &[
                        "filter", "del", "dev", name, direction, "chain", "0", "protocol", "all",
                        "pref", "1", "handle", "1", "bpf",
                    ],
                )?;
            }
        }
    }
    Ok(())
}
pub fn prepare_guard(config: &RuntimeConfig) -> Result<()> {
    if let Some(ha) = &config.ha {
        std::fs::create_dir_all(PIN_DIRECTORY)?;
        let object = crate::btf::kernel_object(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/velstra"
        )))?;
        let mut ebpf = EbpfLoader::new()
            .map_pin_path("HA_DEADLINE", Path::new(DEADLINE_PIN))
            .map_pin_path("HA_OWNER", Path::new(OWNER_PIN))
            .load(&object)?;
        Array::<_, u64>::try_from(ebpf.map_mut("HA_DEADLINE").context("HA deadline map")?)?
            .set(0, 0, 0)?;
        let program: &mut SchedClassifier = ebpf
            .program_mut("velstra_ha_guard")
            .context("HA guard program")?
            .try_into()?;
        program.load()?;
        if Path::new(GUARD_PIN).exists() {
            std::fs::remove_file(GUARD_PIN)?;
        }
        program.pin(GUARD_PIN)?;
        let exit: &mut RawTracePoint = ebpf
            .program_mut("velstra_ha_exit")
            .context("HA exit fence")?
            .try_into()?;
        exit.load()?;
        let id = exit.attach("sched_process_exit")?;
        let link: FdLink = exit.take_link(id)?.into();
        if Path::new(EXIT_PIN).exists() {
            std::fs::remove_file(EXIT_PIN)?;
        }
        link.pin(EXIT_PIN)?;
        for interface in &ha.interfaces {
            if Path::new("/sys/class/net").join(interface).exists() {
                attach_guard(interface)?;
            }
        }
        remove_obsolete_guards(&ha.interfaces)?;
    } else if Path::new(DEADLINE_PIN).exists() {
        remove_obsolete_guards(&[])?;
        // Explicit configuration removal, not merely loading a standalone
        // diagnostic object, disables the retained guard.
        let data = MapData::from_pin(DEADLINE_PIN)?;
        Array::<_, u64>::try_from(aya::maps::Map::Array(data))?.set(0, u64::MAX, 0)?;
        if Path::new(OWNER_PIN).exists() {
            let data = MapData::from_pin(OWNER_PIN)?;
            Array::<_, u32>::try_from(aya::maps::Map::Array(data))?.set(0, 0, 0)?;
        }
        if Path::new(EXIT_PIN).exists() {
            std::fs::remove_file(EXIT_PIN)?;
        }
    }
    Ok(())
}
/// Created after ordinary hooks; dropped before their last userspace owner.
/// Abrupt exit is handled independently by the pinned kernel tracepoint.
pub struct AgentLifetime {
    owner: Array<MapData, u32>,
    pid: u32,
}
impl Drop for AgentLifetime {
    fn drop(&mut self) {
        match self.owner.get(&0, 0) {
            Ok(pid) if pid != self.pid => return,
            Ok(_) => {}
            Err(error) => {
                log::error!(
                    "HA liveness map unavailable during shutdown: {error}; forcing kernel exit fence"
                );
                std::process::abort();
            }
        }
        if let Err(error) = self.owner.set(0, 0, 0) {
            log::error!("HA graceful-exit fence failed: {error}; forcing kernel exit fence");
            std::process::abort();
        }
    }
}

pub fn register_agent(enabled: bool) -> Result<Option<AgentLifetime>> {
    if !enabled {
        return Ok(None);
    }
    ensure!(
        Path::new(EXIT_PIN).exists(),
        "HA exit fence is not attached"
    );
    let mut owner =
        Array::<_, u32>::try_from(aya::maps::Map::Array(MapData::from_pin(OWNER_PIN)?))?;
    let pid = std::process::id();
    owner.set(0, pid, 0)?;
    Ok(Some(AgentLifetime { owner, pid }))
}
/// The WireGuard listen ports the kernel map must gain and lose to match the
/// configuration exactly.
fn wireguard_port_changes(present: &BTreeSet<u16>, wanted: &[u16]) -> (Vec<u16>, Vec<u16>) {
    let add = wanted
        .iter()
        .copied()
        .filter(|port| !present.contains(port))
        .collect();
    // A port that stays in the map after its tunnel is gone keeps being
    // treated as HA WireGuard traffic on a port that may now mean anything.
    let remove = present
        .iter()
        .copied()
        .filter(|port| !wanted.contains(port))
        .collect();
    (add, remove)
}
/// Whether the HA guard itself brings `name` up once the guard is on it.
///
/// Not a link the firewall holds (`held`): that one must carry the firewall's
/// own hooks under a policy in force as well, and the guard is installed long
/// before either — at load, before the first XDP attach, and on a recreated
/// link within one 20 ms poll. Raising it here would let it forward unfiltered
/// until the firewall's next pass, so the firewall raises it instead, once
/// both are in place (`Firewall::activate_held_links`). One owner per link.
fn guard_raises_link(config: &HaConfig, name: &str, held: impl Fn(&str) -> bool) -> bool {
    !config.disabled.iter().any(|n| n == name) && !held(name)
}
/// Called under the firewall configuration lock before admitting a new lease.
/// `held` names the links the firewall raises itself (see `guard_raises_link`).
pub fn reconcile_interfaces(
    ebpf: &mut aya::Ebpf,
    config: &HaConfig,
    seen: &mut BTreeMap<String, u32>,
    held: impl Fn(&str) -> bool,
) -> Result<bool> {
    {
        let mut ports = HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("HA_WG_PORTS")
                .context("HA WireGuard port map")?,
        )?;
        let present = ports
            .keys()
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let (add, remove) = wireguard_port_changes(&present, &config.wireguard_ports);
        for port in add {
            ports.insert(port, 1, 0)?;
        }
        for port in remove {
            ports.remove(&port)?;
        }
    }
    let mut complete = true;
    for name in &config.interfaces {
        let index = std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok());
        let Some(index) = index else {
            if !config.disabled.contains(name) {
                complete = false;
            }
            if let Some(old) = seen.remove(name) {
                HashMap::<_, u32, u8>::try_from(
                    ebpf.map_mut("HA_IFACES").context("HA interface map")?,
                )?
                .remove(&old)?;
            }
            continue;
        };
        if seen.get(name) != Some(&index) {
            if let Some(old) = seen.remove(name) {
                HashMap::<_, u32, u8>::try_from(
                    ebpf.map_mut("HA_IFACES").context("HA interface map")?,
                )?
                .remove(&old)?;
            }
            attach_guard(name)?;
            HashMap::<_, u32, u8>::try_from(
                ebpf.map_mut("HA_IFACES").context("HA interface map")?,
            )?
            .insert(index, 1, 0)?;
            // ActivationPolicy=manual keeps recreated links down until this
            // persistent guard is installed. Standby links can then resolve the
            // shared address only after a valid lease opens the kernel gate.
            if guard_raises_link(config, name, &held) {
                tool("ip", &["link", "set", "dev", name, "up"])?;
            }
            seen.insert(name.clone(), index);
        }
    }
    Ok(complete)
}

/// Node-local sockets on the unfenced control network must retain their own
/// connection state across authoritative data-plane snapshot replacement.
pub fn control_addresses(config: &HaConfig) -> Result<BTreeSet<IpAddr>> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            unsafe {
                libc::freeifaddrs(self.0);
            }
        }
    }
    let mut head = std::ptr::null_mut();
    ensure!(
        unsafe { libc::getifaddrs(&mut head) } == 0,
        "reading control addresses: {}",
        std::io::Error::last_os_error()
    );
    let _addresses = Addresses(head);
    let mut current = head;
    let mut result = BTreeSet::new();
    while let Some(entry) = unsafe { current.as_ref() } {
        current = entry.ifa_next;
        if entry.ifa_name.is_null() || entry.ifa_addr.is_null() {
            continue;
        }
        let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }.to_bytes();
        if config
            .interfaces
            .iter()
            .any(|name_| name_.as_bytes() == name)
        {
            continue;
        }
        let family = unsafe { (*entry.ifa_addr).sa_family } as i32;
        let ip = match family {
            libc::AF_INET => IpAddr::V4(std::net::Ipv4Addr::from(
                unsafe {
                    (*entry.ifa_addr.cast::<libc::sockaddr_in>())
                        .sin_addr
                        .s_addr
                }
                .to_ne_bytes(),
            )),
            libc::AF_INET6 => IpAddr::V6(std::net::Ipv6Addr::from(unsafe {
                (*entry.ifa_addr.cast::<libc::sockaddr_in6>())
                    .sin6_addr
                    .s6_addr
            })),
            _ => continue,
        };
        if !ip.is_unspecified() {
            result.insert(ip);
        }
    }
    Ok(result)
}
/// What this agent tells the coordinator, from the state as it is now.
/// The generation is kept even when stale: reporting zero would falsely
/// authorize the witness to discard warm state as a two-node cold boot.
fn agent_report(
    config: &HaConfig,
    state: &State,
    policy: [u8; 32],
    links_ready: bool,
    ready: bool,
    active: bool,
    now: u64,
) -> Agent {
    Agent {
        cluster: config.cluster.clone(),
        node: config.node,
        coordinator_boot: state.role.coordinator_boot,
        agent_boot: state.agent_boot,
        policy,
        ready_term: state.ready_term,
        forwarding_term: state.active_term,
        eligible: config.enabled && links_ready && (state.cold || ready || active),
        updated_ns: now,
    }
}
pub async fn monitor(firewall: Arc<Mutex<Firewall>>, shared: Shared, config: HaConfig) {
    let mut poll = tokio::time::interval(Duration::from_millis(20));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut heartbeat_timing = timing::Heartbeat::default();
    // The authority term whose takeover has already had its host
    // inventory applied (see below).
    let mut host_applied_term = 0;
    loop {
        let tick_wait_entry = now_ns();
        let scheduled_tick = poll.tick().await;
        let tick_observation = heartbeat_timing.tick(tick_wait_entry, scheduled_tick);
        let wait = timing::Span::start(timing::Phase::HaLockWait);
        let mut fw = firewall.lock().await;
        drop(wait);
        let _hold = timing::Span::start(timing::Phase::HaLockHold);
        let observed_policy = {
            let _timing = timing::Span::start(timing::Phase::HaPolicy);
            fw.sync_policy()
        };
        let policy = match observed_policy {
            Ok(p) => p,
            Err(_) => {
                let _ = fw.ha_deadline(0);
                continue;
            }
        };
        let observed_links = {
            let _timing = timing::Span::start(timing::Phase::HaGuards);
            fw.ha_interfaces(&config)
        };
        let links_ready = match observed_links {
            Ok(value) => value,
            Err(error) => {
                log::warn!("HA guard reconcile failed: {error:#}");
                false
            }
        };
        let role = {
            let _timing = timing::Span::start(timing::Phase::HaReadRole);
            read_role().ok().filter(|r| {
                r.cluster == config.cluster
                    && r.node == config.node
                    && role_fresh(&config, r.updated_ns, now_ns())
            })
        };
        let wait = timing::Span::start(timing::Phase::HaStateLockWait);
        let mut state = shared.lock().await;
        drop(wait);
        let now = now_ns();
        let coordinator_live = state.accept_role(&config, role, now);
        if state.ready_policy != policy {
            if state.retained_owner == state.ready_term && state.ready_term > 0 {
                state.ready_policy = policy;
            } else {
                state.ready_term = 0;
            }
        }
        let ready = state.is_ready(&config, policy, now);
        let active = state.forwarding_allowed(&config, policy, links_ready, now);
        state.observe(&config, policy, links_ready, coordinator_live, now);
        // Only a member that could otherwise take part counts as stuck: a
        // missing coordinator or link is its own, reported, reason.
        let cold = state.cold;
        state.track_usable(
            now,
            ready || active || cold || !coordinator_live || !links_ready,
        );
        // A genuinely cold election has a complete empty baseline. Publish
        // that fact before acknowledging forwarding: Wren may already have
        // renewed the initial claim by the time its VPN task starts. Warm
        // replicas instead retain the endpoint cache installed with their
        // authenticated predecessor snapshot.
        if active
            && state.cold
            && !config.wireguard.is_empty()
            && let Err(error) = wireguard::publish(&state, &state.role.authority, Vec::new())
                .and_then(|()| {
                    wireguard::publish_clock(std::path::Path::new(wireguard::CLOCK_DIR), None)
                })
        {
            let _ = fw.ha_deadline(0);
            state.active_term = 0;
            log::warn!("HA cold VPN baseline publish failed: {error:#}");
            continue;
        }
        // About to open forwarding on a takeover. Wren added the VIPs before
        // it set `vips_ready`, and with `dst-local` rules they change this
        // host's local address set, which the firewall applies with its
        // datapath gate closed. Left to the 2 s inventory poll, that rewrite
        // ran at an arbitrary moment after forwarding had opened and dropped
        // whatever arrived meanwhile: a lost WireGuard handshake then waited
        // 5 s for its retry. Apply the addresses now, while forwarding is
        // still closed; Wren starts WireGuard only once we acknowledge.
        //
        // The rewrite holds this loop, and Wren withdraws the VIPs from an
        // agent whose report is older than `FRESH_NS` (100 ms). So report
        // first, still not forwarding, and decide on the next tick with the
        // role read after the rewrite. Once per term: a takeover whose VIPs
        // came and went is left to the poll.
        if active && state.active_term == 0 && host_applied_term != state.role.authority.term {
            host_applied_term = state.role.authority.term;
            // Stamp it when it is written: Wren judges its age, and the
            // rewrite below holds this loop until the next report.
            let report = agent_report(
                &config,
                &state,
                policy,
                links_ready,
                ready,
                active,
                now_ns(),
            );
            if let Err(error) = write_agent(&report) {
                log::warn!("HA readiness publish failed: {error:#}");
            }
            if let Err(error) = fw.refresh_host_inventory() {
                log::warn!(
                    "HA takeover: applying the host's addresses before forwarding failed: {error:#}"
                );
            }
            continue;
        }
        let deadline = if active { state.role.deadline_ns } else { 0 };
        if active != (state.active_term > 0) {
            log::debug!(
                "HA forwarding transition: active={active} ready={ready} local_term={} retained={} authority={:?} claim={} vips={} agent_match={} policy_match={} lease_ms={} role_age_ms={}",
                state.ready_term,
                state.retained_owner,
                state.role.authority,
                state.role.claimed_ready_term,
                state.role.vips_ready,
                state.role.claimed_agent_boot == state.agent_boot,
                state.role.authority.policy == policy,
                state.role.deadline_ns.saturating_sub(now) / 1_000_000,
                now.saturating_sub(state.role.updated_ns) / 1_000_000
            );
        }
        let fence_ok = match publish_kernel_fence(|value| fw.ha_deadline(value), deadline) {
            Ok(()) => true,
            Err(error) => {
                log::error!(
                    "HA kernel fence update failed; fence reset attempted and forwarding readiness withdrawn: {error:#}"
                );
                false
            }
        };
        if fence_ok && active {
            state.cold = false;
            state.active_term = state.role.authority.term;
            state.ready_term = state.active_term;
            state.ready_policy = policy;
            state.retained_owner = state.active_term;
            state.ready_at = now;
        } else {
            state.active_term = 0;
        }
        let agent = agent_report(&config, &state, policy, links_ready, ready, active, now);
        let published = {
            let _timing = timing::Span::start(timing::Phase::HaPublish);
            write_agent(&agent)
        };
        if let Err(error) = published {
            let _ = fw.ha_deadline(0);
            state.active_term = 0;
            log::warn!("HA readiness publish failed: {error:#}");
        } else {
            heartbeat_timing.published(tick_observation, agent.updated_ns);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_fence_publication_clears_the_previous_lease() {
        let mut writes = Vec::new();
        let error = publish_kernel_fence(
            |deadline| {
                writes.push(deadline);
                if deadline != 0 {
                    anyhow::bail!("HA deadline map update rejected");
                }
                Ok(())
            },
            9_000_000_000,
        );
        assert!(error.is_err());
        assert_eq!(writes, [9_000_000_000, 0]);
    }

    #[test]
    fn fence_clear_is_attempted_when_every_map_write_fails() {
        let mut writes = Vec::new();
        let error = publish_kernel_fence(
            |deadline| {
                writes.push(deadline);
                anyhow::bail!("HA deadline map unavailable");
            },
            0,
        );
        assert!(error.is_err());
        assert_eq!(writes, [0, 0]);
    }

    #[test]
    fn successful_fence_publication_does_not_clear() {
        let mut writes = Vec::new();
        publish_kernel_fence(
            |deadline| {
                writes.push(deadline);
                Ok(())
            },
            4_000_000_000,
        )
        .unwrap();
        assert_eq!(writes, [4_000_000_000]);
    }

    fn config() -> HaConfig {
        HaConfig {
            enabled: true,
            disabled: vec![],
            wireguard_ports: vec![],
            wireguard: vec![],
            wireguard_policy: String::new(),
            cluster: "test-cluster-0123456789".into(),
            node: 1,
            interfaces: vec!["wan".into()],
            control_interfaces: vec![],
            role_fresh_ms: 100,
        }
    }
    #[tokio::test]
    async fn telemetry_distinguishes_authority_freshness_and_unknown_remote_lag() {
        let shared = State::new(Some(config())).unwrap();
        let mut state = shared.lock().await;
        let now = 5_000_000_000;
        assert_eq!(state.telemetry(now)["role"], "Fenced");
        state.role.updated_ns = now;
        state.ready_at = now - 50_000_000;
        state.ready_term = 7;
        assert_eq!(state.telemetry(now)["role"], "Backup");
        assert_eq!(state.telemetry(now)["sync_age_ms"], 50);
        state.role.authority.owner = 1;
        state.active_term = 7;
        state.role.deadline_ns = now + 100_000_000;
        assert_eq!(state.telemetry(now)["role"], "Master");
        assert!(state.telemetry(now)["sync_age_ms"].is_null());
        assert_eq!(state.telemetry(now + 200_000_000)["role"], "Fenced");
        state.config = None;
        assert_eq!(state.telemetry(now)["role"], "standalone");
    }
    #[tokio::test]
    async fn only_a_standalone_node_or_the_fresh_lease_owner_owns_its_state() {
        let shared = State::new(Some(config())).unwrap();
        let mut state = shared.lock().await;
        let now = 5_000_000_000;
        assert!(state.leased());
        assert!(!state.owns_state(now), "fenced");
        state.role.updated_ns = now;
        state.ready_term = 7;
        assert!(!state.owns_state(now), "a standby never sweeps");
        state.role.authority.owner = 1;
        state.active_term = 7;
        state.role.deadline_ns = now + 100_000_000;
        assert!(state.owns_state(now), "the lease owner sweeps");
        // Each condition on its own withdraws ownership.
        state.active_term = 0;
        assert!(!state.owns_state(now), "not yet forwarding");
        state.active_term = 7;
        state.role.authority.owner = 2;
        assert!(!state.owns_state(now), "the peer owns the lease");
        state.role.authority.owner = 1;
        state.role.updated_ns = 0;
        assert!(!state.owns_state(now), "a stale role report");
        state.role.updated_ns = now;
        assert!(
            !state.owns_state(now + 200_000_000),
            "an expired lease is not ownership"
        );
        state.config.as_mut().expect("config").enabled = false;
        assert!(!state.leased(), "a disabled [ha] is not a lease");
        assert!(state.owns_state(now), "nor does it fence the node");
        state.config = None;
        assert!(!state.leased());
        assert!(
            state.owns_state(now),
            "without leased HA the node owns its state"
        );
    }
    #[tokio::test]
    async fn a_standby_reports_why_it_cannot_take_over() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        let now = now_ns();
        state.role = Role {
            cluster: cfg.cluster.clone(),
            node: 1,
            authority: Authority {
                term: 4,
                owner: 2,
                boot: [2; 16],
                policy: [8; 32],
            },
            updated_ns: now,
            ..Role::default()
        };
        let authority = state.role.authority.clone();
        state.snapshot_ready(&authority);
        state.observe(&cfg, [8; 32], true, true, now);
        assert_eq!(state.telemetry(now)["role"], "Backup");
        assert_eq!(state.telemetry(now)["ready"], true);
        assert!(state.telemetry(now)["not_ready"].is_null());
        // The owner committed a policy this standby has not received yet.
        state.observe(&cfg, [9; 32], true, true, now);
        assert_eq!(state.telemetry(now)["ready"], false);
        assert_eq!(
            state.telemetry(now)["not_ready"],
            "policy differs from the owner's; awaiting configuration sync"
        );
        state.observe(&cfg, [8; 32], false, true, now);
        assert_eq!(
            state.telemetry(now)["not_ready"],
            "data links are not ready"
        );
        state.observe(&cfg, [8; 32], true, true, now + 2_000_000_000);
        assert_eq!(state.telemetry(now)["not_ready"], "state snapshot is stale");
        state.begin_install();
        state.observe(&cfg, [8; 32], true, true, now);
        assert_eq!(
            state.telemetry(now)["not_ready"],
            "no complete state snapshot from the owner"
        );
        let fresh_agent = State::new(Some(cfg.clone())).unwrap();
        let mut fresh_agent = fresh_agent.lock().await;
        fresh_agent.role = state.role.clone();
        fresh_agent.observe(&cfg, [8; 32], true, true, now);
        assert_eq!(
            fresh_agent.telemetry(now)["not_ready"],
            "fresh agent has no state snapshot yet"
        );
        state.observe(&cfg, [8; 32], true, false, now);
        assert_eq!(
            state.telemetry(now)["not_ready"],
            "coordinator is not reporting"
        );
    }
    /// HA-04 class: a standby whose replicated state became unusable (stale,
    /// or for a policy it no longer holds) is ineligible, and a restarted owner
    /// is cold. Neither may be granted, so the pair stays dark until somebody
    /// restarts an agent. After a bounded wait the stale standby discards its
    /// replicated state and becomes an honest cold member, which the witness's
    /// two-cold-members rule can open a new epoch with.
    #[tokio::test]
    async fn a_standby_with_unusable_state_becomes_cold_after_the_bound() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        let start = 50_000_000_000;
        state.snapshot_ready(&Authority {
            term: 4,
            owner: 2,
            policy: [3; 32],
            boot: [2; 16],
        });
        assert!(!state.cold);
        // Fresh state, or a member that is forwarding, is never discarded.
        state.track_usable(start, true);
        assert!(!state.flush_due());
        state.track_usable(start + STALE_STATE_DISCARD_NS * 2, true);
        assert!(!state.flush_due());
        // Unusable, but not yet for the whole bound.
        state.track_usable(start, false);
        state.track_usable(start + STALE_STATE_DISCARD_NS - 1, false);
        assert!(!state.flush_due());
        // Usable again in between restarts the wait.
        state.track_usable(start + STALE_STATE_DISCARD_NS - 1, true);
        state.track_usable(start + STALE_STATE_DISCARD_NS, false);
        assert!(!state.flush_due());
        state.track_usable(start + 2 * STALE_STATE_DISCARD_NS, false);
        assert!(state.flush_due());
        // A forwarding member must never discard its tables.
        state.active_term = 4;
        assert!(!state.flush_due());
        state.active_term = 0;
        // A genuinely cold agent has nothing to discard.
        state.cold = true;
        assert!(!state.flush_due());
        state.cold = false;
        state.discarded_stale_state();
        assert!(state.cold && state.ready_term == 0 && !state.flush_due());
        state.observe(&cfg, [3; 32], true, true, start);
        assert_eq!(
            state.not_ready,
            Some("stale state discarded; awaiting a state snapshot")
        );
        // A later complete snapshot makes it an ordinary warm standby again.
        state.begin_install();
        assert!(!state.cold);
    }
    #[test]
    fn role_freshness_follows_the_configured_witness_budget() {
        let mut cfg = config();
        let now = 10_000_000_000;
        assert!(role_fresh(&cfg, now - 100_000_000, now));
        assert!(!role_fresh(&cfg, now - 101_000_000, now));
        cfg.role_fresh_ms = 330;
        assert!(role_fresh(&cfg, now - 300_000_000, now));
        assert!(!role_fresh(&cfg, now - 331_000_000, now));
        assert!(
            !role_fresh(&cfg, now + 1, now),
            "a role from the future is not fresh"
        );
    }
    /// The guard goes on long before the firewall's hooks (at load, before the
    /// first XDP attach; on a recreated link within one poll). A link the
    /// firewall holds must therefore never be raised by the guard: it would
    /// forward unfiltered until the firewall's next pass found it.
    #[test]
    fn the_guard_never_raises_a_link_the_firewall_holds() {
        let mut cfg = config();
        cfg.interfaces = vec!["wan".into(), "lan".into(), "sync".into()];
        cfg.disabled = vec!["sync".into()];
        let held = |name: &str| name == "lan";
        assert!(
            guard_raises_link(&cfg, "wan", held),
            "not held: the guard raises it"
        );
        assert!(
            !guard_raises_link(&cfg, "lan", held),
            "held: only the firewall may raise it, hooks and guard both in place"
        );
        assert!(
            !guard_raises_link(&cfg, "sync", held),
            "disabled stays down"
        );
    }
    #[test]
    fn removed_wireguard_ports_leave_the_kernel_map() {
        let present: BTreeSet<u16> = [51820, 51821].into_iter().collect();
        let (add, remove) = wireguard_port_changes(&present, &[51821, 51822]);
        assert_eq!(add, vec![51822]);
        assert_eq!(
            remove,
            vec![51820],
            "a port no longer configured must stop being treated as HA WireGuard"
        );
        let (add, remove) = wireguard_port_changes(&present, &[]);
        assert!(add.is_empty());
        assert_eq!(remove, vec![51820, 51821]);
    }
    #[test]
    fn guard_inventory_does_not_hide_coordinates_with_tc_show_selectors() {
        assert_eq!(
            guard_inventory_args("dmz0", "ingress"),
            ["-j", "filter", "show", "dev", "dmz0", "ingress"]
        );
        assert_eq!(
            guard_inventory_args("eth2", "egress"),
            ["-j", "filter", "show", "dev", "eth2", "egress"]
        );
    }
    #[test]
    fn guard_scope_cleanup_requires_reserved_coordinates_and_verified_kernel_owner() {
        use serde_json::json;
        let owned = [17].into_iter().collect();
        // Real iproute2 shape: tc/f_bpf.c calls lib/bpf_legacy.c's
        // bpf_dump_prog_info, whose program metadata is nested under `prog`.
        let filter = json!({"protocol":"all","kind":"bpf","pref":1,"chain":0,
            "options":{"handle":"0x1","bpf_name":"guard:[*fsobj]",
                "direct-action":true,"not_in_hw":true,
                "prog":{"id":17,"name":"velstra_ha_guar","tag":"9ddbb820a1a8c749","jited":1}}});
        assert!(obsolete_guard_ids(std::slice::from_ref(&filter), &owned));
        for different in [
            json!({"protocol":"all","chain":0,"kind":"bpf","pref":2,"options":{"handle":"0x1","prog":{"id":17}}}),
            json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,"options":{"handle":"0x2","prog":{"id":17}}}),
            json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,"options":{"handle":"0x1","prog":{"id":18}}}),
            json!({"protocol":"all","chain":0,"kind":"bpf","pref":1}),
            json!({"protocol":"all","chain":0,"kind":"flower","pref":1,"options":{"handle":"0x1","prog":{"id":17}}}),
            // The previous synthetic flat fixture is not a verified kernel
            // identity. Never treat it as a fallback for missing nested data.
            json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,"options":{"handle":"0x1","id":17}}),
        ] {
            assert!(
                !obsolete_guard_ids(&[different], &owned),
                "unrelated filters must survive HA scope changes"
            );
        }
    }
    #[test]
    fn guard_scope_cleanup_never_borrows_owner_from_other_chain_or_protocol() {
        use serde_json::json;
        let owned = [17].into_iter().collect();
        let foreign = json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,
            "options":{"handle":"0x1","prog":{"id":18}}});
        for (field, value) in [
            ("chain", json!(1)),
            ("chain", json!("0")),
            ("chain", json!(null)),
            ("protocol", json!("ip")),
            ("protocol", json!(null)),
        ] {
            let mut other = foreign.clone();
            other["options"]["prog"]["id"] = json!(17);
            other[field] = value;
            assert!(!obsolete_guard_ids(&[foreign.clone(), other], &owned));
        }
        for field in ["chain", "protocol"] {
            let mut missing = foreign.clone();
            missing["options"]["prog"]["id"] = json!(17);
            missing.as_object_mut().unwrap().remove(field);
            assert!(!obsolete_guard_ids(&[foreign.clone(), missing], &owned));
        }
    }
    #[test]
    fn guard_scope_cleanup_rejects_malformed_and_conflicting_program_ids() {
        use serde_json::json;
        let owned = [17].into_iter().collect();
        for id in [
            json!(null),
            json!(-1),
            json!(0),
            json!("17"),
            json!(17.0),
            json!(4_294_967_296u64),
            json!({"id":17}),
        ] {
            let filter = json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,
                "options":{"handle":"0x1","id":17,"prog":{"id":id}}});
            assert!(!obsolete_guard_ids(&[filter], &owned));
        }
        for legacy in [json!(18), json!(null), json!("17"), json!(-1)] {
            let filter = json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,
                "options":{"handle":"0x1","id":legacy,"prog":{"id":17}}});
            assert!(!obsolete_guard_ids(&[filter], &owned));
        }
        let same = json!({"protocol":"all","chain":0,"kind":"bpf","pref":1,
            "options":{"handle":1,"id":17,"prog":{"id":17}}});
        assert!(obsolete_guard_ids(&[same], &owned));
    }
    #[tokio::test]
    async fn captured_role_must_remain_fresh_after_state_lock_wait() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        let published = 1_000_000_000;
        let role = Role {
            cluster: cfg.cluster.clone(),
            node: cfg.node,
            coordinator_boot: [7; 16],
            authority: Authority {
                term: 5,
                owner: cfg.node,
                boot: [7; 16],
                policy: [8; 32],
            },
            claimed_agent_boot: state.agent_boot,
            deadline_ns: published + 1_000_000_000,
            updated_ns: published,
            vips_ready: true,
            ..Role::default()
        };
        let boundary = published + cfg.role_fresh_ms * 1_000_000;
        assert!(role_fresh(&cfg, role.updated_ns, published + 90_000_000));
        assert!(state.accept_role(&cfg, Some(role.clone()), boundary));
        assert_eq!(state.role.updated_ns, published);
        assert!(state.forwarding_allowed(&cfg, [8; 32], true, boundary));
        assert!(state.role.deadline_ns > boundary + 1);
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, boundary + 1));
        assert!(!state.accept_role(&cfg, Some(role.clone()), boundary + 1));
        assert_eq!(state.role.deadline_ns, 0);
        assert!(!state.role.vips_ready);
        assert_eq!(state.role.updated_ns, 0);
        assert_eq!(
            state.role.authority.term, 5,
            "retain generation, not authority"
        );
        state.observe(&cfg, [8; 32], true, false, boundary + 1);
        assert_eq!(state.not_ready, Some("coordinator is not reporting"));

        for candidate in [
            None,
            Some(Role {
                updated_ns: boundary + 1,
                ..role.clone()
            }),
            Some(Role {
                node: 2,
                ..role.clone()
            }),
            Some(Role {
                cluster: "foreign-cluster".into(),
                ..role.clone()
            }),
        ] {
            assert!(state.accept_role(&cfg, Some(role.clone()), boundary));
            assert!(!state.accept_role(&cfg, candidate, boundary));
            assert_eq!(state.role.deadline_ns, 0);
            assert!(!state.forwarding_allowed(&cfg, [8; 32], true, boundary));
        }
    }
    #[tokio::test]
    async fn forwarding_grant_is_bound_to_agent_epoch_policy_and_complete_state() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        let now = now_ns();
        state.role = Role {
            cluster: cfg.cluster.clone(),
            node: 1,
            coordinator_boot: [7; 16],
            authority: Authority {
                term: 5,
                owner: 1,
                boot: [7; 16],
                policy: [8; 32],
            },
            deadline_ns: now + 100_000_000,
            updated_ns: now,
            vips_ready: true,
            vpn_ready: true,
            claimed_ready_term: 0,
            claimed_agent_boot: state.agent_boot,
        };
        assert!(state.forwarding_allowed(&cfg, [8; 32], true, now));
        state.role.claimed_agent_boot = [0; 16];
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, now));
        state.role.claimed_agent_boot = state.agent_boot;
        assert!(!state.forwarding_allowed(&cfg, [9; 32], true, now));
        assert!(!state.forwarding_allowed(&cfg, [8; 32], false, now));
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, now + 100_000_000));
        state.role.claimed_ready_term = 4;
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, now));
        state.ready_term = 4;
        state.ready_policy = [8; 32];
        state.ready_at = now;
        assert!(state.forwarding_allowed(&cfg, [8; 32], true, now));
        state.begin_install();
        state.role.claimed_ready_term = 0;
        assert!(
            !state.forwarding_allowed(&cfg, [8; 32], true, now),
            "a partial snapshot cannot accept a cold grant"
        );
        state.role.claimed_ready_term = 4;
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, now));
        assert_eq!(state.ready_term, 0);
        state.snapshot_ready(&Authority {
            term: 4,
            owner: 2,
            policy: [8; 32],
            boot: [2; 16],
        });
        assert!(state.forwarding_allowed(&cfg, [8; 32], true, now));
        state.ready_at = now.saturating_sub(2_000_000_000);
        assert!(
            state.forwarding_allowed(&cfg, [8; 32], true, now),
            "the exact committed baseline remains owned"
        );
        state.role.claimed_ready_term = 3;
        assert!(!state.forwarding_allowed(&cfg, [8; 32], true, now));
    }
    #[tokio::test]
    async fn retained_owner_can_accept_its_explicit_successor_grant_after_long_witness_outage() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        let now = now_ns() + 3_000_000_000;
        state.ready_term = 4;
        state.retained_owner = 4;
        state.ready_policy = [3; 32];
        state.role = Role {
            authority: Authority {
                term: 5,
                owner: 1,
                boot: [7; 16],
                policy: [3; 32],
            },
            coordinator_boot: [7; 16],
            claimed_ready_term: 4,
            claimed_agent_boot: state.agent_boot,
            vips_ready: true,
            deadline_ns: now + 100_000_000,
            updated_ns: now,
            ..Role::default()
        };
        assert!(
            state.forwarding_allowed(&cfg, [3; 32], true, now),
            "a witness grant based on this exact retained baseline must reopen the owner"
        );
        state.role.claimed_ready_term = 3;
        assert!(
            !state.forwarding_allowed(&cfg, [3; 32], true, now),
            "a different baseline is not authorized"
        );
        state.role.claimed_ready_term = 4;
        state.role.claimed_agent_boot = [0; 16];
        assert!(
            !state.forwarding_allowed(&cfg, [3; 32], true, now),
            "retained state cannot cross agent incarnations"
        );
        state.role.claimed_agent_boot = state.agent_boot;
        state.role.authority.owner = 2;
        assert!(
            !state.is_ready(&cfg, [3; 32], now),
            "a known successor invalidates indefinite local retention"
        );
    }
    #[tokio::test]
    async fn committed_warm_claim_recovers_standby_after_lost_ack_without_reclassifying_cold() {
        let cfg = config();
        let shared = State::new(Some(cfg.clone())).unwrap();
        let mut state = shared.lock().await;
        state.snapshot_ready(&Authority {
            term: 4,
            owner: 2,
            policy: [3; 32],
            boot: [2; 16],
        });
        let later = now_ns() + 3_000_000_000;
        assert!(!state.is_ready(&cfg, [3; 32], later));
        state.role = Role {
            authority: Authority {
                term: 5,
                owner: 1,
                boot: [7; 16],
                policy: [3; 32],
            },
            coordinator_boot: [7; 16],
            claimed_ready_term: 4,
            claimed_agent_boot: state.agent_boot,
            vips_ready: true,
            deadline_ns: later + 100_000_000,
            updated_ns: later,
            ..Role::default()
        };
        assert!(state.is_ready(&cfg, [3; 32], later));
        assert!(state.forwarding_allowed(&cfg, [3; 32], true, later));
        state.role.claimed_agent_boot = [0; 16];
        assert!(!state.is_ready(&cfg, [3; 32], later));
        state.role.claimed_agent_boot = state.agent_boot;
        state.begin_install();
        assert!(!state.is_ready(&cfg, [3; 32], later));
    }
    #[tokio::test]
    async fn expired_snapshot_is_never_a_cold_vote() {
        let shared = State::new(Some(config())).unwrap();
        let mut state = shared.lock().await;
        assert!(state.cold);
        state.snapshot_ready(&Authority {
            term: 7,
            owner: 2,
            policy: [3; 32],
            boot: [2; 16],
        });
        let later = now_ns() + 2_000_000_000;
        assert!(!state.is_ready(&config(), [3; 32], later));
        assert!(!state.cold);
        assert_eq!(
            state.ready_term, 7,
            "retain evidence that the maps are not empty"
        );
        state.begin_install();
        assert!(
            !state.cold,
            "failed installation must await a full snapshot"
        );
        assert_eq!(state.ready_term, 0);
    }
    #[tokio::test]
    async fn receiver_rejects_stale_authority_and_active_node_imports() {
        let shared = State::new(Some(config())).unwrap();
        let mut state = shared.lock().await;
        let authority = Authority {
            term: 4,
            owner: 2,
            boot: [2; 16],
            policy: [3; 32],
        };
        state.role.authority = authority.clone();
        state.role.updated_ns = now_ns();
        let peer = "10.0.0.2".parse().unwrap();
        state
            .receive_authority(&Some(authority.clone()), [3; 32], peer)
            .unwrap();
        let mut stale = authority.clone();
        stale.term -= 1;
        assert!(
            state
                .receive_authority(&Some(stale), [3; 32], peer)
                .is_err()
        );
        assert!(state.receive_authority(&None, [3; 32], peer).is_err());
        state.active_term = 4;
        assert!(
            state
                .receive_authority(&Some(authority), [3; 32], peer)
                .is_err()
        );
    }
}
