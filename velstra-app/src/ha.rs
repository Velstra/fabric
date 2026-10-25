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

use crate::firewall::Firewall;

pub const ROLE_PATH: &str = "/run/velstra/ha/role.json";
pub const AGENT_PATH: &str = "/run/velstra/ha/agent.json";
pub const PIN_DIRECTORY: &str = "/sys/fs/bpf/velstra-ha";
pub const DEADLINE_PIN: &str = "/sys/fs/bpf/velstra-ha/deadline";
pub const OWNER_PIN: &str = "/sys/fs/bpf/velstra-ha/owner";
const EXIT_PIN: &str = "/sys/fs/bpf/velstra-ha/exit";
const GUARD_PIN: &str = "/sys/fs/bpf/velstra-ha/guard";
const FRESH_NS: u64 = 100_000_000;
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
        })))
    }
    fn is_ready(&self, config: &HaConfig, policy: [u8; 32], now: u64) -> bool {
        self.ready_term > 0
            && self.ready_policy == policy
            && (self.retained_owner == self.ready_term
                && self.role.authority.owner == config.node
                && (self.role.authority.term == self.retained_owner
                    || self.role.claimed_ready_term == self.retained_owner
                        && self.role.claimed_agent_boot == self.agent_boot)
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
                        && fresh(self.role.updated_ns, now_ns()),
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
        self.ready_term = 0;
        self.ready_policy = [0; 32];
        self.ready_at = 0;
        self.retained_owner = 0;
    }
    pub fn snapshot_ready(&mut self, authority: &Authority) {
        self.cold = false;
        self.ready_term = authority.term;
        self.ready_policy = authority.policy;
        self.ready_at = now_ns();
    }
    pub fn heartbeat(&mut self, authority: &Authority) {
        if self.ready_term == authority.term && self.ready_policy == authority.policy {
            self.ready_at = now_ns();
        }
    }
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
fn fresh(updated: u64, now: u64) -> bool {
    updated <= now && now - updated <= FRESH_NS
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
        filter["kind"] == "bpf"
            && filter["pref"] == 1
            && (filter["options"]["handle"] == "0x1" || filter["options"]["handle"] == 1)
            && filter["options"]["id"]
                .as_u64()
                .and_then(|id| u32::try_from(id).ok())
                .is_some_and(|id| owned.contains(&id))
    })
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
                .args(["-j", "filter", "show", "dev", name, direction, "pref", "1"])
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
                        "filter", "del", "dev", name, direction, "pref", "1", "handle", "1", "bpf",
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
/// Called under the firewall configuration lock before admitting a new lease.
pub fn reconcile_interfaces(
    ebpf: &mut aya::Ebpf,
    config: &HaConfig,
    seen: &mut BTreeMap<String, u32>,
) -> Result<bool> {
    {
        let mut ports = HashMap::<_, u16, u8>::try_from(
            ebpf.map_mut("HA_WG_PORTS")
                .context("HA WireGuard port map")?,
        )?;
        for port in &config.wireguard_ports {
            ports.insert(*port, 1, 0)?;
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
            if !config.disabled.contains(name) {
                tool("ip", &["link", "set", "dev", name, "up"])?;
            }
            seen.insert(name.clone(), index);
        }
    }
    Ok(complete)
}

pub async fn monitor(firewall: Arc<Mutex<Firewall>>, shared: Shared, config: HaConfig) {
    let mut links = BTreeMap::new();
    let mut poll = tokio::time::interval(Duration::from_millis(20));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        poll.tick().await;
        let mut fw = firewall.lock().await;
        let policy = match fw.sync_policy() {
            Ok(p) => p,
            Err(_) => {
                let _ = fw.ha_deadline(0);
                continue;
            }
        };
        let links_ready = match fw.ha_interfaces(&config, &mut links) {
            Ok(value) => value,
            Err(error) => {
                log::warn!("HA guard reconcile failed: {error:#}");
                false
            }
        };
        let role = read_role().ok().filter(|r| {
            r.cluster == config.cluster && r.node == config.node && fresh(r.updated_ns, now_ns())
        });
        let mut state = shared.lock().await;
        if let Some(role) = role {
            state.role = role;
        } else {
            state.role.deadline_ns = 0;
            state.role.vips_ready = false;
            state.role.updated_ns = 0;
        }
        let now = now_ns();
        if state.ready_policy != policy {
            if state.retained_owner == state.ready_term && state.ready_term > 0 {
                state.ready_policy = policy;
            } else {
                state.ready_term = 0;
            }
        }
        let ready = state.is_ready(&config, policy, now);
        let active = state.forwarding_allowed(&config, policy, links_ready, now);
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
        if let Err(error) = fw.ha_deadline(deadline) {
            log::error!("HA kernel fence update failed: {error:#}");
            continue;
        }
        if active {
            state.cold = false;
            state.active_term = state.role.authority.term;
            state.ready_term = state.active_term;
            state.ready_policy = policy;
            state.retained_owner = state.active_term;
            state.ready_at = now;
        } else {
            state.active_term = 0;
        }
        // Keep the generation even when stale: reporting zero would falsely
        // authorize the witness to discard warm state as a two-node cold boot.
        let ready_term = state.ready_term;
        let agent = Agent {
            cluster: config.cluster.clone(),
            node: config.node,
            coordinator_boot: state.role.coordinator_boot,
            agent_boot: state.agent_boot,
            policy,
            ready_term,
            forwarding_term: state.active_term,
            eligible: config.enabled && links_ready && (state.cold || ready || active),
            updated_ns: now,
        };
        if let Err(error) = write_agent(&agent) {
            let _ = fw.ha_deadline(0);
            state.active_term = 0;
            log::warn!("HA readiness publish failed: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        }
    }
    #[test]
    fn guard_scope_cleanup_requires_reserved_coordinates_and_verified_kernel_owner() {
        use serde_json::json;
        let owned = [17].into_iter().collect();
        let filter = json!({"kind":"bpf","pref":1,"options":{"handle":"0x1","id":17}});
        assert!(obsolete_guard_ids(std::slice::from_ref(&filter), &owned));
        for different in [
            json!({"kind":"bpf","pref":2,"options":{"handle":"0x1","id":17}}),
            json!({"kind":"bpf","pref":1,"options":{"handle":"0x2","id":17}}),
            json!({"kind":"bpf","pref":1,"options":{"handle":"0x1","id":18}}),
            json!({"kind":"bpf","pref":1}),
            json!({"kind":"flower","pref":1,"options":{"handle":"0x1","id":17}}),
        ] {
            assert!(
                !obsolete_guard_ids(&[different], &owned),
                "unrelated filters must survive HA scope changes"
            );
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
