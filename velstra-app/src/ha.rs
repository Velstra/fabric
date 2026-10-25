//! Local half of witness-authorized HA. Only fresh coordinator grants bound to
//! THIS agent incarnation may open the pinned kernel lease. Role files contain
//! no secrets and are accepted only from a trusted root-owned runtime directory.
pub mod wireguard;
use std::{
    collections::BTreeMap,
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
    programs::SchedClassifier,
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
            active_term: 0,
            agent_boot: boot,
        })))
    }
    fn is_ready(&self, config: &HaConfig, policy: [u8; 32], now: u64) -> bool {
        self.ready_policy == policy
            && (self.retained_owner == self.ready_term
                && self.role.authority.owner == config.node
                && self.role.authority.term == self.retained_owner
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
        self.ready_term = 0;
        self.ready_policy = [0; 32];
        self.ready_at = 0;
        self.retained_owner = 0;
    }
    pub fn snapshot_ready(&mut self, authority: &Authority) {
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
pub fn prepare_guard(config: &RuntimeConfig) -> Result<()> {
    if let Some(ha) = &config.ha {
        std::fs::create_dir_all(PIN_DIRECTORY)?;
        let object = crate::btf::kernel_object(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/velstra"
        )))?;
        let mut ebpf = EbpfLoader::new()
            .map_pin_path("HA_DEADLINE", Path::new(DEADLINE_PIN))
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
        for interface in &ha.interfaces {
            if Path::new("/sys/class/net").join(interface).exists() {
                attach_guard(interface)?;
            }
        }
    } else if Path::new(DEADLINE_PIN).exists() {
        // Explicit configuration removal, not merely loading a standalone
        // diagnostic object, disables the retained guard.
        let data = MapData::from_pin(DEADLINE_PIN)?;
        Array::<_, u64>::try_from(aya::maps::Map::Array(data))?.set(0, u64::MAX, 0)?;
    }
    Ok(())
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
            seen.remove(name);
            continue;
        };
        if seen.get(name) != Some(&index) {
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
        if let Err(error) = fw.ha_deadline(deadline) {
            log::error!("HA kernel fence update failed: {error:#}");
            continue;
        }
        if active {
            state.active_term = state.role.authority.term;
            state.ready_term = state.active_term;
            state.ready_policy = policy;
            state.retained_owner = state.active_term;
            state.ready_at = now;
        } else {
            state.active_term = 0;
        }
        let ready_term = if ready || active { state.ready_term } else { 0 };
        let agent = Agent {
            cluster: config.cluster.clone(),
            node: config.node,
            coordinator_boot: state.role.coordinator_boot,
            agent_boot: state.agent_boot,
            policy,
            ready_term,
            forwarding_term: state.active_term,
            eligible: config.enabled && links_ready,
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
