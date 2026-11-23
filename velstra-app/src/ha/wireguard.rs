//! Public roaming endpoints, replicated only inside the authenticated HA epoch.
//! WireGuard session secrets stay in-kernel; promotion initiates fresh handshakes.
use std::{
    net::{IpAddr, SocketAddr},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

use super::{Authority, State};

pub const PATH: &str = "/run/velstra/ha/wireguard.json";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub interface: [u8; 16],
    pub public_key: [u8; 32],
    pub ip: [u8; 16],
    pub port: u16,
    pub family: u8,
}
impl Endpoint {
    pub fn validate(&self) -> Result<()> {
        let end = self
            .interface
            .iter()
            .position(|b| *b == 0)
            .context("unterminated WireGuard interface")?;
        ensure!(
            end > 0
                && self.interface[end..].iter().all(|b| *b == 0)
                && self.interface[..end]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.')),
            "invalid WireGuard interface"
        );
        ensure!(
            self.public_key != [0; 32] && self.port > 0 && matches!(self.family, 4 | 6),
            "invalid WireGuard endpoint"
        );
        if self.family == 4 {
            ensure!(self.ip[4..] == [0; 12], "noncanonical IPv4 endpoint");
        }
        let ip = if self.family == 4 {
            IpAddr::from(<[u8; 4]>::try_from(&self.ip[..4])?)
        } else {
            IpAddr::from(self.ip)
        };
        ensure!(
            !ip.is_unspecified() && !ip.is_multicast(),
            "invalid WireGuard endpoint IP"
        );
        Ok(())
    }
    pub fn name(&self) -> &str {
        std::str::from_utf8(
            &self.interface[..self.interface.iter().position(|b| *b == 0).unwrap_or(16)],
        )
        .unwrap_or("")
    }
}
/// The owner's wall clock, as replicated to its standby. Both members present
/// one WireGuard identity, so a remote peer keeps one handshake replay floor
/// for the pair: the newest TAI64N timestamp it has accepted, taken from the
/// initiator's CLOCK_REALTIME. A successor whose wall clock lags its
/// predecessor's (a resumed VM: its clock stopped while paused) sends
/// handshakes the remote peer drops as replays until the lag is passed. Wren
/// compares this against its own clock before it initiates (wren-ha
/// `wireguard::promote`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerClock {
    /// CLOCK_REALTIME in ns when the owner sampled it.
    pub wall_ns: u64,
    /// Whether the owner's clock was disciplined by NTP (kernel maxerror under
    /// 16 s, systemd's own `NTPSynchronized` rule).
    pub synchronised: bool,
}

/// The kernel's ceiling for its admitted clock error, and systemd's threshold
/// for calling a clock synchronised (see Sentinel `clock.rs`).
const MAX_ERROR_US: libc::c_long = 16_000_000;
/// How often the owner refreshes the replicated clock. The standby dates each
/// sample by its own CLOCK_BOOTTIME on receipt, so an unchanged sample stays
/// exact; refreshing only bounds what a long-lived session carries.
pub const CLOCK_REFRESH_NS: u64 = 1_000_000_000;

impl PeerClock {
    /// This member's wall clock now, or `None` when it cannot be read.
    pub fn sample() -> Option<Self> {
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let wall_ns = u64::try_from(wall.as_nanos()).ok().filter(|n| *n > 0)?;
        Some(Self {
            wall_ns,
            synchronised: kernel_synchronised(),
        })
    }
}

/// Whether the kernel admits an error bound under 16 s (NTP disciplines it).
fn kernel_synchronised() -> bool {
    // SAFETY: modes = 0 makes adjtimex read-only; the struct is fully owned.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut timex) };
    state >= 0 && timex.maxerror < MAX_ERROR_US
}

/// Where the agent publishes the predecessor's clock for the clock-step helper.
/// Not under /run/velstra/ha: Wren may write there, and the helper must not
/// act on a reading Wren could forge. Wren's unit cannot see this directory.
pub const CLOCK_DIR: &str = "/run/velstra/ha-clock";
pub const CLOCK_FILE: &str = "peer.json";

/// A replicated [`PeerClock`] with the local CLOCK_BOOTTIME of its receipt, so
/// a reader can project the owner's wall clock to its own present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockObservation {
    pub wall_ns: u64,
    pub synchronised: bool,
    pub observed_ns: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cache {
    pub cluster: String,
    pub node: u8,
    pub policy: String,
    pub authority: Authority,
    pub endpoints: Vec<Endpoint>,
}

pub async fn scan(interfaces: &[String]) -> Result<Vec<Endpoint>> {
    if interfaces.is_empty() {
        return Ok(Vec::new());
    }
    let binary = std::env::var("VELSTRA_WG_BIN").unwrap_or_else(|_| "wg".into());
    let mut command = tokio::process::Command::new(binary);
    command
        .args(["show", "all", "endpoints"])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_millis(80), command.output()).await??;
    ensure!(
        output.status.success() && output.stdout.len() <= 1_048_576,
        "reading public WireGuard endpoints failed"
    );
    let mut result = Vec::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 3, "invalid WireGuard endpoint output");
        if !interfaces.iter().any(|i| i == fields[0]) || fields[2] == "(none)" {
            continue;
        }
        let bytes = fields[0].as_bytes();
        ensure!(bytes.len() < 16, "invalid WireGuard interface length");
        let mut interface = [0; 16];
        interface[..bytes.len()].copy_from_slice(bytes);
        let public_key: [u8; 32] = STANDARD
            .decode(fields[1])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid WireGuard public key"))?;
        let address: SocketAddr = fields[2].parse()?;
        let mut ip = [0; 16];
        let family = match address.ip() {
            IpAddr::V4(v) => {
                ip[..4].copy_from_slice(&v.octets());
                4
            }
            IpAddr::V6(v) => {
                ensure!(
                    match address {
                        SocketAddr::V6(v) => v.scope_id() == 0,
                        _ => true,
                    },
                    "scoped HA WireGuard endpoints unsupported"
                );
                ip = v.octets();
                6
            }
        };
        let endpoint = Endpoint {
            interface,
            public_key,
            ip,
            port: address.port(),
            family,
        };
        endpoint.validate()?;
        result.push(endpoint);
        ensure!(
            result.len() <= 4096,
            "HA WireGuard endpoint capacity exceeded"
        );
    }
    Ok(result)
}

pub fn publish(state: &State, authority: &Authority, endpoints: Vec<Endpoint>) -> Result<()> {
    let config = state.config.as_ref().context("HA config absent")?;
    for e in &endpoints {
        e.validate()?;
        ensure!(
            config.wireguard.iter().any(|n| n == e.name()),
            "unconfigured WireGuard interface"
        );
    }
    let cache = Cache {
        cluster: config.cluster.clone(),
        node: config.node,
        policy: config.wireguard_policy.clone(),
        authority: authority.clone(),
        endpoints,
    };
    replace_private(Path::new(PATH), &serde_json::to_vec(&cache)?)
}

/// Publish the predecessor's clock into `dir` (0700) as [`CLOCK_FILE`], or
/// remove it when there is none.
pub fn publish_clock(dir: &Path, observation: Option<ClockObservation>) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let path = dir.join(CLOCK_FILE);
    let Some(observation) = observation else {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        };
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    replace_private(&path, &serde_json::to_vec(&observation)?)
}

/// Write `bytes` to `path` through a 0600, exclusively created, unfollowed
/// stage file and an atomic rename.
fn replace_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut random = [0; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| anyhow::anyhow!("HA randomness unavailable"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .context("HA state file name")?;
    let stage = path.with_file_name(format!(
        ".{name}-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&stage)?;
        file.write_all(bytes)?;
        std::fs::rename(&stage, path)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(stage);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_clock_sample_is_a_present_wall_time() {
        let clock = PeerClock::sample().expect("the test host has a wall clock");
        // After 2020-01-01: a sample is a real epoch time, never zero.
        assert!(clock.wall_ns > 1_577_836_800_000_000_000);
    }

    #[test]
    fn the_peer_clock_is_published_privately_outside_wrens_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("velstra-ha-clock-{}", std::process::id()));
        let observed = ClockObservation {
            wall_ns: 5,
            synchronised: true,
            observed_ns: 7,
        };
        publish_clock(&dir, Some(observed)).unwrap();
        let file = dir.join(CLOCK_FILE);
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            r#"{"wall_ns":5,"synchronised":true,"observed_ns":7}"#
        );
        assert_eq!(std::fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // No predecessor: no reading at all, never a stale one.
        publish_clock(&dir, None).unwrap();
        assert!(!file.exists());
        publish_clock(&dir, None).unwrap();
        // The WireGuard snapshot Wren reads no longer carries a clock.
        assert!(!Path::new(CLOCK_DIR).starts_with(Path::new(PATH).parent().unwrap()));
        let _ = std::fs::remove_dir_all(dir);
    }
}
