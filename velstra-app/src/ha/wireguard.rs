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
    use std::io::Write;
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
    let mut random = [0; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random)
        .map_err(|_| anyhow::anyhow!("HA randomness unavailable"))?;
    let stage = Path::new(PATH).with_file_name(format!(
        ".wireguard-{}",
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
        file.write_all(&serde_json::to_vec(&cache)?)?;
        std::fs::rename(&stage, PATH)?;
        Ok(())
    })();
    let _ = std::fs::remove_file(stage);
    result
}
