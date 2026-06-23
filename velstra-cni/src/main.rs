//! # velstra-cni
//!
//! A Kubernetes/CNI plugin that wires a pod into a Velstra-managed network: on
//! `ADD` it allocates an IP (host-local IPAM), creates a veth pair into the pod
//! netns, addresses and routes it, and returns a CNI result; on `DEL` it tears
//! that down. The runtime invokes it with the `CNI_*` environment variables and
//! the network config on stdin.
//!
//! This is the data-path plumbing slice. Attaching Velstra's XDP firewall/LB to
//! each pod's host veth is done by the `velstra` agent (run as a DaemonSet)
//! watching for the `vel*` interfaces this plugin creates — see `docs/`.

mod cni;
mod controller;
mod ipam;
mod net;

use std::{
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;

use crate::{
    cni::{CniError, CniResult, Dns, Interface, IpConfig, NetConf, Route, SUPPORTED_VERSIONS},
    ipam::{DEFAULT_STATE_ROOT, Ipam},
};

fn main() {
    // Logs MUST go to stderr — stdout carries the CNI result JSON.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Stderr)
        .init();
    std::process::exit(run());
}

/// CNI entry point. Returns the process exit code (0 on success).
fn run() -> i32 {
    let command = std::env::var("CNI_COMMAND").unwrap_or_default();

    let mut stdin = String::new();
    let _ = std::io::stdin().read_to_string(&mut stdin);

    // VERSION needs no network config.
    if command == "VERSION" {
        println!("{}", version_json());
        return 0;
    }

    let conf: NetConf = match serde_json::from_str(&stdin) {
        Ok(conf) => conf,
        Err(e) => return fail("1.0.0", format!("invalid network config: {e}")),
    };
    let version = conf.cni_version.clone();

    let outcome = match command.as_str() {
        "ADD" => cmd_add(&conf),
        "DEL" => cmd_del(&conf),
        "CHECK" => Ok(None),
        other => Err(anyhow!("unsupported CNI_COMMAND {other:?}")),
    };

    match outcome {
        Ok(Some(result)) => {
            println!("{}", serde_json::to_string(&result).unwrap());
            0
        }
        Ok(None) => 0,
        Err(e) => fail(&version, format!("{e:#}")),
    }
}

/// Print a CNI error object and return a failing exit code.
fn fail(version: &str, msg: String) -> i32 {
    let err = CniError::new(version, msg);
    println!("{}", serde_json::to_string(&err).unwrap());
    1
}

#[derive(Serialize)]
struct VersionInfo {
    #[serde(rename = "cniVersion")]
    cni_version: &'static str,
    #[serde(rename = "supportedVersions")]
    supported_versions: &'static [&'static str],
}

fn version_json() -> String {
    serde_json::to_string(&VersionInfo {
        cni_version: "1.0.0",
        supported_versions: SUPPORTED_VERSIONS,
    })
    .unwrap()
}

/// Read a required `CNI_*` environment variable.
fn env(key: &str) -> Result<String> {
    std::env::var(key).with_context(|| format!("missing {key}"))
}

fn cmd_add(conf: &NetConf) -> Result<Option<CniResult>> {
    let netns = env("CNI_NETNS")?;
    let ifname = env("CNI_IFNAME")?;
    let container_id = env("CNI_CONTAINERID")?;
    let host_veth = net::veth_name(&container_id);

    if !conf.controllers.is_empty() {
        return cmd_add_controller(conf, &netns, &ifname, &container_id, &host_veth);
    }

    // Standalone mode: the plugin's own host-local IPAM.
    let subnet = conf
        .subnet
        .as_deref()
        .ok_or_else(|| anyhow!("network config is missing `subnet`"))?;
    let ipam = Ipam::open(&conf.name, subnet, Path::new(DEFAULT_STATE_ROOT))?;
    let (ip_addr, prefix, gateway) = ipam.allocate(&container_id, conf.gateway.as_deref())?;

    if let Err(e) = net::setup(&netns, &ifname, &host_veth, ip_addr, prefix, gateway, None) {
        // Roll back the IP so a retry can reuse it.
        let _ = ipam.release(&container_id);
        return Err(e.context("setting up pod networking"));
    }

    Ok(Some(cni_result(
        conf, &ifname, &netns, ip_addr, prefix, gateway, "",
    )))
}

/// Controller-integrated ADD: the controller allocates the IP/MAC and, on the
/// next derive, pushes this node's agent an interface binding for `host_veth`.
fn cmd_add_controller(
    conf: &NetConf,
    netns: &str,
    ifname: &str,
    container_id: &str,
    host_veth: &str,
) -> Result<Option<CniResult>> {
    let vni = conf
        .vni
        .ok_or_else(|| anyhow!("controller mode requires `vni`"))?;
    let subnet = conf
        .subnet
        .as_deref()
        .ok_or_else(|| anyhow!("controller mode requires `subnet` for the pod prefix/gateway"))?;
    let (prefix, gateway) = prefix_and_gateway(subnet, conf.gateway.as_deref())?;
    let node = resolve_node_id(conf)?;
    let tls = conf.tls_options();

    let port = controller::create_port(&conf.controllers, &tls, vni, &node, host_veth, None)?;
    let ip_addr: Ipv4Addr = port
        .ip
        .parse()
        .map_err(|_| anyhow!("controller returned an invalid ip {:?}", port.ip))?;

    if let Err(e) = net::setup(
        netns,
        ifname,
        host_veth,
        ip_addr,
        prefix,
        gateway,
        Some(&port.mac),
    ) {
        // Roll back the port so a retry can reuse the address.
        let _ = controller::remove_port(&conf.controllers, &tls, &port.id);
        return Err(e.context("setting up pod networking"));
    }
    // Remember the port id so DEL (which only gets the container id) can find it.
    record_port(Path::new(DEFAULT_STATE_ROOT), container_id, &port.id)?;

    Ok(Some(cni_result(
        conf, ifname, netns, ip_addr, prefix, gateway, &port.mac,
    )))
}

fn cmd_del(conf: &NetConf) -> Result<Option<CniResult>> {
    // DEL must succeed even if the resources are already gone.
    let container_id = env("CNI_CONTAINERID")?;
    let _ = net::teardown(&net::veth_name(&container_id));

    if !conf.controllers.is_empty() {
        if let Some(port_id) = take_port(Path::new(DEFAULT_STATE_ROOT), &container_id) {
            let _ = controller::remove_port(&conf.controllers, &conf.tls_options(), &port_id);
        }
        return Ok(None);
    }

    if let Some(subnet) = conf.subnet.as_deref()
        && let Ok(ipam) = Ipam::open(&conf.name, subnet, Path::new(DEFAULT_STATE_ROOT))
    {
        let _ = ipam.release(&container_id);
    }
    Ok(None)
}

/// Build the CNI ADD result. An empty `mac` is omitted by the serializer.
fn cni_result(
    conf: &NetConf,
    ifname: &str,
    netns: &str,
    ip_addr: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    mac: &str,
) -> CniResult {
    CniResult {
        cni_version: conf.cni_version.clone(),
        interfaces: vec![Interface {
            name: ifname.to_string(),
            mac: mac.to_string(),
            sandbox: netns.to_string(),
        }],
        ips: vec![IpConfig {
            address: format!("{ip_addr}/{prefix}"),
            gateway: Some(gateway.to_string()),
            interface: 0,
        }],
        routes: vec![Route {
            dst: "0.0.0.0/0".into(),
            gw: None,
        }],
        dns: Dns::default(),
    }
}

/// Parse a subnet into the pod's prefix length and default gateway (the first
/// usable address of the subnet, unless `gateway_override` is given).
fn prefix_and_gateway(subnet: &str, gateway_override: Option<&str>) -> Result<(u8, Ipv4Addr)> {
    let cidr = velstra_common::parse_cidr_v4(subnet)
        .map_err(|e| anyhow!("invalid subnet {subnet:?}: {e}"))?;
    let gateway = match gateway_override {
        Some(g) => g.parse().map_err(|_| anyhow!("invalid gateway {g:?}"))?,
        None => Ipv4Addr::from(u32::from_be_bytes(cidr.octets) + 1),
    };
    Ok((cidr.prefix, gateway))
}

/// Resolve this node's host id: `node`, else `node_file` (default
/// `/run/velstra/node`), else the system hostname.
fn resolve_node_id(conf: &NetConf) -> Result<String> {
    if let Some(node) = conf.node.as_deref().filter(|n| !n.is_empty()) {
        return Ok(node.to_string());
    }
    let path = conf.node_file.as_deref().unwrap_or("/run/velstra/node");
    if let Ok(s) = std::fs::read_to_string(path) {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let host = host.trim();
    if !host.is_empty() {
        return Ok(host.to_string());
    }
    bail!("could not determine node id (set `node`, `nodeFile`, or a hostname)")
}

/// Path of the per-container record mapping a container id to its port id.
fn port_record_path(state_root: &Path, container_id: &str) -> PathBuf {
    state_root.join("ports").join(container_id)
}

/// Persist `container_id -> port_id` so DEL can later find the port to remove.
fn record_port(state_root: &Path, container_id: &str, port_id: &str) -> Result<()> {
    let path = port_record_path(state_root, container_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, port_id).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Read and delete the port id recorded for `container_id` (idempotent).
fn take_port(state_root: &Path, container_id: &str) -> Option<String> {
    let path = port_record_path(state_root, container_id);
    let id = std::fs::read_to_string(&path).ok()?.trim().to_string();
    let _ = std::fs::remove_file(&path);
    (!id.is_empty()).then_some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_and_gateway_defaults_to_first_usable() {
        let (prefix, gw) = prefix_and_gateway("192.168.100.0/24", None).unwrap();
        assert_eq!(prefix, 24);
        assert_eq!(gw, "192.168.100.1".parse::<Ipv4Addr>().unwrap());

        // An explicit gateway overrides the default.
        let (_, gw) = prefix_and_gateway("10.0.0.0/8", Some("10.9.9.9")).unwrap();
        assert_eq!(gw, "10.9.9.9".parse::<Ipv4Addr>().unwrap());

        assert!(prefix_and_gateway("not-a-cidr", None).is_err());
    }

    #[test]
    fn port_record_roundtrips_then_is_consumed() {
        let root = std::env::temp_dir().join(format!("velstra-cni-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        record_port(&root, "container-xyz", "port-5000-192.168.100.5").unwrap();
        // First take returns the id; a second take finds nothing (consumed).
        assert_eq!(
            take_port(&root, "container-xyz").as_deref(),
            Some("port-5000-192.168.100.5")
        );
        assert_eq!(take_port(&root, "container-xyz"), None);
        // Unknown container ids are simply absent.
        assert_eq!(take_port(&root, "never-seen"), None);

        let _ = std::fs::remove_dir_all(&root);
    }
}
