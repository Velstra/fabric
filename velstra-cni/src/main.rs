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
//! watching for the `hyp*` interfaces this plugin creates — see `docs/`.

mod cni;
mod ipam;
mod net;

use std::{io::Read, path::Path};

use anyhow::{Context, Result, anyhow};
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
    let subnet = conf
        .subnet
        .as_deref()
        .ok_or_else(|| anyhow!("network config is missing `subnet`"))?;

    let ipam = Ipam::open(&conf.name, subnet, Path::new(DEFAULT_STATE_ROOT))?;
    let (ip_addr, prefix, gateway) = ipam.allocate(&container_id, conf.gateway.as_deref())?;

    let host_veth = net::veth_name(&container_id);
    if let Err(e) = net::setup(&netns, &ifname, &host_veth, ip_addr, prefix, gateway) {
        // Roll back the IP so a retry can reuse it.
        let _ = ipam.release(&container_id);
        return Err(e.context("setting up pod networking"));
    }

    Ok(Some(CniResult {
        cni_version: conf.cni_version.clone(),
        interfaces: vec![Interface {
            name: ifname,
            mac: String::new(),
            sandbox: netns,
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
    }))
}

fn cmd_del(conf: &NetConf) -> Result<Option<CniResult>> {
    // DEL must succeed even if the resources are already gone.
    let container_id = env("CNI_CONTAINERID")?;
    let _ = net::teardown(&net::veth_name(&container_id));
    if let Some(subnet) = conf.subnet.as_deref()
        && let Ok(ipam) = Ipam::open(&conf.name, subnet, Path::new(DEFAULT_STATE_ROOT))
    {
        let _ = ipam.release(&container_id);
    }
    Ok(None)
}
