//! Pod network plumbing: create a veth pair, move one end into the container's
//! network namespace, address it, and route. Implemented by driving `ip(8)`,
//! which keeps the plugin dependency-free and easy to follow.

use std::{net::Ipv4Addr, path::Path, process::Command};

use anyhow::{Context, Result, bail};

/// Deterministic, ≤15-char host-side veth name derived from the container id, so
/// DEL (which only gets the id) can find and delete the same interface.
pub fn veth_name(container_id: &str) -> String {
    // FNV-1a, truncated to 32 bits.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in container_id.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("hyp{:08x}", hash as u32) // "hyp" + 8 hex = 11 chars
}

/// Run an `ip` command, surfacing stderr on failure.
fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("spawning `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// `ip(8)` resolves a netns by *name* under `/var/run/netns`; CNI hands us a
/// path, so we symlink it in under a temporary name for the duration of the op.
struct NetnsLink(String);

impl NetnsLink {
    fn create(netns_path: &str) -> Result<Self> {
        let dir = Path::new("/var/run/netns");
        std::fs::create_dir_all(dir).context("creating /var/run/netns")?;
        let name = format!("hypcni{}", std::process::id());
        let link = dir.join(&name);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(netns_path, &link)
            .with_context(|| format!("linking netns {netns_path}"))?;
        Ok(Self(name))
    }

    fn name(&self) -> &str {
        &self.0
    }
}

impl Drop for NetnsLink {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(Path::new("/var/run/netns").join(&self.0));
    }
}

/// Wire up the pod: a veth pair with `host_veth` on the host and `ifname` inside
/// `netns`, addressed `ip/prefix` with a default route via `gateway`, plus a
/// host route to the pod over the host veth.
pub fn setup(
    netns: &str,
    ifname: &str,
    host_veth: &str,
    ip_addr: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
) -> Result<()> {
    let link = NetnsLink::create(netns)?;
    let ns = link.name();
    let peer = format!("{host_veth}p"); // temporary; renamed to ifname inside the ns

    // Remove any leftover from a previous, half-finished ADD with the same id.
    let _ = ip(&["link", "del", host_veth]);

    ip(&[
        "link", "add", host_veth, "type", "veth", "peer", "name", &peer,
    ])?;
    ip(&["link", "set", &peer, "netns", ns])?;
    ip(&["-n", ns, "link", "set", &peer, "name", ifname])?;
    ip(&["-n", ns, "link", "set", "lo", "up"])?;
    ip(&["-n", ns, "link", "set", ifname, "up"])?;
    ip(&[
        "-n",
        ns,
        "addr",
        "add",
        &format!("{ip_addr}/{prefix}"),
        "dev",
        ifname,
    ])?;
    ip(&[
        "-n",
        ns,
        "route",
        "replace",
        "default",
        "via",
        &gateway.to_string(),
    ])?;
    ip(&["link", "set", host_veth, "up"])?;
    ip(&[
        "route",
        "replace",
        &format!("{ip_addr}/32"),
        "dev",
        host_veth,
    ])?;
    Ok(())
}

/// Tear down a pod's host-side veth (its peer disappears with the netns).
/// Idempotent: a missing interface is not an error.
pub fn teardown(host_veth: &str) -> Result<()> {
    let _ = ip(&["link", "del", host_veth]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veth_name_is_deterministic_and_short() {
        let a = veth_name("abc123");
        assert_eq!(a, veth_name("abc123"));
        assert_ne!(a, veth_name("abc124"));
        assert!(a.len() <= 15, "ifname too long: {a}");
        assert!(a.starts_with("hyp"));
    }
}
