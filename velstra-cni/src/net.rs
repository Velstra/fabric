//! Pod network plumbing: create a veth pair, move one end into the container's
//! network namespace, address it, and route. Implemented by driving `ip(8)`,
//! which keeps the plugin dependency-free and easy to follow.

use std::{
    net::Ipv4Addr,
    path::Path,
    process::Command,
    thread::sleep,
    time::{Duration, Instant},
};

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
    format!("vel{:08x}", hash as u32) // "vel" + 8 hex = 11 chars
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

/// Whether an XDP program is attached to `host_veth`. `ip -details link show`
/// prints an `xdp` / `xdpgeneric` / `xdpoffload` line once the agent has attached
/// its firewall program to the interface. A transient failure to resolve the
/// interface is reported as "not yet attached", not an error, so the poll keeps
/// waiting.
fn xdp_attached(host_veth: &str) -> bool {
    let Ok(out) = Command::new("ip")
        .args(["-details", "link", "show", "dev", host_veth])
        .output()
    else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    shows_xdp(&String::from_utf8_lossy(&out.stdout))
}

/// The parse half of [`xdp_attached`], split out so the one decision that gates
/// admitting a pod can be tested without a kernel. `ip -details link show` names
/// the attached program with a `prog/xdp` (or `xdpgeneric`/`xdpoffload`) token;
/// an interface with nothing attached prints no `xdp` anywhere. Host veth names
/// are `vel` + hex, so the interface's own name can never spell it.
fn shows_xdp(link_show_output: &str) -> bool {
    link_show_output.contains("xdp")
}

/// Block until the agent has attached its XDP firewall to `host_veth`, or
/// `timeout` elapses (M3). Controller-mode ADD calls this *after* the pod
/// interface is up and addressed but *before* returning success: kubelet does
/// not start the pod's containers until ADD returns, so blocking here closes the
/// fail-open window in which a pod could send/receive traffic before the
/// firewall is enforcing. On timeout the caller fails the ADD closed (rolling
/// back the port + veth) rather than admitting an unenforced pod.
pub fn wait_for_xdp(host_veth: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let poll = Duration::from_millis(100);
    loop {
        if xdp_attached(host_veth) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out after {timeout:?} waiting for the agent to attach the XDP \
                 firewall to {host_veth}; refusing to admit an unenforced pod"
            );
        }
        sleep(poll);
    }
}

/// `ip(8)` resolves a netns by *name* under `/var/run/netns`; CNI hands us a
/// path, so we symlink it in under a temporary name for the duration of the op.
struct NetnsLink(String);

impl NetnsLink {
    fn create(netns_path: &str) -> Result<Self> {
        let dir = Path::new("/var/run/netns");
        std::fs::create_dir_all(dir).context("creating /var/run/netns")?;
        let name = format!("velcni{}", std::process::id());
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
/// host route to the pod over the host veth. If `mac` is given, the pod
/// interface wears it — required in controller mode so the overlay's ARP
/// suppression (which answers with the allocated MAC) routes frames to the pod.
pub fn setup(
    netns: &str,
    ifname: &str,
    host_veth: &str,
    ip_addr: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    mac: Option<&str>,
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
    // Set the MAC while the interface is down, before bringing it up.
    if let Some(mac) = mac {
        ip(&["-n", ns, "link", "set", ifname, "address", mac])?;
    }
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

    /// If this fails, the poll that gates pod admission has stopped recognising
    /// an attached XDP program (kubelet then starts the pod's containers with no
    /// firewall on its veth), or started seeing one where there is none (the
    /// M3 fail-closed wait becomes a no-op).
    #[test]
    fn an_interface_with_no_program_attached_does_not_read_as_enforced() {
        // Real `ip -details link show dev vel1a2b3c4d` for a plain veth.
        let bare = "7: vel1a2b3c4d@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \
                    qdisc noqueue state UP mode DEFAULT group default \n    \
                    link/ether 3a:9c:11:22:33:44 brd ff:ff:ff:ff:ff:ff link-netns cni-1 \n    \
                    veth addrgenmode eui64 numtxqueues 1 numrxqueues 1";
        assert!(
            !shows_xdp(bare),
            "an unenforced pod interface read as firewalled"
        );

        // The same interface once the agent attached its program.
        for attached in [
            "prog/xdp id 214 tag 8f9c0f2a1b3d4e5f jited",
            "xdpgeneric/id:214",
            "xdpoffload/id:214",
        ] {
            assert!(
                shows_xdp(&format!("{bare}\n    {attached}")),
                "an enforced pod interface read as unenforced: {attached}"
            );
        }
    }

    /// If this fails, controller-mode ADD no longer fails closed: it would
    /// return success for a pod whose veth the agent never firewalled, and
    /// kubelet would start the containers on an unenforced interface.
    #[test]
    fn waiting_on_an_interface_that_never_gets_a_program_gives_up_rather_than_admitting_it() {
        let err = wait_for_xdp(
            // A name no interface can have: `ip` reports "does not exist".
            "vel-no-such-if",
            Duration::from_millis(150),
        )
        .expect_err("the wait returned success for an interface with no firewall");
        assert!(
            err.to_string()
                .contains("refusing to admit an unenforced pod"),
            "the failure does not say why the pod was refused: {err}"
        );
    }

    #[test]
    fn veth_name_is_deterministic_and_short() {
        let a = veth_name("abc123");
        assert_eq!(a, veth_name("abc123"));
        assert_ne!(a, veth_name("abc124"));
        assert!(a.len() <= 15, "ifname too long: {a}");
        assert!(a.starts_with("vel"));
    }
}
