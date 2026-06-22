//! A minimal file-backed host-local IPAM: allocate one IPv4 per container from
//! a subnet, tracking allocations as files under a state directory so DEL can
//! free by container id. A coarse lock file serialises concurrent invocations.

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use velstra_common::parse_cidr_v4;

/// Default root for IPAM state. One subdirectory per network name.
pub const DEFAULT_STATE_ROOT: &str = "/var/lib/velstra-cni";

/// A pool of addresses for one network, persisted under `<root>/<network>/`.
pub struct Ipam {
    dir: PathBuf,
    net: u32,
    prefix: u8,
    default_gateway: u32,
}

impl Ipam {
    /// Open (creating if needed) the IPAM state for `network` over `subnet`.
    pub fn open(network: &str, subnet: &str, state_root: &Path) -> Result<Self> {
        let cidr = parse_cidr_v4(subnet).map_err(|e| anyhow::anyhow!("invalid subnet: {e}"))?;
        if cidr.prefix >= 31 {
            bail!("subnet {subnet} is too small to allocate from");
        }
        let dir = state_root.join(network);
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        let net = u32::from_be_bytes(cidr.octets);
        Ok(Self {
            dir,
            net,
            prefix: cidr.prefix,
            default_gateway: net + 1, // first usable address
        })
    }

    /// Number of addresses in the subnet (`2^(32-prefix)`).
    fn size(&self) -> u32 {
        1u32 << (32 - self.prefix as u32)
    }

    /// Allocate the first free address for `container_id`, returning
    /// `(address, prefix, gateway)`. The gateway and the network/broadcast
    /// addresses are skipped.
    pub fn allocate(
        &self,
        container_id: &str,
        gateway_override: Option<&str>,
    ) -> Result<(Ipv4Addr, u8, Ipv4Addr)> {
        let _lock = self.lock()?;
        let gateway = match gateway_override {
            Some(g) => u32::from(g.parse::<Ipv4Addr>().context("invalid gateway")?),
            None => self.default_gateway,
        };

        // Usable host range: network+1 .. broadcast-1.
        for host in (self.net + 1)..(self.net + self.size() - 1) {
            if host == gateway {
                continue;
            }
            let ip = Ipv4Addr::from(host);
            let path = self.dir.join(ip.to_string());
            // create_new is the atomic "claim this address" operation.
            if let Ok(()) = fs::write_new(&path, container_id) {
                return Ok((ip, self.prefix, Ipv4Addr::from(gateway)));
            }
        }
        bail!("no free addresses left in the subnet");
    }

    /// Release every address held by `container_id` (idempotent).
    pub fn release(&self, container_id: &str) -> Result<()> {
        let _lock = self.lock()?;
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".lock") {
                continue;
            }
            if fs::read_to_string(&path).ok().as_deref() == Some(container_id) {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(())
    }

    /// Acquire the coarse per-network lock (best effort; proceeds after a
    /// timeout rather than failing the whole CNI call).
    fn lock(&self) -> Result<LockGuard> {
        let path = self.dir.join(".lock");
        for _ in 0..200 {
            if fs::write_new(&path, "").is_ok() {
                return Ok(LockGuard(path));
            }
            sleep(Duration::from_millis(10));
        }
        // Stale lock: take it over rather than wedging forever.
        let _ = fs::write(&path, "");
        Ok(LockGuard(path))
    }
}

/// Removes the lock file when dropped.
struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Small `fs` helpers local to this module.
mod fs {
    pub use std::fs::*;
    use std::{io::Write, path::Path};

    /// Create a file only if it does not exist, writing `contents`.
    pub fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        f.write_all(contents.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "velstra-ipam-test-{}-{}",
            std::process::id(),
            // a per-call salt so tests don't share state
            COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn allocates_sequentially_skipping_reserved() {
        let root = temp_root();
        let ipam = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        // /29 = 8 addrs: .0 network, .1 gateway, .2..=.6 usable, .7 broadcast.
        let (a, prefix, gw) = ipam.allocate("c1", None).unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(prefix, 29);
        assert_eq!(gw, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            ipam.allocate("c2", None).unwrap().0,
            Ipv4Addr::new(10, 0, 0, 3)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn release_frees_the_address() {
        let root = temp_root();
        let ipam = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        let (a, ..) = ipam.allocate("c1", None).unwrap();
        ipam.release("c1").unwrap();
        // Next allocation reuses the freed address.
        assert_eq!(ipam.allocate("c2", None).unwrap().0, a);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn honours_gateway_override_and_exhaustion() {
        let root = temp_root();
        let ipam = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        // Override the gateway to .2: only .2 is skipped, so .1 becomes usable.
        let (a, _, gw) = ipam.allocate("c1", Some("10.0.0.2")).unwrap();
        assert_eq!(gw, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(a, Ipv4Addr::new(10, 0, 0, 1));
        // Usable: .1 (taken), .3, .4, .5, .6 = 5 total; the 6th fails.
        for c in ["c2", "c3", "c4", "c5"] {
            ipam.allocate(c, Some("10.0.0.2")).unwrap();
        }
        assert!(ipam.allocate("c6", Some("10.0.0.2")).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_tiny_subnets() {
        let root = temp_root();
        assert!(Ipam::open("net", "10.0.0.0/31", &root).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }
}
