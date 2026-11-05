//! A minimal file-backed host-local IPAM: allocate one IPv4 per container from
//! a subnet, tracking allocations as files under a state directory so DEL can
//! free by container id. A coarse lock file serialises concurrent invocations.

use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    thread::sleep,
    time::{Duration, Instant},
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
        // The upper bound keeps at least one usable host after the network,
        // gateway and broadcast are taken; the lower bound is not cosmetic.
        // `size()` computes `1 << (32 - prefix)`, and a `/0` — which the CIDR
        // parser accepts — makes that `1 << 32`: a panic in debug, and on x86
        // in release a shift-by-`32 % 32 = 0` that silently returns 1, so the
        // allocator would hand out a single address for the whole IPv4 space.
        // A CNI subnet shorter than /8 is a configuration error regardless, and
        // the cheapest correct guard is to name a floor.
        if cidr.prefix < 8 || cidr.prefix >= 31 {
            bail!(
                "subnet {subnet} (/{}) is out of range for allocation; use /8 through /30",
                cidr.prefix
            );
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
            match fs::write_new(&path, container_id) {
                Ok(()) => return Ok((ip, self.prefix, Ipv4Addr::from(gateway))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating IPAM lease {}", path.display()));
                }
            }
        }
        bail!("no free addresses left in the subnet");
    }

    /// Release every address held by `container_id` (idempotent).
    pub fn release(&self, container_id: &str) -> Result<()> {
        let _lock = self.lock()?;
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| name.starts_with('.'))
            {
                continue;
            }
            if fs::read_to_string(&path)
                .with_context(|| format!("reading IPAM lease {}", path.display()))?
                == container_id
            {
                fs::remove_file(&path)
                    .with_context(|| format!("removing IPAM lease {}", path.display()))?;
            }
        }
        fs::File::open(&self.dir)?
            .sync_all()
            .context("syncing released IPAM leases")?;
        Ok(())
    }

    /// The kernel owns lock lifetime. A busy owner is never declared stale by
    /// elapsed time, and the shared lock inode is never removed or replaced.
    fn lock(&self) -> Result<fs::File> {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        let path = self.dir.join(".lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .context("opening IPAM lock")?;
        if !file.metadata()?.is_file() {
            bail!("IPAM lock is not a regular file");
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            // SAFETY: file owns a live descriptor; flock neither borrows nor
            // takes ownership of any Rust memory. Drop closes/unlocks it.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(file);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::WouldBlock
                && error.kind() != std::io::ErrorKind::Interrupted
            {
                return Err(error).context("acquiring IPAM lock");
            }
            if Instant::now() >= deadline {
                bail!("IPAM lock is busy; retry the CNI operation (live owner was not displaced)");
            }
            sleep(Duration::from_millis(10));
        }
    }
}

/// Small `fs` helpers local to this module.
mod fs {
    pub use std::fs::*;
    use std::{
        io::Write,
        os::unix::fs::OpenOptionsExt,
        path::Path,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// Create a file only if it does not exist, writing `contents`.
    pub fn write_new(path: &Path, contents: &str) -> std::io::Result<()> {
        write_new_with(path, contents, |file, contents| {
            file.write_all(contents.as_bytes())?;
            file.sync_all()
        })
    }

    pub(super) fn write_new_with(
        path: &Path,
        contents: &str,
        write: impl FnOnce(&mut File, &str) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("lease has no parent"))?;
        let (temporary, mut file) = loop {
            let temporary = parent.join(format!(
                ".lease-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)
            {
                Ok(file) => break (temporary, file),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        };
        let mut published = false;
        let result = (|| {
            write(&mut file, contents)?;
            hard_link(&temporary, path)?;
            published = true;
            File::open(parent)?.sync_all()
        })();
        if result.is_err() && published {
            let _ = remove_file(path);
        }
        let cleaned = remove_file(temporary);
        result.and(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_lock_owner_is_not_stolen_after_two_seconds() {
        use std::os::unix::fs::MetadataExt;
        let root = temp_root();
        let ipam = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        let owner = ipam.lock().unwrap();
        let inode = std::fs::metadata(ipam.dir.join(".lock")).unwrap().ino();
        let contender = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        let thread = std::thread::spawn(move || contender.allocate("contender", None));
        std::thread::sleep(Duration::from_millis(2200));
        let error = thread.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("live owner was not displaced"));
        assert_eq!(
            std::fs::metadata(ipam.dir.join(".lock")).unwrap().ino(),
            inode
        );
        assert!(!ipam.dir.join("10.0.0.2").exists());
        drop(owner); // Closing the descriptor is also the kernel's crash-recovery mechanism.
        assert_eq!(
            ipam.allocate("recovered", None).unwrap().0,
            Ipv4Addr::new(10, 0, 0, 2)
        );
        assert_eq!(
            std::fs::metadata(ipam.dir.join(".lock")).unwrap().ino(),
            inode
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_owner_write_never_publishes_or_leaves_an_ownerless_lease() {
        use std::io::Write;
        let root = temp_root();
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("10.0.0.2");
        let error = fs::write_new_with(&path, "container", |file, _| {
            file.write_all(b"partial")?;
            Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        fs::write_new(&path, "container").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "container");
        assert_eq!(
            fs::write_new(&path, "other").unwrap_err().kind(),
            std::io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "container");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn release_reports_unreadable_lease_instead_of_claiming_success() {
        let root = temp_root();
        let ipam = Ipam::open("net", "10.0.0.0/29", &root).unwrap();
        std::fs::create_dir(ipam.dir.join("10.0.0.2")).unwrap();
        assert!(
            ipam.release("container")
                .unwrap_err()
                .to_string()
                .contains("reading IPAM lease")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

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

    /// A subnet the allocator cannot compute a size for is refused, not opened.
    ///
    /// `/0` is the sharp one: the CIDR parser accepts it, and `size()` would
    /// evaluate `1 << 32` — undefined-behaviour-shaped, a debug panic and a
    /// release value of 1. Whichever way it lands, it is reached from a config
    /// field, so it is refused at the door rather than depended on downstream.
    #[test]
    fn a_degenerate_subnet_is_refused_rather_than_panicking() {
        let root = temp_root();
        for bad in ["0.0.0.0/0", "10.0.0.0/1", "10.0.0.0/31", "10.0.0.0/32"] {
            assert!(
                Ipam::open("net", bad, &root).is_err(),
                "{bad} was opened for allocation"
            );
        }
        // The endpoints of the allowed range still open.
        assert!(Ipam::open("net", "10.0.0.0/8", &root).is_ok());
        assert!(Ipam::open("net", "10.0.0.0/30", &root).is_ok());
    }

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
