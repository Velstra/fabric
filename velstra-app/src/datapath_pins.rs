//! Optional appliance-owned kernel links. Process death must not unhook policy.
//!
//! One writer holds a process lock for this private bpffs directory. The shared
//! apply gate closes both inherited and new programs during replacement. Pins
//! are retired explicitly when an interface/hook leaves the desired set; normal
//! process teardown only closes descriptors and leaves enforcement attached.

use std::{
    collections::BTreeSet,
    fs::{DirBuilder, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use aya::{
    maps::{Array, Map, MapData, MapType},
    programs::{
        XdpMode,
        links::{FdLink, LinkError, PinnedLink},
        tc::SchedClassifierLink,
        xdp::XdpLink,
    },
};

pub struct DatapathPins {
    root: PathBuf,
    _lock: File,
}

/// Kernel state and its lifecycle catalogue must survive/reinitialize together.
/// Scratch buffers are per-invocation and deliberately are not persistent.
pub const FLOW_STATE_PINS: &[(&str, &str)] = &[
    ("FW_SLOT", "flow-slot-v1"),
    ("FW_ALLOC", "flow-allocator-v1"),
    ("FW_INDEX", "flow-index-v1"),
    ("FW_SCOPE_META", "flow-scope-meta-v1"),
    ("FW_LABELS", "flow-labels-v1"),
    ("FW_POLICY", "flow-policies-v1"),
    ("FW_TIMEOUT", "flow-timeouts-v1"),
];

impl DatapathPins {
    pub fn open(root: &Path) -> Result<Self> {
        // SAFETY: geteuid has no arguments or memory-safety preconditions.
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "persistent datapath requires root"
        );
        ensure!(
            root.is_absolute(),
            "datapath state directory must be absolute"
        );
        match DirBuilder::new().mode(0o700).create(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("creating private datapath directory"),
        }
        let metadata = std::fs::symlink_metadata(root)?;
        private_directory(&metadata)?;
        ensure!(
            root.canonicalize()? == root,
            "datapath directory must not contain symlinks or traversal"
        );
        let directory = File::open(root)?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: the descriptor is live; stat points to writable storage of the
        // kernel ABI type. Only read it after a successful fstatfs.
        let result = unsafe { libc::fstatfs(directory.as_raw_fd(), stat.as_mut_ptr()) };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("checking datapath filesystem");
        }
        // SAFETY: fstatfs returned success and initialized stat above.
        let stat = unsafe { stat.assume_init() };
        ensure!(
            stat.f_type == 0xcafe4a11,
            "datapath state directory must be on bpffs"
        );

        let locks = Path::new("/run/velstra-datapath-locks");
        match DirBuilder::new().mode(0o755).create(locks) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("creating datapath lock directory"),
        }
        let lock_dir = std::fs::symlink_metadata(locks)?;
        ensure!(
            lock_dir.is_dir() && lock_dir.uid() == 0 && lock_dir.permissions().mode() & 0o022 == 0,
            "datapath lock directory must be owned by root and not writable by other users"
        );
        let lock_path = locks.join(format!("pins-{}-{}.lock", metadata.dev(), metadata.ino()));
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(lock_path)?;
        let lock_metadata = lock.metadata()?;
        ensure!(
            lock_metadata.is_file()
                && lock_metadata.uid() == 0
                && lock_metadata.permissions().mode() & 0o077 == 0,
            "datapath lock must be a private root-owned regular file"
        );
        // SAFETY: lock owns the descriptor for the lifetime of this object.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("another agent owns this datapath directory");
        }
        let pins = Self {
            root: root.to_owned(),
            _lock: lock,
        };
        pins.validate_maps()?;
        pins.recover_unpublished_flow_maps()?;
        Ok(pins)
    }

    fn validate_maps(&self) -> Result<()> {
        // The loader reuses a pinned descriptor without checking the actual
        // kernel map against its ELF declaration. Check our stable control ABI
        // before any writes or replacements, including during maintenance.
        for (name, kind, entries) in [
            ("apply-state", MapType::Array, 1),
            ("programs", MapType::ProgramArray, 3),
            ("ipv6-programs", MapType::ProgramArray, 3),
            ("ipv6-tc-programs", MapType::ProgramArray, 1),
        ] {
            let path = self.root.join(name);
            if !path.try_exists()? {
                continue;
            }
            let info = MapData::from_pin(&path)?.info()?;
            ensure!(
                info.map_type()? == kind
                    && info.key_size() == 4
                    && info.value_size() == 4
                    && info.max_entries() == entries
                    && info.map_flags() == 0,
                "incompatible persistent control map {name}; no datapath changes were made"
            );
        }
        let core = [
            (
                "FW_SLOT",
                MapType::Array,
                4,
                core::mem::size_of::<velstra_common::FirewallFlowSlot>() as u32,
                velstra_common::firewall_control::FIREWALL_FLOW_CAPACITY,
            ),
            (
                "FW_ALLOC",
                MapType::Array,
                4,
                core::mem::size_of::<velstra_common::FirewallFlowAllocator>() as u32,
                1,
            ),
            (
                "FW_INDEX",
                MapType::Hash,
                core::mem::size_of::<velstra_common::FirewallFlowKey>() as u32,
                core::mem::size_of::<velstra_common::FirewallFlowRef>() as u32,
                velstra_common::firewall_control::FIREWALL_FLOW_CAPACITY,
            ),
        ];
        for (map, kind, key, value, count) in core
            .into_iter()
            .chain(velstra::flow_scopes::scope_map_specs())
        {
            let path = self.flow_map_path(map)?;
            if !path.try_exists()? {
                continue;
            }
            let info = MapData::from_pin(&path)?.info()?;
            ensure!(
                info.map_type()? == kind
                    && info.key_size() == key
                    && info.value_size() == value
                    && info.max_entries() == count
                    && info.map_flags() == 0,
                "incompatible persistent state map {map}; no datapath changes were made"
            );
        }
        Ok(())
    }

    pub fn flow_map_path(&self, map: &str) -> Result<PathBuf> {
        let (_, name) = FLOW_STATE_PINS
            .iter()
            .find(|(key, _)| *key == map)
            .with_context(|| format!("unknown persistent flow map {map}"))?;
        Ok(self.root.join(name))
    }

    fn recover_unpublished_flow_maps(&self) -> Result<()> {
        let mut present = Vec::new();
        for (map, _) in FLOW_STATE_PINS {
            let path = self.flow_map_path(map)?;
            if path.try_exists()? {
                present.push(path);
            }
        }
        if present.is_empty() || present.len() == FLOW_STATE_PINS.len() {
            return Ok(());
        }
        let metadata = self.flow_map_path("FW_SCOPE_META")?;
        if metadata.try_exists()? {
            let map: Array<_, velstra_common::FlowScopeMetadata> =
                Array::try_from(Map::from_map_data(MapData::from_pin(&metadata)?)?)?;
            ensure!(
                map.get(&0, 0)? == velstra_common::FlowScopeMetadata::EMPTY,
                "persistent flow state is incomplete after namespace publication; refusing to discard live state"
            );
        } else {
            let mut has_hooks = false;
            for entry in std::fs::read_dir(&self.root)? {
                let entry = entry?;
                has_hooks |= entry.file_name().to_str().is_some_and(owned_link_name);
            }
            ensure!(
                !has_hooks,
                "persistent flow namespace is missing while enforcement links exist; refusing to discard potentially live state"
            );
        }
        // A namespace is initialized only AFTER every state map has loaded,
        // and before any new hooks or scope views can publish a grant. An
        // interrupted initial loader therefore leaves only unpublished maps.
        for path in present {
            std::fs::remove_file(path).context("recovering unpublished flow map group")?;
        }
        Ok(())
    }

    pub fn gate(&self) -> PathBuf {
        self.root.join("apply-state")
    }

    /// A PROG_ARRAY loses its entries when its last userspace reference closes,
    /// even while an attached program still refers to the map. Retain that
    /// reference along with the links so a daemon crash cannot empty tail calls.
    pub fn programs(&self) -> PathBuf {
        self.root.join("programs")
    }
    pub fn ipv6_programs(&self) -> PathBuf {
        self.root.join("ipv6-programs")
    }
    pub fn ipv6_tc_programs(&self) -> PathBuf {
        self.root.join("ipv6-tc-programs")
    }

    pub fn xdp_path(&self, index: u32, mode: XdpMode) -> PathBuf {
        self.root.join(format!("xdp-{index}-{}", mode_name(mode)))
    }

    pub fn tc_path(&self, index: u32, ingress: bool) -> PathBuf {
        self.root.join(format!(
            "{}-{index}",
            if ingress { "bum" } else { "egress" }
        ))
    }

    pub fn handoff_path(&self, index: u32) -> PathBuf {
        self.root.join(format!("handoff-{index}"))
    }

    pub fn inherited_handoff(&self, index: u32) -> Result<Option<SchedClassifierLink>> {
        let path = self.handoff_path(index);
        if !path.try_exists()? {
            return Ok(None);
        }
        Ok(Some(FdLink::from(PinnedLink::from_pin(path)?).try_into()?))
    }

    pub fn inherited_xdp(&self, index: u32) -> Result<Option<(XdpMode, XdpLink)>> {
        let mut existing = Vec::new();
        for mode in [
            XdpMode::Default,
            XdpMode::Driver,
            XdpMode::Skb,
            XdpMode::Hardware,
        ] {
            let path = self.xdp_path(index, mode);
            if path.try_exists()? {
                existing.push((mode, path));
            }
        }
        ensure!(
            existing.len() <= 1,
            "multiple persistent XDP modes for interface {index}"
        );
        let Some((mode, path)) = existing.pop() else {
            return Ok(None);
        };
        Ok(Some((
            mode,
            FdLink::from(PinnedLink::from_pin(path)?).try_into()?,
        )))
    }

    pub fn inherited_tc(&self, index: u32, ingress: bool) -> Result<Option<SchedClassifierLink>> {
        let path = self.tc_path(index, ingress);
        if !path.try_exists()? {
            return Ok(None);
        }
        Ok(Some(FdLink::from(PinnedLink::from_pin(path)?).try_into()?))
    }

    /// Keep the pin, but return an ordinary typed descriptor to the reconciler.
    /// No unpin/re-pin window is introduced when replacing an inherited link.
    pub fn pin_new<L>(&self, path: &Path, link: L) -> Result<L>
    where
        L: TryInto<FdLink, Error = LinkError> + TryFrom<FdLink, Error = LinkError>,
    {
        let fd = link
            .try_into()
            .context("kernel does not provide a pinnable link for this hook")?;
        let _pinned = fd.pin(path).context("pinning datapath enforcement")?;
        FdLink::from(PinnedLink::from_pin(path)?)
            .try_into()
            .context("reopening pinned datapath link")
    }

    /// Startup adopts the current link set under the closed shared apply gate.
    /// Old hooks not adopted by the complete configuration must not outlive it.
    pub fn retire_unused(&self, wanted: &BTreeSet<PathBuf>) -> Result<()> {
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("invalid datapath pin name")?;
            if name == "apply-state"
                || name == "programs"
                || name == "ipv6-programs"
                || name == "ipv6-tc-programs"
                || FLOW_STATE_PINS.iter().any(|(_, pin)| *pin == name)
            {
                continue;
            }
            ensure!(
                owned_link_name(name),
                "unexpected object in private datapath directory: {name}"
            );
            if !wanted.contains(&entry.path()) {
                std::fs::remove_file(entry.path()).context("retiring obsolete datapath hook")?;
            }
        }
        Ok(())
    }

    /// Explicit maintenance action, separate from service stop/crash. Validate
    /// the whole directory before changing it; never delete foreign objects.
    pub fn detach(&self) -> Result<()> {
        for entry in std::fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_str().context("invalid datapath pin name")?;
            ensure!(
                name == "apply-state"
                    || name == "programs"
                    || name == "ipv6-programs"
                    || name == "ipv6-tc-programs"
                    || owned_link_name(name)
                    || FLOW_STATE_PINS.iter().any(|(_, pin)| *pin == name),
                "unexpected object in private datapath directory: {name}"
            );
        }
        let path = self.gate();
        if path.try_exists()? {
            let mut gate: Array<_, u32> =
                Array::try_from(Map::from_map_data(MapData::from_pin(&path)?)?)?;
            gate.set(0, velstra_common::CONFIG_UPDATING, 0)?;
        }
        self.retire_unused(&BTreeSet::new())?;
        for (map, _) in FLOW_STATE_PINS {
            let path = self.flow_map_path(map)?;
            if path.try_exists()? {
                std::fs::remove_file(path)?;
            }
        }
        let programs = self.programs();
        if programs.try_exists()? {
            std::fs::remove_file(programs)?;
        }
        let ipv6_programs = self.ipv6_programs();
        if ipv6_programs.try_exists()? {
            std::fs::remove_file(ipv6_programs)?;
        }
        let ipv6_tc = self.ipv6_tc_programs();
        if ipv6_tc.try_exists()? {
            std::fs::remove_file(ipv6_tc)?;
        }
        if path.try_exists()? {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

fn mode_name(mode: XdpMode) -> &'static str {
    match mode {
        XdpMode::Default => "default",
        XdpMode::Driver => "driver",
        XdpMode::Skb => "skb",
        XdpMode::Hardware => "hw",
    }
}

fn owned_link_name(name: &str) -> bool {
    let parts: Vec<_> = name.split('-').collect();
    match parts.as_slice() {
        ["xdp", index, "default" | "driver" | "skb" | "hw"]
        | ["egress" | "bum" | "handoff", index] => index
            .parse::<u32>()
            .is_ok_and(|value| value > 0 && value.to_string() == *index),
        _ => false,
    }
}

fn private_directory(metadata: &std::fs::Metadata) -> Result<()> {
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        bail!("datapath directory must be a private root-owned directory");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_owned_hook_names_can_be_retired() {
        for name in [
            "xdp-1-driver",
            "xdp-123-skb",
            "xdp-9-hw",
            "egress-12",
            "bum-42",
            "handoff-42",
        ] {
            assert!(owned_link_name(name), "{name}");
        }
        for name in [
            "xdp-0-skb",
            "xdp-01-driver",
            "xdp-1-other",
            "xdp-1-skb-extra",
            "egress-0",
            "egress-+1",
            "egress-4294967296",
            "foreign",
            "apply-state",
            "../xdp-1-skb",
        ] {
            assert!(!owned_link_name(name), "{name}");
        }
    }
}
