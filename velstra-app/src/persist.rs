//! Keeping the datapath alive across an agent restart (DP-12, DP-27).
//!
//! Without this, every XDP and TC attachment belongs to the agent process: the
//! moment it dies the programs detach and the links forward unfiltered until a
//! new agent attaches again, and the connection-state maps die with it, so
//! every established and NAT'd connection is dropped on every restart.
//!
//! With `[state] persist = true` the agent pins, under [`ROOT`] in bpffs:
//!
//! * every XDP link and TC egress link, so a dead agent leaves the last policy
//!   **enforcing**, and the next agent swaps its programs in with one atomic
//!   `bpf_link_update` per link instead of detaching and re-attaching;
//! * the connection-state maps (`CONNTRACK`, `FW_FLOWS`, `SYN_FLOWS` and the
//!   SYN-cookie key), so the next agent adopts the flows in flight.
//!
//! State is adopted only into an identical layout. The pins live in a directory
//! named by [`layout_tag`]: a different state-struct layout, table size or
//! interface-to-policy assignment gives a different directory, the old one is
//! removed, and the agent starts with empty tables and says so. A pinned map is
//! also checked against the expected kernel definition before it is reused.

use std::{
    io,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use aya::{
    EbpfLoader,
    maps::{MapData, MapType},
};
use log::{info, warn};

use crate::state_tables::Sizing;

/// Where everything is pinned. Must be on bpffs.
pub const ROOT: &str = "/sys/fs/bpf/velstra";
const LINKS: &str = "links";
const STATE_PREFIX: &str = "state-";
const PROGS_PREFIX: &str = "progs-";

/// The tail-call program arrays. The kernel empties a program array once no
/// user-space reference to it remains (to break reference cycles), so a dead
/// agent's pinned links would keep running programs whose every tail call
/// fails — dropping all traffic instead of enforcing the last policy. Each
/// agent therefore pins its own arrays, under a directory of its own; the next
/// agent removes them once its programs have replaced the old ones.
pub const PROGRAM_ARRAYS: [&str; 3] = ["VELSTRA_PROGS", "V4_STATE_PROGS", "EGRESS_PROGS"];

/// Bump when the **meaning** of any field of `FirewallKey`, `FirewallState`,
/// `FlowKey`, `FlowState` or `SynFlow` changes without its size changing. A
/// size change is caught on its own; a reinterpretation is not, and adopting
/// state written under another meaning would enforce nonsense.
pub const STATE_LAYOUT_VERSION: u32 = 1;

/// One connection-state map the agent pins, with its expected definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateMap {
    pub name: &'static str,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// The map types a state map may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapKind {
    LruHash,
    Array,
}

impl MapKind {
    fn matches(self, kind: MapType) -> bool {
        matches!(
            (self, kind),
            (MapKind::LruHash, MapType::LruHash) | (MapKind::Array, MapType::Array)
        )
    }
}

fn size<T>() -> u32 {
    size_of::<T>() as u32
}

/// Every map whose contents survive a restart, sized by `sizing`.
pub fn state_maps(sizing: &Sizing) -> [StateMap; 4] {
    use velstra_common::{FirewallKey, FirewallState, FlowKey, FlowState, SynFlow};
    [
        StateMap {
            name: "FW_FLOWS",
            kind: MapKind::LruHash,
            key_size: size::<FirewallKey>(),
            value_size: size::<FirewallState>(),
            max_entries: sizing.fw_flows,
        },
        StateMap {
            name: "CONNTRACK",
            kind: MapKind::LruHash,
            key_size: size::<FlowKey>(),
            value_size: size::<FlowState>(),
            max_entries: sizing.conntrack,
        },
        StateMap {
            name: "SYN_FLOWS",
            kind: MapKind::LruHash,
            key_size: size::<FlowKey>(),
            value_size: size::<SynFlow>(),
            max_entries: sizing.syn_flows,
        },
        // The cookie key travels with the half-open handshakes it signed.
        StateMap {
            name: "SYN_SECRET",
            kind: MapKind::Array,
            key_size: size::<u32>(),
            value_size: size::<u64>(),
            max_entries: 2,
        },
    ]
}

/// The directory name state is pinned under: every property that decides
/// whether old state may be read by the new agent.
///
/// `identity` is the interface → policy-id assignment. Policy ids are scoped
/// into every state key, and a policy id that moved to another zone while the
/// agent was down must not let the new owner inherit the old owner's flows —
/// exactly what a live reload answers with `reload-reset`.
pub fn layout_tag(maps: &[StateMap], identity: &[(String, u32)]) -> String {
    let mut hash = Fnv::new();
    hash.write(&STATE_LAYOUT_VERSION.to_le_bytes());
    for map in maps {
        hash.write(map.name.as_bytes());
        hash.write(&[map.kind as u8]);
        for field in [map.key_size, map.value_size, map.max_entries] {
            hash.write(&field.to_le_bytes());
        }
    }
    let mut identity = identity.to_vec();
    identity.sort();
    for (name, policy) in identity {
        hash.write(name.as_bytes());
        hash.write(&[0]);
        hash.write(&policy.to_le_bytes());
    }
    format!("{STATE_PREFIX}{:016x}", hash.0)
}

/// FNV-1a: stable across builds and Rust versions, unlike `DefaultHasher`.
struct Fnv(u64);

impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// What a link pin is for. The XDP attach mode is part of the name because the
/// kernel does not report it for a link and an operator who changed the mode
/// must get a fresh attachment rather than the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkRole {
    Xdp(XdpModeName),
    Egress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpModeName {
    Driver,
    Skb,
    Hardware,
}

impl XdpModeName {
    fn as_str(self) -> &'static str {
        match self {
            XdpModeName::Driver => "drv",
            XdpModeName::Skb => "skb",
            XdpModeName::Hardware => "hw",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "drv" => XdpModeName::Driver,
            "skb" => XdpModeName::Skb,
            "hw" => XdpModeName::Hardware,
            _ => return None,
        })
    }
}

/// The pin file name of `role` on `iface`.
pub fn link_file(role: LinkRole, iface: &str) -> String {
    match role {
        LinkRole::Xdp(mode) => format!("xdp-{}-{iface}", mode.as_str()),
        LinkRole::Egress => format!("egress-{iface}"),
    }
}

/// The role and interface a pin file name stands for, if it is one of ours.
pub fn parse_link_file(file: &str) -> Option<(LinkRole, &str)> {
    if let Some(iface) = file.strip_prefix("egress-") {
        return valid_iface(iface).then_some((LinkRole::Egress, iface));
    }
    let rest = file.strip_prefix("xdp-")?;
    let (mode, iface) = rest.split_once('-')?;
    let mode = XdpModeName::parse(mode)?;
    valid_iface(iface).then_some((LinkRole::Xdp(mode), iface))
}

fn valid_iface(name: &str) -> bool {
    !name.is_empty() && name.len() < 16 && !name.contains(['/', '\0'])
}

/// The pin directory the agent owns.
#[derive(Debug, Clone)]
pub struct Persist {
    root: PathBuf,
}

/// The outcome of preparing the state directory.
#[derive(Debug)]
pub struct StateDir {
    pub path: PathBuf,
    /// The previous agent's maps are reused; `false` means fresh tables.
    pub adopted: bool,
}

impl Persist {
    /// Open (creating if needed) the pin directory under `root`, which must be
    /// on a mounted bpffs.
    pub fn open(root: &Path) -> Result<Self> {
        let parent = root.parent().unwrap_or(root);
        anyhow::ensure!(
            on_bpffs(parent)?,
            "{} is not a mounted bpffs; cannot persist the datapath",
            parent.display()
        );
        std::fs::create_dir_all(root.join(LINKS))
            .with_context(|| format!("creating {}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Pick the state directory for `maps` under `tag`, removing every other
    /// layout's directory and any pinned map that does not match `maps`.
    pub fn prepare_state(&self, tag: &str, maps: &[StateMap]) -> Result<StateDir> {
        for entry in read_dir(&self.root)? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(STATE_PREFIX) && name != tag {
                warn!(
                    "connection state pinned under {name} has another layout or interface \
                     assignment; starting with empty state tables"
                );
                remove_tree(&entry.path())?;
            }
        }
        let path = self.root.join(tag);
        let present = maps.iter().filter(|m| path.join(m.name).exists()).count();
        let mut adopted = present == maps.len();
        if adopted {
            for map in maps {
                if let Err(error) = check_pinned(&path.join(map.name), map) {
                    warn!("not adopting pinned {}: {error:#}", map.name);
                    adopted = false;
                }
            }
        } else if present > 0 {
            warn!("pinned connection state is incomplete; starting with empty state tables");
        }
        if !adopted && path.exists() {
            remove_tree(&path)?;
        }
        std::fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        if adopted {
            info!("adopting the connection state of the previous agent ({tag})");
        }
        Ok(StateDir { path, adopted })
    }

    /// Point the loader's state maps at `dir`: reused when pinned there,
    /// created and pinned there otherwise.
    pub fn apply<'a>(loader: &mut EbpfLoader<'a>, dir: &Path, maps: &[StateMap]) {
        for map in maps {
            loader.map_pin_path(map.name, dir.join(map.name));
        }
    }

    /// The pin path of `role` on `iface`.
    pub fn link_path(&self, role: LinkRole, iface: &str) -> PathBuf {
        self.root.join(LINKS).join(link_file(role, iface))
    }

    /// Every pinned XDP link for `iface`, whatever its mode.
    pub fn xdp_pins(&self, iface: &str) -> Result<Vec<(XdpModeName, PathBuf)>> {
        Ok(self
            .link_pins()?
            .into_iter()
            .filter_map(|(role, name, path)| match role {
                LinkRole::Xdp(mode) if name == iface => Some((mode, path)),
                _ => None,
            })
            .collect())
    }

    /// Every link pin, parsed.
    pub fn link_pins(&self) -> Result<Vec<(LinkRole, String, PathBuf)>> {
        let mut pins = Vec::new();
        for entry in read_dir(&self.root.join(LINKS))? {
            let file = entry.file_name();
            let file = file.to_string_lossy();
            match parse_link_file(&file) {
                Some((role, iface)) => pins.push((role, iface.to_string(), entry.path())),
                None => warn!("ignoring unexpected pin {}", entry.path().display()),
            }
        }
        Ok(pins)
    }

    /// Pin this agent's tail-call program arrays (see [`PROGRAM_ARRAYS`]) in a
    /// directory no other agent uses. Returns that directory.
    pub fn pin_program_arrays(&self, ebpf: &aya::Ebpf) -> Result<PathBuf> {
        let generation = format!(
            "{PROGS_PREFIX}{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        );
        let dir = self.root.join(generation);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        for name in PROGRAM_ARRAYS {
            ebpf.map(name)
                .with_context(|| format!("{name} missing"))?
                .pin(dir.join(name))
                .with_context(|| format!("pinning {name}"))?;
        }
        Ok(dir)
    }

    /// Remove every agent's program arrays except `keep`'s. Called once this
    /// agent's programs own every pinned link: the previous agent's programs
    /// are then unreachable and may go.
    pub fn sweep_program_arrays(&self, keep: &Path) -> Result<()> {
        for entry in read_dir(&self.root)? {
            let path = entry.path();
            let name = entry.file_name();
            if name.to_string_lossy().starts_with(PROGS_PREFIX) && path != keep {
                remove_tree(&path)?;
            }
        }
        Ok(())
    }

    /// Detach every pinned link and drop every pinned state map.
    pub fn release(root: &Path) -> Result<()> {
        if root.exists() {
            remove_tree(root)?;
        }
        Ok(())
    }
}

fn read_dir(path: &Path) -> Result<Vec<std::fs::DirEntry>> {
    match std::fs::read_dir(path) {
        Ok(entries) => entries
            .collect::<io::Result<Vec<_>>>()
            .with_context(|| format!("listing {}", path.display())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("listing {}", path.display())),
    }
}

/// bpffs supports unlink and rmdir but not `remove_dir_all`'s openat walk on
/// every kernel, so walk it by hand.
fn remove_tree(path: &Path) -> Result<()> {
    if path.is_dir() {
        for entry in read_dir(path)? {
            remove_tree(&entry.path())?;
        }
        std::fs::remove_dir(path).with_context(|| format!("removing {}", path.display()))
    } else {
        remove_pin(path)
    }
}

/// Remove one pin; one that is already gone is not an error.
pub fn remove_pin(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
    }
}

fn check_pinned(path: &Path, expected: &StateMap) -> Result<()> {
    let map = MapData::from_pin(path).with_context(|| format!("opening {}", path.display()))?;
    let info = map.info().context("reading pinned map metadata")?;
    let kind = info.map_type()?;
    let found = (
        info.key_size(),
        info.value_size(),
        info.max_entries(),
        expected.kind.matches(kind),
    );
    if found
        != (
            expected.key_size,
            expected.value_size,
            expected.max_entries,
            true,
        )
    {
        bail!(
            "pinned definition {kind:?} key {} value {} entries {} does not match {:?}",
            found.0,
            found.1,
            found.2,
            expected
        );
    }
    Ok(())
}

fn on_bpffs(path: &Path) -> Result<bool> {
    const BPF_FS_MAGIC: i64 = 0xcafe_4a11;
    let text = path
        .to_str()
        .with_context(|| format!("{} is not UTF-8", path.display()))?;
    let c_path = std::ffi::CString::new(text).context("pin path contains NUL")?;
    // SAFETY: statfs writes only into the zeroed struct handed to it.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(false);
        }
        return Err(error).with_context(|| format!("statfs {}", path.display()));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(stat.f_type as i64 == BPF_FS_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maps() -> [StateMap; 4] {
        state_maps(&Sizing::for_connections(65_536))
    }

    #[test]
    fn the_layout_tag_is_stable_and_names_every_property_that_matters() {
        let identity = vec![("lan0".to_string(), 1), ("wan0".to_string(), 2)];
        let tag = layout_tag(&maps(), &identity);
        assert!(tag.starts_with(STATE_PREFIX) && tag.len() == STATE_PREFIX.len() + 16);
        // Order of the interface list is not a property of the layout.
        let reversed: Vec<_> = identity.iter().rev().cloned().collect();
        assert_eq!(tag, layout_tag(&maps(), &reversed));
        // Deterministic: the same inputs name the same directory every run.
        assert_eq!(tag, layout_tag(&maps(), &identity));

        // A resized table, a renumbered zone or a moved interface: fresh state.
        let resized = state_maps(&Sizing::for_connections(131_072));
        assert_ne!(tag, layout_tag(&resized, &identity));
        let renumbered = vec![("lan0".to_string(), 2), ("wan0".to_string(), 1)];
        assert_ne!(tag, layout_tag(&maps(), &renumbered));
        let mut widened = maps();
        widened[0].value_size += 8;
        assert_ne!(tag, layout_tag(&widened, &identity));
    }

    #[test]
    fn the_state_maps_are_the_ones_the_datapath_keys_connections_on() {
        let names: Vec<_> = maps().iter().map(|m| m.name).collect();
        assert_eq!(names, ["FW_FLOWS", "CONNTRACK", "SYN_FLOWS", "SYN_SECRET"]);
        let sizing = Sizing::for_connections(65_536);
        assert_eq!(maps()[0].max_entries, sizing.fw_flows);
        // The expected definition follows the shared types, so a datapath that
        // widens a state struct gets a fresh state directory, not a misread.
        use velstra_common::{FirewallKey, FirewallState, FlowKey, FlowState};
        assert_eq!(
            (maps()[0].key_size, maps()[0].value_size),
            (size::<FirewallKey>(), size::<FirewallState>())
        );
        assert_eq!(
            (maps()[1].key_size, maps()[1].value_size),
            (size::<FlowKey>(), size::<FlowState>())
        );
    }

    #[test]
    fn link_pin_names_round_trip_and_reject_foreign_files() {
        for (role, iface) in [
            (LinkRole::Xdp(XdpModeName::Driver), "wan0"),
            (LinkRole::Xdp(XdpModeName::Skb), "lan0.10"),
            (LinkRole::Xdp(XdpModeName::Hardware), "eth-x"),
            (LinkRole::Egress, "ppp0"),
        ] {
            let file = link_file(role, iface);
            assert_eq!(parse_link_file(&file), Some((role, iface)), "{file}");
        }
        for foreign in [
            "xdp-",
            "xdp-fast-wan0",
            "egress-",
            "egress-averyveryverylongname",
            "HA_OWNER",
        ] {
            assert_eq!(parse_link_file(foreign), None, "{foreign}");
        }
    }

    #[test]
    fn a_path_off_bpffs_is_refused() {
        let dir = std::env::temp_dir().join(format!("velstra-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let error = Persist::open(&dir.join("velstra")).unwrap_err();
        assert!(format!("{error:#}").contains("not a mounted bpffs"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
