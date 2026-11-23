//! How large the connection-state maps are (DP-06).
//!
//! The eBPF object declares `CONNTRACK`, `FW_FLOWS` and `SYN_FLOWS` with 65,536
//! entries each. One masqueraded connection holds four `FW_FLOWS` entries and a
//! port-forward six, so the object's own sizes cap a box at about 16,000
//! concurrent connections (about 10,900 through DNAT) whatever its memory. The
//! agent therefore resizes these maps at load time, from `[state] connections`
//! or, absent that, from the host's memory.
//!
//! The kernel preallocates every element of an LRU hash map, so the size is
//! memory committed at load whether or not it is used. The default spends about
//! a twelfth of RAM on it.

use velstra_config::StateTables;

/// `FW_FLOWS` entries one connection can hold: a port-forward records the WAN
/// pair, the reply pair under the reply policy and the router-open pair.
pub const FW_ENTRIES_PER_CONNECTION: u32 = 6;
/// `CONNTRACK` (NAT) entries one connection can hold: a DNAT binding has a
/// forward and a reverse entry.
pub const CT_ENTRIES_PER_CONNECTION: u32 = 2;
/// `SYN_FLOWS` records per connection. A proxied connection keeps its record —
/// the sequence offset every one of its packets is translated by — for as
/// long as it lives, and any connection may be a proxied one: that is one.
/// The second is headroom for records of ended connections the agent's splice
/// sweep has not removed yet. After the last claim on a record lapses it is
/// removed at the end of the second complete round after that, and no sooner
/// than the grace (`crate::reclaim`: 2 s, or ten HA sync intervals): at most
/// about three rounds plus the grace, a round being two walks of
/// `crate::reclaim::PASS_TICKS` ticks, so some 30 s while ticks keep their
/// one-second pace (a tick whose larger walk outlasts that pace, which has not
/// been measured at the 2M-connection ceiling, stretches this). With every
/// connection slot in use the LRU then evicts no live record while proxied
/// connections end at up to about `connections / 30` per second (8,700/s at
/// 256k connections).
pub const SYN_ENTRIES_PER_CONNECTION: u32 = 2;

/// Kernel bytes per preallocated LRU element besides key and value
/// (`struct htab_elem` with its LRU node and hash).
const ELEMENT_OVERHEAD: u64 = 48;
/// Share of RAM the default sizing may commit: one twelfth.
const RAM_DIVISOR: u64 = 12;
/// The default never sizes for fewer connections than the object's own maps
/// already hold, so a small host is never made worse by resizing.
pub const MIN_DEFAULT_CONNECTIONS: u32 = 16_384;
/// Nor for more than a host can sensibly use from a single table.
pub const MAX_DEFAULT_CONNECTIONS: u32 = 2_097_152;
/// Sizes are rounded down to a multiple of this.
const GRANULE: u32 = 1024;

/// Share of a table's slots in use at which the agent warns.
pub const HIGH_WATER_PERCENT: u64 = 80;

/// The resolved entry count of every connection-state map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sizing {
    /// Concurrent connections the tables are sized for.
    pub connections: u32,
    pub fw_flows: u32,
    pub conntrack: u32,
    pub syn_flows: u32,
}

impl Sizing {
    /// `(map name, max_entries)` for every map this sizing covers.
    pub fn maps(&self) -> [(&'static str, u32); 3] {
        [
            ("FW_FLOWS", self.fw_flows),
            ("CONNTRACK", self.conntrack),
            ("SYN_FLOWS", self.syn_flows),
        ]
    }

    /// The sizing for `connections` concurrent connections.
    pub fn for_connections(connections: u32) -> Self {
        Self {
            connections,
            fw_flows: connections.saturating_mul(FW_ENTRIES_PER_CONNECTION),
            conntrack: connections.saturating_mul(CT_ENTRIES_PER_CONNECTION),
            syn_flows: connections
                .saturating_mul(SYN_ENTRIES_PER_CONNECTION)
                .max(GRANULE),
        }
    }

    /// Kernel memory these tables commit at load.
    pub fn committed_bytes(&self) -> u64 {
        let entry =
            |key: usize, value: usize| ELEMENT_OVERHEAD + round8(key as u64) + round8(value as u64);
        u64::from(self.fw_flows)
            * entry(
                size_of::<velstra_common::FirewallKey>(),
                size_of::<velstra_common::FirewallState>(),
            )
            + u64::from(self.conntrack)
                * entry(
                    size_of::<velstra_common::FlowKey>(),
                    size_of::<velstra_common::FlowState>(),
                )
            + u64::from(self.syn_flows)
                * entry(
                    size_of::<velstra_common::FlowKey>(),
                    size_of::<velstra_common::SynFlow>(),
                )
    }
}

fn round8(bytes: u64) -> u64 {
    bytes.div_ceil(8) * 8
}

/// Resolve `[state]` against a host with `total_ram` bytes of memory.
pub fn resolve(state: &StateTables, total_ram: u64) -> Sizing {
    Sizing::for_connections(
        state
            .connections
            .unwrap_or_else(|| default_connections(total_ram)),
    )
}

/// The connection count a host with `total_ram` bytes gets by default.
pub fn default_connections(total_ram: u64) -> u32 {
    let per_connection = Sizing::for_connections(GRANULE).committed_bytes() / u64::from(GRANULE);
    let affordable = total_ram / RAM_DIVISOR / per_connection.max(1);
    let clamped = affordable.clamp(
        u64::from(MIN_DEFAULT_CONNECTIONS),
        u64::from(MAX_DEFAULT_CONNECTIONS),
    ) as u32;
    clamped / GRANULE * GRANULE
}

/// Total physical memory, or `None` if the kernel will not say.
pub fn host_memory() -> Option<u64> {
    // SAFETY: sysinfo writes only into the zeroed struct it is handed.
    let mut info: libc::sysinfo = unsafe { std::mem::zeroed() };
    if unsafe { libc::sysinfo(&mut info) } != 0 {
        return None;
    }
    // `totalram` is a C `unsigned long`, 32 bits on some targets.
    #[allow(clippy::useless_conversion)]
    let total = u64::from(info.totalram);
    total.checked_mul(u64::from(info.mem_unit.max(1)))
}

/// Whether `used` of `capacity` slots is at or past the high-water mark.
pub fn past_high_water(used: u64, capacity: u64) -> bool {
    capacity > 0 && used.saturating_mul(100) >= capacity.saturating_mul(HIGH_WATER_PERCENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    #[test]
    fn a_four_gigabyte_host_holds_a_quarter_million_connections_by_default() {
        // DP-06: the object's 65,536-entry maps capped every box at ~16k.
        let sizing = resolve(&StateTables::default(), 4 * GIB);
        assert!(sizing.connections >= 256 * 1024, "{sizing:?}");
        assert!(sizing.fw_flows >= 4 * 65_536 * 4, "{sizing:?}");
        // And it commits no more than the share of RAM it promises.
        assert!(
            sizing.committed_bytes() <= 4 * GIB / RAM_DIVISOR,
            "{sizing:?}"
        );
    }

    #[test]
    fn the_default_never_shrinks_below_the_objects_own_tables_nor_grows_without_bound() {
        let tiny = resolve(&StateTables::default(), 64 << 20);
        assert_eq!(tiny.connections, MIN_DEFAULT_CONNECTIONS);
        assert!(tiny.fw_flows >= 65_536);
        let huge = resolve(&StateTables::default(), 1 << 50);
        assert_eq!(huge.connections, MAX_DEFAULT_CONNECTIONS);
        for ram in [GIB, 3 * GIB, 7 * GIB + 12345] {
            assert_eq!(
                resolve(&StateTables::default(), ram).connections % GRANULE,
                0
            );
        }
    }

    #[test]
    fn an_explicit_size_wins_over_the_memory_derived_one() {
        let state = StateTables {
            connections: Some(100_000),
            persist: false,
        };
        let sizing = resolve(&state, 64 * GIB);
        assert_eq!(sizing.connections, 100_000);
        assert_eq!(sizing.fw_flows, 600_000);
        assert_eq!(sizing.conntrack, 200_000);
        assert_eq!(sizing.syn_flows, 200_000);
    }

    #[test]
    fn every_connection_can_be_a_proxied_one() {
        // A splice lives as long as its connection: sizing it for half of
        // them let the LRU evict live idle ones once the rest came and went.
        // And the same again as headroom for ended connections the sweep
        // has not yet removed (see SYN_ENTRIES_PER_CONNECTION).
        for connections in [1024, 50_000, MAX_DEFAULT_CONNECTIONS] {
            assert!(Sizing::for_connections(connections).syn_flows >= 2 * connections);
        }
    }

    #[test]
    fn every_masqueraded_or_forwarded_connection_fits() {
        // Masquerade: 4 FW + 1 CT. Port-forward on main: 6 FW + 2 CT.
        let sizing = Sizing::for_connections(50_000);
        assert!(sizing.fw_flows >= 50_000 * 6 && sizing.conntrack >= 50_000 * 2);
    }

    #[test]
    fn the_high_water_mark_is_exact_and_safe_on_an_empty_table() {
        assert!(!past_high_water(79, 100));
        assert!(past_high_water(80, 100));
        assert!(!past_high_water(0, 0));
        assert!(past_high_water(u64::MAX, u64::MAX));
    }

    #[test]
    fn host_memory_is_reported() {
        assert!(host_memory().is_some_and(|bytes| bytes > 0));
    }
}
