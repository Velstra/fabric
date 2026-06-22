//! The global firewall configuration, stored as the single entry of the
//! `CONFIG` BPF array map.

use crate::policy::Action;

/// Boolean toggles packed into [`GlobalConfig::flags`].
///
/// Implemented as associated constants rather than a `bitflags` dependency to
/// keep this crate dependency-free and `const`-friendly in eBPF.
pub struct ConfigFlags;

impl ConfigFlags {
    /// Drop all ICMP traffic (classic ping-flood / smurf mitigation).
    pub const DROP_ICMP: u32 = 1 << 0;
    /// Emit an `aya-log` line for every notable action — drops, forwards and
    /// NAT rewrites. Invaluable when watching what the data plane does, but
    /// costly on the hot path: leave it off in production.
    pub const LOG: u32 = 1 << 1;
    /// Track connections (TCP/UDP) and allow established flows in either
    /// direction, so replies are permitted even under a deny-by-default policy —
    /// a stateful gateway firewall. The blocklist still wins.
    pub const STATEFUL: u32 = 1 << 2;

    /// Mask of all defined flags; used to reject unknown bits.
    pub const ALL: u32 = Self::DROP_ICMP | Self::LOG | Self::STATEFUL;
}

/// Global firewall configuration shared kernel <-> user space.
///
/// `#[repr(C)]` pins the field layout so both sides agree byte-for-byte. The
/// type is deliberately POD (plain old data): two `u32`s, no padding, trivially
/// copyable into and out of a BPF map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalConfig {
    /// Default [`Action`] (encoded via [`Action::as_u32`]) when no rule matches.
    pub default_action: u32,
    /// Bitmask of [`ConfigFlags`].
    pub flags: u32,
}

impl GlobalConfig {
    /// A safe fallback used by the data plane if the `CONFIG` map is somehow
    /// empty: pass everything, no special handling. Fail-open by design.
    pub const DEFAULT: Self = Self {
        default_action: Action::Pass.as_u32(),
        flags: 0,
    };

    /// Construct a config from a typed default action and a flag bitmask.
    #[inline]
    pub const fn new(default_action: Action, flags: u32) -> Self {
        Self {
            default_action: default_action.as_u32(),
            flags,
        }
    }

    /// The decoded default [`Action`].
    #[inline]
    pub const fn default_action(&self) -> Action {
        Action::from_u32(self.default_action)
    }

    /// Whether a given [`ConfigFlags`] bit (or mask) is set.
    #[inline]
    pub const fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// SAFETY: `GlobalConfig` is `#[repr(C)]` and contains only `u32`s, so it is
// plain old data with no padding, invalid bit patterns, or pointers — exactly
// the contract `aya::Pod` requires for copying to/from BPF maps.
#[cfg(feature = "user")]
unsafe impl aya::Pod for GlobalConfig {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_fail_open() {
        let cfg = GlobalConfig::DEFAULT;
        assert_eq!(cfg.default_action(), Action::Pass);
        assert!(!cfg.has_flag(ConfigFlags::DROP_ICMP));
        assert!(!cfg.has_flag(ConfigFlags::LOG));
    }

    #[test]
    fn flags_combine_and_query() {
        let cfg = GlobalConfig::new(Action::Drop, ConfigFlags::DROP_ICMP | ConfigFlags::LOG);
        assert_eq!(cfg.default_action(), Action::Drop);
        assert!(cfg.has_flag(ConfigFlags::DROP_ICMP));
        assert!(cfg.has_flag(ConfigFlags::LOG));
    }

    #[test]
    fn layout_is_two_u32() {
        assert_eq!(core::mem::size_of::<GlobalConfig>(), 8);
        assert_eq!(core::mem::align_of::<GlobalConfig>(), 4);
    }
}
