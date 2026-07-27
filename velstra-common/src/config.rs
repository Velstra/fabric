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
    /// **Loose** source validation (uRPF, RFC 3704 §3.2): a packet is dropped
    /// unless *some* route back to its source address exists. Catches addresses
    /// that could never answer — bogons, unrouted space — while tolerating the
    /// asymmetric paths that a multi-homed edge produces.
    pub const RPF_LOOSE: u32 = 1 << 3;
    /// **Strict** source validation (uRPF, RFC 3704 §2): the route back to the
    /// source must leave by the interface the packet arrived on. This is the
    /// BCP 38 rule — it stops a neighbour on one link from claiming an address
    /// that belongs to another — but it drops legitimate traffic wherever
    /// routing is asymmetric, so it is opt-in per policy.
    ///
    /// Set together with [`Self::RPF_LOOSE`], strict wins; the data plane reads
    /// this bit first.
    pub const RPF_STRICT: u32 = 1 << 4;

    /// Mask of all defined flags; used to reject unknown bits.
    pub const ALL: u32 =
        Self::DROP_ICMP | Self::LOG | Self::STATEFUL | Self::RPF_LOOSE | Self::RPF_STRICT;
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

    /// How this policy validates a packet's source address.
    #[inline]
    pub const fn source_validation(&self) -> SourceValidation {
        // Strict is checked first so a config carrying both bits enforces the
        // stronger rule rather than silently relaxing to loose.
        if self.has_flag(ConfigFlags::RPF_STRICT) {
            SourceValidation::Strict
        } else if self.has_flag(ConfigFlags::RPF_LOOSE) {
            SourceValidation::Loose
        } else {
            SourceValidation::Disabled
        }
    }
}

/// Source-address validation mode (uRPF, RFC 3704) for one policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceValidation {
    /// Accept any source address. The default — uRPF drops traffic, and which
    /// traffic depends on the routing table, so it is never turned on for you.
    Disabled,
    /// The source must be routable somewhere.
    Loose,
    /// The route back to the source must leave by the ingress interface.
    Strict,
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
