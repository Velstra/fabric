//! NPTv6 — stateless IPv6-to-IPv6 network prefix translation (RFC 6296).
//!
//! NPTv6 maps an **internal** prefix onto an **external** (e.g. provider-
//! delegated) prefix 1:1 and algorithmically, with no per-flow state. Its defining
//! property is **checksum neutrality**: the translation overwrites the prefix and
//! then folds a one's-complement *adjustment* into a later 16-bit word so that the
//! one's-complement sum over the whole address is unchanged. Because the TCP/UDP/
//! ICMPv6 checksum covers the address (via the pseudo-header) as a one's-complement
//! sum, keeping that sum invariant means the L4 checksum stays valid **without any
//! recomputation** — and IPv6 has no header checksum of its own. So the data plane
//! only rewrites address bytes; no checksum fix-up is needed.
//!
//! All the arithmetic lives here as pure, unit-tested functions; the eBPF program
//! only copies the resulting bytes into the packet.
//!
//! ## Scope (v1)
//!
//! Prefix lengths are a whole number of 16-bit words (`/16`, `/32`, `/48`, `/64`),
//! which covers the common delegated-prefix cases. The adjustment is folded into
//! the first host word (index `prefix_words`); the RFC's `0xffff`-skip corner case
//! (an address whose adjustment word is already `0xffff`) is not handled and is
//! astronomically rare in practice.

/// One's-complement add of two 16-bit words (RFC 1071 end-around carry).
#[inline]
pub const fn oc_add(a: u16, b: u16) -> u16 {
    let s = a as u32 + b as u32;
    ((s & 0xffff) + (s >> 16)) as u16
}

/// One's-complement sum of the first `n` big-endian 16-bit words of `addr`.
#[inline]
const fn prefix_sum(addr: &[u8; 16], n: usize) -> u16 {
    let mut sum = 0u16;
    let mut i = 0;
    while i < n {
        let w = u16::from_be_bytes([addr[2 * i], addr[2 * i + 1]]);
        sum = oc_add(sum, w);
        i += 1;
    }
    sum
}

/// The precomputed NPTv6 rule for one boundary interface, ready for the data plane.
///
/// The same rule serves both directions: outbound (internal → external) source
/// translation on egress, and inbound (external → internal) destination
/// translation on ingress. `delta_out` is the one's-complement value added to the
/// adjustment word when writing the external prefix; the inbound path adds its
/// one's-complement (`!delta_out`), i.e. subtracts it.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Npt66 {
    /// Internal prefix bytes (only the first `prefix_words` words are used).
    pub internal: [u8; 16],
    /// External prefix bytes (only the first `prefix_words` words are used).
    pub external: [u8; 16],
    /// One's-complement adjustment folded into the host word on an internal →
    /// external rewrite (its complement is used for the reverse).
    pub delta_out: u16,
    /// Number of leading 16-bit words that make up the prefix (`prefix_len / 16`).
    pub prefix_words: u8,
    /// Explicit padding, always zero.
    pub _pad: u8,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Npt66 {}

impl Npt66 {
    /// Build a rule from the two prefixes (given as full 16-byte addresses, of
    /// which only `prefix_words` words matter) and the prefix word count. Computes
    /// the checksum-neutral `delta_out = Σ(internal) ⊖ Σ(external)`.
    #[inline]
    pub fn new(internal: [u8; 16], external: [u8; 16], prefix_words: u8) -> Self {
        let n = prefix_words as usize;
        let int_sum = prefix_sum(&internal, n);
        let ext_sum = prefix_sum(&external, n);
        // delta_out = int_sum - ext_sum  (one's complement): add int_sum and the
        // complement of ext_sum. Adding this to the host word compensates for the
        // sum change caused by swapping the prefix, so the total sum is invariant.
        let delta_out = oc_add(int_sum, !ext_sum);
        Self {
            internal,
            external,
            delta_out,
            prefix_words,
            _pad: 0,
        }
    }
}

/// Translate `addr` by overwriting its prefix with `new_prefix` (first
/// `prefix_words` words) and folding `delta` into the first host word. Pure and
/// checksum-neutral. The caller passes the direction-appropriate `new_prefix`/
/// `delta`.
#[inline]
pub fn npt66_rewrite(
    mut addr: [u8; 16],
    new_prefix: &[u8; 16],
    prefix_words: u8,
    delta: u16,
) -> [u8; 16] {
    let n = prefix_words as usize;
    // Overwrite the prefix words.
    let mut i = 0;
    while i < n && i < 8 {
        addr[2 * i] = new_prefix[2 * i];
        addr[2 * i + 1] = new_prefix[2 * i + 1];
        i += 1;
    }
    // Fold the adjustment into the first host word (index `prefix_words`). Per
    // RFC 6296 §3.7, a computed `0x0000` is stored as `0xffff` (the two are equal
    // in one's-complement, but the field must never hold `0x0000`) — this keeps the
    // forward/reverse mapping consistent.
    if n < 8 {
        let w = u16::from_be_bytes([addr[2 * n], addr[2 * n + 1]]);
        let adjusted = match oc_add(w, delta) {
            0x0000 => 0xffff,
            other => other,
        };
        let b = adjusted.to_be_bytes();
        addr[2 * n] = b[0];
        addr[2 * n + 1] = b[1];
    }
    addr
}

impl Npt66 {
    /// Whether `addr`'s prefix matches this rule's internal prefix (outbound).
    #[inline]
    pub fn matches_internal(&self, addr: &[u8; 16]) -> bool {
        prefix_eq(addr, &self.internal, self.prefix_words)
    }

    /// Whether `addr`'s prefix matches this rule's external prefix (inbound).
    #[inline]
    pub fn matches_external(&self, addr: &[u8; 16]) -> bool {
        prefix_eq(addr, &self.external, self.prefix_words)
    }

    /// Outbound: rewrite an internal source to the external prefix.
    #[inline]
    pub fn translate_out(&self, addr: [u8; 16]) -> [u8; 16] {
        npt66_rewrite(addr, &self.external, self.prefix_words, self.delta_out)
    }

    /// Inbound: rewrite an external destination back to the internal prefix. The
    /// reverse adjustment is the one's complement of `delta_out`.
    #[inline]
    pub fn translate_in(&self, addr: [u8; 16]) -> [u8; 16] {
        npt66_rewrite(addr, &self.internal, self.prefix_words, !self.delta_out)
    }
}

/// Whether the first `n` 16-bit words of `a` and `b` are equal.
#[inline]
fn prefix_eq(a: &[u8; 16], b: &[u8; 16], prefix_words: u8) -> bool {
    let n = (prefix_words as usize).min(8) * 2;
    let mut i = 0;
    while i < n {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One's-complement sum over all eight 16-bit words of an address — the
    /// quantity the L4 pseudo-header checksum depends on. NPTv6 must preserve it.
    fn full_sum(addr: &[u8; 16]) -> u16 {
        let mut sum = 0u16;
        for i in 0..8 {
            sum = oc_add(sum, u16::from_be_bytes([addr[2 * i], addr[2 * i + 1]]));
        }
        sum
    }

    fn v6(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }

    #[test]
    fn translation_is_checksum_neutral() {
        // A /48 ULA → provider prefix mapping (RFC 6296 style).
        let rule = Npt66::new(v6("fd01:203:405::"), v6("2001:db8:1::"), 3);
        let internal = v6("fd01:203:405:6:7:8:9:a");
        let external = rule.translate_out(internal);
        // The prefix was swapped...
        assert_eq!(&external[..6], &v6("2001:db8:1::")[..6]);
        // ...and the whole-address one's-complement sum is unchanged (so the L4
        // checksum stays valid with no recomputation).
        assert_eq!(full_sum(&internal), full_sum(&external));
    }

    #[test]
    fn out_then_in_round_trips() {
        let rule = Npt66::new(v6("fd00:dead:beef::"), v6("2001:db8:abcd::"), 3);
        // Hosts whose adjustment (subnet) word is non-zero round-trip exactly. Per
        // RFC 6296 the adjustment word never holds 0x0000 (a subnet-0 word maps to
        // the 0xffff equivalence), so realistic subnets are lossless.
        for host in [
            "fd00:dead:beef:1:2:3:4:5",
            "fd00:dead:beef:ffff:0:0:0:1",
            "fd00:dead:beef:abcd:1122:3344:5566:7788",
        ] {
            let internal = v6(host);
            let external = rule.translate_out(internal);
            assert!(rule.matches_external(&external));
            assert_eq!(rule.translate_in(external), internal, "round-trip {host}");
            assert_eq!(full_sum(&internal), full_sum(&external));
        }
    }

    #[test]
    fn a_64_prefix_folds_into_word_four() {
        let rule = Npt66::new(v6("fd12:3456:789a:bcde::"), v6("2001:db8:0:1::"), 4);
        let internal = v6("fd12:3456:789a:bcde:1:2:3:4");
        let external = rule.translate_out(internal);
        assert_eq!(&external[..8], &v6("2001:db8:0:1::")[..8]);
        assert_eq!(full_sum(&internal), full_sum(&external));
        assert_eq!(rule.translate_in(external), internal);
    }

    #[test]
    fn matches_only_its_own_prefix() {
        let rule = Npt66::new(v6("fd01:203:405::"), v6("2001:db8:1::"), 3);
        assert!(rule.matches_internal(&v6("fd01:203:405:99::1")));
        assert!(!rule.matches_internal(&v6("fd01:203:406::1")));
        assert!(rule.matches_external(&v6("2001:db8:1:5::9")));
        assert!(!rule.matches_external(&v6("2001:db8:2::9")));
    }

    #[test]
    fn npt66_is_pod_sized() {
        // internal[16] + external[16] + delta_out(2) + prefix_words(1) + pad(1).
        assert_eq!(core::mem::size_of::<Npt66>(), 36);
    }
}
