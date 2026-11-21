//! The `MASQUERADE` map's contract: egress ifindex → the address to translate to.
//!
//! An uplink that masquerades and has lost its address (a DHCP lease that
//! lapsed, a PPPoE session that dropped) used to lose its entry. Without one, a
//! packet leaving it is not masqueraded at all — it falls through to the plain
//! egress policy, which passes by default, and a LAN host's private source
//! address goes out onto the provider's wire whenever a route out of the uplink
//! survives the lease. So the entry stays, holding [`UNADDRESSED`], and the data
//! plane reads that as "nothing may leave here but the box asking for an address".

/// The value an uplink's `MASQUERADE` entry holds while it has no IPv4 address.
///
/// The unspecified address, because it is the one value that can never be a
/// real translation target — and because it is exactly the source a DHCP client
/// sends from before it has a lease, which is the traffic that must still leave.
pub const UNADDRESSED: [u8; 4] = [0; 4];

/// Candidates the standalone allocator may claim for one flow, and so the
/// only candidates discovery ever has to visit (PERF-02).
///
/// The window is a property of the flow alone, never of table history: a
/// flow's binding is always among its own first `NAPT_WINDOW` probes, so the
/// cost of finding it — or of proving there is none before claiming — is
/// bounded by this constant whatever the table held before. A whole-domain
/// scan per new flow in softirq is what collapsed masquerade to a few hundred
/// connections per second. With scattered probes, a full window at domain
/// occupancy `a` happens with probability about `a^128`: 1e-12 at 80 %,
/// 2e-6 at 90 %, so a refusal means the remote endpoint's domain is
/// effectively full, and it is counted (`egress_nat_no_candidate`).
pub const NAPT_WINDOW: u32 = 128;

/// Probe strides for a domain whose size is not a power of two: primes above
/// every possible domain size (a domain has at most 65535 ports), so each is
/// coprime with any domain and a flow's probes never repeat inside it.
/// Power-of-two domains (the default 32768 and usual CGNAT blocks) take any
/// odd stride instead, which gives every flow its own probe chain; sixteen
/// shared chains measurably cluster (0.33 % instead of 0.14 % refused at
/// 95 % fill, see `refusal_rate_by_domain_fill`).
const NAPT_STRIDES: [u32; 16] = [
    0x22e1bd, 0x23e783, 0x10a155, 0x167629, 0x3cd553, 0x5350cd, 0x7e85df, 0x53f2f1, 0x67e485,
    0x28949b, 0x3e460b, 0x53c20f, 0x11f72b, 0xdf0037, 0xe38cf7, 0xce61df,
];

/// One source's finite port domain (its CGNAT block, or 32768..=65535) and a
/// flow's position in it. `candidate` walks it cyclically from the seed's
/// offset (the replicated allocator's window, unchanged for mixed-version
/// peers); `probe` is the standalone allocator's scattered window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NaptDomain {
    pub first: u32,
    pub count: u32,
    pub offset: u32,
    /// Distance between consecutive standalone probes, already reduced
    /// modulo `count`; coprime with `count`.
    pub stride: u32,
}

impl NaptDomain {
    #[inline(always)]
    pub fn new(src: [u8; 4], seed: u32, layout: &crate::CgnatLayout) -> Self {
        let (first, last) = layout.range_of(src).unwrap_or((32768, 65535));
        if first == 0 || last < first {
            return Self {
                first: 0,
                count: 0,
                offset: 0,
                stride: 0,
            };
        }
        let count = last as u32 - first as u32 + 1;
        // The offset uses the seed's low bits (at most 15 of them for a
        // power-of-two domain); the stride the bits above, so the two are
        // independent.
        let stride = if count & (count - 1) == 0 {
            ((seed >> 15) % count) | 1
        } else {
            NAPT_STRIDES[(seed >> 28) as usize & (NAPT_STRIDES.len() - 1)] % count
        };
        Self {
            first: first as u32,
            count,
            offset: seed % count,
            stride,
        }
    }

    #[inline(always)]
    pub fn candidate(&self, index: u32) -> u16 {
        // Keep division-by-zero panic paths out of the kernel object, even
        // for a corrupted/disabled domain. Such a domain has no candidate.
        if self.count == 0 || index >= self.count {
            return 0;
        }
        (self.first + (self.offset + index) % self.count) as u16
    }

    /// How many standalone probes this domain has: the whole domain when it
    /// is no larger than the window, so a small CGNAT block stays complete.
    #[inline(always)]
    pub fn window(&self) -> u32 {
        if self.count < NAPT_WINDOW {
            self.count
        } else {
            NAPT_WINDOW
        }
    }

    /// Standalone probe `index` (< [`Self::window`]), or 0 outside it.
    /// Probe 0 is `candidate(0)` — the legacy allocator's first port — so a
    /// binding an older image made there is still this flow's own. The rest
    /// step by the flow's stride; being coprime with the domain, the first
    /// `window()` probes are all distinct.
    #[inline(always)]
    pub fn probe(&self, index: u32) -> u16 {
        if self.count == 0 || index >= self.window() {
            return 0;
        }
        let step = (index as u64 * self.stride as u64) % self.count as u64;
        (self.first + ((self.offset as u64 + step) % self.count as u64) as u32) as u16
    }
}

#[cfg(test)]
mod window_tests {
    use super::*;

    fn layout(base: u16, block: u16) -> crate::CgnatLayout {
        crate::CgnatLayout::new(base, block)
    }

    fn domains() -> impl Iterator<Item = NaptDomain> {
        let layouts = [
            crate::CgnatLayout::default(),
            layout(32768, 512),
            layout(1024, 1000),
            layout(40000, 97),
            layout(2000, 128),
            layout(2000, 129),
            layout(60000, 3),
        ];
        layouts.into_iter().flat_map(|layout| {
            (0..64u32).map(move |i| {
                let seed = napt_seed(
                    [10, 0, (i >> 3) as u8, i as u8],
                    [192, 0, 2, 1],
                    40000 + i as u16,
                    443,
                ) ^ (i << 28);
                NaptDomain::new([10, 0, 0, i as u8], seed, &layout)
            })
        })
    }

    #[test]
    fn window_probes_are_distinct_and_inside_the_domain() {
        for domain in domains() {
            assert!(domain.count > 0, "{domain:?}");
            let mut seen = std::collections::BTreeSet::new();
            for index in 0..domain.window() {
                let port = domain.probe(index) as u32;
                assert!(
                    port >= domain.first && port < domain.first + domain.count,
                    "{domain:?} {index}"
                );
                assert!(
                    seen.insert(port),
                    "probe {index} repeats a port in {domain:?}"
                );
            }
            assert_eq!(domain.probe(domain.window()), 0, "{domain:?}");
        }
    }

    #[test]
    fn a_domain_no_larger_than_the_window_is_probed_completely() {
        for domain in domains().filter(|d| d.count <= NAPT_WINDOW) {
            assert_eq!(domain.window(), domain.count);
            let ports: std::collections::BTreeSet<u32> = (0..domain.window())
                .map(|i| domain.probe(i) as u32)
                .collect();
            assert_eq!(ports, (domain.first..domain.first + domain.count).collect());
        }
    }

    #[test]
    fn the_first_probe_is_the_legacy_first_candidate() {
        for domain in domains() {
            assert_eq!(domain.probe(0), domain.candidate(0));
        }
        let seed = napt_seed([10, 0, 0, 9], [198, 51, 100, 7], 51515, 80);
        let domain = NaptDomain::new([10, 0, 0, 9], seed, &crate::CgnatLayout::default());
        assert_eq!(domain.probe(0), napt_port(seed, 0));
    }

    /// The window's refusal rate, measured: one remote endpoint's default
    /// domain filled to a fraction by the allocator itself (so its own
    /// clustering counts), then fresh flows that would each need a port.
    /// Expected about `fill^128`: none at 80 % and 90 %, ~0.14 % at 95 %,
    /// ~28 % at 99 %. This is the capacity statement for flows to ONE remote
    /// ip:port from one public address; different endpoints never compete.
    #[test]
    fn refusal_rate_by_domain_fill() {
        let layout = crate::CgnatLayout::default();
        let flow = |n: u32| {
            let src = [10, (n >> 16) as u8, (n >> 8) as u8, n as u8];
            let sport = 1024 + (n % 64000) as u16;
            (src, napt_seed(src, [203, 0, 113, 5], sport, 443))
        };
        let mut occupied = std::collections::HashSet::new();
        let mut next = 0u32;
        let trials = 20_000u32;
        let mut measured = Vec::new();
        for (fill, ceiling) in [(0.80, 0.0), (0.90, 0.0), (0.95, 0.0025), (0.99, 0.32)] {
            while (occupied.len() as f64) < 32768.0 * fill {
                let (src, seed) = flow(next);
                next += 1;
                let domain = NaptDomain::new(src, seed, &layout);
                if let Some(port) = (0..domain.window())
                    .map(|i| domain.probe(i))
                    .find(|port| !occupied.contains(port))
                {
                    occupied.insert(port);
                }
            }
            let refused = (0..trials)
                .filter(|t| {
                    let (src, seed) = flow(1_000_000 + t);
                    let domain = NaptDomain::new(src, seed, &layout);
                    (0..domain.window()).all(|i| occupied.contains(&domain.probe(i)))
                })
                .count();
            let rate = refused as f64 / trials as f64;
            measured.push((fill, rate));
            assert!(
                rate <= ceiling,
                "fill {fill}: refusal {rate} above {ceiling}"
            );
        }
        // 99 % fill refuses often enough to be measured, and less often than
        // a uniformly random window would allow to be off by much.
        let (_, at_99) = measured[3];
        assert!(at_99 > 0.15, "99 % refusal implausibly low: {measured:?}");
    }

    /// Model of the allocator over one remote endpoint's domain: claim the
    /// first vacant probe, discover by scanning the window. Every live
    /// binding is found by its own flow, no two flows share a port, and at
    /// 80 % occupancy no flow is refused.
    #[test]
    fn model_allocation_finds_every_binding_and_never_shares_a_port() {
        let layout = crate::CgnatLayout::default();
        let mut owner: std::collections::HashMap<u16, (u32, u16)> =
            std::collections::HashMap::new();
        let mut bindings = Vec::new();
        let target = (32768.0 * 0.8) as u32;
        let mut refused = 0;
        for flow in 0..target {
            let src = [10, 1, (flow >> 8) as u8, flow as u8];
            let sport = 1024 + (flow % 60000) as u16;
            let seed = napt_seed(src, [203, 0, 113, 5], sport, 443);
            let domain = NaptDomain::new(src, seed, &layout);
            let port = (0..domain.window())
                .map(|i| domain.probe(i))
                .find(|port| !owner.contains_key(port));
            match port {
                Some(port) => {
                    owner.insert(port, (flow, sport));
                    bindings.push((flow, sport, seed, src, port));
                }
                None => refused += 1,
            }
        }
        assert_eq!(refused, 0, "a flow was refused at 80 % occupancy");
        for (flow, sport, seed, src, port) in bindings {
            let domain = NaptDomain::new(src, seed, &layout);
            let found = (0..domain.window())
                .map(|i| domain.probe(i))
                .find(|p| owner.get(p) == Some(&(flow, sport)));
            assert_eq!(found, Some(port));
        }
    }
}

/// Whether an IPv4 packet with source `src` must be dropped leaving an uplink
/// whose `MASQUERADE` entry is `nat_ip`.
///
/// Only an unaddressed masquerade uplink drops, and it drops everything except
/// what is itself unaddressed: a forwarded packet would leave with an internal
/// source, and the box's own packet — from some other interface's address —
/// would leave un-translated the same way. What remains is the DHCP client's
/// DISCOVER/REQUEST, sent from `0.0.0.0`, which is how the uplink gets an
/// address back.
#[inline(always)]
pub fn unaddressed_uplink_drops(nat_ip: Option<[u8; 4]>, src: [u8; 4]) -> bool {
    matches!(nat_ip, Some(ip) if ip == UNADDRESSED) && src != UNADDRESSED
}

/// Stable per-flow seed for bounded masquerade port allocation.
///
/// Fold the complete tuple into the low bits BEFORE reducing it to the port
/// range. Multiplication alone cannot do that: source ports in the upper16bits
/// would otherwise disappear modulo32768, making every such client compete
/// for the same eight ports. Explicit network order is architecture independent.
/// This is distribution, not a cryptographic secret or a SYN-cookie primitive.
#[inline(always)]
pub fn napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    let mut hash = u32::from_be_bytes(src)
        ^ u32::from_be_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ dport as u32;
    // Fixed-cost 32-bit avalanche; no allocation, loop, helper or map lookup.
    hash ^= hash >> 16;
    hash = hash.wrapping_mul(0x7feb_352d);
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(0x846c_a68b);
    hash ^ (hash >> 16)
}

/// Allocator used by deployed images before the avalanche correction.
///
/// Only search for an EXISTING replicated binding with this seed. Never
/// allocate a new flow from it: its poor distribution is the bug corrected by
/// [`napt_seed`]. Keep this compatibility search while rolling upgrades from
/// that allocator are supported. A chosen public port is connection state, not
/// something an upgraded peer may replace with its own preferred candidate.
#[inline(always)]
pub fn legacy_napt_seed(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> u32 {
    (u32::from_le_bytes(src)
        ^ u32::from_le_bytes(dst).rotate_left(16)
        ^ ((sport as u32) << 16)
        ^ dport as u32)
        .wrapping_mul(2654435761)
}

/// An allocation belongs to this inside endpoint only when it is a genuine
/// single-ended masquerade entry, not a coincident DNAT/hairpin target.
#[inline(always)]
pub fn napt_binding_matches(state: &crate::FlowState, origin: [u8; 4], port: u16) -> bool {
    state.flags == crate::FlowState::ORIGIN
        && state.nat_ip == origin
        && state.nat_port == port
        && state.nat2_ip == [0; 4]
        && state.nat2_port == 0
}

/// The observed owner of one reverse NAPT key. An expired foreign binding is
/// still foreign: expiry is not an atomic compare-and-replace permission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NaptSlot {
    Owned,
    Vacant,
    Foreign,
}

#[inline(always)]
pub fn napt_slot(state: Option<&crate::FlowState>, origin: [u8; 4], port: u16) -> NaptSlot {
    match state {
        Some(state) if napt_binding_matches(state, origin, port) => NaptSlot::Owned,
        Some(_) => NaptSlot::Foreign,
        None => NaptSlot::Vacant,
    }
}

/// Result of reserving a single candidate, not proof of global map capacity.
/// LRU insertion can still evict an unrelated key; that is a separate limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NaptClaim {
    Existing,
    Inserted,
    Busy,
    Failed,
}

/// Resolve a vacancy/insert race without replacing another endpoint's state.
/// `insert_noexist` MUST use BPF_NOEXIST, never BPF_ANY or delete-then-insert.
/// Only EEXIST is a normal race: reread actual ownership, reusing the same flow
/// or letting the caller try its next candidate. Other errors fail closed.
#[inline(always)]
pub fn napt_claim(
    observed: NaptSlot,
    insert_noexist: impl FnOnce() -> Result<(), i32>,
    owned_after_race: impl FnOnce() -> bool,
) -> NaptClaim {
    match observed {
        NaptSlot::Owned => NaptClaim::Existing,
        NaptSlot::Foreign => NaptClaim::Busy,
        NaptSlot::Vacant => match insert_noexist() {
            Ok(()) => NaptClaim::Inserted,
            Err(-17) if owned_after_race() => NaptClaim::Existing,
            Err(-17) => NaptClaim::Busy,
            Err(_) => NaptClaim::Failed,
        },
    }
}

/// Bounded existing-binding search shared with the real egress dataplane.
/// A free/foreign/expired earlier slot is NOT a reason to stop looking for the
/// allocation this connection already owns. Zero means no existing allocation.
#[inline(always)]
pub fn napt_find_existing(
    src: [u8; 4],
    seed: u32,
    layout: &crate::CgnatLayout,
    mut belongs_to_flow: impl FnMut(u16) -> bool,
) -> u16 {
    for probe in 0..8 {
        let candidate = layout
            .candidate(src, seed, probe)
            .unwrap_or_else(|| napt_port(seed, probe));
        if belongs_to_flow(candidate) {
            return candidate;
        }
    }
    0
}

/// Candidate `i` in the inclusive ephemeral range32768..65535, never port0.
/// The dataplane retains its separate small, verifier-bounded probe count.
#[inline(always)]
pub fn napt_port(seed: u32, i: u16) -> u16 {
    32768 + (seed.wrapping_add(i as u32) % 32768) as u16
}

/// Whether a NAT entry may be written over what a key already holds (DP-24).
/// A destination-NAT or load-balancer reverse entry is published with
/// `BPF_NOEXIST`; when that finds an entry, only an expired one or one that
/// already carries exactly this rewrite (the same flow, re-admitted or claimed
/// concurrently by another CPU) may be replaced. A live entry with a different
/// rewrite belongs to another flow and is never overwritten.
#[inline(always)]
pub fn nat_entry_replaceable(
    existing: &crate::FlowState,
    candidate: &crate::FlowState,
    proto: u8,
    now: u64,
    timeouts: crate::ConntrackTimeouts,
) -> bool {
    existing.expired(proto, now, timeouts)
        || (existing.flags == candidate.flags
            && existing.nat_ip == candidate.nat_ip
            && existing.nat_port == candidate.nat_port
            && existing.nat2_ip == candidate.nat2_ip
            && existing.nat2_port == candidate.nat2_port)
}

/// What the egress masquerade path may do after the port probe.
///
/// A translated packet and its reverse conntrack entry are one publication.
/// Installing either without the other leaves a private source on the wire or
/// a public port that DNATs an unsolicited packet to the inside host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MasqueradeCommit {
    /// Reverse state exists and this packet was rewritten to the public tuple.
    Translated,
    /// Do not emit the packet. Leave any pre-existing binding in place.
    Drop,
    /// Do not emit the packet, and delete the reverse binding just created.
    DropAndForget,
}

/// `existing` is a live binding for this inside endpoint. `inserted` is a new
/// reverse entry created for this packet. `rewritten` is true only when the
/// source translation of this packet succeeded.
#[inline(always)]
pub fn masquerade_commit(existing: bool, inserted: bool, rewritten: bool) -> MasqueradeCommit {
    if existing {
        return if rewritten {
            MasqueradeCommit::Translated
        } else {
            MasqueradeCommit::Drop
        };
    }
    if !inserted || !rewritten {
        return if inserted {
            MasqueradeCommit::DropAndForget
        } else {
            MasqueradeCommit::Drop
        };
    }
    MasqueradeCommit::Translated
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn complete_domain_visits_every_ephemeral_port_once_even_at_seed_wrap() {
        for seed in [0, 1, 32767, u32::MAX - 3, u32::MAX] {
            let domain = NaptDomain::new([10, 0, 0, 1], seed, &crate::CgnatLayout::default());
            let visited: BTreeSet<_> = (0..domain.count).map(|i| domain.candidate(i)).collect();
            assert_eq!(visited, (32768..=65535).collect());
        }
    }

    #[test]
    fn complete_domain_covers_exact_cgnat_block_without_crossing_subscriber_boundary() {
        for size in [1, 7, 9, 65, 511, 512, 65535] {
            let layout = crate::CgnatLayout::new(1, size);
            for src in [[10, 0, 0, 1], [10, 0, 0, 2]] {
                let (first, last) = layout.range_of(src).unwrap();
                for seed in [0, 1, u32::MAX - 3, u32::MAX] {
                    let domain = NaptDomain::new(src, seed, &layout);
                    let visited: BTreeSet<_> =
                        (0..domain.count).map(|i| domain.candidate(i)).collect();
                    assert_eq!(visited, (first..=last).collect());
                    assert_eq!(domain.count, size as u32);
                }
            }
        }
    }

    #[test]
    fn complete_domain_is_not_an_eight_or_sixty_four_candidate_window() {
        let domain = NaptDomain::new([10, 0, 0, 1], 0, &crate::CgnatLayout::default());
        let mut occupied = BTreeSet::new();
        for _ in 0..129 {
            let port = (0..domain.count)
                .map(|i| domain.candidate(i))
                .find(|port| !occupied.contains(port))
                .unwrap();
            assert!(occupied.insert(port));
        }
        assert_eq!(occupied.len(), 129);
        assert_eq!(occupied.last(), Some(&32896));
    }

    #[test]
    fn complete_domain_rejects_invalid_or_exhausted_indexes_without_panicking() {
        let empty = NaptDomain {
            first: 0,
            count: 0,
            offset: 0,
            stride: 0,
        };
        assert_eq!(empty.candidate(0), 0);
        assert_eq!(empty.window(), 0);
        assert_eq!(empty.probe(0), 0);
        let domain = NaptDomain::new([10, 0, 0, 1], 0, &crate::CgnatLayout::default());
        assert_eq!(domain.candidate(domain.count), 0);
        assert_eq!(domain.candidate(u32::MAX), 0);
    }

    #[test]
    fn vacant_claim_never_overwrites_a_foreign_insertion_racing_the_lookup() {
        use std::cell::RefCell;
        let origin = [192, 0, 2, 7];
        let foreign = crate::FlowState::masquerade([192, 0, 2, 8], 43001);
        let state = RefCell::new(None);
        let observed = napt_slot(state.borrow().as_ref(), origin, 43000);
        // Another CPU wins after the first lookup and before our NOEXIST.
        *state.borrow_mut() = Some(foreign);
        let result = napt_claim(
            observed,
            || {
                assert!(state.borrow().is_some());
                Err(-17)
            },
            || {
                matches!(
                    napt_slot(state.borrow().as_ref(), origin, 43000),
                    NaptSlot::Owned
                )
            },
        );
        assert_eq!(result, NaptClaim::Busy);
        assert!(napt_binding_matches(
            state.borrow().as_ref().unwrap(),
            [192, 0, 2, 8],
            43001
        ));
    }

    #[test]
    fn same_flow_racing_a_vacant_lookup_reuses_the_winning_binding() {
        let own = crate::FlowState::masquerade([192, 0, 2, 7], 43000);
        assert_eq!(
            napt_claim(
                NaptSlot::Vacant,
                || Err(-17),
                || napt_binding_matches(&own, [192, 0, 2, 7], 43000)
            ),
            NaptClaim::Existing
        );
        assert_eq!(
            napt_claim(NaptSlot::Vacant, || Ok(()), || panic!("no race")),
            NaptClaim::Inserted
        );
        assert_eq!(
            napt_claim(NaptSlot::Vacant, || Err(-17), || false),
            NaptClaim::Busy
        );
    }

    #[test]
    fn foreign_live_or_expired_slot_never_invokes_insert_or_delete() {
        for age in [0, u64::MAX] {
            let foreign = crate::FlowState {
                age_ns: age,
                ..crate::FlowState::masquerade([192, 0, 2, 8], 43001)
            };
            let observed = napt_slot(Some(&foreign), [192, 0, 2, 7], 43000);
            assert_eq!(observed, NaptSlot::Foreign);
            assert_eq!(
                napt_claim(
                    observed,
                    || panic!("must not overwrite/reclaim foreign"),
                    || panic!("no insertion attempted")
                ),
                NaptClaim::Busy
            );
        }
        let own = crate::FlowState::masquerade([192, 0, 2, 7], 43000);
        assert_eq!(
            napt_claim(
                napt_slot(Some(&own), [192, 0, 2, 7], 43000),
                || panic!("existing allocation"),
                || panic!("no race")
            ),
            NaptClaim::Existing
        );
    }

    #[test]
    fn claim_unknown_failure_cannot_become_success_or_an_ordinary_collision() {
        for error in [-1, -12, -22, 17, 0] {
            assert_eq!(
                napt_claim(NaptSlot::Vacant, || Err(error), || panic!("not EEXIST")),
                NaptClaim::Failed
            );
        }
    }

    #[test]
    fn all_expired_foreign_candidates_still_refuse_admission_without_safe_reclamation() {
        let seed = napt_seed([198, 18, 20, 50], [198, 18, 10, 254], 43000, 9000);
        let foreign = crate::FlowState {
            age_ns: u64::MAX,
            ..crate::FlowState::masquerade([192, 0, 2, 8], 43001)
        };
        let mut visited = Vec::new();
        let chosen = (0..8).find_map(|probe| {
            let port = napt_port(seed, probe);
            visited.push(port);
            let observed = napt_slot(Some(&foreign), [198, 18, 20, 50], 43000);
            match napt_claim(
                observed,
                || panic!("unsafe reclamation is not an allocation permission"),
                || panic!("foreign slot does not attempt publication"),
            ) {
                NaptClaim::Existing | NaptClaim::Inserted => Some(port),
                NaptClaim::Busy => None,
                NaptClaim::Failed => panic!("occupied slots do not attempt a failing syscall"),
            }
        });
        assert!(chosen.is_none());
        assert_eq!(visited.len(), 8);
        // This is an explicit availability restriction, not an expiry/GC fix.
        // A foreign timestamp cannot provide atomic compare/delete ownership.
        assert_eq!(foreign.age_ns, u64::MAX);
    }

    #[test]
    fn allocator_retries_the_next_existing_candidate_after_foreign_race() {
        let seed = napt_seed([198, 18, 20, 50], [198, 18, 10, 254], 43000, 9000);
        let mut visited = Vec::new();
        let chosen = (0..8).find_map(|probe| {
            let port = napt_port(seed, probe);
            visited.push(port);
            let claim = napt_claim(
                NaptSlot::Vacant,
                || if probe == 0 { Err(-17) } else { Ok(()) },
                || false,
            );
            match claim {
                NaptClaim::Inserted | NaptClaim::Existing => Some(port),
                NaptClaim::Busy => None,
                NaptClaim::Failed => panic!("unexpected failure"),
            }
        });
        assert_eq!(chosen, Some(napt_port(seed, 1)));
        assert_eq!(visited, vec![napt_port(seed, 0), napt_port(seed, 1)]);
    }

    #[test]
    fn mixed_version_native_reset_tuple_has_distinct_old_and_new_windows() {
        // Actual two-node rolling trace: old owner39759, upgraded owner57646,
        // same TCP sequence; the independent backend reset the new tuple.
        let src = [198, 18, 20, 50];
        let dst = [198, 18, 10, 253];
        let old = legacy_napt_seed(src, dst, 43251, 19251);
        let current = napt_seed(src, dst, 43251, 19251);
        assert_eq!(napt_port(old, 0), 39759);
        assert_eq!(napt_port(current, 0), 57646);
        assert!((0..8).all(|i| napt_port(current, i) != napt_port(old, 0)));
        assert!(napt_binding_matches(
            &crate::FlowState::masquerade(src, 43251),
            src,
            43251
        ));
        let layout = crate::CgnatLayout::default();
        let allocated = napt_port(old, 0);
        assert_eq!(
            napt_find_existing(src, current, &layout, |p| p == allocated),
            0
        );
        assert_eq!(
            napt_find_existing(src, old, &layout, |p| p == allocated),
            allocated
        );
    }

    #[test]
    fn free_earlier_collision_slots_cannot_renumber_an_established_flow() {
        let src = [198, 18, 20, 50];
        let seed = napt_seed(src, [198, 18, 10, 253], 43251, 19251);
        for layout in [
            crate::CgnatLayout::default(),
            crate::CgnatLayout::new(1024, 64),
        ] {
            for occupied_probe in 1..8 {
                let allocated = layout
                    .candidate(src, seed, occupied_probe)
                    .unwrap_or_else(|| napt_port(seed, occupied_probe));
                let mut observed = Vec::new();
                assert_eq!(
                    napt_find_existing(src, seed, &layout, |candidate| {
                        observed.push(candidate);
                        candidate == allocated
                    }),
                    allocated
                );
                assert_eq!(observed.len(), usize::from(occupied_probe) + 1);
            }
            let mut probes = 0;
            assert_eq!(
                napt_find_existing(src, seed, &layout, |_| {
                    probes += 1;
                    false
                }),
                0
            );
            assert_eq!(probes, 8);
        }
    }

    #[test]
    fn masquerade_ownership_never_accepts_dnat_hairpin_or_another_endpoint() {
        let ip = [192, 0, 2, 7];
        let state = crate::FlowState::masquerade(ip, 43000);
        assert!(napt_binding_matches(&state, ip, 43000));
        assert!(!napt_binding_matches(&state, [192, 0, 2, 8], 43000));
        assert!(!napt_binding_matches(&state, ip, 43001));
        assert!(!napt_binding_matches(
            &crate::FlowState::forward(ip, 43000),
            ip,
            43000
        ));
        assert!(!napt_binding_matches(
            &crate::FlowState::reverse(ip, 43000),
            ip,
            43000
        ));
        for changed in [
            crate::FlowState {
                nat2_ip: [192, 0, 2, 1],
                ..state
            },
            crate::FlowState {
                nat2_port: 7,
                ..state
            },
            crate::FlowState {
                flags: state.flags | crate::FlowState::REVERSE,
                ..state
            },
        ] {
            assert!(!napt_binding_matches(&changed, ip, 43000));
        }
    }

    #[test]
    fn native_ten_session_regression_no_longer_collapses_to_one_eight_port_window() {
        let src = [198, 18, 20, 50];
        let dst = [198, 18, 10, 254];
        let mut legacy = BTreeSet::new();
        let mut corrected = BTreeSet::new();
        for sport in 43000..43010 {
            let old = (u32::from_le_bytes(src)
                ^ u32::from_le_bytes(dst).rotate_left(16)
                ^ ((sport as u32) << 16)
                ^ 9101)
                .wrapping_mul(2654435761);
            let seed = napt_seed(src, dst, sport, 9101);
            for probe in 0..8 {
                legacy.insert(napt_port(old, probe));
                corrected.insert(napt_port(seed, probe));
            }
        }
        // Exact observed x86_64 defect remains an explicit negative control.
        assert_eq!(legacy.len(), 8);
        assert!(corrected.len() >= 64, "{corrected:?}");
    }

    #[test]
    fn every_tuple_bit_affects_the_seed_not_just_the_destination_port() {
        let src = u32::from_be_bytes([198, 18, 20, 50]);
        let dst = u32::from_be_bytes([198, 18, 10, 254]);
        let seed = napt_seed(src.to_be_bytes(), dst.to_be_bytes(), 43000, 9101);
        for bit in 0..32 {
            assert_ne!(
                seed,
                napt_seed(
                    (src ^ (1 << bit)).to_be_bytes(),
                    dst.to_be_bytes(),
                    43000,
                    9101
                )
            );
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    (dst ^ (1 << bit)).to_be_bytes(),
                    43000,
                    9101
                )
            );
        }
        for bit in 0..16 {
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    dst.to_be_bytes(),
                    43000 ^ (1 << bit),
                    9101
                )
            );
            assert_ne!(
                seed,
                napt_seed(
                    src.to_be_bytes(),
                    dst.to_be_bytes(),
                    43000,
                    9101 ^ (1 << bit)
                )
            );
        }
    }

    #[test]
    fn adjacent_client_ports_and_addresses_spread_over_the_ephemeral_range() {
        for source in [
            [198, 18, 20, 50],
            [198, 18, 20, 51],
            [192, 0, 2, 18],
            [192, 0, 3, 18],
        ] {
            let bases: BTreeSet<_> = (32768..=65535)
                .map(|sport| napt_port(napt_seed(source, [198, 18, 10, 254], sport, 10920), 0))
                .collect();
            // A uniform32768-sample/32768-bin distribution occupies about20713
            // bins; the old implementation occupies exactly one for each IP.
            assert!(bases.len() > 20000, "{source:?}: {} bins", bases.len());
        }
    }

    #[test]
    fn candidates_stay_in_range_and_wrap_without_overflow() {
        for seed in [0, 1, 32767, 32768, u32::MAX - 7, u32::MAX] {
            for probe in 0..=u16::MAX {
                assert!((32768..=65535).contains(&napt_port(seed, probe)));
            }
            let candidates: BTreeSet<_> = (0..8).map(|probe| napt_port(seed, probe)).collect();
            assert_eq!(candidates.len(), 8);
        }
    }

    #[test]
    fn an_unaddressed_uplink_carries_only_its_own_address_request() {
        // A LAN host's forwarded packet, and the box's own from another link.
        assert!(unaddressed_uplink_drops(
            Some(UNADDRESSED),
            [192, 168, 1, 10]
        ));
        assert!(unaddressed_uplink_drops(Some(UNADDRESSED), [10, 0, 0, 1]));
        // The DHCP client asking for a lease.
        assert!(!unaddressed_uplink_drops(Some(UNADDRESSED), [0, 0, 0, 0]));
    }

    #[test]
    fn an_addressed_or_ordinary_link_is_not_this_rule_s_business() {
        assert!(!unaddressed_uplink_drops(
            Some([203, 0, 113, 9]),
            [192, 168, 1, 10]
        ));
        assert!(!unaddressed_uplink_drops(None, [192, 168, 1, 10]));
    }

    #[test]
    fn masquerade_drops_when_reverse_state_or_rewrite_is_missing() {
        // Map insert failed, or every probe was occupied: do not translate.
        assert_eq!(
            masquerade_commit(false, false, false),
            MasqueradeCommit::Drop
        );
        // A rewrite reported without a binding is still not publishable.
        assert_eq!(
            masquerade_commit(false, false, true),
            MasqueradeCommit::Drop
        );
        // New binding installed, packet rewrite failed: forget the binding so
        // the public port cannot DNAT an unsolicited packet, and do not emit
        // the original private source.
        assert_eq!(
            masquerade_commit(false, true, false),
            MasqueradeCommit::DropAndForget
        );
        // Existing binding, this packet could not be rewritten: drop it and
        // keep the binding created by an earlier successful packet.
        assert_eq!(
            masquerade_commit(true, false, false),
            MasqueradeCommit::Drop
        );
        assert_eq!(
            masquerade_commit(false, true, true),
            MasqueradeCommit::Translated
        );
        assert_eq!(
            masquerade_commit(true, false, true),
            MasqueradeCommit::Translated
        );
    }

    #[test]
    fn a_live_foreign_reverse_entry_is_never_overwritten() {
        let t = crate::ConntrackTimeouts::DEFAULT;
        let mine = crate::FlowState {
            last_seen_ns: 100,
            ..crate::FlowState::reverse([198, 51, 100, 1], 8080)
        };
        let foreign = crate::FlowState {
            last_seen_ns: 100,
            ..crate::FlowState::reverse2([198, 51, 100, 1], 8080, [10, 1, 0, 3], 40000)
        };
        assert!(!nat_entry_replaceable(&foreign, &mine, 6, 200, t));
        // The same rewrite (a concurrent claim of the same flow) is replaceable.
        assert!(nat_entry_replaceable(&mine, &mine, 6, 200, t));
        // An expired entry no longer protects anything.
        let late = 100 + t.tcp_established as u64 * 1_000_000_000;
        assert!(nat_entry_replaceable(&foreign, &mine, 6, late, t));
        // Lifetime bits and counters do not make an entry foreign.
        let busy = crate::FlowState {
            packets: 9,
            _pad: 1,
            ..mine
        };
        assert!(nat_entry_replaceable(&busy, &mine, 17, 200, t));
    }

    #[test]
    fn the_ha_window_starts_with_exactly_the_legacy_eight_candidates() {
        // DP-26: an older peer searches only these eight; the HA window must
        // extend them, not reorder them.
        let src = [192, 168, 50, 100];
        let layout = crate::CgnatLayout::default();
        for seed in [0u32, 1, 7, 32_767, 32_768, 1 << 20, u32::MAX - 100] {
            let domain = NaptDomain::new(src, seed, &layout);
            for i in 0..8u16 {
                assert_eq!(domain.candidate(i as u32), napt_port(seed, i), "{seed} {i}");
            }
        }
    }
}
