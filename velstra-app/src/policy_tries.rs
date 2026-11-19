//! The six policy tries, written by difference (DP-28, DP-17).
//!
//! `BLOCKLIST`, `BLOCKLIST6` and the four rule tries hold almost all of a large
//! configuration: a GeoIP or feed blocklist alone can be 262,144 prefixes. Every
//! live reconfigure used to delete every old entry and insert every new one
//! while the datapath gate was closed, so a one-line commit on top of a 60,000
//! entry blocklist stalled all traffic for seconds.
//!
//! The agent now keeps a **mirror** of exactly what it wrote into each trie.
//! A reconfigure computes the desired entries, removes the ones the mirror has
//! and the new configuration does not, and writes only entries that are new or
//! whose value changed. An LPM update of an existing key swaps the value in
//! place, so the datapath sees either the old or the new verdict for it, never
//! a gap. The mirror is updated per successful kernel operation, so after a
//! partial failure it still says what the maps hold and the rollback is the
//! same difference taken back towards the previous configuration.
//!
//! Desired entries are computed — and their count checked against each trie's
//! kernel capacity — before the caller closes the gate, so a configuration that
//! cannot fit is refused with a per-trie message and no traffic blip (DP-17).

use std::{collections::HashMap as StdMap, hash::Hash};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf, Pod,
    maps::{
        Map,
        lpm_trie::{Key, LpmTrie},
    },
};
use velstra_common::{
    PolicyId, ScopedAddr, ScopedAddr6, ScopedDstPortKey, ScopedDstPortKey6, ScopedSrcPortKey,
    ScopedSrcPortKey6, port_rule_value, port_rule_with_limit,
};
use velstra_config::{PolicyConfig, ResolvedRule};

use crate::firewall::{
    cidr_bits, cidr6_bits, port_rule_dst_lpm, port_rule_dst6_lpm, port_rule_src_lpm,
    port_rule_src6_lpm,
};

/// One trie's entries: `(prefix length, key) → value`.
pub type Entries<K, V> = StdMap<(u32, K), V>;

/// The entries of all six policy tries, either desired or as written.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PolicyTries {
    pub blocklist: Entries<ScopedAddr, u32>,
    pub blocklist6: Entries<ScopedAddr6, u32>,
    pub port_rules: Entries<ScopedSrcPortKey, u64>,
    pub port_rules6: Entries<ScopedSrcPortKey6, u64>,
    pub dst_rules: Entries<ScopedDstPortKey, u64>,
    pub dst_rules6: Entries<ScopedDstPortKey6, u64>,
}

/// What one difference cost, for the log line and the stall measurement.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Diff {
    pub removed: usize,
    pub written: usize,
    pub unchanged: usize,
}

impl Diff {
    fn add(&mut self, other: Diff) {
        self.removed += other.removed;
        self.written += other.written;
        self.unchanged += other.unchanged;
    }
}

impl PolicyTries {
    /// `(map name, entries, what it holds)` for every trie, for capacity checks.
    pub fn counts(&self) -> [(&'static str, usize, &'static str); 6] {
        [
            ("BLOCKLIST", self.blocklist.len(), "IPv4 blocklist prefixes"),
            (
                "BLOCKLIST6",
                self.blocklist6.len(),
                "IPv6 blocklist prefixes",
            ),
            (
                "PORT_RULES",
                self.port_rules.len(),
                "IPv4 rules without a destination",
            ),
            (
                "PORT_RULES6",
                self.port_rules6.len(),
                "IPv6 rules with a source",
            ),
            (
                "DST_RULES",
                self.dst_rules.len(),
                "IPv4 rules with a destination",
            ),
            (
                "DST_RULES6",
                self.dst_rules6.len(),
                "IPv6 rules with a destination",
            ),
        ]
    }

    /// Whether `cidr`'s key is one the configuration wrote, so a run-time
    /// unblock of the same prefix must leave it in place.
    pub fn has_block(&self, prefix: u32, key: ScopedAddr) -> bool {
        self.blocklist.contains_key(&(prefix, key))
    }

    pub fn has_block6(&self, prefix: u32, key: ScopedAddr6) -> bool {
        self.blocklist6.contains_key(&(prefix, key))
    }
}

/// The entries `policies` put in the six tries. `slots` maps `(policy, rule
/// index)` to the rule's rate-limit slot; `ifindex` resolves a rule's
/// `in-interface` and must refuse a name that does not exist.
pub fn desired(
    policies: &[PolicyConfig],
    slots: &std::collections::HashMap<(PolicyId, usize), u32>,
    ifindex: impl Fn(&str) -> Result<u32>,
) -> Result<PolicyTries> {
    let mut tries = PolicyTries::default();
    for policy in policies {
        for cidr in &policy.blocklist {
            let (prefix, addr) = cidr.lpm_key();
            tries.blocklist.insert(
                (
                    ScopedAddr::POLICY_BITS + prefix,
                    ScopedAddr::new(policy.id, addr),
                ),
                1,
            );
        }
        for cidr in &policy.blocklist6 {
            let (prefix, addr) = cidr.lpm_key();
            tries.blocklist6.insert(
                (
                    ScopedAddr6::POLICY_BITS + prefix,
                    ScopedAddr6::new(policy.id, addr),
                ),
                1,
            );
        }
        for (index, rule) in policy.port_rules.iter().enumerate() {
            let slot = slots.get(&(policy.id, index)).copied().unwrap_or(0);
            insert_rule(&mut tries, policy.id, rule, slot, &ifindex)?;
        }
    }
    Ok(tries)
}

/// A rule lands in exactly one of the four rule tries: the family and the
/// constrained end follow from what the operator wrote.
fn insert_rule(
    tries: &mut PolicyTries,
    policy: PolicyId,
    rule: &ResolvedRule,
    slot: u32,
    ifindex: &impl Fn(&str) -> Result<u32>,
) -> Result<()> {
    let proto = rule.key.proto;
    let icmp_type = rule.icmp_type;
    let port = if icmp_type == 0 { rule.key.port } else { 0 };
    let ifindex = ifindex(&rule.in_interface)?;
    let value = |bits: u8| {
        port_rule_with_limit(
            port_rule_value(rule.action, rule.log, bits) | rule.scope,
            slot,
        ) as u64
            | ((rule.id() as u64) << 32)
    };
    // The same four filters the full rewrite used, each on its own, so a rule
    // lands exactly where it always has.
    if rule.dst.is_some() {
        let (prefix, addr) = port_rule_dst_lpm(&rule.dst);
        let key = ScopedDstPortKey::with_ifindex(policy, proto, icmp_type, port, ifindex, addr);
        tries
            .dst_rules
            .insert((prefix, key), value(cidr_bits(&rule.dst)));
    }
    if rule.dst6.is_some() {
        let (prefix, addr) = port_rule_dst6_lpm(&rule.dst6);
        let key = ScopedDstPortKey6::with_ifindex(policy, proto, icmp_type, port, ifindex, addr);
        tries
            .dst_rules6
            .insert((prefix, key), value(cidr6_bits(&rule.dst6)));
    }
    if rule.src6.is_some() {
        let (prefix, addr) = port_rule_src6_lpm(&rule.src6);
        let key = ScopedSrcPortKey6::with_ifindex(policy, proto, icmp_type, port, ifindex, addr);
        tries
            .port_rules6
            .insert((prefix, key), value(cidr6_bits(&rule.src6)));
    }
    if rule.dst.is_none() && rule.src6.is_none() && rule.dst6.is_none() {
        let (prefix, addr) = port_rule_src_lpm(&rule.src);
        let key = ScopedSrcPortKey::with_ifindex(policy, proto, icmp_type, port, ifindex, addr);
        tries
            .port_rules
            .insert((prefix, key), value(cidr_bits(&rule.src)));
    }
    Ok(())
}

/// Refuse `desired` if any trie would exceed its kernel capacity. Called
/// before the gate closes, so the refusal costs no traffic.
pub fn check_capacity(ebpf: &Ebpf, desired: &PolicyTries) -> Result<()> {
    let mut over = Vec::new();
    for (name, count, what) in desired.counts() {
        let capacity = trie_capacity(ebpf, name)?;
        if count > capacity as usize {
            over.push(format!(
                "{name}: {count} entries ({what}) exceed the data plane's {capacity}"
            ));
        }
    }
    if !over.is_empty() {
        bail!(
            "configuration does not fit the data plane, nothing was changed: {}",
            over.join("; ")
        );
    }
    Ok(())
}

fn trie_capacity(ebpf: &Ebpf, name: &str) -> Result<u32> {
    let Some(Map::LpmTrie(data)) = ebpf.map(name) else {
        bail!("{name} LPM trie missing");
    };
    Ok(data
        .info()
        .with_context(|| format!("reading {name} capacity"))?
        .max_entries())
}

/// The kernel side of one trie, so the difference can be tested without one.
pub trait TrieWrite<K, V> {
    fn put(&mut self, prefix: u32, key: K, value: V) -> Result<()>;
    /// Remove; `Ok(())` also when the key was already absent.
    fn delete(&mut self, prefix: u32, key: K) -> Result<()>;
}

impl<K: Pod, V: Pod> TrieWrite<K, V> for LpmTrie<&mut aya::maps::MapData, K, V> {
    fn put(&mut self, prefix: u32, key: K, value: V) -> Result<()> {
        self.insert(&Key::new(prefix, key), value, 0)
            .map_err(anyhow::Error::from)
    }

    fn delete(&mut self, prefix: u32, key: K) -> Result<()> {
        match self.remove(&Key::new(prefix, key)) {
            Ok(()) => Ok(()),
            Err(aya::maps::MapError::KeyNotFound) => Ok(()),
            Err(aya::maps::MapError::SyscallError(error))
                if error.io_error.raw_os_error() == Some(libc::ENOENT) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Bring one trie from what `written` says it holds to `desired`, keeping
/// `written` exact after every kernel operation. Removals go first, so the
/// trie never holds more than the larger of the two sets.
pub fn sync<K, V>(
    trie: &mut impl TrieWrite<K, V>,
    written: &mut Entries<K, V>,
    desired: &Entries<K, V>,
    what: &str,
) -> Result<Diff>
where
    K: Copy + Eq + Hash + std::fmt::Debug,
    V: Copy + PartialEq,
{
    let mut diff = Diff::default();
    let stale: Vec<(u32, K)> = written
        .keys()
        .filter(|entry| !desired.contains_key(entry))
        .copied()
        .collect();
    for (prefix, key) in stale {
        trie.delete(prefix, key)
            .with_context(|| format!("removing a {what} entry"))?;
        written.remove(&(prefix, key));
        diff.removed += 1;
    }
    for (entry, value) in desired {
        if written.get(entry) == Some(value) {
            diff.unchanged += 1;
            continue;
        }
        trie.put(entry.0, entry.1, *value)
            .with_context(|| format!("inserting a {what} entry"))?;
        written.insert(*entry, *value);
        diff.written += 1;
    }
    Ok(diff)
}

/// Bring all six tries from `written` to `desired`.
pub fn sync_all(ebpf: &mut Ebpf, written: &mut PolicyTries, desired: &PolicyTries) -> Result<Diff> {
    fn trie<'a, K: Pod, V: Pod>(
        ebpf: &'a mut Ebpf,
        name: &str,
    ) -> Result<LpmTrie<&'a mut aya::maps::MapData, K, V>> {
        LpmTrie::try_from(
            ebpf.map_mut(name)
                .ok_or_else(|| anyhow!("{name} map missing"))?,
        )
        .with_context(|| format!("opening {name}"))
    }
    let mut total = Diff::default();
    total.add(sync(
        &mut trie(ebpf, "BLOCKLIST")?,
        &mut written.blocklist,
        &desired.blocklist,
        "blocklist",
    )?);
    total.add(sync(
        &mut trie(ebpf, "BLOCKLIST6")?,
        &mut written.blocklist6,
        &desired.blocklist6,
        "IPv6 blocklist",
    )?);
    total.add(sync(
        &mut trie(ebpf, "PORT_RULES")?,
        &mut written.port_rules,
        &desired.port_rules,
        "port rule",
    )?);
    total.add(sync(
        &mut trie(ebpf, "PORT_RULES6")?,
        &mut written.port_rules6,
        &desired.port_rules6,
        "IPv6 port rule",
    )?);
    total.add(sync(
        &mut trie(ebpf, "DST_RULES")?,
        &mut written.dst_rules,
        &desired.dst_rules,
        "destination rule",
    )?);
    total.add(sync(
        &mut trie(ebpf, "DST_RULES6")?,
        &mut written.dst_rules6,
        &desired.dst_rules6,
        "IPv6 destination rule",
    )?);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trie that records every kernel operation and can be told to fail.
    #[derive(Default)]
    struct FakeTrie {
        held: Entries<u32, u32>,
        ops: usize,
        fail_after: Option<usize>,
    }

    impl TrieWrite<u32, u32> for FakeTrie {
        fn put(&mut self, prefix: u32, key: u32, value: u32) -> Result<()> {
            self.ops += 1;
            if self.fail_after.is_some_and(|n| self.ops > n) {
                bail!("No space left on device");
            }
            self.held.insert((prefix, key), value);
            Ok(())
        }
        fn delete(&mut self, prefix: u32, key: u32) -> Result<()> {
            self.ops += 1;
            self.held.remove(&(prefix, key));
            Ok(())
        }
    }

    fn entries(range: std::ops::Range<u32>, value: u32) -> Entries<u32, u32> {
        range.map(|k| ((32, k), value)).collect()
    }

    #[test]
    fn an_unchanged_large_trie_costs_no_kernel_operation() {
        // DP-28: a one-entry commit on a 60,000 entry blocklist rewrote all of it.
        let mut trie = FakeTrie::default();
        let mut written = Entries::default();
        let big = entries(0..60_000, 1);
        sync(&mut trie, &mut written, &big, "test").unwrap();
        trie.ops = 0;

        let unchanged = sync(&mut trie, &mut written, &big, "test").unwrap();
        assert_eq!(trie.ops, 0);
        assert_eq!(unchanged.unchanged, 60_000);

        let mut one_more = big.clone();
        one_more.insert((24, 70_000), 1);
        let diff = sync(&mut trie, &mut written, &one_more, "test").unwrap();
        assert_eq!((trie.ops, diff.written, diff.removed), (1, 1, 0));
        assert_eq!(trie.held, one_more);
    }

    #[test]
    fn withdrawn_entries_are_removed_and_changed_values_rewritten() {
        let mut trie = FakeTrie::default();
        let mut written = Entries::default();
        sync(&mut trie, &mut written, &entries(0..10, 1), "test").unwrap();
        let mut next = entries(5..10, 1);
        next.insert((32, 7), 2);
        let diff = sync(&mut trie, &mut written, &next, "test").unwrap();
        assert_eq!(diff.removed, 5);
        assert_eq!(diff.written, 1);
        assert_eq!(trie.held, next);
        assert_eq!(written, next);
    }

    #[test]
    fn a_partial_failure_leaves_the_mirror_exact_and_the_rollback_restores_the_old_set() {
        let mut trie = FakeTrie::default();
        let mut written = Entries::default();
        let old = entries(0..100, 1);
        sync(&mut trie, &mut written, &old, "test").unwrap();

        trie.ops = 0;
        trie.fail_after = Some(10);
        let new = entries(50..250, 1);
        assert!(sync(&mut trie, &mut written, &new, "test").is_err());
        assert_eq!(
            written, trie.held,
            "the mirror must say what the trie holds"
        );

        trie.fail_after = None;
        sync(&mut trie, &mut written, &old, "test").unwrap();
        assert_eq!(trie.held, old);
        assert_eq!(written, old);
    }

    fn policy(blocklist: &[&str], rules: Vec<ResolvedRule>) -> PolicyConfig {
        let mut p = velstra_config::RuntimeConfig::passthrough()
            .policies
            .remove(0);
        p.id = 3;
        p.blocklist = blocklist
            .iter()
            .map(|c| velstra_common::parse_cidr_v4(c).unwrap())
            .collect();
        p.port_rules = rules;
        p
    }

    fn rules(toml: &str) -> Vec<ResolvedRule> {
        let path = std::env::temp_dir().join(format!(
            "velstra-policy-tries-{}-{}.toml",
            std::process::id(),
            toml.len()
        ));
        std::fs::write(&path, toml).unwrap();
        let cfg = velstra_config::load_file(&path);
        std::fs::remove_file(&path).unwrap();
        cfg.unwrap().policies.remove(0).port_rules
    }

    #[test]
    fn every_rule_lands_in_exactly_one_trie_and_blocks_are_policy_scoped() {
        let rules = rules(
            r#"
            [[port_rule]]
            proto = "tcp"
            port = 22
            [[port_rule]]
            proto = "tcp"
            port = 80
            dst = "192.0.2.0/24"
            [[port_rule]]
            proto = "tcp"
            port = 443
            src = "2001:db8::/32"
            [[port_rule]]
            proto = "udp"
            port = 53
            dst = "2001:db8::1"
            "#,
        );
        let tries = desired(
            &[policy(&["198.51.100.0/24", "203.0.113.7"], rules)],
            &Default::default(),
            |_| Ok(0),
        )
        .unwrap();
        let counts: Vec<usize> = tries.counts().iter().map(|(_, n, _)| *n).collect();
        assert_eq!(counts, [2, 0, 1, 1, 1, 1]);
        assert!(tries.blocklist.keys().all(|(_, k)| k.policy_id == 3));
    }

    #[test]
    fn a_rule_on_a_missing_interface_is_refused_before_anything_is_written() {
        let rules = rules(
            r#"
            [[port_rule]]
            proto = "tcp"
            port = 22
            in-interface = "gone0"
            "#,
        );
        let error = desired(&[policy(&[], rules)], &Default::default(), |name| {
            anyhow::ensure!(name.is_empty(), "no interface {name}");
            Ok(0)
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("gone0"));
    }
}
