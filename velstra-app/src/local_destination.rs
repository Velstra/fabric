//! Rules whose destination is this host (`dst = "local"`).
//!
//! An emitter cannot know which addresses a host holds: a DHCP lease, a
//! SLAAC or DHCPv6 address and a VRRP address that moves between members are
//! all decided at run time. Sentinel used to resolve "to the firewall" from
//! the static addresses in its configuration, which left a DHCP management
//! port unreachable by its own management rules, never counted a VRRP address
//! as local, widened the rule to *any* destination on a box with no static
//! address, and made the compiled policy differ between HA members.
//!
//! So the configuration names the host symbolically and the agent resolves it
//! here, from the same rtnetlink observation the rest of the host-derived
//! state uses, every time the maps are written. The symbolic rule stays in
//! [`RuntimeConfig`] (and so in the HA policy fingerprint); only the copy
//! handed to the map writers is concrete.

use std::{
    borrow::Cow,
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use velstra_common::{Cidr4, Cidr6, PORT_RULE_V4_ONLY, PORT_RULE_V6_ONLY};
use velstra_config::{PolicyConfig, ResolvedRule, RuntimeConfig};

/// Whether any policy carries a local-destination rule. Without one, the host
/// observation keeps no local set at all, so an address change costs exactly
/// what it cost before this existed.
pub(crate) fn has_local_rules(cfg: &RuntimeConfig) -> bool {
    cfg.policies
        .iter()
        .flat_map(|p| &p.port_rules)
        .any(|r| r.dst_local)
}

/// Every address a packet can be addressed to and be for this host: unicast,
/// on any link, in both families. Loopback is left out (a packet arriving on
/// a wire for it is a martian the kernel drops anyway), as are the
/// unspecified and multicast addresses.
pub(crate) fn observed(links: &[crate::host_inventory::Interface]) -> BTreeSet<IpAddr> {
    let v4 = links
        .iter()
        .flat_map(|l| l.addresses.iter())
        .map(|(ip, _)| Ipv4Addr::from(*ip))
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
        .map(IpAddr::V4);
    let v6 = links
        .iter()
        .flat_map(|l| l.addresses6.iter())
        .map(|ip| Ipv6Addr::from(*ip))
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast())
        .map(IpAddr::V6);
    v4.chain(v6).collect()
}

/// One local-destination rule as one host-route rule per local address it
/// applies to. A family-scoped rule takes only that family's addresses.
fn expand(rule: &ResolvedRule, local: &BTreeSet<IpAddr>) -> Vec<ResolvedRule> {
    local
        .iter()
        .filter(|ip| match ip {
            IpAddr::V4(_) => rule.scope & PORT_RULE_V6_ONLY == 0,
            IpAddr::V6(_) => rule.scope & PORT_RULE_V4_ONLY == 0,
        })
        .map(|ip| {
            let mut concrete = rule.clone();
            concrete.dst_local = false;
            match ip {
                IpAddr::V4(v4) => {
                    concrete.dst = Some(Cidr4 {
                        octets: v4.octets(),
                        prefix: 32,
                    });
                }
                IpAddr::V6(v6) => {
                    concrete.dst6 = Some(Cidr6 {
                        octets: v6.octets(),
                        prefix: 128,
                    });
                }
            }
            concrete
        })
        .collect()
}

/// The configuration the map writers are given: every local-destination rule
/// replaced by its host routes for `local`. Borrowed unchanged when there is
/// none, which is every configuration that does not use the feature.
///
/// A host holding no address of a rule's family gives that rule no entries:
/// it then matches nothing, which is narrower than what it said and never
/// wider.
pub(crate) fn concrete<'a>(
    cfg: &'a RuntimeConfig,
    local: &BTreeSet<IpAddr>,
) -> Cow<'a, RuntimeConfig> {
    if !has_local_rules(cfg) {
        return Cow::Borrowed(cfg);
    }
    let mut out = cfg.clone();
    for policy in &mut out.policies {
        policy.port_rules = policy
            .port_rules
            .iter()
            .flat_map(|rule| {
                if rule.dst_local {
                    expand(rule, local)
                } else {
                    vec![rule.clone()]
                }
            })
            .collect();
    }
    Cow::Owned(out)
}

/// Refuse to write a symbolic rule into a map. Written as-is it would carry
/// no address and land in the address-less trie — "to any destination" — so
/// a missed [`concrete`] must fail the apply, not widen the rule.
pub(crate) fn ensure_concrete(cfg: &RuntimeConfig) -> anyhow::Result<()> {
    ensure_concrete_policies(&cfg.policies)
}

/// [`ensure_concrete`] for a writer that is handed the policies alone.
pub(crate) fn ensure_concrete_policies(policies: &[PolicyConfig]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !policies
            .iter()
            .flat_map(|p| &p.port_rules)
            .any(|r| r.dst_local),
        "a local-destination rule reached the map writer unresolved; refusing to program it as any-destination"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse through the agent's own loader, as a config file would be.
    fn load(text: &str) -> anyhow::Result<RuntimeConfig> {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "velstra-local-destination-{}-{n}.toml",
            std::process::id()
        ));
        std::fs::write(&path, text)?;
        let out = velstra_config::load_file(&path);
        let _ = std::fs::remove_file(&path);
        out
    }

    fn cfg(text: &str) -> RuntimeConfig {
        load(text).unwrap()
    }

    const LOCAL_SSH: &str = r#"
default_action = "drop"
[[policy]]
id = 7
name = "mgmt"
default_action = "drop"
[[policy.port_rule]]
name = "mgmt-ssh"
proto = "tcp"
port = 22
action = "pass"
dst = "local"
[[policy.port_rule]]
name = "web"
proto = "tcp"
port = 443
action = "pass"
"#;

    fn local(addrs: &[&str]) -> BTreeSet<IpAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn a_local_rule_resolves_symbolically_and_matches_no_address_on_its_own() {
        let c = cfg(LOCAL_SSH);
        let ssh = &c.policies.iter().find(|p| p.id == 7).unwrap().port_rules[0];
        assert!(ssh.dst_local);
        assert!(ssh.dst.is_none() && ssh.dst6.is_none() && ssh.src.is_none());
        assert!(has_local_rules(&c));
        // Unresolved, it must never reach a writer.
        assert!(ensure_concrete(&c).is_err());
    }

    #[test]
    fn every_observed_address_of_either_family_becomes_one_host_route() {
        let c = cfg(LOCAL_SSH);
        // A DHCP lease, a VRRP address and a SLAAC address — none of which
        // any static configuration names.
        let live = local(&["10.81.0.246", "10.92.0.1", "2001:db8:50::1234"]);
        let out = concrete(&c, &live);
        ensure_concrete(&out).unwrap();
        let rules = &out.policies.iter().find(|p| p.id == 7).unwrap().port_rules;
        let ssh: Vec<_> = rules.iter().filter(|r| r.name == "mgmt-ssh").collect();
        assert_eq!(ssh.len(), 3);
        let v4: BTreeSet<_> = ssh
            .iter()
            .filter_map(|r| r.dst)
            .map(|d| (d.octets, d.prefix))
            .collect();
        assert!(v4.contains(&([10, 81, 0, 246], 32)) && v4.contains(&([10, 92, 0, 1], 32)));
        assert!(ssh.iter().any(|r| r.dst6.is_some_and(|d| d.prefix == 128)));
        // Other rules are untouched.
        assert_eq!(rules.iter().filter(|r| r.name == "web").count(), 1);
    }

    #[test]
    fn a_family_scoped_local_rule_takes_only_its_familys_addresses() {
        let c = cfg(&LOCAL_SSH.replace("dst = \"local\"", "dst = \"local\"\nfamily = \"ipv4\""));
        let out = concrete(&c, &local(&["10.0.0.1", "2001:db8::1"]));
        let ssh: Vec<_> = out
            .policies
            .iter()
            .flat_map(|p| &p.port_rules)
            .filter(|r| r.name == "mgmt-ssh")
            .collect();
        assert_eq!(ssh.len(), 1, "{ssh:?}");
        assert!(ssh.iter().all(|r| r.dst6.is_none() && r.dst.is_some()));
    }

    #[test]
    fn no_addresses_means_the_rule_matches_nothing_rather_than_everything() {
        let c = cfg(LOCAL_SSH);
        let out = concrete(&c, &BTreeSet::new());
        let p = out.policies.iter().find(|p| p.id == 7).unwrap();
        assert!(p.port_rules.iter().all(|r| r.name != "mgmt-ssh"));
    }

    #[test]
    fn local_destination_cannot_be_combined_with_a_source() {
        let text = LOCAL_SSH.replace("dst = \"local\"", "dst = \"local\"\nsrc = \"10.0.0.0/8\"");
        assert!(load(&text).is_err());
    }

    /// HA readiness compares policy fingerprints between members. A local
    /// rule must count (it is not "any destination") but must not carry the
    /// member's own addresses (it is the same rule on both members).
    #[test]
    fn the_policy_fingerprint_sees_a_local_rule_but_no_member_address() {
        let local = cfg(LOCAL_SSH);
        let any = cfg(&LOCAL_SSH.replace("dst = \"local\"\n", ""));
        let fingerprint = crate::conntrack_sync::secure::policy_fingerprint;
        assert_ne!(fingerprint(&local).unwrap(), fingerprint(&any).unwrap());
        // The fingerprint is of the symbolic configuration the agent keeps —
        // `concrete` borrows it and never writes back — so two members with
        // different addresses fingerprint the same policy.
        let before = fingerprint(&local).unwrap();
        let member = concrete(&local, &super::tests::local(&["10.92.0.2"]));
        assert!(matches!(member, Cow::Owned(_)));
        assert_eq!(before, fingerprint(&local).unwrap());
    }

    #[test]
    fn loopback_and_multicast_are_not_local_destinations() {
        let links = vec![crate::host_inventory::Interface {
            name: "lo".into(),
            index: 1,
            mac: None,
            addresses: vec![
                ([127, 0, 0, 1], [255, 0, 0, 0]),
                ([192, 0, 2, 1], [255, 255, 255, 0]),
            ],
            addresses6: vec![
                Ipv6Addr::LOCALHOST.octets(),
                "fe80::1".parse::<Ipv6Addr>().unwrap().octets(),
            ],
        }];
        let seen = observed(&links);
        assert_eq!(seen, local(&["192.0.2.1", "fe80::1"]));
    }
}
