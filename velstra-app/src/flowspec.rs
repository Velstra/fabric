//! A3 second half — **enforcing wren's FlowSpec feed in the data plane**.
//!
//! wren learns BGP FlowSpec rules (RFC 8955) from its peers and streams them
//! over its control socket. Until now that feed had no consumer: a rule arrived,
//! was logged, and nothing dropped a packet because of it. This module is the
//! other end — it subscribes, translates each rule into the firewall rules the
//! data plane already understands, and hands them to the same programming path
//! the configuration takes.
//!
//! ```text
//! + flowspec action discard match dst 10.50.0.0/24 proto =6 dport =22
//! - flowspec match dst 10.50.0.0/24 proto =6 dport =22
//! % end-of-dump
//! ```
//!
//! ## No new maps, and deliberately so
//!
//! The obvious design is a dedicated pair of tries for FlowSpec, and it was the
//! plan until the data plane turned out to already express everything needed:
//! a rule constrains a protocol, a destination port and **one** end's prefix,
//! which is exactly the shape of a FlowSpec rule that a firewall can enforce.
//! What the design does instead is merge — the agent programs the configured
//! rules and the FlowSpec rules as one set ([`merge_into`]) — and that choice is
//! worth more than the maps it saves:
//!
//! * **One writer.** A separate map would have shared the key space with the
//!   configuration and been clobbered by the next reconcile, or needed its own
//!   reconcile to avoid it. Merged, there is exactly one thing writing the
//!   tries, and a collision between a configured rule and an advertised one is
//!   settled in plain Rust that can be unit tested rather than in whichever
//!   order two writers happened to run.
//! * **No eBPF change.** No verifier stack to fit under, no `ebpfHash` to bump,
//!   no chance of a mis-step defanging the data plane.
//!
//! **An advertised rule can only ever make a verdict more restrictive.** Where
//! the operator has written `pass` for what a peer asks to discard, the discard
//! is what happens: a rule that arrived because somebody is being attacked is
//! not overridden by one written last year, and the operator's lever is turning
//! enforcement off or not peering — both decisions rather than accidents. Where
//! the configuration *already* denies, its own form of denial stands: a
//! configured `reject` is not quietly turned into a `drop` because a peer said
//! `discard`. The traffic stops either way, and which answer the sender gets is
//! something the operator chose on purpose.
//!
//! ## What is refused, and why refusing is the point
//!
//! A FlowSpec rule the data plane cannot express is **refused, counted and
//! named** — never approximated. Enforcing "discard dst 10.50.0.0/24 tcp/22" by
//! ignoring the destination would drop port 22 to every network on the box: a
//! self-inflicted outage, and strictly worse than not enforcing at all. Each
//! refusal carries the reason and the rule it applies to, so `show` can say
//! precisely what arrived and what is in force — which is the difference between
//! a feature that is partly implemented and one that is quietly wrong.

use std::{collections::BTreeMap, fmt};

use velstra_common::{Action, Cidr4, PortKey, parse_cidr_v4};
use velstra_config::{ResolvedRule, RuntimeConfig};

/// One line of the feed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    /// A rule was advertised or re-advertised. `spec` is the flow specification
    /// exactly as it arrived, which is also its identity: a re-advertisement of
    /// the same specification replaces the previous actions.
    Update {
        spec: String,
        actions: Vec<String>,
    },
    Withdraw {
        spec: String,
    },
    /// The initial snapshot is complete. Worth acting on rather than ignoring:
    /// it is the moment the set is known to be whole, so the first programming
    /// pass can be one write instead of one per rule.
    EndOfDump,
}

/// Why a rule cannot be enforced.
///
/// Every variant names something the data plane genuinely cannot express, and
/// each one exists because approximating it would enforce something *other* than
/// what was advertised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The line was not one of the three shapes the feed emits.
    Malformed(String),
    /// A specification naming both ends. A longest-prefix key ranks exactly one
    /// address field, so a rule constrains its source or its destination; one
    /// naming both would have to drop the other half, which widens it.
    BothEnds,
    /// No prefix at all. Without one the rule names a protocol and a port and
    /// nothing else, so enforcing it would apply to every address on the box.
    NoPrefix,
    /// An operator other than a plain `=`, or a conjunction. `dport >1024` is a
    /// range, and the trie key holds one port.
    NotAnEquality {
        component: &'static str,
        got: String,
    },
    /// A component with no equivalent in the data plane's key.
    Unsupported { component: String },
    /// An IPv6 prefix. RFC 8956 rules arrive through the same feed; the
    /// translation below builds IPv4 rules only, and silently dropping the
    /// family would leave the operator believing an IPv6 attack was being
    /// filtered.
    NotIpv4(String),
    /// A rate-limit action. The data plane's per-rule limiter counts **packets**
    /// and FlowSpec specifies **bytes**; converting between them requires
    /// inventing an average packet size, and a mitigation that is out by the
    /// ratio of what was assumed to what is arriving is worse than one that
    /// says it did nothing. (A rate of zero is not affected: RFC 8955 §7.1 says
    /// that *is* discard, and wren sends it as `discard`.)
    RateLimit(String),
    /// The rule carried no action wren recognised. Explicit rather than implied:
    /// treating it as `discard` would turn a malformed advertisement into a
    /// blackhole.
    NoAction,
    /// The prefix is broader than the operator allows a peer to ask for. The one
    /// guard that is policy rather than capability, and the reason it exists is
    /// that a single advertisement of `0.0.0.0/0` from a peer having a bad day
    /// would otherwise take the site off the air.
    TooBroad { prefix: u8, floor: u8 },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Malformed(line) => write!(f, "not a feed line: {line:?}"),
            Refusal::BothEnds => f.write_str(
                "names both a source and a destination prefix; a rule constrains one end",
            ),
            Refusal::NoPrefix => f.write_str("names no prefix, so it would apply to every address"),
            Refusal::NotAnEquality { component, got } => {
                write!(
                    f,
                    "{component} {got:?} is not a single `=`; a rule holds one value"
                )
            }
            Refusal::Unsupported { component } => {
                write!(
                    f,
                    "{component} is not something the data plane can match on"
                )
            }
            Refusal::NotIpv4(prefix) => write!(f, "{prefix} is not IPv4"),
            Refusal::RateLimit(rate) => write!(
                f,
                "rate-limit {rate} is in bytes/s and the limiter counts packets; \
                 not enforced rather than guessed"
            ),
            Refusal::NoAction => f.write_str("carries no action to enforce"),
            Refusal::TooBroad { prefix, floor } => {
                write!(
                    f,
                    "/{prefix} is broader than the /{floor} floor for advertised rules"
                )
            }
        }
    }
}

/// Parse one line of the feed.
///
/// The fields before `match` are keyword/value pairs and the specification is
/// last, so this reads pairs until `match` and takes the rest whole — a field
/// added to the feed later slots in ahead of `match` without breaking it.
pub fn parse_line(line: &str) -> Result<Line, Refusal> {
    let line = line.trim_end_matches(['\n', '\r']);
    if line == "% end-of-dump" {
        return Ok(Line::EndOfDump);
    }
    let mut words = line.split_whitespace();
    let verb = words.next();
    if words.next() != Some("flowspec") {
        return Err(Refusal::Malformed(line.to_string()));
    }
    let mut actions = Vec::new();
    let mut spec = String::new();
    while let Some(word) = words.next() {
        if word == "match" {
            spec = words.collect::<Vec<_>>().join(" ");
            break;
        }
        match word {
            "action" => {
                let value = words.next().unwrap_or_default();
                actions = value.split(',').map(str::to_string).collect();
            }
            // A pair this version does not know about. Skipped rather than
            // refused: the feed's whole shape exists so it can grow, and a
            // consumer that fell over on a new field would make adding one
            // impossible.
            _ => {
                let _ = words.next();
            }
        }
    }
    if spec.is_empty() {
        return Err(Refusal::Malformed(line.to_string()));
    }
    match verb {
        Some("+") => Ok(Line::Update { spec, actions }),
        Some("-") => Ok(Line::Withdraw { spec }),
        _ => Err(Refusal::Malformed(line.to_string())),
    }
}

/// The parts of a flow specification the data plane can key on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Parsed {
    src: Option<Cidr4>,
    dst: Option<Cidr4>,
    proto: Option<u8>,
    /// Destination ports, as a list because `dport =80|=443` is one
    /// advertisement and two rules.
    dports: Vec<u16>,
}

/// Split a flow specification into the fields a rule is built from.
fn parse_spec(spec: &str) -> Result<Parsed, Refusal> {
    let mut out = Parsed::default();
    let mut words = spec.split_whitespace();
    while let Some(key) = words.next() {
        let value = words.next().unwrap_or_default();
        match key {
            "src" | "dst" => {
                if value.contains(':') {
                    return Err(Refusal::NotIpv4(value.to_string()));
                }
                let cidr = parse_cidr_v4(value).map_err(|_| Refusal::Unsupported {
                    component: format!("{key} {value}"),
                })?;
                if key == "src" {
                    out.src = Some(cidr);
                } else {
                    out.dst = Some(cidr);
                }
            }
            "proto" => out.proto = Some(single_equality("proto", value)? as u8),
            "dport" => {
                for one in equalities("dport", value)? {
                    out.dports.push(one as u16);
                }
            }
            // Named rather than lumped into "unsupported": these are the ones an
            // operator is most likely to have advertised on purpose, and being
            // told which of them was dropped is the difference between a rule
            // that did nothing and a rule that did nothing *for this reason*.
            other => {
                return Err(Refusal::Unsupported {
                    component: other.to_string(),
                });
            }
        }
    }
    Ok(out)
}

/// The values of a `=`-only operator list — `=80|=443` is two, `=22` is one.
///
/// Anything else is refused: `<`, `>` and `&` describe ranges and conjunctions,
/// and the key holds a single value per rule.
fn equalities(component: &'static str, value: &str) -> Result<Vec<u32>, Refusal> {
    let mut out = Vec::new();
    for part in value.split('|') {
        out.push(single_equality(component, part)?);
    }
    Ok(out)
}

fn single_equality(component: &'static str, value: &str) -> Result<u32, Refusal> {
    let bad = || Refusal::NotAnEquality {
        component,
        got: value.to_string(),
    };
    let digits = value.strip_prefix('=').ok_or_else(bad)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    digits.parse().map_err(|_| bad())
}

/// What a rule came to.
#[derive(Clone, Debug, PartialEq)]
pub struct Enforced {
    /// The specification as advertised, kept so `show` can name it.
    pub spec: String,
    pub rules: Vec<ResolvedRule>,
}

/// Turn one advertisement into the rules the data plane will hold.
///
/// `floor` is the broadest prefix an advertised rule may carry (a `/0` from a
/// peer is not a mitigation, it is an outage). Pass `0` to accept anything.
pub fn translate(spec: &str, actions: &[String], floor: u8) -> Result<Enforced, Refusal> {
    let action = action_of(actions)?;
    let parsed = parse_spec(spec)?;
    if parsed.src.is_some() && parsed.dst.is_some() {
        return Err(Refusal::BothEnds);
    }
    let end = parsed.src.or(parsed.dst).ok_or(Refusal::NoPrefix)?;
    if end.prefix < floor {
        return Err(Refusal::TooBroad {
            prefix: end.prefix,
            floor,
        });
    }
    // A rule with no protocol names no port either — a port belongs to a
    // protocol — and the trie key holds one protocol, so there is nothing to
    // key such a rule on. Refused rather than expanded over the protocols
    // somebody thought of: a mitigation that covers TCP, UDP and ICMP and lets
    // the flood in over GRE is a mitigation that did not work.
    let proto = parsed.proto.ok_or(Refusal::Unsupported {
        component: "a rule with no protocol".to_string(),
    })?;
    if !parsed.dports.is_empty() && !matches!(proto, 6 | 17) {
        return Err(Refusal::Unsupported {
            component: format!("a port on protocol {proto}"),
        });
    }

    let ports: Vec<u16> = if parsed.dports.is_empty() {
        vec![0]
    } else {
        parsed.dports.clone()
    };
    let rules = ports
        .into_iter()
        .map(|port| ResolvedRule {
            key: PortKey::new(proto, port),
            icmp_type: 0,
            in_interface: String::new(),
            scope: 0,
            src: parsed.src,
            dst: parsed.dst,
            src6: None,
            dst6: None,
            action,
            // Logged: a packet dropped because of something a peer said is
            // exactly the drop somebody will need to account for later.
            log: true,
            limit: None,
        })
        .collect();
    Ok(Enforced {
        spec: spec.to_string(),
        rules,
    })
}

/// The action a set of wire tokens comes to.
fn action_of(actions: &[String]) -> Result<Action, Refusal> {
    let mut verdict = None;
    for token in actions {
        if token == "discard" {
            verdict = Some(Action::Drop);
        } else if let Some(rate) = token.strip_prefix("rate-limit:") {
            return Err(Refusal::RateLimit(rate.to_string()));
        }
        // `mark:<dscp>` sets a DSCP the data plane does not write. It is not a
        // refusal on its own: a rule that says "discard and mark" is enforced as
        // a discard, and a marked packet that was dropped is not a packet whose
        // marking matters.
    }
    verdict.ok_or(Refusal::NoAction)
}

/// Everything the feed has said, and what came of it.
#[derive(Debug, Default)]
pub struct Store {
    /// Specification → the rules it produced. A re-advertisement replaces.
    enforced: BTreeMap<String, Enforced>,
    /// Specification → why it produced nothing. Kept, not discarded: a rule that
    /// arrived and is not being enforced is the single most important thing this
    /// module can report.
    refused: BTreeMap<String, Refusal>,
    /// The broadest prefix an advertised rule may carry.
    floor: u8,
}

impl Store {
    pub fn new(floor: u8) -> Self {
        Self {
            floor,
            ..Self::default()
        }
    }

    /// Apply one line. Returns whether anything an operator can observe changed
    /// — the rules in force **or** the list of what arrived and is not being
    /// enforced.
    ///
    /// The refusals count. They did not at first, and the VM check caught what
    /// that costs: a rule that is advertised and cannot be enforced changes
    /// nothing about the data plane, so it produced no push, so it never reached
    /// the query surface and `show firewall flowspec` said the feed was quiet.
    /// The one thing somebody needs during an attack is exactly that difference.
    /// Reprogramming is skipped when only the refusals moved — see
    /// `Firewall::set_flowspec` — so saying "changed" here costs nothing.
    pub fn apply(&mut self, line: Line) -> bool {
        match line {
            Line::Update { spec, actions } => match translate(&spec, &actions, self.floor) {
                Ok(enforced) => {
                    let was_refused = self.refused.remove(&spec).is_some();
                    self.enforced.insert(spec, enforced.clone()) != Some(enforced) || was_refused
                }
                Err(why) => {
                    // A rule that used to be enforceable and now is not stops
                    // being enforced: the peer changed what it is asking for.
                    let was = self.enforced.remove(&spec).is_some();
                    // A refusal repeated verbatim is not news; a new one, or the
                    // same rule refused for a different reason, is.
                    let fresh = self.refused.get(&spec) != Some(&why);
                    self.refused.insert(spec, why);
                    was || fresh
                }
            },
            Line::Withdraw { spec } => {
                let was_refused = self.refused.remove(&spec).is_some();
                self.enforced.remove(&spec).is_some() || was_refused
            }
            Line::EndOfDump => false,
        }
    }

    /// Every rule in force, in advertisement order.
    pub fn rules(&self) -> Vec<ResolvedRule> {
        self.enforced
            .values()
            .flat_map(|e| e.rules.iter().cloned())
            .collect()
    }

    /// What arrived and is not being enforced, with the reason.
    pub fn refusals(&self) -> impl Iterator<Item = (&str, &Refusal)> {
        self.refused.iter().map(|(s, r)| (s.as_str(), r))
    }

    pub fn enforced_count(&self) -> usize {
        self.enforced.len()
    }
}

/// Add `rules` to every policy in `cfg`, and hand back the merged config.
///
/// Every policy, because a FlowSpec rule is not written "in zone lan" — it is
/// what a peer is asking this box to drop, wherever the traffic arrives.
///
/// On a collision with a configured rule — same protocol, port and prefix — the
/// more restrictive action stands (`pass` < `drop` < `reject`). In practice that
/// means an advertised discard overrides a configured pass, and leaves a
/// configured denial exactly as the operator wrote it. See the module
/// documentation for why both halves of that are deliberate.
pub fn merge_into(cfg: &RuntimeConfig, rules: &[ResolvedRule]) -> RuntimeConfig {
    let mut merged = cfg.clone();
    for policy in &mut merged.policies {
        for rule in rules {
            match policy.port_rules.iter_mut().find(|existing| {
                existing.key == rule.key
                    && existing.src == rule.src
                    && existing.dst == rule.dst
                    && existing.icmp_type == rule.icmp_type
                    && existing.in_interface == rule.in_interface
            }) {
                Some(existing) => {
                    if rule.action as u32 > existing.action as u32 {
                        existing.action = rule.action;
                        existing.log = true;
                    }
                }
                None => policy.port_rules.push(rule.clone()),
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(s: &str) -> Cidr4 {
        parse_cidr_v4(s).expect("a test CIDR")
    }

    #[test]
    fn an_advertisement_parses_into_its_actions_and_its_specification() {
        let line =
            parse_line("+ flowspec action discard match dst 10.50.0.0/24 proto =6 dport =22\n")
                .expect("a well-formed line");
        assert_eq!(
            line,
            Line::Update {
                spec: "dst 10.50.0.0/24 proto =6 dport =22".into(),
                actions: vec!["discard".into()],
            }
        );
    }

    #[test]
    fn a_withdrawal_carries_only_the_specification() {
        assert_eq!(
            parse_line("- flowspec match dst 10.50.0.0/24 proto =6 dport =22").unwrap(),
            Line::Withdraw {
                spec: "dst 10.50.0.0/24 proto =6 dport =22".into()
            }
        );
    }

    #[test]
    fn the_end_of_the_snapshot_is_its_own_line() {
        assert_eq!(parse_line("% end-of-dump").unwrap(), Line::EndOfDump);
    }

    #[test]
    fn a_field_this_version_does_not_know_slots_in_ahead_of_the_match() {
        // The feed's shape exists so it can grow. A consumer that refused an
        // unknown pair would make adding one a breaking change.
        let line =
            parse_line("+ flowspec action discard peer 192.0.2.1 match dst 10.0.0.0/8 proto =6")
                .expect("an unknown pair is skipped, not refused");
        assert_eq!(
            line,
            Line::Update {
                spec: "dst 10.0.0.0/8 proto =6".into(),
                actions: vec!["discard".into()],
            }
        );
    }

    #[test]
    fn several_actions_arrive_as_several_tokens() {
        let Line::Update { actions, .. } =
            parse_line("+ flowspec action discard,mark:46 match src 192.0.2.0/24 proto =17")
                .unwrap()
        else {
            panic!("expected an update");
        };
        assert_eq!(actions, vec!["discard".to_string(), "mark:46".to_string()]);
    }

    #[test]
    fn a_line_that_is_not_the_feeds_shape_is_refused() {
        assert!(matches!(parse_line("garbage"), Err(Refusal::Malformed(_))));
        assert!(matches!(
            parse_line("+ flowspec action discard"),
            Err(Refusal::Malformed(_))
        ));
    }

    #[test]
    fn a_discard_on_a_destination_becomes_one_rule() {
        let e = translate(
            "dst 10.50.0.0/24 proto =6 dport =22",
            &["discard".into()],
            0,
        )
        .expect("enforceable");
        assert_eq!(e.rules.len(), 1);
        let r = &e.rules[0];
        assert_eq!(r.key, PortKey::new(6, 22));
        assert_eq!(r.dst, Some(cidr("10.50.0.0/24")));
        assert_eq!(r.src, None);
        assert_eq!(r.action, Action::Drop);
        assert!(r.log, "a drop nobody can account for later");
    }

    #[test]
    fn two_ports_in_one_advertisement_become_two_rules() {
        let e = translate(
            "dst 10.50.0.0/24 proto =6 dport =80|=443",
            &["discard".into()],
            0,
        )
        .expect("enforceable");
        let ports: Vec<u16> = e.rules.iter().map(|r| r.key.port).collect();
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn a_rule_naming_both_ends_is_refused_rather_than_halved() {
        // Dropping either half widens the rule. Widening a discard is how a
        // mitigation becomes an outage.
        assert_eq!(
            translate(
                "src 192.0.2.0/24 dst 10.50.0.0/24 proto =6",
                &["discard".into()],
                0
            ),
            Err(Refusal::BothEnds)
        );
    }

    #[test]
    fn a_rule_with_no_prefix_is_refused() {
        assert_eq!(
            translate("proto =6 dport =22", &["discard".into()], 0),
            Err(Refusal::NoPrefix)
        );
    }

    #[test]
    fn a_range_is_refused_rather_than_rounded() {
        assert!(matches!(
            translate(
                "dst 10.0.0.0/8 proto =6 dport >1024",
                &["discard".into()],
                0
            ),
            Err(Refusal::NotAnEquality { .. })
        ));
        assert!(matches!(
            translate(
                "dst 10.0.0.0/8 proto =6 dport =80&=443",
                &["discard".into()],
                0
            ),
            Err(Refusal::NotAnEquality { .. })
        ));
    }

    #[test]
    fn a_component_the_key_has_no_room_for_is_named_in_the_refusal() {
        let refusal = translate(
            "dst 10.0.0.0/8 proto =6 tcp-flags =2",
            &["discard".into()],
            0,
        )
        .unwrap_err();
        assert_eq!(
            refusal,
            Refusal::Unsupported {
                component: "tcp-flags".into()
            }
        );
    }

    #[test]
    fn an_ipv6_rule_says_so_rather_than_being_dropped_on_the_floor() {
        assert!(matches!(
            translate("dst 2001:db8::/32 proto =6", &["discard".into()], 0),
            Err(Refusal::NotIpv4(_))
        ));
    }

    #[test]
    fn a_rate_limit_is_refused_because_the_units_do_not_match() {
        assert!(matches!(
            translate("dst 10.0.0.0/8 proto =6", &["rate-limit:12500".into()], 0),
            Err(Refusal::RateLimit(_))
        ));
    }

    #[test]
    fn marking_alongside_a_discard_does_not_stop_the_discard() {
        let e = translate(
            "dst 10.0.0.0/8 proto =6",
            &["discard".into(), "mark:46".into()],
            0,
        )
        .expect("the discard is enforceable whatever the marking says");
        assert_eq!(e.rules[0].action, Action::Drop);
    }

    #[test]
    fn no_action_enforces_nothing() {
        // Implying `discard` here would turn a malformed advertisement into a
        // blackhole.
        assert_eq!(
            translate("dst 10.0.0.0/8 proto =6", &["none".into()], 0),
            Err(Refusal::NoAction)
        );
    }

    #[test]
    fn a_rule_with_no_protocol_is_refused_rather_than_guessed_at() {
        let refusal = translate("dst 10.50.0.0/24", &["discard".into()], 0).unwrap_err();
        assert!(
            matches!(&refusal, Refusal::Unsupported { component } if component.contains("protocol")),
            "{refusal:?}"
        );
    }

    #[test]
    fn a_prefix_broader_than_the_floor_is_refused() {
        assert_eq!(
            translate("dst 10.0.0.0/8 proto =6", &["discard".into()], 24),
            Err(Refusal::TooBroad {
                prefix: 8,
                floor: 24
            })
        );
        assert!(translate("dst 10.50.0.0/24 proto =6", &["discard".into()], 24).is_ok());
    }

    #[test]
    fn a_re_advertisement_of_the_same_rule_changes_nothing() {
        // What this protects is the data plane: every change reprograms the
        // policy maps, and a feed that repeats itself must not mean a rewrite
        // per repetition.
        let mut store = Store::new(0);
        let line = || Line::Update {
            spec: "dst 10.50.0.0/24 proto =6 dport =22".into(),
            actions: vec!["discard".into()],
        };
        assert!(
            store.apply(line()),
            "the first advertisement changed nothing"
        );
        assert!(!store.apply(line()), "a repeat reprogrammed the data plane");
    }

    #[test]
    fn a_withdrawal_takes_the_rule_out_again() {
        let mut store = Store::new(0);
        store.apply(Line::Update {
            spec: "dst 10.50.0.0/24 proto =6 dport =22".into(),
            actions: vec!["discard".into()],
        });
        assert_eq!(store.rules().len(), 1);
        assert!(store.apply(Line::Withdraw {
            spec: "dst 10.50.0.0/24 proto =6 dport =22".into()
        }));
        assert!(store.rules().is_empty());
    }

    #[test]
    fn a_rule_that_stops_being_enforceable_stops_being_enforced() {
        // The peer changed what it is asking for. Keeping yesterday's rule
        // would be enforcing something nobody is asking for any more.
        let mut store = Store::new(0);
        store.apply(Line::Update {
            spec: "dst 10.50.0.0/24 proto =6 dport =22".into(),
            actions: vec!["discard".into()],
        });
        assert_eq!(store.rules().len(), 1);
        assert!(store.apply(Line::Update {
            spec: "dst 10.50.0.0/24 proto =6 dport =22".into(),
            actions: vec!["rate-limit:1000".into()],
        }));
        assert!(store.rules().is_empty());
        assert_eq!(store.refusals().count(), 1);
    }

    /// A pass-everything config with one policy, which is what
    /// `RuntimeConfig::passthrough` already is.
    fn one_policy() -> RuntimeConfig {
        RuntimeConfig::passthrough()
    }

    #[test]
    fn an_advertised_discard_overrides_a_configured_pass() {
        let mut cfg = one_policy();
        let permit = ResolvedRule {
            key: PortKey::new(6, 22),
            icmp_type: 0,
            in_interface: String::new(),
            scope: 0,
            src: None,
            dst: parse_cidr_v4("10.50.0.0/24").ok(),
            src6: None,
            dst6: None,
            action: Action::Pass,
            log: false,
            limit: None,
        };
        cfg.policies[0].port_rules.push(permit);

        let advertised = translate(
            "dst 10.50.0.0/24 proto =6 dport =22",
            &["discard".into()],
            0,
        )
        .unwrap()
        .rules;
        let merged = merge_into(&cfg, &advertised);
        assert_eq!(
            merged.policies[0].port_rules.len(),
            1,
            "the rule was duplicated"
        );
        assert_eq!(merged.policies[0].port_rules[0].action, Action::Drop);
    }

    #[test]
    fn a_configured_reject_keeps_its_own_form_of_denial() {
        // The traffic stops either way. Which answer the sender gets is
        // something the operator chose on purpose, and an advertisement that
        // only says "discard" is not an instruction to change it.
        let mut cfg = one_policy();
        cfg.policies[0].port_rules.push(ResolvedRule {
            key: PortKey::new(6, 22),
            icmp_type: 0,
            in_interface: String::new(),
            scope: 0,
            src: None,
            dst: parse_cidr_v4("10.50.0.0/24").ok(),
            src6: None,
            dst6: None,
            action: Action::Reject,
            log: false,
            limit: None,
        });
        let advertised = translate(
            "dst 10.50.0.0/24 proto =6 dport =22",
            &["discard".into()],
            0,
        )
        .unwrap()
        .rules;
        let merged = merge_into(&cfg, &advertised);
        assert_eq!(merged.policies[0].port_rules[0].action, Action::Reject);
    }

    #[test]
    fn an_advertised_rule_reaches_every_policy() {
        // Not "in zone lan": it is what a peer is asking this box to drop,
        // wherever the traffic arrives.
        let mut cfg = one_policy();
        let mut second = cfg.policies[0].clone();
        second.id = 1;
        cfg.policies.push(second);
        let advertised = translate("dst 10.50.0.0/24 proto =6", &["discard".into()], 0)
            .unwrap()
            .rules;
        let merged = merge_into(&cfg, &advertised);
        for policy in &merged.policies {
            assert_eq!(policy.port_rules.len(), 1, "a policy was left unprotected");
        }
    }

    #[test]
    fn a_refusal_is_kept_so_it_can_be_reported() {
        let mut store = Store::new(0);
        store.apply(Line::Update {
            spec: "src 1.0.0.0/8 dst 2.0.0.0/8 proto =6".into(),
            actions: vec!["discard".into()],
        });
        let (spec, why) = store
            .refusals()
            .next()
            .expect("the refusal was thrown away");
        assert!(spec.contains("src 1.0.0.0/8"));
        assert_eq!(why, &Refusal::BothEnds);
    }
}

// ---- the running task ----------------------------------------------------

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::Mutex,
};

use crate::firewall::Firewall;

/// Reconnect backoff, floor and ceiling. wren restarting is ordinary — it is the
/// routing daemon on the same box — so the floor is short and the ceiling is
/// low enough that a rule advertised during an outage is enforced within seconds
/// of wren coming back.
const BACKOFF_FLOOR: Duration = Duration::from_millis(500);
const BACKOFF_CEIL: Duration = Duration::from_secs(10);

/// Subscribe to wren's FlowSpec feed and keep the data plane in step with it.
///
/// Runs until the process ends. Every failure — wren absent, wren restarting, a
/// line that makes no sense — is a thing to report and carry on from, never a
/// reason to stop: the alternative is a mitigation feed that goes quiet the
/// first time the routing daemon is restarted and that nobody notices until an
/// attack is not being filtered.
///
/// **What is in force is not cleared when the feed drops.** wren going away says
/// nothing about whether the attack has stopped, and dropping the rules on a
/// disconnect would lift the mitigation at exactly the wrong moment. The rules
/// are replaced wholesale by the snapshot the next connection opens with, so a
/// rule withdrawn while the link was down is gone one round-trip later.
pub async fn enforce(socket: PathBuf, firewall: Arc<Mutex<Firewall>>, floor: u8) {
    let mut backoff = BACKOFF_FLOOR;
    loop {
        match subscribe(&socket, &firewall, floor).await {
            Ok(()) => {
                info!("wren closed the flowspec feed; resubscribing");
                backoff = BACKOFF_FLOOR;
            }
            Err(e) => {
                warn!(
                    "flowspec feed unavailable ({e}); retrying in {:.1}s, keeping what is in force",
                    backoff.as_secs_f32()
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_CEIL);
                continue;
            }
        }
        tokio::time::sleep(BACKOFF_FLOOR).await;
    }
}

/// One subscription, from connect to disconnect.
///
/// The store is rebuilt from scratch per connection, because the feed opens with
/// a snapshot: carrying the previous connection's set over would keep enforcing
/// a rule that was withdrawn while nobody was listening.
async fn subscribe(
    socket: &Path,
    firewall: &Arc<Mutex<Firewall>>,
    floor: u8,
) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(b"monitor flowspec\n").await?;
    stream.flush().await?;
    info!("subscribed to wren's flowspec feed at {}", socket.display());

    let mut store = Store::new(floor);
    let mut lines = BufReader::new(stream).lines();
    // Nothing is programmed until the snapshot is complete: the first pass is
    // then one write rather than one per rule, and a box coming up under attack
    // does not spend that moment reprogramming its policy maps repeatedly.
    let mut settled = false;
    let mut dirty = false;

    while let Some(line) = lines.next_line().await? {
        if line.is_empty() {
            continue;
        }
        // wren answers a subscription on a daemon without BGP with a sentence
        // rather than a feed. Said once, at the level somebody will look at.
        if !line.starts_with(['+', '-', '%']) {
            warn!("wren refused the flowspec subscription: {line}");
            return Ok(());
        }
        match parse_line(&line) {
            Ok(Line::EndOfDump) => {
                settled = true;
                if std::mem::take(&mut dirty) || store.enforced_count() > 0 {
                    push(firewall, &store).await;
                }
            }
            Ok(parsed) => {
                let changed = store.apply(parsed);
                if changed && settled {
                    push(firewall, &store).await;
                } else {
                    dirty |= changed;
                }
            }
            Err(why) => warn!("flowspec: {why}"),
        }
    }
    Ok(())
}

/// Put what the store holds into the data plane, and say what is not in force.
///
/// The refusals are logged on every push rather than once when they arrive: what
/// matters operationally is not that a rule was refused at some point, it is
/// that it is *still* not being enforced, and that is a question somebody asks
/// while looking at a live log.
async fn push(firewall: &Arc<Mutex<Firewall>>, store: &Store) {
    let rules = store.rules();
    let enforced = store.enforced_count();
    let refused: Vec<(String, String)> = store
        .refusals()
        .map(|(spec, why)| (spec.to_string(), why.to_string()))
        .collect();
    for (spec, why) in &refused {
        warn!("flowspec not enforced [{spec}]: {why}");
    }
    match firewall.lock().await.set_flowspec(rules, refused) {
        Ok(()) => info!(
            "flowspec: {enforced} rule(s) in force, {} not enforced",
            store.refusals().count()
        ),
        // The data plane keeps whatever it had: a failed reprogram is not a
        // reason to have no rules at all.
        Err(e) => warn!("flowspec could not be programmed ({e:#}); keeping the previous set"),
    }
}

/// Whether a stateful-firewall flow entry is one this rule discards.
///
/// A rule that only stops flows which have not started yet is not a mitigation:
/// a flood with a stable five-tuple is admitted for as long as its entry lives,
/// and that is exactly the traffic somebody advertised the rule to stop. So a
/// newly-enforced discard also **purges the entries it matches**.
///
/// Purging is deliberately *narrow*. Clearing more than the rule names would be
/// the classic conntrack flush: under a deny-by-default policy, a mid-connection
/// packet whose entry has gone is re-judged as if it were new, and a connection
/// nobody asked to break, breaks. So the match is the rule's own — protocol,
/// port and prefix — and nothing wider.
///
/// `port == 0` in the rule means "every port of that protocol", which is what a
/// rule naming no port compiles to; ICMP entries carry the message type in the
/// port field rather than a port, and a rule for ICMP names no port, so the two
/// never collide.
pub fn flow_is_discarded(rule: &ResolvedRule, key: &velstra_common::FlowKey) -> bool {
    if rule.action != Action::Drop {
        return false;
    }
    if key.proto != rule.key.proto {
        return false;
    }
    if rule.key.port != 0 && key.dst_port != rule.key.port {
        return false;
    }
    match (rule.src, rule.dst) {
        (Some(src), None) => within(src, key.src_ip),
        (None, Some(dst)) => within(dst, key.dst_ip),
        // A rule with neither end is refused before it gets here, and one with
        // both is refused too. Matching nothing is the safe reading of a shape
        // that should not exist.
        _ => false,
    }
}

/// Whether `addr` falls inside `cidr`.
fn within(cidr: Cidr4, addr: [u8; 4]) -> bool {
    let bits = cidr.prefix as u32;
    if bits == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - bits.min(32));
    u32::from_be_bytes(addr) & mask == u32::from_be_bytes(cidr.octets) & mask
}

#[cfg(test)]
mod purge_tests {
    use velstra_common::FlowKey;

    use super::*;

    fn rule(proto: u8, port: u16, dst: &str) -> ResolvedRule {
        let ports = if port == 0 {
            String::new()
        } else {
            format!(" dport ={port}")
        };
        translate(
            &format!("dst {dst} proto ={proto}{ports}"),
            &["discard".to_string()],
            0,
        )
        .expect("enforceable")
        .rules
        .remove(0)
    }

    fn flow(proto: u8, dst: [u8; 4], dport: u16) -> FlowKey {
        FlowKey::new(0, [192, 0, 2, 9], dst, 12345, dport, proto)
    }

    #[test]
    fn a_flow_the_rule_names_is_purged() {
        let r = rule(6, 22, "10.50.0.0/24");
        assert!(flow_is_discarded(&r, &flow(6, [10, 50, 0, 7], 22)));
    }

    #[test]
    fn a_flow_to_another_network_is_left_alone() {
        // The narrowness is the point: clearing this would re-judge a connection
        // nobody asked to break.
        let r = rule(6, 22, "10.50.0.0/24");
        assert!(!flow_is_discarded(&r, &flow(6, [10, 51, 0, 7], 22)));
    }

    #[test]
    fn another_port_on_the_same_host_is_left_alone() {
        let r = rule(6, 22, "10.50.0.0/24");
        assert!(!flow_is_discarded(&r, &flow(6, [10, 50, 0, 7], 443)));
    }

    #[test]
    fn another_protocol_is_left_alone() {
        let r = rule(6, 22, "10.50.0.0/24");
        assert!(!flow_is_discarded(&r, &flow(17, [10, 50, 0, 7], 22)));
    }

    #[test]
    fn a_rule_naming_no_port_takes_every_port_of_its_protocol() {
        // Which is also how an ICMP rule reaches the entries whose port field
        // carries a message type rather than a port.
        let r = rule(1, 0, "10.50.0.0/24");
        assert!(flow_is_discarded(&r, &flow(1, [10, 50, 0, 7], 9)));
        assert!(flow_is_discarded(&r, &flow(1, [10, 50, 0, 7], 1)));
    }

    #[test]
    fn a_source_rule_matches_on_the_source() {
        let mut r = rule(6, 0, "10.50.0.0/24");
        r.src = r.dst.take();
        assert!(flow_is_discarded(
            &r,
            &FlowKey::new(0, [10, 50, 0, 7], [192, 0, 2, 1], 1, 2, 6)
        ));
        assert!(!flow_is_discarded(
            &r,
            &FlowKey::new(0, [10, 51, 0, 7], [192, 0, 2, 1], 1, 2, 6)
        ));
    }

    #[test]
    fn a_rule_that_passes_purges_nothing() {
        let mut r = rule(6, 22, "10.50.0.0/24");
        r.action = Action::Pass;
        assert!(!flow_is_discarded(&r, &flow(6, [10, 50, 0, 7], 22)));
    }
}

#[cfg(test)]
mod visibility_tests {
    use super::*;

    fn refused_line(spec: &str) -> Line {
        Line::Update {
            spec: spec.to_string(),
            actions: vec!["discard".into()],
        }
    }

    #[test]
    fn a_rule_that_cannot_be_enforced_is_still_news() {
        // What the VM check caught: a refusal changes nothing about the data
        // plane, so it produced no push, so `show firewall flowspec` said the
        // feed was quiet while a peer was asking for something it could not have.
        let mut store = Store::new(0);
        assert!(
            store.apply(refused_line("src 1.0.0.0/8 dst 2.0.0.0/8 proto =6")),
            "a refusal was not reported as a change"
        );
        assert_eq!(store.refusals().count(), 1);
    }

    #[test]
    fn the_same_refusal_repeated_is_not() {
        let mut store = Store::new(0);
        store.apply(refused_line("src 1.0.0.0/8 dst 2.0.0.0/8 proto =6"));
        assert!(
            !store.apply(refused_line("src 1.0.0.0/8 dst 2.0.0.0/8 proto =6")),
            "a repeat was reported as a change"
        );
    }

    #[test]
    fn a_rule_becoming_enforceable_again_is_news() {
        let mut store = Store::new(24);
        // Too broad for the floor…
        assert!(store.apply(refused_line("dst 10.0.0.0/8 proto =6")));
        // …and then narrowed by the peer.
        let mut store2 = Store::new(24);
        assert!(store2.apply(refused_line("dst 10.50.0.0/24 proto =6")));
        assert_eq!(store2.rules().len(), 1);
        assert_eq!(store2.refusals().count(), 0);
    }

    #[test]
    fn withdrawing_a_refused_rule_clears_it_from_view() {
        // Otherwise `show` keeps naming a rule nobody is asking for any more.
        let mut store = Store::new(0);
        store.apply(refused_line("src 1.0.0.0/8 dst 2.0.0.0/8 proto =6"));
        assert!(store.apply(Line::Withdraw {
            spec: "src 1.0.0.0/8 dst 2.0.0.0/8 proto =6".into()
        }));
        assert_eq!(store.refusals().count(), 0);
    }
}
