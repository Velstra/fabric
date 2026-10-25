//! Stable userspace/kernel ABI for rule counters and packet events.

#[inline(always)]
pub const fn tag_rule(value: u32, id: u32) -> u64 {
    value as u64 | ((id as u64) << 32)
}

#[inline(always)]
pub const fn winning_tagged_rule(a: u64, b: u64) -> u64 {
    let av = a as u32;
    let bv = b as u32;
    if !crate::port_rule_present(av) {
        return b;
    }
    if !crate::port_rule_present(bv) {
        return a;
    }
    // Rank once. Selecting a low-word winner then comparing it with the input
    // duplicates branches in BPF, multiplying verifier states at every probe.
    let ar = (crate::port_rule_bits(av) << 8) | (av & 0xff);
    let br = (crate::port_rule_bits(bv) << 8) | (bv & 0xff);
    if ar >= br { a } else { b }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleCounterKey {
    pub policy: u32,
    pub rule_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleCounters {
    pub packets: u64,
    pub bytes: u64,
    pub accepted: u64,
    pub dropped: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PacketEvent {
    pub timestamp_ns: u64,
    pub policy: u32,
    pub rule_id: u32,
    pub ifindex: u32,
    pub length: u32,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub family: u8,
    pub action: u8,
    pub direction: u8,
    pub reason: u32,
    pub _pad: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleCounterKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleCounters {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tagged_ranking_matches_the_policy_order_across_all_metadata() {
        let mut values = vec![0];
        for action in [
            crate::Action::Pass,
            crate::Action::Drop,
            crate::Action::Reject,
        ] {
            for bits in [0, 8, 24, 32, 64, 128] {
                for log in [false, true] {
                    values.push(crate::port_rule_value(action, log, bits));
                }
            }
        }
        for &a in &values {
            for &b in &values {
                let got = winning_tagged_rule(tag_rule(a, 17), tag_rule(b, 29));
                assert_eq!(got as u32, crate::port_rule_winner(a, b));
            }
        }
    }

    #[test]
    fn abi_has_no_implicit_padding_to_leak_to_userspace() {
        assert_eq!(core::mem::size_of::<RuleCounterKey>(), 8);
        assert_eq!(core::mem::size_of::<RuleCounters>(), 32);
        assert_eq!(core::mem::size_of::<PacketEvent>(), 72);
    }

    #[test]
    fn rule_ranking_keeps_the_identity_of_the_actual_winner() {
        let broad = tag_rule(crate::port_rule_value(crate::Action::Drop, true, 0), 17);
        let narrow = tag_rule(crate::port_rule_value(crate::Action::Pass, false, 24), 29);
        assert_eq!(winning_tagged_rule(broad, narrow), narrow);
        assert_eq!(winning_tagged_rule(narrow, broad), narrow);
        assert_eq!(winning_tagged_rule(0, narrow), narrow);
        assert_eq!(winning_tagged_rule(broad, 0), broad);
        assert_eq!(crate::port_rule_action(broad as u32), crate::Action::Drop);
        assert!(crate::port_rule_logs(broad as u32));
    }
}
