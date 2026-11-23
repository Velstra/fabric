"""Source-wiring guards, not packet or concurrent-map fault injection tests."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRITERS = (
    "ct_record",
    "ct_record_wire4",
    "ct_seed_reply",
    "ct_router_open",
    "ct_cookie_admitted",
    # The SYN proxy's own handshake ACK (XDP_TX) advances the server-facing
    # state no egress hook sees (DP-31); it fails closed like the others.
    "ct_synproxy_acked",
)


def calls(source):
    for match in re.finditer(r"\b(" + "|".join(WRITERS) + r")\s*\(", source):
        depth = 1
        end = match.end()
        while depth and end < len(source):
            depth += (source[end] == "(") - (source[end] == ")")
            end += 1
        if depth:
            raise ValueError("unclosed state writer call")
        yield match.group(1), source[end:].lstrip()


class PublicationWiring(unittest.TestCase):
    def test_every_packet_writer_call_checks_failure(self):
        observed = []
        for name in ("main.rs", "icmp_nat.rs"):
            source = (ROOT / "velstra-ebpf/src" / name).read_text()
            for writer, following in calls(source):
                observed.append(writer)
                self.assertTrue(following.startswith(".failed()"), (name, writer))
        self.assertEqual(len(observed), 18)
        self.assertEqual(set(observed), set(WRITERS))

    def test_all_directional_inserts_use_one_fallible_helper(self):
        source = (ROOT / "velstra-ebpf/src/conntrack.rs").read_text()
        prefix, helper = source.split("unsafe fn publish_scratch", 1)
        self.assertNotRegex(prefix, r"FW_FLOWS\s*\.\s*insert")
        self.assertEqual(len(re.findall(r"FW_FLOWS\s*\.\s*insert", helper)), 2)
        self.assertIn("publish_state_pair(", helper)
        self.assertNotIn("remove(", helper)
        self.assertEqual(prefix.count("publish_scratch(scratch)"), 4)

    def test_noop_and_failure_are_distinct_at_each_writer(self):
        source = (ROOT / "velstra-ebpf/src/conntrack.rs").read_text()
        for writer in WRITERS:
            self.assertRegex(source, rf"fn {writer}\([^{{]*-> StatePublication")
        self.assertEqual(source.count("return StatePublication::Failed;"), 6)
        self.assertIn("return StatePublication::NoChange;", source)

    def test_guard_recognizes_discarded_call(self):
        self.assertEqual(list(calls("ct_record(&key, flag);")), [("ct_record", ";")])
        checked = list(calls("ct_seed_reply(&FlowKey::new(1, 2), f)\n.failed()"))
        self.assertEqual(checked, [("ct_seed_reply", ".failed()")])

    def test_icmp_success_counter_follows_publication(self):
        source = (ROOT / "velstra-ebpf/src/icmp_nat.rs").read_text()
        self.assertEqual(source.count("bump(Counter::EgressMasqueraded)"), 1)
        self.assertLess(source.index("if ct_record("), source.index("bump(Counter::EgressMasqueraded)"))


if __name__ == "__main__":
    unittest.main()
