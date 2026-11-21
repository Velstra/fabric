"""Wiring guard for the masquerade binding's reopen rule.

`nat_lifetime::reopen` (velstra-common, unit-tested there) starts a binding's
lifetime afresh when the inside client opens a new connection on a reused
tuple. It is only right for segments the client sent: a SYN that arrives from
outside must not shorten a public port's hold. So the shipped egress update
must call it, and nothing else may.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "velstra-ebpf/src"
FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?fn\s+(\w+)', re.M)


def enclosing_fn(text, offset):
    names = [m.group(1) for m in FN.finditer(text, 0, offset)]
    return names[-1] if names else None


class ReopenWiring(unittest.TestCase):
    def callers(self, pattern):
        found = set()
        for path in sorted(SOURCES.glob("*.rs")):
            text = path.read_text()
            for match in re.finditer(pattern, text):
                found.add((path.name, enclosing_fn(text, match.start())))
        return found

    def test_only_the_egress_binding_update_reopens(self):
        self.assertEqual(self.callers(r"nat_lifetime::reopen\s*\("), {("main.rs", "nat_lifetime_update")})

    def test_the_egress_update_is_the_masquerades(self):
        self.assertEqual(self.callers(r"(?<!fn )nat_lifetime_update\s*\("), {("main.rs", "masquerade_egress")})

    def test_lookups_from_outside_keep_the_plain_update(self):
        self.assertIn(("main.rs", "account_flow"), self.callers(r"nat_lifetime::update\s*\("))
        self.assertNotIn(("main.rs", "nat_lifetime_update"), self.callers(r"nat_lifetime::update\s*\("))


if __name__ == "__main__":
    unittest.main()
