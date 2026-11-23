"""Wiring guards for the standalone NAPT window (PERF-02).

The allocator's correctness is unit-tested in velstra-common (window_tests)
and measured on the wire by Sentinel's checks.nat-cps. These guards pin the
two properties a later edit could silently undo: no per-flow search is ever
sized by table history (a global bound, the whole domain), and discovery and
allocation use one and the same window.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "velstra-ebpf/src"
FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+(\w+)', re.M)


def enclosing_fn(text, offset):
    names = [m.group(1) for m in FN.finditer(text, 0, offset)]
    return names[-1] if names else None


def fn_body(text, name):
    start = re.search(r"\bfn\s+" + name + r"\s*[(<]", text).start()
    following = FN.search(text, start + 1)
    return text[start: following.start() if following else len(text)]


class StandaloneWindow(unittest.TestCase):
    def setUp(self):
        self.domain = (SOURCES / "napt_domain.rs").read_text()
        self.main = (SOURCES / "main.rs").read_text()

    def test_no_search_is_sized_by_table_history(self):
        everything = "\n".join(p.read_text() for p in sorted(SOURCES.glob("*.rs")))
        for marker in ("NAPT_SEARCH", "unbounded(", "atomic_or"):
            self.assertNotIn(marker, everything, marker)
        # Every loop over candidates goes through find()/claim(), and each
        # of their callers passes a window, never the domain size.
        loops = [enclosing_fn(self.domain, m.start()) for m in re.finditer(r"bpf_loop\(", self.domain)]
        self.assertEqual(sorted(loops), ["claim", "find"])
        for name in ("existing", "allocate"):
            body = fn_body(self.domain, name)
            self.assertIn("let count = s.domain.window();", body, name)
            self.assertIn("Search::new(", body, name)
        self.assertNotRegex(self.domain, r"(find|claim)\(&mut s,\s*s\.domain\.count")
        self.assertNotIn("bpf_loop(\n            s.domain.count", self.domain)

    def test_discovery_and_allocation_share_the_scattered_window(self):
        self.assertIn("scattered: true,", fn_body(self.domain, "new"))
        self.assertIn("self.domain.probe(index)", fn_body(self.domain, "port"))
        for callback in ("find_owned", "reserve"):
            self.assertIn("let port = s.port(index);", fn_body(self.domain, callback), callback)
        # The replicated window alone walks linearly.
        linear = fn_body(self.domain, "linear")
        self.assertIn("s.scattered = false;", linear)
        self.assertEqual(self.domain.count("s.scattered = false"), 1)

    def test_masquerade_searches_the_window_before_claiming(self):
        body = fn_body(self.main, "masquerade_egress")
        search = body.index("napt_domain::existing(&flow, wan_ip, &layout)")
        claim = body.index("napt_domain::allocate(&flow, wan_ip, &layout, bytes)")
        self.assertLess(search, claim)
        self.assertLess(body.index("let standalone = napt_domain::enabled();"), search)

    def test_only_known_helpers_write_nat_state(self):
        writers = set()
        for path in sorted(SOURCES.glob("*.rs")):
            text = path.read_text()
            for match in re.finditer(r"CONNTRACK\s*\.\s*insert\s*\(", text):
                writers.add((path.name, enclosing_fn(text, match.start())))
        self.assertEqual(writers, {("main.rs", "publish_nat"), ("main.rs", "claim_hairpin_port"),
                                   ("main.rs", "insert_masquerade_binding")})
        callers = set()
        for path in sorted(SOURCES.glob("*.rs")):
            text = path.read_text()
            for match in re.finditer(r"(?<!fn )insert_masquerade_binding\s*\(", text):
                callers.add((path.name, enclosing_fn(text, match.start())))
        self.assertEqual(callers, {("main.rs", "claim_masquerade_nat"), ("napt_domain.rs", "reserve")})


if __name__ == "__main__":
    unittest.main()
