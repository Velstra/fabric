"""Writer-inventory guards; not a concurrent packet correctness proof."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FN = re.compile(r'^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+(\w+)', re.M)


def enclosing_fn(text, offset):
    """Name of the last `fn` declared before `offset`."""
    names = [m.group(1) for m in FN.finditer(text, 0, offset)]
    return names[-1] if names else None


def fn_body(text, name):
    """Source from `fn name(` up to the next top-level `fn`."""
    start = re.search(r"\bfn\s+" + name + r"\s*[(<]", text).start()
    following = FN.search(text, start + 1)
    nxt = FN.search(text, following.end()) if following and following.start() == start else following
    return text[start: nxt.start() if nxt else len(text)]


class SearchBoundWiring(unittest.TestCase):
    # Every function allowed to write NAT state (CONNTRACK). Each guarded
    # writer refuses while a complete-domain search holds the displacement
    # bound; the marked claim is reachable only from guarded callers.
    GUARDED_WRITERS = ("publish_nat", "claim_hairpin_port")
    MARKED_CLAIM = "claim_marked_masquerade_nat"

    def test_only_guarded_helpers_publish_nat_state(self):
        sources = ROOT / "velstra-ebpf/src"
        writers = []
        for path in sorted(sources.glob("*.rs")):
            text = path.read_text()
            for match in re.finditer(r"CONNTRACK\s*\.\s*insert\s*\(", text):
                writers.append((path.name, enclosing_fn(text, match.start())))
        self.assertEqual(
            sorted(set(writers)),
            sorted({("main.rs", name) for name in self.GUARDED_WRITERS + (self.MARKED_CLAIM,)}),
        )
        main = (sources / "main.rs").read_text()
        for name in self.GUARDED_WRITERS:
            body = fn_body(main, name)
            self.assertLess(body.index("napt_domain::unbounded()"), body.index("CONNTRACK"), name)
        legacy = fn_body(main, "claim_masquerade_nat")
        self.assertLess(legacy.index("napt_domain::unbounded()"), legacy.index(self.MARKED_CLAIM + "("))
        callers = []
        for path in sorted(sources.glob("*.rs")):
            text = path.read_text()
            for match in re.finditer(r"(?<!fn )" + self.MARKED_CLAIM + r"\s*\(", text):
                name = enclosing_fn(text, match.start())
                if name != self.MARKED_CLAIM:
                    callers.append((path.name, name))
        self.assertEqual(sorted(callers), [("main.rs", "claim_masquerade_nat"), ("napt_domain.rs", "reserve")])

    def test_domain_marks_before_claim_and_rechecks_after_miss(self):
        source = (ROOT / "velstra-ebpf/src/napt_domain.rs").read_text()
        reserve = source.split('fn reserve(', 1)[1].split('fn search(', 1)[0]
        self.assertLess(reserve.index("note(marker)"), reserve.index("claim_marked_masquerade_nat("))
        self.assertIn("s.domain.first == 32768 && s.domain.count == 32768", reserve)
        search = source.split('fn search(', 1)[1].split('pub fn existing(', 1)[0]
        self.assertIn("if bound() != before", search)
        self.assertIn("s.domain.count,", search)

    def test_metadata_has_no_eviction_or_reset_writer(self):
        source = (ROOT / "velstra-ebpf/src/napt_domain.rs").read_text()
        self.assertIn("NAPT_SEARCH: Array<u64> = Array::with_max_entries(1, 0)", source)
        self.assertIn("atomic_or::<u64, { core::intrinsics::AtomicOrdering::SeqCst }>", source)
        for path in (ROOT / "velstra-app/src").rglob("*.rs"):
            self.assertNotIn('"NAPT_SEARCH"', path.read_text(), str(path))


if __name__ == "__main__":
    unittest.main()
