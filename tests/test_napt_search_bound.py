"""Writer-inventory guards; not a concurrent packet correctness proof."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SearchBoundWiring(unittest.TestCase):
    def test_only_guarded_helpers_publish_nat_state(self):
        sources = ROOT / "velstra-ebpf/src"
        writers = []
        for path in sources.glob("*.rs"):
            writers += [path.name] * len(re.findall(r"CONNTRACK\s*\.\s*insert\s*\(", path.read_text()))
        self.assertEqual(writers, ["main.rs", "main.rs"])
        main = (sources / "main.rs").read_text()
        generic = main.split("fn insert_nat(", 1)[1].split("fn claim_masquerade_nat(", 1)[0]
        self.assertLess(generic.index("napt_domain::unbounded()"), generic.index("CONNTRACK.insert"))
        legacy = main.split("fn claim_masquerade_nat(", 1)[1].split("fn claim_marked_masquerade_nat(", 1)[0]
        self.assertLess(legacy.index("napt_domain::unbounded()"), legacy.index("claim_marked_masquerade_nat("))

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
