"""Execute the production claim initializer with deterministic map/clock mocks.

Requires rustc on PATH. The real common types and the function's exact source
are compiled, not a Python translation of the initialization algorithm.
Kernel publication and allocator behavior are covered by the packet suites.
"""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
use std::cell::{Cell, RefCell, UnsafeCell};
use velstra_common::{FlowKey, FlowState};
const BPF_NOEXIST: u32 = 1;
const NOW: u64 = 123456789;
thread_local! {
    static SCRATCH: UnsafeCell<FlowState> = const { UnsafeCell::new(FlowState::masquerade([0; 4], 0)) };
    static MISSING: Cell<bool> = const { Cell::new(false) };
    static ERROR: Cell<i32> = const { Cell::new(0) };
    static WRITTEN: RefCell<Option<(FlowKey, FlowState, u64)>> = const { RefCell::new(None) };
}
struct Scratch;
static NAT_INSERT_SCRATCH: Scratch = Scratch;
impl Scratch {
    fn get_ptr_mut(&self, index: u32) -> Option<*mut FlowState> {
        assert_eq!(index, 0);
        if MISSING.get() { None } else { Some(SCRATCH.with(UnsafeCell::get)) }
    }
}
struct Conntrack;
static CONNTRACK: Conntrack = Conntrack;
impl Conntrack {
    fn insert(&self, key: &FlowKey, state: &FlowState, flags: u64) -> Result<(), i32> {
        assert_eq!(flags, BPF_NOEXIST as u64);
        WRITTEN.replace(Some((*key, *state, flags)));
        match ERROR.get() { 0 => Ok(()), error => Err(error) }
    }
}
unsafe fn bpf_ktime_get_ns() -> u64 { NOW }

FUNCTION

#[test]
fn unchanged_fields_accounting_padding_and_publication_errors() {
    let key = FlowKey::new(17, [192, 0, 2, 1], [198, 51, 100, 2], 2000, 3000, 17);
    for packets in [0, 1, u64::MAX - 1, u64::MAX] {
        for bytes in [0, 1, u64::MAX - 1, u64::MAX] {
            for increment in [0, 1, 1500, u64::MAX] {
                for error in [0, -17, -12] {
                    let original = FlowState {
                        nat_ip: [1, 2, 3, 4], nat2_ip: [5, 6, 7, 8],
                        nat_port: 0xabcd, nat2_port: 0x1234, flags: 0x9876, _pad: 0xdead,
                        packets, bytes, last_seen_ns: u64::MAX, age_ns: 987654321,
                    };
                    let mut expected = original;
                    expected.account(increment);
                    expected.last_seen_ns = NOW;
                    expected.age_ns = 0;
                    ERROR.set(error);
                    WRITTEN.replace(None);
                    assert_eq!(insert_masquerade_binding(&key, &original, increment), error);
                    let actual = WRITTEN.take().expect("claim must attempt publication");
                    assert_eq!(actual.0, key);
                    assert_eq!(actual.1, expected);
                    assert_eq!(actual.2, BPF_NOEXIST as u64);
                    assert_eq!(original.last_seen_ns, u64::MAX);
                    assert_eq!(original.age_ns, 987654321);
                }
            }
        }
    }
    MISSING.set(true);
    WRITTEN.replace(None);
    assert_eq!(insert_masquerade_binding(&key, &FlowState::masquerade([0; 4], 0), 1), -12);
    assert!(WRITTEN.take().is_none());
}
'''


class NatClaimInitialization(unittest.TestCase):
    def test_actual_rust_function_preserves_old_result(self):
        source = (ROOT / "velstra-ebpf/src/main.rs").read_text()
        function = "fn insert_masquerade_binding(" + source.split(
            "fn insert_masquerade_binding(", 1
        )[1].split("\n#[repr(C)]", 1)[0]
        rustc = os.environ.get("RUSTC", "rustc")
        with tempfile.TemporaryDirectory(prefix="fabric-claim-contract-") as temporary:
            directory = Path(temporary)
            common = directory / "libvelstra_common.rlib"
            subprocess.run([rustc, "--edition=2024", "--crate-type=rlib", "--crate-name",
                            "velstra_common", str(ROOT / "velstra-common/src/lib.rs"),
                            "-o", str(common)], check=True)
            harness = directory / "claim.rs"
            harness.write_text(HARNESS.replace("FUNCTION", function))
            binary = directory / "claim-tests"
            subprocess.run([rustc, "--edition=2024", "--test", str(harness), "--extern",
                            f"velstra_common={common}", "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
