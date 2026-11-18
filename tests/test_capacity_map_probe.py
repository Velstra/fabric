"""Pure host fixture boundaries, not actual kernel occupancy qualification."""

import importlib.util
import ctypes
import errno
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location("capacity_map_probe", Path(__file__).with_name("capacity_map_probe.py"))
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class CapacityProbeTests(unittest.TestCase):
    def test_exact_reviewed_layout_and_stale_value(self):
        self.assertEqual(P.KEY.size, 44)
        self.assertEqual(P.VALUE.size, 24)
        self.assertEqual(P.VALUE.unpack(P.STALE_VALUE), (0, 604800000000000, 3, 0))
        keys = {P.fixture_key(i, 123) for i in range(65536)}
        self.assertEqual(len(keys), 65536)
        self.assertNotEqual(P.fixture_key(0, 123), P.fixture_key(0, 124))

    def test_wrong_maps_abi_capacity_or_identity_are_refused(self):
        good = dict(id=123, name="FW_FLOWS", type="lru_hash", bytes_key=44, bytes_value=24, max_entries=65536)
        P.validate_metadata(good, 123)
        for key, value in (("id", 124), ("name", "CONNTRACK"), ("type", "hash"),
                           ("bytes_key", 48), ("bytes_value", 32), ("max_entries", 1024)):
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                P.validate_metadata(dict(good, **{key: value}), 123)

    def test_mutation_needs_explicit_permission_before_any_kernel_or_file_io(self):
        class Args:
            allow_disposable_map_mutation = False
        with self.assertRaisesRegex(RuntimeError, "explicit disposable"):
            P.execute(Args())

    def test_cleanup_requires_exact_bounded_ownership_and_narrow_path(self):
        good = dict(version=1, map_id=123, count=52429, nonce=321)
        P.validate_state(good, 123)
        for change in (dict(count=0), dict(count=65537), dict(count=True), dict(map_id=124),
                       dict(nonce=-1), dict(version=True), dict(extra="foreign")):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                P.validate_state(dict(good, **change), 123)
        self.assertEqual(P.state_path("/run/qa-capacity-owned.json"), Path("/run/qa-capacity-owned.json"))
        for path in ("/tmp/qa-capacity-owned.json", "/run/foreign.json", "/run/qa-capacity-dir/state.json"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                P.state_path(path)

    def test_insertion_is_full_width_noexist_and_never_downgrades_to_overwrite(self):
        kernel = P.Kernel.__new__(P.Kernel)
        kernel.fd = 123
        calls = []
        def capture(command, attr):
            calls.append((command, attr.map_fd, attr.flags,
                          ctypes.string_at(attr.key, P.KEY.size),
                          ctypes.string_at(attr.value, P.VALUE.size)))
        kernel.call = capture
        key = P.fixture_key(1234, 5678)
        kernel.insert(key, P.STALE_VALUE)
        self.assertEqual(calls, [(2, 123, 1, key, P.STALE_VALUE)])
        def exists(command, attr):
            calls.append((command, attr.flags))
            raise OSError(errno.EEXIST, "already exists")
        kernel.call = exists
        with self.assertRaises(OSError):
            kernel.insert(key, P.STALE_VALUE)
        self.assertEqual(calls[-1], (2, 1))
        self.assertEqual(len(calls), 2, "a conflict must not retry with BPF_ANY")

    def test_batch_update_and_invalid_widths_are_rejected_before_kernel_io(self):
        kernel = P.Kernel.__new__(P.Kernel)
        kernel.fd = 123
        def forbidden(*args):
            raise AssertionError("unexpected kernel operation")
        kernel.call = forbidden
        for command in (0, 2, 24, 25, 26, 28):
            with self.subTest(command=command), self.assertRaises(RuntimeError):
                kernel.batch(command, [P.fixture_key(0, 1)])
        for keys in ([], [b"short"], [P.fixture_key(0, 1)] * (P.CHUNK + 1)):
            with self.assertRaises(RuntimeError):
                kernel.batch(27, keys)
        with self.assertRaises(RuntimeError):
            kernel.insert(b"short", P.STALE_VALUE)
        with self.assertRaises(RuntimeError):
            kernel.insert(P.fixture_key(0, 1), b"short")


if __name__ == "__main__":
    unittest.main()
