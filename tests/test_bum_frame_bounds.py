"""Guard the unchanged BUM copy bounds at both tunnel callers."""

from pathlib import Path
import unittest


class BumFrameBounds(unittest.TestCase):
    def test_caller_rejects_the_same_short_frames_as_save(self):
        source = (Path(__file__).resolve().parents[1] / "velstra-ebpf/src/main.rs").read_text()
        helper = source.split("fn save_bum_frame(", 1)[1].split("#[inline", 1)[0]
        self.assertIn("len < EthHdr::LEN as u32 || len > 16384", helper)
        self.assertIn("return Err(());", helper)
        for function in ("bum_vxlan", "bum_srv6"):
            caller = source.split(f"fn {function}(", 1)[1].split("let frame = save_bum_frame", 1)[0]
            lower = caller.index("if frame_len < EthHdr::LEN as u32")
            upper = caller.index("if frame_len > 16384")
            self.assertLess(lower, upper)
            self.assertIn("return Err(());", caller[lower:upper])
            self.assertIn("return Ok(TC_ACT_OK as i32);", caller[upper:])
        # The moved lower-bound guard changes no copy-admissible length,
        # including both boundaries and every possible 16-bit frame length.
        for length in range(65536):
            old_copy = not (length > 16384) and not (length < 14 or length > 16384)
            new_copy = not (length < 14) and not (length > 16384)
            self.assertEqual(old_copy, new_copy, length)


if __name__ == "__main__":
    unittest.main()
