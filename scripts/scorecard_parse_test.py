"""Tests for scripts/scorecard-parse.py."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parent / "scorecard-parse.py"
SPEC = importlib.util.spec_from_file_location("scorecard_parse", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load scorecard-parse.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ClassifyTailTest(unittest.TestCase):
    def test_diagnostic_before_final_ok_is_ok(self) -> None:
        self.assertEqual(MODULE.classify_tail("!port 174 timed out! OK"), ("OK", ""))

    def test_actual_timeout_is_timeout(self) -> None:
        self.assertEqual(MODULE.classify_tail("TIMEOUT"), ("TIMEOUT", "TIMEOUT"))

    def test_classic_no_result_marker_is_cant(self) -> None:
        self.assertEqual(
            MODULE.classify_tail("NO RESULT"),
            ("CANT", "NO RESULT"),
        )


if __name__ == "__main__":
    unittest.main()
