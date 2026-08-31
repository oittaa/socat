"""Tests for scripts/merge-coverprofile.py."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "merge-coverprofile.py"


def load_merge():
    spec = importlib.util.spec_from_file_location("merge_coverprofile", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load merge-coverprofile.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["merge_coverprofile"] = mod
    spec.loader.exec_module(mod)
    return mod


merge = load_merge()


def profile(mode: str, *rows: str) -> str:
    return "\n".join((f"mode: {mode}", *rows, ""))


class MergeCoverprofileTest(unittest.TestCase):
    def test_set_ors_counts(self):
        raw = profile(
            "set",
            "a.go:1.1,2.1 2 0",
            "a.go:1.1,2.1 2 1",
            "b.go:3.1,4.1 1 1",
            "a.go:1.1,2.1 2 1",
        )
        got = merge.merge_coverprofile(raw)
        self.assertEqual(
            got,
            profile(
                "set",
                "a.go:1.1,2.1 2 1",
                "b.go:3.1,4.1 1 1",
            ),
        )

    def test_count_adds_counts(self):
        raw = profile(
            "count",
            "a.go:1.1,2.1 2 0",
            "a.go:1.1,2.1 2 5",
            "b.go:3.1,4.1 1 1",
            "a.go:1.1,2.1 2 3",
        )
        got = merge.merge_coverprofile(raw)
        self.assertEqual(
            got,
            profile(
                "count",
                "a.go:1.1,2.1 2 8",
                "b.go:3.1,4.1 1 1",
            ),
        )

    def test_atomic_adds_counts(self):
        raw = profile(
            "atomic",
            "a.go:1.1,2.1 2 0",
            "a.go:1.1,2.1 2 5",
            "b.go:3.1,4.1 1 1",
            "a.go:1.1,2.1 2 3",
        )
        got = merge.merge_coverprofile(raw)
        self.assertEqual(
            got,
            profile(
                "atomic",
                "a.go:1.1,2.1 2 8",
                "b.go:3.1,4.1 1 1",
            ),
        )

    def test_inconsistent_numstmt_errors(self):
        raw = profile(
            "atomic",
            "a.go:1.1,2.1 2 1",
            "a.go:1.1,2.1 3 1",
        )
        with self.assertRaisesRegex(ValueError, r"inconsistent NumStmt: changed from 2 to 3"):
            merge.merge_coverprofile(raw)

    def test_missing_mode_errors(self):
        with self.assertRaises(ValueError):
            merge.merge_coverprofile("a.go:1.1,2.1 1 1\n")

    def test_unknown_mode_errors(self):
        with self.assertRaisesRegex(ValueError, r"bad mode line"):
            merge.merge_coverprofile("mode: banana\na.go:1.1,2.1 1 1\n")

    def test_malformed_record_errors(self):
        with self.assertRaises(ValueError):
            merge.merge_coverprofile("mode: atomic\nnot-a-record\n")

    def test_cli_writes_dst(self):
        raw = "mode: atomic\na.go:1.1,2.1 1 0\na.go:1.1,2.1 1 2\n"
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "in.out"
            dst = Path(td) / "out.out"
            src.write_text(raw, encoding="utf-8")
            self.assertEqual(merge.main([str(src), str(dst)]), 0)
            self.assertEqual(dst.read_text(encoding="utf-8"), "mode: atomic\na.go:1.1,2.1 1 2\n")


if __name__ == "__main__":
    unittest.main()
