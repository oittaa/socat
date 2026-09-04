#!/usr/bin/env python3
"""Deterministic regression test for scorecard process ownership and sibling shard survival."""

from __future__ import annotations

import os
import pathlib
import platform
import subprocess
import sys
import unittest

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
BASH_TEST = SCRIPT_DIR / "classic-scorecard-ownership-test.sh"


class ScorecardOwnershipTest(unittest.TestCase):
    def test_sibling_shard_survival_and_legacy_cleanup_failure(self) -> None:
        if platform.system() != "Linux":
            raise unittest.SkipTest("requires Linux /proc filesystem for process ownership isolation test")
        if not BASH_TEST.is_file():
            self.fail(f"missing test script: {BASH_TEST}")

        res = subprocess.run(
            ["bash", str(BASH_TEST)],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            sys.stderr.write(res.stderr)
            sys.stdout.write(res.stdout)
        self.assertEqual(res.returncode, 0, f"bash test failed with output:\n{res.stdout}\n{res.stderr}")
        self.assertIn("ALL TESTS PASSED: process ownership isolation verified.", res.stdout)


if __name__ == "__main__":
    unittest.main()
