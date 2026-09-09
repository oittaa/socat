"""Tests for scripts/scorecard-update.py."""
from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parent / "scorecard-update.py"
SPEC = importlib.util.spec_from_file_location("scorecard_update", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load scorecard-update.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def result(label: str, statuses: dict[int, str] | None = None) -> dict:
    selected = statuses or {}
    tests = {}
    for test_id in range(1, 501):
        status = selected.get(test_id, "OK")
        tests[str(test_id)] = {
            "id": test_id,
            "name": f"TEST_{test_id}",
            "status": status,
        }
    counts = {status: 0 for status in MODULE.STATUSES}
    for test in tests.values():
        counts[test["status"]] += 1
    return {
        "meta": {
            "label": label,
            "mode": "classic",
            "val_t": "auto",
            "jobs": "1",
            "shard_timeout": "7200",
            "test_sh_args": "--internet",
            "only": "" if label == "classic" else "functions filan",
            "max_n": "",
            "source_revision": "abc123-dirty",
            "classic_version": "1.8.1.3",
        },
        "summary": {
            "ok": counts["OK"],
            "failed": counts["FAILED"],
            "cant": counts["CANT"],
            "timeout": counts["TIMEOUT"],
            "unknown": counts["UNKNOWN"],
            "total_recorded": len(tests),
            "shard_timeouts": [],
        },
        "tests": tests,
    }


def write_json(path: pathlib.Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


class ValidateResultTest(unittest.TestCase):
    def test_accepts_complete_canonical_run(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / "result.json"
            write_json(path, result("go", {2: "FAILED", 3: "CANT"}))
            doc = MODULE.validate_result(
                path,
                label="go",
                source_revision="abc123-dirty",
            )
            self.assertEqual(doc["summary"]["total_recorded"], 500)

    def test_rejects_timeout_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / "result.json"
            write_json(path, result("classic", {7: "TIMEOUT"}))
            with self.assertRaisesRegex(MODULE.ScorecardError, "incomplete"):
                MODULE.validate_result(path, label="classic")

    def test_rejects_noncanonical_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / "result.json"
            doc = result("classic")
            doc["meta"]["mode"] = "fast"
            write_json(path, doc)
            with self.assertRaisesRegex(MODULE.ScorecardError, "expected 'classic'"):
                MODULE.validate_result(path, label="classic")

    def test_rejects_reporting_errors_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / "result.json"
            doc = result("classic", {50: "FAILED"})
            doc["summary"]["reporting_errors"] = [
                {
                    "id": 50,
                    "name": "WEIRD",
                    "reason": "upstream CANT and FAILED lists both include this test",
                    "printed": "FAILED",
                }
            ]
            write_json(path, doc)
            with self.assertRaisesRegex(MODULE.ScorecardError, "reporting error"):
                MODULE.validate_result(path, label="classic")


if __name__ == "__main__":
    unittest.main()
