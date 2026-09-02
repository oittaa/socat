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
    def test_update_script_supports_passwordless_sudo_docker(self) -> None:
        updater = (SCRIPT.parent / "update-scorecard.sh").read_text()
        self.assertIn('sudo -n "$docker_bin" version', updater)
        self.assertIn("temporary wrapper; no account changes", updater)

    def test_docker_wrapper_forwards_host_loss_allowlist(self) -> None:
        wrapper = (SCRIPT.parent / "docker-classic-scorecard.sh").read_text()
        self.assertIn('-e ALLOW_LOST="${ALLOW_LOST:-', wrapper)

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


class PublishTest(unittest.TestCase):
    README = """# Scorecard baselines

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (host) | 475 | 24 | 103 |
| classic 1.8.1.3 (Docker, root) | 1 | 2 | 3 |
| go (this tree, host) | 471 | 7 | 127 |
| go (this tree, Docker, root, privileged, `--internet`) | 4 | 5 | 6 |

Vs classic Docker, Go has 4 OK against 1 classic OK (`parity_gap_total` 7 in `go-vs-classic-docker-gaps.json`).
"""

    def test_publishes_all_artifacts_and_updates_mechanical_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = pathlib.Path(tempdir)
            classic_dir = root / "work" / "classic"
            go_dir = root / "work" / "go"
            destination = root / "published"
            readme = destination / "README.md"
            classic = result("classic", {1: "FAILED", 2: "CANT"})
            go = result("go", {1: "FAILED", 2: "CANT", 3: "FAILED"})
            write_json(classic_dir / "classic-docker-baseline.json", classic)
            (classic_dir / "classic-docker-baseline.summary.txt").write_text("classic\n")
            write_json(
                classic_dir / "host-vs-docker-verify.json",
                {
                    "host_ok": 2,
                    "host_ok_ran": 2,
                    "still_ok": 1,
                    "lost_count": 1,
                    "lost": [{"id": "1"}],
                    "gained_from_cant_count": 1,
                    "gained_from_cant": [{"id": "2"}],
                },
            )
            write_json(go_dir / "go-docker-baseline.json", go)
            (go_dir / "go-docker-baseline.summary.txt").write_text("go\n")
            write_json(
                go_dir / "go-vs-classic-docker-gaps.json",
                {
                    "classic_docker_ok": 498,
                    "go_ok": 497,
                    "parity_fail": [{"id": "3"}],
                    "parity_cant": [],
                    "parity_other": [],
                    "parity_gap_total": 1,
                    "new_ok_vs_classic_docker": [],
                },
            )
            destination.mkdir(parents=True)
            readme.write_text(self.README)

            MODULE.publish(
                classic_dir,
                go_dir,
                destination,
                readme,
                source_revision="abc123-dirty",
            )

            self.assertEqual(
                json.loads((destination / "classic-docker-vs-host.json").read_text())[
                    "lost_count"
                ],
                1,
            )
            text = readme.read_text()
            self.assertIn("| classic 1.8.1.3 (Docker, root) | 498 | 1 | 1 |", text)
            self.assertIn(
                "| go (this tree, Docker, root, privileged, `--internet`) | 497 | 2 | 1 |",
                text,
            )
            self.assertIn("Go has 497 OK against 498\nclassic OK", text)
            self.assertIn("`parity_gap_total` 1", text)

    def test_stale_gap_report_does_not_touch_published_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = pathlib.Path(tempdir)
            classic_dir = root / "classic"
            go_dir = root / "go"
            destination = root / "published"
            destination.mkdir()
            readme = destination / "README.md"
            readme.write_text(self.README)
            original = destination / "go-docker-baseline.json"
            original.write_text("unchanged\n")
            classic = result("classic")
            go = result("go", {1: "FAILED"})
            write_json(classic_dir / "classic-docker-baseline.json", classic)
            (classic_dir / "classic-docker-baseline.summary.txt").write_text("classic\n")
            write_json(
                classic_dir / "host-vs-docker-verify.json",
                {
                    "host_ok": 0,
                    "host_ok_ran": 0,
                    "still_ok": 0,
                    "lost_count": 0,
                    "lost": [],
                    "gained_from_cant_count": 0,
                    "gained_from_cant": [],
                },
            )
            write_json(go_dir / "go-docker-baseline.json", go)
            (go_dir / "go-docker-baseline.summary.txt").write_text("go\n")
            write_json(
                go_dir / "go-vs-classic-docker-gaps.json",
                {
                    "classic_docker_ok": 500,
                    "go_ok": 499,
                    "parity_fail": [],
                    "parity_cant": [],
                    "parity_other": [],
                    "parity_gap_total": 0,
                    "new_ok_vs_classic_docker": [],
                },
            )

            with self.assertRaisesRegex(MODULE.ScorecardError, "stale parity_fail"):
                MODULE.publish(classic_dir, go_dir, destination, readme)
            self.assertEqual(original.read_text(), "unchanged\n")


if __name__ == "__main__":
    unittest.main()
