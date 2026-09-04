"""Tests for scripts/scorecard-parse.py."""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parent / "scorecard-parse.py"
SPEC = importlib.util.spec_from_file_location("scorecard_parse", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load scorecard-parse.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def parse_shard(text: str, *, summary: str | None = None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        (out / "shard-0.log").write_text(text)
        if summary is not None:
            (out / "shard-0.summary").write_text(summary)
        return MODULE.parse_logs(out)


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


class DottedNameTest(unittest.TestCase):
    def test_dotted_names_keep_ok_failed_and_cant(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 375 OPENSSL_METHOD_TLS1.1: test OpenSSL method TLS1.1... OK",
                    "test 376 OPENSSL_METHOD_TLS1.2: test OpenSSL method TLS1.2... FAILED: handshake",
                    "test 378 OPENSSL_METHOD_DTLS1.2: test OpenSSL method DTLS1.2... Option openssl-method not available",
                    "Summary: 608 tests, 3 selected; 1 ok, 1 failed, 1 could not be performed",
                    "CANT: 378",
                    "FAILED: 376",
                ]
            )
            + "\n"
        )
        tls11 = parsed["tests"]["375"]
        tls12 = parsed["tests"]["376"]
        dtls = parsed["tests"]["378"]
        self.assertEqual(tls11["name"], "OPENSSL_METHOD_TLS1.1")
        self.assertEqual(tls11["status"], "OK")
        self.assertEqual(tls12["name"], "OPENSSL_METHOD_TLS1.2")
        self.assertEqual(tls12["status"], "FAILED")
        self.assertNotIn("conflict", tls12)
        self.assertEqual(dtls["name"], "OPENSSL_METHOD_DTLS1.2")
        self.assertEqual(dtls["status"], "CANT")
        self.assertEqual(parsed["summary"]["ok"], 1)
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["cant"], 1)


class UpstreamListConflictTest(unittest.TestCase):
    def test_printed_failed_upstream_cant_preserves_conflict(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 304 IOCTL_VOID: test the ioctl-void option... FAILED (rc2=0, because root?)",
                    "Summary: 608 tests, 1 selected; 0 ok, 0 failed, 1 could not be performed",
                    "CANT: 304",
                ]
            )
            + "\n"
        )
        test = parsed["tests"]["304"]
        self.assertEqual(test["status"], "CANT")
        self.assertEqual(test["printed_status"], "FAILED")
        self.assertEqual(test["detail"], "(rc2=0, because root?)")
        self.assertIn("FAILED (rc2=0, because root?)", test["raw"])
        self.assertEqual(
            test["conflict"],
            "printed FAILED; upstream CANT list includes this test",
        )
        self.assertEqual(parsed["summary"]["cant"], 1)
        self.assertEqual(parsed["summary"]["failed"], 0)
        self.assertEqual(len(parsed["summary"]["conflicts"]), 1)
        self.assertEqual(parsed["summary"]["conflicts"][0]["id"], 304)

    def test_genuine_failed_remains_failed(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 228 TCP4SERVICE: TCP4 service... FAILED: diff:",
                    "Summary: 608 tests, 1 selected; 0 ok, 1 failed, 0 could not be performed",
                    "FAILED: 228",
                ]
            )
            + "\n"
        )
        test = parsed["tests"]["228"]
        self.assertEqual(test["status"], "FAILED")
        self.assertNotIn("conflict", test)
        self.assertNotIn("printed_status", test)
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["conflicts"], [])

    def test_printed_failed_without_lists_stays_failed(self) -> None:
        parsed = parse_shard(
            "test 10 SOMETHING: something... FAILED: boom\n"
            "Summary: 608 tests, 1 selected; 0 ok, 1 failed, 0 could not be performed\n"
        )
        test = parsed["tests"]["10"]
        self.assertEqual(test["status"], "FAILED")
        self.assertNotIn("conflict", test)
        self.assertEqual(parsed["summary"]["failed"], 1)


class IncompleteShardTest(unittest.TestCase):
    def test_shard_timeout_does_not_downgrade_printed_failed(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 304 IOCTL_VOID: test the ioctl-void option... FAILED (rc2=0, because root?)",
                    "test 305 SETSOCKOPT: test the setsockopt option...",
                    "SHARD TIMEOUT",
                    "CANT: 304",
                ]
            )
            + "\n",
            summary="shard-0 timeout 124 leftover",
        )
        ioctl = parsed["tests"]["304"]
        self.assertEqual(ioctl["status"], "FAILED")
        self.assertNotIn("conflict", ioctl)
        self.assertEqual(parsed["tests"]["305"]["status"], "TIMEOUT")
        self.assertEqual(parsed["summary"]["shard_timeouts"], [0])
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["conflicts"], [])

    def test_missing_summary_does_not_override_printed_failed(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 50 WEIRD: weird case... FAILED: boom",
                    "CANT: 50",
                ]
            )
            + "\n"
        )
        test = parsed["tests"]["50"]
        self.assertEqual(test["status"], "FAILED")
        self.assertNotIn("conflict", test)
        self.assertNotIn("printed_status", test)
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["cant"], 0)
        self.assertEqual(parsed["summary"]["conflicts"], [])
        self.assertEqual(parsed["summary"]["shard_timeouts"], [])

    def test_non_timeout_abort_does_not_override_printed_failed(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 304 IOCTL_VOID: test the ioctl-void option... FAILED (rc2=0, because root?)",
                    "Summary: (no summary, exit=1) range 1-608",
                    "CANT: 304",
                ]
            )
            + "\n",
            summary="0 1 608 1 0 0 0 0 1",
        )
        test = parsed["tests"]["304"]
        self.assertEqual(test["status"], "FAILED")
        self.assertNotIn("conflict", test)
        self.assertNotIn("printed_status", test)
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["conflicts"], [])
        self.assertEqual(parsed["summary"]["shard_timeouts"], [])


class ContradictorySummaryTest(unittest.TestCase):
    def test_id_in_both_cant_and_failed_is_reporting_error(self) -> None:
        parsed = parse_shard(
            "\n".join(
                [
                    "test 50 WEIRD: weird case... FAILED: boom",
                    "Summary: 608 tests, 1 selected; 0 ok, 1 failed, 1 could not be performed",
                    "CANT: 50",
                    "FAILED: 50",
                ]
            )
            + "\n"
        )
        test = parsed["tests"]["50"]
        self.assertEqual(test["status"], "FAILED")
        self.assertNotIn("conflict", test)
        self.assertEqual(
            test["reporting_error"],
            "upstream CANT and FAILED lists both include this test",
        )
        self.assertEqual(len(parsed["summary"]["reporting_errors"]), 1)
        self.assertEqual(parsed["summary"]["reporting_errors"][0]["id"], 50)
        self.assertEqual(parsed["summary"]["conflicts"], [])


def _run_parse_cli(
    text: str, *, summary: str | None = None
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        (out / "shard-0.log").write_text(text)
        if summary is not None:
            (out / "shard-0.summary").write_text(summary)
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT), str(out)],
            capture_output=True,
            text=True,
            check=False,
        )


class ParseCliExitTest(unittest.TestCase):
    def test_reporting_errors_exit_nonzero_without_regression_flag(self) -> None:
        completed = _run_parse_cli(
            "\n".join(
                [
                    "test 50 WEIRD: weird case... FAILED: boom",
                    "Summary: 608 tests, 1 selected; 0 ok, 1 failed, 1 could not be performed",
                    "CANT: 50",
                    "FAILED: 50",
                ]
            )
            + "\n"
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("REPORTING ERRORS", completed.stdout)

    def test_ioctl_void_conflict_exits_zero(self) -> None:
        completed = _run_parse_cli(
            "\n".join(
                [
                    "test 304 IOCTL_VOID: test the ioctl-void option... FAILED (rc2=0, because root?)",
                    "Summary: 608 tests, 1 selected; 0 ok, 0 failed, 1 could not be performed",
                    "CANT: 304",
                ]
            )
            + "\n"
        )
        self.assertEqual(completed.returncode, 0)
        self.assertIn("CONFLICTS", completed.stdout)


class HarnessFailureTest(unittest.TestCase):
    def test_empty_selection_with_genuine_summary_is_success(self) -> None:
        text = (
            "Summary: 608 tests, 0 selected; 0 ok, 0 failed, 0 could not be performed\n"
        )
        parsed = parse_shard(text, summary="0 1 608 0 0 0 0 0 0")
        self.assertEqual(parsed["summary"]["total_recorded"], 0)
        self.assertEqual(parsed["summary"]["startup_failed"], [])
        self.assertEqual(parsed["summary"]["incomplete_aborts"], [])
        completed = _run_parse_cli(text, summary="0 1 608 0 0 0 0 0 0")
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn("STARTUP FAILED", completed.stdout)

    def test_failed_tests_with_genuine_summary_are_not_startup_failure(self) -> None:
        text = "\n".join(
            [
                "test 228 TCP4SERVICE: TCP4 service... FAILED: diff:",
                "Summary: 608 tests, 1 selected; 0 ok, 1 failed, 0 could not be performed",
                "FAILED: 228",
            ]
        ) + "\n"
        completed = _run_parse_cli(text, summary="0 1 608 1 0 1 0 0 1")
        self.assertEqual(completed.returncode, 0)
        self.assertNotIn("STARTUP FAILED", completed.stdout)
        parsed = parse_shard(text, summary="0 1 608 1 0 1 0 0 1")
        self.assertEqual(parsed["summary"]["failed"], 1)
        self.assertEqual(parsed["summary"]["startup_failed"], [])

    def test_nonzero_exit_before_results_is_startup_failure(self) -> None:
        text = (
            "option type \"IP_ADD_SOURCE_MEMBERSHIP\" inconsistency:\n"
            "ip-add-source-membership\n"
        )
        parsed = parse_shard(text, summary="0 1 608 1 0 0 0 0 0")
        self.assertEqual(parsed["summary"]["startup_failed"], [0])
        self.assertEqual(parsed["summary"]["total_recorded"], 0)
        self.assertTrue(parsed["summary"]["harness_notes"])
        self.assertIn("ip-add-source-membership", parsed["summary"]["harness_notes"][0])
        completed = _run_parse_cli(text, summary="0 1 608 1 0 0 0 0 0")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("STARTUP FAILED", completed.stdout)
        self.assertIn("ip-add-source-membership", completed.stdout)

    def test_incomplete_abort_preserves_printed_results_and_fails_parse(self) -> None:
        text = "\n".join(
            [
                "test 50 WEIRD: weird case... FAILED: boom",
                "CANT: 50",
            ]
        ) + "\n"
        parsed = parse_shard(text, summary="0 1 608 1 0 0 0 0 1")
        self.assertEqual(parsed["tests"]["50"]["status"], "FAILED")
        self.assertEqual(parsed["summary"]["incomplete_aborts"], [0])
        self.assertEqual(parsed["summary"]["startup_failed"], [])
        completed = _run_parse_cli(text, summary="0 1 608 1 0 0 0 0 1")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("INCOMPLETE", completed.stdout)

    def test_shard_timeout_is_not_startup_failure(self) -> None:
        text = "\n".join(
            [
                "test 305 SETSOCKOPT: test the setsockopt option...",
                "SHARD TIMEOUT",
            ]
        ) + "\n"
        parsed = parse_shard(text, summary="0 1 608 124 0 0 0 0 0")
        self.assertEqual(parsed["summary"]["shard_timeouts"], [0])
        self.assertEqual(parsed["summary"]["startup_failed"], [])
        self.assertEqual(parsed["summary"]["incomplete_aborts"], [])
        completed = _run_parse_cli(text, summary="0 1 608 124 0 0 0 0 0")
        self.assertEqual(completed.returncode, 0)


if __name__ == "__main__":
    unittest.main()
