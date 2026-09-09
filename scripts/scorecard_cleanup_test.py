"""Regression tests for classic-scorecard process ownership.

These tests pin the env-marker ownership model. A finished shard must not
SIGTERM a sibling shard or another invocation from the same tree.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
HELPER = SCRIPTS / "scorecard-proc.sh"
RUNNER = SCRIPTS / "classic-scorecard.sh"


def _linux_proc() -> bool:
    return os.path.isdir("/proc") and os.uname().sysname == "Linux"


def _running(pid: int) -> bool:
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().split()[2]
    except (FileNotFoundError, IndexError, PermissionError):
        return False
    return state not in ("Z", "X")


def _wait_stopped(pid: int) -> None:
    for _ in range(1_000_000):
        if not _running(pid):
            return
    raise AssertionError(f"pid {pid} still running after cleanup")


def _wait_comm(pid: int, name: str) -> None:
    for _ in range(1_000_000):
        if not _running(pid):
            raise AssertionError(f"pid {pid} exited before comm={name!r}")
        try:
            comm = pathlib.Path(f"/proc/{pid}/comm").read_text().strip()
        except FileNotFoundError:
            raise AssertionError(f"pid {pid} vanished before comm={name!r}") from None
        if comm == name:
            return
    raise AssertionError(f"pid {pid} never reached comm={name!r}")


def _spawn_marked(
    *,
    argv0: str,
    binary: str,
    run_id: str,
    shard: str,
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.Popen[bytes], int]:
    ready_r, ready_w = os.pipe()
    code = "\n".join(
        [
            "import os, sys",
            "fd = int(sys.argv[1])",
            "os.write(fd, b'ready')",
            "os.close(fd)",
            "os.execv(sys.argv[2], [sys.argv[3], '3600'])",
        ]
    )
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    env["SOCAT_SCORECARD_RUN"] = run_id
    env["SOCAT_SCORECARD_SHARD"] = shard
    proc = subprocess.Popen(
        [sys.executable, "-c", code, str(ready_w), binary, argv0],
        pass_fds=(ready_w,),
        env=env,
    )
    os.close(ready_w)
    if os.read(ready_r, 16) != b"ready":
        proc.kill()
        raise AssertionError("worker did not signal readiness")
    os.close(ready_r)
    return proc, proc.pid


def _cleanup(run_id: str, shard: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-c",
            f'''
set -euo pipefail
. "{HELPER}"
export SOCAT_SCORECARD_CLEANUP_GRACE=0
scorecard_cleanup_owned "{run_id}" "{shard}"
''',
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _reap(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.kill()
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


class ScorecardScriptWiringTest(unittest.TestCase):
    def test_runner_does_not_use_path_based_pgrep_cleanup(self) -> None:
        runner = RUNNER.read_text()
        helper = HELPER.read_text()
        self.assertIn('source=scorecard-proc.sh', runner)
        self.assertIn("scorecard_cleanup_owned", runner)
        self.assertIn('cleanup_orphans "$id"', runner)
        self.assertIn('export SOCAT_SCORECARD_SHARD="$id"', runner)
        self.assertIn("SOCAT_SCORECARD_RUN", runner)
        self.assertNotIn("pgrep -x socat", runner)
        self.assertNotIn("pgrep -x socat", helper)
        self.assertNotIn("$ROOT/socat", helper)
        # SHARD must not be exported on the main process (would suicide on cleanup).
        export_line = [
            line
            for line in runner.splitlines()
            if line.startswith("export TEST_SH ")
        ]
        self.assertEqual(len(export_line), 1)
        self.assertNotIn("SOCAT_SCORECARD_SHARD", export_line[0])
        self.assertIn("SOCAT_SCORECARD_RUN", export_line[0])


@unittest.skipUnless(_linux_proc(), "requires Linux /proc for environment-based process ownership")
class CleanupOwnershipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        # These fixtures rename the executable; multicall dispatchers cannot
        # select sleep from a socat argv[0]. Ubuntu provides GNU as gnusleep.
        sleep = shutil.which("gnusleep") or shutil.which("sleep") or "/bin/sleep"
        self.sleep = shutil.copy(sleep, self.root / "sleepbin")
        os.chmod(self.sleep, 0o755)
        self.socat = self.root / "socat"
        shutil.copy(self.sleep, self.socat)
        os.chmod(self.socat, 0o755)
        self.run_id = f"scorecard-test-{os.getpid()}-{self.root.name}"
        self.procs: list[subprocess.Popen[bytes]] = []

    def tearDown(self) -> None:
        for proc in self.procs:
            _reap(proc)
        try:
            _cleanup(self.run_id)
        except subprocess.CalledProcessError:
            pass
        self.temp.cleanup()

    def _owned(self, shard: str, *, argv0: pathlib.Path | None = None, binary: str | None = None):
        proc, pid = _spawn_marked(
            argv0=str(argv0 or self.socat),
            binary=binary or str(self.socat),
            run_id=self.run_id,
            shard=shard,
        )
        self.procs.append(proc)
        return proc, pid

    def test_finished_shard_does_not_kill_ready_sibling(self) -> None:
        _, pid1 = self._owned("1")
        _, pid2 = self._owned("2")
        _wait_comm(pid1, "socat")
        _wait_comm(pid2, "socat")
        self.assertTrue(_running(pid1))
        self.assertTrue(_running(pid2))

        _cleanup(self.run_id, "1")

        _wait_stopped(pid1)
        self.assertTrue(_running(pid2), "ready sibling shard must keep its process")

        _cleanup(self.run_id, "2")
        _wait_stopped(pid2)

    def test_owned_timeout_leftovers_are_cleaned(self) -> None:
        _, pid = self._owned("7")
        _wait_comm(pid, "socat")
        self.assertTrue(_running(pid))
        _cleanup(self.run_id, "7")
        _wait_stopped(pid)

    def test_external_binary_is_still_owned(self) -> None:
        """SOCAT may point at a foreign binary; ownership is the env markers."""
        external = self.root / "foreign-socat"
        shutil.copy(self.sleep, external)
        os.chmod(external, 0o755)
        _, pid = self._owned("4", argv0=str(external), binary=str(external))
        self.assertTrue(_running(pid))
        _cleanup(self.run_id, "4")
        _wait_stopped(pid)

    def test_shard_1_does_not_match_shard_10(self) -> None:
        _, pid1 = self._owned("1")
        _, pid10 = self._owned("10")
        _wait_comm(pid1, "socat")
        _wait_comm(pid10, "socat")
        _cleanup(self.run_id, "1")
        _wait_stopped(pid1)
        self.assertTrue(_running(pid10))
        _cleanup(self.run_id, "10")
        _wait_stopped(pid10)


if __name__ == "__main__":
    unittest.main()
