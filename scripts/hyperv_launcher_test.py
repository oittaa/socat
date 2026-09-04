"""Tests for Hyper-V lab check/parity command delivery.

The PowerShell -> ssh.exe -> bash -lc command previously died with a
quote-matching EOF before guest validation. Delivery is now a login-shell
program plus argv (the extracted guest worktree), so quoting is not nested.
"""
from __future__ import annotations

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parent
PS1 = SCRIPTS / "hyperv" / "socat-classic-lab.ps1"
RUNNER = SCRIPTS / "hyperv" / "guest-login-run.sh"
GUEST_CHECK = SCRIPTS / "hyperv" / "guest-check.sh"
PARITY_WORKDIR = "/var/lib/socat-lab/classic-parity"


def _invoke_lab_check_body() -> str:
    text = PS1.read_text()
    start = text.index("function Invoke-LabCheck")
    end = text.index("function Show-LabStatus")
    return text[start:end]


class LabPs1WiringTest(unittest.TestCase):
    def test_check_and_parity_use_login_shell_argv_not_nested_bash_lc(self) -> None:
        body = _invoke_lab_check_body()
        commands = [
            line
            for line in body.splitlines()
            if line.lstrip() and not line.lstrip().startswith("#")
        ]
        self.assertFalse(any("bash -lc" in line for line in commands))
        self.assertNotIn('$checkCommand', body)
        self.assertNotIn('bash -lc `"', PS1.read_text())
        self.assertIn("'bash' '--login'", body)
        self.assertIn("guest-login-run.sh", body)
        self.assertIn("SOCAT_CLASSIC_PARITY_WORKDIR=$ClassicParityWorkdir", body)
        self.assertIn("$remoteDirectory $taskArg", body)
        self.assertIn("'env'", body)
        # Guest cwd, PATH (login shell), output/exit (Invoke-Native), cleanup stay.
        self.assertIn("rm -rf -- '$remoteDirectory' '$remoteArchive'", body)
        self.assertIn("KeepGuestWorktree", body)
        self.assertIn("Invoke-Native ssh.exe", body)
        self.assertIn('$ClassicParityWorkdir = \'%s\'' % PARITY_WORKDIR, PS1.read_text())

    def test_tool_probe_may_still_use_simple_bash_lc(self) -> None:
        probe = PS1.read_text()
        start = probe.index("function Test-LabCheckTools")
        body = probe[start : probe.index("function Invoke-LabCheck")]
        self.assertIn("bash -lc '", body)
        self.assertNotIn('bash -lc `"', body)


class GuestLoginRunTest(unittest.TestCase):
    def _workdir(self, tmp: pathlib.Path) -> pathlib.Path:
        hyperv = tmp / "scripts" / "hyperv"
        hyperv.mkdir(parents=True)
        return tmp

    def test_check_runs_guest_script_in_workdir_and_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            marker = tmp / "check-cwd"
            (tmp / "scripts" / "hyperv" / "guest-check.sh").write_text(
                "#!/usr/bin/env bash\nset -euo pipefail\npwd > check-cwd\necho check-ok\n"
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("check-ok", completed.stdout)
            self.assertEqual(marker.read_text().strip(), str(tmp))

    def test_check_propagates_guest_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            (tmp / "scripts" / "hyperv" / "guest-check.sh").write_text(
                "#!/usr/bin/env bash\necho guest-failed >&2\nexit 7\n"
            )
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "check"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 7)
            self.assertIn("guest-failed", completed.stderr)

    def test_parity_sets_cache_and_runs_make_in_workdir(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            bindir = tmp / "bin"
            bindir.mkdir()
            make = bindir / "make"
            make.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf '%s\\n' \"$PWD\" > make-cwd\n"
                "printf '%s\\n' \"$SOCAT_CLASSIC_PARITY_WORKDIR\" > make-parity\n"
                "printf '%s\\n' \"$*\" > make-args\n"
                "echo parity-ok\n"
            )
            make.chmod(make.stat().st_mode | stat.S_IEXEC)
            env = os.environ.copy()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env.pop("SOCAT_CLASSIC_PARITY_WORKDIR", None)
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "parity"],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("parity-ok", completed.stdout)
            self.assertEqual((tmp / "make-cwd").read_text().strip(), str(tmp))
            self.assertEqual((tmp / "make-parity").read_text().strip(), PARITY_WORKDIR)
            self.assertEqual((tmp / "make-args").read_text().strip(), "classic-parity")

    def test_parity_honors_existing_cache_env(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            bindir = tmp / "bin"
            bindir.mkdir()
            make = bindir / "make"
            make.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$SOCAT_CLASSIC_PARITY_WORKDIR\"\n"
            )
            make.chmod(make.stat().st_mode | stat.S_IEXEC)
            env = os.environ.copy()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            env["SOCAT_CLASSIC_PARITY_WORKDIR"] = "/custom/parity-cache"
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "parity"],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), "/custom/parity-cache")

    def test_parity_propagates_make_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            bindir = tmp / "bin"
            bindir.mkdir()
            make = bindir / "make"
            make.write_text("#!/usr/bin/env bash\nexit 9\n")
            make.chmod(make.stat().st_mode | stat.S_IEXEC)
            env = os.environ.copy()
            env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "parity"],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            self.assertEqual(completed.returncode, 9)

    def test_login_shell_argv_form_matches_launcher(self) -> None:
        """The argv ssh.exe should pass: bash --login runner workdir check."""
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            self._workdir(tmp)
            (tmp / "scripts" / "hyperv" / "guest-check.sh").write_text(
                "#!/usr/bin/env bash\nexit 0\n"
            )
            guest_runner = tmp / "scripts" / "hyperv" / "guest-login-run.sh"
            guest_runner.write_text(RUNNER.read_text())
            completed = subprocess.run(
                [
                    "bash",
                    "--login",
                    str(guest_runner),
                    str(tmp),
                    "check",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_real_guest_check_script_still_runs_make_check(self) -> None:
        text = GUEST_CHECK.read_text()
        self.assertIn("make check", text)
        self.assertIn("go test -count=1 -v ./internal/xio/netopen -run '^TestVSOCK'", text)

    def test_unknown_task_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            tmp = pathlib.Path(raw)
            completed = subprocess.run(
                ["bash", str(RUNNER), str(tmp), "nope"],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
