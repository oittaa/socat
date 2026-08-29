"""Synthetic tests for scripts/classic-parity.py.

Fixtures are invented by this project. They do not copy official socat
help text or man-page paragraphs.
"""

from __future__ import annotations

import copy
import importlib.util
import io
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parent / "classic-parity.py"


def load_parity():
    spec = importlib.util.spec_from_file_location("classic_parity", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load classic-parity.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["classic_parity"] = mod
    spec.loader.exec_module(mod)
    return mod


parity = load_parity()


SYNTHETIC_YO = """\
startdit()
dit(bf(tt(-V)))
dit(bf(tt(-h | -?)))
label(option_d)dit(bf(tt(-d)))
dit(bf(tt(-d -d | -dd | -d2)))
dit(bf(tt(-ly[<facility>])))
label(option_stats)dit(bf(tt(--statistics)))
enddit()

label(ADDRESS_TYPES)
label(ADDRESS_WIDGET)dit(bf(tt(WIDGET:<path>)) (bf(tt(WIDG:<path>))))
label(ADDRESS_STDIN)dit(bf(tt(STDIN)))
label(ADDRESS_PIPE)dit(bf(tt(PIPE:<filename>)))
label(ADDRESS_SHELL)dit(bf(tt(SHELL:<shell-command>)))
label(ADDRESS_DCCP)dit(bf(tt(DCCP-CONNECT:<host>:<port>)) (bf(tt(DCCP:<host>:<port>))))
label(ADDRESS_DCCP4_LISTEN)dit(bf(tt(DCCP4-LISTEN:<port>)))
label(ADDRESS_DTLS)dit(bf(tt(OPENSSL-DTLS-CLIENT:<host>:<port>)))
COMMENT(label(ADDRESS_HIDDEN)dit(bf(tt(HIDDEN:<x>))))
label(OPTION_FROB)dit(bf(tt(frob[=<bool>])))
label(OPTION_VISIBLE)dit(bf(tt(visible[=<bool>])) (bf(tt(vis[=<bool>]))))
COMMENT(label(OPTION_SECRET)dit(bf(tt(secret[=<bool>])))
   unused because of code(select()).)
label(OPTION_UDP_IGNORE)dit(bf(tt(udp-ignore-peerport>)))
"""

SYNTHETIC_HHH = """\
socat by test
   address-head:
      WIDGET:<path>			groups=FD,NAMED
      WIDG				is an alias name for WIDGET
      STDIN				groups=FD
      PIPE:<filename>			groups=FD,NAMED,FIFO
      DCCP-CONNECT:<host>:<port>	groups=FD,SOCKET,DCCP
      DCCP4-LISTEN:<port>		groups=FD,SOCKET,LISTEN,DCCP
      OPENSSL-DTLS-CLIENT:<host>:<port>	groups=FD,SOCKET,OPENSSL
      FOO:<x>				groups=FD,DCCP
   opts:
      frob		groups=FD		phase=LATE		type=BOOL
      vis		is an alias for visible
      visible		groups=FD		phase=LATE		type=BOOL
      o-creat		groups=OPEN,FD		phase=LATE		type=BOOL
      creat		is an alias for o-creat
      create		is an alias for o-creat
      binary		groups=OPEN		phase=LATE		type=BOOL
      bin		is an alias for binary
      o-binary		is an alias for binary
      glued		groups=FD,IPAPP,UDPLITEphase=LATE		type=BOOL
      openssl-method	is an alias for method
"""

SYNTHETIC_GO_HELP = """\
socat test by oittaa — multipurpose relay (Go)

Usage:
  socat [options] <address> <address>

Options:
  -V              print version
  -h|-?           print help
  -d|-d0..-d4     verbosity
  --statistics    stats

Address types:

  Files
    WIDGET:<path>  a widget
    WIDG           alias of WIDGET
    STDIN          standard input
    PIPE[:<filename>]  a pipe
    SHELL[:<command>]  a shell
    WS:<url>       websocket extra
    WS-LISTEN:<port>  websocket extra listen

Address options:
  Form: option or option=value.
    frob      frobnicate
    visible   show it
    vis       alias of visible
    creat     create if missing
    create    alias of creat
    o-creat   alias of creat
    alpn      go-only extra
"""

BASELINE = {
    "repository": "https://example.invalid/socat.git",
    "release_tag": "tag-0.0.0",
    "release_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "reviewed_master_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
}

POLICY = {
    "unsupported_addresses": {
        "DCCP": "intentional exception",
        "DTLS": "stream TLS only",
        "UDPLITE": "intentional exception",
        "READLINE": "not implemented",
    },
    "unsupported_options": {
        "udp-ignore-peerport": "documented but never implemented",
    },
    "foreign_options": {},
    "parser_only_options": {
        "openssl-method": "C parser alias; not advertised",
    },
    "go_only_addresses": {"WS": "extension"},
    "go_only_options": {"alpn": "extension"},
    "platform_options": {
        "linux": [],
        "darwin": ["ip-recvif"],
        "windows": ["binary"],
    },
}


class MacroParserTest(unittest.TestCase):
    def test_matching_paren_nested(self) -> None:
        text = "(a(b())c)"
        self.assertEqual(parity.matching_paren(text, 0), len(text) - 1)

    def test_unbalanced_paren_raises(self) -> None:
        with self.assertRaises(ValueError):
            parity.matching_paren("(oops", 0)

    def test_startdit_is_not_dit(self) -> None:
        self.assertIsNone(parity.take_macro("startdit(x)", 5, "dit"))
        self.assertIsNotNone(parity.take_macro("dit(x)", 0, "dit"))


class YoParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.got = parity.parse_socat_yo(SYNTHETIC_YO)

    def test_addresses_and_aliases(self) -> None:
        self.assertIn("WIDGET", self.got.addresses)
        self.assertIn("WIDG", self.got.addresses)
        self.assertIn("STDIN", self.got.addresses)
        self.assertIn("PIPE", self.got.addresses)
        self.assertIn("SHELL", self.got.addresses)
        self.assertIn("DCCP4-LISTEN", self.got.addresses)
        self.assertIn("OPENSSL-DTLS-CLIENT", self.got.addresses)
        self.assertEqual(self.got.address_aliases["WIDG"], "WIDGET")

    def test_section_labels_are_not_addresses(self) -> None:
        self.assertNotIn("TYPES", self.got.addresses)
        self.assertNotIn("ADDRESS_TYPES", self.got.addresses)

    def test_comment_entries_omitted(self) -> None:
        self.assertNotIn("HIDDEN", self.got.addresses)
        self.assertNotIn("secret", self.got.options)

    def test_options_and_aliases(self) -> None:
        self.assertIn("frob", self.got.options)
        self.assertIn("visible", self.got.options)
        self.assertIn("vis", self.got.options)
        self.assertEqual(self.got.option_aliases["vis"], "visible")

    def test_trailing_angle_bracket_stripped(self) -> None:
        self.assertIn("udp-ignore-peerport", self.got.options)

    def test_cli_flags_from_labeled_and_unlabeled_dit(self) -> None:
        for flag in ("-V", "-h", "-?", "-d", "-dd", "-d2", "-ly", "--statistics"):
            self.assertIn(flag, self.got.flags, flag)


class HhhParserTest(unittest.TestCase):
    def setUp(self) -> None:
        self.got = parity.parse_classic_hhh(SYNTHETIC_HHH)

    def test_addresses_and_alias_name_for(self) -> None:
        self.assertIn("WIDGET", self.got.addresses)
        self.assertIn("WIDG", self.got.addresses)
        self.assertEqual(self.got.address_aliases["WIDG"], "WIDGET")
        self.assertEqual(self.got.address_groups["WIDGET"], "FD,NAMED")
        self.assertEqual(self.got.address_groups["FOO"], "FD,DCCP")
        self.assertEqual(self.got.option_aliases["create"], "o-creat")

    def test_options_aliases_and_glued_groups(self) -> None:
        self.assertIn("frob", self.got.options)
        self.assertEqual(self.got.option_aliases["vis"], "visible")
        self.assertEqual(self.got.option_meta["glued"]["groups"], "FD,IPAPP,UDPLITE")
        self.assertEqual(self.got.option_meta["glued"]["phase"], "LATE")
        self.assertEqual(self.got.option_meta["glued"]["type"], "BOOL")

    def test_opts_only_dump_has_no_addresses(self) -> None:
        got = parity.parse_classic_hhh(
            "   opts:\n      frob\tgroups=FD\t\tphase=LATE\t\ttype=BOOL\n"
        )
        self.assertEqual(got.addresses, set())
        self.assertIn("frob", got.options)


class GoHelpParserTest(unittest.TestCase):
    def test_flags_addresses_options_and_aliases(self) -> None:
        got = parity.parse_go_help(SYNTHETIC_GO_HELP)
        self.assertIn("-V", got.flags)
        self.assertIn("-h", got.flags)
        self.assertIn("-?", got.flags)
        self.assertIn("--statistics", got.flags)
        self.assertIn("WIDGET", got.addresses)
        self.assertEqual(got.address_aliases["WIDG"], "WIDGET")
        self.assertIn("WS", got.addresses)
        self.assertIn("PIPE", got.addresses)
        self.assertIn("SHELL", got.addresses)
        self.assertNotIn("PIPE[", got.addresses)
        self.assertNotIn("SHELL[", got.addresses)
        self.assertEqual(got.option_aliases["vis"], "visible")
        self.assertEqual(got.option_aliases["create"], "creat")
        self.assertIn("alpn", got.options)


class VersionFeaturesTest(unittest.TestCase):
    def test_feature_complete_with_indented_define_value(self) -> None:
        text = (
            "  #define WITH_OPENSSL 1\n"
            "  #define WITH_READLINE 1\n"
            "  #define WITH_LIBWRAP 1\n"
            "  #undef WITH_FIPS\n"
        )
        self.assertEqual(parity.missing_feature_complete(text), [])
        feats = parity.parse_classic_v(text)
        self.assertTrue(feats["WITH_OPENSSL"])
        self.assertFalse(feats["WITH_FIPS"])

    def test_missing_openssl_is_reported(self) -> None:
        text = "  #undef WITH_OPENSSL\n  #define WITH_READLINE 1\n  #define WITH_LIBWRAP 1\n"
        self.assertEqual(parity.missing_feature_complete(text), ["WITH_OPENSSL"])

    def test_darwin_does_not_require_libwrap(self) -> None:
        text = (
            "  #define WITH_OPENSSL 1\n"
            "  #define WITH_READLINE 1\n"
            "  #undef WITH_LIBWRAP\n"
        )
        self.assertEqual(parity.missing_feature_complete(text, goos="darwin"), [])
        self.assertEqual(parity.missing_feature_complete(text, goos="macos"), [])
        self.assertEqual(parity.missing_feature_complete(text, goos="linux"), ["WITH_LIBWRAP"])
        self.assertIn("WITH_LIBWRAP", parity.feature_complete_defines_for("linux"))
        self.assertNotIn("WITH_LIBWRAP", parity.feature_complete_defines_for("darwin"))


class CompareTest(unittest.TestCase):
    def _report(self, **kwargs):
        release_docs = parity.parse_socat_yo(SYNTHETIC_YO)
        release_hhh = parity.parse_classic_hhh(SYNTHETIC_HHH)
        go_help = parity.parse_go_help(SYNTHETIC_GO_HELP)
        args = dict(
            release_docs=release_docs,
            release_hhh=release_hhh,
            master_docs=release_docs,
            master_hhh=None,
            go_help=go_help,
            policy=POLICY,
            baseline=BASELINE,
            goos="linux",
        )
        args.update(kwargs)
        return parity.compare_interfaces(**args)

    def test_supported_synthetic_names_match(self) -> None:
        report = self._report()
        self.assertNotIn("frob", report.missing_options)
        self.assertNotIn("WIDGET", report.missing_addresses)
        self.assertNotIn("PIPE", report.missing_addresses)
        self.assertNotIn("SHELL", report.missing_addresses)
        self.assertNotIn("DCCP-CONNECT", report.missing_addresses)
        self.assertNotIn("DCCP4-LISTEN", report.missing_addresses)
        self.assertNotIn("OPENSSL-DTLS-CLIENT", report.missing_addresses)
        self.assertNotIn("FOO", report.missing_addresses)
        self.assertNotIn("WS", report.unexpected_addresses)
        self.assertNotIn("WS-LISTEN", report.unexpected_addresses)
        self.assertNotIn("alpn", report.unexpected_options)
        self.assertNotIn("create", report.unexpected_options)
        self.assertNotIn("o-creat", report.unexpected_options)
        self.assertNotIn("binary", report.missing_options)
        self.assertEqual(report.option_alias_mismatches, [])
        self.assertEqual(report.address_alias_mismatches, [])

    def test_creat_create_o_creat_are_one_alias_class(self) -> None:
        report = self._report()
        self.assertFalse(
            any(m["alias"] in {"create", "creat", "o-creat"} for m in report.option_alias_mismatches)
        )

    def test_dropped_create_alias_is_missing_even_when_creat_remains(self) -> None:
        go = parity.parse_go_help(
            SYNTHETIC_GO_HELP.replace("    create    alias of creat\n", "")
        )
        self.assertIn("creat", go.options)
        self.assertNotIn("create", go.options)
        report = self._report(go_help=go)
        self.assertIn("create", report.missing_options)
        self.assertNotIn("creat", report.missing_options)

    def test_windows_binary_requires_each_official_spelling(self) -> None:
        go = parity.parse_go_help(
            SYNTHETIC_GO_HELP + "    binary     windows mode\n    bin        alias of binary\n"
        )
        report = self._report(go_help=go, goos="windows")
        self.assertNotIn("binary", report.unexpected_options)
        self.assertNotIn("bin", report.unexpected_options)
        self.assertIn("o-binary", report.missing_options)
        present = parity.parse_go_help(
            SYNTHETIC_GO_HELP
            + "    binary     windows mode\n"
            + "    bin        alias of binary\n"
            + "    o-binary   alias of binary\n"
        )
        complete = self._report(go_help=present, goos="windows")
        self.assertNotIn("o-binary", complete.missing_options)
        linux = self._report(goos="linux")
        self.assertNotIn("binary", linux.missing_options)
        self.assertNotIn("bin", linux.missing_options)
        self.assertNotIn("o-binary", linux.missing_options)

    def test_go_alias_does_not_expand_policy_allowlist(self) -> None:
        go = parity.parse_go_help(SYNTHETIC_GO_HELP + "    typo       alias of alpn\n")
        report = self._report(go_help=go)
        self.assertIn("typo", report.unexpected_options)
        self.assertNotIn("alpn", report.unexpected_options)
        win = parity.parse_go_help(
            SYNTHETIC_GO_HELP
            + "    binary     windows mode\n"
            + "    bin        alias of binary\n"
            + "    o-binary   alias of binary\n"
            + "    typo       alias of binary\n"
        )
        win_report = self._report(go_help=win, goos="windows")
        self.assertIn("typo", win_report.unexpected_options)
        self.assertNotIn("binary", win_report.unexpected_options)

    def test_incomplete_v_is_a_failure(self) -> None:
        report = self._report(feature_defines_missing=["WITH_OPENSSL"])
        self.assertTrue(report.has_failures())
        report_ok = self._report(feature_defines_missing=[])
        self.assertFalse(report_ok.feature_defines_missing)

    def test_master_review_drift_is_a_failure(self) -> None:
        drifted = self._report(current_master_commit="c" * 40)
        self.assertTrue(drifted.master_review_drift)
        self.assertTrue(drifted.has_failures())
        pinned = self._report(current_master_commit=BASELINE["reviewed_master_commit"])
        self.assertFalse(pinned.master_review_drift)

    def test_parser_only_does_not_fail_audit(self) -> None:
        report = self._report()
        self.assertIn("openssl-method", report.parser_only_ignored)
        self.assertNotIn("openssl-method", report.missing_options)
        self.assertFalse(
            any(m["alias"] == "openssl-method" for m in report.option_alias_mismatches)
        )

    def test_unsupported_option_is_not_missing(self) -> None:
        report = self._report()
        self.assertNotIn("udp-ignore-peerport", report.missing_options)

    def test_other_platform_option_is_not_missing_on_linux(self) -> None:
        docs = parity.parse_socat_yo(
            SYNTHETIC_YO + "\nlabel(OPTION_RECVIF)dit(bf(tt(ip-recvif[=<bool>])))\n"
        )
        report = self._report(release_docs=docs, release_hhh=None)
        self.assertNotIn("ip-recvif", report.missing_options)

    def test_other_platform_option_advertised_here_is_unexpected(self) -> None:
        go = parity.parse_go_help(SYNTHETIC_GO_HELP + "    ip-recvif   darwin recv\n")
        linux = self._report(go_help=go, goos="linux")
        self.assertIn("ip-recvif", linux.unexpected_options)
        darwin = self._report(go_help=go, goos="darwin")
        self.assertNotIn("ip-recvif", darwin.unexpected_options)

    def test_platform_option_is_not_unexpected_on_its_goos(self) -> None:
        policy = copy.deepcopy(POLICY)
        policy["platform_options"]["linux"] = ["sctp-maxseg"]
        go = parity.parse_go_help(SYNTHETIC_GO_HELP + "    sctp-maxseg  sctp mss\n")
        linux = self._report(go_help=go, goos="linux", policy=policy)
        self.assertNotIn("sctp-maxseg", linux.unexpected_options)
        darwin = self._report(go_help=go, goos="darwin", policy=policy)
        self.assertIn("sctp-maxseg", darwin.unexpected_options)

    def test_unlisted_platform_alias_is_unexpected_when_official_omits_it(self) -> None:
        opts_only = parity.parse_classic_hhh(
            "   opts:\n      frob\tgroups=FD\t\tphase=LATE\t\ttype=BOOL\n"
        )
        go = parity.parse_go_help(
            SYNTHETIC_GO_HELP
            + "    binary     windows mode\n"
            + "    bin        alias of binary\n"
            + "    o-binary   alias of binary\n"
        )
        listed = copy.deepcopy(POLICY)
        listed["platform_options"]["windows"] = ["binary", "bin", "o-binary"]
        covered = self._report(
            go_help=go, goos="windows", policy=listed, release_hhh=opts_only
        )
        for name in ("binary", "bin", "o-binary"):
            self.assertNotIn(name, covered.unexpected_options)
        canonical_only = copy.deepcopy(POLICY)
        canonical_only["platform_options"]["windows"] = ["binary"]
        thin = self._report(
            go_help=go, goos="windows", policy=canonical_only, release_hhh=opts_only
        )
        self.assertNotIn("binary", thin.unexpected_options)
        self.assertIn("bin", thin.unexpected_options)
        self.assertIn("o-binary", thin.unexpected_options)

    def test_missing_option_is_reported(self) -> None:
        go = parity.parse_go_help(SYNTHETIC_GO_HELP.replace("    frob      frobnicate\n", ""))
        report = self._report(go_help=go)
        self.assertIn("frob", report.missing_options)
        self.assertTrue(report.has_failures())

    def test_alias_target_mismatch(self) -> None:
        go_text = SYNTHETIC_GO_HELP.replace("vis       alias of visible", "vis       alias of frob")
        report = self._report(go_help=parity.parse_go_help(go_text))
        self.assertTrue(report.option_alias_mismatches)
        self.assertEqual(report.option_alias_mismatches[0]["alias"], "vis")

    def test_release_master_drift(self) -> None:
        master = parity.parse_socat_yo(
            SYNTHETIC_YO + "\nlabel(OPTION_NEWER)dit(bf(tt(newer[=<bool>])))\n"
        )
        report = self._report(master_docs=master, master_hhh=None)
        self.assertIn("newer", report.release_master_option_drift)


class CaptureHelpTest(unittest.TestCase):
    def _script(self, directory: Path, v_text: str, hhh_text: str) -> Path:
        py = directory / "fake_socat.py"
        py.write_text(
            "import sys\n"
            f"V = {v_text!r}\n"
            f"HHH = {hhh_text!r}\n"
            "arg = sys.argv[1] if len(sys.argv) > 1 else ''\n"
            "if arg == '-V':\n"
            "    sys.stdout.write(V)\n"
            "elif arg == '-hhh':\n"
            "    sys.stdout.write(HHH)\n"
            "else:\n"
            "    raise SystemExit(2)\n",
            encoding="utf-8",
        )
        if os.name == "nt":
            wrapper = directory / "fake-socat.cmd"
            wrapper.write_text(
                f'@echo off\r\n"{sys.executable}" "{py}" %*\r\n',
                encoding="utf-8",
            )
            return wrapper
        wrapper = directory / "fake-socat"
        wrapper.write_text(
            "#!/bin/sh\n"
            f"exec {shlex.quote(sys.executable)} {shlex.quote(str(py))} \"$@\"\n",
            encoding="utf-8",
        )
        wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
        return wrapper

    def test_capture_writes_only_under_outdir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            v = (
                "  #define WITH_OPENSSL 1\n"
                "  #define WITH_READLINE 1\n"
                "  #define WITH_LIBWRAP 1\n"
            )
            binary = self._script(root, v, SYNTHETIC_HHH)
            outdir = root / "out"
            info = parity.capture_classic_help(binary, outdir)
            self.assertTrue(Path(info["v_path"]).is_file())
            self.assertTrue(Path(info["hhh_path"]).is_file())
            self.assertTrue(str(Path(info["v_path"])).startswith(str(outdir)))

    def test_capture_refuses_incomplete_features(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            v = "  #undef WITH_OPENSSL\n  #define WITH_READLINE 1\n  #define WITH_LIBWRAP 1\n"
            binary = self._script(root, v, SYNTHETIC_HHH)
            with self.assertRaises(SystemExit) as ctx:
                parity.capture_classic_help(binary, root / "out")
            self.assertIn("WITH_OPENSSL", str(ctx.exception))
            self.assertFalse((root / "out" / "socat-hhh.txt").exists())

    def test_capture_on_darwin_allows_missing_libwrap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            v = (
                "  #define WITH_OPENSSL 1\n"
                "  #define WITH_READLINE 1\n"
                "  #undef WITH_LIBWRAP\n"
            )
            binary = self._script(root, v, SYNTHETIC_HHH)
            with patch.object(parity.sys, "platform", "darwin"):
                info = parity.capture_classic_help(binary, root / "out")
            self.assertTrue(Path(info["hhh_path"]).is_file())


class WorktreeSafetyTest(unittest.TestCase):
    def test_ensure_worktree_does_not_delete_caller_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            dest = Path(td) / "caller-supplied"
            dest.mkdir()
            marker = dest / "keep-me"
            marker.write_text("precious\n", encoding="utf-8")
            repo = Path(td) / "repo"
            repo.mkdir()
            with self.assertRaises(SystemExit) as ctx:
                parity.ensure_worktree(repo, dest, "deadbeef")
            self.assertIn("refusing to delete", str(ctx.exception))
            self.assertTrue(marker.exists())
            self.assertEqual(marker.read_text(encoding="utf-8"), "precious\n")

    def test_sync_refuses_nonempty_nongit_repo_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            repo = workdir / "repo"
            repo.mkdir()
            marker = repo / "keep-me"
            marker.write_text("precious\n", encoding="utf-8")
            with self.assertRaises(SystemExit) as ctx:
                parity.sync_classic(workdir, BASELINE)
            self.assertIn("refusing to delete", str(ctx.exception))
            self.assertTrue(marker.exists())


class CliTest(unittest.TestCase):
    def test_extract_and_compare_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            yo = root / "socat.yo"
            hhh = root / "socat.hhh"
            go = root / "go.hhh"
            policy = root / "policy.json"
            baseline = root / "baseline.json"
            yo.write_text(SYNTHETIC_YO, encoding="utf-8")
            hhh.write_text(SYNTHETIC_HHH, encoding="utf-8")
            go.write_text(SYNTHETIC_GO_HELP, encoding="utf-8")
            vpath = root / "socat-V.txt"
            vpath.write_text(
                "  #define WITH_OPENSSL 1\n"
                "  #define WITH_READLINE 1\n"
                "  #define WITH_LIBWRAP 1\n",
                encoding="utf-8",
            )
            policy.write_text(json.dumps(POLICY), encoding="utf-8")
            baseline.write_text(json.dumps(BASELINE), encoding="utf-8")
            extract = subprocess.run(
                [sys.executable, str(SCRIPT), "extract", "--yo", str(yo), "--hhh", str(hhh)],
                check=True,
                capture_output=True,
                text=True,
            )
            payload = json.loads(extract.stdout)
            self.assertIn("WIDGET", payload["addresses"])
            self.assertIn("frob", payload["options"])
            self.assertIn("-V", payload["flags"])
            compare = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "compare",
                    "--release-yo",
                    str(yo),
                    "--release-hhh",
                    str(hhh),
                    "--release-v",
                    str(vpath),
                    "--master-yo",
                    str(yo),
                    "--go-help",
                    str(go),
                    "--policy",
                    str(policy),
                    "--baseline",
                    str(baseline),
                    "--goos",
                    "linux",
                    "--workdir",
                    str(root / "workdir"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            report = json.loads(compare.stdout)
            self.assertEqual(report["reviewed_master_commit"], BASELINE["reviewed_master_commit"])
            self.assertIn("openssl-method", report["parser_only_ignored"])
            self.assertNotIn("frob", report["missing_options"])
            self.assertEqual(report["feature_defines_missing"], [])

    def test_compare_fail_on_diff(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            yo = root / "socat.yo"
            go = root / "go.hhh"
            policy = root / "policy.json"
            baseline = root / "baseline.json"
            yo.write_text(SYNTHETIC_YO, encoding="utf-8")
            go.write_text("Options:\n  -V\nAddress types:\nAddress options:\n", encoding="utf-8")
            policy.write_text(json.dumps(POLICY), encoding="utf-8")
            baseline.write_text(json.dumps(BASELINE), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "compare",
                    "--release-yo",
                    str(yo),
                    "--go-help",
                    str(go),
                    "--policy",
                    str(policy),
                    "--baseline",
                    str(baseline),
                    "--goos",
                    "linux",
                    "--fail-on-diff",
                    "--workdir",
                    str(root / "workdir"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)

    def test_compare_fail_on_diff_when_hhh_lacks_v(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            yo = root / "socat.yo"
            hhh = root / "socat.hhh"
            go = root / "go.hhh"
            policy = root / "policy.json"
            baseline = root / "baseline.json"
            yo.write_text(SYNTHETIC_YO, encoding="utf-8")
            hhh.write_text(SYNTHETIC_HHH, encoding="utf-8")
            go.write_text(SYNTHETIC_GO_HELP, encoding="utf-8")
            policy.write_text(json.dumps(POLICY), encoding="utf-8")
            baseline.write_text(json.dumps(BASELINE), encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "compare",
                    "--release-yo",
                    str(yo),
                    "--release-hhh",
                    str(hhh),
                    "--go-help",
                    str(go),
                    "--policy",
                    str(policy),
                    "--baseline",
                    str(baseline),
                    "--goos",
                    "linux",
                    "--fail-on-diff",
                    "--workdir",
                    str(root / "workdir"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 1)
            report = json.loads(proc.stdout)
            self.assertIn("socat -V output missing", report["feature_defines_missing"])


class GitUrlTest(unittest.TestCase):
    def test_https_and_git_protocol_are_the_same_official_repo(self) -> None:
        https = "https://repo.or.cz/socat.git"
        git = "git://repo.or.cz/socat.git"
        self.assertTrue(parity.origin_is_official(git, https))
        self.assertTrue(parity.origin_is_official(https + "/", git))
        self.assertFalse(
            parity.origin_is_official("https://github.com/dest-unreach/socat.git", https)
        )


class RepoPolicyTest(unittest.TestCase):
    REQUIRED_KEYS = (
        "unsupported_addresses",
        "unsupported_options",
        "foreign_options",
        "parser_only_options",
        "go_only_addresses",
        "go_only_options",
        "platform_options",
    )

    def test_repo_policy_loads(self) -> None:
        policy = parity.load_policy()
        for key in self.REQUIRED_KEYS:
            self.assertIn(key, policy, key)
        self.assertNotIn("expected_missing", policy)
        self.assertNotIn("expected_missing_options", policy)
        self.assertNotIn("expected_missing_addresses", policy)
        for family in ("DCCP", "READLINE", "DTLS", "UDPLITE"):
            self.assertIn(family, policy["unsupported_addresses"])
        for extra in ("WS", "WSS", "QUIC"):
            self.assertIn(extra, policy["go_only_addresses"])
        platforms = policy["platform_options"]
        self.assertIn("linux", platforms)
        self.assertIn("darwin", platforms)
        self.assertIn("windows", platforms)
        for name in ("notail", "sctp-maxseg", "sctp-nodelay"):
            self.assertIn(name, platforms["linux"])
        for name in (
            "ip-recvif",
            "ip-recvdstaddr",
            "recvif",
            "recvdstaddr",
            "iprecvdstaddr",
            "nopush",
            "noopt",
            "tcp-nopush",
            "tcp-noopt",
        ):
            self.assertIn(name, platforms["darwin"])
        for name in (
            "binary",
            "text",
            "noinherit",
            "bin",
            "o-binary",
            "o-text",
            "o-noinherit",
        ):
            self.assertIn(name, platforms["windows"])

    def test_go_only_and_platform_sets_are_disjoint(self) -> None:
        policy = parity.load_policy()
        go_only = {name.lower() for name in (policy.get("go_only_options") or {})}
        platform: set[str] = set()
        for block in (policy.get("platform_options") or {}).values():
            if isinstance(block, dict):
                platform.update(name.lower() for name in block)
            elif isinstance(block, list):
                platform.update(name.lower() for name in block)
        overlap = go_only & platform
        self.assertEqual(overlap, set(), f"go_only_options overlap platform_options: {sorted(overlap)}")


class OriginSafetyTest(unittest.TestCase):
    def test_wrong_origin_is_rejected_before_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            repo = workdir / "repo"
            subprocess.run(["git", "init", "--bare", str(repo)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/example/socat.git"],
                check=True,
                capture_output=True,
            )
            with self.assertRaises(SystemExit) as ctx:
                parity.sync_classic(workdir, BASELINE)
            self.assertIn("official repository", str(ctx.exception))


class FormatReportTest(unittest.TestCase):
    def _report(self, **kwargs) -> parity.CompareReport:
        values = dict(
            release_tag="tag-0.0.0",
            release_commit="a" * 40,
            reviewed_master_commit="b" * 40,
            goos="linux",
            current_master_commit="b" * 40,
        )
        values.update(kwargs)
        return parity.CompareReport(**values)

    def test_ok_report_lists_commits_and_goos(self) -> None:
        text = parity.format_parity_report(self._report())
        self.assertIn("GOOS: linux", text)
        self.assertIn("tag-0.0.0", text)
        self.assertIn("a" * 40, text)
        self.assertIn("reviewed master: " + "b" * 40, text)
        self.assertIn("current official master: " + "b" * 40, text)
        self.assertIn("master review drift: no", text)
        self.assertIn("result: ok", text)

    def test_fail_report_includes_drift_guidance(self) -> None:
        report = self._report(current_master_commit="c" * 40, missing_options=["frob"])
        report.master_review_drift = True
        text = parity.format_parity_report(report)
        self.assertIn("result: FAIL", text)
        self.assertIn("master review drift: yes", text)
        self.assertIn("current official master: " + "c" * 40, text)
        self.assertIn("classic-baseline.json", text)
        self.assertIn("frob", text)


class CompareFromWorkdirTest(unittest.TestCase):
    def test_reads_ignored_layout_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            release_yo = workdir / "worktrees" / "release" / "doc" / "socat.yo"
            master_yo = workdir / "worktrees" / "master" / "doc" / "socat.yo"
            release_out = workdir / "out" / "release"
            master_out = workdir / "out" / "master"
            release_yo.parent.mkdir(parents=True)
            master_yo.parent.mkdir(parents=True)
            release_out.mkdir(parents=True)
            master_out.mkdir(parents=True)
            release_yo.write_text(SYNTHETIC_YO, encoding="utf-8")
            master_yo.write_text(SYNTHETIC_YO, encoding="utf-8")
            v = (
                "  #define WITH_OPENSSL 1\n"
                "  #define WITH_READLINE 1\n"
                "  #define WITH_LIBWRAP 1\n"
            )
            (release_out / "socat-hhh.txt").write_text(SYNTHETIC_HHH, encoding="utf-8")
            (release_out / "socat-V.txt").write_text(v, encoding="utf-8")
            (master_out / "socat-hhh.txt").write_text(SYNTHETIC_HHH, encoding="utf-8")
            (master_out / "socat-V.txt").write_text(v, encoding="utf-8")
            go = workdir / "go.hhh"
            go.write_text(SYNTHETIC_GO_HELP, encoding="utf-8")
            report = parity.compare_from_workdir(
                workdir=workdir,
                baseline=BASELINE,
                policy=POLICY,
                goos="linux",
                go_help=str(go),
            )
            self.assertEqual(report.goos, "linux")
            self.assertEqual(report.release_tag, BASELINE["release_tag"])
            self.assertEqual(report.release_commit, BASELINE["release_commit"])
            self.assertNotIn("frob", report.missing_options)
            self.assertEqual(report.feature_defines_missing, [])
            self.assertFalse(report.master_review_drift)


class RunCommandTest(unittest.TestCase):
    def _report(self, **kwargs) -> parity.CompareReport:
        values = dict(
            release_tag="tag-0.0.0",
            release_commit="a" * 40,
            reviewed_master_commit="b" * 40,
            goos="linux",
            current_master_commit="b" * 40,
        )
        values.update(kwargs)
        return parity.CompareReport(**values)

    def test_run_prints_summary_and_fails_on_diff(self) -> None:
        report = self._report(missing_options=["frob"])
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            out = workdir / "report.json"
            with (
                patch.object(parity, "sync_classic", return_value={}) as sync,
                patch.object(parity, "build_classic", return_value={}) as build,
                patch.object(parity, "compare_from_workdir", return_value=report) as compare,
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = parity.main(
                        [
                            "run",
                            "--workdir",
                            str(workdir),
                            "--goos",
                            "linux",
                            "--out",
                            str(out),
                        ]
                    )
            self.assertEqual(rc, 1)
            self.assertEqual(sync.call_count, 1)
            self.assertEqual(build.call_count, 2)
            self.assertEqual(compare.call_count, 1)
            text = buf.getvalue()
            self.assertIn("classic parity", text)
            self.assertIn("result: FAIL", text)
            self.assertIn("frob", text)
            self.assertNotIn("{", text)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["missing_options"], ["frob"])

    def test_run_ok_when_compare_has_no_failures(self) -> None:
        report = self._report()
        with tempfile.TemporaryDirectory() as td:
            workdir = Path(td)
            with (
                patch.object(parity, "sync_classic", return_value={}),
                patch.object(parity, "build_classic", return_value={}),
                patch.object(parity, "compare_from_workdir", return_value=report),
            ):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = parity.main(["run", "--workdir", str(workdir), "--goos", "linux"])
            self.assertEqual(rc, 0)
            self.assertIn("result: ok", buf.getvalue())


class MakeAndWorkflowPolicyTest(unittest.TestCase):
    ROOT = Path(__file__).resolve().parent.parent

    def test_check_does_not_run_classic_parity(self) -> None:
        text = (self.ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^classic-parity:")
        lines = text.splitlines()
        body: list[str] = []
        in_check = False
        for line in lines:
            if in_check:
                if line.startswith("\t"):
                    body.append(line)
                    continue
                break
            if line.startswith("check:"):
                in_check = True
                body.append(line)
        self.assertTrue(in_check)
        self.assertNotIn("classic-parity", "\n".join(body))

    def test_workflow_is_manual_only_without_artifacts(self) -> None:
        path = self.ROOT / ".github" / "workflows" / "classic-parity.yml"
        text = path.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("schedule:", text)
        self.assertNotIn("cron:", text)
        self.assertRegex(text, r"(?m)^\s+contents:\s+read\s*$")
        self.assertNotRegex(text, r"(?m)^\s+push:")
        self.assertNotRegex(text, r"(?m)^\s+pull_request:")
        self.assertNotIn("actions/upload-artifact", text)
        self.assertNotIn("actions/cache@", text)
        self.assertNotIn("GOOS=", text)
        self.assertNotIn("GOARCH=", text)
        self.assertIn("make classic-parity", text)
        self.assertIn("macos-latest", text)
        self.assertIn("ubuntu-latest", text)


class BuildPlanTest(unittest.TestCase):
    def test_existing_makefile_plans_distclean_then_configure(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tree = Path(td)
            (tree / "configure").write_text("#!/bin/sh\n", encoding="utf-8")
            (tree / "Makefile").write_text("all:\n", encoding="utf-8")
            self.assertEqual(
                parity.classic_build_plan(tree),
                ["distclean", "configure", "make"],
            )

    def test_fresh_tree_configures_without_distclean(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tree = Path(td)
            (tree / "configure").write_text("#!/bin/sh\n", encoding="utf-8")
            self.assertEqual(parity.classic_build_plan(tree), ["configure", "make"])


if __name__ == "__main__":
    unittest.main()
