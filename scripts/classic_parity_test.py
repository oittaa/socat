"""Synthetic tests for scripts/classic-parity.py.

Fixtures are invented by this project. They do not copy official socat
help text or man-page paragraphs.
"""

from __future__ import annotations

import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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
   opts:
      frob		groups=FD		phase=LATE		type=BOOL
      vis		is an alias for visible
      visible		groups=FD		phase=LATE		type=BOOL
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
    WS:<url>       websocket extra

Address options:
  Form: option or option=value.
    frob      frobnicate
    visible   show it
    vis       alias of visible
    alpn      go-only extra
"""

BASELINE = {
    "repository": "https://example.invalid/socat.git",
    "release_tag": "tag-0.0.0",
    "release_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "reviewed_master_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
}

POLICY = {
    "unsupported_addresses": {},
    "unsupported_options": {
        "udp-ignore-peerport": "documented but never implemented",
    },
    "foreign_options": {},
    "parser_only_options": {
        "openssl-method": "C parser alias; not advertised",
    },
    "go_only_addresses": {"WS": "extension"},
    "go_only_options": {"alpn": "extension"},
    "platform_options": {"linux": [], "darwin": ["ip-recvif"], "windows": []},
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
        self.assertEqual(got.option_aliases["vis"], "visible")
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
        self.assertNotIn("WS", report.unexpected_addresses)
        self.assertNotIn("alpn", report.unexpected_options)
        self.assertEqual(report.option_alias_mismatches, [])
        self.assertEqual(report.address_alias_mismatches, [])

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
        path = directory / "fake-socat"
        path.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = "-V" ]; then cat <<\'EOF\'\n'
            f"{v_text}"
            "EOF\n"
            'elif [ "$1" = "-hhh" ]; then cat <<\'EOF\'\n'
            f"{hhh_text}"
            "EOF\n"
            "else exit 2\n"
            "fi\n",
            encoding="utf-8",
        )
        path.chmod(path.stat().st_mode | stat.S_IEXEC)
        return path

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


if __name__ == "__main__":
    unittest.main()
