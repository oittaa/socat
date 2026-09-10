"""Offline regression tests for the committed classic parity policy."""

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "classic_parity", SCRIPT_DIR / "classic-parity.py"
)
parity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = parity
SPEC.loader.exec_module(parity)

ALIASES = {"recverr": "ip-recverr", "iprecverr": "ip-recverr"}
SPELLINGS = {"ip-recverr", *ALIASES}


class IPRecvErrPlatformPolicyTest(unittest.TestCase):
    def setUp(self):
        self.policy = parity.load_policy(SCRIPT_DIR / "classic-policy.json")
        self.baseline = parity.load_baseline(SCRIPT_DIR / "classic-baseline.json")
        # The documentation names the option even where native help omits it.
        self.docs = parity.ExtractedInterface(options={"ip-recverr"})
        self.native_help = parity.ExtractedInterface(
            options=SPELLINGS, option_aliases=ALIASES
        )

    def compare(self, goos, go_help, *, native_help=None):
        return parity.compare_interfaces(
            release_docs=self.docs,
            release_hhh=native_help,
            master_docs=self.docs,
            master_hhh=native_help,
            go_help=go_help,
            policy=self.policy,
            baseline=self.baseline,
            goos=goos,
        )

    def test_unavailable_option_is_not_missing_off_linux(self):
        for goos in ("darwin", "windows"):
            for native_help in (None, self.native_help):
                with self.subTest(goos=goos, aliases=native_help is not None):
                    report = self.compare(
                        goos, parity.ExtractedInterface(), native_help=native_help
                    )
                    self.assertFalse(report.has_failures(), report.to_json())

    def test_linux_still_requires_each_official_spelling(self):
        for missing in sorted(SPELLINGS):
            with self.subTest(missing=missing):
                go_help = parity.ExtractedInterface(
                    options=SPELLINGS - {missing},
                    option_aliases={
                        name: target
                        for name, target in ALIASES.items()
                        if name != missing
                    },
                )
                report = self.compare("linux", go_help, native_help=self.native_help)
                self.assertEqual(report.missing_options, [missing])
                self.assertTrue(report.has_failures())

    def test_linux_advertised_family_passes(self):
        report = self.compare("linux", self.native_help, native_help=self.native_help)
        self.assertFalse(report.has_failures(), report.to_json())

    def test_unrelated_missing_option_still_fails(self):
        self.docs.options.add("ip-ttl")
        report = self.compare("darwin", parity.ExtractedInterface())
        self.assertEqual(report.missing_options, ["ip-ttl"])
        self.assertTrue(report.has_failures())


if __name__ == "__main__":
    unittest.main()
