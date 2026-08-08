#!/usr/bin/env python3
"""Compare two scorecard results.json files (baseline vs current).

Exit 1 with --regression-exit if any test that was OK is no longer OK.

Usage:
  ./scripts/scorecard-compare.py \\
      testdata/scorecard/classic-baseline.json \\
      .classic-scorecard/results.json

  ./scripts/scorecard-compare.py go-prev.json go-now.json --regression-exit
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys


def _load_parse_api():
    parse_py = pathlib.Path(__file__).resolve().parent / "scorecard-parse.py"
    ns: dict = {}
    exec(compile(parse_py.read_text(), str(parse_py), "exec"), ns)
    return ns["compare"], ns["print_compare"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("baseline", type=pathlib.Path)
    ap.add_argument("current", type=pathlib.Path)
    ap.add_argument("--regression-exit", action="store_true")
    ap.add_argument("--write", type=pathlib.Path, help="write compare JSON")
    args = ap.parse_args()

    compare, print_compare = _load_parse_api()
    baseline = json.loads(args.baseline.read_text())
    current = json.loads(args.current.read_text())
    cmp = compare(baseline, current)
    print_compare(cmp)
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(cmp, indent=2) + "\n")
        print(f"wrote {args.write}")
    if args.regression_exit and cmp["regression_count"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
