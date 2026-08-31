#!/usr/bin/env python3
"""Collapse concatenated go coverprofiles to unique blocks.

`go test -coverpkg=./... -coverprofile=out ./...` writes one copy of every
instrumented block per test binary. `go tool cover` merges those copies with
max(count). Codecov and naive statement sums do not, so a last-write-wins
upload can drop coverage from integration tests.

This script emits a single record per (file, span) using max(count).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def merge_coverprofile(text: str) -> str:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("mode:"):
        raise ValueError("coverprofile missing mode: header")
    mode = lines[0]
    merged: dict[tuple[str, str, int], int] = {}
    order: list[tuple[str, str, int]] = []
    for i, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        try:
            file, rest = line.rsplit(":", 1)
            loc, n_s, c_s = rest.split()
            n, c = int(n_s), int(c_s)
        except ValueError as e:
            raise ValueError(f"line {i}: malformed coverprofile record") from e
        key = (file, loc, n)
        prev = merged.get(key)
        if prev is None:
            merged[key] = c
            order.append(key)
            continue
        if c > prev:
            merged[key] = c
    out = [mode]
    for key in sorted(order, key=lambda k: (k[0], k[1])):
        file, loc, n = key
        out.append(f"{file}:{loc} {n} {merged[key]}")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("src", type=Path, help="input coverprofile")
    p.add_argument("dst", type=Path, help="merged coverprofile")
    args = p.parse_args(argv)
    if not args.src.is_file():
        print(f"missing coverprofile {args.src}", file=sys.stderr)
        return 1
    args.dst.write_text(merge_coverprofile(args.src.read_text()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
