#!/usr/bin/env python3
"""Collapse concatenated go coverprofiles to unique blocks.

`go test -coverpkg=./... -coverprofile=out ./...` writes one copy of every
instrumented block per test binary. `go tool cover` merges those copies the
same way: bitwise OR in set mode, addition in count and atomic modes.
Codecov and naive last-write-wins uploads do not, so later zeros can drop
integration-test hits and heatmaps can under-count.

This script emits a single record per (file, span) using those merge rules.
Duplicate spans with inconsistent NumStmt are rejected.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

VALID_MODES = frozenset({"set", "count", "atomic"})


def merge_coverprofile(text: str) -> str:
    lines = text.splitlines()
    if not lines or not lines[0].startswith("mode:"):
        raise ValueError("coverprofile missing mode: header")
    mode_line = lines[0]
    const_p = "mode: "
    if not mode_line.startswith(const_p) or mode_line == const_p:
        raise ValueError(f"bad mode line: {mode_line}")
    mode = mode_line[len(const_p) :]
    if mode not in VALID_MODES:
        raise ValueError(f"bad mode line: {mode_line}")

    # Keyed by file and source span, matching go tool cover. NumStmt is
    # stored with the block and must stay consistent across duplicates.
    merged: dict[tuple[str, str], tuple[int, int]] = {}
    order: list[tuple[str, str]] = []
    for i, line in enumerate(lines[1:], start=2):
        if not line.strip():
            continue
        try:
            file, rest = line.rsplit(":", 1)
            loc, n_s, c_s = rest.split()
            n, c = int(n_s), int(c_s)
        except ValueError as e:
            raise ValueError(f"line {i}: malformed coverprofile record") from e
        key = (file, loc)
        prev = merged.get(key)
        if prev is None:
            merged[key] = (n, c)
            order.append(key)
            continue
        prev_n, prev_c = prev
        if n != prev_n:
            raise ValueError(f"inconsistent NumStmt: changed from {prev_n} to {n}")
        if mode == "set":
            merged[key] = (n, prev_c | c)
        else:
            merged[key] = (n, prev_c + c)
    out = [mode_line]
    for key in sorted(order, key=lambda k: (k[0], k[1])):
        file, loc = key
        n, c = merged[key]
        out.append(f"{file}:{loc} {n} {c}")
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
    try:
        args.dst.write_text(merge_coverprofile(args.src.read_text()), encoding="utf-8")
    except ValueError as e:
        print(e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
