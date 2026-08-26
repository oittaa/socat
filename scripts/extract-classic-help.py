#!/usr/bin/env python3
"""Build the classic socat -hhh option catalog as Go source.

The catalog records every advertised option spelling from official
`socat -hhh` output: spelling, canonical defname, help groups, phase, and
type. Parser-only optionnames[] entries that are not printed are omitted.

Baseline: https://repo.or.cz/socat.git tag-1.8.1.3
(12c08bf66d709fba17035ce95d85bd218428d9ba). Official master
af5388c898c7bb60997935aee93c223deba60c4a has identical xiohelp.c, xioopts.h,
optionnames[], and xio*.c.

Usage:
  python3 scripts/extract-classic-help.py DUMP.hhh > catalog_gen.go
  python3 scripts/extract-classic-help.py DUMP.hhh -o catalog_gen.go
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Address aliases print "is an alias name for"; option aliases omit "name".
# Classic help pads with tabs; long GROUP_IPAPP lists can glue into "UDPLITEphase=".
OPTION_DETAIL_RE = re.compile(
    r"^\s{6}(\S+)\s+groups=(\S+?)(?:\s*)phase=(\S+)\s+type=(\S+)\s*$"
)
OPTION_ALIAS_RE = re.compile(r"^\s{6}(\S+)\s+is an alias for (\S+)\s*$")

TAG = "tag-1.8.1.3"
COMMIT = "12c08bf66d709fba17035ce95d85bd218428d9ba"
MASTER = "af5388c898c7bb60997935aee93c223deba60c4a"
REPO = "https://repo.or.cz/socat.git"


def go_str(value: str) -> str:
    return json.dumps(value)


def go_strings(values: list[str]) -> str:
    if not values:
        return "nil"
    inner = ", ".join(go_str(v) for v in values)
    return f"[]string{{{inner}}}"


def option_section(text: str) -> str:
    marker = "\n   opts:"
    idx = text.find(marker)
    if idx < 0 and text.startswith("   opts:"):
        return text
    if idx < 0:
        raise ValueError("classic -hhh dump has no 'opts:' section")
    return text[idx + 1 :]


def parse_hhh_options(text: str) -> list[dict[str, object]]:
    section = option_section(text)
    details: dict[str, tuple[list[str], str, str]] = {}
    aliases: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in section.splitlines():
        m = OPTION_DETAIL_RE.match(line)
        if m:
            spelling = m.group(1)
            if spelling in seen:
                continue
            seen.add(spelling)
            groups = m.group(2).split(",")
            details[spelling] = (groups, m.group(3), m.group(4))
            continue
        m = OPTION_ALIAS_RE.match(line)
        if m:
            spelling, canonical = m.group(1), m.group(2)
            if spelling in seen:
                continue
            seen.add(spelling)
            aliases.append((spelling, canonical))

    entries: dict[str, dict[str, object]] = {}
    for spelling, (groups, phase, typ) in details.items():
        entries[spelling] = {
            "spelling": spelling,
            "canonical": spelling,
            "groups": groups,
            "phase": phase,
            "type": typ,
        }
    missing: list[str] = []
    for spelling, canonical in aliases:
        src = details.get(canonical)
        if src is None:
            missing.append(f"{spelling}->{canonical}")
            continue
        groups, phase, typ = src
        entries[spelling] = {
            "spelling": spelling,
            "canonical": canonical,
            "groups": groups,
            "phase": phase,
            "type": typ,
        }
    if missing:
        raise ValueError("alias targets missing from -hhh details: " + ", ".join(missing))
    if not entries:
        raise ValueError("no option entries parsed from -hhh dump")
    return [entries[name] for name in sorted(entries)]


def generate(entries: list[dict[str, object]]) -> str:
    lines = [
        "// Code generated from classic socat -hhh. DO NOT EDIT.",
        f"// Source: {REPO} {TAG} ({COMMIT}).",
        f"// Official master {MASTER} has no option/help differences.",
        "//go:generate python3 ../../scripts/extract-classic-help.py testdata/tag-1.8.1.3.hhh -o catalog_gen.go",
        "",
        "package classiccatalog",
        "",
        "// Options is the advertised classic -hhh option catalog, keyed by spelling.",
        "var Options = map[string]Entry{",
    ]
    for e in entries:
        spelling = str(e["spelling"])
        canonical = str(e["canonical"])
        groups = list(e["groups"])  # type: ignore[arg-type]
        phase = str(e["phase"])
        typ = str(e["type"])
        lines.append(
            "\t"
            + go_str(spelling)
            + ": {Spelling: "
            + go_str(spelling)
            + ", Canonical: "
            + go_str(canonical)
            + ", Groups: "
            + go_strings(groups)
            + ", Phase: "
            + go_str(phase)
            + ", Type: "
            + go_str(typ)
            + "},"
        )
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump", help="classic socat -hhh output (full or opts: section)")
    ap.add_argument("-o", "--output", help="write Go source here instead of stdout")
    args = ap.parse_args()
    text = Path(args.dump).read_text(errors="replace")
    src = generate(parse_hhh_options(text))
    if args.output:
        Path(args.output).write_text(src)
    else:
        sys.stdout.write(src)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
