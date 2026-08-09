#!/usr/bin/env python3
"""Parse classic test.sh scorecard logs into a structured results document.

Statuses:
  OK       — test passed
  FAILED   — test ran and failed
  CANT     — could not be performed (missing feature, root, internet, …)
  TIMEOUT  — shard killed mid-run; test started or was never finished
  UNKNOWN  — no per-test line and not listed in Summary CANT/FAILED

Usage:
  scorecard-parse.py OUT_DIR [--label LABEL] [--socat PATH] [--write PATH]
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

# test  12 EXECPIPES: description... OK
# test 228 TCP4SERVICE: ... FAILED: diff:
# test  24 OPENSSL: ... Feature FOO not available
# test 405 OPENSSL_SNI: ... use test.sh option --internet
RE_TEST = re.compile(
    r"^test\s+(\d+)\s+([A-Za-z0-9_]+):\s+(.*?)\.\.\.\s*(.*)$"
)
RE_SUMMARY = re.compile(
    r"Summary:\s+(\d+)\s+tests,\s+(\d+)\s+selected;\s+"
    r"(\d+)\s+ok,\s+(\d+)\s+failed,\s+(\d+)\s+could not be performed"
)
RE_CANT_LIST = re.compile(r"^CANT:\s*(.*)$")
RE_FAILED_LIST = re.compile(r"^FAILED:\s*(.*)$")
RE_SHARD_TIMEOUT = re.compile(r"SHARD TIMEOUT|exit=124")


def classify_tail(tail: str) -> tuple[str, str]:
    """Map the text after '...' to (status, detail)."""
    t = tail.strip()
    if not t:
        return "UNKNOWN", ""
    if t == "OK" or t.startswith("OK "):
        return "OK", ""
    if t.startswith("FAILED"):
        detail = t[len("FAILED") :].lstrip(" :")
        return "FAILED", detail
    # Classic yellow CANT reasons (no FAILED/OK keyword)
    # Examples: "Feature X not available", "must be root", "use test.sh option --internet"
    lower = t.lower()
    if any(
        x in lower
        for x in (
            "not available",
            "not configured",
            "must be root",
            "only on ",
            "use test.sh option",
            "broken dns",
            "no option",
            "services file not found",
            "cannot determine",
        )
    ):
        return "CANT", t
    if "timeout" in lower or "timed out" in lower:
        return "TIMEOUT", t
    # "NO RESULT" and similar
    if t.startswith("NO RESULT") or "no result" in lower:
        return "FAILED", t
    return "UNKNOWN", t


def parse_id_list(s: str) -> list[int]:
    out: list[int] = []
    for tok in s.split():
        if tok.isdigit():
            out.append(int(tok))
    return out


def parse_logs(out_dir: pathlib.Path) -> dict[str, Any]:
    tests: dict[int, dict[str, Any]] = {}
    shard_timeouts: list[int] = []
    last_seen_by_shard: dict[int, int] = {}

    for log in sorted(out_dir.glob("shard-*.log"), key=lambda p: p.name):
        sid = int(log.stem.split("-")[1])
        text = log.read_text(errors="replace")
        lines = text.splitlines()
        shard_timed_out = bool(RE_SHARD_TIMEOUT.search(text)) or (
            (out_dir / f"shard-{sid}.summary").exists()
            and (out_dir / f"shard-{sid}.summary").read_text().split()[3:4] == ["124"]
        )
        if shard_timed_out:
            shard_timeouts.append(sid)

        summary_cant: list[int] = []
        summary_failed: list[int] = []
        last_id = 0

        for line in lines:
            m = RE_TEST.match(line.strip())
            if m:
                tid = int(m.group(1))
                name = m.group(2)
                desc = m.group(3).strip()
                status, detail = classify_tail(m.group(4))
                last_id = tid
                tests[tid] = {
                    "id": tid,
                    "name": name,
                    "description": desc,
                    "status": status,
                    "detail": detail,
                    "shard": sid,
                    "raw": line.strip()[:300],
                }
                continue
            m = RE_CANT_LIST.match(line.strip())
            if m:
                summary_cant = parse_id_list(m.group(1))
                continue
            m = RE_FAILED_LIST.match(line.strip())
            if m:
                # Avoid the "FAILED:  /path/to/socat:" command-echo lines
                ids = parse_id_list(m.group(1))
                if ids:
                    summary_failed = ids

        last_seen_by_shard[sid] = last_id

        # Fill CANT/FAILED from Summary lists if missing per-test lines
        for tid in summary_cant:
            if tid not in tests:
                tests[tid] = {
                    "id": tid,
                    "name": "",
                    "description": "",
                    "status": "CANT",
                    "detail": "from Summary CANT list",
                    "shard": sid,
                    "raw": "",
                }
            elif tests[tid]["status"] == "UNKNOWN":
                tests[tid]["status"] = "CANT"
        for tid in summary_failed:
            if tid not in tests:
                tests[tid] = {
                    "id": tid,
                    "name": "",
                    "description": "",
                    "status": "FAILED",
                    "detail": "from Summary FAILED list",
                    "shard": sid,
                    "raw": "",
                }
            elif tests[tid]["status"] not in ("OK", "FAILED"):
                tests[tid]["status"] = "FAILED"

        # If shard timed out, mark incomplete tail as TIMEOUT
        if shard_timed_out and last_id:
            # The last test line may be incomplete (no OK/FAILED). Mark UNKNOWN→TIMEOUT.
            t = tests.get(last_id)
            if t and t["status"] in ("UNKNOWN",):
                t["status"] = "TIMEOUT"
                t["detail"] = t.get("detail") or "shard timeout (no final result)"

    # Summarize
    counts = {"OK": 0, "FAILED": 0, "CANT": 0, "TIMEOUT": 0, "UNKNOWN": 0}
    for t in tests.values():
        st = t["status"]
        counts[st] = counts.get(st, 0) + 1

    return {
        "tests": {str(k): tests[k] for k in sorted(tests)},
        "summary": {
            "ok": counts.get("OK", 0),
            "failed": counts.get("FAILED", 0),
            "cant": counts.get("CANT", 0),
            "timeout": counts.get("TIMEOUT", 0),
            "unknown": counts.get("UNKNOWN", 0),
            "total_recorded": len(tests),
            "shard_timeouts": shard_timeouts,
        },
    }


def socat_version(path: str) -> str:
    try:
        out = subprocess.check_output([path, "-V"], stderr=subprocess.STDOUT, text=True, timeout=5)
        return out.strip().splitlines()[0] if out.strip() else path
    except Exception as e:
        return f"{path} ({e})"


def git_rev(root: pathlib.Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return ""


def build_document(
    out_dir: pathlib.Path,
    *,
    label: str,
    socat: str,
    test_sh: str,
    extra_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    root = out_dir.resolve()
    # Prefer repo root (parent of .classic-scorecard)
    repo = root.parent if root.name.startswith(".") else root
    parsed = parse_logs(out_dir)
    meta = {
        "label": label,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hostname": platform.node(),
        "platform": platform.platform(),
        "socat": socat,
        "socat_version": socat_version(socat) if socat else "",
        "test_sh": test_sh,
        "git": git_rev(repo),
        "out_dir": str(out_dir),
    }
    if extra_meta:
        meta.update(extra_meta)
    return {"meta": meta, "summary": parsed["summary"], "tests": parsed["tests"]}


def compare(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare two result docs. Regression = was OK, now not OK."""
    btests = baseline.get("tests") or {}
    ctests = current.get("tests") or {}
    all_ids = sorted(set(btests) | set(ctests), key=lambda x: int(x))

    regressions: list[dict[str, Any]] = []
    improvements: list[dict[str, Any]] = []
    new_fails: list[dict[str, Any]] = []
    status_changes: list[dict[str, Any]] = []

    incomplete: list[dict[str, Any]] = []
    for tid in all_ids:
        b = btests.get(tid)
        c = ctests.get(tid)
        bs = b["status"] if b else None
        cs = c["status"] if c else None
        name = (c or b or {}).get("name") or ""
        if bs == cs:
            continue
        entry = {
            "id": int(tid),
            "name": name,
            "from": bs,
            "to": cs,
            "detail": (c or {}).get("detail", ""),
        }
        # Missing from current = incomplete shard (timeout), not a real regression.
        if c is None:
            incomplete.append(entry)
            continue
        if b is None:
            # New test number vs older baseline — note only if FAILED
            if cs == "FAILED":
                new_fails.append(entry)
            status_changes.append(entry)
            continue
        status_changes.append(entry)
        # True regression: was OK, now FAILED/TIMEOUT/CANT/UNKNOWN
        if bs == "OK" and cs != "OK":
            regressions.append(entry)
        if bs != "OK" and cs == "OK":
            improvements.append(entry)

    return {
        "baseline_label": (baseline.get("meta") or {}).get("label"),
        "current_label": (current.get("meta") or {}).get("label"),
        "baseline_summary": baseline.get("summary"),
        "current_summary": current.get("summary"),
        "regressions": regressions,
        "improvements": improvements,
        "new_fails": new_fails,
        "incomplete": incomplete,
        "status_changes": status_changes,
        "regression_count": len(regressions),
        "improvement_count": len(improvements),
        "incomplete_count": len(incomplete),
    }


def print_compare(cmp: dict[str, Any]) -> None:
    bs = cmp.get("baseline_summary") or {}
    cs = cmp.get("current_summary") or {}
    print("======== SCORECARD COMPARE ========")
    print(f"baseline: {cmp.get('baseline_label')}  OK={bs.get('ok')} FAIL={bs.get('failed')} CANT={bs.get('cant')} TIMEOUT={bs.get('timeout')}")
    print(f"current:  {cmp.get('current_label')}  OK={cs.get('ok')} FAIL={cs.get('failed')} CANT={cs.get('cant')} TIMEOUT={cs.get('timeout')}")
    print()
    if cmp["regressions"]:
        print(f"REGRESSIONS ({cmp['regression_count']}) — was OK, now not:")
        for e in cmp["regressions"][:60]:
            print(f"  {e['id']:4d} {e['name']:<32} {e['from']} → {e['to']}  {e.get('detail','')[:60]}")
        if cmp["regression_count"] > 60:
            print(f"  ... and {cmp['regression_count']-60} more")
        print()
    else:
        print("REGRESSIONS: none")
        print()
    if cmp["improvements"]:
        print(f"IMPROVEMENTS ({cmp['improvement_count']}) — newly OK:")
        for e in cmp["improvements"][:40]:
            print(f"  {e['id']:4d} {e['name']:<32} {e['from']} → {e['to']}")
        if cmp["improvement_count"] > 40:
            print(f"  ... and {cmp['improvement_count']-40} more")
        print()
    if cmp.get("incomplete"):
        print(f"INCOMPLETE ({cmp.get('incomplete_count', 0)}) — in baseline but missing from current (shard timeout?)")
        print()
    if cmp["new_fails"]:
        print(f"NEW FAILS (not in baseline, now FAILED): {len(cmp['new_fails'])}")
        for e in cmp["new_fails"][:20]:
            print(f"  {e['id']:4d} {e['name']:<32} {e.get('detail','')[:60]}")
        print()
    # Useful: OK on both vs real FAIL (classic OK, go FAILED)
    real_fail = [e for e in cmp["regressions"] if e.get("to") == "FAILED"]
    real_cant = [e for e in cmp["regressions"] if e.get("to") == "CANT"]
    print(f"Parity gap (classic OK): FAILED={len(real_fail)} CANT={len(real_cant)} other={cmp['regression_count']-len(real_fail)-len(real_cant)}")



def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("out_dir", type=pathlib.Path, help="scorecard output dir with shard-*.log")
    ap.add_argument("--label", default="run", help="label for this run (classic|go|…)")
    ap.add_argument("--socat", default=os.environ.get("SOCAT", ""), help="socat binary path")
    ap.add_argument("--test-sh", default="", help="path to classic test.sh")
    ap.add_argument("--write", type=pathlib.Path, help="write results JSON here")
    ap.add_argument("--compare", type=pathlib.Path, help="baseline JSON to compare against")
    ap.add_argument(
        "--regression-exit",
        action="store_true",
        help="exit 1 if any OK→non-OK regression vs --compare",
    )
    ap.add_argument("--meta", action="append", default=[], help="extra meta key=value")
    args = ap.parse_args()

    extra = {}
    for item in args.meta:
        if "=" in item:
            k, v = item.split("=", 1)
            extra[k] = v

    doc = build_document(
        args.out_dir,
        label=args.label,
        socat=args.socat or "",
        test_sh=args.test_sh,
        extra_meta=extra or None,
    )

    write_path = args.write or (args.out_dir / "results.json")
    write_path.parent.mkdir(parents=True, exist_ok=True)
    write_path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    # Also JSONL for easy grepping
    jsonl = write_path.with_suffix(".jsonl")
    with jsonl.open("w") as f:
        for tid in sorted(doc["tests"], key=int):
            f.write(json.dumps(doc["tests"][tid]) + "\n")

    s = doc["summary"]
    print(
        f"wrote {write_path}  OK={s['ok']} FAILED={s['failed']} CANT={s['cant']} "
        f"TIMEOUT={s['timeout']} UNKNOWN={s['unknown']} total={s['total_recorded']}"
    )
    print(f"wrote {jsonl}")

    if args.compare:
        baseline = json.loads(args.compare.read_text())
        cmp = compare(baseline, doc)
        print_compare(cmp)
        cmp_path = args.out_dir / "compare.json"
        cmp_path.write_text(json.dumps(cmp, indent=2) + "\n")
        print(f"wrote {cmp_path}")
        if args.regression_exit and cmp["regression_count"]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
