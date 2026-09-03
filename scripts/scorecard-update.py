#!/usr/bin/env python3
"""Validate and publish reproducible Docker scorecard runs."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
from collections import Counter
from typing import Any


STATUSES = ("OK", "FAILED", "CANT", "TIMEOUT", "UNKNOWN")


class ScorecardError(ValueError):
    """A run is incomplete or internally inconsistent."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise ScorecardError(f"missing scorecard output: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScorecardError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ScorecardError(f"expected a JSON object in {path}")
    return doc


def validate_result(
    path: pathlib.Path,
    *,
    label: str,
    source_revision: str = "",
) -> dict[str, Any]:
    doc = load_json(path)
    meta = doc.get("meta")
    summary = doc.get("summary")
    tests = doc.get("tests")
    if not isinstance(meta, dict) or not isinstance(summary, dict) or not isinstance(tests, dict):
        raise ScorecardError(f"{path} must contain meta, summary, and tests objects")
    if meta.get("label") != label:
        raise ScorecardError(
            f"{path} has label={meta.get('label')!r}; expected {label!r}"
        )
    required_meta = {
        "mode": "classic",
        "val_t": "auto",
        "jobs": "1",
        "shard_timeout": "7200",
    }
    for key, expected in required_meta.items():
        if str(meta.get(key, "")) != expected:
            raise ScorecardError(
                f"{path} has {key}={meta.get(key)!r}; expected {expected!r}"
            )
    test_sh_args = str(meta.get("test_sh_args", "")).split()
    if "--internet" not in test_sh_args:
        raise ScorecardError(f"{path} was not run with TEST_SH_ARGS=--internet")
    expected_only = "" if label == "classic" else "functions filan"
    if meta.get("only", "") != expected_only:
        raise ScorecardError(
            f"{path} has only={meta.get('only')!r}; expected {expected_only!r}"
        )
    if meta.get("max_n", ""):
        raise ScorecardError(f"{path} was capped with MAX_N={meta.get('max_n')!r}")
    if source_revision and meta.get("source_revision") != source_revision:
        raise ScorecardError(
            f"{path} has source_revision={meta.get('source_revision')!r}; "
            f"expected {source_revision!r}"
        )
    if not meta.get("classic_version"):
        raise ScorecardError(f"{path} does not record the classic test.sh version")

    if len(tests) < 500:
        raise ScorecardError(
            f"{path} recorded only {len(tests)} tests; a full run should record at least 500"
        )
    counts: Counter[str] = Counter()
    for test_id, test in tests.items():
        if not isinstance(test, dict):
            raise ScorecardError(f"{path} test {test_id} is not an object")
        status = test.get("status")
        if status not in STATUSES:
            raise ScorecardError(f"{path} test {test_id} has invalid status {status!r}")
        counts[status] += 1

    summary_keys = {
        "OK": "ok",
        "FAILED": "failed",
        "CANT": "cant",
        "TIMEOUT": "timeout",
        "UNKNOWN": "unknown",
    }
    for status, key in summary_keys.items():
        if summary.get(key) != counts[status]:
            raise ScorecardError(
                f"{path} summary {key}={summary.get(key)!r}; counted {counts[status]}"
            )
    if summary.get("total_recorded") != len(tests):
        raise ScorecardError(
            f"{path} summary total_recorded={summary.get('total_recorded')!r}; "
            f"counted {len(tests)}"
        )
    if counts["TIMEOUT"] or counts["UNKNOWN"]:
        raise ScorecardError(
            f"{path} is incomplete: TIMEOUT={counts['TIMEOUT']} UNKNOWN={counts['UNKNOWN']}; "
            "inspect the working logs and rerun"
        )
    shard_timeouts = summary.get("shard_timeouts")
    if shard_timeouts:
        raise ScorecardError(f"{path} reports shard timeouts: {shard_timeouts}")
    reporting_errors = summary.get("reporting_errors") or []
    if reporting_errors:
        raise ScorecardError(
            f"{path} has {len(reporting_errors)} parser reporting error(s); "
            "refuse to publish contradictory CANT/FAILED lists"
        )
    return doc


def _status(test: Any) -> str | None:
    return test.get("status") if isinstance(test, dict) else None


def validate_reports(
    classic_dir: pathlib.Path,
    go_dir: pathlib.Path,
    classic: dict[str, Any],
    go: dict[str, Any],
) -> None:
    classic_ids = set(classic["tests"])
    go_ids = set(go["tests"])
    if classic_ids != go_ids:
        missing_go = sorted(classic_ids - go_ids, key=int)
        missing_classic = sorted(go_ids - classic_ids, key=int)
        raise ScorecardError(
            "classic and Go runs recorded different tests: "
            f"missing from Go={missing_go[:10]}, missing from classic={missing_classic[:10]}"
        )
    if classic["meta"]["classic_version"] != go["meta"]["classic_version"]:
        raise ScorecardError("classic and Go runs used different classic test.sh versions")

    verify = load_json(classic_dir / "host-vs-docker-verify.json")
    lost = verify.get("lost")
    gained = verify.get("gained_from_cant")
    if not isinstance(lost, list) or verify.get("lost_count") != len(lost):
        raise ScorecardError("host-vs-docker verification has an inconsistent lost_count")
    if not isinstance(gained, list) or verify.get("gained_from_cant_count") != len(gained):
        raise ScorecardError(
            "host-vs-docker verification has an inconsistent gained_from_cant_count"
        )
    if verify.get("host_ok_ran") != verify.get("still_ok", 0) + len(lost):
        raise ScorecardError("host-vs-docker verification totals do not add up")

    gaps = load_json(go_dir / "go-vs-classic-docker-gaps.json")
    parity_fail = gaps.get("parity_fail")
    parity_cant = gaps.get("parity_cant")
    parity_other = gaps.get("parity_other")
    new_ok = gaps.get("new_ok_vs_classic_docker")
    if not all(isinstance(rows, list) for rows in (parity_fail, parity_cant, parity_other, new_ok)):
        raise ScorecardError("Go-vs-classic gap report has invalid row lists")

    calculated_fail: list[str] = []
    calculated_cant: list[str] = []
    calculated_other: list[str] = []
    calculated_new_ok: list[str] = []
    for test_id in classic_ids:
        classic_status = _status(classic["tests"][test_id])
        go_status = _status(go["tests"][test_id])
        if classic_status == "OK" and go_status != "OK":
            if go_status == "FAILED":
                calculated_fail.append(test_id)
            elif go_status == "CANT":
                calculated_cant.append(test_id)
            else:
                calculated_other.append(test_id)
        if classic_status != "OK" and go_status == "OK":
            calculated_new_ok.append(test_id)

    def ids(rows: list[Any]) -> set[str]:
        return {str(row.get("id")) for row in rows if isinstance(row, dict)}

    expected_lists = (
        ("parity_fail", parity_fail, calculated_fail),
        ("parity_cant", parity_cant, calculated_cant),
        ("parity_other", parity_other, calculated_other),
        ("new_ok_vs_classic_docker", new_ok, calculated_new_ok),
    )
    for name, rows, expected in expected_lists:
        if ids(rows) != set(expected):
            raise ScorecardError(f"Go-vs-classic gap report has stale {name} rows")
    if gaps.get("classic_docker_ok") != classic["summary"]["ok"]:
        raise ScorecardError("Go-vs-classic gap report has a stale classic OK total")
    if gaps.get("go_ok") != go["summary"]["ok"]:
        raise ScorecardError("Go-vs-classic gap report has a stale Go OK total")
    calculated_gap = len(calculated_fail) + len(calculated_cant) + len(calculated_other)
    if gaps.get("parity_gap_total") != calculated_gap:
        raise ScorecardError("Go-vs-classic gap report has a stale parity gap total")


def update_readme(
    text: str,
    classic: dict[str, Any],
    go: dict[str, Any],
    gaps: dict[str, Any],
) -> str:
    classic_summary = classic["summary"]
    go_summary = go["summary"]

    def replace_once(pattern: str, replacement: str, source: str, description: str) -> str:
        updated, count = re.subn(pattern, replacement, source, count=1, flags=re.MULTILINE)
        if count != 1:
            raise ScorecardError(f"could not find the {description} in the scorecard README")
        return updated

    text = replace_once(
        r"^\| classic [^|]+ \(Docker, root\) \| \d+ \| \d+ \| \d+ \|$",
        (
            f"| classic {classic['meta']['classic_version']} (Docker, root) | "
            f"{classic_summary['ok']} | {classic_summary['failed']} | {classic_summary['cant']} |"
        ),
        text,
        "classic Docker summary row",
    )
    text = replace_once(
        r"^\| go \(this tree, Docker, root, privileged, `--internet`\) \| \d+ \| \d+ \| \d+ \|$",
        (
            "| go (this tree, Docker, root, privileged, `--internet`) | "
            f"{go_summary['ok']} | {go_summary['failed']} | {go_summary['cant']} |"
        ),
        text,
        "Go Docker summary row",
    )
    text = replace_once(
        r"Vs classic Docker, Go has \d+ OK against \d+\s+classic OK "
        r"\(`parity_gap_total` \d+ in `go-vs-classic-docker-gaps\.json`\)\.",
        (
            f"Vs classic Docker, Go has {go_summary['ok']} OK against "
            f"{classic_summary['ok']}\nclassic OK (`parity_gap_total` "
            f"{gaps['parity_gap_total']} in `go-vs-classic-docker-gaps.json`)."
        ),
        text,
        "Docker parity summary sentence",
    )
    return text


def publish(
    classic_dir: pathlib.Path,
    go_dir: pathlib.Path,
    destination: pathlib.Path,
    readme_path: pathlib.Path,
    *,
    source_revision: str = "",
) -> tuple[dict[str, Any], dict[str, Any]]:
    classic = validate_result(
        classic_dir / "classic-docker-baseline.json",
        label="classic",
        source_revision=source_revision,
    )
    go = validate_result(
        go_dir / "go-docker-baseline.json",
        label="go",
        source_revision=source_revision,
    )
    validate_reports(classic_dir, go_dir, classic, go)
    gaps = load_json(go_dir / "go-vs-classic-docker-gaps.json")
    new_readme = update_readme(readme_path.read_text(), classic, go, gaps)

    copies = {
        classic_dir / "classic-docker-baseline.json": destination / "classic-docker-baseline.json",
        classic_dir / "classic-docker-baseline.summary.txt": destination / "classic-docker-baseline.summary.txt",
        classic_dir / "host-vs-docker-verify.json": destination / "classic-docker-vs-host.json",
        go_dir / "go-docker-baseline.json": destination / "go-docker-baseline.json",
        go_dir / "go-docker-baseline.summary.txt": destination / "go-docker-baseline.summary.txt",
        go_dir / "go-vs-classic-docker-gaps.json": destination / "go-vs-classic-docker-gaps.json",
    }
    payloads: dict[pathlib.Path, bytes] = {}
    for source, target in copies.items():
        try:
            payloads[target] = source.read_bytes()
        except FileNotFoundError as exc:
            raise ScorecardError(f"missing scorecard output: {source}") from exc
    payloads[readme_path] = new_readme.encode()

    destination.mkdir(parents=True, exist_ok=True)
    pending: list[tuple[pathlib.Path, pathlib.Path]] = []
    try:
        for target, payload in payloads.items():
            temp = target.with_name(f".{target.name}.scorecard-update-{os.getpid()}")
            temp.write_bytes(payload)
            pending.append((temp, target))
        for temp, target in pending:
            os.replace(temp, target)
    finally:
        for temp, _ in pending:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
    return classic, go


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-result", help="validate one full Docker result")
    validate.add_argument("path", type=pathlib.Path)
    validate.add_argument("--label", choices=("classic", "go"), required=True)
    validate.add_argument("--source-revision", default="")

    publish_parser = commands.add_parser("publish", help="publish two validated runs")
    publish_parser.add_argument("--classic-dir", type=pathlib.Path, required=True)
    publish_parser.add_argument("--go-dir", type=pathlib.Path, required=True)
    publish_parser.add_argument("--destination", type=pathlib.Path, required=True)
    publish_parser.add_argument("--readme", type=pathlib.Path, required=True)
    publish_parser.add_argument("--source-revision", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    try:
        if args.command == "validate-result":
            doc = validate_result(
                args.path,
                label=args.label,
                source_revision=args.source_revision,
            )
            summary = doc["summary"]
            print(
                f"validated {args.label}: OK={summary['ok']} FAILED={summary['failed']} "
                f"CANT={summary['cant']} total={summary['total_recorded']}"
            )
            return 0
        classic, go = publish(
            args.classic_dir,
            args.go_dir,
            args.destination,
            args.readme,
            source_revision=args.source_revision,
        )
        print(
            "published Docker scorecards: "
            f"classic OK={classic['summary']['ok']}, Go OK={go['summary']['ok']}"
        )
        return 0
    except ScorecardError as exc:
        print(f"scorecard update refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
