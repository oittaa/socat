#!/usr/bin/env python3
"""Transient official-socat compatibility audit.

Downloads official classic socat into a gitignored working directory,
extracts the public interface from doc/socat.yo and socat -hhh, and
compares it with this project's advertised names.

Does not write official source, binaries, help dumps, or rendered
documentation into tracked paths. Production Go code does not import
this tool's output.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

FEATURE_COMPLETE_DEFINES = ("WITH_OPENSSL", "WITH_READLINE", "WITH_LIBWRAP")
FETCH_BACKOFF_SECONDS = (4, 8, 16, 32)

ADDRESS_LABEL_RE = re.compile(r"^ADDRESS_")
OPTION_LABEL_RE = re.compile(r"^OPTION_")
CLI_TOKEN_RE = re.compile(r"^-[A-Za-z0-9?-]+$")
OPTION_NAME_CUT_RE = re.compile(r"[=:\[>\s]")
ADDRESS_TOKEN_RE = re.compile(r"^[A-Za-z][A-Za-z0-9.+_-]*$")
# Classic help pads with tabs; long GROUP_IPAPP lists can glue into "UDPLITEphase=".
HHH_OPT_DETAIL_RE = re.compile(
    r"^\s{6}(\S+)\s+groups=(\S+?)(?:\s*)phase=(\S+)\s+type=(\S+)\s*$"
)
HHH_OPT_ALIAS_RE = re.compile(r"^\s{6}(\S+)\s+is an alias for (\S+)\s*$")
HHH_ADDR_DETAIL_RE = re.compile(
    r"^\s{6}([A-Za-z][A-Za-z0-9.+_-]*)(?::\S*)?\s+groups=(\S+)\s*$"
)
HHH_ADDR_ALIAS_RE = re.compile(
    r"^\s{6}([A-Za-z][A-Za-z0-9.+_-]*)\s+is an alias name for ([A-Za-z][A-Za-z0-9.+_-]*)\s*$"
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_workdir(root: Path | None = None) -> Path:
    return (root or repo_root()) / "testdata" / "tmp" / "classic-parity"


def default_workdir_arg() -> str:
    env = os.environ.get("SOCAT_CLASSIC_PARITY_WORKDIR")
    if env:
        return env
    return str(default_workdir())


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def default_baseline_path() -> Path:
    return Path(__file__).resolve().parent / "classic-baseline.json"


def default_policy_path() -> Path:
    return Path(__file__).resolve().parent / "classic-policy.json"


def load_baseline(path: Path | None = None) -> dict[str, Any]:
    return load_json(path or default_baseline_path())


def load_policy(path: Path | None = None) -> dict[str, Any]:
    return load_json(path or default_policy_path())


def _ident_cont(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def matching_paren(text: str, open_idx: int) -> int:
    """Return the index of the ')' that closes text[open_idx] == '('."""
    if open_idx >= len(text) or text[open_idx] != "(":
        raise ValueError("matching_paren requires '('")
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced parenthesis")


def take_macro(text: str, start: int, name: str) -> tuple[str, int] | None:
    """If text[start:] begins with name(, return (inner, index after closing paren).

    Requires a non-identifier character before name so startdit( is not dit(.
    """
    token = name + "("
    if not text.startswith(token, start):
        return None
    if start > 0 and _ident_cont(text[start - 1]):
        return None
    open_idx = start + len(name)
    close_idx = matching_paren(text, open_idx)
    return text[open_idx + 1 : close_idx], close_idx + 1


def next_macro(text: str, start: int, names: Iterable[str]) -> tuple[str, str, int] | None:
    """Find the next named macro at or after start. Returns (name, inner, end)."""
    named = tuple(names)
    n = len(text)
    i = start
    while i < n:
        if text[i] == "(":
            for name in named:
                ns = i - len(name)
                if ns < start:
                    continue
                taken = take_macro(text, ns, name)
                if taken is not None:
                    inner, end = taken
                    return name, inner, end
        i += 1
    return None


def strip_comment_macros(text: str) -> str:
    """Remove COMMENT(...) including nested parentheses, left to right."""
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        taken = take_macro(text, i, "COMMENT")
        if taken is not None:
            _, end = taken
            i = end
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def collect_tt_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    i = 0
    while True:
        found = next_macro(text, i, ("tt",))
        if found is None:
            break
        _, inner, end = found
        bodies.append(inner)
        i = end
    return bodies


def spelling_from_option_tt(inner: str) -> str | None:
    inner = inner.strip()
    if not inner:
        return None
    cut = OPTION_NAME_CUT_RE.search(inner)
    name = inner[: cut.start()] if cut else inner
    name = name.strip().rstrip(">").lower()
    if not name or name.startswith("-"):
        return None
    if not re.match(r"^[a-z][\w.-]*$", name):
        return None
    return name


def address_keywords_from_tt(inner: str) -> list[str]:
    inner = inner.strip()
    if not inner or inner.startswith("-"):
        return []
    first = inner.split(":", 1)[0]
    first = first.strip().rstrip(">").upper()
    if not ADDRESS_TOKEN_RE.match(first):
        return []
    return [first]


def cli_flags_from_tt(inner: str) -> list[str]:
    flags: list[str] = []
    for chunk in re.split(r"\s*\|\s*", inner):
        chunk = chunk.strip()
        if not chunk.startswith("-"):
            continue
        token = chunk.split("<", 1)[0].split("[", 1)[0].split(" ", 1)[0].rstrip(")")
        if CLI_TOKEN_RE.match(token):
            flags.append(token)
    return flags


@dataclass
class ExtractedInterface:
    options: set[str] = field(default_factory=set)
    option_aliases: dict[str, str] = field(default_factory=dict)
    addresses: set[str] = field(default_factory=set)
    address_aliases: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)
    option_meta: dict[str, dict[str, str]] = field(default_factory=dict)
    address_groups: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "options": sorted(self.options),
            "option_aliases": dict(sorted(self.option_aliases.items())),
            "addresses": sorted(self.addresses),
            "address_aliases": dict(sorted(self.address_aliases.items())),
            "flags": sorted(self.flags),
            "option_meta": dict(sorted(self.option_meta.items())),
            "address_groups": dict(sorted(self.address_groups.items())),
        }


def _apply_option_tts(out: ExtractedInterface, tts: list[str]) -> None:
    names: list[str] = []
    for body in tts:
        sp = spelling_from_option_tt(body)
        if sp:
            names.append(sp)
    if not names:
        return
    canonical = names[0]
    out.options.add(canonical)
    for alias in names[1:]:
        if alias != canonical:
            out.options.add(alias)
            out.option_aliases[alias] = canonical


def _apply_address_tts(out: ExtractedInterface, tts: list[str]) -> None:
    names: list[str] = []
    for body in tts:
        names.extend(address_keywords_from_tt(body))
    if not names:
        return
    canonical = names[0]
    out.addresses.add(canonical)
    for alias in names[1:]:
        if alias != canonical:
            out.addresses.add(alias)
            out.address_aliases[alias] = canonical


def _apply_flag_tts(out: ExtractedInterface, tts: list[str]) -> None:
    for body in tts:
        for flag in cli_flags_from_tt(body):
            out.flags.add(flag)


def parse_socat_yo(text: str) -> ExtractedInterface:
    """Parse public names from doc/socat.yo with a balanced-macro walk."""
    text = strip_comment_macros(text)
    out = ExtractedInterface()
    i = 0
    n = len(text)
    while i < n:
        taken_label = take_macro(text, i, "label")
        if taken_label is not None:
            label_inner, label_end = taken_label
            j = label_end
            while j < n and text[j] in " \t\n\r":
                j += 1
            dit = take_macro(text, j, "dit")
            if dit is None:
                i = label_end
                continue
            dit_inner, dit_end = dit
            tts = collect_tt_bodies(dit_inner)
            label = label_inner.strip()
            if ADDRESS_LABEL_RE.match(label):
                _apply_address_tts(out, tts)
            elif OPTION_LABEL_RE.match(label):
                _apply_option_tts(out, tts)
            else:
                _apply_flag_tts(out, tts)
            i = dit_end
            continue
        taken_dit = take_macro(text, i, "dit")
        if taken_dit is not None:
            dit_inner, dit_end = taken_dit
            _apply_flag_tts(out, collect_tt_bodies(dit_inner))
            i = dit_end
            continue
        i += 1
    return out


def parse_classic_hhh(text: str) -> ExtractedInterface:
    """Parse addresses, options, aliases, and diagnostic group/phase/type from -hhh."""
    out = ExtractedInterface()
    if text.startswith("   opts:"):
        opts_idx = 0
        addr_text = ""
        opt_text = text
    else:
        opts_idx = text.find("\n   opts:")
        if opts_idx >= 0:
            addr_text = text[:opts_idx]
            opt_text = text[opts_idx + 1 :]
        else:
            addr_text = text
            opt_text = ""

    for line in addr_text.splitlines():
        m = HHH_ADDR_ALIAS_RE.match(line)
        if m:
            alias, target = m.group(1).upper(), m.group(2).upper()
            out.addresses.add(alias)
            out.addresses.add(target)
            out.address_aliases[alias] = target
            continue
        m = HHH_ADDR_DETAIL_RE.match(line)
        if m:
            name = m.group(1).upper()
            out.addresses.add(name)
            out.address_groups[name] = m.group(2)
            continue

    if not opt_text:
        return out
    for line in opt_text.splitlines():
        m = HHH_OPT_ALIAS_RE.match(line)
        if m:
            alias, target = m.group(1).lower(), m.group(2).lower()
            out.options.add(alias)
            out.options.add(target)
            out.option_aliases[alias] = target
            continue
        m = HHH_OPT_DETAIL_RE.match(line)
        if m:
            name = m.group(1).lower()
            out.options.add(name)
            out.option_meta[name] = {
                "groups": m.group(2),
                "phase": m.group(3),
                "type": m.group(4),
            }
    return out


def parse_classic_v(text: str) -> dict[str, bool]:
    features: dict[str, bool] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#undef "):
            name = line.split()[1]
            features[name] = False
            continue
        if line.startswith("#define "):
            parts = line.split()
            name = parts[1]
            # A later #undef wins if both appear; last line in file order wins.
            features[name] = True
    return features


def feature_defined(text: str, name: str) -> bool:
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#undef " + name) and (
            line == "#undef " + name or line.startswith("#undef " + name + " ")
        ):
            return False
        if line == "#define " + name or line.startswith("#define " + name + " "):
            return True
    return False


def missing_feature_complete(text: str) -> list[str]:
    return [name for name in FEATURE_COMPLETE_DEFINES if not feature_defined(text, name)]


def parse_go_flag_field(field: str) -> list[str]:
    field = field.split("<", 1)[0]
    flags: list[str] = []
    for part in field.split("|"):
        part = part.strip()
        if ".." in part:
            part = part.split("..", 1)[0]
        if CLI_TOKEN_RE.match(part):
            flags.append(part)
    return flags


def parse_go_help(text: str) -> ExtractedInterface:
    """Parse this project's socat -hhh output."""
    out = ExtractedInterface()
    section = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("Options:"):
            section = "flags"
            continue
        if line.startswith("Address types:"):
            section = "addresses"
            continue
        if line.startswith("Address options:"):
            section = "options"
            continue
        if not line.strip():
            continue
        if section == "flags":
            stripped = line.lstrip()
            if stripped.startswith("-"):
                field = stripped.split(None, 1)[0]
                for flag in parse_go_flag_field(field):
                    out.flags.add(flag)
            continue
        if section == "addresses":
            if not line.startswith("    "):
                continue
            token = line.strip().split(None, 1)[0]
            rest = line.strip()[len(token) :].strip()
            name = token.split(":", 1)[0].upper()
            if not ADDRESS_TOKEN_RE.match(name):
                continue
            if rest.lower().startswith("alias of "):
                target = rest[len("alias of ") :].split()[0].split(":", 1)[0].upper()
                out.addresses.add(name)
                out.addresses.add(target)
                out.address_aliases[name] = target
            else:
                out.addresses.add(name)
            continue
        if section == "options":
            if not line.startswith("    "):
                continue
            token = line.strip().split(None, 1)[0]
            rest = line.strip()[len(token) :].strip()
            name = token.lower()
            if not re.match(r"^[a-z][\w.-]*$", name):
                continue
            out.options.add(name)
            if rest.lower().startswith("alias of "):
                target = rest[len("alias of ") :].split()[0].lower()
                out.option_aliases[name] = target
    return out


def merge_extracted(*parts: ExtractedInterface) -> ExtractedInterface:
    out = ExtractedInterface()
    for part in parts:
        out.options |= part.options
        out.addresses |= part.addresses
        out.flags |= part.flags
        out.option_aliases.update(part.option_aliases)
        out.address_aliases.update(part.address_aliases)
        out.option_meta.update(part.option_meta)
        out.address_groups.update(part.address_groups)
    return out


def policy_name_set(policy: dict[str, Any], *keys: str) -> set[str]:
    names: set[str] = set()
    for key in keys:
        block = policy.get(key) or {}
        if isinstance(block, dict):
            names.update(block.keys())
        elif isinstance(block, list):
            names.update(block)
    return names


def platform_option_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_options") or {}
    block = plat.get(goos) or {}
    if isinstance(block, dict):
        return set(block.keys())
    if isinstance(block, list):
        return set(block)
    return set()


def other_platform_options(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_options") or {}
    names: set[str] = set()
    for other, block in plat.items():
        if other == goos:
            continue
        if isinstance(block, dict):
            names.update(block.keys())
        elif isinstance(block, list):
            names.update(block)
    return names


def resolve_alias(aliases: dict[str, str], name: str) -> str:
    seen: set[str] = set()
    cur = name
    while cur in aliases and cur not in seen:
        seen.add(cur)
        cur = aliases[cur]
    return cur


@dataclass
class CompareReport:
    release_tag: str
    release_commit: str
    reviewed_master_commit: str
    goos: str
    missing_options: list[str] = field(default_factory=list)
    missing_addresses: list[str] = field(default_factory=list)
    missing_flags: list[str] = field(default_factory=list)
    unexpected_options: list[str] = field(default_factory=list)
    unexpected_addresses: list[str] = field(default_factory=list)
    unexpected_flags: list[str] = field(default_factory=list)
    option_alias_mismatches: list[dict[str, str]] = field(default_factory=list)
    address_alias_mismatches: list[dict[str, str]] = field(default_factory=list)
    release_master_option_drift: list[str] = field(default_factory=list)
    release_master_address_drift: list[str] = field(default_factory=list)
    parser_only_ignored: list[str] = field(default_factory=list)
    feature_defines_missing: list[str] = field(default_factory=list)

    def has_failures(self) -> bool:
        return bool(
            self.missing_options
            or self.missing_addresses
            or self.missing_flags
            or self.unexpected_options
            or self.unexpected_addresses
            or self.unexpected_flags
            or self.option_alias_mismatches
            or self.address_alias_mismatches
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "release_tag": self.release_tag,
            "release_commit": self.release_commit,
            "reviewed_master_commit": self.reviewed_master_commit,
            "goos": self.goos,
            "missing_options": self.missing_options,
            "missing_addresses": self.missing_addresses,
            "missing_flags": self.missing_flags,
            "unexpected_options": self.unexpected_options,
            "unexpected_addresses": self.unexpected_addresses,
            "unexpected_flags": self.unexpected_flags,
            "option_alias_mismatches": self.option_alias_mismatches,
            "address_alias_mismatches": self.address_alias_mismatches,
            "release_master_option_drift": self.release_master_option_drift,
            "release_master_address_drift": self.release_master_address_drift,
            "parser_only_ignored": self.parser_only_ignored,
            "feature_defines_missing": self.feature_defines_missing,
        }


def compare_interfaces(
    *,
    release_docs: ExtractedInterface,
    release_hhh: ExtractedInterface | None,
    master_docs: ExtractedInterface | None,
    master_hhh: ExtractedInterface | None,
    go_help: ExtractedInterface,
    policy: dict[str, Any],
    baseline: dict[str, Any],
    goos: str,
    feature_defines_missing: list[str] | None = None,
) -> CompareReport:
    release_public = merge_extracted(release_docs, release_hhh or ExtractedInterface())
    master_public = merge_extracted(
        master_docs or ExtractedInterface(), master_hhh or ExtractedInterface()
    )
    unsupported_opts = {
        n.lower()
        for n in policy_name_set(policy, "unsupported_options", "foreign_options")
    }
    parser_only = {n.lower() for n in policy_name_set(policy, "parser_only_options")}
    go_only_opts = {n.lower() for n in policy_name_set(policy, "go_only_options")}
    other_plat = {n.lower() for n in other_platform_options(policy, goos)}
    this_plat = {n.lower() for n in platform_option_set(policy, goos)}
    unsupported_addrs = {n.upper() for n in policy_name_set(policy, "unsupported_addresses")}
    go_only_addrs = {n.upper() for n in policy_name_set(policy, "go_only_addresses")}

    advertised_opts = set(release_public.options)
    advertised_addrs = set(release_public.addresses)
    advertised_flags = set(release_public.flags)

    report = CompareReport(
        release_tag=str(baseline.get("release_tag", "")),
        release_commit=str(baseline.get("release_commit", "")),
        reviewed_master_commit=str(baseline.get("reviewed_master_commit", "")),
        goos=goos,
        feature_defines_missing=list(feature_defines_missing or []),
    )

    for name in sorted(advertised_opts):
        if name in go_help.options:
            continue
        if name in parser_only:
            report.parser_only_ignored.append(name)
            continue
        if name in unsupported_opts or name in other_plat:
            continue
        report.missing_options.append(name)

    for name in sorted(advertised_addrs):
        if name in go_help.addresses:
            continue
        if name in unsupported_addrs:
            continue
        report.missing_addresses.append(name)

    for name in sorted(advertised_flags):
        if name not in go_help.flags:
            report.missing_flags.append(name)

    for name in sorted(go_help.options):
        if name in advertised_opts or name in go_only_opts or name in this_plat:
            continue
        if name in master_public.options:
            continue
        report.unexpected_options.append(name)

    for name in sorted(go_help.addresses):
        if name in advertised_addrs or name in go_only_addrs:
            continue
        if name in master_public.addresses:
            continue
        report.unexpected_addresses.append(name)

    for name in sorted(go_help.flags):
        if name in advertised_flags:
            continue
        if name in master_public.flags:
            continue
        report.unexpected_flags.append(name)

    for alias, target in sorted(release_public.option_aliases.items()):
        if alias in parser_only:
            if alias not in report.parser_only_ignored:
                report.parser_only_ignored.append(alias)
            continue
        if alias not in go_help.options and (
            alias in unsupported_opts or alias in other_plat
        ):
            continue
        if alias not in go_help.option_aliases:
            continue
        go_canon = resolve_alias(go_help.option_aliases, alias)
        classic_canon = resolve_alias(release_public.option_aliases, alias)
        if go_canon != classic_canon:
            report.option_alias_mismatches.append(
                {"alias": alias, "classic": target, "go": go_help.option_aliases[alias]}
            )

    for alias, target in sorted(release_public.address_aliases.items()):
        if alias in unsupported_addrs:
            continue
        if alias not in go_help.address_aliases:
            continue
        go_canon = resolve_alias(go_help.address_aliases, alias)
        classic_canon = resolve_alias(release_public.address_aliases, alias)
        if go_canon != classic_canon:
            report.address_alias_mismatches.append(
                {"alias": alias, "classic": target, "go": go_help.address_aliases[alias]}
            )

    if master_docs is not None or master_hhh is not None:
        report.release_master_option_drift = sorted(
            (master_public.options - advertised_opts)
            | (advertised_opts - master_public.options)
        )
        report.release_master_address_drift = sorted(
            (master_public.addresses - advertised_addrs)
            | (advertised_addrs - master_public.addresses)
        )

    return report


def run_cmd(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if check and proc.returncode != 0:
        err = (proc.stderr or "") + (proc.stdout or "")
        raise subprocess.CalledProcessError(
            proc.returncode, args, output=proc.stdout, stderr=err or proc.stderr
        )
    return proc


def run_git_retry(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    delays = (0,) + FETCH_BACKOFF_SECONDS
    last: BaseException | None = None
    for i, delay in enumerate(delays):
        if delay:
            time.sleep(delay)
        try:
            return run_cmd(args, cwd=cwd)
        except subprocess.CalledProcessError as exc:
            last = exc
            stderr = (exc.stderr or "") + (exc.stdout or "")
            networkish = any(
                token in stderr.lower()
                for token in (
                    "unable to access",
                    "could not resolve",
                    "connection",
                    "timed out",
                    "network",
                    "temporary failure",
                )
            )
            if not networkish or i == len(delays) - 1:
                raise
    assert last is not None
    raise last


def git_head(path: Path) -> str:
    proc = run_cmd(["git", "rev-parse", "HEAD"], cwd=path)
    return proc.stdout.strip()


def is_git_repo(path: Path) -> bool:
    if not path.exists():
        return False
    proc = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--git-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def sync_classic(workdir: Path, baseline: dict[str, Any]) -> dict[str, str]:
    """Clone/fetch official socat. Never deletes workdir or caller paths."""
    workdir.mkdir(parents=True, exist_ok=True)
    repo = workdir / "repo"
    release_tag = str(baseline["release_tag"])
    release_commit = str(baseline["release_commit"])
    master_commit = str(baseline["reviewed_master_commit"])
    url = str(baseline["repository"])

    if is_git_repo(repo):
        run_git_retry(["git", "-C", str(repo), "fetch", "--tags", "origin"])
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", master_commit])
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", release_commit])
    else:
        if repo.exists() and any(repo.iterdir()):
            raise SystemExit(
                f"refusing to clone into non-empty {repo}; "
                "refusing to delete a caller-supplied path"
            )
        run_git_retry(["git", "clone", "--bare", url, str(repo)])
        run_git_retry(["git", "-C", str(repo), "fetch", "--tags", "origin"])
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", master_commit])

    tag_sha = run_cmd(
        ["git", "-C", str(repo), "rev-parse", f"{release_tag}^{{commit}}"]
    ).stdout.strip()
    if tag_sha != release_commit:
        raise SystemExit(
            f"release tag {release_tag} resolves to {tag_sha}, expected {release_commit}"
        )

    wt_root = workdir / "worktrees"
    wt_root.mkdir(parents=True, exist_ok=True)
    release_wt = wt_root / "release"
    master_wt = wt_root / "master"
    ensure_worktree(repo, release_wt, release_commit)
    ensure_worktree(repo, master_wt, master_commit)
    return {
        "repo": str(repo),
        "release_worktree": str(release_wt),
        "master_worktree": str(master_wt),
        "release_commit": release_commit,
        "reviewed_master_commit": master_commit,
        "release_tag": release_tag,
    }


def ensure_worktree(repo: Path, dest: Path, commit: str) -> None:
    """Check out commit at dest. Never deletes dest if it already exists."""
    if dest.exists():
        if is_git_repo(dest):
            head = git_head(dest)
            if head != commit:
                raise SystemExit(
                    f"worktree {dest} is at {head}, expected {commit}; "
                    "refusing to delete a caller-supplied path"
                )
            return
        raise SystemExit(
            f"worktree path {dest} exists and is not the expected checkout; "
            "refusing to delete a caller-supplied path"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_cmd(["git", "-C", str(repo), "worktree", "add", "--detach", str(dest), commit])


def capture_classic_help(binary: Path, outdir: Path) -> dict[str, str]:
    """Run socat -V/-hhh into outdir. Refuse -hhh if feature defines are missing."""
    outdir.mkdir(parents=True, exist_ok=True)
    v_text = run_cmd([str(binary), "-V"]).stdout
    missing = missing_feature_complete(v_text)
    if missing:
        raise SystemExit(
            "classic binary is not feature-complete; missing "
            + ", ".join(missing)
            + "; refusing to trust -hhh"
        )
    hhh_text = run_cmd([str(binary), "-hhh"]).stdout
    v_path = outdir / "socat-V.txt"
    hhh_path = outdir / "socat-hhh.txt"
    v_path.write_text(v_text, encoding="utf-8")
    hhh_path.write_text(hhh_text, encoding="utf-8")
    return {
        "binary": str(binary),
        "v_path": str(v_path),
        "hhh_path": str(hhh_path),
    }


def build_classic(tree: Path, outdir: Path) -> dict[str, str]:
    if sys.platform not in ("linux", "darwin"):
        raise SystemExit(f"classic build is not supported on {sys.platform}")
    env = os.environ.copy()
    if not (tree / "configure").exists():
        # The git tag does not ship a generated configure. Use the tag's
        # config.h.in; do not run autoheader.
        if (tree / "autoconf.sh").exists():
            run_cmd(["sh", "autoconf.sh"], cwd=tree, env=env)
        else:
            run_cmd(["autoconf"], cwd=tree, env=env)
    if not (tree / "Makefile").exists():
        run_cmd(["./configure"], cwd=tree, env=env)
    run_cmd(["make"], cwd=tree, env=env)
    binary = tree / "socat"
    if not binary.exists():
        raise SystemExit(f"classic build produced no binary at {binary}")
    return capture_classic_help(binary, outdir)


def build_go_binary(root: Path, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    run_cmd(["go", "build", "-o", str(dest), "./cmd/socat"], cwd=root)
    return dest


def extract_from_paths(
    *,
    yo_path: Path | None = None,
    hhh_path: Path | None = None,
) -> ExtractedInterface:
    parts: list[ExtractedInterface] = []
    if yo_path is not None:
        parts.append(parse_socat_yo(yo_path.read_text(encoding="utf-8", errors="replace")))
    if hhh_path is not None:
        parts.append(parse_classic_hhh(hhh_path.read_text(encoding="utf-8", errors="replace")))
    if not parts:
        raise SystemExit("extract requires --yo and/or --hhh")
    return merge_extracted(*parts)


def cmd_sync(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    info = sync_classic(workdir, baseline)
    json.dump(info, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    tree = workdir / "worktrees" / args.tree
    if not tree.exists():
        raise SystemExit(f"missing worktree {tree}; run sync first")
    outdir = workdir / "out" / args.tree
    info = build_classic(tree, outdir)
    json.dump(info, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    yo = Path(args.yo) if args.yo else None
    hhh = Path(args.hhh) if args.hhh else None
    if yo is None and hhh is None:
        workdir = Path(args.workdir).resolve()
        tree = workdir / "worktrees" / args.tree
        yo = tree / "doc" / "socat.yo"
        hhh_candidate = workdir / "out" / args.tree / "socat-hhh.txt"
        hhh = hhh_candidate if hhh_candidate.exists() else None
        if not yo.exists():
            raise SystemExit(f"missing {yo}; run sync first")
    extracted = extract_from_paths(yo_path=yo, hhh_path=hhh)
    payload = extracted.to_json()
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    root = repo_root()
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    policy = load_policy(Path(args.policy) if args.policy else None)
    if args.goos:
        goos = args.goos
    else:
        goos = run_cmd(["go", "env", "GOOS"], cwd=root).stdout.strip()

    release_yo = (
        Path(args.release_yo)
        if args.release_yo
        else workdir / "worktrees" / "release" / "doc" / "socat.yo"
    )
    master_yo = (
        Path(args.master_yo)
        if args.master_yo
        else workdir / "worktrees" / "master" / "doc" / "socat.yo"
    )
    release_hhh_path = (
        Path(args.release_hhh)
        if args.release_hhh
        else workdir / "out" / "release" / "socat-hhh.txt"
    )
    master_hhh_path = (
        Path(args.master_hhh)
        if args.master_hhh
        else workdir / "out" / "master" / "socat-hhh.txt"
    )
    release_v_path = workdir / "out" / "release" / "socat-V.txt"

    if not release_yo.exists():
        raise SystemExit(f"missing {release_yo}; run sync first")
    release_docs = parse_socat_yo(release_yo.read_text(encoding="utf-8", errors="replace"))
    master_docs = None
    if master_yo.exists():
        master_docs = parse_socat_yo(master_yo.read_text(encoding="utf-8", errors="replace"))

    release_hhh = None
    feature_missing: list[str] = []
    if release_hhh_path.exists():
        release_hhh = parse_classic_hhh(
            release_hhh_path.read_text(encoding="utf-8", errors="replace")
        )
        if release_v_path.exists():
            feature_missing = missing_feature_complete(
                release_v_path.read_text(encoding="utf-8", errors="replace")
            )
    master_hhh = None
    if master_hhh_path.exists():
        master_hhh = parse_classic_hhh(
            master_hhh_path.read_text(encoding="utf-8", errors="replace")
        )

    if args.go_help:
        go_text = Path(args.go_help).read_text(encoding="utf-8", errors="replace")
    elif args.go_binary:
        go_text = run_cmd([str(Path(args.go_binary)), "-hhh"]).stdout
    else:
        go_bin = build_go_binary(root, workdir / "out" / "go-socat")
        go_text = run_cmd([str(go_bin), "-hhh"]).stdout
    go_help = parse_go_help(go_text)

    report = compare_interfaces(
        release_docs=release_docs,
        release_hhh=release_hhh,
        master_docs=master_docs,
        master_hhh=master_hhh,
        go_help=go_help,
        policy=policy,
        baseline=baseline,
        goos=goos,
        feature_defines_missing=feature_missing,
    )
    payload = report.to_json()
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    if args.fail_on_diff and report.has_failures():
        return 1
    return 0


def add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--workdir",
        default=default_workdir_arg(),
        help="gitignored working directory (never deleted)",
    )
    p.add_argument("--baseline", help="path to classic-baseline.json")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Audit this project's public names against official classic socat."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sync = sub.add_parser("sync", help="clone/fetch official socat into the workdir")
    add_common_args(sync)
    sync.set_defaults(func=cmd_sync)

    build = sub.add_parser("build", help="build classic inside the ignored workdir")
    add_common_args(build)
    build.add_argument("--tree", choices=("release", "master"), default="release")
    build.set_defaults(func=cmd_build)

    extract = sub.add_parser("extract", help="parse yo and/or -hhh into JSON")
    add_common_args(extract)
    extract.add_argument("--yo")
    extract.add_argument("--hhh")
    extract.add_argument("--tree", choices=("release", "master"), default="release")
    extract.add_argument("--out")
    extract.set_defaults(func=cmd_extract)

    compare = sub.add_parser("compare", help="compare official public names with Go -hhh")
    add_common_args(compare)
    compare.add_argument("--policy")
    compare.add_argument("--goos")
    compare.add_argument("--go-binary")
    compare.add_argument("--go-help")
    compare.add_argument("--release-yo")
    compare.add_argument("--master-yo")
    compare.add_argument("--release-hhh")
    compare.add_argument("--master-hhh")
    compare.add_argument("--out")
    compare.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="exit 1 when missing/unexpected names or alias mismatches remain",
    )
    compare.set_defaults(func=cmd_compare)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
