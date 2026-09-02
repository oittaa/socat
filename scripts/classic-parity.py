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
    r"^\s{6}([A-Za-z][A-Za-z0-9.+_-]*)(?:[:\[].*?)?\s+groups=(\S+)\s*$"
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


def feature_complete_defines_for(goos: str | None = None) -> tuple[str, ...]:
    """Defines required before trusting a native classic -hhh dump.

    Linux reference builds include tcp-wrappers. Darwin typically does not
    ship libwrap; OpenSSL and readline are still required there.
    """
    plat = (goos or sys.platform).lower()
    if plat in ("darwin", "macos"):
        return ("WITH_OPENSSL", "WITH_READLINE")
    return FEATURE_COMPLETE_DEFINES


def missing_feature_complete(text: str, *, goos: str | None = None) -> list[str]:
    return [
        name
        for name in feature_complete_defines_for(goos)
        if not feature_defined(text, name)
    ]


def parse_go_flag_field(field: str) -> list[str]:
    field = field.split("<", 1)[0].split("[", 1)[0]
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
            # PIPE[:<filename>] and SHELL[:<command>] must not become PIPE[ / SHELL[.
            name = re.split(r"[:\[]", token, maxsplit=1)[0].upper().rstrip(">")
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


def _platform_block_names(plat: dict[str, Any], goos: str) -> set[str]:
    block = plat.get(goos) or {}
    if isinstance(block, dict):
        return set(block.keys())
    if isinstance(block, list):
        return set(block)
    return set()


def platform_option_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_options") or {}
    return _platform_block_names(plat, goos)


def platform_extra_option_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_extra_options") or {}
    return _platform_block_names(plat, goos)


def platform_unsupported_option_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_unsupported_options") or {}
    return _platform_block_names(plat, goos)


def platform_unsupported_flag_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_unsupported_flags") or {}
    return _platform_block_names(plat, goos)


def other_platform_options(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_options") or {}
    names: set[str] = set()
    for other in plat:
        if other == goos:
            continue
        names.update(_platform_block_names(plat, other))
    return names


def platform_address_set(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_addresses") or {}
    return {n.upper() for n in _platform_block_names(plat, goos)}


def other_platform_addresses(policy: dict[str, Any], goos: str) -> set[str]:
    plat = policy.get("platform_addresses") or {}
    names: set[str] = set()
    for other in plat:
        if other == goos:
            continue
        names.update(_platform_block_names(plat, other))
    return {n.upper() for n in names}


def resolve_alias(aliases: dict[str, str], name: str) -> str:
    seen: set[str] = set()
    cur = name
    while cur in aliases and cur not in seen:
        seen.add(cur)
        cur = aliases[cur]
    return cur


def alias_universe(*maps: dict[str, str]) -> set[str]:
    names: set[str] = set()
    for aliases in maps:
        names.update(aliases.keys())
        names.update(aliases.values())
    return names


def spellings_for_policy_seed(
    seed: str, *maps: dict[str, str], include_canonical: bool
) -> set[str]:
    """Names covered by one policy entry.

    Pass official (classic) alias maps only. Do not pass the Go
    implementation's alias map: that would let it expand its own allowlist.

    include_canonical=True (unsupported/foreign/platform): the seed, its
    resolved canonical, and every official spelling that resolves to that
    canonical.

    include_canonical=False (parser-only aliases): the seed and official
    spellings that resolve *to the seed*, not the documented canonical it
    points at.

    Go-only names are listed explicitly; call this with no alias maps.
    """
    out = {seed}
    for aliases in maps:
        if include_canonical:
            canon = resolve_alias(aliases, seed)
            out.add(canon)
            target = canon
        else:
            target = seed
        for name in alias_universe(aliases) | {seed}:
            if name == target or resolve_alias(aliases, name) == target:
                out.add(name)
    return out


def expand_policy_spellings(
    seeds: Iterable[str],
    *maps: dict[str, str],
    include_canonical: bool,
) -> set[str]:
    out: set[str] = set()
    for seed in seeds:
        if not seed:
            continue
        out |= spellings_for_policy_seed(
            seed, *maps, include_canonical=include_canonical
        )
    return out


def equivalence_groups(policy: dict[str, Any], key: str, *, upper: bool) -> list[set[str]]:
    """Named canonical groups that should compare as one alias class."""
    out: list[set[str]] = []
    for block in policy.get(key) or []:
        if not isinstance(block, list):
            continue
        names = {str(n).upper() if upper else str(n).lower() for n in block if n}
        if names:
            out.append(names)
    return out


def same_alias_class(
    alias: str,
    classic_aliases: dict[str, str],
    go_aliases: dict[str, str],
    extra_groups: Iterable[set[str]] | None = None,
) -> bool:
    """True when Go's chosen canonical is in the same classic alias class."""
    go_canon = resolve_alias(go_aliases, alias)
    classic_canon = resolve_alias(classic_aliases, alias)
    if resolve_alias(classic_aliases, go_canon) == classic_canon:
        return True
    if extra_groups:
        for group in extra_groups:
            if go_canon in group and classic_canon in group:
                return True
    return False


def name_matches_family(name: str, family: str) -> bool:
    """Match DCCP4-LISTEN to DCCP, OPENSSL-DTLS-CLIENT to DTLS, UDPLITE6 to UDPLITE."""
    name = name.upper()
    family = family.upper()
    if not family or not name:
        return False
    if name == family:
        return True
    if name.startswith(family + "-"):
        return True
    if len(name) > len(family) and name.startswith(family) and name[len(family)].isdigit():
        return True
    return family in name.split("-")


def group_tokens(groups: str) -> set[str]:
    return {part.upper() for part in groups.split(",") if part}


def expand_address_families(
    families: set[str],
    extracted: ExtractedInterface,
) -> set[str]:
    """Propagate policy family names through official aliases and -hhh groups."""
    if not families:
        return set()
    names = set(extracted.addresses)
    names.update(extracted.address_aliases.keys())
    names.update(extracted.address_aliases.values())
    unsupported: set[str] = set()
    for name in names:
        if any(name_matches_family(name, fam) for fam in families):
            unsupported.add(name)
            continue
        groups = extracted.address_groups.get(name, "")
        if not groups:
            groups = extracted.address_groups.get(
                resolve_alias(extracted.address_aliases, name), ""
            )
        if group_tokens(groups) & families:
            unsupported.add(name)
    changed = True
    while changed:
        changed = False
        for alias, target in extracted.address_aliases.items():
            if alias in unsupported and target not in unsupported:
                unsupported.add(target)
                changed = True
            if target in unsupported and alias not in unsupported:
                unsupported.add(alias)
                changed = True
    return unsupported


def expand_go_only_addresses(seeds: set[str], advertised: Iterable[str]) -> set[str]:
    """Family roots only: WS covers WS-LISTEN, not WSS. No alias-map expansion.

    Call only for go_only_addresses. platform_addresses must not use this:
    a Linux family seed such as SCTP would hide invented Go names like SCTP-TYPO.
    """
    seeds_u = {s.upper() for s in seeds if s}
    out = set(seeds_u)
    for name in advertised:
        upper = name.upper()
        if any(name_matches_family(upper, seed) for seed in seeds_u):
            out.add(upper)
    return out


def normalize_git_url(url: str) -> str:
    """Compare official git:// and https:// URLs without accepting other hosts."""
    u = url.strip().rstrip("/")
    if u.lower().endswith(".git"):
        u = u[:-4]
    lower = u.lower()
    for prefix in ("git://", "https://", "http://", "ssh://"):
        if lower.startswith(prefix):
            u = u[len(prefix) :]
            lower = u.lower()
            break
    else:
        if "@" in u:
            _, rest = u.split("@", 1)
            if ":" in rest and not rest.startswith("//"):
                host, path = rest.split(":", 1)
                u = host + "/" + path.lstrip("/")
    return u.lower().rstrip("/")


def origin_is_official(actual: str, expected: str) -> bool:
    return normalize_git_url(actual) == normalize_git_url(expected)


def origin_url(repo: Path) -> str:
    return run_cmd(["git", "-C", str(repo), "remote", "get-url", "origin"]).stdout.strip()


def assert_official_origin(repo: Path, expected_url: str) -> None:
    actual = origin_url(repo)
    if not origin_is_official(actual, expected_url):
        raise SystemExit(
            f"workdir origin {actual!r} is not the official repository {expected_url!r}"
        )


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
    master_feature_defines_missing: list[str] = field(default_factory=list)
    current_master_commit: str = ""
    master_review_drift: bool = False

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
            or self.feature_defines_missing
            or self.master_feature_defines_missing
            or self.master_review_drift
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "release_tag": self.release_tag,
            "release_commit": self.release_commit,
            "reviewed_master_commit": self.reviewed_master_commit,
            "current_master_commit": self.current_master_commit,
            "master_review_drift": self.master_review_drift,
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
            "master_feature_defines_missing": self.master_feature_defines_missing,
        }


def _fmt_name_list(names: list[str], limit: int | None = None) -> str:
    if not names:
        return "(none)"
    if limit is not None and len(names) > limit:
        shown = ", ".join(names[:limit])
        shown += f" ... (+{len(names) - limit})"
        return f"{len(names)}: {shown}"
    return f"{len(names)}: {', '.join(names)}"


def format_parity_report(report: CompareReport) -> str:
    """Human-readable summary for `make classic-parity`."""
    drift = "yes" if report.master_review_drift else "no"
    result = "FAIL" if report.has_failures() else "ok"
    lines = [
        "classic parity",
        f"  GOOS: {report.goos}",
        f"  release: {report.release_tag} ({report.release_commit})",
        f"  reviewed master: {report.reviewed_master_commit}",
        f"  current official master: {report.current_master_commit or '(unknown)'}",
        f"  master review drift: {drift}",
        f"  missing options: {_fmt_name_list(report.missing_options)}",
        f"  missing addresses: {_fmt_name_list(report.missing_addresses)}",
        f"  missing flags: {_fmt_name_list(report.missing_flags)}",
        f"  unexpected options: {_fmt_name_list(report.unexpected_options)}",
        f"  unexpected addresses: {_fmt_name_list(report.unexpected_addresses)}",
        f"  unexpected flags: {_fmt_name_list(report.unexpected_flags)}",
        f"  option alias mismatches: {len(report.option_alias_mismatches)}",
        f"  address alias mismatches: {len(report.address_alias_mismatches)}",
        f"  feature defines missing: {_fmt_name_list(report.feature_defines_missing)}",
        f"  master feature defines missing: {_fmt_name_list(report.master_feature_defines_missing)}",
        f"  result: {result}",
    ]
    if report.master_review_drift:
        lines.append(
            "  official master moved past the reviewed commit; "
            "review the drift and update scripts/classic-baseline.json"
        )
    return "\n".join(lines) + "\n"


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
    master_feature_defines_missing: list[str] | None = None,
    current_master_commit: str = "",
) -> CompareReport:
    release_public = merge_extracted(release_docs, release_hhh or ExtractedInterface())
    master_public = merge_extracted(
        master_docs or ExtractedInterface(), master_hhh or ExtractedInterface()
    )
    official_opt_aliases = merge_extracted(
        release_public, master_public
    ).option_aliases
    unsupported_opts = expand_policy_spellings(
        {n.lower() for n in policy_name_set(policy, "unsupported_options", "foreign_options")},
        official_opt_aliases,
        include_canonical=True,
    )
    parser_only = expand_policy_spellings(
        {n.lower() for n in policy_name_set(policy, "parser_only_options")},
        official_opt_aliases,
        include_canonical=False,
    )
    go_only_opts = expand_policy_spellings(
        {n.lower() for n in policy_name_set(policy, "go_only_options")},
        include_canonical=True,
    )
    other_plat = expand_policy_spellings(
        {n.lower() for n in other_platform_options(policy, goos)},
        official_opt_aliases,
        include_canonical=True,
    )
    this_plat = expand_policy_spellings(
        {n.lower() for n in platform_option_set(policy, goos)},
        official_opt_aliases,
        include_canonical=True,
    )
    this_plat_extras = {
        n.lower() for n in platform_extra_option_set(policy, goos)
    }
    plat_unsup = expand_policy_spellings(
        {n.lower() for n in platform_unsupported_option_set(policy, goos)},
        official_opt_aliases,
        include_canonical=True,
    )
    official_merged = merge_extracted(release_public, master_public)
    family_seeds = {n.upper() for n in policy_name_set(policy, "unsupported_addresses")}
    unsupported_addrs = expand_address_families(family_seeds, official_merged)
    # Platform families waive official Linux-only addresses as missing on
    # Darwin/Windows. They must not waive extra Go spellings on this GOOS.
    other_plat_addrs = expand_address_families(
        other_platform_addresses(policy, goos), official_merged
    )
    go_only_addrs = expand_go_only_addresses(
        {n.upper() for n in policy_name_set(policy, "go_only_addresses")},
        go_help.addresses,
    )
    unsupported_flags = policy_name_set(policy, "unsupported_flags")
    plat_unsup_flags = platform_unsupported_flag_set(policy, goos)
    go_only_flags = policy_name_set(policy, "go_only_flags")
    option_equiv = equivalence_groups(policy, "option_canonical_equivalences", upper=False)
    address_equiv = equivalence_groups(policy, "address_canonical_equivalences", upper=True)

    advertised_opts = set(release_public.options)
    advertised_addrs = set(release_public.addresses)
    advertised_flags = set(release_public.flags)
    reviewed_master = str(baseline.get("reviewed_master_commit", ""))
    current_master = current_master_commit or reviewed_master

    report = CompareReport(
        release_tag=str(baseline.get("release_tag", "")),
        release_commit=str(baseline.get("release_commit", "")),
        reviewed_master_commit=reviewed_master,
        goos=goos,
        feature_defines_missing=list(feature_defines_missing or []),
        master_feature_defines_missing=list(master_feature_defines_missing or []),
        current_master_commit=current_master,
        master_review_drift=bool(current_master and current_master != reviewed_master),
    )

    for name in sorted(advertised_opts):
        if name in go_help.options:
            continue
        if name in parser_only:
            report.parser_only_ignored.append(name)
            continue
        if name in unsupported_opts or name in other_plat or name in plat_unsup:
            continue
        report.missing_options.append(name)

    for name in sorted(advertised_addrs):
        if name in go_help.addresses:
            continue
        if name in unsupported_addrs or name in other_plat_addrs:
            continue
        report.missing_addresses.append(name)

    for name in sorted(advertised_flags):
        if name in go_help.flags:
            continue
        if name in unsupported_flags or name in plat_unsup_flags:
            continue
        report.missing_flags.append(name)

    for name in sorted(go_help.options):
        if name in advertised_opts:
            continue
        if name in go_only_opts or name in this_plat or name in this_plat_extras:
            continue
        if name in master_public.options:
            continue
        report.unexpected_options.append(name)

    for name in sorted(go_help.addresses):
        if name in advertised_addrs:
            continue
        if name in go_only_addrs:
            continue
        if name in master_public.addresses:
            continue
        report.unexpected_addresses.append(name)

    for name in sorted(go_help.flags):
        if name in advertised_flags:
            continue
        if name in go_only_flags:
            continue
        if name in master_public.flags:
            continue
        report.unexpected_flags.append(name)

    for alias, _target in sorted(release_public.option_aliases.items()):
        if alias in parser_only:
            if alias not in report.parser_only_ignored:
                report.parser_only_ignored.append(alias)
            continue
        if alias not in go_help.options and (
            alias in unsupported_opts or alias in other_plat or alias in plat_unsup
        ):
            continue
        if alias not in go_help.option_aliases:
            continue
        go_canon = resolve_alias(go_help.option_aliases, alias)
        classic_canon = resolve_alias(release_public.option_aliases, alias)
        if not same_alias_class(
            alias,
            release_public.option_aliases,
            go_help.option_aliases,
            option_equiv,
        ):
            report.option_alias_mismatches.append(
                {"alias": alias, "classic": classic_canon, "go": go_canon}
            )

    for alias, _target in sorted(release_public.address_aliases.items()):
        if alias in unsupported_addrs or alias in other_plat_addrs:
            continue
        if alias not in go_help.address_aliases:
            continue
        go_canon = resolve_alias(go_help.address_aliases, alias)
        classic_canon = resolve_alias(release_public.address_aliases, alias)
        if not same_alias_class(
            alias,
            release_public.address_aliases,
            go_help.address_aliases,
            address_equiv,
        ):
            report.address_alias_mismatches.append(
                {"alias": alias, "classic": classic_canon, "go": go_canon}
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


def worktree_path(workdir: Path, kind: str, commit: str) -> Path:
    """Checkout path for one baseline pin. Commit-specific so pin updates do not reuse dest."""
    return workdir / "worktrees" / f"{kind}-{commit}"


def baseline_worktree(workdir: Path, baseline: dict[str, Any], kind: str) -> Path:
    if kind == "release":
        commit = str(baseline["release_commit"])
    elif kind == "master":
        commit = str(baseline["reviewed_master_commit"])
    else:
        raise SystemExit(f"unknown worktree kind {kind!r}")
    return worktree_path(workdir, kind, commit)


def sync_classic(workdir: Path, baseline: dict[str, Any]) -> dict[str, Any]:
    """Clone/fetch official socat. Never deletes workdir or caller paths."""
    workdir.mkdir(parents=True, exist_ok=True)
    repo = workdir / "repo"
    release_tag = str(baseline["release_tag"])
    release_commit = str(baseline["release_commit"])
    master_commit = str(baseline["reviewed_master_commit"])
    url = str(baseline["repository"])

    if is_git_repo(repo):
        assert_official_origin(repo, url)
        run_git_retry(["git", "-C", str(repo), "fetch", "--tags", "origin"])
        run_git_retry(
            [
                "git",
                "-C",
                str(repo),
                "fetch",
                "origin",
                "+refs/heads/master:refs/remotes/origin/master",
            ]
        )
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", release_commit])
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", master_commit])
    else:
        if repo.exists() and any(repo.iterdir()):
            raise SystemExit(
                f"refusing to clone into non-empty {repo}; "
                "refusing to delete a caller-supplied path"
            )
        run_git_retry(["git", "clone", "--bare", url, str(repo)])
        assert_official_origin(repo, url)
        run_git_retry(["git", "-C", str(repo), "fetch", "--tags", "origin"])
        run_git_retry(
            [
                "git",
                "-C",
                str(repo),
                "fetch",
                "origin",
                "+refs/heads/master:refs/remotes/origin/master",
            ]
        )
        run_git_retry(["git", "-C", str(repo), "fetch", "origin", master_commit])

    tag_sha = run_cmd(
        ["git", "-C", str(repo), "rev-parse", f"{release_tag}^{{commit}}"]
    ).stdout.strip()
    if tag_sha != release_commit:
        raise SystemExit(
            f"release tag {release_tag} resolves to {tag_sha}, expected {release_commit}"
        )

    current_master = run_cmd(
        ["git", "-C", str(repo), "rev-parse", "refs/remotes/origin/master"]
    ).stdout.strip()
    master_review_drift = current_master != master_commit

    wt_root = workdir / "worktrees"
    wt_root.mkdir(parents=True, exist_ok=True)
    release_wt = worktree_path(workdir, "release", release_commit)
    master_wt = worktree_path(workdir, "master", master_commit)
    ensure_worktree(repo, release_wt, release_commit)
    ensure_worktree(repo, master_wt, master_commit)
    return {
        "repo": str(repo),
        "release_worktree": str(release_wt),
        "master_worktree": str(master_wt),
        "release_commit": release_commit,
        "reviewed_master_commit": master_commit,
        "current_master_commit": current_master,
        "master_review_drift": master_review_drift,
        "release_tag": release_tag,
        "origin_url": origin_url(repo),
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
    missing = missing_feature_complete(v_text, goos=sys.platform)
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


def classic_build_plan(tree: Path) -> list[str]:
    """Configure is never skipped just because a Makefile already exists."""
    steps: list[str] = []
    if not (tree / "configure").exists():
        steps.append("autoconf")
    if (tree / "Makefile").exists():
        steps.append("distclean")
        if not (tree / "configure").exists():
            steps.append("autoconf")
    steps.append("configure")
    steps.append("make")
    return steps


def build_classic(tree: Path, outdir: Path) -> dict[str, str]:
    if sys.platform not in ("linux", "darwin"):
        raise SystemExit(f"classic build is not supported on {sys.platform}")
    env = os.environ.copy()

    def ensure_configure() -> None:
        if (tree / "configure").exists():
            return
        if (tree / "autoconf.sh").exists():
            run_cmd(["sh", "autoconf.sh"], cwd=tree, env=env)
        else:
            run_cmd(["autoconf"], cwd=tree, env=env)

    for step in classic_build_plan(tree):
        if step == "autoconf":
            ensure_configure()
        elif step == "distclean":
            run_cmd(["make", "distclean"], cwd=tree, env=env, check=False)
            ensure_configure()
        elif step == "configure":
            run_cmd(["./configure"], cwd=tree, env=env)
        elif step == "make":
            run_cmd(["make"], cwd=tree, env=env)
        else:
            raise SystemExit(f"unknown classic build step {step!r}")
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


def inspect_classic_v(
    v_path: Path | None, hhh_used: bool, *, goos: str | None = None
) -> list[str]:
    """Fail closed: -hhh is untrusted without a complete -V dump."""
    if not hhh_used:
        return []
    if v_path is None or not v_path.exists():
        return ["socat -V output missing"]
    text = v_path.read_text(encoding="utf-8", errors="replace")
    if not text.strip():
        return ["socat -V output empty"]
    return missing_feature_complete(text, goos=goos)


def read_current_master_commit(workdir: Path) -> str:
    repo = workdir / "repo"
    if not is_git_repo(repo):
        return ""
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "refs/remotes/origin/master"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def resolve_v_path(explicit: str | None, hhh_path: Path, fallback: Path) -> Path:
    if explicit:
        return Path(explicit)
    sibling = hhh_path.parent / "socat-V.txt"
    if sibling.exists():
        return sibling
    return fallback


def cmd_sync(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    info = sync_classic(workdir, baseline)
    json.dump(info, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


def cmd_path(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    sys.stdout.write(str(baseline_worktree(workdir, baseline, args.tree)) + "\n")
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    tree = baseline_worktree(workdir, baseline, args.tree)
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
        baseline = load_baseline(Path(args.baseline) if args.baseline else None)
        tree = baseline_worktree(workdir, baseline, args.tree)
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


def compare_from_workdir(
    *,
    workdir: Path,
    baseline: dict[str, Any],
    policy: dict[str, Any],
    goos: str | None = None,
    go_binary: str | None = None,
    go_help: str | None = None,
    release_yo: str | None = None,
    master_yo: str | None = None,
    release_hhh: str | None = None,
    master_hhh: str | None = None,
    release_v: str | None = None,
    master_v: str | None = None,
) -> CompareReport:
    root = repo_root()
    if not goos:
        goos = run_cmd(["go", "env", "GOOS"], cwd=root).stdout.strip()

    release_yo_path = (
        Path(release_yo)
        if release_yo
        else baseline_worktree(workdir, baseline, "release") / "doc" / "socat.yo"
    )
    master_yo_path = (
        Path(master_yo)
        if master_yo
        else baseline_worktree(workdir, baseline, "master") / "doc" / "socat.yo"
    )
    release_hhh_path = (
        Path(release_hhh) if release_hhh else workdir / "out" / "release" / "socat-hhh.txt"
    )
    master_hhh_path = (
        Path(master_hhh) if master_hhh else workdir / "out" / "master" / "socat-hhh.txt"
    )
    release_v_path = resolve_v_path(
        release_v,
        release_hhh_path,
        workdir / "out" / "release" / "socat-V.txt",
    )
    master_v_path = resolve_v_path(
        master_v,
        master_hhh_path,
        workdir / "out" / "master" / "socat-V.txt",
    )

    if not release_yo_path.exists():
        raise SystemExit(f"missing {release_yo_path}; run sync first")
    release_docs = parse_socat_yo(release_yo_path.read_text(encoding="utf-8", errors="replace"))
    master_docs = None
    if master_yo_path.exists():
        master_docs = parse_socat_yo(master_yo_path.read_text(encoding="utf-8", errors="replace"))

    release_hhh_iface = None
    feature_missing: list[str] = []
    if release_hhh_path.exists():
        release_hhh_iface = parse_classic_hhh(
            release_hhh_path.read_text(encoding="utf-8", errors="replace")
        )
        feature_missing = inspect_classic_v(release_v_path, True, goos=goos)
    master_hhh_iface = None
    master_feature_missing: list[str] = []
    if master_hhh_path.exists():
        master_hhh_iface = parse_classic_hhh(
            master_hhh_path.read_text(encoding="utf-8", errors="replace")
        )
        master_feature_missing = inspect_classic_v(master_v_path, True, goos=goos)

    if go_help:
        go_text = Path(go_help).read_text(encoding="utf-8", errors="replace")
    elif go_binary:
        go_text = run_cmd([str(Path(go_binary)), "-hhh"]).stdout
    else:
        go_bin = build_go_binary(root, workdir / "out" / "go-socat")
        go_text = run_cmd([str(go_bin), "-hhh"]).stdout
    go_iface = parse_go_help(go_text)

    return compare_interfaces(
        release_docs=release_docs,
        release_hhh=release_hhh_iface,
        master_docs=master_docs,
        master_hhh=master_hhh_iface,
        go_help=go_iface,
        policy=policy,
        baseline=baseline,
        goos=goos,
        feature_defines_missing=feature_missing,
        master_feature_defines_missing=master_feature_missing,
        current_master_commit=read_current_master_commit(workdir),
    )


def cmd_compare(args: argparse.Namespace) -> int:
    report = compare_from_workdir(
        workdir=Path(args.workdir).resolve(),
        baseline=load_baseline(Path(args.baseline) if args.baseline else None),
        policy=load_policy(Path(args.policy) if args.policy else None),
        goos=args.goos,
        go_binary=args.go_binary,
        go_help=args.go_help,
        release_yo=args.release_yo,
        master_yo=args.master_yo,
        release_hhh=args.release_hhh,
        master_hhh=args.master_hhh,
        release_v=args.release_v,
        master_v=args.master_v,
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


def cmd_run(args: argparse.Namespace) -> int:
    """Sync, build official trees, compare native Go -hhh, print a summary."""
    workdir = Path(args.workdir).resolve()
    baseline = load_baseline(Path(args.baseline) if args.baseline else None)
    policy = load_policy(Path(args.policy) if args.policy else None)
    sync_classic(workdir, baseline)
    build_classic(
        baseline_worktree(workdir, baseline, "release"), workdir / "out" / "release"
    )
    build_classic(
        baseline_worktree(workdir, baseline, "master"), workdir / "out" / "master"
    )
    report = compare_from_workdir(
        workdir=workdir,
        baseline=baseline,
        policy=policy,
        goos=args.goos,
        go_binary=args.go_binary,
        go_help=args.go_help,
    )
    sys.stdout.write(format_parity_report(report))
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
    return 1 if report.has_failures() else 0


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

    path = sub.add_parser("path", help="print a pinned classic worktree path")
    add_common_args(path)
    path.add_argument("--tree", choices=("release", "master"), default="release")
    path.set_defaults(func=cmd_path)

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
    compare.add_argument("--release-v", help="socat -V dump for --release-hhh")
    compare.add_argument("--master-v", help="socat -V dump for --master-hhh")
    compare.add_argument("--out")
    compare.add_argument(
        "--fail-on-diff",
        action="store_true",
        help="exit 1 on name/alias diffs, incomplete -V, or official master SHA drift",
    )
    compare.set_defaults(func=cmd_compare)

    run = sub.add_parser(
        "run",
        help=(
            "sync, build official trees, and compare native Go -hhh "
            "(make classic-parity; always fails on diffs or master drift)"
        ),
    )
    add_common_args(run)
    run.add_argument("--policy")
    run.add_argument("--goos")
    run.add_argument("--go-binary")
    run.add_argument("--go-help")
    run.add_argument("--out", help="optional JSON report path under the workdir")
    run.set_defaults(func=cmd_run)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
