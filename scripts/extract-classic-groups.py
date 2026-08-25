#!/usr/bin/env python3
"""Extract address and option groups from classic socat 1.8.1.3 sources.

Option keywords come from the alphabetically sorted optionnames[] table in
xioopts.c, each mapped through the optdesc symbol it references. Deriving
keywords from optdesc defname/nickname is incorrect: duplicate nicknames
exist (noatime, pktinfo) and classic parseopts looks up optionnames[].

Usage:
  python3 scripts/extract-classic-groups.py /tmp/socat-classic > internal/xio/classicgroups_gen.go
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ATOMIC = {
    "GROUP_FD": "fd",
    "GROUP_FIFO": "fifo",
    "GROUP_CHR": "chr",
    "GROUP_BLK": "blk",
    "GROUP_REG": "reg",
    "GROUP_FILE": "reg",
    "GROUP_SOCKET": "socket",
    "GROUP_READLINE": "readline",
    "GROUP_NAMED": "named",
    "GROUP_OPEN": "open",
    "GROUP_EXEC": "exec",
    "GROUP_FORK": "fork",
    "GROUP_LISTEN": "listen",
    "GROUP_SHELL": "shell",
    "GROUP_CHILD": "child",
    "GROUP_RETRY": "retry",
    "GROUP_TERMIOS": "termios",
    "GROUP_RANGE": "range",
    "GROUP_PTY": "pty",
    "GROUP_PARENT": "parent",
    "GROUP_SOCK_UNIX": "sock-unix",
    "GROUP_SOCK_IP4": "sock-ip4",
    "GROUP_SOCK_IP6": "sock-ip6",
    "GROUP_INTERFACE": "interface",
    "GROUP_TUN": "interface",
    "GROUP_IP_UDP": "ip-udp",
    "GROUP_IP_TCP": "ip-tcp",
    "GROUP_IP_SOCKS": "socks",
    "GROUP_IP_SOCKS4": "socks",
    "GROUP_OPENSSL": "openssl",
    "GROUP_PROCESS": "process",
    "GROUP_APPL": "appl",
    "GROUP_HTTP": "http",
    "GROUP_REMOTE": "remote",
    "GROUP_POSIXMQ": "posixmq",
    "GROUP_IP_SCTP": "ip-sctp",
    "GROUP_IP_DCCP": "ip-dccp",
    "GROUP_IP_UDPLITE": "ip-udplite",
}

COMPOSITE = {
    "GROUP_SOCK_IP": ["sock-ip4", "sock-ip6"],
    "GROUP_IPAPP": ["ip-udp", "ip-tcp", "ip-sctp", "ip-dccp", "ip-udplite"],
    "GROUP_ANY": ["process", "appl"],
}

ADDR_BLOCK_RE = re.compile(r"const struct addrdesc\s+(\w+)\s*=\s*\{(.*?)\}\s*;", re.S)
OPT_BLOCK_RE = re.compile(r"const struct optdesc\s+(\w+)\s*=\s*\{(.*?)\};", re.S)
ADDRNAME_RE = re.compile(r'\{\s*"([^"]+)"\s*,\s*&(\w+)\s*\}')
OPTNAME_ENTRY_RE = re.compile(r'IF_[A-Z0-9]+\s*\(\s*"([^"]+)"\s*,\s*&(\w+)\s*\)')
OPTNAMES_ARRAY_RE = re.compile(
    r"const struct optname optionnames\[\]\s*=\s*\{(.*?)^\}\s*;",
    re.S | re.M,
)
STRING_RE = re.compile(r'"([^"]*)"')


def strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def expand_groups(expr: str) -> list[str]:
    expr = " ".join(strip_comments(expr).split())
    out: list[str] = []
    seen: set[str] = set()
    for tok in re.findall(r"GROUP_[A-Z0-9_]+", expr):
        if tok in ("GROUP_NONE", "GROUP_ADDR", "GROUP_ALL"):
            continue
        names = COMPOSITE.get(tok)
        if names is None:
            name = ATOMIC.get(tok)
            names = [name] if name else []
        for name in names:
            if name not in seen:
                seen.add(name)
                out.append(name)
    return out


def groups_expr(block: str) -> str:
    m = re.search(r"((?:GROUP_[A-Z0-9_]+(?:\s*\|\s*)?)+)", strip_comments(block))
    return m.group(1) if m else ""


def c_strings(block: str) -> list[str]:
    return STRING_RE.findall(strip_comments(block))


def go_str(value: str) -> str:
    return json.dumps(value)


def go_strings(values: list[str]) -> str:
    if not values:
        return "nil"
    inner = ", ".join(go_str(v) for v in values)
    return f"[]string{{{inner}}}"


def classic_root(path: Path) -> Path:
    if (path / "xioopts.c").is_file():
        return path
    nested = path / "src"
    if (nested / "xioopts.c").is_file():
        return nested
    raise FileNotFoundError(f"xioopts.c not found under {path}")


def parse_optdesc_groups(src: Path) -> dict[str, list[str]]:
    symbols: dict[str, list[str]] = {}
    for path in sorted(src.glob("xio*.c")):
        text = strip_comments(path.read_text(errors="replace"))
        for m in OPT_BLOCK_RE.finditer(text):
            symbols[m.group(1)] = expand_groups(groups_expr(m.group(2)))
    return symbols


def parse_optionnames(src: Path) -> list[tuple[str, str]]:
    text = strip_comments((src / "xioopts.c").read_text(errors="replace"))
    m = OPTNAMES_ARRAY_RE.search(text)
    if not m:
        raise ValueError("optionnames[] not found in xioopts.c")
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, symbol in OPTNAME_ENTRY_RE.findall(m.group(1)):
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        entries.append((key, symbol))
    if not entries:
        raise ValueError("optionnames[] contained no IF_* keyword entries")
    return entries


def generate(src: Path) -> str:
    src = classic_root(src)
    files = sorted(src.glob("xio*.c"))
    text = strip_comments("\n".join(p.read_text(errors="replace") for p in files))

    addresses: dict[str, list[str]] = {}
    symbol_to_name: dict[str, str] = {}
    for m in ADDR_BLOCK_RE.finditer(text):
        block = m.group(2)
        name = (c_strings(block) or [""])[0].upper()
        if not name:
            continue
        symbol_to_name[m.group(1)] = name
        addresses[name] = expand_groups(groups_expr(block))

    aliases: dict[str, str] = {}
    open_c = (src / "xioopen.c").read_text(errors="replace")
    for m in ADDRNAME_RE.finditer(open_c):
        alias = m.group(1).upper()
        target = symbol_to_name.get(m.group(2))
        if target and alias != target:
            aliases[alias] = target
            if alias not in addresses and target in addresses:
                addresses[alias] = addresses[target]

    optdesc = parse_optdesc_groups(src)
    options: dict[str, list[str]] = {}
    missing: list[str] = []
    for keyword, symbol in parse_optionnames(src):
        groups = optdesc.get(symbol)
        if groups is None:
            missing.append(f"{keyword}->{symbol}")
            continue
        options[keyword] = groups
    if missing:
        raise ValueError("optionnames[] referenced unknown optdesc symbols: " + ", ".join(missing))

    lines = [
        "// Code generated from classic socat tag-1.8.1.3. DO NOT EDIT.",
        "// Source: https://repo.or.cz/socat.git tag-1.8.1.3",
        "// (addrdesc in xio*.c, addressnames[] in xioopen.c, optionnames[] in xioopts.c).",
        "//go:generate python3 ../../scripts/extract-classic-groups.py /tmp/socat-classic",
        "",
        "package xio",
        "",
        "// ClassicAddressGroups is the expanded GROUP_* set for each address keyword",
        "// in classic socat 1.8.1.3. Aliases from addressnames[] are included.",
        "var ClassicAddressGroups = map[string][]string{",
    ]
    for name in sorted(addresses):
        lines.append(f"\t{go_str(name)}: {go_strings(addresses[name])},")
    lines.extend(
        [
            "}",
            "",
            "// ClassicOptionGroups is the expanded GROUP_* set for each option keyword",
            "// in classic socat 1.8.1.3, taken from optionnames[] via its optdesc symbol.",
            "var ClassicOptionGroups = map[string][]string{",
        ]
    )
    for name in sorted(options):
        lines.append(f"\t{go_str(name)}: {go_strings(options[name])},")
    lines.extend(
        [
            "}",
            "",
            "// ClassicAddressAliases maps addressnames[] aliases to the canonical addrdesc name.",
            "var ClassicAddressAliases = map[string]string{",
        ]
    )
    for name in sorted(aliases):
        lines.append(f"\t{go_str(name)}: {go_str(aliases[name])},")
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/socat-classic")
    sys.stdout.write(generate(src))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
