#!/usr/bin/env python3
"""Extract address and option groups from classic socat 1.8.1.3 sources.

Usage:
  python3 scripts/extract-classic-groups.py /tmp/socat-classic/src > internal/xio/classicgroups_gen.go
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
OPT_BLOCK_RE = re.compile(r"const struct optdesc\s+\w+\s*=\s*\{(.*?)\};", re.S)
ADDRNAME_RE = re.compile(r'\{\s*"([^"]+)"\s*,\s*&(\w+)\s*\}')
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


def set_option(options: dict[str, list[str]], name: str | None, groups: list[str], overwrite: bool) -> None:
    if not name:
        return
    key = name.lower()
    if overwrite or key not in options:
        options[key] = groups


def main() -> int:
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/socat-classic/src")
    files = list(src.glob("xio*.c"))
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

    options: dict[str, list[str]] = {}
    for m in OPT_BLOCK_RE.finditer(text):
        block = strip_comments(m.group(1))
        strings = c_strings(block)
        if not strings:
            continue
        groups = expand_groups(groups_expr(block))
        set_option(options, strings[0], groups, overwrite=True)
        if len(strings) > 1:
            set_option(options, strings[1], groups, overwrite=False)

    print("// Code generated from classic socat tag-1.8.1.3. DO NOT EDIT.")
    print("// Source: git://repo.or.cz/socat.git tag-1.8.1.3 (xio*.c, xioopen.c).")
    print("//go:generate python3 ../../scripts/extract-classic-groups.py /tmp/socat-classic/src")
    print()
    print("package xio")
    print()
    print("// ClassicAddressGroups is the expanded GROUP_* set for each address keyword")
    print("// in classic socat 1.8.1.3. Aliases from addressnames[] are included.")
    print("var ClassicAddressGroups = map[string][]string{")
    for name in sorted(addresses):
        print(f"\t{go_str(name)}: {go_strings(addresses[name])},")
    print("}")
    print()
    print("// ClassicOptionGroups is the expanded GROUP_* set for each option keyword")
    print("// and nickname in classic socat 1.8.1.3. A defname wins over a later nickname.")
    print("var ClassicOptionGroups = map[string][]string{")
    for name in sorted(options):
        print(f"\t{go_str(name)}: {go_strings(options[name])},")
    print("}")
    print()
    print("// ClassicAddressAliases maps addressnames[] aliases to the canonical addrdesc name.")
    print("var ClassicAddressAliases = map[string]string{")
    for name in sorted(aliases):
        print(f"\t{go_str(name)}: {go_str(aliases[name])},")
    print("}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
