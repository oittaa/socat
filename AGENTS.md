# Repository Agent Instructions

## Supported platforms

Only Linux (`linux`), macOS (`darwin`), and Windows (`windows`) are supported.
Unsupported `GOOS` builds are allowed to fail. Never add AIX, Solaris,
illumos, FreeBSD, OpenBSD, NetBSD, or DragonFly support, tests, constants,
wrappers, or fallback implementations, and do not make those platforms
compile.

**Unix** in this project means Linux + macOS only. Go’s broad `unix` build
tag includes unsupported systems and must not be used.

Build constraints:

- Shared Linux/macOS files: `//go:build linux || darwin`
- OS-specific files: `//go:build linux`, `//go:build darwin`, or `//go:build windows`
- Do not use broad negatives (`!windows`, `!linux`, `!darwin`, `!unix`)
- If a stub is needed by more than one supported OS, list those OS names
  explicitly (for example `darwin || windows`)

`make check` (`goos-check`) rejects the `unix` tag, unsupported GOOS names
(AIX, Solaris, illumos, FreeBSD, OpenBSD, NetBSD, DragonFly, and other
KnownOS values besides linux/darwin/windows), and those broad negatives in
`*.go` files, including filename suffixes that imply those GOOS values.
`*_unix.go` is not an implicit `unix` tag (Go does not filename-match `unix`).
POSIX spellings such as `BSDLY` / `bsdly` / `so-bsdcompat` are option names,
not platform lists.

`golang.org/x/sys/unix` is fine; the restriction is platform scope, not the
package name. Do not create portability abstractions for hypothetical future
platforms.

## CLI help and comments

`socat -h` / `-hh` / `-hhh` describe behavior only. Do not mention classic C
internals (`groups=`, `phase=`, `type=`, `PH_*`, `TYPE_*`, `GROUP_*`,
`OFUNC_*`) or the word “classic”.

Runtime comments stay short. Do not narrate classic C control flow, commit
hashes, or C function names in production files. Compatibility evidence belongs
in PR descriptions, focused tests, README exceptions,
`scripts/classic-policy.json`, and `scripts/classic-parity.py` reports.

## Classic socat compatibility

Stay a drop-in replacement for classic socat
(`git://repo.or.cz/socat.git`, https://repo.or.cz/socat.git) unless a
change is a documented security exception.

Use the latest released tag from the official repository as the primary
compatibility baseline, and also check current master for newer behavior.
Cite the exact tag or commit used. Do not use third-party mirrors when the
official repository is available. If the latest release and master differ,
report the difference before implementing.

Also read the official man page from that same repository. `doc/socat.yo`
is the YODL source (https://repo.or.cz/socat.git/blob_plain/HEAD:/doc/socat.yo
is current master). Prefer `git show <tag>:doc/socat.yo` for the same tag
or commit used as the C-source baseline. The rendered HTML is
http://www.dest-unreach.org/socat/doc/socat.html. Do not use third-party
man-page mirrors when these are available.

The man page is the documented option interface, including types such as
`[=<bool>]` (value `"0"` or `"1"`; omitted value means `"1"`). Classic C
call sites sometimes only test whether the option is present. If the man
page and the C parser disagree, report the difference before implementing;
do not copy a presence-only check as the documented boolean interface.

Security-related deviations belong in README ("Intentional differences
from classic socat" / "Unsupported / security-related") and in a code
comment at the call site.

If a change would diverge from classic behavior for any other reason,
ask before implementing it.

Live comparison against official release and master is
`make classic-parity` (`scripts/classic-parity.py run`). Compatibility-changing
PRs should run it explicitly. Ordinary `make check` stays offline from
repo.or.cz. Scheduled parity failures caused by official master drift
require review and an intentional update of `scripts/classic-baseline.json`.
Do not check in official `-hhh`/`-V` dumps or a generated option catalog.
Policy classifications (unsupported, foreign, parser-only, platform-specific,
Go-only) live in `scripts/classic-policy.json`.

## Required pre-commit validation

Before committing, run `make check` from the repository root in a Linux
environment and require it to pass. When working from Windows, also run
`go test ./...` natively on Windows to catch platform-specific failures.

Do not commit with a failing check. A check may be skipped only when the user
explicitly authorizes it; report every skipped check in the final response.
