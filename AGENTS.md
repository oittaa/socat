# Repository Agent Instructions

## Supported platforms

Only Linux (`linux`), macOS (`darwin`), and Windows (`windows`) are supported.
Unsupported `GOOS` builds may fail. Do not add code, tests, constants,
fallbacks, or build support for other operating systems.

“Unix” means Linux and macOS only. Do not use Go’s broad `unix` build tag.

Build constraints:

- Shared Linux/macOS: `//go:build linux || darwin`
- OS-specific: `//go:build linux`, `darwin`, or `windows`
- Multi-platform stubs must list each supported OS explicitly
- Do not use broad negative constraints such as `!windows`

`*_unix.go` is an ordinary filename; Go does not treat `unix` as a filename
platform suffix. `golang.org/x/sys/unix` is allowed. Names such as `BSDLY`,
`bsdly`, and `so-bsdcompat` are options, not platform support.

Do not create portability abstractions for unsupported or hypothetical
platforms. `make check` enforces these rules through `goos-check`.

## Help and comments

`socat -h`, `-hh`, and `-hhh` describe behavior only. Do not mention “classic”
or implementation details such as C function names, phases, groups, internal
types, or commit hashes.

Keep runtime comments short. Put compatibility evidence in PR descriptions,
focused tests, README exceptions, and parity reports.

## Classic socat compatibility

Follow the man page (`doc/socat.yo` from the pinned classic release) over
classic socat's implementation. Do not reproduce classic bugs or
backwards-compatibility quirks. Where `doc/socat.yo` does not specify
behavior, match classic's implementation. Deviate from the man page only
when that deviation is explicitly documented in a call-site comment, the
README, or AGENTS.md. Ask before introducing a new deviation from the man
page.

Official repository:

- `https://repo.or.cz/socat.git`
- `git://repo.or.cz/socat.git`

Use the latest released tag as the primary baseline and current master as the
secondary baseline. Record exact commits and report release/master differences
before implementing. Read `doc/socat.yo` from that tag or commit. Do not use
third-party source or man-page mirrors when the official repository is
available.

Treat the man page as the documented interface. For `[=<bool>]`, accept `0`,
`1`, or omission meaning `1`.

Go-only extensions (for example Go duration syntax, or
`yes`/`no`/`true`/`false` booleans) are a superset only. Every documented
classic form must still be accepted, and each extension must be documented
in the README.

Decode command-line, address, and option values once, during parsing and
preparation, into typed values (bools, enums, numbers, durations). Subsystems
must not re-parse option strings. Validate before side effects such as
creating files or opening sockets.

Malformed values, missing required values, and options that do not apply to
an address fail with an error. Do not fall back or ignore them. Unrecognized
environment-variable values are the exception: log a warning and use the
default.

Access-control and security filters (for example tcpwrap) fail closed on
syntax they do not support.

Document security deviations in the README under “Intentional differences from
classic socat” or “Unsupported / security-related”, and add a short comment at
the relevant call site.

Run `make classic-parity` for compatibility-changing work. It compares against
the pinned release and reviewed master in `scripts/classic-baseline.json`.
Review master drift before updating that file.

Do not commit official source extracts, binaries, generated catalogs, or
`-hhh`/`-V` dumps. Classify name-level differences (omitted, extra,
parser-only, or per-OS) in `scripts/classic-policy.json` with a reason.
Document behavior differences per the man-page rule above.

Ordinary `make check` must remain independent of repo.or.cz.

## Testing guidelines

- Assert observable behavior or documented contracts (`doc/socat.yo`), not incidental presentation.
- Do not freeze undocumented whitespace, tab counts, timestamp formats, or internal log phrasing.
- Build constraints over runtime skips: use `//go:build linux || darwin` or OS-specific filenames (`*_linux_test.go`, `*_darwin_test.go`, `*_windows_test.go`). Never use `if runtime.GOOS == "windows" { t.Skip() }` in cross-platform test files.
- Never use bare `t.Skip()`; every skip must provide an explicit explanation (e.g., `t.Skip("requires root (CAP_NET_ADMIN)")`).
- No fixed `time.Sleep` for synchronization: use channels, socket readiness, or bounded context cancellations.
- For negative assertions (quiescence / verifying no unexpected message arrives), synchronize on an observable barrier (e.g., marker packet or stream flush) rather than arbitrary sleep windows.
- Test against interface contracts; do not assert unexported concrete types (e.g., `*udpForkListener`, `*cancelConn`) across package boundaries unless internal unit logic is the explicit target.
- Regression tests must demonstrably fail when the bug is reintroduced.
- Do not add tests solely to increase coverage percentage.
- Do not hardcode individual source files or test/fuzz function names in Makefiles, CI, or runner scripts. Select packages or build tags, or discover files and targets automatically.
- `make check` enforces build constraints through `goos-check`.

## Required validation

Before committing:

- Run `make check` on Linux.
- When working from Windows, also run native `go test ./...`.

Do not commit failing checks. Skip a required check only with explicit user
authorization, and report every skipped check.
