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

Remain compatible with official classic socat unless a difference is an
intentional, documented security exception.

Official repository:

- `https://repo.or.cz/socat.git`
- `git://repo.or.cz/socat.git`

Use the latest released tag as the primary baseline and current master as the
secondary baseline. Record exact commits and report release/master differences
before implementing.

Read `doc/socat.yo` from the same tag or commit. Do not use third-party source
or man-page mirrors when the official repository is available.

Treat the man page as the documented interface. For `[=<bool>]`, accept `0`,
`1`, or omission meaning `1`. If documentation and implementation disagree,
report it before choosing behavior.

Document security deviations in the README under “Intentional differences from
classic socat” or “Unsupported / security-related”, and add a short comment at
the relevant call site. Ask before introducing any other incompatibility.

Run `make classic-parity` for compatibility-changing work. It compares against
the pinned release and reviewed master in `scripts/classic-baseline.json`.
Review master drift before updating that file.

Do not commit official source extracts, binaries, generated catalogs, or
`-hhh`/`-V` dumps. Compatibility classifications belong in
`scripts/classic-policy.json`.

Ordinary `make check` must remain independent of repo.or.cz.

## Testing guidelines

- Assert observable behavior or documented contracts (`doc/socat.yo`), not incidental presentation.
- Do not freeze undocumented whitespace, tab counts, timestamp formats, or internal log phrasing.
- Build constraints over runtime skips: use `//go:build linux || darwin` or OS-specific filenames (`*_unix_test.go`). Never use `if runtime.GOOS == "windows" { t.Skip() }` in cross-platform test files.
- Never use bare `t.Skip()`; every skip must provide an explicit explanation (e.g., `t.Skip("requires root (CAP_NET_ADMIN)")`).
- No fixed `time.Sleep` for synchronization: use channels, socket readiness, or bounded context cancellations.
- For negative assertions (quiescence / verifying no unexpected message arrives), synchronize on an observable barrier (e.g., marker packet or stream flush) rather than arbitrary sleep windows.
- Test against interface contracts; do not assert unexported concrete types (e.g., `*udpForkListener`, `*cancelConn`) across package boundaries unless internal unit logic is the explicit target.
- Regression tests must demonstrably fail when the bug is reintroduced.
- Do not add tests solely to increase coverage percentage.

## Required validation

Before committing:

- Run `make check` on Linux.
- When working from Windows, also run native `go test ./...`.

Do not commit failing checks. Skip a required check only with explicit user
authorization, and report every skipped check.

