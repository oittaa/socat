# Classic -hhh catalog fixture

Baseline: official [`socat.git`](https://repo.or.cz/socat.git) `tag-1.8.1.3`
(`12c08bf66d709fba17035ce95d85bd218428d9ba`). Official master
`af5388c898c7bb60997935aee93c223deba60c4a` currently has identical `xiohelp.c`,
`xioopts.h`, `optionnames[]`, and `xio*.c`.

Files:

- `tag-1.8.1.3.hhh` — `opts:` section of `socat -hhh` from a feature-complete
  Ubuntu 26.04 / glibc 2.41+ Linux build (OpenSSL, GNU Readline, libwrap).
  **795** unique spellings, including `b7200` from a real `<termios.h>`
  `#define B7200 7200U`.
- `tag-1.8.1.3.V` — `socat -V` from that same binary (build provenance).
  The compile-date and kernel lines are sanitized so rebuilds do not churn
  git.

`b7200` is advertised when the host actually defines `B7200`. Ubuntu 26.04 /
glibc 2.41+ does that in `<bits/termios-baud.h>`. Older glibc (Ubuntu 24.04 /
2.39) does not; `scripts/build-classic-help-catalog.sh` then **fails** with a
prerequisite message. Do not pass `CPPFLAGS=-DB7200=7200U`. `b900` and
`b3600` remain HP-UX-only and stay in `DocsOnlyNotInThisBinary`.

`--enable-openssl-method` and `--enable-fips` stay off (configure defaults).
The documented names (`method`, `fips`) are in `DocsOnlyNotInThisBinary`.
Parser-only aliases `openssl-method` and `openssl-fips` are in
`OptionalParserOnlyAliases`. Documented `udp-ignore-peerport` (man
`OPTION_UDP_IGNORE_PEERPORT`; not in `optionnames[]`) is docs-only and
classified unsupported (classic C never implemented it; not backlog).
`cool-write` / `coolwrite` stay in the advertised catalog but are
`IntentionalPublicOmissions` (this port stopped advertising the deprecated
option). Do not pass `--enable-resolve` extra flags: resolve support is
already on by default. Do not enable `--enable-res-deprecated`.

## Rebuild

Rebuild on **Ubuntu 26.04** (or another host whose `<termios.h>` defines
`B7200`) with the Linux `make check` / CI `gofmt` toolchain from `go.mod`.
`catalog_gen.go` is `gofmt` output; `TestExtractClassicHelpMatchesCheckedInCatalog`
and CI `make fmt-check` are the source of truth. `.gitattributes` keeps LF
so Windows checkouts do not fail `gofmt -l`.

From the repository root:

```bash
# Debian/Ubuntu packages used for the checked-in dump:
#   build-essential autoconf libssl-dev libreadline-dev libwrap0-dev libsctp-dev
scripts/build-classic-help-catalog.sh
```

The script clones (or reuses) the official tag, runs `autoconf` then a
**clean** `./configure && make` with default flags, writes these testdata
files, and regenerates `catalog_gen.go` through `gofmt`. It does **not** run
`autoheader` (the tag's `config.h.in` is the one to use). It always
distcleans first so a leftover binary cannot be reused.

`CLASSIC_BUILD_DIR`, if set, is never `rm -rf`'d. An existing user path that
is not the official tag checkout is a hard error. The default cache
`/tmp/socat-tag-1.8.1.3-full` is deleted only after `realpath` confirms that
exact `/tmp` path.

To extract from an already-built feature-complete binary that advertises
795 spellings including `b7200`:

```bash
SOCAT=/path/to/socat scripts/build-classic-help-catalog.sh --extract-only
```

`socat -V` must `#define WITH_OPENSSL`, `WITH_READLINE`, and `WITH_LIBWRAP`.
A binary built without those libraries advertises 732 spellings and must not
replace this fixture. A feature-complete binary whose `<termios.h>` lacks
`B7200` advertises 794 spellings and must not replace this fixture.
