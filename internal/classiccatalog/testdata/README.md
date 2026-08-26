# Classic -hhh catalog fixture

Baseline: official [`socat.git`](https://repo.or.cz/socat.git) `tag-1.8.1.3`
(`12c08bf66d709fba17035ce95d85bd218428d9ba`). Official master
`af5388c898c7bb60997935aee93c223deba60c4a` currently has identical `xiohelp.c`,
`xioopts.h`, `optionnames[]`, and `xio*.c`.

Files:

- `tag-1.8.1.3.hhh` — `opts:` section of `socat -hhh` from a feature-complete
  Linux build (OpenSSL, GNU Readline, libwrap). **794** unique spellings.
- `tag-1.8.1.3.V` — `socat -V` from that same binary (build provenance).

`b7200` is compiled only when `B7200` is defined (HP-UX) and is **not** in this
Linux dump. It is recorded in `DocsOnlyNotInThisBinary`; 794+1=795
feature-complete spellings.

`--enable-openssl-method` and `--enable-fips` stay off (configure defaults).
Those documented names (`method` / `openssl-method`, `fips` / `openssl-fips`)
are also in `DocsOnlyNotInThisBinary`. Do not pass `--enable-resolve` extra
flags: resolve support is already on by default. Do not enable
`--enable-res-deprecated`.

## Rebuild

From the repository root:

```bash
# Debian/Ubuntu packages used for the checked-in dump:
#   build-essential autoconf libssl-dev libreadline-dev libwrap0-dev libsctp-dev
scripts/build-classic-help-catalog.sh
```

The script clones (or reuses) the official tag, runs `autoconf` then
`./configure && make` with default flags, writes these testdata files, and
regenerates `catalog_gen.go`. It does **not** run `autoheader` (the tag's
`config.h.in` is the one to use).

To extract from an already-built feature-complete binary:

```bash
SOCAT=/path/to/socat scripts/build-classic-help-catalog.sh --extract-only
```

`socat -V` must `#define WITH_OPENSSL`, `WITH_READLINE`, and `WITH_LIBWRAP`.
A binary built without those libraries advertises 732 spellings and must not
replace this fixture.
