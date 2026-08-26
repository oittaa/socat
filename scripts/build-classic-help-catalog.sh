#!/usr/bin/env bash
# Rebuild internal/classiccatalog testdata from official socat tag-1.8.1.3.
#
# Default: clone https://repo.or.cz/socat.git at 12c08bf66d709fba17035ce95d85bd218428d9ba,
# autoconf, ./configure, make, then extract socat -V / -hhh.
# --extract-only uses $SOCAT (or the first argument) and skips the build.
set -euo pipefail

TAG=tag-1.8.1.3
COMMIT=12c08bf66d709fba17035ce95d85bd218428d9ba
REPO=https://repo.or.cz/socat.git

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TESTDATA="$ROOT/internal/classiccatalog/testdata"
EXTRACT="$ROOT/scripts/extract-classic-help.py"
WORK=${CLASSIC_BUILD_DIR:-/tmp/socat-${TAG}-full}

extract_only=0
bin=${SOCAT:-}

usage() {
	sed -n '2,8p' "$0" | sed 's/^# //'
	echo "Usage: $0 [--extract-only] [SOCAT_BINARY]"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--extract-only) extract_only=1; shift ;;
	-h|--help) usage; exit 0 ;;
	--) shift; break ;;
	-*) echo "unknown flag: $1" >&2; usage >&2; exit 2 ;;
	*) bin=$1; shift ;;
	esac
done

require_feature_complete() {
	local v
	v=$("$1" -V)
	local missing=()
	for feat in WITH_OPENSSL WITH_READLINE WITH_LIBWRAP; do
		if ! grep -qE "^[[:space:]]*#define ${feat}([[:space:]]|$)" <<<"$v"; then
			missing+=("$feat")
		fi
	done
	if [[ ${#missing[@]} -gt 0 ]]; then
		echo "$1 -V is not feature-complete (missing: ${missing[*]})" >&2
		echo "$v" >&2
		exit 1
	fi
}

write_fixtures() {
	local socat=$1
	require_feature_complete "$socat"
	"$socat" -V >"$TESTDATA/${TAG}.V"
	python3 - "$socat" "$TESTDATA/${TAG}.hhh" <<'PY'
import re, subprocess, sys
from pathlib import Path
bin_path, dest = sys.argv[1], Path(sys.argv[2])
hhh = subprocess.check_output([bin_path, "-hhh"], text=True, errors="replace")
idx = hhh.find("\n   opts:")
if idx < 0:
    raise SystemExit("classic -hhh has no opts: section")
section = hhh[idx + 1 :]
if not section.endswith("\n"):
    section += "\n"
seen = set()
for line in section.splitlines():
    m = re.match(r"^\s{6}(\S+)\s+(groups=|is an alias for )", line)
    if m:
        seen.add(m.group(1))
header = """# Classic socat -hhh option catalog (opts: section).
# Source: https://repo.or.cz/socat.git tag-1.8.1.3
# Commit: 12c08bf66d709fba17035ce95d85bd218428d9ba
# Official master af5388c898c7bb60997935aee93c223deba60c4a has identical
# xiohelp.c, xioopts.h, optionnames[], and xio*.c.
#
# Feature-complete Linux build with OpenSSL, GNU Readline, and libwrap
# (configure defaults once those libraries are present). Unique advertised
# spellings: %d. b7200 requires HP-UX B7200 and is recorded in
# DocsOnlyNotInThisBinary; 794+1=795 feature-complete spellings.
#
# Rebuild: scripts/build-classic-help-catalog.sh
# Provenance: testdata/tag-1.8.1.3.V
#
""" % len(seen)
dest.write_text(header + section)
print("wrote", dest, "unique spellings", len(seen), file=sys.stderr)
PY
	python3 "$EXTRACT" "$TESTDATA/${TAG}.hhh" | gofmt >"$ROOT/internal/classiccatalog/catalog_gen.go"
	echo "wrote $ROOT/internal/classiccatalog/catalog_gen.go"
}

if [[ $extract_only -eq 1 ]]; then
	if [[ -z $bin ]]; then
		echo "SOCAT binary required with --extract-only" >&2
		exit 2
	fi
	write_fixtures "$bin"
	exit 0
fi

if [[ -n $bin ]]; then
	write_fixtures "$bin"
	exit 0
fi

if [[ ! -d $WORK/.git ]]; then
	rm -rf "$WORK"
	git clone --branch "$TAG" --depth 1 "$REPO" "$WORK"
fi
git -C "$WORK" rev-parse HEAD | grep -qx "$COMMIT"
if [[ ! -x $WORK/configure ]]; then
	# The git tag does not ship a generated configure. Use the tag's
	# config.h.in; do not run autoheader.
	(cd "$WORK" && autoconf)
fi
if [[ ! -f $WORK/Makefile ]]; then
	(cd "$WORK" && ./configure)
fi
if [[ ! -x $WORK/socat ]]; then
	make -C "$WORK" -j"$(nproc)"
fi
write_fixtures "$WORK/socat"
