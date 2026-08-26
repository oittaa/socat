#!/usr/bin/env bash
# Rebuild internal/classiccatalog testdata from official socat tag-1.8.1.3.
#
# Default: clone https://repo.or.cz/socat.git at 12c08bf66d709fba17035ce95d85bd218428d9ba,
# autoconf, ./configure, make, then extract socat -V / -hhh.
# --extract-only uses $SOCAT (or the first argument) and skips the build.
#
# The checked-in fixture is a feature-complete Linux dump with 795 unique
# -hhh spellings, including b7200. Ubuntu 26.04 / glibc 2.41+ defines
# B7200 in <bits/termios-baud.h> as 7200U. Older glibc (Ubuntu 24.04 /
# 2.39) does not; this script then passes CPPFLAGS=-DB7200=7200U so the
# advertised catalog matches that host. Always distclean/reconfigure/make;
# do not reuse a leftover binary in $CLASSIC_BUILD_DIR.
set -euo pipefail

TAG=tag-1.8.1.3
COMMIT=12c08bf66d709fba17035ce95d85bd218428d9ba
REPO=https://repo.or.cz/socat.git
ADVERTISED_COUNT=795

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TESTDATA="$ROOT/internal/classiccatalog/testdata"
EXTRACT="$ROOT/scripts/extract-classic-help.py"
WORK=${CLASSIC_BUILD_DIR:-/tmp/socat-${TAG}-full}

extract_only=0
bin=${SOCAT:-}

usage() {
	sed -n '2,16p' "$0" | sed 's/^# //'
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

host_defines_b7200() {
	echo '#include <termios.h>' | ${CC:-gcc} -E -dM - 2>/dev/null | grep -qE '[[:space:]]B7200[[:space:]]'
}

write_fixtures() {
	local socat=$1
	require_feature_complete "$socat"
	"$socat" -V >"$TESTDATA/${TAG}.V"
	python3 - "$socat" "$TESTDATA/${TAG}.hhh" "$ADVERTISED_COUNT" <<'PY'
import re, subprocess, sys
from pathlib import Path
bin_path, dest, want_count_s = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
want_count = int(want_count_s)
hhh = subprocess.check_output([bin_path, "-hhh"], text=True, errors="replace")
idx = hhh.find("\n   opts:")
if idx < 0:
    raise SystemExit("classic -hhh has no opts: section")
section = hhh[idx + 1 :]
if not section.endswith("\n"):
    section += "\n"
seen = set()
b7200_line = ""
for line in section.splitlines():
    m = re.match(r"^\s{6}(\S+)\s+(groups=|is an alias for )", line)
    if not m:
        continue
    name = m.group(1)
    seen.add(name)
    if name == "b7200":
        b7200_line = line.strip()
if "b7200" not in seen:
    raise SystemExit("classic -hhh is missing b7200; rebuild with a glibc that defines B7200 (Ubuntu 26.04) or CPPFLAGS=-DB7200=7200U")
if len(seen) != want_count:
    raise SystemExit("classic -hhh unique spellings %d, want %d" % (len(seen), want_count))
if "groups=TERMIOS" not in b7200_line or "phase=FD" not in b7200_line or "type=CONST" not in b7200_line:
    raise SystemExit("b7200 line is not TERMIOS/FD/CONST: %s" % b7200_line)
header = """# Classic socat -hhh option catalog (opts: section).
# Source: https://repo.or.cz/socat.git tag-1.8.1.3
# Commit: 12c08bf66d709fba17035ce95d85bd218428d9ba
# Official master af5388c898c7bb60997935aee93c223deba60c4a has identical
# xiohelp.c, xioopts.h, optionnames[], and xio*.c.
#
# Feature-complete Linux build with OpenSSL, GNU Readline, and libwrap
# (configure defaults once those libraries are present). Unique advertised
# spellings: %d, including b7200 (glibc B7200 / bits/termios-baud.h, or
# CPPFLAGS=-DB7200=7200U on older glibc).
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

if [[ ! -d $WORK/.git ]] || ! git -C "$WORK" rev-parse HEAD 2>/dev/null | grep -qx "$COMMIT"; then
	rm -rf "$WORK"
	git clone --branch "$TAG" --depth 1 "$REPO" "$WORK"
fi
git -C "$WORK" rev-parse HEAD | grep -qx "$COMMIT"
if [[ ! -x $WORK/configure ]]; then
	# The git tag does not ship a generated configure. Use the tag's
	# config.h.in; do not run autoheader.
	(cd "$WORK" && autoconf)
fi
# Always distclean/reconfigure/make. A leftover Makefile/binary from an
# older glibc (no B7200) must not be reused.
(cd "$WORK" && make distclean >/dev/null 2>&1 || true)
if host_defines_b7200; then
	echo "host <termios.h> defines B7200" >&2
	(cd "$WORK" && ./configure)
else
	echo "host <termios.h> does not define B7200; configuring with CPPFLAGS=-DB7200=7200U to match Ubuntu 26.04 / glibc bits/termios-baud.h" >&2
	(cd "$WORK" && env CPPFLAGS=-DB7200=7200U ./configure)
fi
make -C "$WORK" -j"$(nproc)"
write_fixtures "$WORK/socat"
