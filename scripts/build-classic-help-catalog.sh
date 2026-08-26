#!/usr/bin/env bash
# Rebuild internal/classiccatalog testdata from official socat tag-1.8.1.3.
#
# Default: clone https://repo.or.cz/socat.git at 12c08bf66d709fba17035ce95d85bd218428d9ba,
# autoconf, ./configure, make, then extract socat -V / -hhh.
# --extract-only uses $SOCAT (or the first argument) and skips the build.
#
# The checked-in fixture is a feature-complete Ubuntu 26.04 / glibc 2.41+
# dump with 795 unique -hhh spellings, including b7200 from a real
# <termios.h> `#define B7200 7200U`. Do not pass -DB7200; that would make
# an official build advertise a host API this machine does not provide.
# Rebuild on that host, or extract from such a binary with --extract-only.
#
# CLASSIC_BUILD_DIR, if set, is never deleted. An unsuitable existing user
# path is a hard error. The default /tmp cache is deleted only after
# realpath confirms the exact path /tmp/socat-tag-1.8.1.3-full.
set -euo pipefail

TAG=tag-1.8.1.3
COMMIT=12c08bf66d709fba17035ce95d85bd218428d9ba
REPO=https://repo.or.cz/socat.git
ADVERTISED_COUNT=795
DEFAULT_CACHE=/tmp/socat-${TAG}-full

ROOT=$(cd "$(dirname "$0")/.." && pwd)
TESTDATA="$ROOT/internal/classiccatalog/testdata"
EXTRACT="$ROOT/scripts/extract-classic-help.py"

extract_only=0
bin=${SOCAT:-}

usage() {
	sed -n '2,18p' "$0" | sed 's/^# //'
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

require_gofmt() {
	if ! command -v gofmt >/dev/null 2>&1; then
		echo "gofmt not found. Generate catalog_gen.go on the Linux make-check VM with the go.mod toolchain (CI lint: make fmt-check)." >&2
		exit 1
	fi
}

suitable_checkout() {
	[[ -d $1/.git ]] && git -C "$1" rev-parse HEAD 2>/dev/null | grep -qx "$COMMIT"
}

resolved_path() {
	realpath -m -- "$1"
}

clone_official() {
	git clone --branch "$TAG" --depth 1 "$REPO" "$1"
	git -C "$1" rev-parse HEAD | grep -qx "$COMMIT"
}

prepare_work() {
	local resolved
	if [[ -n ${CLASSIC_BUILD_DIR:-} ]]; then
		WORK=$CLASSIC_BUILD_DIR
		if [[ -e $WORK ]] && ! suitable_checkout "$WORK"; then
			echo "CLASSIC_BUILD_DIR=$WORK is not the official $TAG checkout ($COMMIT)." >&2
			echo "Refusing to delete a user-controlled path. Point CLASSIC_BUILD_DIR at a new directory or use --extract-only." >&2
			exit 1
		fi
		if [[ ! -d $WORK/.git ]]; then
			clone_official "$WORK"
		fi
		return
	fi

	WORK=$DEFAULT_CACHE
	if [[ -e $WORK ]] && ! suitable_checkout "$WORK"; then
		resolved=$(resolved_path "$WORK")
		if [[ $resolved == "$DEFAULT_CACHE" ]]; then
			rm -rf -- "$resolved"
		else
			echo "default cache $WORK resolves to $resolved, not $DEFAULT_CACHE; refusing to delete." >&2
			WORK=$(mktemp -d "/tmp/socat-${TAG}-XXXXXX")
			echo "cloning into $WORK instead" >&2
			clone_official "$WORK"
			return
		fi
	fi
	if [[ ! -d $WORK/.git ]]; then
		clone_official "$WORK"
	fi
}

write_fixtures() {
	local socat=$1
	require_feature_complete "$socat"
	require_gofmt
	python3 - "$socat" "$TESTDATA/${TAG}.V" <<'PY'
import re, subprocess, sys
from pathlib import Path
bin_path, dest = sys.argv[1], Path(sys.argv[2])
text = subprocess.check_output([bin_path, "-V"], text=True, errors="replace")
text = re.sub(r"(?m)^(socat version \S+) on .*$", r"\1", text)
text = re.sub(r"(?m)^   running on .*$", "   running on <rebuild-host>", text)
if not text.endswith("\n"):
    text += "\n"
dest.write_text(text)
print("wrote", dest, file=sys.stderr)
PY
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
    raise SystemExit(
        "classic -hhh is missing b7200. Rebuild on Ubuntu 26.04 / glibc 2.41+ "
        "(<termios.h> defines B7200) or --extract-only from such a binary. "
        "Do not pass -DB7200=7200U."
    )
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
# Feature-complete Ubuntu 26.04 / glibc 2.41+ Linux build with OpenSSL,
# GNU Readline, and libwrap (configure defaults once those libraries are
# present). Unique advertised spellings: %d, including b7200 from a real
# <termios.h> #define B7200 7200U. Do not forge B7200 with CPPFLAGS.
#
# Rebuild: scripts/build-classic-help-catalog.sh
# Provenance: testdata/tag-1.8.1.3.V (timestamps/kernel sanitized)
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

# Resolve the work tree before the B7200 check so a bad CLASSIC_BUILD_DIR
# fails without depending on host termios, and is never deleted.
prepare_work
git -C "$WORK" rev-parse HEAD | grep -qx "$COMMIT"
if ! host_defines_b7200; then
	echo "host <termios.h> does not define B7200." >&2
	echo "The checked-in catalog is a real Ubuntu 26.04 / glibc 2.41+ build" >&2
	echo "(#define B7200 7200U in <bits/termios-baud.h>)." >&2
	echo "Rebuild on that host, or extract from such a binary:" >&2
	echo "  SOCAT=/path/to/socat $0 --extract-only" >&2
	echo "Do not pass CPPFLAGS=-DB7200=7200U; that advertises a host API this system does not provide." >&2
	exit 1
fi
if [[ ! -x $WORK/configure ]]; then
	# The git tag does not ship a generated configure. Use the tag's
	# config.h.in; do not run autoheader.
	(cd "$WORK" && autoconf)
fi
# Always distclean/reconfigure/make so a leftover binary cannot be reused.
(cd "$WORK" && make distclean >/dev/null 2>&1 || true)
echo "host <termios.h> defines B7200; configuring $WORK" >&2
(cd "$WORK" && ./configure)
make -C "$WORK" -j"$(nproc)"
write_fixtures "$WORK/socat"
