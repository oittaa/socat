#!/usr/bin/env bash
# Refresh every committed, reproducible Docker scorecard artifact on Linux.
#
# This command deliberately does not git add or commit anything. It publishes
# only after both full runs pass completeness and consistency checks.
# Usage: bash ./scripts/update-scorecard.sh  (or: make update-scorecard)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

die() {
  echo "scorecard update: $*" >&2
  exit 1
}

if [[ "$(uname -s)" != "Linux" ]]; then
  die "this reproducible workflow must run on a Linux Docker host"
fi

for command in git python3; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done
docker_bin="$(command -v docker || true)"
[[ -n "$docker_bin" ]] || die "required command not found: docker"

[[ -f "$ROOT/testdata/scorecard/classic-baseline.json" ]] || \
  die "missing testdata/scorecard/classic-baseline.json; run from a complete clone"

PUBLISHED_PATHS=(
  testdata/scorecard/README.md
  testdata/scorecard/classic-docker-baseline.json
  testdata/scorecard/classic-docker-baseline.summary.txt
  testdata/scorecard/classic-docker-vs-host.json
  testdata/scorecard/go-docker-baseline.json
  testdata/scorecard/go-docker-baseline.summary.txt
  testdata/scorecard/go-vs-classic-docker-gaps.json
)
if ! git diff --quiet -- "${PUBLISHED_PATHS[@]}" || \
   ! git diff --cached --quiet -- "${PUBLISHED_PATHS[@]}"; then
  die "committed scorecard files already have changes; commit or stash them first"
fi

SOURCE_REVISION="$(git rev-parse --short HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  SOURCE_REVISION="${SOURCE_REVISION}-dirty"
fi
export SOURCE_REVISION
mkdir -p "$ROOT/.scorecard"
RUN_ROOT="$(mktemp -d "$ROOT/.scorecard/update.XXXXXX")"
CLASSIC_OUT="$RUN_ROOT/classic"
GO_OUT="$RUN_ROOT/go"
mkdir -p "$CLASSIC_OUT" "$GO_OUT"

echo "== Docker preflight =="
if docker version >/dev/null 2>&1; then
  echo "  access:  direct"
elif command -v sudo >/dev/null 2>&1 && \
     sudo -n "$docker_bin" version >/dev/null 2>&1; then
  docker_wrapper_dir="$RUN_ROOT/docker-bin"
  mkdir -p "$docker_wrapper_dir"
  printf '#!/usr/bin/env bash\nexec sudo -n %q "$@"\n' "$docker_bin" \
    >"$docker_wrapper_dir/docker"
  chmod 0755 "$docker_wrapper_dir/docker"
  PATH="$docker_wrapper_dir:$PATH"
  export PATH
  echo "  access:  passwordless sudo (temporary wrapper; no account changes)"
else
  die "cannot reach the Docker daemon directly or through passwordless sudo; start Docker and check your socket permissions"
fi
daemon_os="$(docker info --format '{{.OSType}}' 2>/dev/null)"
[[ "$daemon_os" == "linux" ]] || die "Docker daemon OS is $daemon_os, not linux"

echo "  source:  $SOURCE_REVISION"
echo "  workdir: $RUN_ROOT"
echo
echo "== Build pinned classic test environment =="
docker build -t socat-classic-test -f docker/classic-test/Dockerfile "$ROOT"

echo
echo "== Privileged-container capability probe =="
docker run --rm --privileged --entrypoint /bin/bash socat-classic-test -ceu '
namespace=socat-scorecard-probe
tunnel=scprobe0
cleanup() {
  ip tuntap del dev "$tunnel" mode tun >/dev/null 2>&1 || true
  ip netns delete "$namespace" >/dev/null 2>&1 || true
}
trap cleanup EXIT
[[ "$(id -u)" == "0" ]]
ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ping -c 1 -W 1 127.0.0.1 >/dev/null
[[ -c /dev/net/tun ]] || {
  echo "privileged container has no /dev/net/tun" >&2
  exit 1
}
ip tuntap add dev "$tunnel" mode tun
ip link set "$tunnel" up
getent hosts example.com >/dev/null
curl -fsS --connect-timeout 10 --max-time 20 https://example.com/ >/dev/null
echo "privileged Docker, network namespaces, TUN, DNS, and HTTPS are available"
' || die "privileged Docker probe failed; this host cannot produce the canonical scorecard"

echo
echo "== Full classic C scorecard =="
OUT_HOST="$CLASSIC_OUT" \
  IMAGE=socat-classic-test \
  HOST_BASELINE="$ROOT/testdata/scorecard/classic-baseline.json" \
  NO_BUILD=1 \
  PRIVILEGED=1 \
  MODE=classic \
  JOBS=1 \
  VAL_T=auto \
  SHARD_TIMEOUT=7200 \
  ONLY= \
  MAX_N= \
  LABEL=classic \
  DOCKER_EXTRA= \
  ALLOW_LOST=216,304,399,410,453,520,542,543,582 \
  REGRESSION_EXIT=0 \
  SCORECARD_EXIT=0 \
  TEST_SH_ARGS=--internet \
  ./scripts/docker-classic-scorecard.sh
python3 -B scripts/scorecard-update.py validate-result \
  "$CLASSIC_OUT/classic-docker-baseline.json" \
  --label classic \
  --source-revision "$SOURCE_REVISION"
python3 -B scripts/scorecard-compare.py \
  testdata/scorecard/classic-docker-baseline.json \
  "$CLASSIC_OUT/classic-docker-baseline.json" \
  --write "$CLASSIC_OUT/compare-vs-previous.json"

echo
echo "== Build Go scorecard image =="
docker build -t socat-go-test -f docker/go-test/Dockerfile "$ROOT"

echo
echo "== Full Go scorecard against the fresh classic result =="
OUT_HOST="$GO_OUT" \
  IMAGE=socat-go-test \
  CLASSIC_IMAGE=socat-classic-test \
  CLASSIC_BASELINE="$CLASSIC_OUT/classic-docker-baseline.json" \
  NO_BUILD=1 \
  USE_HOST_BIN=0 \
  PRIVILEGED=1 \
  MODE=classic \
  JOBS=1 \
  VAL_T=auto \
  SHARD_TIMEOUT=7200 \
  ONLY='functions filan' \
  MAX_N= \
  LABEL=go \
  DOCKER_EXTRA= \
  REGRESSION_EXIT=0 \
  SCORECARD_EXIT=0 \
  TEST_SH_ARGS=--internet \
  ./scripts/docker-go-scorecard.sh
python3 -B scripts/scorecard-update.py validate-result \
  "$GO_OUT/go-docker-baseline.json" \
  --label go \
  --source-revision "$SOURCE_REVISION"
python3 -B scripts/scorecard-compare.py \
  testdata/scorecard/go-docker-baseline.json \
  "$GO_OUT/go-docker-baseline.json" \
  --write "$GO_OUT/compare-vs-previous.json"

echo
echo "== Validate and publish committed artifacts =="
python3 -B scripts/scorecard-update.py publish \
  --classic-dir "$CLASSIC_OUT" \
  --go-dir "$GO_OUT" \
  --destination "$ROOT/testdata/scorecard" \
  --readme "$ROOT/testdata/scorecard/README.md" \
  --source-revision "$SOURCE_REVISION"

echo
echo "Scorecard refresh complete. Full logs remain in:"
echo "  $RUN_ROOT"
echo
git status --short -- "${PUBLISHED_PATHS[@]}"
echo
echo "Review with:"
echo "  git diff -- testdata/scorecard"
echo "Then add and commit the scorecard files when the changes look right."
