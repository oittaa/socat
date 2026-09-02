#!/usr/bin/env bash
# Build and run classic test.sh inside Docker (root + network caps).
#
# Purpose:
#   - Isolated full classic scorecard (safe for raw IP / root tests)
#   - Verify host classic baseline OK tests still pass
#   - Capture more root-required OK results for later Go work
#
# Usage:
#   ./scripts/docker-classic-scorecard.sh
#   MODE=stable ONLY=ancillary ./scripts/docker-classic-scorecard.sh
#   NO_BUILD=1 ./scripts/docker-classic-scorecard.sh   # reuse image
#   TEST_SH_ARGS=--internet ./scripts/docker-classic-scorecard.sh
#
# Results:
#   $OUT_HOST/results.json
#   $OUT_HOST/classic-docker-baseline.json
#   $OUT_HOST/host-vs-docker-verify.json  (if host baseline present)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-socat-classic-test}"
OUT_HOST="${OUT_HOST:-$ROOT/.scorecard/docker}"
HOST_BASELINE="${HOST_BASELINE:-$ROOT/testdata/scorecard/classic-baseline.json}"
NO_BUILD="${NO_BUILD:-0}"
# Default MODE=classic for truth; override for faster smoke.
MODE="${MODE:-classic}"
JOBS="${JOBS:-1}"
VAL_T="${VAL_T:-auto}"
SHARD_TIMEOUT="${SHARD_TIMEOUT:-7200}"
ONLY="${ONLY:-}"
MAX_N="${MAX_N:-}"
LABEL="${LABEL:-classic}"
DOCKER_EXTRA="${DOCKER_EXTRA:-}"

mkdir -p "$OUT_HOST"

if [[ "$NO_BUILD" != "1" ]]; then
  echo "Building image $IMAGE ..."
  docker build -t "$IMAGE" -f docker/classic-test/Dockerfile "$ROOT"
fi

# Caps for raw IP, multicast, chroot/setuid classic tests; TUN for interface tests.
# Prefer explicit caps over --privileged (stronger isolation, enough for most root tests).
CAP_ARGS=(
  --cap-add=NET_ADMIN
  --cap-add=NET_RAW
  --cap-add=SYS_CHROOT
  --cap-add=SETUID
  --cap-add=SETGID
  --cap-add=SYS_ADMIN
  --cap-add=NET_BIND_SERVICE
)
# Optional privileged mode if CAP-only is too weak for a specific host kernel.
if [[ "${PRIVILEGED:-0}" == "1" ]]; then
  CAP_ARGS=(--privileged)
fi

DEVICE_ARGS=()
if [[ -e /dev/net/tun ]]; then
  DEVICE_ARGS+=(--device /dev/net/tun)
fi

MOUNT_ARGS=(
  -v "$OUT_HOST:/out"
)
if [[ -f "$HOST_BASELINE" ]]; then
  MOUNT_ARGS+=(-v "$HOST_BASELINE:/baseline/classic-baseline.json:ro")
  export_host_bl="/baseline/classic-baseline.json"
else
  export_host_bl=""
fi

echo "Running $IMAGE (MODE=$MODE JOBS=$JOBS) ..."
echo "  host results → $OUT_HOST"
echo "  host baseline → ${HOST_BASELINE:-<none>}"

set +e
# shellcheck disable=SC2086
docker run --rm \
  "${CAP_ARGS[@]}" \
  "${DEVICE_ARGS[@]+"${DEVICE_ARGS[@]}"}" \
  "${MOUNT_ARGS[@]}" \
  -e MODE="$MODE" \
  -e JOBS="$JOBS" \
  -e VAL_T="$VAL_T" \
  -e SHARD_TIMEOUT="$SHARD_TIMEOUT" \
  -e ONLY="$ONLY" \
  -e MAX_N="$MAX_N" \
  -e LABEL="$LABEL" \
  -e SKIP_BUILD=1 \
  -e OUT_DIR=/out \
  -e SAVE_BASELINE=/out/classic-docker-baseline.json \
  -e HOST_BASELINE="${export_host_bl}" \
  -e ALLOW_LOST="${ALLOW_LOST:-216,304,399,410,453,492,520,542,543,582}" \
  -e REGRESSION_EXIT="${REGRESSION_EXIT:-0}" \
  -e KEEP_LOGS=1 \
  -e TEST_SH_ARGS="${TEST_SH_ARGS:-}" \
  -e SOURCE_REVISION="${SOURCE_REVISION:-}" \
  $DOCKER_EXTRA \
  "$IMAGE"
ec=$?
set -e

echo
echo "Docker run exit=$ec"
if [[ -f "$OUT_HOST/results.json" ]]; then
  python3 - <<PY
import json
from pathlib import Path
p = Path("$OUT_HOST/results.json")
d = json.loads(p.read_text())
s = d["summary"]
m = d.get("meta", {})
print(f"Docker classic: OK={s['ok']} FAILED={s['failed']} CANT={s['cant']} "
      f"TIMEOUT={s.get('timeout')} total={s['total_recorded']}")
print(f"  socat={m.get('socat')} mode={m.get('val_t')} label={m.get('label')}")
PY
fi
if [[ -f "$OUT_HOST/host-vs-docker-verify.json" ]]; then
  python3 - <<PY
import json
from pathlib import Path
r = json.loads(Path("$OUT_HOST/host-vs-docker-verify.json").read_text())
print(f"Verify vs host: host_ok={r['host_ok']} still_ok={r['still_ok']} "
      f"lost={r['lost_count']} cant→ok={r['gained_from_cant_count']}")
PY
fi

# Also run offline compare if host baseline exists
if [[ -f "$HOST_BASELINE" && -f "$OUT_HOST/results.json" ]]; then
  echo
  echo "=== scorecard-compare (host baseline → docker) ==="
  python3 "$ROOT/scripts/scorecard-compare.py" \
    "$HOST_BASELINE" "$OUT_HOST/results.json" \
    --write "$OUT_HOST/compare-host-vs-docker.json" || true
fi

exit "$ec"
