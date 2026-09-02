#!/usr/bin/env bash
# Build and run Go socat against classic test.sh inside Docker (root + network caps).
# Compares to classic-docker-baseline (root-capable classic truth) by default.
#
# Usage:
#   ./scripts/docker-go-scorecard.sh
#   NO_BUILD=1 MODE=stable ONLY=ancillary ./scripts/docker-go-scorecard.sh
#   # Fast iterate: mount host-built binaries (skip gobuild stage)
#   USE_HOST_BIN=1 NO_BUILD=1 ./scripts/docker-go-scorecard.sh
#   # Match testdata/scorecard/go-docker-baseline.json
#   # (NETNS needs PRIVILEGED=1; internet tests need TEST_SH_ARGS=--internet):
#   USE_HOST_BIN=1 NO_BUILD=1 MODE=classic PRIVILEGED=1 TEST_SH_ARGS=--internet \
#     ./scripts/docker-go-scorecard.sh
#
# Results: $OUT_HOST/results.json  (+ go-docker-baseline.json if SAVE set)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

IMAGE="${IMAGE:-socat-go-test}"
CLASSIC_IMAGE="${CLASSIC_IMAGE:-socat-classic-test}"
OUT_HOST="${OUT_HOST:-$ROOT/.scorecard/docker-go}"
CLASSIC_BASELINE="${CLASSIC_BASELINE:-$ROOT/testdata/scorecard/classic-docker-baseline.json}"
NO_BUILD="${NO_BUILD:-0}"
USE_HOST_BIN="${USE_HOST_BIN:-0}"
MODE="${MODE:-classic}"
JOBS="${JOBS:-1}"
VAL_T="${VAL_T:-auto}"
SHARD_TIMEOUT="${SHARD_TIMEOUT:-7200}"
ONLY="${ONLY:-}"
MAX_N="${MAX_N:-}"
LABEL="${LABEL:-go}"
DOCKER_EXTRA="${DOCKER_EXTRA:-}"
REGRESSION_EXIT="${REGRESSION_EXIT:-0}"

mkdir -p "$OUT_HOST"

if [[ "$NO_BUILD" != "1" ]]; then
  echo "Building classic base image $CLASSIC_IMAGE (if needed) ..."
  docker build -t "$CLASSIC_IMAGE" -f docker/classic-test/Dockerfile "$ROOT"
  if [[ "$USE_HOST_BIN" != "1" ]]; then
    echo "Building Go image $IMAGE ..."
    docker build -t "$IMAGE" -f docker/go-test/Dockerfile "$ROOT"
  fi
fi

if [[ "$USE_HOST_BIN" == "1" ]]; then
  echo "Building host Go binaries ..."
  make -s build
  IMAGE="$CLASSIC_IMAGE"
fi

CAP_ARGS=(
  --cap-add=NET_ADMIN
  --cap-add=NET_RAW
  --cap-add=SYS_CHROOT
  --cap-add=SETUID
  --cap-add=SETGID
  --cap-add=SYS_ADMIN
  --cap-add=NET_BIND_SERVICE
)
if [[ "${PRIVILEGED:-0}" == "1" ]]; then
  CAP_ARGS=(--privileged)
fi

DEVICE_ARGS=()
if [[ -e /dev/net/tun ]]; then
  DEVICE_ARGS+=(--device /dev/net/tun)
fi

MOUNT_ARGS=(-v "$OUT_HOST:/out")
if [[ -f "$CLASSIC_BASELINE" ]]; then
  MOUNT_ARGS+=(-v "$CLASSIC_BASELINE:/baseline/classic-docker-baseline.json:ro")
fi

BIN_MOUNTS=()
SOCAT_PATH=/opt/go/socat
FILAN_PATH=/opt/go/filan
PROCAN_PATH=/opt/go/procan
if [[ "$USE_HOST_BIN" == "1" ]]; then
  BIN_MOUNTS+=(
    -v "$ROOT/socat:/opt/go/socat:ro"
    -v "$ROOT/filan:/opt/go/filan:ro"
    -v "$ROOT/procan:/opt/go/procan:ro"
  )
fi

echo "Running $IMAGE as LABEL=$LABEL (MODE=$MODE) ..."
echo "  results → $OUT_HOST"
echo "  baseline → ${CLASSIC_BASELINE:-<none>}"

set +e
# shellcheck disable=SC2086
docker run --rm \
  "${CAP_ARGS[@]}" \
  "${DEVICE_ARGS[@]+"${DEVICE_ARGS[@]}"}" \
  "${MOUNT_ARGS[@]}" \
  "${BIN_MOUNTS[@]+"${BIN_MOUNTS[@]}"}" \
  -e MODE="$MODE" \
  -e JOBS="$JOBS" \
  -e VAL_T="$VAL_T" \
  -e SHARD_TIMEOUT="$SHARD_TIMEOUT" \
  -e ONLY="$ONLY" \
  -e MAX_N="$MAX_N" \
  -e LABEL="$LABEL" \
  -e SKIP_BUILD=1 \
  -e OUT_DIR=/out \
  -e SOCAT="$SOCAT_PATH" \
  -e FILAN="$FILAN_PATH" \
  -e PROCAN="$PROCAN_PATH" \
  -e SAVE_BASELINE=/out/go-docker-baseline.json \
  -e BASELINE=/baseline/classic-docker-baseline.json \
  -e HOST_BASELINE= \
  -e REGRESSION_EXIT="$REGRESSION_EXIT" \
  -e KEEP_LOGS=1 \
  -e SCORECARD_EXIT="${SCORECARD_EXIT:-0}" \
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
print(f"Docker Go: OK={s['ok']} FAILED={s['failed']} CANT={s['cant']} "
      f"TIMEOUT={s.get('timeout')} total={s['total_recorded']}")
print(f"  socat={m.get('socat')} label={m.get('label')}")
PY
fi

if [[ -f "$CLASSIC_BASELINE" && -f "$OUT_HOST/results.json" ]]; then
  echo
  echo "=== scorecard-compare (classic-docker → go-docker) ==="
  python3 "$ROOT/scripts/scorecard-compare.py" \
    "$CLASSIC_BASELINE" "$OUT_HOST/results.json" \
    --write "$OUT_HOST/compare-go-vs-classic-docker.json" || true
  # Root-gap report: classic-docker OK that Go did not get
  python3 - "$CLASSIC_BASELINE" "$OUT_HOST/results.json" "$OUT_HOST" <<'PY'
import json
import sys
from pathlib import Path

base_path = Path(sys.argv[1])
cur_path = Path(sys.argv[2])
out = Path(sys.argv[3])
base = json.loads(base_path.read_text())
cur = json.loads(cur_path.read_text())

def st(t, k):
    v = t.get(str(k))
    if v is None:
        return None
    if isinstance(v, str):
        return v
    return v.get("status")

bt, ct = base["tests"], cur["tests"]
parity_fail, parity_cant, parity_other, new_ok = [], [], [], []
for k, v in sorted(bt.items(), key=lambda x: int(x[0]) if str(x[0]).isdigit() else str(x[0])):
    bs, cs = st(bt, k), st(ct, k)
    name = v.get("name", "") if isinstance(v, dict) else ""
    if bs == "OK" and cs != "OK":
        row = {"id": k, "name": name, "status": cs or "MISSING"}
        if cs == "FAILED":
            parity_fail.append(row)
        elif cs == "CANT":
            parity_cant.append(row)
        else:
            parity_other.append(row)
    if bs != "OK" and cs == "OK":
        new_ok.append({"id": k, "name": name, "was": bs})

report = {
    "classic_docker_ok": sum(1 for k in bt if st(bt, k) == "OK"),
    "go_ok": sum(1 for k in ct if st(ct, k) == "OK"),
    "parity_fail": parity_fail,
    "parity_cant": parity_cant,
    "parity_other": parity_other,
    "parity_gap_total": len(parity_fail) + len(parity_cant) + len(parity_other),
    "new_ok_vs_classic_docker": new_ok,
}
(out / "go-vs-classic-docker-gaps.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"classic-docker OK: {report['classic_docker_ok']}")
print(f"go-docker OK:      {report['go_ok']}")
print(f"parity gap:        {report['parity_gap_total']}  "
      f"(FAILED={len(parity_fail)} CANT={len(parity_cant)} other={len(parity_other)})")
print(f"wrote {out}/go-vs-classic-docker-gaps.json")
rootish = [
    r for r in parity_cant + parity_fail
    if any(x in (r.get("name") or "").upper()
           for x in ("RAW", "IP4SCM", "IP6SCM", "IP4ENV", "IP6ENV",
                     "TCPWRAP", "TUN", "BROADCAST", "MULTICAST", "ROOT", "IP4", "IP6"))
]
if rootish:
    print("Root/feature gap sample (classic OK, go not):")
    for r in rootish[:40]:
        print(f"  {r['id']:>4} {r['status']:6} {r['name']}")
PY
fi

exit "$ec"
