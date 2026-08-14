#!/usr/bin/env bash
# Run lab scenarios: two containers on one user-defined Docker network.
# Usage:
#   ./examples/lab/run.sh
#   ./examples/lab/run.sh tls quic
#   USE_HOST_BIN=1 ./examples/lab/run.sh socks5
#
# compose.yaml is optional documentation for Compose v2 users.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LAB="$ROOT/examples/lab"
cd "$LAB"

ALL=(tls quic socks5 wss)
if [[ $# -gt 0 ]]; then
  SCENARIOS=("$@")
else
  SCENARIOS=("${ALL[@]}")
fi

for sc in "${SCENARIOS[@]}"; do
  if [[ ! -f "$LAB/scenarios/${sc}.sh" ]]; then
    echo "unknown scenario: $sc" >&2
    exit 2
  fi
done

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 2
fi
if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required on the host (lab certificates)" >&2
  exit 2
fi

mkdir -p "$LAB/certs/out"
"$LAB/certs/gen.sh" "$LAB/certs/out"

export LAB_IMAGE="${LAB_IMAGE:-socat-lab}"
BIN_MOUNT=()
if [[ "${USE_HOST_BIN:-0}" == "1" ]]; then
  echo "Building host socat ..."
  make -C "$ROOT" -s build
  BIN_MOUNT=(-v "$ROOT/socat:/usr/local/bin/socat:ro")
fi

echo "Building image $LAB_IMAGE ..."
docker build -t "$LAB_IMAGE" -f "$LAB/Dockerfile" "$ROOT"

run_one() {
  local sc="$1"
  local id net srv cli ec
  id="lab${sc}$$"
  net="socat-${id}"
  srv="socat-${id}-server"
  cli="socat-${id}-client"
  ec=1
  docker network create "$net" >/dev/null
  # Always drop this scenario's containers/network.
  cleanup() {
    docker rm -f "$srv" "$cli" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
  }
  trap cleanup RETURN
  docker run -d --name "$srv" --hostname server --network "$net" \
    -e ROLE=server -e SCENARIO="$sc" \
    -v "$LAB/certs/out:/certs:ro" \
    -v "$LAB/scenarios:/lab/scenarios:ro" \
    "${BIN_MOUNT[@]+"${BIN_MOUNT[@]}"}" \
    "$LAB_IMAGE" >/dev/null
  set +e
  docker run --rm --name "$cli" --hostname client --network "$net" \
    -e ROLE=client -e SCENARIO="$sc" \
    -v "$LAB/certs/out:/certs:ro" \
    -v "$LAB/scenarios:/lab/scenarios:ro" \
    "${BIN_MOUNT[@]+"${BIN_MOUNT[@]}"}" \
    "$LAB_IMAGE"
  ec=$?
  set -e
  if [[ $ec -ne 0 ]]; then
    echo "---- $srv logs ----"
    docker logs "$srv" 2>&1 || true
  fi
  return "$ec"
}

fail=0
for sc in "${SCENARIOS[@]}"; do
  echo
  echo "======== lab $sc ========"
  if run_one "$sc"; then
    echo "PASS $sc"
  else
    echo "FAIL $sc"
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo
  echo "lab: one or more scenarios failed"
  exit 1
fi
echo
echo "lab: all scenarios passed"
exit 0
