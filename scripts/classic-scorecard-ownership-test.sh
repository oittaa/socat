#!/usr/bin/env bash
# Deterministic regression test for classic-scorecard.sh process ownership.
# Verifies:
# 1. Shard-scoped cleanup terminates owned shard processes while sibling shards survive.
# 2. Invocation-scoped cleanup terminates all shards of the invocation while unrelated invocations survive.
# 3. Demonstrates that legacy unowned cleanup kills sibling shard processes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

TMP="$(mktemp -d /tmp/scorecard-ownership-test.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

DUMMY_SOCAT="$TMP/socat"
if command -v gcc >/dev/null 2>&1; then
  gcc -x c - -o "$DUMMY_SOCAT" <<'EOF'
#include <unistd.h>
int main(void) {
  while (1) {
    pause();
  }
  return 0;
}
EOF
else
  cp "$(command -v sleep)" "$DUMMY_SOCAT"
fi
chmod +x "$DUMMY_SOCAT"

sed -n '/^cleanup_orphans() {/,/^}/p' "$SCRIPT_DIR/classic-scorecard.sh" > "$TMP/cleanup.sh"
# shellcheck disable=SC1090
source "$TMP/cleanup.sh"

wait_for_alive() {
  local pid="$1"
  local deadline=$((SECONDS + 3))
  while [[ $SECONDS -lt $deadline ]]; do
    if kill -0 "$pid" 2>/dev/null; then
      if [[ -r "/proc/$pid/environ" ]]; then
        return 0
      fi
    fi
    sleep 0.05
  done
  echo "process $pid failed to start" >&2
  return 1
}

wait_for_dead() {
  local pid="$1"
  local deadline=$((SECONDS + 3))
  while [[ $SECONDS -lt $deadline ]]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "process $pid failed to terminate" >&2
  return 1
}

echo "=== Test 1: Sibling shard survival under scoped cleanup ==="

INV_1="test_inv_$$"
INV_2="other_inv_$$"
SHARD_1="${INV_1}_shard_1"
SHARD_2="${INV_1}_shard_2"
SHARD_OTHER="${INV_2}_shard_1"

(
  export SOCAT_SCORECARD_INVOCATION="$INV_1"
  export SOCAT_SCORECARD_SHARD="$SHARD_1"
  exec "$DUMMY_SOCAT"
) &
PID_S1=$!

(
  export SOCAT_SCORECARD_INVOCATION="$INV_1"
  export SOCAT_SCORECARD_SHARD="$SHARD_2"
  exec "$DUMMY_SOCAT"
) &
PID_S2=$!

(
  export SOCAT_SCORECARD_INVOCATION="$INV_2"
  export SOCAT_SCORECARD_SHARD="$SHARD_OTHER"
  exec "$DUMMY_SOCAT"
) &
PID_OTHER=$!

wait_for_alive "$PID_S1"
wait_for_alive "$PID_S2"
wait_for_alive "$PID_OTHER"

echo "Running cleanup for shard 1 ($SHARD_1)..."
cleanup_orphans "$SHARD_1"

wait_for_dead "$PID_S1"
echo "  [PASS] Shard 1 process $PID_S1 terminated cleanly"

if kill -0 "$PID_S2" 2>/dev/null; then
  echo "  [PASS] Sibling Shard 2 process $PID_S2 survived Shard 1 cleanup"
else
  echo "  [FAIL] Sibling Shard 2 process was killed by Shard 1 cleanup!" >&2
  exit 1
fi

if kill -0 "$PID_OTHER" 2>/dev/null; then
  echo "  [PASS] Unrelated process $PID_OTHER survived Shard 1 cleanup"
else
  echo "  [FAIL] Unrelated process was killed by Shard 1 cleanup!" >&2
  exit 1
fi

echo "Running cleanup for full invocation 1 ($INV_1)..."
cleanup_orphans "$INV_1"

wait_for_dead "$PID_S2"
echo "  [PASS] Shard 2 process $PID_S2 terminated after invocation cleanup"

if kill -0 "$PID_OTHER" 2>/dev/null; then
  echo "  [PASS] Unrelated process $PID_OTHER survived invocation 1 cleanup"
else
  echo "  [FAIL] Unrelated process was killed by invocation 1 cleanup!" >&2
  exit 1
fi

cleanup_orphans "$INV_2"
wait_for_dead "$PID_OTHER"
echo "  [PASS] Unrelated process terminated after its own invocation cleanup"

echo
echo "=== Test 2: Verify legacy unowned cleanup fails sibling survival ==="

(
  export SOCAT_SCORECARD_INVOCATION="$INV_1"
  export SOCAT_SCORECARD_SHARD="$SHARD_1"
  exec "$DUMMY_SOCAT"
) &
PID_LEGACY_1=$!

(
  export SOCAT_SCORECARD_INVOCATION="$INV_1"
  export SOCAT_SCORECARD_SHARD="$SHARD_2"
  exec "$DUMMY_SOCAT"
) &
PID_LEGACY_2=$!

wait_for_alive "$PID_LEGACY_1"
wait_for_alive "$PID_LEGACY_2"

legacy_cleanup() {
  local pids
  pids=$(pgrep -x socat 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    for p in $pids; do
      local exe
      exe=$(readlink -f /proc/$p/exe 2>/dev/null || true)
      if [[ "$exe" == "$TMP/socat"* ]]; then
        kill -9 "$p" 2>/dev/null || true
      fi
    done
  fi
}

echo "Running legacy unowned cleanup from shard 1..."
legacy_cleanup

if wait_for_dead "$PID_LEGACY_2"; then
  echo "  [CONFIRMED] Legacy cleanup killed sibling Shard 2 process $PID_LEGACY_2 (reproduced bug)"
else
  echo "  [UNEXPECTED] Legacy cleanup did not kill sibling process" >&2
  kill -9 "$PID_LEGACY_2" 2>/dev/null || true
  exit 1
fi

echo
echo "ALL TESTS PASSED: process ownership isolation verified."
