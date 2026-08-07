#!/usr/bin/env bash
# Thin wrapper: prefer the parallel scorecard runner.
# For a single-process classic run: SERIAL=1 ./scripts/run-classic-tests.sh test.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ "${SERIAL:-0}" == "1" ]]; then
  make -C "$ROOT" -s build
  export SOCAT="${SOCAT:-$ROOT/socat}" FILAN="${FILAN:-$ROOT/filan}" PROCAN="${PROCAN:-$ROOT/procan}"
  TEST_SH="${1:-${CLASSIC_TEST_SH:-}}"
  [[ -n "$TEST_SH" && -f "$TEST_SH" ]] || { echo "usage: SERIAL=1 $0 /path/to/test.sh" >&2; exit 2; }
  exec bash "$TEST_SH" -t "${VAL_T:-0.1}"
fi
exec "$ROOT/scripts/classic-scorecard.sh" "$@"
