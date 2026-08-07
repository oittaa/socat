#!/usr/bin/env bash
# Run classic socat test.sh against this implementation (manual scorecard).
# Not wired into CI yet.
#
# Usage:
#   ./scripts/run-classic-tests.sh /path/to/classic/test.sh
#   CLASSIC_TEST_SH=/path/to/test.sh ./scripts/run-classic-tests.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

make build

export SOCAT="${SOCAT:-$ROOT/socat}"
export FILAN="${FILAN:-$ROOT/filan}"
export PROCAN="${PROCAN:-$ROOT/procan}"

TEST_SH="${1:-${CLASSIC_TEST_SH:-}}"
if [[ -z "$TEST_SH" ]]; then
  echo "usage: $0 /path/to/classic/test.sh" >&2
  echo "Or set CLASSIC_TEST_SH. Obtain test.sh from https://repo.or.cz/socat.git (GPL-2)." >&2
  exit 2
fi
if [[ ! -f "$TEST_SH" ]]; then
  echo "not found: $TEST_SH" >&2
  exit 2
fi

echo "SOCAT=$SOCAT"
echo "FILAN=$FILAN"
echo "PROCAN=$PROCAN"
echo "Running classic test suite: $TEST_SH"
bash "$TEST_SH"
