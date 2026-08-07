#!/usr/bin/env bash
# Parallel classic socat test.sh scorecard for this Go reimplementation.
#
# Why this exists:
#   Full test.sh is ~600 cases. When healthy, most finish in <1s each.
#   A single hung socat can freeze the whole suite for tens of minutes.
#   This runner shards by test number, isolates ports, and bounds each shard.
#
# Usage:
#   ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#   JOBS=8 SHARD_TIMEOUT=120 ./scripts/classic-scorecard.sh /path/to/test.sh
#   ONLY=functions ./scripts/classic-scorecard.sh /path/to/test.sh   # group filter
#   MAX_N=100 ./scripts/classic-scorecard.sh /path/to/test.sh      # first N only
#
# Does not modify upstream test.sh in place; uses a temp copy with a port base.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
SHARD_TIMEOUT="${SHARD_TIMEOUT:-180}"   # wall seconds per shard (not per test)
VAL_T="${VAL_T:-0.05}"                 # classic -t base timeout (smaller = faster)
BASE_PORT="${BASE_PORT:-20000}"        # first shard port base; each shard + PORT_STRIDE
PORT_STRIDE="${PORT_STRIDE:-3000}"     # port space per shard (avoid collisions)
MAX_N="${MAX_N:-}"                     # optional cap on highest test number
ONLY="${ONLY:-}"                       # optional classic group/name filter (e.g. functions,tcp)
KEEP_LOGS="${KEEP_LOGS:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/.classic-scorecard}"

TEST_SH="${1:-${CLASSIC_TEST_SH:-}}"
if [[ -z "$TEST_SH" || ! -f "$TEST_SH" ]]; then
  echo "usage: $0 /path/to/classic/test.sh" >&2
  echo "Clone: git clone --depth 1 https://repo.or.cz/socat.git /tmp/socat-master" >&2
  exit 2
fi
TEST_SH="$(cd "$(dirname "$TEST_SH")" && pwd)/$(basename "$TEST_SH")"

# Build binaries
make -s build
export SOCAT="${SOCAT:-$ROOT/socat}"
export FILAN="${FILAN:-$ROOT/filan}"
export PROCAN="${PROCAN:-$ROOT/procan}"

# Kill leftover socat from this tree only (never broad killall bash)
cleanup_orphans() {
  # Match our built binary path only
  local p
  for p in $(pgrep -x socat 2>/dev/null || true); do
    if tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -qF "$ROOT/socat"; then
      kill "$p" 2>/dev/null || true
    fi
  done
}
cleanup_orphans

# Discover highest test number by scanning NAME= assignments (approx) or fixed 650
# Classic 1.8.1.3 has Summary: 608 tests — use 650 as safe upper unless MAX_N set.
TOTAL="${MAX_N:-650}"

mkdir -p "$OUT_DIR"
rm -f "$OUT_DIR"/shard-*.log "$OUT_DIR"/shard-*.summary "$OUT_DIR"/aggregate.txt

echo "classic scorecard"
echo "  test.sh:        $TEST_SH"
echo "  SOCAT:          $SOCAT"
echo "  jobs:           $JOBS"
echo "  shard_timeout:  ${SHARD_TIMEOUT}s"
echo "  -t (val_t):     $VAL_T"
echo "  total range:    1..$TOTAL"
echo "  only filter:    ${ONLY:-<all numbered>}"
echo "  logs:           $OUT_DIR"
echo

# Build shard ranges: contiguous blocks of test numbers.
# Using -N start -Z end keeps one test.sh process per shard (avoids 600× init cost).
mapfile -t RANGES < <(python3 - "$JOBS" "$TOTAL" <<'PY'
import sys
jobs, total = int(sys.argv[1]), int(sys.argv[2])
jobs = max(1, min(jobs, total))
# Even-ish splits
base, rem = divmod(total, jobs)
start = 1
for i in range(jobs):
    size = base + (1 if i < rem else 0)
    end = start + size - 1
    if size > 0:
        print(f"{start} {end}")
    start = end + 1
PY
)

run_shard() {
  local id="$1" start="$2" end="$3"
  local port_base=$((BASE_PORT + id * PORT_STRIDE))
  local log="$OUT_DIR/shard-${id}.log"
  local work
  work="$(mktemp -d "${TMPDIR:-/tmp}/socat-shard-$id.XXXXXX")"

  # Temp copy with isolated _PORT base so parallel shards never fight.
  # Also force a private TMPDIR for artifacts.
  local patched="$work/test.sh"
  sed -e "s/^_PORT=12001/_PORT=${port_base}/" "$TEST_SH" >"$patched"
  chmod +x "$patched"

  local args=(-t "$VAL_T" -N "$start" -Z "$end")
  # Optional classic filter tokens (group names / test names)
  # When ONLY is set, still apply number window so shards stay disjoint.
  local filter=()
  if [[ -n "$ONLY" ]]; then
    # shellcheck disable=SC2206
    filter=($ONLY)
  fi

  local ec=0
  # Outer timeout kills hung shards (the main 30‑minute problem).
  set +e
  (
    export TMPDIR="$work/tmp"
    mkdir -p "$TMPDIR"
    export SOCAT FILAN PROCAN
    cd "$work"
    # shellcheck disable=SC2086
    timeout --signal=TERM --kill-after=15 "${SHARD_TIMEOUT}" \
      bash "$patched" "${args[@]}" ${filter[@]+"${filter[@]}"}
  ) >"$log" 2>&1
  ec=$?
  set -e

  # Parse classic counters from log (last matching lines win)
  local ok fail cant
  ok=$(grep -E 'numOK=|^Summary:' "$log" | tail -5 || true)
  # Prefer Summary line
  local summary
  summary=$(grep -E '^Summary:' "$log" | tail -1 || true)
  if [[ -z "$summary" ]]; then
    if [[ $ec -eq 124 ]]; then
      summary="Summary: SHARD TIMEOUT (range $start-$end, ${SHARD_TIMEOUT}s)"
    else
      summary="Summary: (no summary, exit=$ec) range $start-$end"
    fi
  fi

  # Extract OK/FAIL/CANT from Summary if present:
  # Summary: 608 tests, 50 selected; 40 ok, 3 failed, 7 could not be performed
  local sok=0 sfail=0 scant=0
  if [[ "$summary" =~ ([0-9]+)[[:space:]]+ok,[[:space:]]+([0-9]+)[[:space:]]+failed,[[:space:]]+([0-9]+) ]]; then
    sok="${BASH_REMATCH[1]}"
    sfail="${BASH_REMATCH[2]}"
    scant="${BASH_REMATCH[3]}"
  fi

  # Also count line-level results as a cross-check (hangs may omit Summary)
  local lok lfail
  lok=$(grep -cE '\.\.\. OK\s*$' "$log" 2>/dev/null || echo 0)
  lfail=$(grep -cE '\.\.\. FAILED' "$log" 2>/dev/null || echo 0)

  printf '%s\n' "$id $start $end $ec $sok $sfail $scant $lok $lfail" >"$OUT_DIR/shard-${id}.summary"
  printf 'shard %d  tests %d-%d  exit=%d  summary: %s\n' "$id" "$start" "$end" "$ec" "$summary" \
    | tee -a "$OUT_DIR/aggregate.txt"

  # Cleanup temp workdir unless debugging
  if [[ "$KEEP_LOGS" != "1" ]]; then
    rm -rf "$work"
  fi

  cleanup_orphans
  return 0
}

export -f run_shard cleanup_orphans
export TEST_SH OUT_DIR BASE_PORT PORT_STRIDE VAL_T SHARD_TIMEOUT ONLY SOCAT FILAN PROCAN ROOT KEEP_LOGS

echo "shards:"
i=0
for range in "${RANGES[@]}"; do
  read -r s e <<<"$range"
  echo "  [$i] $s-$e  ports ~$((BASE_PORT + i * PORT_STRIDE))+"
  i=$((i + 1))
done
echo

# Launch shards in parallel (bounded by JOBS which equals number of ranges)
i=0
pids=()
for range in "${RANGES[@]}"; do
  read -r s e <<<"$range"
  run_shard "$i" "$s" "$e" &
  pids+=($!)
  i=$((i + 1))
done

ec_all=0
for p in "${pids[@]}"; do
  if ! wait "$p"; then
    ec_all=1
  fi
done

cleanup_orphans

echo
echo "======== AGGREGATE ========"

python3 - "$OUT_DIR" <<'PY'
import pathlib, re, sys
out = pathlib.Path(sys.argv[1])
total_ok = total_fail = total_cant = 0
line_ok = line_fail = 0
timeouts = 0
shards = sorted(out.glob("shard-*.summary"), key=lambda p: int(p.stem.split("-")[1]))
print(f"{'shard':>5}  {'range':>12}  {'exit':>4}  {'ok':>4}  {'fail':>4}  {'cant':>4}  {'log_ok':>6}  {'log_fail':>8}")
for sp in shards:
    parts = sp.read_text().split()
    # id start end ec sok sfail scant lok lfail
    if len(parts) < 9:
        print(sp, parts)
        continue
    sid, start, end, ec, sok, sfail, scant, lok, lfail = parts[:9]
    sid, start, end, ec = map(int, (sid, start, end, ec))
    sok, sfail, scant = int(sok), int(sfail), int(scant)
    lok, lfail = int(lok), int(lfail)
    total_ok += sok
    total_fail += sfail
    total_cant += scant
    line_ok += lok
    line_fail += lfail
    if ec == 124:
        timeouts += 1
    print(f"{sid:5d}  {start:5d}-{end:<5d}  {ec:4d}  {sok:4d}  {sfail:4d}  {scant:4d}  {lok:6d}  {lfail:8d}")

print()
print(f"From Summary lines:  OK={total_ok}  FAILED={total_fail}  CANT={total_cant}  (sum selected={total_ok+total_fail+total_cant})")
print(f"From log greps:      OK={line_ok}  FAILED={line_fail}")
if timeouts:
    print(f"Shards hit SHARD_TIMEOUT: {timeouts}  (see shard-*.log; raise SHARD_TIMEOUT or fix hangs)")

# List failed tests across logs
fails = []
for log in sorted(out.glob("shard-*.log")):
    for line in log.read_text(errors="replace").splitlines():
        if re.search(r"\.\.\. FAILED", line) or (line.startswith("test ") and "FAILED" in line):
            fails.append(line.strip()[:200])
if fails:
    print("\nFailed tests:")
    for f in fails[:80]:
        print(" ", f)
    if len(fails) > 80:
        print(f"  ... and {len(fails)-80} more")

# Write machine-readable total
(out / "totals.txt").write_text(
    f"ok={total_ok}\nfail={total_fail}\ncant={total_cant}\nline_ok={line_ok}\nline_fail={line_fail}\ntimeouts={timeouts}\n"
)
# Non-zero if any hard failures or shard timeouts
sys.exit(1 if total_fail or timeouts or line_fail else 0)
PY
agg_ec=$?

echo
echo "Logs under $OUT_DIR (shard-*.log)."
echo "Tip: ONLY=functions JOBS=1 $0 $TEST_SH   # fast smoke"
echo "     JOBS=8 SHARD_TIMEOUT=120 $0 $TEST_SH  # full parallel"

exit "$agg_ec"
