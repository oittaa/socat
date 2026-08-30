#!/usr/bin/env bash
# Classic socat test.sh scorecard for this Go reimplementation.
#
# Classic upstream runs test.sh **sequentially** (one process, tests in order)
# and auto-calibrates -t from machine speed. That is slower but far less flaky.
#
# This runner can:
#   - Match classic: MODE=classic (JOBS=1, auto -t, long wall timeout)
#   - Stable parity: MODE=stable  (JOBS=1, generous -t, long timeout)
#   - Fast iterate:  MODE=fast    (parallel shards, short -t; default)
#
# A single hung socat can freeze an unbounded suite; every mode still uses a
# wall SHARD_TIMEOUT and kills leftover socat from this tree between shards.
#
# After each run it writes structured results:
#   OUT_DIR/results.json   — full snapshot (meta + per-test status)
#   OUT_DIR/results.jsonl  — one JSON object per test
#   OUT_DIR/compare.json   — if BASELINE= is set
#
# Usage:
#   # Fast parallel (default) — good for smoke, flakier under load
#   ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#
#   # Same shape as classic: sequential + auto val_t (recommended for baselines)
#   MODE=classic ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#
#   # Sequential with fixed generous -t (no auto-calibration)
#   MODE=stable ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#
#   # Record classic C baseline once
#   SOCAT=/path/to/classic/socat LABEL=classic MODE=classic \
#     SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
#     ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#
#   # Go regression vs last baseline
#   MODE=classic BASELINE=testdata/scorecard/go-baseline.json REGRESSION_EXIT=1 \
#     SAVE_BASELINE=testdata/scorecard/go-baseline.json \
#     ./scripts/classic-scorecard.sh /path/to/classic/test.sh
#
#   JOBS=8 SHARD_TIMEOUT=120 VAL_T=0.1 ONLY=functions MAX_N=100 ...
#   VAL_T=auto  — omit -t; let test.sh calibrate (classic default)
#
# Does not modify upstream test.sh in place; uses a temp copy with a port base.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# MODE presets (explicit env still wins if set after — apply only when unset)
MODE="${MODE:-fast}"
case "$MODE" in
  classic)
    # Match upstream: one process, auto -t, plenty of wall time.
    : "${JOBS:=1}"
    : "${VAL_T:=auto}"
    : "${SHARD_TIMEOUT:=7200}"   # 2h wall for full sequential suite
    ;;
  stable)
    # Sequential with fixed generous linger (reproducible without calibration).
    : "${JOBS:=1}"
    : "${VAL_T:=0.5}"
    : "${SHARD_TIMEOUT:=3600}"
    ;;
  fast|"")
    : "${JOBS:=$(nproc 2>/dev/null || echo 4)}"
    : "${VAL_T:=0.05}"
    : "${SHARD_TIMEOUT:=180}"
    ;;
  *)
    echo "unknown MODE=$MODE (use classic|stable|fast)" >&2
    exit 2
    ;;
esac

JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
SHARD_TIMEOUT="${SHARD_TIMEOUT:-180}"   # wall seconds per shard (not per test)
VAL_T="${VAL_T:-0.05}"                 # classic -t; "auto" = omit -t (test.sh calibrates)
BASE_PORT="${BASE_PORT:-20000}"        # first shard port base; each shard + PORT_STRIDE
PORT_STRIDE="${PORT_STRIDE:-3000}"     # port space per shard (avoid collisions)
MAX_N="${MAX_N:-}"                     # optional cap on highest test number
ONLY="${ONLY:-}"                       # optional classic group/name filter (e.g. functions,tcp)
KEEP_LOGS="${KEEP_LOGS:-0}"
OUT_DIR="${OUT_DIR:-$ROOT/.scorecard/host}"
# Structured results / baselines
LABEL="${LABEL:-}"                     # auto: classic|go from binary path if empty
BASELINE="${BASELINE:-}"               # path to results.json to compare against
SAVE_BASELINE="${SAVE_BASELINE:-}"     # copy results.json here after run
REGRESSION_EXIT="${REGRESSION_EXIT:-0}" # 1 = exit non-zero on OK→non-OK vs BASELINE
SKIP_BUILD="${SKIP_BUILD:-0}"          # 1 = do not make build (when using foreign SOCAT)
TEST_SH_ARGS="${TEST_SH_ARGS:-}"       # extra test.sh flags, e.g. --internet
export TEST_SH_ARGS

TEST_SH="${1:-${CLASSIC_TEST_SH:-}}"
if [[ -z "$TEST_SH" ]] && command -v python3 >/dev/null 2>&1; then
  cached_tree="$(python3 -B "$ROOT/scripts/classic-parity.py" path --tree release)"
  cached_test_sh="$cached_tree/test.sh"
  if [[ -f "$cached_test_sh" ]]; then
    TEST_SH="$cached_test_sh"
  fi
fi
if [[ -z "$TEST_SH" || ! -f "$TEST_SH" ]]; then
  echo "classic test.sh not found; run make classic-parity or pass its path" >&2
  exit 2
fi
TEST_SH="$(cd "$(dirname "$TEST_SH")" && pwd)/$(basename "$TEST_SH")"

# Do not patch test.sh. Read TUNNET= from this copy so a classic sync cannot
# reintroduce a local address on the TUNREAD peer (see classic-tunnet-guard.sh).
GUARD="$(cd "$(dirname "$0")" && pwd)/classic-tunnet-guard.sh"
if [[ -x "$GUARD" ]]; then
  "$GUARD" "$TEST_SH"
fi

# Build binaries unless using an external SOCAT only
if [[ "$SKIP_BUILD" != "1" ]]; then
  make -s build
fi

resolve_executable() {
  local value="$1"
  if [[ "$value" == */* ]]; then
    local dir base
    dir="$(cd "$(dirname "$value")" && pwd)"
    base="$(basename "$value")"
    [[ -x "$dir/$base" ]] || return 1
    printf '%s/%s\n' "$dir" "$base"
    return
  fi
  command -v "$value"
}

SOCAT="${SOCAT:-$ROOT/socat}"
SOCAT="$(resolve_executable "$SOCAT")" || { echo "SOCAT is not executable: $SOCAT" >&2; exit 2; }
target_bin_dir="$(dirname "$SOCAT")"
FILAN="${FILAN:-$target_bin_dir/filan}"
PROCAN="${PROCAN:-$target_bin_dir/procan}"
FILAN="$(resolve_executable "$FILAN")" || { echo "FILAN is not executable: $FILAN" >&2; exit 2; }
PROCAN="$(resolve_executable "$PROCAN")" || { echo "PROCAN is not executable: $PROCAN" >&2; exit 2; }
export SOCAT FILAN PROCAN

# Auto label
if [[ -z "$LABEL" ]]; then
  if [[ "$SOCAT" == "$ROOT/socat" || "$SOCAT" == "./socat" ]]; then
    LABEL=go
  else
    LABEL=classic
  fi
fi

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

# Resolve -t args for test.sh (empty / auto → classic self-calibration)
VAL_T_ARGS=()
VAL_T_DISPLAY="$VAL_T"
case "$VAL_T" in
  ""|auto|AUTO)
    VAL_T_DISPLAY="auto (test.sh calibrates)"
    ;;
  *)
    VAL_T_ARGS=(-t "$VAL_T")
    ;;
esac

echo "classic scorecard"
echo "  test.sh:        $TEST_SH"
echo "  SOCAT:          $SOCAT"
echo "  label:          $LABEL"
echo "  mode:           $MODE"
echo "  jobs:           $JOBS"
echo "  shard_timeout:  ${SHARD_TIMEOUT}s"
echo "  -t (val_t):     $VAL_T_DISPLAY"
echo "  total range:    1..$TOTAL"
echo "  only filter:    ${ONLY:-<all numbered>}"
echo "  test.sh extras: ${TEST_SH_ARGS:-<none>}"
echo "  logs:           $OUT_DIR"
echo "  baseline:       ${BASELINE:-<none>}"
echo "  save_baseline:  ${SAVE_BASELINE:-<none>}"
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

  # Classic test.sh expects helper scripts (socks4echo.sh, proxyecho.sh, …)
  # next to it. Symlink them into the shard workdir.
  local classic_dir
  classic_dir="$(dirname "$TEST_SH")"
  local helper
  for helper in "$classic_dir"/*; do
    local base
    base="$(basename "$helper")"
    case "$base" in
      test.sh|socat|filan|procan|*.c|*.h|*.o|*.a|config*|Makefile*|doc|*.1) continue ;;
    esac
    if [[ -f "$helper" && -x "$helper" ]] || [[ "$base" == *.sh ]] || [[ "$base" == *.pem ]] || [[ "$base" == *.crt ]] || [[ "$base" == *.key ]]; then
      ln -sfn "$helper" "$work/$base" 2>/dev/null || cp -a "$helper" "$work/$base" 2>/dev/null || true
    fi
  done
  # Also common generated cert names if present in CWD of classic tree
  for helper in testsrv.pem testsrv.crt testsrv.key testcli.pem testcli.crt testsrv6.pem testsrv6.crt testsrv6.key; do
    if [[ -f "$classic_dir/$helper" ]]; then
      ln -sfn "$classic_dir/$helper" "$work/$helper" 2>/dev/null || cp -a "$classic_dir/$helper" "$work/$helper" 2>/dev/null || true
    fi
  done
  # Some upstream capability checks invoke bare socat instead of $SOCAT.
  # Make every spelling resolve to the binaries selected for this scorecard.
  ln -sfn "$SOCAT" "$work/socat"
  ln -sfn "$FILAN" "$work/filan"
  ln -sfn "$PROCAN" "$work/procan"

  # -N/-Z window; -t only when VAL_T is a number (classic omits -t to auto-calibrate).
  # Rebuild args inside the function (export -f subshells do not keep arrays).
  local args=()
  case "${VAL_T:-}" in
    ""|auto|AUTO) ;;
    *) args+=(-t "$VAL_T") ;;
  esac
  args+=(-N "$start" -Z "$end")
  local extra=()
  if [[ -n "${TEST_SH_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    extra=($TEST_SH_ARGS)
  fi
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
    export PATH="$work:$PATH"
    # shellcheck disable=SC2086
    timeout --signal=TERM --kill-after=15 "${SHARD_TIMEOUT}" \
      bash "$patched" "${args[@]}" ${extra[@]+"${extra[@]}"} ${filter[@]+"${filter[@]}"}
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

# set +e: the aggregate parser exits 1 when there are FAILs; we still want
# structured results + baseline save afterward.
set +e
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
# Aggregate exit: non-zero if hard failures or shard timeouts (legacy behaviour)
sys.exit(1 if total_fail or timeouts or line_fail else 0)
PY
agg_ec=$?
set -e

echo
echo "======== STRUCTURED RESULTS ========"
parse_ec=0
COMPARE_ARGS=()
if [[ -n "$BASELINE" && -f "$BASELINE" ]]; then
  COMPARE_ARGS+=(--compare "$BASELINE")
  if [[ "$REGRESSION_EXIT" == "1" ]]; then
    COMPARE_ARGS+=(--regression-exit)
  fi
fi
set +e
python3 "$ROOT/scripts/scorecard-parse.py" "$OUT_DIR" \
  --label "$LABEL" \
  --socat "$SOCAT" \
  --test-sh "$TEST_SH" \
  --write "$OUT_DIR/results.json" \
  --meta "val_t=$VAL_T" \
  --meta "jobs=$JOBS" \
  --meta "shard_timeout=$SHARD_TIMEOUT" \
  ${COMPARE_ARGS[@]+"${COMPARE_ARGS[@]}"}
parse_ec=$?
set -e

if [[ -n "$SAVE_BASELINE" ]]; then
  mkdir -p "$(dirname "$SAVE_BASELINE")"
  cp -f "$OUT_DIR/results.json" "$SAVE_BASELINE"
  # Keep a sidecar copy of summary for humans
  python3 - "$SAVE_BASELINE" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
doc = json.loads(p.read_text())
s = doc["summary"]
m = doc["meta"]
side = p.with_suffix(".summary.txt")
side.write_text(
    f"label={m.get('label')}\n"
    f"timestamp={m.get('timestamp')}\n"
    f"socat={m.get('socat')}\n"
    f"socat_version={m.get('socat_version')}\n"
    f"git={m.get('git')}\n"
    f"ok={s.get('ok')}\n"
    f"failed={s.get('failed')}\n"
    f"cant={s.get('cant')}\n"
    f"timeout={s.get('timeout')}\n"
    f"unknown={s.get('unknown')}\n"
    f"total_recorded={s.get('total_recorded')}\n"
)
print(f"saved baseline {p}")
print(f"saved summary  {side}")
PY
fi

echo
echo "Logs under $OUT_DIR (shard-*.log)."
echo "Results: $OUT_DIR/results.json  (+ results.jsonl)"
echo "Tip: ONLY=functions JOBS=1 $0 $TEST_SH   # fast smoke"
echo "     JOBS=8 SHARD_TIMEOUT=120 $0 $TEST_SH  # full parallel"
echo "     BASELINE=testdata/scorecard/classic-baseline.json $0 $TEST_SH  # compare"
echo "     SAVE_BASELINE=testdata/scorecard/classic-baseline.json SOCAT=... $0 $TEST_SH"

# Exit: prefer regression exit if requested; else aggregate fail/timeout
if [[ "$REGRESSION_EXIT" == "1" && $parse_ec -ne 0 ]]; then
  exit "$parse_ec"
fi
exit "$agg_ec"
