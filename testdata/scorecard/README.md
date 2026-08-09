# Scorecard baselines

This directory holds **saved results** from classic `test.sh` runs so we do not
need to re-run the classic C binary on every development cycle.

## Approach

1. **Classic baseline (rare)** — run once against Gerhard’s C socat (or after
   upgrading the classic tree / host libs). Save to
   `classic-baseline.json`.
2. **Go run (often)** — run our binary; write `results.json` under
   `.classic-scorecard/`.
3. **Compare** — either:
   - Go vs **classic baseline** → “how far from classic parity?”
   - Go vs **previous Go baseline** → “did we regress?”

Statuses recorded per test:

| Status | Meaning |
|--------|---------|
| `OK` | passed |
| `FAILED` | ran and failed |
| `CANT` | could not perform (missing feature, root, internet, …) |
| `TIMEOUT` | shard killed; incomplete result |
| `UNKNOWN` | no clear result line |

## How classic runs vs our runner

Upstream **`test.sh`** is **sequential**: one process, tests 1…N in order, and
if you omit `-t` it measures machine speed and sets `val_t` itself.

Our **`scripts/classic-scorecard.sh`** can match that or go faster:

| `MODE` | Behaviour | Flake risk | Speed |
|--------|-----------|------------|-------|
| `classic` | `JOBS=1`, `VAL_T=auto` (no `-t`), long wall timeout | lowest | slowest (~tens of min) |
| `stable` | `JOBS=1`, `VAL_T=0.5` | low | slow |
| `fast` (default) | parallel shards, short `VAL_T` | higher | fast |

**Why fast is flaky:** short `-t`, concurrent ports/CPU, orphaned processes
from a prior test, and shard wall timeouts that leave incomplete results
(which look like regressions vs a previous baseline).

**Anti-flake checklist:**

1. Prefer `MODE=classic` (or `MODE=stable`) for baselines and “is this a real FAIL?”.
2. Use `VAL_T=0.1` or higher if you stay parallel; `0.05` is aggressive.
3. Raise `SHARD_TIMEOUT` if a shard dies with exit 124.
4. Re-run only the FAILED names with `ONLY='NAME1 NAME2' JOBS=1` before chasing.
5. Kill leftovers only for **this** tree’s binary (the runner already does that).

## Commands

```bash
# Obtain classic tree
git clone --depth 1 https://repo.or.cz/socat.git /tmp/socat-master
# Use a built classic binary, e.g. /tmp/socat-1.8.1.3/socat

# 1) Record classic baseline — sequential like upstream (recommended)
SOCAT=/tmp/socat-1.8.1.3/socat \
  FILAN=/tmp/socat-1.8.1.3/filan \
  PROCAN=/tmp/socat-1.8.1.3/procan \
  SKIP_BUILD=1 LABEL=classic MODE=classic \
  SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# 2) Go parity run (same classic-like shape; low flake)
MODE=classic \
  BASELINE=testdata/scorecard/classic-baseline.json \
  LABEL=go REGRESSION_EXIT=0 \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# 3) Update Go baseline after intentional improvements
MODE=classic \
  SAVE_BASELINE=testdata/scorecard/go-baseline.json \
  BASELINE=testdata/scorecard/go-baseline.json \
  REGRESSION_EXIT=1 \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# Fast parallel smoke only
JOBS=8 VAL_T=0.1 SHARD_TIMEOUT=300 \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# Offline compare only
./scripts/scorecard-compare.py \
  testdata/scorecard/classic-baseline.json \
  .classic-scorecard/results.json
```

## Files

| File | Role |
|------|------|
| `classic-baseline.json` | Reference: classic C results on a known host |
| `classic-baseline.summary.txt` | Human one-pager for classic |
| `go-baseline.json` | Optional: last known-good Go run (regression gate) |
| `.classic-scorecard/results.json` | Latest run (gitignored working data) |

## When to refresh classic baseline

- Classic socat version changes
- Host gains/loses features (OpenSSL, SCTP, root tests, …)
- `test.sh` itself updates (new/renumbered tests)

## Why not only go test?

Unit/e2e tests catch local contracts. Classic `test.sh` is still the
**parity scorecard** (~600 cases). Structured baselines make that
scorecard usable as a regression suite without paying the classic binary
cost every time.
