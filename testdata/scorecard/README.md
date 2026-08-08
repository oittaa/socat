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

## Commands

```bash
# Obtain classic tree
git clone --depth 1 https://repo.or.cz/socat.git /tmp/socat-master
# Use a built classic binary, e.g. /tmp/socat-1.8.1.3/socat

# 1) Record classic baseline (slow; do rarely)
SOCAT=/tmp/socat-1.8.1.3/socat \
  FILAN=/tmp/socat-1.8.1.3/filan \
  PROCAN=/tmp/socat-1.8.1.3/procan \
  SKIP_BUILD=1 LABEL=classic \
  SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
  JOBS=8 SHARD_TIMEOUT=240 VAL_T=0.05 \
  ./scripts/classic-scorecard.sh /tmp/socat-master/test.sh

# 2) Run Go implementation and compare to classic (no classic re-run)
BASELINE=testdata/scorecard/classic-baseline.json \
  LABEL=go REGRESSION_EXIT=0 \
  JOBS=8 SHARD_TIMEOUT=240 VAL_T=0.05 \
  ./scripts/classic-scorecard.sh /tmp/socat-master/test.sh

# 3) Update Go baseline after intentional improvements
SAVE_BASELINE=testdata/scorecard/go-baseline.json \
  BASELINE=testdata/scorecard/go-baseline.json \
  REGRESSION_EXIT=1 \
  ./scripts/classic-scorecard.sh /tmp/socat-master/test.sh

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
