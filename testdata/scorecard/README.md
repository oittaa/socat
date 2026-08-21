# Scorecard baselines

This directory holds **saved results** from classic `test.sh` runs so we do not
need to re-run the classic C binary on every development cycle.

Working runs (logs, `results.json`) go under **`.scorecard/`** at the repo
root (gitignored). Defaults: `.scorecard/host`, `.scorecard/docker`,
`.scorecard/docker-go`. Ad-hoc runs: `OUT_DIR` / `OUT_HOST=$PWD/.scorecard/name`.

## Approach

1. **Classic baseline (rare)** — run once against Gerhard’s C socat (or after
   upgrading the classic tree / host libs). Save to
   `classic-baseline.json`.
2. **Go run (often)** — run our binary; write `results.json` under
   `.scorecard/host/`.
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

## Docker classic scorecard (recommended for root / raw IP)

Run Gerhard’s C socat + `test.sh` **as root inside Ubuntu 26.04** with network
capabilities. This is safer than root on the laptop and unlocks many tests that
are `CANT` (must be root) on an unprivileged host.

```bash
# Build image + full MODE=classic run; verify host-OK set still passes
./scripts/docker-classic-scorecard.sh

# Reuse image; write under a custom dir
NO_BUILD=1 OUT_HOST=$PWD/.scorecard/docker \
  ./scripts/docker-classic-scorecard.sh

# Smoke only
NO_BUILD=1 MODE=stable ONLY=ancillary \
  OUT_HOST=$PWD/.scorecard/docker-smoke \
  ./scripts/docker-classic-scorecard.sh
```

Image: `docker/classic-test/Dockerfile` → tag `socat-classic-test`.  
Host wrapper: `scripts/docker-classic-scorecard.sh`  
Results: `.scorecard/docker/results.json` and
`testdata/scorecard/classic-docker-baseline.json` (saved reference).

Caps used: `NET_ADMIN`, `NET_RAW`, `SYS_CHROOT`, `SETUID`, `SETGID`,
`SYS_ADMIN`, `NET_BIND_SERVICE`, plus `/dev/net/tun` when present.

Expected host→docker losses (environment, not binary bugs): UDP6 multicast
route, VSOCK device, “not with root” denials, missing `systemd-socket-activate`,
and one PTY ioctl case under root. `NETNS` / `NETNS_EXEC` need
`PRIVILEGED=1` (see Go Docker section). Default Docker caps do not let
`ip netns add` create `/run/netns/<name>`.

### Go under test in Docker

```bash
# Build classic base + Go image, full MODE=classic vs classic-docker-baseline
./scripts/docker-go-scorecard.sh

# Host-built binaries (skip gobuild stage)
USE_HOST_BIN=1 NO_BUILD=1 ./scripts/docker-go-scorecard.sh

# netns= (NETNS, NETNS_EXEC): ip netns add needs a privileged container.
# Default --cap-add=SYS_ADMIN is not enough (mount --make-shared /run/netns).
USE_HOST_BIN=1 NO_BUILD=1 PRIVILEGED=1 ONLY='NETNS NETNS_EXEC' \
  ./scripts/docker-go-scorecard.sh
```

Results land in `.scorecard/docker-go/`. Use this path for root-only
features (RAWIP, raw IP ancillary, TUN, `netns=`).

`PRIVILEGED=1` runs `docker run --privileged`. Without it, `ip netns add`
fails and classic `test.sh` reports FAILED (no namespace file), not CANT.
On an unprivileged host the same tests stay **CANT** (must be root).
The committed Go Docker baseline uses `PRIVILEGED=1 MODE=classic`, so
`NETNS` / `NETNS_EXEC` are OK. Refresh it the same way.

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
  .scorecard/host/results.json
```

## Latest committed baselines

Counts come from structured `results.json`. Refresh the numbers when you
save a new baseline.

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (host) | 475 | 24 | 103 |
| classic 1.8.1.3 (Docker, root) | 552 | 8 | 42 |
| go (this tree, host) | 449 | 6 | 148 |
| go (this tree, Docker, root, privileged) | 511 | 6 | 86 |

Go host FAILED: `OPENSSLLISTENDSA` (DSA, by design), `UDP6MULTICAST_UNIDIR`
(host environment), `REUSEADDR_NULL` (NO RESULT), `OPENSSL_ANULL`,
`V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND` (listen requires
`cert=`). Go Docker FAILED: `OPENSSLLISTENDSA`, `REUSEADDR_NULL` (NO RESULT),
`OPENSSL_ANULL`, `V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND`
(listen requires `cert=`), and `SOCKETPAIR_BOUNDARIES` (`SOCKETPAIR` with
`socktype=datagram` is still a byte relay, so UDP packet boundaries merge).
Both Go runs also record UNKNOWN=2 (`EXECPTYKILL` parse quirk, `PROCAN_CTTY`).

`OPENPTYWAITSLAVE` can `TIMEOUT` in a long sequential Docker run; an isolated
`ONLY=OPENPTYWAITSLAVE` re-run is OK. The committed Docker baseline records
that OK. Do not treat a full-run timeout of that name as a regression until
you re-run it alone.

Vs the previous Go Docker baseline (506 OK / 5 FAILED / 92 CANT), this refresh
gains `UDP6MULTICAST_UNIDIR`, `CONNECT_TO_DGRAM`, `CONNECT_TO_SEQPACKET`,
`SEQPACKET_TO_STREAM`, and `SEQPACKET_TO_DGRAM`. `SOCKETPAIR_BOUNDARIES`
moves from CANT to FAILED because the address now runs.

Use `go-baseline.json` + `REGRESSION_EXIT=1` after a **MODE=classic** run
to catch real Go regressions with less noise.

Classic host checklist: `scripts/classic-host-check.sh`.

## Files

| File | Role |
|------|------|
| `classic-baseline.json` | Reference: classic C results on a known host (often non-root) |
| `classic-baseline.summary.txt` | Human one-pager for classic |
| `classic-docker-baseline.json` | Classic C in Docker as root (more OK; raw/IP/tcpwrap) |
| `classic-docker-vs-host.json` | Host OK set vs docker verify report |
| `go-baseline.json` | Last known-good Go host run (regression gate) |
| `go-docker-baseline.json` | Last known-good Go Docker/root run |
| `go-vs-classic-docker-gaps.json` | Classic-docker OK that Go did not get |
| `.scorecard/host/` | Latest host run (gitignored working data) |
| `.scorecard/docker/` | Latest docker classic run (working data) |
| `.scorecard/docker-go/` | Latest docker Go run (working data) |

## When to refresh classic baseline

- Classic socat version changes
- Host gains/loses features (OpenSSL, SCTP, root tests, …)
- `test.sh` itself updates (new/renumbered tests)

## Why not only go test?

Unit/e2e tests catch local contracts. Classic `test.sh` is still the
**parity scorecard** (~600 cases). Structured baselines make that
scorecard usable as a regression suite without paying the classic binary
cost every time.
