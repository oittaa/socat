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

`scripts/scorecard-parse.py` keeps dotted test names (for example
`OPENSSL_METHOD_TLS1.2`). On a shard that printed a valid `Summary:` footer
and did not time out, it prefers the explicit upstream `CANT:` / `FAILED:`
ID lists when those lists are unambiguous, and records a per-test `conflict`
when the printed `... FAILED` / `... OK` token disagrees. A missing
`Summary:` footer or a non-timeout abort does not override a printed
outcome. Overlap between the two lists is a reporting error: both
`scorecard-parse.py` and `scorecard-update.py validate-result` reject the
result independently of `--regression-exit`, and `classic-scorecard.sh`
does not overwrite `SAVE_BASELINE`. These are parser corrections,
not changes in socat behavior. Committed JSON in this directory is not
rewritten only to match a parser change.

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

For a committed refresh, a fresh clone on a Linux Docker host needs one command:

```bash
bash ./scripts/update-scorecard.sh
# Or: make update-scorecard
```

It checks the Docker daemon (using passwordless `sudo` automatically when
direct socket access is unavailable), proves that a privileged container can
create a network namespace and TUN device, checks container DNS and HTTPS
access, rebuilds the pinned classic image, and runs the full classic
`test.sh` twice: first with classic C and then with this Go tree. Both runs use
`MODE=classic`, `PRIVILEGED=1`, and `TEST_SH_ARGS=--internet`. Only complete,
internally consistent runs are copied
into this directory; timeouts, unknown results, contradictory CANT/FAILED
lists, mismatched test sets, or stale comparison reports leave the committed
files untouched. Full logs stay under a
printed `.scorecard/update.*` path, together with comparisons against the
previous committed Docker baselines.

The Go run passes `functions filan` explicitly. That is the complete numbered
suite used by the scorecard, but omits `test.sh`'s unnumbered `consistency`
prechecks because those require internal type, phase, and group fields that this
port intentionally does not expose in user help.

The command updates the Docker JSON baselines, their summaries, both comparison
reports, and the mechanical Docker counts in this README. It never stages or
commits files. Review `git diff -- testdata/scorecard`, adjust explanatory prose
if a status changed, then commit the result.

The lower-level commands below remain useful for smoke tests and diagnosis:

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
route, VSOCK device, "not with root" denials, missing `systemd-socket-activate`,
one PTY ioctl case under root, a timing-sensitive classic DTLS-client test,
and DCCP tests when the host kernel has retired DCCP. `NETNS` /
`NETNS_EXEC` need `PRIVILEGED=1` (see Go Docker section). Default Docker caps
do not let `ip netns add` create `/run/netns/<name>`.

The saved `classic-docker-baseline.json` still records test 492 `ACCEPT_FD`
as CANT (`systemd-socket-activate not available`). Rebuilt images install
the `systemd` package so that binary is present (they do not boot systemd).
A focused rerun of 492 passes for C and Go; the latest full Go Docker run
now records it as OK. The classic reference is retained from its earlier run.

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

# Match testdata/scorecard/go-docker-baseline.json
USE_HOST_BIN=1 NO_BUILD=1 MODE=classic PRIVILEGED=1 TEST_SH_ARGS=--internet \
  ./scripts/docker-go-scorecard.sh
```

Results land in `.scorecard/docker-go/`. Use this path for root-only
features (RAWIP, raw IP ancillary, TUN, `netns=`).

`PRIVILEGED=1` runs `docker run --privileged`. Without it, `ip netns add`
fails and classic `test.sh` reports FAILED (no namespace file), not CANT.
On an unprivileged host the same tests stay **CANT** (must be root).

`TEST_SH_ARGS` is extra flags for classic `test.sh` (example: `--internet`).
The committed Go Docker baseline uses `PRIVILEGED=1 MODE=classic
TEST_SH_ARGS=--internet`, so `NETNS` / `NETNS_EXEC` and the outbound
address-order tests are OK. Refresh it the same way. Rebuild the classic
image after a Dockerfile change (do not use `NO_BUILD=1` that first time).
Without `--internet`, those address-order tests stay CANT and look like
regressions vs this baseline.

The image installs `bind9-host` and `dnsutils` because `--internet`
address-order tests call `nslookup` / `host`.

## Commands

```bash
# Sync and build the pinned release in the shared parity cache.
make classic-parity
CLASSIC_TREE="$(python3 -B scripts/classic-parity.py path --tree release)"

# 1) Record classic baseline — sequential like upstream (recommended)
SOCAT="$CLASSIC_TREE/socat" \
  FILAN="$CLASSIC_TREE/filan" \
  PROCAN="$CLASSIC_TREE/procan" \
  SKIP_BUILD=1 LABEL=classic MODE=classic \
  SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
  ./scripts/classic-scorecard.sh

# 2) Go parity run (same classic-like shape; low flake)
MODE=classic \
  BASELINE=testdata/scorecard/classic-baseline.json \
  LABEL=go REGRESSION_EXIT=0 \
  ./scripts/classic-scorecard.sh

# 3) Update Go baseline after intentional improvements
MODE=classic \
  SAVE_BASELINE=testdata/scorecard/go-baseline.json \
  BASELINE=testdata/scorecard/go-baseline.json \
  REGRESSION_EXIT=1 \
  ./scripts/classic-scorecard.sh

# Fast parallel smoke only
JOBS=8 VAL_T=0.1 SHARD_TIMEOUT=300 \
  ./scripts/classic-scorecard.sh

# Offline compare only
./scripts/scorecard-compare.py \
  testdata/scorecard/classic-baseline.json \
  .scorecard/host/results.json
```

## Latest committed baselines

Counts come from structured `results.json`. Refresh the numbers when you
save a new baseline.

The compatibility source baseline is the official `tag-1.8.1.3` release
(`12c08bf66d709fba17035ce95d85bd218428d9ba`), also checked against official
master (`af5388c898c7bb60997935aee93c223deba60c4a`). The Go host baseline was
recorded in `MODE=stable` (`JOBS=1`, `VAL_T=0.5`). The Go Docker baseline was
recorded with `MODE=classic PRIVILEGED=1 TEST_SH_ARGS=--internet`.

The latest Go Docker run tested `15c12a4fef49fc2d54a2481c4a20e53afc9dc78e`
on the Hyper-V Linux lab VM on 2026-09-03. It recorded all 605 numbered
tests, with no timeouts, unknown results, or regressions from the previous
Go Docker baseline: all 538 previously passing tests still pass. The one
additional pass is `ACCEPT_FD`, enabled by the image dependency above.
The classic test script, libc, and OpenSSL versions were unchanged;
the saved classic and host baselines were not rerun or replaced.

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (host) | 475 | 24 | 103 |
| classic 1.8.1.3 (Docker, root) | 565 | 4 | 36 |
| go (this tree, host) | 471 | 7 | 127 |
| go (this tree, Docker, root, privileged, `--internet`) | 539 | 6 | 60 |

Go host FAILED: `OPENSSL_COMPRESS` (`compress=auto` is intentionally rejected),
`OPENSSLLISTENDSA` (DSA, by design), `REUSEADDR_NULL` (NO RESULT),
`OPENSSL_ANULL`, `V1800_OPENSSL_LISTEN_RANGE`,
`V1800_OPENSSL_LISTEN_BIND` (listen requires `cert=`), and `SHELL_SIGINT`
(classic `test.sh` greps a `waitpid` warning log; see below). It records no
UNKNOWN or TIMEOUT results. Go Docker FAILED: `OPENSSL_COMPRESS`,
`OPENSSLLISTENDSA`, `OPENSSL_ANULL`, `SHELL_SIGINT`,
`V1800_OPENSSL_LISTEN_RANGE`, and `V1800_OPENSSL_LISTEN_BIND`.
`REUSEADDR_NULL` and `IOCTL_VOID` are CANT. `SOCKETPAIR_BOUNDARIES` is OK.
Both Go runs record UNKNOWN=0.

The previous Go Docker baseline recorded 538 OK / 7 FAILED / 60 CANT.
`IOCTL_VOID` now records CANT with a conflict: upstream prints
`FAILED (rc2=0, because root?)` but includes the test in its CANT list.
That reduction in FAILED is a reporting correction, not a behavior fix.
Re-parsing the previous run with the corrected parser gives
538 OK / 6 FAILED / 61 CANT; `ACCEPT_FD` is the only subsequent status change.
The refreshed JSON also retains dotted names such as `OPENSSL_METHOD_TLS1.2`.

`SHELL_SIGINT` is not a signal-delivery bug. Classic `test.sh` looks for
`W waitpid(): child … exited with status 130` / `exited on signal 2` in
socat's log. This port waits with Go `Wait()` and does not emit that line, so
the classic case is FAILED. SIGINT pass-through is covered by
`TestEXECParentSignalPassThrough`. Do not treat the classic `test.sh` FAILED
as a behavior regression.

## Post-#234 gap triage

The endpoint-setup refactor kept the structured scorecard set at 605 tests.
A sequential `ONLY="functions filan" JOBS=1 VAL_T=0.1` Go run reported
470 OK / 7 FAILED / 128 CANT. The committed host baseline is
471 OK / 7 FAILED / 127 CANT (`go-baseline.json`). Treat a one-test OK/CANT
move as a re-run question, not as a refactor regression.

Official classic baseline rechecked 2026-09-04 from
[repo.or.cz/socat.git](https://repo.or.cz/socat.git):

| Ref | Commit | Tree |
|-----|--------|------|
| `tag-1.8.1.3` | `12c08bf66d709fba17035ce95d85bd218428d9ba` | `0e4f2df1dc5e882663067ffa27c8457684f5fcde` |
| reviewed master | `af5388c898c7bb60997935aee93c223deba60c4a` | `0e4f2df1dc5e882663067ffa27c8457684f5fcde` |

Release and master are still identical. No new compatibility choice from
drift. `scripts/classic-baseline.json` already pins those commits.

Matching C under the same filter was 498 OK / 2 FAILED / 105 CANT. The 2 C
failures were `OPENSSL_ANULL` and `OPENSSL_DTLS_CLIENT`. That leaves 28
pre-existing C-to-Go differences (6 FAILED + 22 CANT) plus `OPENSSL_ANULL`
which FAILED on both. Committed Docker comparison
(`go-vs-classic-docker-gaps.json`) is 5 FAILED + 22 CANT (`parity_gap_total`
27) because Docker `OPENSSL_ANULL` FAILED on both sides and Docker `SOCAT_MUX`
is OK on both sides.

Do not enable excluded TLS features to make tests pass.

### Go FAILED names

| Test | Class | Notes |
|------|-------|-------|
| `OPENSSL_COMPRESS` | Intentional exclusion | `compress=auto` is rejected; `compress=none` is accepted. README / `classic-policy.json`. Reproduction: `OPENSSL-LISTEN:…,compress=auto` exits 1 with “compress is not supported”. |
| `OPENSSLLISTENDSA` | Intentional exclusion | DSA keys are rejected. README table “DSA, SSLv3, and weak TLS ciphers”. Covered by `TestLoadKeyPairRejectsDSA`. |
| `OPENSSL_ANULL` | Shared with classic C | Classic `test.sh` uses `ciphers=aNULL`. Both C and Go print FAILED. Weak ciphers stay rejected. |
| `SHELL_SIGINT` | Harness log format, not delivery | `test.sh` greps C `waitpid` warnings. This port logs `socatsignalpass(): propagated signal to … sub processes` and does **not** emit `W waitpid():…`. `TestEXECParentSignalPassThrough` covers SIGINT. Do not fake C waitpid lines. |
| `SOCAT_MUX` | Environment / harness | Classic `test.sh` runs `./socat-mux.sh` from the classic tree. This repo does not vendor that script. Committed Go host and Go Docker baselines are **OK**. Classic **host** baseline is FAILED `(rc2b=1)`; classic Docker is OK. A sequential Go FAILED is a missing helper or timing flake: re-run `ONLY=SOCAT_MUX JOBS=1` with classic `test.sh` helpers linked, do not change mux/UDP parents. |
| `V1800_OPENSSL_LISTEN_RANGE` | Intentional exclusion | Generated 1.8.0 regression case runs `OPENSSL-LISTEN:$PORT,range=…` **without** `cert=`. Classic C binds and treats `timeout` 124 as success. This port fails immediately: `OPENSSL-LISTEN: option "cert" is required` (rc=1). README: “TLS listeners fail immediately when `cert=` is missing.” `TestTLSServerConfigRequiresCert`. |
| `V1800_OPENSSL_LISTEN_BIND` | Intentional exclusion | Same as RANGE with `bind=` instead of `range=`. |

Documentation vs runtime: classic `doc/socat.yo` documents OPENSSL-LISTEN
certificate use; classic C still starts a listen without `cert=` long enough
for those V1800 cases to pass. This port’s immediate refusal is the
documented security exception, not an implementation defect.

### Docker CANT vs classic OK (22)

All are documented exclusions or missing classic-only protocols, not
capability-detection bugs to “fix” by advertising unsupported names:

| Names | Class |
|-------|-------|
| `READLINE`, `READLINE_OVFL` | GNU readline not implemented |
| `COOLWRITE`, `COOLSTDIO` | `cool-write` deprecated; use `children-shutup` |
| `OPENSSL_DTLS_SERVER`, `OPENSSL_DTLS_TO_SERVER`, `OPENSSL_DTLS_TO_CLIENT`, `RCVTIMEO_DTLS` | DTLS not in Go `crypto/tls` |
| `UDP_DATAGRAM_PEERPORT` | `udp-ignore-peerport` documented but never implemented by classic C |
| `UDPLITE4STREAM`, `UDPLITE6STREAM`, `UDPLITE4LISTENENV`, `UDPLITE6LISTENENV`, `UDPLITE4_L_MAXCHILDREN`, `UDPLITE6_L_MAXCHILDREN`, `V1800_UDPLITE_*` (6) | UDP-Lite removed from modern Linux |

### Help-type consistency precheck

Unfiltered classic `test.sh` also runs unnumbered `consistency` checks before
numbered tests. The option-type check greps `-hhh` for
`ip-add-source-membership` and requires a C-internal `type=IP-MREQ-SOURCE`
field. This port implements the option (`internal/xio/mcast_opt.go`) and
lists it in user help, but `-hhh` must not grow `type=` / `phase=` /
`groups=` / `opt:` metadata (`TestHelpOmitsInternalMetadata`).
`ONLY=functions filan` skips those prechecks. Do not suppress the precheck
and do not add C-internal fields to user help. The scorecard reports the
stop when it happens.

### What not to change

No socat runtime fix belongs with this triage. In particular: do not allow
missing `cert=` on TLS listeners, do not enable TLS compression or DSA, do
not emit fake `waitpid` logs, and do not add a universal lifecycle framework
to chase `SOCAT_MUX`.

`OPENPTYWAITSLAVE` can `TIMEOUT` in a long sequential Docker run; an isolated
`ONLY=OPENPTYWAITSLAVE` re-run is OK. The committed Docker baseline records it
as OK. Do not treat a full-run timeout of that name as a regression until you
re-run it alone.

Classic `OPENSSL_DTLS_CLIENT` is also timing-sensitive: `test.sh` delays the
server payload by `2*val_t` but gives the client an idle timeout of only
`3*val_t`. Re-run test 399 alone before treating an OK/FAILED change as a socat
regression.

An earlier Go host refresh from 483 OK / 6 FAILED / 116 CANT
moved 13 UDPLITE tests OK→CANT after UDP-Lite addresses were removed (#135;
Linux 7.1 retired the protocol). `RES_NSADDR` moved CANT→OK (`res-nsaddr`,
#134). `SHELL_SIGINT` moved CANT→FAILED as above (the option is now
advertised). Host `UDP6MULTICAST_UNIDIR` stays OK.

The earlier Go Docker refresh from 550 OK / 7 FAILED / 48 CANT to
538 OK / 7 FAILED / 60 CANT made the same UDPLITE, `RES_NSADDR`, and
`SHELL_SIGINT` status changes. Docker
`PROXY_CONNECT_MAXCHILDREN` stays OK (an earlier full-run FAILED was a flake;
isolated re-run passed). Classic `cool-write` is deprecated (use
`children-shutup`); this port does not advertise it, so `COOLWRITE` /
`COOLSTDIO` stay CANT. Host-only OK that Docker does not get:
`GOPEN_TO_DENIED` (not with root). Vs classic Docker, Go has 539 OK against 565
classic OK (`parity_gap_total` 27 in `go-vs-classic-docker-gaps.json`).

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
