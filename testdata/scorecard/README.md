# Scorecard baselines

Saved classic `test.sh` results. Working runs go under gitignored `.scorecard/`
(`host`, `docker`, `docker-go`).

Statuses: `OK`, `FAILED`, `CANT`, `TIMEOUT`, `UNKNOWN`. When a test prints
`FAILED` but the `Summary:` CANT list includes it, the parser records `CANT`
and a conflict. Overlapping CANT/FAILED lists are a reporting error and do
not overwrite `SAVE_BASELINE`.

## Refresh

On a Linux Docker host:

```bash
make update-scorecard
```

That rebuilds the classic image, runs classic C then this tree as root with
`MODE=classic`, `PRIVILEGED=1`, and `TEST_SH_ARGS=--internet`, and copies
complete results into this directory. It does not commit. The Go run passes
`functions filan` (the numbered suite) and skips unnumbered `consistency`
prechecks that require C-internal `-hhh` fields.

Lower-level runners: `scripts/docker-classic-scorecard.sh`,
`scripts/docker-go-scorecard.sh`. Host checklist:
`scripts/classic-host-check.sh`.

`MODE=classic` (`JOBS=1`, auto `-t`) is the baseline shape. `stable` is
sequential with `VAL_T=0.5`. `fast` is parallel and flaky; do not save it.

```bash
make classic-parity
CLASSIC_TREE="$(python3 -B scripts/classic-parity.py path --tree release)"

SOCAT="$CLASSIC_TREE/socat" FILAN="$CLASSIC_TREE/filan" \
  PROCAN="$CLASSIC_TREE/procan" SKIP_BUILD=1 LABEL=classic MODE=classic \
  SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
  ./scripts/classic-scorecard.sh

MODE=classic BASELINE=testdata/scorecard/classic-docker-baseline.json \
  LABEL=go REGRESSION_EXIT=0 ./scripts/classic-scorecard.sh
```

`PRIVILEGED=1` is required for `NETNS` / `NETNS_EXEC`. Rebuild the image after
a Dockerfile change (do not use `NO_BUILD=1` that first time).

## Latest committed baselines

Counts come from structured `results.json`. Official classic source pins are
in `scripts/classic-baseline.json`. Docker runs used `MODE=classic
PRIVILEGED=1 TEST_SH_ARGS=--internet` at `3ddf9d4`. Host JSON is older and
was not rerun with that refresh.

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (host) | 475 | 24 | 103 |
| classic 1.8.1.3 (Docker, root) | 565 | 3 | 37 |
| go (this tree, host) | 471 | 7 | 127 |
| go (this tree, Docker, root, privileged, `--internet`) | 541 | 9 | 55 |

Go Docker FAILED: `OPENSSL_COMPRESS`, `OPENSSLLISTENDSA`, `OPENSSL_ANULL`,
`OPENSSL_DTLS_CLIENT`, `OPENSSL_DTLS_SERVER`, `VSOCK_ECHO`, `SHELL_SIGINT`,
`V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND`. Classic Docker
FAILED: `OPENSSL_ANULL`, `OPENSSL_DTLS_CLIENT`, `VSOCK_ECHO`. `IOCTL_VOID`
is CANT (printed FAILED because root). Classic `SYSTEM_SIGINT` is the same
kind of conflict.

Vs classic Docker, Go has 541 OK against 565
classic OK (`parity_gap_total` 24 in `go-vs-classic-docker-gaps.json`).

### Classic OK, Go not (24)

6 FAILED:

| Test | Why |
|------|-----|
| `OPENSSL_COMPRESS` | `compress=` enablement is rejected |
| `OPENSSLLISTENDSA` | DSA keys are rejected |
| `OPENSSL_DTLS_SERVER` | Peer pins DTLS 1.2; this port is 1.3-only |
| `SHELL_SIGINT` | `test.sh` greps C `waitpid` log lines; pass-through is `TestEXECParentSignalPassThrough` |
| `V1800_OPENSSL_LISTEN_RANGE` | TLS listen requires `cert=` |
| `V1800_OPENSSL_LISTEN_BIND` | Same with `bind=` |

18 CANT: `READLINE`, `READLINE_OVFL`; `COOLWRITE`, `COOLSTDIO` (`cool-write`
is deprecated); `UDP_DATAGRAM_PEERPORT` (`test.sh` version-gates on `-V` line
2, which is not a classic version string here — do not bump `Version` to
pass it); UDP-Lite (removed from modern Linux), including duplicate
`UDPLITE4STREAM` ids 521 and 522 and the six `V1800_UDPLITE_*` cases.

Shared Docker FAILED, so not in the gap: `OPENSSL_ANULL`,
`OPENSSL_DTLS_CLIENT`, `VSOCK_ECHO` (both report "Network is unreachable"
to CID 1 on this VM). `SOCAT_MUX` and `ACCEPT_FD` pass on both Docker runs.

### DTLS 1.3

| Test | Docker | Notes |
|------|--------|-------|
| `OPENSSL_DTLS_CLIENT` | FAILED both | Peer uses `-dtls1_2`; also timing-sensitive — re-run 399 alone before treating a flip as a regression |
| `OPENSSL_DTLS_SERVER` | Go FAILED, classic OK | Same 1.2 pin |
| `OPENSSL_DTLS_TO_SERVER`, `OPENSSL_DTLS_TO_CLIENT` | OK | 8192-byte transfers, MTU 1200 |
| `RCVTIMEO_DTLS` | OK | Silent-handshake receive timeout |

See [DTLS validation](../../docs/dtls13.md#validation).

### Operational notes

- Host-only OK that Docker does not get: `GOPEN_TO_DENIED` (not with root).
- Expected host→docker losses include UDP6 multicast routing, VSOCK, root
  denials, `IOCTL_VOID`, timing-sensitive classic DTLS-client, and DCCP when
  the kernel has retired it. `ALLOW_LOST` lists those ids.
- `OPENPTYWAITSLAVE` can `TIMEOUT` in a long sequential Docker run; an
  isolated `ONLY=OPENPTYWAITSLAVE` re-run is OK if the committed baseline is
  OK.
- Do not patch official `test.sh`, fake `waitpid` logs, advertise
  `cool-write`, or allow TLS listen without `cert=`.

## Files

| File | Role |
|------|------|
| `classic-baseline.json` | Classic C on a known host |
| `classic-docker-baseline.json` | Classic C in Docker as root |
| `classic-docker-vs-host.json` | Host OK set vs docker |
| `go-baseline.json` | Go host regression gate |
| `go-docker-baseline.json` | Go Docker/root run |
| `go-vs-classic-docker-gaps.json` | Classic-docker OK that Go did not get |

Refresh classic host JSON when the classic version, host features, or
`test.sh` numbering changes.
