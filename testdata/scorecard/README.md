# Scorecard baselines

Classic `test.sh` results. Working logs go under gitignored `.scorecard/`.

These are saved snapshots, not measurements of the current checkout.
In the table, "this tree" means the `meta.source_revision` recorded in
`go-docker-baseline.json`. The binary version and run date are recorded in
`meta.socat_version` and `meta.timestamp`, and in the summary files.

Counts from `classic-docker-baseline.summary.txt` and
`go-docker-baseline.summary.txt`:

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (Docker, root) | 565 | 3 | 37 |
| go (this tree, Docker, root, privileged, `--internet`) | 541 | 9 | 55 |

Vs classic Docker, Go has 541 OK against 565
classic OK (`parity_gap_total` 24 in `go-vs-classic-docker-gaps.json`).

Names and per-test status are in those JSON files.

## Recorded failure explanations

The gap report includes only tests that passed for classic. Its six
`FAILED` entries have the following previously triaged explanations:

| Test | Explanation |
|------|-------------|
| `OPENSSL_COMPRESS` | Requests `compress=auto`; TLS compression is intentionally rejected. |
| `OPENSSLLISTENDSA` | Uses a DSA certificate, which is intentionally unsupported. |
| `OPENSSL_DTLS_SERVER` | Its OpenSSL peer explicitly uses DTLS 1.2; this implementation supports only DTLS 1.3. |
| `SHELL_SIGINT` | Expects a particular `waitpid` warning in the log. Signal forwarding has a separate behavioral test. |
| `V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND` | Start a TLS listener without `cert=`. Classic warns and binds; this implementation fails immediately. These failures do not establish defects in `range=` or `bind=`. |

The protocol and certificate choices are documented in the main README's
[intentional differences](../../README.md#intentional-differences-from-classic-socat)
and [unsupported features](../../README.md#unsupported--security-related).
`TestEXECParentSignalPassThrough` in
[`e2e/exec_signal_unix_test.go`](../../e2e/exec_signal_unix_test.go)
checks signal delivery rather than that log message.

The other three Go `FAILED` results (`OPENSSL_ANULL`, `OPENSSL_DTLS_CLIENT`,
and `VSOCK_ECHO`) also failed for classic in these snapshots, so they are
not part of the gap. The remaining gap entries are `CANT`, meaning the
test could not run; that status alone does not establish a runtime defect.

## Refresh

On a Linux Docker host:

```bash
make update-scorecard
```

That runs classic C and this tree as root (`MODE=classic`, `PRIVILEGED=1`,
`--internet`) and copies complete results here. It does not commit.

Official classic source pins: `scripts/classic-baseline.json`.

## Files

| File | Role |
|------|------|
| `classic-docker-baseline.json` | Classic C in Docker as root |
| `go-docker-baseline.json` | Go Docker/root run |
| `go-vs-classic-docker-gaps.json` | Classic-docker OK that Go did not get |
| `classic-docker-vs-host.json` | Host OK set vs docker |
| `classic-baseline.json` | Classic C host run |
| `go-baseline.json` | Go host run |
