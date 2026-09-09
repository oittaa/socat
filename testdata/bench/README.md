# Benchmarks

Optional loopback measures. Not `make test` and not `make e2e`.

The suite starts real socat processes and compares this Go binary with
classic C socat on `PATH` (`SOCAT_CLASSIC_BIN` overrides detection).
Numbers are one Hyper-V guest; `host.json` is the source of truth.

Classic OPENSSL pins P-256. Go `crypto/tls` / DTLS defaults to
**X25519MLKEM768**. Quote `meta.tls` rather than guessing. Classic DTLS is
1.2; Go is 1.3. Those versions do not interoperate. Neither DTLS stack
retransmits application data — quote goodput with loss and frame size.
UDP and DTLS use different frame sizes, so their rates are not encryption
overhead. A 1 MiB DTLS run is handshake-skewed.

## Run

```bash
make bench
# or
SOCAT_CLASSIC_BIN=/path/to/classic/socat python3 -B scripts/bench.py

SOCAT_BENCH_SIZE=64M SOCAT_BENCH_RUNS=3 python3 -B scripts/bench.py tcp tls quic dtls

SOCAT_BENCH_DTLS_CLIENT_BIN="$PWD/testdata/tmp/openssl-dtls-client" \
GOMAXPROCS=6 GOGC=100 \
SOCAT_BENCH_SIZE=1G SOCAT_BENCH_RUNS=7 SOCAT_BENCH_WARMUP=2 \
  SOCAT_BENCH_SAVE_BASELINE=testdata/bench/host.json python3 -B scripts/bench.py
```

The Python runner builds `./socat` and `benchclient` unless the skip-build
variables are set. Payload is a fresh AES-128-CTR blob (not `/dev/zero`).
Work files live in a locked per-user temp root (`/dev/shm/socat-bench-<uid>`
on Linux when that is usable).

Classic DTLS RTT/handshake cases need the optional OpenSSL helper:

```bash
mkdir -p testdata/tmp
cc -O3 -Wall -Wextra -Werror scripts/testdata/openssl-dtls-client.c \
  -lssl -lcrypto -o testdata/tmp/openssl-dtls-client
export SOCAT_BENCH_DTLS_CLIENT_BIN="$PWD/testdata/tmp/openssl-dtls-client"
```

Without it, classic DTLS bulk still runs.

## Cases

Bulk client is `socat -u OPEN:payload,rdonly PROTO:...`; server is
`socat -u PROTO-LISTEN OPEN:sink,creat,trunc,wronly`. Default 256 MiB, 1
warmup + 5 timed runs, **median**. Sink prefers tmpfs. Stream cases require
the exact byte count.

| ID | Listen / connect | Binaries |
|----|------------------|----------|
| `tcp` | TCP4-LISTEN / TCP4 | classic, go |
| `unix` | UNIX-LISTEN / UNIX-CONNECT | classic, go |
| `udp` | UDP4-RECV / UDP4-SENDTO | classic, go |
| `tls` | TLS-LISTEN / TLS (classic: OPENSSL-LISTEN / OPENSSL) | classic, go |
| `ws` | WS-LISTEN / WS | go only |
| `wss` | WSS-LISTEN / WSS | go only |
| `quic` | QUIC-LISTEN / QUIC | go only |
| `dtls` | DTLS-LISTEN / DTLS | classic (1.2), go (1.3) |

TLS/WSS/QUIC/DTLS share one generated ECDSA P-256 cert. Client:
`verify=1,cafile=,commonname=localhost`. Listener: `verify=0`.

| ID | What | Metric |
|----|------|--------|
| `tcp-rr` / `tls-rr` / `quic-rr` / `dtls-rr` | 64-byte ping-pong via `benchclient` | µs/RTT |
| `tls-hs` / `dtls-hs` | connect + 1 byte + close | handshakes/s |

Classic `fork` is a process; Go `fork` is a goroutine. QUIC is a UDP byte
tunnel (`alpn=socat`), not HTTP/3. DTLS bulk uses 1024-byte application
datagrams (20-byte header) so each fits Go's default 1200-byte MTU. Go
`dtls-hs` includes the cookie retry. `udp`/`dtls` report send and receive
MiB/s plus loss; corrupt frames fail the run.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOCAT_BIN` | `./socat` | Go binary |
| `SOCAT_CLASSIC_BIN` | `socat` on PATH | Classic binary |
| `SOCAT_BENCH_CLIENT_BIN` | run directory `benchclient` | Helper binary |
| `SOCAT_BENCH_DTLS_CLIENT_BIN` | empty | Classic DTLS RTT/handshake helper |
| `SOCAT_BENCH_OPENSSL_BIN` | `openssl` on PATH | Classic TLS probe |
| `SOCAT_BENCH_WORKDIR` | `testdata/tmp/bench` | Default copy destination |
| `SOCAT_BENCH_OUT` | `$SOCAT_BENCH_WORKDIR/results.json` | JSON at end of a successful run |
| `SOCAT_BENCH_SIZE` | `256M` | Logical payload |
| `SOCAT_BENCH_RUNS` / `SOCAT_BENCH_WARMUP` | `5` / `1` | Timed / untimed runs |
| `SOCAT_BENCH_BUFFER` | `8192` | socat `-b`; DTLS bulk caps at 1024 |
| `SOCAT_BENCH_PAYLOAD` | AES-CTR blob | Optional file, ≥ size |
| `SOCAT_BENCH_SAVE_BASELINE` | empty | Copy JSON + summary here |
| `SOCAT_BENCH_RR_N` / `WARMUP` / `SIZE` | 20000 / 1000 / 64 | Ping-pong |
| `SOCAT_BENCH_HS_N` / `WARMUP` | 200 / 20 | Handshakes |
| `SOCAT_BENCH_SKIP_BUILD` / `SKIP_CLIENT_BUILD` | `0` | Reuse binaries |
| `SOCAT_BENCH_PROBE_ONLY` | `0` | Handshake probe only |

Both binaries bind `127.0.0.1`. RSS is peak `VmRSS` (50 ms sample); `n/a`
without `/proc`. Classic `tls-rr` / `tls-hs` use Go `benchclient` against
OPENSSL-LISTEN.

## Recorded snapshot

From `testdata/bench/host.json` (`3ddf9d4`, Go 1.27.1, classic 1.8.1.3,
OpenSSL 3.5.5, Linux 7.0.0-31 Hyper-V guest, 6 vCPUs, 1 GiB AES-128-CTR,
median of 7 timed runs after 2 warmups). Copy new medians from
`host.summary.txt` when refreshing.

**DTLS: classic 1.2; Go 1.3.**

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 1 GiB | 917.6 MiB/s | 2203.3 MiB/s | 10.6 / 26.4 MiB |
| UNIX 1 GiB | 808.7 MiB/s | 2203.1 MiB/s | 10.4 / 26.4 MiB |
| UDP 1 GiB (send / receive / loss) | 1118.4 / 1118.4 MiB/s / 0.000% | 1183.0 / 1183.0 MiB/s / 0.000% | 10.5 / 30.5 MiB |
| TLS 1 GiB | 917.5 MiB/s | 1335.7 MiB/s | 21.0 / 28.8 MiB |
| WS 1 GiB | n/a | 328.3 MiB/s | n/a / 27.5 MiB |
| WSS 1 GiB | n/a | 318.0 MiB/s | n/a / 29.7 MiB |
| QUIC 1 GiB | n/a | 562.9 MiB/s | n/a / 40.0 MiB |
| DTLS 1 GiB (send / receive / loss) | 137.0 / 137.0 MiB/s / 0.001216% | 40.9 / 40.9 MiB/s / 0.001029% | 21.1 / 38.4 MiB |
| TCP 64 B RTT (median / p99) | 88.8 / 178.3 us | 138.2 / 218.1 us | 5.2 / 15.9 MiB |
| TLS 64 B RTT (median / p99) | 94.9 / 161.4 us | 143.9 / 224.8 us | 11.0 / 14.8 MiB |
| QUIC 64 B RTT (median / p99) | n/a | 331.0 / 446.8 us | n/a / 19.4 MiB |
| DTLS 64 B RTT (median / p99) | 85.7 / 170.6 us | 254.8 / 362.2 us | 10.9 / 19.0 MiB |
| TLS handshake | 23.7 /s | 959.0 /s | 24.9 / 18.9 MiB |
| DTLS handshake | 679.9 /s | 647.9 /s | 24.4 / 18.8 MiB |

DTLS: 1,069,464 × 1024-byte datagrams; unpaced loopback, not a lossless
capacity. Library send-path notes: [dtls13-send-perf.md](dtls13-send-perf.md).

| Pairing | Used by | Version | Cipher | Group |
|---------|---------|---------|--------|-------|
| Go crypto/tls → Go TLS-LISTEN | tls, tls-rr, tls-hs (go) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| OpenSSL → classic OPENSSL-LISTEN | tls (classic) | TLSv1.3 | TLS_AES_256_GCM_SHA384 | P-256 |
| Go crypto/tls → classic OPENSSL-LISTEN | tls-rr, tls-hs (classic) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | P-256 |
| quic-go → Go QUIC-LISTEN | quic, quic-rr | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| Go dtls13 → Go DTLS-LISTEN | dtls, dtls-rr, dtls-hs (go) | DTLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| OpenSSL → classic DTLS-LISTEN | dtls, dtls-rr, dtls-hs (classic) | DTLS 1.2 | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | P-256 |
