# Benchmarks

Optional loopback measures. They are not `make test` and not `make e2e`.

The suite starts real socat processes. It compares this Go binary with classic
C socat when `CLASSIC_SOCAT` is set.

Classic TLS uses the **distro OpenSSL** (this host: 3.5.5) and an unpatched
classic 1.8.1.3. That binary pins P-256 via `SSL_CTX_set_tmp_ecdh`. Go
`crypto/tls` defaults to hybrid **X25519MLKEM768**. The probe records both
values. Do not guess.

## Payload (not /dev/zero)

The stream cases do **not** read `/dev/zero`.

A compress option (classic `OPENSSL` compress, or a later flag) would make a
zero stream look much faster than real data. The default payload is a cached
**AES-128-CTR** blob of the requested size (zeros go into the cipher only).
That ciphertext does not compress.

Set `BENCH_PAYLOAD=/path/to/file` to use your own file. The file must be at
least `SIZE` bytes. The runner copies the first `SIZE` bytes.

Working files live under `testdata/tmp/bench/` (gitignored). The payload may
also sit in `/dev/shm` when that directory is writable.

## Run

```bash
# From the repo root
make bench
# or
CLASSIC_SOCAT=/path/to/classic/socat ./scripts/bench.sh

# Subset and smaller size
SIZE=64M RUNS=3 ./scripts/bench.sh tcp tls quic

# Record the committed snapshot
SIZE=1G RUNS=7 WARMUP=2 SAVE_BASELINE=testdata/bench/host.json ./scripts/bench.sh
```

`make bench` does not run from `make test` or `make e2e`.

## Cases

### Bulk stream (socat to socat)

`dd` is not in the timed path. The client is
`socat -u OPEN:payload,rdonly PROTO:...`. The server is
`socat -u PROTO-LISTEN OPEN:sink,creat,trunc,wronly`.
The sink is on tmpfs (`/dev/shm`) when possible so we can check the byte count
without a disk write as the main cost.

Default size is 256 MiB. Default is 1 warmup + 5 timed runs. The report uses
the **median**.

| ID | Listen / connect | Binaries |
|----|------------------|----------|
| `tcp` | TCP4-LISTEN / TCP4 | classic, go |
| `unix` | UNIX-LISTEN / UNIX-CONNECT | classic, go |
| `tls` | TLS-LISTEN / TLS (classic: OPENSSL-LISTEN / OPENSSL) | classic, go |
| `quic` | QUIC-LISTEN / QUIC | go only |

TLS and QUIC use the same RSA-2048 cert (SAN `DNS:localhost`, `IP:127.0.0.1`).
The client sets `verify=1,cafile=,commonname=localhost`. The listener sets
`verify=0` (no client certificate).

### Interactive (socat listen + `scripts/benchclient`)

Socat is the echo front (`PIPE`). `benchclient` is a measure tool. It is not
installed.

| ID | What | Metric |
|----|------|--------|
| `tcp-rr` / `tls-rr` / `quic-rr` | 64-byte ping-pong | µs/RTT (median, p99) |
| `tls-hs` | connect + 1 byte + close | handshakes/s |

`tls-hs` uses `fork` on the listener. Classic `fork` starts a process. Go
`fork` starts a goroutine. The RSS and rate show that difference.

QUIC is a UDP byte tunnel (`alpn=socat`). It is not TLS and not HTTP/3.
Classic socat has no QUIC.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOCAT` | `./socat` | Go binary |
| `CLASSIC_SOCAT` | search common paths | Classic C binary |
| `OPENSSL_BIN` | `openssl` on PATH | Distro OpenSSL (certs, payload, probe) |
| `SIZE` | `256M` | Stream payload (MiB if `M`) |
| `RUNS` | `5` | Timed runs |
| `WARMUP` | `1` | Untimed runs |
| `BUF` | `8192` | socat `-b` |
| `BENCH_PAYLOAD` | AES-CTR blob | Optional file, ≥ `SIZE` |
| `SAVE_BASELINE` | empty | Copy JSON + summary here |
| `RR_N` / `RR_WARMUP` / `RR_SIZE` | 20000 / 1000 / 64 | Ping-pong |
| `HS_N` / `HS_WARMUP` | 200 / 20 | Handshakes |
| `SKIP_BUILD` | `0` | Skip `make build` |
| `PROBE_ONLY` | `0` | Handshake probe only; merge `meta.tls` into `SAVE_BASELINE` |

Both binaries use `-b 8192` and bind `127.0.0.1`.

## Output

Each run writes JSON (`meta` + `cases`) and a text summary. Structured JSON is
the source of truth. The table below must match `testdata/bench/host.json`.

`meta` records: time, git, host, kernel, CPU, nproc, Go version, classic
version, OpenSSL version, size, runs, payload kind, payload hash, and
**`meta.tls`**: the negotiated TLS version, cipher, and group for each
pairing the suite uses. The probe is a real handshake against the same
listen command as the timed case. Do not write “may be” for those values.

RSS is the peak `VmRSS` of the socat process tree (50 ms sample). For
`tls-hs` that includes classic child processes.

## Honesty

- These numbers are one machine. Run the script on your host.
- The saved host is a Hyper-V guest. Absolute loopback latency includes
  virtualization and host-scheduler effects; use the classic/Go pairing for
  relative comparisons rather than comparing raw latency with bare metal.
- Quote `meta.tls` for version, cipher, and group. Go TLS/QUIC uses
  **X25519MLKEM768**. Classic OPENSSL (distro OpenSSL + unpatched 1.8.1.3)
  uses **P-256**. Classic bulk TLS uses **TLS_AES_256_GCM_SHA384**; Go uses
  **TLS_AES_128_GCM_SHA256**.
- `tls-rr` / `tls-hs` (classic) use the Go `benchclient` against classic
  OPENSSL-LISTEN. That pairing is not classic↔classic.
- QUIC is not a drop-in TLS replacement.
- Do not claim a winner unless the JSON shows it.

## Recorded snapshot

Recorded 2026-08-20 in an Ubuntu 26.04 Hyper-V guest (6 vCPUs) backed by an
AMD Ryzen 7 9800X3D, Linux 7.0.0-28, Go 1.26.7, classic socat 1.8.1.3, and
distro OpenSSL 3.5.5. Payload: 1 GiB AES-128-CTR (incompressible; not
`/dev/zero`). Median of 7 timed runs after 1 warmup, `-b 8192`.

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 1 GiB | 878.2 MiB/s | 1988.8 MiB/s | 10.4 / 20.9 MiB |
| UNIX 1 GiB | 777.8 MiB/s | 1989.1 MiB/s | 10.2 / 21.2 MiB |
| TLS 1 GiB | 878.1 MiB/s | 1060.3 MiB/s | 21.1 / 24.8 MiB |
| QUIC 1 GiB | n/a | 579.3 MiB/s | n/a / 36.7 MiB |
| TCP 64 B RTT | 89.5 µs | 68.1 µs | 5.2 / 10.6 MiB |
| TLS 64 B RTT | 94.9 µs | 138.7 µs | 10.9 / 12.3 MiB |
| QUIC 64 B RTT | n/a | 324.8 µs | n/a / 17.2 MiB |
| TLS handshake | 23.6 /s | 661.9 /s | 25.2 / 18.1 MiB |

Recorded handshakes (same binaries as the table; see `meta.tls` in `host.json`):

| Pairing | Used by | Version | Cipher | Group |
|---------|---------|---------|--------|-------|
| Go `crypto/tls` ↔ Go TLS-LISTEN | `tls`, `tls-rr`, `tls-hs` (go) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| Distro OpenSSL 3.5.5 ↔ classic OPENSSL-LISTEN | `tls` (classic) | TLS 1.3 | TLS_AES_256_GCM_SHA384 | P-256 |
| Go `crypto/tls` ↔ classic OPENSSL-LISTEN | `tls-rr`, `tls-hs` (classic) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | P-256 |
| quic-go ↔ Go QUIC-LISTEN | `quic`, `quic-rr` | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |

- Go TLS/QUIC used hybrid post-quantum **X25519MLKEM768**. Classic OPENSSL used
  **P-256** because unpatched 1.8.1.3 explicitly pins that curve.
- Bulk TLS also used different ciphers: classic **AES-256-GCM**, Go **AES-128-GCM**.
- `tls-hs` (classic) is a Go client to a classic listener, so that column is P-256. The Go `tls-hs` column is X25519MLKEM768. The rate gap is also classic `fork(2)` vs Go goroutines.
- QUIC is a UDP byte tunnel (`alpn=socat`). It is not HTTP/3 and not OpenSSL.
- These numbers are one machine. Run the script on your host. JSON: `host.json`.

## Refresh the committed snapshot

```bash
SIZE=1G RUNS=7 WARMUP=2 SAVE_BASELINE=testdata/bench/host.json ./scripts/bench.sh
```

Then copy the medians from `testdata/bench/host.summary.txt` into the
**Recorded snapshot** table in this file. Do not guess.
