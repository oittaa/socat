# Benchmarks

Optional loopback measures. They are not `make test` and not `make e2e`.

The suite starts real socat processes. It compares this Go binary with classic
C socat found on `PATH`. `SOCAT_CLASSIC_BIN` overrides automatic detection.

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

Set `SOCAT_BENCH_PAYLOAD=/path/to/file` to use your own file. The file must be
at least `SOCAT_BENCH_SIZE` bytes. The runner copies that many bytes.

Working files live under `testdata/tmp/bench/` (gitignored). On Linux, payloads
and sinks use `/dev/shm` when it is writable. The runner keeps at most one raw
payload and its matching UDP-framed variant, removes obsolete cache variants,
and cleans temporary sinks on exit or at the next start after an interrupted
run. It also checks available space before creating large files and fails
early when the selected payload will not fit.

## Run

```bash
# From the repo root
make bench
# or
SOCAT_CLASSIC_BIN=/path/to/classic/socat python3 -B scripts/bench.py

# Subset and smaller size
SOCAT_BENCH_SIZE=64M SOCAT_BENCH_RUNS=3 python3 -B scripts/bench.py tcp tls quic

# Record the committed snapshot
SOCAT_BENCH_SIZE=1G SOCAT_BENCH_RUNS=7 SOCAT_BENCH_WARMUP=2 \
  SOCAT_BENCH_SAVE_BASELINE=testdata/bench/host.json python3 -B scripts/bench.py
```

`make bench` does not run from `make test` or `make e2e`.
The Python runner builds the Go socat and its benchmark helper unless their
respective skip-build variables are enabled.

PowerShell uses the same runner:

```powershell
$env:SOCAT_BENCH_SIZE = "64M"
$env:SOCAT_BENCH_RUNS = "3"
python -B scripts/bench.py tcp udp tls ws wss quic
```

## Cases

### Bulk transfer (socat to socat)

`dd` is not in the timed path. The client is
`socat -u OPEN:payload,rdonly PROTO:...`. The server is
`socat -u PROTO-LISTEN OPEN:sink,creat,trunc,wronly`.
The sink is on tmpfs (`/dev/shm`) when possible so disk writes are not the main
cost. Stream timing ends only after the receiver exits, and cases require the
exact byte count.

Default size is 256 MiB. Default is 1 warmup + 5 timed runs. The report uses
the **median**.

| ID | Listen / connect | Binaries |
|----|------------------|----------|
| `tcp` | TCP4-LISTEN / TCP4 | classic, go |
| `unix` | UNIX-LISTEN / UNIX-CONNECT | classic, go |
| `udp` | UDP4-RECV / UDP4-SENDTO | classic, go |
| `tls` | TLS-LISTEN / TLS (classic: OPENSSL-LISTEN / OPENSSL) | classic, go |
| `ws` | WS-LISTEN / WS | go only |
| `wss` | WSS-LISTEN / WSS | go only |
| `quic` | QUIC-LISTEN / QUIC | go only |

TLS, WSS, and QUIC use the same freshly generated ECDSA P-256 certificate
(SAN `DNS:localhost`, `IP:127.0.0.1`).
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

`udp` is an unreliable datagram transport using standard UDP
(`IPPROTO_UDP`) with `UDP4-RECV` / `UDP4-SENDTO`. Non-fork `UDP-LISTEN` is
one-shot on this port, so it is not used here.

The runner does not pretend that larger socket buffers make datagrams
lossless. It frames the incompressible payload into fixed-size records with a
sequence number, payload length, and CRC32. After the
sender exits, it waits until the sink is quiet, then reports logical-payload
sender and delivered-receiver MiB/s plus loss, duplicates, reordering, and
corruption. Loss and reordering are measurements; malformed or corrupt
frames fail the run. `SOCAT_BENCH_SIZE` is the logical payload size, excluding
frame headers and final-frame padding. There is no connection EOF, so the
receiver is terminated after the quiet interval.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOCAT_BIN` | `./socat` | Go binary |
| `SOCAT_CLASSIC_BIN` | `socat` on PATH | Classic C binary override |
| `SOCAT_BENCH_OPENSSL_BIN` | `openssl` on PATH | Optional classic TLS probe client |
| `SOCAT_BENCH_SIZE` | `256M` | Stream payload (MiB if `M`) |
| `SOCAT_BENCH_RUNS` | `5` | Timed runs |
| `SOCAT_BENCH_WARMUP` | `1` | Untimed runs |
| `SOCAT_BENCH_BUFFER` | `8192` | socat `-b`; datagram cases require 21..65507 |
| `SOCAT_BENCH_PAYLOAD` | AES-CTR blob | Optional file, ≥ `SOCAT_BENCH_SIZE` |
| `SOCAT_BENCH_GIT_COMMIT` | current checkout | Commit recorded when benchmarking an exported source tree |
| `SOCAT_BENCH_SAVE_BASELINE` | empty | Copy JSON + summary here |
| `SOCAT_BENCH_RR_N` / `SOCAT_BENCH_RR_WARMUP` / `SOCAT_BENCH_RR_SIZE` | 20000 / 1000 / 64 | Ping-pong |
| `SOCAT_BENCH_HS_N` / `SOCAT_BENCH_HS_WARMUP` | 200 / 20 | Handshakes |
| `SOCAT_BENCH_SKIP_BUILD` | `0` | Skip `make build` |
| `SOCAT_BENCH_PROBE_ONLY` | `0` | Handshake probe only; merge `meta.tls` into `SOCAT_BENCH_SAVE_BASELINE` |

Both binaries use `-b 8192` and bind `127.0.0.1`.

## Output

Each run writes JSON (`meta` + `cases`) and a text summary. Structured JSON is
the source of truth. The table below must match `testdata/bench/host.json`.
Datagram rows (`udp`) contain separate `send_mib_s` and
`receive_mib_s` distributions and datagram delivery counters rather than the
stream-only `mib_s` field.

`meta` records: time, git, host, kernel, CPU, nproc, Go version, classic
version, OpenSSL version, size, runs, payload kind, payload hash, and
**`meta.tls`**: the negotiated TLS version, cipher, and group for each
pairing the suite uses. The probe is a real handshake against the same
listen command as the timed case. Do not write “may be” for those values.

RSS is the peak `VmRSS` of the socat process tree (50 ms sample). For
`tls-hs` that includes classic child processes.
Platforms without `/proc` report RSS as `n/a` (`null` in JSON).

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

Recorded 2026-08-31 in an Ubuntu 26.04 Hyper-V guest (6 vCPUs) backed by an
AMD Ryzen 7 9800X3D, Linux 7.0.0-30, Go 1.27.0, classic socat 1.8.1.3, and
distro OpenSSL 3.5.5. Payload: 1 GiB AES-128-CTR (incompressible; not
`/dev/zero`). Median of 7 timed runs after 2 warmups, `-b 8192`.

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 1 GiB | 1060.2 MiB/s | 2198.9 MiB/s | 10.5 / 26.1 MiB |
| UNIX 1 GiB | 876.8 MiB/s | 2199.1 MiB/s | 10.2 / 26.1 MiB |
| UDP 1 GiB (send / receive / loss) | 1115.9 / 1115.8 MiB/s / 0.000% | 1180.6 / 1180.6 MiB/s / 0.000% | 10.4 / 29.8 MiB |
| TLS 1 GiB | 808.1 MiB/s | 1252.4 MiB/s | 21.0 / 28.8 MiB |
| WS 1 GiB | n/a | 1113.7 MiB/s | n/a / 27.0 MiB |
| WSS 1 GiB | n/a | 562.5 MiB/s | n/a / 29.5 MiB |
| QUIC 1 GiB | n/a | 362.6 MiB/s | n/a / 40.9 MiB |
| TCP 64 B RTT (median / p99) | 84.4 / 153.8 µs | 51.3 / 363.6 µs | 5.2 / 13.4 MiB |
| TLS 64 B RTT (median / p99) | 91.9 / 174.9 µs | 99.7 / 206.8 µs | 11.0 / 14.6 MiB |
| QUIC 64 B RTT (median / p99) | n/a | 240.3 / 426.4 µs | n/a / 19.0 MiB |
| TLS handshake | 23.5 /s | 1007.7 /s | 24.9 / 18.5 MiB |

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
SOCAT_BENCH_SIZE=1G SOCAT_BENCH_RUNS=7 SOCAT_BENCH_WARMUP=2 \
  SOCAT_BENCH_SAVE_BASELINE=testdata/bench/host.json python3 -B scripts/bench.py
```

Then copy the medians from `testdata/bench/host.summary.txt` into the
**Recorded snapshot** table in this file. Do not guess.
