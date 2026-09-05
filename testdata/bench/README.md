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
zero stream look much faster than real data. The default payload is a fresh
**AES-128-CTR** blob of the requested size (zeros go into the cipher only).
That ciphertext does not compress. It is generated at the start of each run.

Set `SOCAT_BENCH_PAYLOAD=/path/to/file` to use your own file. The file must be
at least `SOCAT_BENCH_SIZE` bytes. The runner copies that many bytes.

Payloads, framed UDP/DTLS, sinks, logs, certs, and `benchclient` live in a
`tempfile.TemporaryDirectory` named `run-*` inside a locked per-user root.
On Linux that root is `/dev/shm/socat-bench-<uid>` when `/dev/shm` is
writable and allows executing binaries; otherwise it is
`$SOCAT_BENCH_WORKDIR/storage`. The runner holds
the lock for the whole run so concurrent jobs cannot both pass the free-space
check, removes leftover `run-*` directories after taking the lock (SIGKILL
survivors), and deletes the current run directory on exit, including Ctrl+C.
JSON and summary are written only at the end, first into the run directory
and then to `SOCAT_BENCH_OUT` (default `testdata/tmp/bench/`, gitignored) and
`SOCAT_BENCH_SAVE_BASELINE` (the committed snapshot). The runner checks free
space before creating large files and fails early when the selected payload
will not fit.

## Run

```bash
# From the repo root
make bench
# or
SOCAT_CLASSIC_BIN=/path/to/classic/socat python3 -B scripts/bench.py

# Subset and smaller size
SOCAT_BENCH_SIZE=64M SOCAT_BENCH_RUNS=3 python3 -B scripts/bench.py tcp tls quic dtls

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
python -B scripts/bench.py tcp udp tls ws wss quic dtls
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
| `dtls` | DTLS-LISTEN / DTLS | go only |

TLS, WSS, QUIC, and DTLS use the same freshly generated ECDSA P-256 certificate
(SAN `DNS:localhost`, `IP:127.0.0.1`).
The client sets `verify=1,cafile=,commonname=localhost`. The listener sets
`verify=0` (no client certificate).

### Interactive (socat listen + `scripts/benchclient`)

Socat is the echo front (`PIPE`). `benchclient` is a measure tool. It is not
installed.

| ID | What | Metric |
|----|------|--------|
| `tcp-rr` / `tls-rr` / `quic-rr` / `dtls-rr` | 64-byte ping-pong | µs/RTT (median, p99) |
| `tls-hs` / `dtls-hs` | connect + 1 byte + close | handshakes/s |

`tls-hs` and `dtls-hs` use `fork` on the listener. Classic `fork` starts a
process. Go `fork` starts a goroutine. The RSS and rate show that difference.

QUIC is a UDP byte tunnel (`alpn=socat`). It is not TLS and not HTTP/3.
Classic socat has no QUIC.

DTLS is DTLS 1.3 only. It is go-only; the classic baseline's `OPENSSL-DTLS`
supports DTLS 1.2 and does not interoperate. The bulk case uses 1024-byte
application datagrams, including a 20-byte benchmark header, so each fits
one DTLS record at the default 1200-byte MTU. `SOCAT_BENCH_BUFFER` can reduce
this frame size, but cannot increase it. Every handshake includes a cookie
retry, so `dtls-hs` counts that extra round trip.

`udp` is an unreliable datagram transport using standard UDP
(`IPPROTO_UDP`) with `UDP4-RECV` / `UDP4-SENDTO`. Non-fork `UDP-LISTEN` is
one-shot on this port, so it is not used here.

Both `udp` and `dtls` measure unreliable datagram delivery. The runner
frames the incompressible payload into fixed-size records with a
sequence number, payload length, and CRC32. After the
sender exits, it waits until the sink is quiet, then reports logical-payload
sender and delivered-receiver MiB/s plus loss, duplicates, reordering, and
corruption. Loss and reordering are measurements; malformed or corrupt
frames fail the run. `SOCAT_BENCH_SIZE` is the logical payload size, excluding
frame headers and final-frame padding. Rates include client startup and,
for DTLS, the handshake and connection close. They exclude payload generation,
frame validation, and the final quiet interval. Any receiver still running
after that interval is terminated. This is an unpaced loopback workload;
it measures delivered goodput and loss, not a maximum lossless send rate.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOCAT_BIN` | `./socat` | Go binary |
| `SOCAT_CLASSIC_BIN` | `socat` on PATH | Classic C binary override |
| `SOCAT_BENCH_CLIENT_BIN` | run directory `benchclient` | Benchmark helper binary override |
| `SOCAT_BENCH_OPENSSL_BIN` | `openssl` on PATH | Optional classic TLS probe client |
| `SOCAT_BENCH_WORKDIR` | `testdata/tmp/bench` | Default JSON/summary copy destination; fallback storage root |
| `SOCAT_BENCH_OUT` | `$SOCAT_BENCH_WORKDIR/results.json` | JSON written at the end of a successful run |
| `SOCAT_BENCH_SIZE` | `256M` | Logical payload (MiB if `M`) |
| `SOCAT_BENCH_RUNS` | `5` | Timed runs |
| `SOCAT_BENCH_WARMUP` | `1` | Untimed runs |
| `SOCAT_BENCH_BUFFER` | `8192` | socat `-b`; UDP frames require 21..65507; DTLS bulk caps this at 1024 |
| `SOCAT_BENCH_PAYLOAD` | AES-CTR blob | Optional file, ≥ `SOCAT_BENCH_SIZE` |
| `SOCAT_BENCH_GIT_COMMIT` | current checkout | Commit recorded when benchmarking an exported source tree |
| `SOCAT_BENCH_SAVE_BASELINE` | empty | Copy JSON + summary here |
| `SOCAT_BENCH_RR_N` / `SOCAT_BENCH_RR_WARMUP` / `SOCAT_BENCH_RR_SIZE` | 20000 / 1000 / 64 | Ping-pong |
| `SOCAT_BENCH_HS_N` / `SOCAT_BENCH_HS_WARMUP` | 200 / 20 | Handshakes |
| `SOCAT_BENCH_SKIP_BUILD` | `0` | Reuse `SOCAT_BIN` instead of running `go build` |
| `SOCAT_BENCH_SKIP_CLIENT_BUILD` | `0` | Reuse `SOCAT_BENCH_CLIENT_BIN` instead of running `go build` |
| `SOCAT_BENCH_PROBE_ONLY` | `0` | Handshake probe only; merge `meta.tls` into `SOCAT_BENCH_SAVE_BASELINE` |

Both binaries bind `127.0.0.1`. The default is `-b 8192`, except DTLS bulk
uses `-b 1024` on both ends to preserve benchmark frame boundaries.

## Output

Each run writes JSON (`meta` + `cases`) and a text summary at the end.
Structured JSON is the source of truth. The table below must match
`testdata/bench/host.json`.
Datagram rows (`udp`, `dtls`) record `frame_bytes`, separate `send_mib_s` and
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
- Quote `meta.tls` for version, cipher, and group. Go TLS/QUIC/DTLS uses
  **X25519MLKEM768**. Classic OPENSSL (distro OpenSSL + unpatched 1.8.1.3)
  uses **P-256**. Classic bulk TLS uses **TLS_AES_256_GCM_SHA384**; Go uses
  **TLS_AES_128_GCM_SHA256**. The DTLS probe key is `go_client_go_dtls`.
  The probe reports the DTLS 1.3 wire version as **DTLS 1.3**, not TLS 1.3.
- `tls-rr` / `tls-hs` (classic) use the Go `benchclient` against classic
  OPENSSL-LISTEN. That pairing is not classic↔classic.
- QUIC is not a drop-in TLS replacement.
- DTLS is not a drop-in TLS or UDP replacement. It is DTLS 1.3 only and is
  not classic OPENSSL-DTLS. It does not retransmit application data, so
  always quote bulk goodput alongside loss and frame size. UDP and DTLS
  use different default frame sizes; their bulk rates are not a measurement
  of encryption overhead alone. A 1 MiB DTLS run is handshake-skewed;
  do not quote it as sustained throughput.
- Do not claim a winner unless the JSON shows it.

## Recorded snapshot

Recorded 2026-09-05 at `d3e81b5` in an Ubuntu 26.04 Hyper-V guest (6 vCPUs)
backed by an AMD Ryzen 7 9800X3D, Linux 7.0.0-30, Go 1.27.0, classic socat
1.8.1.3, and distro OpenSSL 3.5.5. Payload: 1 GiB AES-128-CTR
(incompressible; not `/dev/zero`). Median of 7 timed runs after 2 warmups.
Bulk uses `-b 8192`, except DTLS uses `-b 1024` at the default 1200-byte MTU.
RTT samples use 20,000 exchanges after 1,000 warmups; handshake samples use
200 connections after 20 warmups.

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 1 GiB | 917.5 MiB/s | 2202.7 MiB/s | 10.4 / 27.5 MiB |
| UNIX 1 GiB | 878.2 MiB/s | 2202.9 MiB/s | 10.2 / 27.5 MiB |
| UDP 1 GiB (send / receive / loss) | 1118.3 / 1118.3 MiB/s / 0.000% | 1255.4 / 1255.3 MiB/s / 0.000% | 10.4 / 31.5 MiB |
| TLS 1 GiB | 917.4 MiB/s | 1337.3 MiB/s | 21.0 / 29.6 MiB |
| WS 1 GiB | n/a | 344.9 MiB/s | n/a / 28.5 MiB |
| WSS 1 GiB | n/a | 339.1 MiB/s | n/a / 30.6 MiB |
| QUIC 1 GiB | n/a | 494.8 MiB/s | n/a / 42.2 MiB |
| DTLS 1 GiB (send / receive / loss) | n/a | 30.7 / 30.7 MiB/s / 0.000187% | n/a / 39.7 MiB |
| TCP 64 B RTT (median / p99) | 90.3 / 151.3 µs | 140.5 / 222.2 µs | 5.2 / 16.4 MiB |
| TLS 64 B RTT (median / p99) | 98.2 / 169.8 µs | 146.1 / 211.9 µs | 10.9 / 15.2 MiB |
| QUIC 64 B RTT (median / p99) | n/a | 334.3 / 469.3 µs | n/a / 19.9 MiB |
| DTLS 64 B RTT (median / p99) | n/a | 288.2 / 423.4 µs | n/a / 19.4 MiB |
| TLS handshake | 23.8 /s | 958.8 /s | 25.6 / 19.0 MiB |
| DTLS handshake | n/a | 588.8 /s | n/a / 19.3 MiB |

DTLS delivered 30.7 MiB/s median goodput (range
29.99–31.19 MiB/s), excluding the 20-byte frame headers and padding.
Each sample sent 1,069,464 application datagrams of 1024 bytes.
Median loss was 0.000187% (two datagrams); the worst sample lost
0.015615% (167 datagrams). There were no duplicates, reordered frames,
or corrupt frames across the seven samples. The text summary rounds loss to
three decimal places; the JSON retains full precision.

All 21 runnable case/implementation pairs passed all seven timed runs;
seven unsupported classic pairs were skipped. The full benchmark exited
successfully. The DTLS handshake rate includes cookie retry, a one-byte echo,
and connection close. These are measured loopback rates at the stated frame
sizes, not a maximum lossless capacity.

Recorded handshakes (same binaries as the table; see `meta.tls` in `host.json`):

| Pairing | Used by | Version | Cipher | Group |
|---------|---------|---------|--------|-------|
| Go `crypto/tls` → Go TLS-LISTEN | `tls`, `tls-rr`, `tls-hs` (go) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| Distro OpenSSL 3.5.5 → classic OPENSSL-LISTEN | `tls` (classic) | TLS 1.3 | TLS_AES_256_GCM_SHA384 | P-256 |
| Go `crypto/tls` → classic OPENSSL-LISTEN | `tls-rr`, `tls-hs` (classic) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | P-256 |
| quic-go → Go QUIC-LISTEN | `quic`, `quic-rr` | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| Go dtls13 → Go DTLS-LISTEN | `dtls`, `dtls-rr`, `dtls-hs` | DTLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |

- Go TLS/QUIC/DTLS used hybrid post-quantum **X25519MLKEM768**. Classic
  OPENSSL used **P-256** because unpatched 1.8.1.3 explicitly pins that curve.
- Bulk TLS used different ciphers: classic **AES-256-GCM**, Go **AES-128-GCM**.
- `tls-hs` (classic) uses a Go client and P-256. Its rate also includes
  classic process creation; Go listeners use goroutines.
- QUIC is a UDP byte tunnel (`alpn=socat`), not HTTP/3. DTLS preserves UDP's
  unreliable delivery semantics.
- These numbers are one machine. Run the script on your host. JSON: `host.json`.

## Refresh the committed snapshot

```bash
SOCAT_BENCH_SIZE=1G SOCAT_BENCH_RUNS=7 SOCAT_BENCH_WARMUP=2 \
  SOCAT_BENCH_SAVE_BASELINE=testdata/bench/host.json python3 -B scripts/bench.py
```

Then copy the medians from `testdata/bench/host.summary.txt` into the
**Recorded snapshot** table in this file. Do not guess.
