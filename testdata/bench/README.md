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

### Bulk transfer (socat to socat)

`dd` is not in the timed path. The client is
`socat -u OPEN:payload,rdonly PROTO:...`. The server is
`socat -u PROTO-LISTEN OPEN:sink,creat,trunc,wronly`.
The sink is on tmpfs (`/dev/shm`) when possible so disk writes are not the main
cost. Stream cases require the exact byte count.

Default size is 256 MiB. Default is 1 warmup + 5 timed runs. The report uses
the **median**.

| ID | Listen / connect | Binaries |
|----|------------------|----------|
| `tcp` | TCP4-LISTEN / TCP4 | classic, go |
| `unix` | UNIX-LISTEN / UNIX-CONNECT | classic, go |
| `udp` | UDP4-RECV / UDP4-SENDTO | classic, go |
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

`udp` is an unreliable datagram transport using standard UDP
(`IPPROTO_UDP`) with `UDP4-RECV` / `UDP4-SENDTO`. Non-fork `UDP-LISTEN` is
one-shot on this port, so it is not used here.

The runner does not pretend that larger socket buffers make datagrams
lossless. It frames the incompressible payload into fixed `BUF`-byte
datagrams with a sequence number, payload length, and CRC32. After the
sender exits, it waits until the sink is quiet, then reports logical-payload
sender and delivered-receiver MiB/s plus loss, duplicates, reordering, and
corruption. Loss and reordering are measurements; malformed or corrupt
frames fail the run. `SIZE` is the logical payload size, excluding frame
headers and final-frame padding. There is no connection EOF, so the
receiver is terminated after the quiet interval.

## Environment

| Variable | Default | Meaning |
|----------|---------|---------|
| `SOCAT` | `./socat` | Go binary |
| `CLASSIC_SOCAT` | search common paths | Classic C binary |
| `OPENSSL_BIN` | `openssl` on PATH | Distro OpenSSL (certs, payload, probe) |
| `SIZE` | `256M` | Stream payload (MiB if `M`) |
| `RUNS` | `5` | Timed runs |
| `WARMUP` | `1` | Untimed runs |
| `BUF` | `8192` | socat `-b`; datagram cases require 21..65507 |
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

Recorded 2026-08-30 in an Ubuntu 26.04 Hyper-V guest (6 vCPUs) backed by an
AMD Ryzen 7 9800X3D, Linux 7.0.0-30, Go 1.27.0, classic socat 1.8.1.3, and
distro OpenSSL 3.5.5. Payload: 1 GiB AES-128-CTR (incompressible; not
`/dev/zero`). Median of 7 timed runs after 2 warmups, `-b 8192`.

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 1 GiB | 833.8 MiB/s | 1660.4 MiB/s | 10.4 / 26.0 MiB |
| UNIX 1 GiB | 545.6 MiB/s | 1537.3 MiB/s | 10.2 / 26.1 MiB |
| UDP 1 GiB (send / receive / loss) | 621.2 / 514.1 MiB/s / 18.462% | 593.1 / 542.2 MiB/s / 7.412% | 10.4 / 30.6 MiB |
| TLS 1 GiB | 629.2 MiB/s | 715.6 MiB/s | 21.1 / 28.7 MiB |
| QUIC 1 GiB | n/a | 171.4 MiB/s | n/a / 40.7 MiB |
| TCP 64 B RTT (median / p99) | 21.8 / 64.6 µs | 23.5 / 3469.2 µs | 5.2 / 13.4 MiB |
| TLS 64 B RTT (median / p99) | 23.2 / 75.2 µs | 24.3 / 76.0 µs | 11.0 / 14.4 MiB |
| QUIC 64 B RTT (median / p99) | n/a | 62.5 / 883.6 µs | n/a / 18.8 MiB |
| TLS handshake | 22.2 /s | 512.7 /s | 25.1 / 19.0 MiB |

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
