# Benchmarks

Optional loopback measures. They are not `make test` and not `make e2e`.

The suite starts real socat processes. It compares this Go binary with classic
C socat when `CLASSIC_SOCAT` is set.

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
./scripts/bench.sh

# Need classic columns
CLASSIC_SOCAT=/path/to/classic/socat ./scripts/bench.sh

# Subset and smaller size
SIZE=64M RUNS=3 ./scripts/bench.sh tcp tls quic

# Record the committed snapshot
SAVE_BASELINE=testdata/bench/host.json ./scripts/bench.sh
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
| `tls` | OPENSSL-LISTEN / OPENSSL | classic, go |
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
| `SIZE` | `256M` | Stream payload (MiB if `M`) |
| `RUNS` | `5` | Timed runs |
| `WARMUP` | `1` | Untimed runs |
| `BUF` | `8192` | socat `-b` |
| `BENCH_PAYLOAD` | AES-CTR blob | Optional file, ≥ `SIZE` |
| `SAVE_BASELINE` | empty | Copy JSON + summary here |
| `RR_N` / `RR_WARMUP` / `RR_SIZE` | 20000 / 1000 / 64 | Ping-pong |
| `HS_N` / `HS_WARMUP` | 200 / 20 | Handshakes |
| `SKIP_BUILD` | `0` | Skip `make build` |

Both binaries use `-b 8192` and bind `127.0.0.1`.

## Output

Each run writes JSON (`meta` + `cases`) and a text summary. Structured JSON is
the source of truth. The root README table must match `testdata/bench/host.json`.

`meta` records: time, git, host, kernel, CPU, nproc, Go version, classic
version, OpenSSL version, size, runs, payload kind, payload hash.

RSS is the peak `VmRSS` of the socat process tree (50 ms sample). For
`tls-hs` that includes classic child processes.

## Honesty

- These numbers are one machine. Run the script on your host.
- Go TLS uses `crypto/tls` (the default KEX may be hybrid X25519MLKEM768).
  Classic uses OpenSSL.
- QUIC is not a drop-in OPENSSL replacement.
- Do not claim a winner unless the JSON shows it.

## Refresh the committed snapshot

```bash
CLASSIC_SOCAT=/path/to/classic/socat \
  SAVE_BASELINE=testdata/bench/host.json \
  ./scripts/bench.sh
```

Then copy the medians from `testdata/bench/host.summary.txt` into the root
README table. Do not guess.
