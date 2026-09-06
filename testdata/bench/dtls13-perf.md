# DTLS 1.3 library performance

PR #244 review compares its original `c1d05da` with `8646740` on the same
Linux lab VM. These measure library connections, not the socat CLI or the
file-transfer benchmark in PR #243.

## Method

- Ubuntu 26.04, Linux 7.0.0-30, six vCPUs on Ryzen 7 9800X3D; Go 1.27.0,
  GCC 15.2.0. Loopback IPv4, OS socket-buffer defaults, one association.
- Every peer permits only DTLS 1.3, AES-128-GCM and X25519. Server certificate
  and hostname are verified. CID is disabled for this common comparison;
  production CID/PQ defaults are unchanged. MTU 1200, 1024-byte records.
- Five samples, rotating library order. Handshake and 1000 warmup round trips
  are excluded. Timing and profiling run separately, without parallel jobs.
- Echo: 50,000 sequential requests and replies; RTT is the sample's mean.
  One-way: 1,048,576 numbered records (1 GiB), concurrent receiver, payload
  validation, duplicate/reorder/loss accounting and 250 ms final drain.
  Delivered MiB/s excludes lost data and the final quiet interval.
- Go allocation counts cover both endpoints in one process. An echo operation
  carries two records; a one-way operation is one offered record. C helpers use
  two connected UDP sockets and a receiver thread; Go uses each library's
  public connection/listener API. This is not a pure cipher speed comparison.

## Findings

The original PR borrowed `Write` input after a deadline could return it to the
caller. The fix restores an owned copy. A synchronized regression blocks the
encoder, expires the write, mutates the input and checks what gets encrypted.
It fails when the copy is removed.

Other changes reuse nonce/mask/header scratch space, transfer independently
allocated decrypted plaintext to the read queue, retain queue storage and
avoid repeated wakeups while readable. The queue charges backing capacity,
including padding. Native UDP uses AddrPort APIs; wrapped transports retain
their existing interface. Crypto buffers remain confined to the session owner.

The old `BenchmarkConnPingPong` was one-way. It is now named
`BenchmarkConnSerialOneWay`, with an actual echo benchmark added. Both source
versions below use the corrected fixture.

| Library / revision | Delivered MiB/s, median (range) | Loss %, median / maximum | RTT us, median |
|---|---:|---:|---:|
| socat original `c1d05da` | 67.60 (67.06-68.21) | 0.000286 / 0.013161 | 82.74 |
| socat improved `8646740` | 69.72 (69.51-70.38) | 0 / 0.017357 | 79.55 |
| Pion `59f4c33` | 68.54 (67.46-69.89) | 0.046730 / 0.068569 | 82.34 |
| wolfSSL `d72f6d9` | 121.86 (114.17-126.98) | 0 / 0.057507 | 79.60 |
| OpenSSL `82733d9` | Failed all five long transfers | N/A | 85.00 |

All completed transfers had zero duplicates, reordered records or corrupt
payloads. Zero median loss does not mean lossless: both socat versions and
wolfSSL lost packets in some samples. These five local samples do not establish
a general throughput ranking across machines or networks.

Delivered throughput improved 3.1% and mean-RTT median fell 3.9%. The isolated
record benchmarks improved about 7-9%, with encode allocations 3 -> 1 and
decode 4 -> 1. The default-config one-way microbenchmark went from 26 to 16
allocations per operation, but only 5755 -> roughly 5512 B/op because the
correctness fix restores the caller-input copy. The common-comparison Pion
helper used roughly 67 allocations and 13215 B per offered record.

The final CPU profile remains dominated by syscall entry (36.2%), futex (10.3%)
and select (4.3%, flat). AES-GCM encrypt/decrypt together account for about 1.2%
flat. Pion also spends most of its leading samples in syscalls and scheduling;
its allocation profile additionally shows record builders, packet copies and
per-record AES setup. Allocation-space percentages are not CPU percentages.

Both C references allocate dynamically: see wolfSSL's
[GrowAnOutputBuffer](https://github.com/wolfSSL/wolfssl/blob/d72f6d9e4e85ffcadfa0c737959dc26b8717947a/src/internal.c#L12494)
and OpenSSL's
[record metadata allocation](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/methods/dtls_meth.c#L318).
Reusable buffers and fewer transport handoffs are useful patterns; C does not
imply zero allocation. Our next measured targets should be transport handoffs
and queue-wait timer creation. Reusing packet/command buffers requires proving
ownership through cancellation before a pool can safely reclaim them.

OpenSSL fails at timed record index 64534 after the warmup, in
[dtls_prepare_record_header](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/methods/dtls_meth.c#L906).
It passes the full sequence to a two-byte WPACKET writer, which rejects values
above 65535 instead of truncating the wire sequence. The same code was present
in inspected master `1935d215` on 2026-09-06. The benchmark leaves the reference
unpatched, preserves failures, and publishes only its completed echo results.
The comparison runner finishes the other cases and then exits nonzero when
any reference fails.

[Raw samples, source hashes, microbenchmarks and profiler summaries](dtls13-perf.json)
include exact reference pins. Linux `make check`, native Windows `go test ./...`
and five repeated Linux DTLS/endpoint race-test runs passed. The write-ownership
and scratch-reuse regressions were checked by reintroducing each defect.

## Reproduce

Keep reference sources/builds outside this repository. Pins are in
`scripts/dtls13-baseline.json`. `scripts/dtls13-lab.py --root "$LAB" --only
openssl` builds the pinned OpenSSL; repeat with `--only pion` for Pion.
Build wolfSSL in a separate checkout of its pin with:

```sh
./autogen.sh
./configure --enable-dtls --enable-dtls13 --enable-dtls-mtu \
  --enable-curve25519 --enable-aesni --enable-intelasm \
  --disable-examples --disable-crypttests --disable-shared --enable-static CFLAGS=-O3
make -j4
```

On this x86-64 lab, `wolfssl/options.h` must enable `WOLFSSL_AESNI` and
`USE_INTEL_SPEEDUP`; the interoperability CMake build did not. Adapt CPU flags
for another architecture and record them. OpenSSL uses its default assembly.

Set `WORK` to a new output directory, `LAB` to the reference lab root and
`WOLF` to the accelerated wolfSSL checkout. From this repository:

```sh
PERF="$PWD/internal/dtls13/testdata/perf"
mkdir -p "$WORK/certs" "$LAB/src/pion/cmd/socat-perf"
go build -o "$WORK/socat-perf" "$PERF/common.go" "$PERF/socat.go"
cp "$PERF/common.go" "$PERF/pion.go" "$LAB/src/pion/cmd/socat-perf/"
(cd "$LAB/src/pion" && go build -o "$WORK/pion-perf" ./cmd/socat-perf)
gcc -O3 -pthread -I"$LAB/install/openssl/include" "$PERF/reference.c" \
  "$LAB/install/openssl/lib/libssl.a" "$LAB/install/openssl/lib/libcrypto.a" \
  -ldl -o "$WORK/openssl-perf"
gcc -O3 -pthread -DUSE_WOLFSSL -I"$WOLF" "$PERF/reference.c" \
  "$WOLF/src/.libs/libwolfssl.a" -lm -o "$WORK/wolfssl-perf"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost,IP:127.0.0.1
```

Export `c1d05da` into another directory, copy `common.go` and `socat.go` there
under the same `internal/dtls13/testdata/perf` path, and build
`$WORK/socat-original-perf` from that directory. Do not build it against the
candidate's module. Then run:

```sh
python3 scripts/dtls13-perf.py --workdir "$WORK" --revision "$(git rev-parse HEAD)" \
  --output "$WORK/comparison.json"
go test ./internal/dtls13 -run '^$' \
  -bench 'Benchmark(EncodeRecord|DecodeRecord|ConnOneWay|ConnPingPong)$' \
  -benchmem -benchtime 1s -count 5
go test ./internal/dtls13 -run '^$' -bench BenchmarkConnOneWay -benchtime 10s \
  -cpuprofile "$WORK/cpu.pprof" -memprofile "$WORK/mem.pprof"
go tool pprof -top "$WORK/cpu.pprof"
go tool pprof -top -alloc_space "$WORK/mem.pprof"
```

For Pion profiles, run `pion-perf` separately with `-mode oneway -n 1048576`,
the three certificate flags (`-cert`, `-key`, `-ca`) and `-cpu-profile` /
`-mem-profile`. Reference dependencies and helpers stay outside `make check`.
