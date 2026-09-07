# DTLS 1.3 library performance

Loopback comparison of library connections (not the socat CLI snapshot in
[README.md](README.md)). Later CLI and allocation notes for the send path are
in [dtls13-send-perf.md](dtls13-send-perf.md).

## Method

Ubuntu 26.04, Linux 7.0.0-30, six vCPUs on Ryzen 7 9800X3D; Go 1.27.0,
GCC 15.2.0. One IPv4 association, OS socket-buffer defaults, MTU 1200,
1024-byte records. Every peer is DTLS 1.3, AES-128-GCM, X25519; CID off for
this comparison (production CID/PQ defaults are unchanged). Five samples,
rotating library order. Handshake and 1000 warmup round trips are excluded.

Echo: 50,000 sequential request/reply pairs; RTT is the sample mean.
One-way: 1,048,576 numbered records (1 GiB) with a concurrent receiver,
payload checks, duplicate/reorder/loss accounting and a 250 ms drain.
Delivered MiB/s excludes lost data. Go allocation counts cover both
endpoints. C helpers use two connected UDP sockets; Go uses each library's
public API. This is not a pure cipher benchmark.

## Results

Recorded 2026-09-06, socat `8646740` vs original `c1d05da`, Pion `59f4c33`,
wolfSSL `d72f6d9`, OpenSSL `82733d9`. [Raw samples](dtls13-perf.json).

| Library | Delivered MiB/s, median (range) | Loss %, median / max | RTT us, median |
|---|---:|---:|---:|
| socat original `c1d05da` | 67.60 (67.06-68.21) | 0.000286 / 0.013161 | 82.74 |
| socat `8646740` | 69.72 (69.51-70.38) | 0 / 0.017357 | 79.55 |
| Pion `59f4c33` | 68.54 (67.46-69.89) | 0.046730 / 0.068569 | 82.34 |
| wolfSSL `d72f6d9` | 121.86 (114.17-126.98) | 0 / 0.057507 | 79.60 |
| OpenSSL `82733d9` | Failed all five long transfers | n/a | 85.00 |

Completed transfers had no duplicates, reordering or corrupt payloads. Zero
median loss is not lossless. These five loopback samples are not a ranking
across machines.

OpenSSL fails at timed record index 64534 in
[dtls_prepare_record_header](https://github.com/openssl/openssl/blob/82733d90b5bc58b8d064ed49c282aa028664a1ed/ssl/record/methods/dtls_meth.c#L906):
the full sequence is passed to a two-byte writer that rejects values above
65535. The runner leaves the reference unpatched.

See the [build and run recipe](dtls13-perf-reproduce.md) for the five helpers,
certificates and reference build settings. They are not part of `make check`.
