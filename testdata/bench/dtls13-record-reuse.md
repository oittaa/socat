# DTLS record-buffer reuse

Compared master `66c2f18` (#246) with session encode scratch, connection-local
datagram and application buffer reuse, and a shared-writer payload pool. Protocol
state still belongs to the connection event loop. The one-second shared write
attempt bound is unchanged: skipping it on exclusive sockets blocked cancellation
and path-migration retries.

These library numbers are from the Cloud Agent host (Intel Xeon, 4 logical CPUs),
not the Ubuntu lab Ryzen used in [dtls13-send-perf.md](dtls13-send-perf.md). Do
not mix the two. Production defaults: DTLS 1.3, AES-128-GCM, X25519MLKEM768,
CID 8, MTU 1200, 1024-byte application records.

`go test ./internal/dtls13 -bench 'BenchmarkEncodeRecord$|BenchmarkDecodeRecord$|BenchmarkConnSerialOneWay$|BenchmarkConnOneWay$' -benchmem -count=5 -benchtime=1s`

Median of five 1-second samples:

| Measurement | Before (#246) | Encode scratch only | Combined reuse |
|---|---:|---:|---:|
| Encode ns/op, allocs, B | 404.2, 1, 1152 | 213.6, 0, 0 | 213.3, 0, 0 |
| Decode ns/op, allocs, B | 411.5, 1, 1152 | 474.1, 1, 1152 | 412.2, 1, 1152 |
| Serial Write+Read MB/s | 71.46 | 74.46 | 87.41 |
| Serial allocs, B | 11, 5048 | 10, 3896 | 5, 432 |
| One-way allocs, B | 10, 5021 | 9, 3864 | 4, 413 |

Decode still allocates in the isolated microbenchmark, which passes a nil
Open destination. Established connections supply a recycled destination.

Isolated encode scratch halved encode time and removed one allocation of 1152
bytes. Combined reuse removed the remaining record-sized copies on the serial
path (Write snapshot, incoming datagram, Open plaintext, shared-queue payload).
Remaining serial allocations are the write command, its cancel/result channels,
and the readable-state notify channel.

Rejected after measurement and contract tests:

- Skipping `SetWriteDeadline` / the one-second attempt bound on exclusive
  sockets. `TestConnFailureInterruptsApplicationWrite` and path migration rely
  on a socket deadline to unblock `WriteTo` and to retry zero-byte attempts.

Linux `go test ./internal/dtls13` and `go test -race ./internal/dtls13 ./internal/xio/dtlsopen -count=5` passed.
