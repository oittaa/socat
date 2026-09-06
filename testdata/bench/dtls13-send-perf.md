# DTLS send-path measurements

Compared master `53ef32b` with direct client socket writes, mutex-protected
cancellation, and conditional shared-queue timers. The mutex replaces the
cancellation watcher; the protocol event loop still owns keys, sequence numbers
and CID state. Runtime code is 11 lines shorter, with three fewer goroutines
per client/listener pair. [Raw samples and profile summaries](dtls13-send-perf.json).

Same Ubuntu lab VM: six vCPUs on Ryzen 7 9800X3D, Go 1.27.0, GOMAXPROCS=6.
Production defaults: DTLS 1.3, AES-128-GCM, X25519MLKEM768, CID 8, MTU 1200,
default socket buffers. CLI transfers use 1024-byte frames and RAM-backed files.
Five rotated 512 MiB runs per direction after one 128 MiB warmup; profiling runs
separately. Delivered throughput accounts for loss. No corruption, duplicates
or reordering occurred. These are single-association loopback measurements.

| CLI direction | Before, MiB/s | After, MiB/s | Change | Maximum loss before / after |
|---|---:|---:|---:|---:|
| Client → server | 33.48 | 43.62 | +30.3% | 0 / 0.021132% |
| Server → client | 32.21 | 34.15 | +6.0% | 0.189067 / 0.003740% |

Median combined peak RSS remained about 39 MiB. These results do not replace
the older seven-run 1 GiB all-protocol snapshot in [README.md](README.md).

Library benchmarks use both UDP endpoints in one process, three 2-second samples
per benchmark, excluding handshakes. Allocation counts cover both endpoints.

| Library measurement | Before | After |
|---|---:|---:|
| One-way offered throughput | 70.26 MiB/s | 89.69 MiB/s |
| Allocations per one-way record | 16 | 10 |
| Allocated bytes per one-way record | 5511 | 5023 |
| Sequential Write + peer Read | 38.97 µs | 40.40 µs |
| Echo round trip | 81.63 µs | 81.45 µs |
| Allocations per echo | 34 | 25 |

Separate CPU and allocation profiles were collected before and after each step.
For a fixed 512 MiB client-send transfer, sender sampled CPU fell from 22.31 to
17.10 seconds; allocated bytes fell from 1.597 to 1.335 GB and allocation events
from 6.43 to 3.21 million. Receiver sampled CPU fell from 13.91 to 11.33 seconds.
The remaining large allocations are input/datagram copies and AEAD buffers.

The direct-client step improved CLI goodput about 16%; mutex cancellation added
about 9% in its paired experiment and removed the watcher machinery. Conditional
queue timers added only about 3% server throughput, but avoid three allocations
and about 248 allocated bytes per shared-socket write with little extra code.
All three are retained. The roughly 4% serial Write/Read slowdown is accepted
against the bulk gains, unchanged RTT, lower allocation volume and smaller code.

Existing deadline, input-ownership, ambiguous-write, CID and KeyUpdate tests remain
applicable. New regressions cover prompt interruption of blocked application
writes and deadlines when the shared write queue is full. Removing socket
interruption makes the shutdown regression fail. Buffer pooling and moving
protocol operations out of the event loop remain separate work.

Validation passed: Linux `make check`, native Windows `go test ./...`, and Linux
`go test -race ./internal/dtls13 ./internal/xio/dtlsopen -count=5`.

Profile each revision separately:

```sh
go test ./internal/dtls13 -run '^$' -bench 'BenchmarkConnOneWay$' \
  -benchtime=8s -cpuprofile=cpu.pprof -memprofile=allocs.pprof
go tool pprof -top cpu.pprof
go tool pprof -alloc_space allocs.pprof
```
