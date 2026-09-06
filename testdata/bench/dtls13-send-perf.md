# DTLS send-path measurements

Compared master `66c2f18` with one cached application-write command per
connection. Successful completion makes its command, reply channel and open
cancellation channel reusable. Failed or abandoned commands are discarded;
concurrent writes allocate when the cache is busy. The completion wakeup,
input copies, deadlines and protocol event loop are unchanged. Runtime code
adds 28 net lines in `conn.go`; there are no new goroutines or buffer pools.
[Raw samples, source fingerprint and profile summaries](dtls13-send-perf.json).

Ubuntu lab VM: six vCPUs on Ryzen 7 9800X3D, Go 1.27.0, GOMAXPROCS=6,
GOGC=100. Defaults: DTLS 1.3, AES-128-GCM, X25519MLKEM768, CID 8,
MTU 1200 and OS socket buffers. CLI transfers use 1024-byte validated frames
and RAM-backed files. Five rotated 512 MiB runs per direction follow one
same-size warmup. Rates count unique delivered payload, including loss.

| CLI direction | Before, MiB/s (range) | After, MiB/s (range) | Median change |
|---|---:|---:|---:|
| Client to server | 42.53 (41.16-43.60) | 42.88 (41.49-43.06) | +0.8% |
| Server to client | 33.70 (33.26-34.49) | 33.81 (33.36-34.38) | +0.3% |

The ranges overlap: this run does not establish a material CLI speedup.
Maximum loss was 0.047313%; no corruption, duplicates, reordering or
trailing bytes occurred. Combined peak RSS stayed around 39 MiB.

Library medians use five rotated 2-second samples, with handshakes excluded.
Each operation writes 1024 bytes; allocation counts cover both endpoints.

| Library measurement | Before | After |
|---|---:|---:|
| Bulk Write, ns/op | 11048 | 10664 |
| Allocations per bulk record | 10 | 6 |
| Allocated bytes per bulk record | 5022 | 4702 |
| Sequential Write + peer Read, us | 39.16 | 38.53 |
| Echo round trip, us | 82.29 | 80.70 |

Separate CPU and allocation profiles cover both variants: 8-second library
runs and fixed 256 MiB CLI transfers. Sender allocation/CPU totals are below;
receiver allocation volume was essentially unchanged. These single profile
pairs describe costs, not statistically reliable CPU improvements.

| Sender profile | Allocated MB before / after | Allocation events before / after | Sampled CPU seconds before / after |
|---|---:|---:|---:|
| Client | 667.8 / 582.2 | 1,606,189 / 536,784 | 9.01 / 8.91 |
| Server | 731.9 / 646.4 | 2,408,563 / 1,338,992 | 11.41 / 11.38 |

Keep this as a small allocation optimization, not a bulk-throughput fix.
The full seven-run 1 GiB snapshot in [README.md](README.md) also includes
the earlier master optimizations; its change from the previous snapshot
must not be attributed solely to command reuse.

Validation: Linux `make check`, native Windows `go test ./...`, and five
Linux race runs of `internal/dtls13` and `internal/xio/dtlsopen`. New tests
exercise overlapping writes and an abandoned write followed by another.
Reintroducing premature or concurrent command reuse makes these tests fail.

```sh
go test ./internal/dtls13 -run '^$' -bench 'BenchmarkConnOneWay$' \
  -benchtime=8s -cpuprofile=cpu.pprof -memprofile=allocs.pprof
go tool pprof -top cpu.pprof
go tool pprof -alloc_space allocs.pprof
```
