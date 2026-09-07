# DTLS send-path measurements

Isolated comparison of master `66c2f18` against one cached application-write
command per connection (#248). Failed or abandoned commands are discarded.
[Raw samples](dtls13-send-perf.json).

Ubuntu lab VM, Go 1.27.0, production defaults (DTLS 1.3, AES-128-GCM,
X25519MLKEM768, CID 8, MTU 1200). CLI: five rotated 512 MiB transfers per
direction after one warmup, 1024-byte frames. Library: five 2-second samples,
1024-byte records, both endpoints.

| CLI direction | Before, MiB/s (range) | After, MiB/s (range) | Median change |
|---|---:|---:|---:|
| Client to server | 42.53 (41.16-43.60) | 42.88 (41.49-43.06) | +0.8% |
| Server to client | 33.70 (33.26-34.49) | 33.81 (33.36-34.38) | +0.3% |

CLI ranges overlap. Maximum loss was 0.047313%; no corruption, duplicates,
reordering or trailing bytes. Peak RSS stayed around 39 MiB.

| Library measurement | Before | After |
|---|---:|---:|
| Allocations per bulk record | 10 | 6 |
| Allocated bytes per bulk record | 5022 | 4702 |
| Bulk Write, ns/op | 11048 | 10664 |

The 1 GiB all-protocol snapshot in [README.md](README.md) also includes
earlier send-path work; do not attribute that table solely to command reuse.
