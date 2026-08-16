# socat (Go)

A modern [Go](https://go.dev) reimplementation of classic [socat](http://www.dest-unreach.org/socat/) — a multipurpose relay for bidirectional data transfer between two independent channels.

**Module:** `github.com/oittaa/socat`  
**License:** MIT  
**Status:** usable core; expanding toward classic parity

## Goals

- **Drop-in CLI** — classic address syntax (`TYPE:params,options`)
- **Speed** — efficient Go I/O, buffer pooling
- **Security** — memory-safe implementation; peer filters (`range`, `sourceport`, `lowport`) on listen/recv
- **Honesty** — `-V` / `-hhh` only advertise features and options that are enforced
- **Companions** — `filan` and `procan` included

## Build

Requires **Go 1.26+** (the `toolchain` directive will fetch it if needed):

```bash
make build
# or
go build -o socat ./cmd/socat
go build -o filan ./cmd/filan
go build -o procan ./cmd/procan
```

## Usage

```bash
# TCP echo server
./socat TCP4-LISTEN:8080,reuseaddr,fork PIPE

# Client
echo hello | ./socat - TCP4:127.0.0.1:8080

# Unix domain
./socat UNIX-LISTEN:/tmp/echo.sock,fork,unlink-early PIPE
./socat - UNIX-CONNECT:/tmp/echo.sock

# EXEC with PTY
echo hi | ./socat - EXEC:cat,pty,cfmakeraw
```

```text
socat [options] <address> <address>
socat -V | -h[h[h]]
```

Common options: `-d`, `-v`, `-x`, `-b`, `-t`, `-T`, `-u`/`-U`, `-4`/`-6`/`-0`, `--statistics`.

### Address types (supported)

| Type | Notes |
|------|--------|
| STDIO, STDIN, STDOUT, STDERR, FD | yes |
| PIPE, OPEN, FILE, CREATE/CREAT, GOPEN, SOCKETPAIR | yes |
| TCP / TCP4 / TCP6 (+ CONNECT, LISTEN / -L) | SO_REUSEADDR default on; `accept-timeout` exits 0 |
| UDP (+ LISTEN, SENDTO, RECV, RECVFROM, DATAGRAM) | basic; peer filters on recv/listen |
| UNIX-CONNECT / UNIX-CLIENT, UNIX-LISTEN | `bind=`, `unlink-close` / `unlink-early` |
| EXEC, SYSTEM, SHELL | pipes, socketpair, **pty**, fdin/fdout, setsid, shut-none; child exit promoted |
| TEXT, STALL, PTY | STALL uses classic full-pipe backpressure |
| TLS / TLS-CONNECT / TLS-LISTEN (`TLS-L`) | stream TLS via `crypto/tls`; **not** DTLS (see [Unsupported / security](#unsupported--security-related)). Classic aliases: `OPENSSL` / `OPENSSL-CONNECT` / `OPENSSL-LISTEN`, `SSL` / `SSL-CONNECT` / `SSL-LISTEN` |
| PROXY / PROXY-CONNECT | HTTP CONNECT client: default HTTP/1.x; `http-version=2` (`net/http`) / `http-version=3` (quic-go/http3); `h2c` |
| SOCKS4 / SOCKS4A / SOCKS5 / SOCKS5-CONNECT | SOCKS clients (`socksport`, `socksuser`, `sockspass`) |
| SOCKS5-LISTEN / SOCKS5-BIND | SOCKS5 BIND (remote listen; two server replies) |
| ABSTRACT-LISTEN / ABSTRACT-CONNECT / … | Linux abstract UNIX namespace |
| libwrap / TCP wrappers | pure-Go `hosts.allow` / `hosts.deny` (`WITH_LIBWRAP`) |
| TUN, INTERFACE | Linux TUN/TAP + AF_PACKET (`WITH_TUN`, `WITH_INTERFACE`; need CAP_NET_ADMIN) |
| WS / WSS (+ CONNECT, LISTEN / -L) | WebSocket byte relay (`github.com/coder/websocket`); **not** in classic socat |
| QUIC / QUIC-CONNECT / QUIC-LISTEN | RFC 9000 byte relay (`github.com/quic-go/quic-go`); **not** HTTP/3; **not** in classic socat |
| SCTP / SCTP4 / SCTP6 (+ CONNECT, LISTEN / -L) | Linux kernel one-to-one SCTP (`SOCK_STREAM` + `IPPROTO_SCTP`, RFC 9260); need `sctp` module |
| POSIXMQ / POSIXMQ-READ / POSIXMQ-RECV / POSIXMQ-SEND | Linux POSIX message queues; `mq-prio`, unlink-early/close, RECV/SEND `fork` + `max-children` |
| DCCP, readline | **not** implemented (`#undef` in `-V`) |

### Options (honored)

Advertised on `-hh` / `-hhh` (test.sh greps these). Highlights:

| Area | Options |
|------|---------|
| Listen/connect | `reuseaddr`, `so-reuseport`, `fork`, `max-children`, `bind`, `connect-timeout`, `accept-timeout`, `pf`, `ai-addrconfig`, `ipv6-v6only`, `backlog` |
| Security filters | `range`, `sourceport`/`sp` (listen = peer filter; connect = bind), `lowport`, `tcpwrap` / `hosts-allow` / `hosts-deny` / `tcpwrap-etc` |
| TUN / INTERFACE | `tun-name`, `tun-type`, `tun-device`, `iff-up`, `iff-no-pi`, `if-mtu` / `interface-mtu`, other `iff-*` flags |
| Files | `rdonly`, `wronly`, `creat`, `excl`, `append`, `trunc`, `mode`, `perm`, `umask`, `nonblock` |
| UNIX | `unlink-early`, `unlink-close`, `unix-bind-tempname` / `bind-tempname` |
| POSIX MQ | `mq-prio` / `posixmq-priority`, `mq-flush`, `mq-maxmsg`, `mq-msgsize` |
| EXEC | `pipes`, `pty`, `fdin`, `fdout`, `setsid`, `stderr`, `shut-none`, `chdir`, `umask` (child inherits, then parent restores) |
| PTY / TERMIOS | `link`, `cfmakeraw`/`raw`/`rawer`, `echo`, `opost`, baud/`ispeed`/`ospeed`, `tiocswinsz`, `pty-wait-slave`, `ctty`; restore tty on close |
| Transfer | `crnl`, `crlf`, `ignoreeof`, `readbytes`, `retry`/`forever`/`interval` |
| TLS | `cert`, `key`, `cafile`/`ca`, `capath`, `verify`, `commonname`, `snihost`, `nosni` (classic aliases: `openssl-capath`, `openssl-commonname`, `openssl-snihost`, `openssl-no-sni`; also `tls-capath`, `tls-commonname`, `tls-snihost`, `tls-no-sni`) |
| WebSocket | `path`, `origin`, `protocol` (binary frames; WSS reuses TLS options) |
| QUIC | `alpn` (default `socat`; not `h3`); reuses TLS options; one bidirectional stream |
| PROXY/SOCKS | `proxyport`, `http-version` (`1.0`/`1.1`/`2`/`3`), `h2c`, `proxy-authorization` / `proxy-authorization-file`, `socksport`, `socksuser` |

**`max-children`:** limits concurrent `fork` sessions on **LISTEN** and on **CONNECT** / **TLS-CONNECT** client reconnect loops. Requires `fork`. Parent redials after `interval` (default 1s).

**`perm=` / `mode=`:** after create/open, `chmod`/`fchmod` sets the exact mode (classic NAMED group). **`umask=`** applies only during open (or child `Start` for EXEC/SHELL), then restores.

### TLS notes

- **Stream TLS only** — see [Unsupported](#unsupported--security-related) for DTLS.
- **Listen requires `cert=`** — `TLS-LISTEN`, `WSS-LISTEN`, and `QUIC-LISTEN` refuse to start without `cert=`. Classic `OPENSSL-LISTEN` warns (`no certificate given; consider option "cert"`), binds, then `SSL_accept` fails (`no shared cipher`). We fail at open instead of inventing a dummy certificate. Classic `V1800_OPENSSL_LISTEN_*` (bind/range only) and `ciphers=aNULL` without `cert=` therefore fail here.
- **No DSA** — see [Unsupported](#unsupported--security-related).
- **`verify` (TLS, WSS, QUIC)** — default on. `verify=0` skips trust and name checks. `verify=1` uses `crypto/x509` (not OpenSSL `SSL_get_verify_result`). With no `cafile`/`capath`, the **system** CA pool is used on both client and listen (classic `SSL_CTX_set_default_verify_paths`).
- **`capath`** — directory of CA certificates (PEM or DER). We load every regular file that parses as a certificate, including OpenSSL hashed names and symlinks. Classic OpenSSL only looks up hashed names.
- **Peer name** — [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) via Go `Certificate.VerifyHostname` (case-insensitive, modern wildcard rules). Classic OPENSSL address types use `strcmp` and treat `*.example.com` as a match for `example.com`. For old test certs with no SAN, we still accept a CN match. An empty `commonname=` does **not** turn off the name check; the dial host is still checked. Use `verify=0` to skip name and trust checks.
- **Post-quantum key exchange** — Go 1.24+ `crypto/tls` defaults to hybrid **X25519MLKEM768**. We inherit that. Classic `test.sh` has no PQC tests; we cover PQC in unit/e2e tests.
- **Multi-address connect** — try every resolved address; log `opening connection to AF=…`; match `bind=` to remote family; `-4`/`-6` reorder dual-stack results.
- **IPv6 peer filters** on `TLS-LISTEN`: `range`, `sourceport`, `lowport` (CN check accepts `::1` vs `[::1]`).

### Unsupported / security-related

We do **not** re-implement features that Go’s standard libraries removed or never offered for security (or crypto-policy) reasons. Prefer modern alternatives.

| Topic | Status | Why / reference |
|-------|--------|------------------|
| **DSA certificates / keys** | Rejected | DSA is obsolete; Go `crypto/tls` does not parse DSA keys. Classic `OPENSSLLISTENDSA` fails by design. Use RSA, ECDSA, or Ed25519. See [Go crypto/tls](https://pkg.go.dev/crypto/tls) and [NIST SP 800-57 / deprecation of DSA](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final). |
| **DTLS** | Not implemented | Not available in Go `crypto/tls` (stream TLS only). See [crypto/tls package docs](https://pkg.go.dev/crypto/tls). |
| **SSLv3 / weak ciphers** | Not offered | Go TLS defaults reject obsolete protocols/ciphers. See [Go TLS cipher suites](https://go.dev/blog/tls-cipher-suites) and [crypto/tls Config](https://pkg.go.dev/crypto/tls#Config). |
| **libwrap / TCP wrappers** | Implemented (pure Go) | No CGO/libwrap0; reads `hosts.allow`/`hosts.deny` (or `tcpwrap-etc=`). Subset: daemon ALL/name, client ALL/IP/hostname/`[ipv6]`. |

### Intentional differences from classic socat

- **WebSocket (WS/WSS)** is a Go extra (classic has no WS). Uses `github.com/coder/websocket` (`NetConn` + binary frames), not frozen `golang.org/x/net/websocket`.
- **QUIC** is a Go extra (classic has no QUIC). Uses `github.com/quic-go/quic-go` (same stack as HTTP/3 CONNECT). One bidirectional stream as a byte pipe. Not HTTP/3 (`alpn` default `socat`). 0-RTT is off.
- **PROXY `http-version=2` / `3`** is a Go extra (classic PROXY is HTTP/1.x). HTTP/2 uses `net/http`. HTTP/3 uses `github.com/quic-go/quic-go/http3` because `golang.org/x/net/http3` is not a public client API.
- **`fork`** uses **goroutines**, not `fork(2)` process isolation
- Companion tools aim for useful parity, not bit-identical C ifdef output
- Unknown options are generally ignored (classic may error more strictly)
- Security-deprecated crypto (DSA, DTLS, etc.) is documented above rather than forced in
- **TLS listen without `cert=`** fails at start (classic warns, listens, then handshake fails). See [TLS notes](#tls-notes).
- **TLS address names** are `TLS` / `TLS-CONNECT` / `TLS-LISTEN`. `OPENSSL*` and `SSL*` remain aliases so classic command lines still work. Peer env vars stay `SOCAT_OPENSSL_X509_*`.

## Classic scorecard

Upstream **`test.sh`** (~608 numbered cases) is the feature scorecard (not CI).
Classic runs it **sequentially** with an auto-calibrated `-t`. Our runner can
match that or go faster (and flakier) with parallel shards.

| Mode | Command shape | Use when |
|------|----------------|----------|
| **classic** | `JOBS=1`, auto `-t`, long wall | Baselines / low flake (closest to upstream) |
| **stable** | `JOBS=1`, `VAL_T=0.5` | Sequential, fixed timeouts |
| **fast** (default) | parallel + short `-t` | Smoke / day-to-day |

Each run writes **structured results** (OK / FAILED / CANT / TIMEOUT) for compare.

See **`testdata/scorecard/README.md`** for the full workflow.

```bash
# obtain classic tree (GPL-2):
#   git clone --depth 1 https://repo.or.cz/socat.git /tmp/socat-master

make build

# Recommended for parity baselines (like classic: one-by-one, auto -t)
MODE=classic \
  BASELINE=testdata/scorecard/classic-baseline.json \
  SAVE_BASELINE=testdata/scorecard/go-baseline.json \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# Fast parallel smoke (default MODE=fast; more flaky under load)
JOBS=8 SHARD_TIMEOUT=240 VAL_T=0.1 \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh

# Record classic C baseline (rare)
SOCAT=/path/to/classic/socat SKIP_BUILD=1 LABEL=classic MODE=classic \
  SAVE_BASELINE=testdata/scorecard/classic-baseline.json \
  ./scripts/classic-scorecard.sh /tmp/socat-1.8.1.3/test.sh
```

**Latest committed baselines** (see `testdata/scorecard/`; counts from structured `results.json`):

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 (host) | 475 | 24 | 103 |
| classic 1.8.1.3 (Docker, root) | 552 | 8 | 42 |
| go (this tree, host) | 449 | 6 | 148 |
| go (this tree, Docker, root) | 504 | 5 | 94 |

Go host FAILED: `OPENSSLLISTENDSA` (DSA, by design), `UDP6MULTICAST_UNIDIR` (host environment), `REUSEADDR_NULL` (NO RESULT), `OPENSSL_ANULL`, `V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND` (listen requires `cert=`). Go Docker FAILED: `OPENSSLLISTENDSA`, `REUSEADDR_NULL`, `OPENSSL_ANULL`, `V1800_OPENSSL_LISTEN_RANGE`, `V1800_OPENSSL_LISTEN_BIND`. Both Go runs also record UNKNOWN=2 (`EXECPTYKILL` parse quirk, `PROCAN_CTTY`).

Use `go-baseline.json` + `REGRESSION_EXIT=1` after a **MODE=classic** run to catch real Go regressions with less noise.

Classic host checklist: `scripts/classic-host-check.sh`.

```bash
go test ./...
go test -tags=e2e ./e2e/...   # after build
```

## Examples / lab

Optional two-container Docker Compose checks (curl, microsocks, HTTP over
TLS / QUIC / WSS / SOCKS5). Not part of `make test` or `make e2e`.

```bash
make lab
# or
./examples/lab/run.sh tls
```

See [examples/lab/README.md](examples/lab/README.md).

## Benchmarks

Loopback on one host. Method: [testdata/bench/README.md](testdata/bench/README.md).
Reproduce: `make bench` (set `CLASSIC_SOCAT` for classic columns).

Recorded 2026-08-14 on Intel N150 (4 cores), Linux 6.8.0-137, Go 1.26.5,
classic socat 1.8.1.3, distro OpenSSL 3.0.13. Payload: 256 MiB AES-128-CTR
(incompressible; not `/dev/zero`). Median of 5 timed runs, `-b 8192`.

| Case | classic | go | Peak RSS (classic / go) |
|------|---------|----|-------------------------|
| TCP 256 MiB | 966.8 MiB/s | 616.5 MiB/s | 8.3 / 20.1 MiB |
| UNIX 256 MiB | 1190.8 MiB/s | 812.0 MiB/s | 8.0 / 20.0 MiB |
| TLS 256 MiB | 616.2 MiB/s | 550.1 MiB/s | 16.5 / 23.4 MiB |
| QUIC 256 MiB | n/a | 279.0 MiB/s | n/a / 34.5 MiB |
| TCP 64 B RTT | 23.0 µs | 21.2 µs | 4.1 / 10.2 MiB |
| TLS 64 B RTT | 31.0 µs | 30.5 µs | 8.6 / 11.9 MiB |
| QUIC 64 B RTT | n/a | 92.9 µs | n/a / 16.1 MiB |
| TLS handshake | 19.3 /s | 217.9 /s | 20.6 / 17.2 MiB |

Recorded handshakes (same binaries as the table; see `meta.tls` in `testdata/bench/host.json`):

| Pairing | Used by | Version | Cipher | Group |
|---------|---------|---------|--------|-------|
| Go `crypto/tls` ↔ Go TLS-LISTEN | `tls`, `tls-rr`, `tls-hs` (go) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |
| Distro OpenSSL 3.0.13 ↔ classic OPENSSL-LISTEN | `tls` (classic) | TLS 1.3 | TLS_AES_256_GCM_SHA384 | P-256 |
| Go `crypto/tls` ↔ classic OPENSSL-LISTEN | `tls-rr`, `tls-hs` (classic) | TLS 1.3 | TLS_AES_128_GCM_SHA256 | P-256 |
| quic-go ↔ Go QUIC-LISTEN | `quic`, `quic-rr` | TLS 1.3 | TLS_AES_128_GCM_SHA256 | X25519MLKEM768 |

- Go TLS/QUIC used hybrid post-quantum **X25519MLKEM768**. Classic OPENSSL used **P-256** (unpatched 1.8.1.3 pins that curve; distro OpenSSL 3.0.13 has no ML-KEM).
- Bulk TLS also used different ciphers: classic **AES-256-GCM**, Go **AES-128-GCM**.
- `tls-hs` (classic) is a Go client to a classic listener, so that column is P-256. The Go `tls-hs` column is X25519MLKEM768. The rate gap is also classic `fork(2)` vs Go goroutines.
- QUIC is a UDP byte tunnel (`alpn=socat`). It is not HTTP/3 and not OpenSSL.
- These numbers are one machine. Run the script on your host. JSON: `testdata/bench/host.json`.

## Layout

```
cmd/socat   cmd/filan   cmd/procan
internal/parse  internal/xio/{netopen,tlsopen,proxyopen,fileopen,tunopen,all}
internal/relay  internal/cli  internal/logx
scripts/classic-scorecard.sh  scripts/scorecard-parse.py  scripts/scorecard-compare.py
scripts/bench.sh              # optional loopback benches
testdata/scorecard/   # classic / go baselines
testdata/bench/       # committed bench snapshot
e2e/
examples/lab/         # optional Compose host/client lab
```

## Prior art

- Classic socat by Gerhard Rieger (GPL-2) — behavior and tests reference  
- [sumup-oss/gocat](https://github.com/sumup-oss/gocat) — performance ideas for TCP↔Unix relays (not a full socat)

## License

MIT — see [LICENSE](LICENSE). This is an independent reimplementation; it does not copy classic socat C sources.
