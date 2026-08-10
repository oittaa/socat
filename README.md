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
| OPENSSL / OPENSSL-CONNECT / OPENSSL-LISTEN (SSL-*) | stream TLS via `crypto/tls`; **not** DTLS (see [Unsupported / security](#unsupported--security-related)) |
| PROXY / PROXY-CONNECT | HTTP CONNECT client (`proxyport`, `http-version`, `crlf`) |
| SOCKS4 / SOCKS4A / SOCKS5 / SOCKS5-CONNECT | SOCKS clients (`socksport`, `socksuser`, `sockspass`) |
| ABSTRACT-LISTEN / ABSTRACT-CONNECT / … | Linux abstract UNIX namespace |
| libwrap / TCP wrappers | pure-Go `hosts.allow` / `hosts.deny` (`WITH_LIBWRAP`) |
| SCTP, DCCP, POSIXMQ, TUN, readline | **not** implemented (`#undef` in `-V`) |

### Options (honored)

Advertised on `-hh` / `-hhh` (test.sh greps these). Highlights:

| Area | Options |
|------|---------|
| Listen/connect | `reuseaddr`, `fork`, `max-children`, `bind`, `connect-timeout`, `accept-timeout`, `pf`, `ai-addrconfig`, `ipv6-v6only`, `backlog` |
| Security filters | `range`, `sourceport`/`sp` (listen = peer filter; connect = bind), `lowport`, `tcpwrap` / `hosts-allow` / `hosts-deny` / `tcpwrap-etc` |
| Files | `rdonly`, `wronly`, `creat`, `excl`, `append`, `trunc`, `mode`, `perm`, `umask`, `nonblock` |
| UNIX | `unlink-early`, `unlink-close` |
| EXEC | `pipes`, `pty`, `fdin`, `fdout`, `setsid`, `stderr`, `shut-none`, `umask` (child inherits, then parent restores) |
| PTY/termios-ish | `link`, `cfmakeraw`, `raw`, `echo`, `opost`, `perm` |
| Transfer | `crnl`, `crlf`, `ignoreeof`, `readbytes`, `retry`/`forever`/`interval` |
| TLS | `cert`, `key`, `cafile`/`ca`, `verify`, `commonname` / `openssl-commonname`, `openssl-snihost` / `snihost`, `openssl-no-sni` / `nosni` |
| PROXY/SOCKS | `proxyport`, `http-version`, `socksport`, `socksuser` |

**`max-children`:** limits concurrent `fork` sessions on **LISTEN** and on **CONNECT** / **OPENSSL-CONNECT** client reconnect loops. Requires `fork`. Parent redials after `interval` (default 1s).

**`perm=` / `mode=`:** after create/open, `chmod`/`fchmod` sets the exact mode (classic NAMED group). **`umask=`** applies only during open (or child `Start` for EXEC/SHELL), then restores.

### TLS notes

- **Stream TLS only** — see [Unsupported](#unsupported--security-related) for DTLS.
- **No DSA** — see [Unsupported](#unsupported--security-related).
- **Post-quantum key exchange** — Go 1.24+ `crypto/tls` defaults to hybrid **X25519MLKEM768**. We inherit that. Classic `test.sh` has no PQC tests; we cover PQC in unit/e2e tests.
- **Multi-address connect** — try every resolved address; log `opening connection to AF=…`; match `bind=` to remote family; `-4`/`-6` reorder dual-stack results.
- **IPv6 peer filters** on OPENSSL-LISTEN: `range`, `sourceport`, `lowport` (CN check accepts `::1` vs `[::1]`).

### Unsupported / security-related

We do **not** re-implement features that Go’s standard libraries removed or never offered for security (or crypto-policy) reasons. Prefer modern alternatives.

| Topic | Status | Why / reference |
|-------|--------|------------------|
| **DSA certificates / keys** | Rejected | DSA is obsolete; Go `crypto/tls` does not parse DSA keys. Classic `OPENSSLLISTENDSA` fails by design. Use RSA, ECDSA, or Ed25519. See [Go crypto/tls](https://pkg.go.dev/crypto/tls) and [NIST SP 800-57 / deprecation of DSA](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final). |
| **DTLS** | Not implemented | Not available in Go `crypto/tls` (stream TLS only). See [crypto/tls package docs](https://pkg.go.dev/crypto/tls). |
| **SSLv3 / weak ciphers** | Not offered | Go TLS defaults reject obsolete protocols/ciphers. See [Go TLS cipher suites](https://go.dev/blog/tls-cipher-suites) and [crypto/tls Config](https://pkg.go.dev/crypto/tls#Config). |
| **libwrap / TCP wrappers** | Implemented (pure Go) | No CGO/libwrap0; reads `hosts.allow`/`hosts.deny` (or `tcpwrap-etc=`). Subset: daemon ALL/name, client ALL/IP/hostname/`[ipv6]`. |

### Intentional differences from classic socat

- **`fork`** uses **goroutines**, not `fork(2)` process isolation
- Companion tools aim for useful parity, not bit-identical C ifdef output
- Unknown options are generally ignored (classic may error more strictly)
- Security-deprecated crypto (DSA, DTLS, etc.) is documented above rather than forced in

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

**Latest committed baselines** (see `testdata/scorecard/`):

| Label | OK | FAILED | CANT |
|-------|-----|--------|------|
| classic 1.8.1.3 | 475 | 24 | 103 |
| go (this tree) | ~337 | ~20 | ~207 |

Use `go-baseline.json` + `REGRESSION_EXIT=1` after a **MODE=classic** run to catch real Go regressions with less noise.

Classic host checklist: `scripts/classic-host-check.sh`.

```bash
go test ./...
go test -tags=e2e ./e2e/...   # after build
```

## Layout

```
cmd/socat   cmd/filan   cmd/procan
internal/parse  internal/addr  internal/relay  internal/cli  internal/logx
scripts/classic-scorecard.sh  scripts/scorecard-parse.py  scripts/scorecard-compare.py
testdata/scorecard/   # classic / go baselines
e2e/
```

## Prior art

- Classic socat by Gerhard Rieger (GPL-2) — behavior and tests reference  
- [sumup-oss/gocat](https://github.com/sumup-oss/gocat) — performance ideas for TCP↔Unix relays (not a full socat)

## License

MIT — see [LICENSE](LICENSE). This is an independent reimplementation; it does not copy classic socat C sources.
