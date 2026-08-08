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
| OPENSSL / OPENSSL-CONNECT / OPENSSL-LISTEN (SSL-*) | stream TLS via `crypto/tls` (`#define WITH_OPENSSL`); **not** DTLS |
| SOCKS, PROXY, SCTP, abstract UNIX, … | **not** implemented (`#undef` in `-V`) |

### Options (honored)

Advertised on `-hh` / `-hhh` (test.sh greps these). Highlights:

| Area | Options |
|------|---------|
| Listen/connect | `reuseaddr`, `fork`, `bind`, `connect-timeout`, `accept-timeout`, `pf`, `ipv6-v6only`, `backlog` |
| Security filters | `range`, `sourceport`/`sp` (listen = peer filter; connect = bind), `lowport` |
| Files | `rdonly`, `wronly`, `creat`, `excl`, `append`, `trunc`, `mode`, `nonblock` |
| UNIX | `unlink-early`, `unlink-close` |
| EXEC | `pipes`, `pty`, `fdin`, `fdout`, `setsid`, `stderr`, `shut-none` |
| PTY/termios-ish | `link`, `cfmakeraw`, `raw`, `echo`, `opost` |
| Transfer | `crnl`, `ignoreeof`, `readbytes`, `retry`/`forever`/`interval` |
| TLS | `cert`, `key`, `cafile`/`ca`, `verify`, `commonname` / `openssl-commonname` |

**Not advertised / not enforced:** `end-close`, `shut-null`, `max-children`, openssl, libwrap, etc.

### Intentional differences from classic socat

- **`fork`** uses **goroutines**, not `fork(2)` process isolation
- Companion tools aim for useful parity, not bit-identical C ifdef output
- Unknown options are generally ignored (classic may error more strictly)

## Classic scorecard

Upstream **`test.sh`** (~608 numbered cases) is the feature scorecard (not CI). Prefer the parallel runner:

```bash
# obtain classic tree (GPL-2):
#   git clone --depth 1 https://repo.or.cz/socat.git /tmp/socat-master
make build
JOBS=8 SHARD_TIMEOUT=180 VAL_T=0.05 ./scripts/classic-scorecard.sh /tmp/socat-master/test.sh
```

**Snapshot (hang-free, JOBS=8):** **210 OK / 72 FAILED / 324 CANT** of 606 selected.  
Deltas vs early hang-free baseline (~156/120/330): **+54 OK**, **−48 FAILED**.  

Classic host checklist: `scripts/classic-host-check.sh`. After installing `libwrap0-dev` + `libreadline-dev` and **rebuilding** classic (no reboot), this host got **504 OK / 3 FAIL / 99 CANT** (was 489/3/114). Logs: `.classic-scorecard/shard-*.log`.

```bash
go test ./...
go test -tags=e2e ./e2e/...   # after build
```

## Layout

```
cmd/socat   cmd/filan   cmd/procan
internal/parse  internal/addr  internal/relay  internal/cli  internal/logx
scripts/classic-scorecard.sh
e2e/
```

## Prior art

- Classic socat by Gerhard Rieger (GPL-2) — behavior and tests reference  
- [sumup-oss/gocat](https://github.com/sumup-oss/gocat) — performance ideas for TCP↔Unix relays (not a full socat)

## License

MIT — see [LICENSE](LICENSE). This is an independent reimplementation; it does not copy classic socat C sources.
