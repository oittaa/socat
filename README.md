# socat (Go)

A modern [Go](https://go.dev) reimplementation of classic [socat](http://www.dest-unreach.org/socat/) — a multipurpose relay for bidirectional data transfer between two independent channels.

**Module:** `github.com/oittaa/socat`  
**License:** MIT  
**Status:** early development (MVP)

## Goals

- **Drop-in CLI** — classic address syntax (`TYPE:params,options`)
- **Speed** — efficient Go I/O, buffer pooling, optional future `splice`
- **Security** — memory-safe implementation; careful parsers; modern TLS defaults (when TLS lands)
- **Feature completeness** — grow toward classic parity, driven by upstream tests
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
# TCP echo server (PIPE is an echo channel)
./socat TCP4-LISTEN:8080,reuseaddr,fork PIPE

# Client
echo hello | ./socat - TCP4:127.0.0.1:8080

# Unix domain
./socat UNIX-LISTEN:/tmp/echo.sock,fork,unlink-early PIPE
./socat - UNIX-CONNECT:/tmp/echo.sock

# Dual stdio
echo hi | ./socat STDIN!!STDOUT -
```

```text
socat [options] <address> <address>
socat -V | -h[h[h]]
```

Common options: `-d`, `-v`, `-x`, `-b`, `-t`, `-T`, `-u`/`-U`, `-4`/`-6`/`-0`, `--statistics`.

### Address types (current)

| Type | Status |
|------|--------|
| STDIO, STDIN, STDOUT, STDERR, FD | yes |
| PIPE, OPEN, CREATE, GOPEN, SOCKETPAIR | yes |
| TCP / TCP4 / TCP6 + LISTEN | yes |
| UDP (+ LISTEN/SENDTO/RECV/RECVFROM basic) | yes |
| UNIX-CONNECT, UNIX-LISTEN | yes |
| EXEC, SYSTEM, SHELL | basic |
| OPENSSL, SOCKS, PROXY, PTY, … | planned |

### Intentional differences from classic socat

- **`fork`** uses **goroutines**, not `fork(2)` process isolation
- Fewer address options (growing over time)
- Companion tools aim for useful parity, not bit-identical C ifdef output

## Test strategy

Unit/integration tests are written in Go, derived from behaviors in classic **`test.sh`** (~264 named cases).

When a feature is ready, run the **full classic suite** as a scorecard (not in CI yet):

```bash
# obtain classic test.sh (GPL-2), then:
make build
SOCAT=$PWD/socat FILAN=$PWD/filan PROCAN=$PWD/procan bash /path/to/test.sh
```

```bash
go test ./...
go test -tags=e2e ./e2e/...   # after build
```

## Layout

```
cmd/socat   cmd/filan   cmd/procan
internal/parse  internal/addr  internal/relay  internal/cli  internal/logx
e2e/
```

## Prior art

- Classic socat by Gerhard Rieger (GPL-2) — behavior and tests reference  
- [sumup-oss/gocat](https://github.com/sumup-oss/gocat) — performance ideas for TCP↔Unix relays (not a full socat)

## License

MIT — see [LICENSE](LICENSE). This is an independent reimplementation; it does not copy classic socat C sources.
