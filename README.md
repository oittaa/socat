# socat (Go)

A modern [Go](https://go.dev) reimplementation of classic [socat](http://www.dest-unreach.org/socat/) — a multipurpose relay for bidirectional data transfer between two independent channels.

[![CI](https://github.com/oittaa/socat/actions/workflows/ci.yml/badge.svg)](https://github.com/oittaa/socat/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/oittaa/socat/branch/master/graph/badge.svg)](https://codecov.io/gh/oittaa/socat)
[![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Module:** `github.com/oittaa/socat`
**Status:** actively developed — classic `test.sh` compatibility is tracked by the
[scorecard](testdata/scorecard/README.md), and Go-only extras (WS/WSS, QUIC,
HTTP/2·3 proxy) ship alongside.

## Table of contents

- [Goals](#goals)
- [Build](#build)
- [Usage](#usage)
- [Encrypt a legacy TCP service](#encrypt-a-legacy-tcp-service)
- [Address types](#address-types)
- [Options](#options)
- [TLS notes](#tls-notes)
- [Intentional differences from classic socat](#intentional-differences-from-classic-socat)
- [Unsupported / security-related](#unsupported--security-related)
- [Environment compatibility](#environment-compatibility)
- [Test](#test)
- [Examples / lab](#examples--lab)
- [Benchmarks](#benchmarks)
- [Layout](#layout)
- [Prior art](#prior-art)
- [License](#license)

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

```text
socat [options] <address> <address>
socat -V | -h | -hh | -hhh
```

Each `<address>` is `TYPE:params,option=value,...`. Use `-` for STDIO.
Common flags: `-d`, `-v`, `-x`, `-b`, `-t`, `-T`, `-u`/`-U`, `-4`/`-6`/`-0`, `--statistics`.
`./socat -h` lists types. `./socat -hh` lists honored options.

```bash
# TCP client from the shell (netcat-style). Talk to any existing service.
printf 'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' | ./socat - TCP4:127.0.0.1:80

# Local app only binds a Unix socket; publish it on TCP for another process or host.
# Example path is PostgreSQL; same shape works for docker.sock, mysqld, …
./socat TCP4-LISTEN:5432,reuseaddr,fork \
  UNIX-CONNECT:/var/run/postgresql/.s.PGSQL.5432

# Reverse: the app wants a Unix socket; the service already listens on TCP.
./socat UNIX-LISTEN:/tmp/app.sock,fork,unlink-early,mode=600 \
  TCP4:127.0.0.1:8080

# Give a program a real TTY (REPLs, pagers, and many CLIs disable features without one).
./socat -,pty,cfmakeraw EXEC:'python3 -i',setsid,stderr
```

## Encrypt a legacy TCP service

The application still speaks **plain TCP**. Socat sits in front and does TLS
or QUIC. Typical cases: an old HTTP server, SMTP, a database port, or any
custom protocol that has no encryption of its own.

```bash
# One-time self-signed cert (or use a real certificate + CA)
openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
  -keyout server.key -out server.crt -subj "/CN=server.example"

# Server host: publish TLS :8443; the app keeps listening on 127.0.0.1:8080
./socat TLS-LISTEN:8443,reuseaddr,fork,cert=server.crt,key=server.key,verify=0 \
  TCP:127.0.0.1:8080

# Client host: the app connects to 127.0.0.1:8080; socat does the TLS hop
./socat TCP-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  TLS:server.example:8443,cafile=server.crt,verify=1
```

`OPENSSL-*` and `SSL-*` are aliases of `TLS-*`. Listen needs `cert=`
(see [TLS notes](#tls-notes)). `verify=0` on the listener means “do not
request a client certificate”. The client still checks the server when
`verify=1` — against `cafile=`/`capath=` when given, otherwise against the
system trust store.

Same shape over **QUIC** (a byte pipe, **not** HTTP/3; ALPN default `socat`):

```bash
# Server
./socat QUIC-LISTEN:4433,reuseaddr,fork,cert=server.crt,key=server.key,verify=0 \
  TCP:127.0.0.1:8080

# Client
./socat TCP-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  QUIC:server.example:4433,cafile=server.crt,verify=1
```

A two-container walk-through is in [examples/lab/README.md](examples/lab/README.md).

## Address types

Implemented types only. Aliases share a row. `./socat -h` prints syntax for
every name. DCCP and readline are not implemented (see
[Unsupported / security-related](#unsupported--security-related)).

| Type | Syntax | Notes |
|------|--------|--------|
| STDIO | `-` or `STDIO` | stdin and stdout together |
| STDIN, STDOUT, STDERR | `STDIN` / `STDOUT` / `STDERR` | one standard stream |
| FD | `FD:<n>` | already-open file descriptor |
| OPEN, FILE | `OPEN:<path>` | open a file |
| CREATE, CREAT | `CREATE:<path>` | create or truncate |
| GOPEN | `GOPEN:<path>` | open or create a file or socket |
| PIPE, FIFO, ECHO | `PIPE` or `PIPE:<path>` | anonymous pipe or named FIFO |
| SOCKETPAIR | `SOCKETPAIR` | unnamed UNIX socket pair |
| TEXT | `TEXT:<string>` | write a fixed string, then EOF |
| STALL | `STALL` | block writes (full-pipe backpressure) |
| PTY | `PTY` | allocate a pseudo-terminal |
| TCP | `TCP4:host:port`, `TCP6:…` | TCP client; `SO_REUSEADDR` default on |
| TCP-LISTEN | `TCP4-LISTEN:port` (`-L`) | TCP server; `accept-timeout` exits 0 |
| UDP | `UDP4:host:port`, `UDP6:…` | UDP client |
| UDP-LISTEN / SENDTO / RECV / RECVFROM / DATAGRAM | `UDP4-LISTEN:port`, `UDP4-SENDTO:host:port`, … | peer filters on recv/listen |
| IP (raw) | `IP4-SENDTO:host:proto`, `IP4-RECV:proto`, … | Linux raw IP; needs privilege |
| UNIX | `UNIX-CONNECT:<path>` / `UNIX-CLIENT` | UNIX-domain stream, Linux seqpacket, or generic client |
| UNIX-LISTEN | `UNIX-LISTEN:<path>` (`-L`) | UNIX-domain stream or Linux seqpacket server |
| UNIX datagram | `UNIX-SENDTO` / `RECV` / `RECVFROM` / `DATAGRAM` | UNIX datagram on Unix platforms (not Windows) |
| ABSTRACT | `ABSTRACT-CONNECT` / `LISTEN` / … | Linux abstract UNIX namespace |
| SOCKET | `SOCKET-CONNECT` / `LISTEN` / `SENDTO` / `DATAGRAM` / `RECV` / `RECVFROM` | generic socket |
| EXEC, SYSTEM, SHELL | `EXEC:<cmd>` / `SYSTEM:<sh>` / `SHELL` | pipes, socketpair, **pty**, fdin/fdout, setsid, shut-none; child exit promoted |
| TLS | `TLS:host:port`, `TLS-CONNECT:host:port` | stream TLS (`crypto/tls`); **not** DTLS |
| TLS-LISTEN | `TLS-LISTEN:<port>` (`-L`) | requires `cert=`; aliases `OPENSSL-*`, `SSL-*` |
| PROXY | `PROXY:<proxy>:<host>:<port>` | HTTP CONNECT; `http-version=2` / `3`, `h2c` |
| SOCKS4, SOCKS4A, SOCKS5 | `SOCKS5:<socks>:<host>:<port>` | SOCKS clients |
| SOCKS5-LISTEN, SOCKS5-BIND | `SOCKS5-LISTEN:<socks>:<host>:<port>` | SOCKS5 BIND (remote listen) |
| TUN, INTERFACE | `TUN` / `INTERFACE:<if>` | Linux TUN/TAP + AF_PACKET; need `CAP_NET_ADMIN` |
| WS, WSS | `WS:host:port`, `WSS-LISTEN:port`, … | WebSocket byte relay (Go extra) |
| QUIC | `QUIC:host:port`, `QUIC-LISTEN:port` | RFC 9000 byte pipe (Go extra); **not** HTTP/3 |
| SCTP | `SCTP4:host:port`, `SCTP4-LISTEN:port` | Linux one-to-one SCTP; needs `sctp` module |
| POSIXMQ | `POSIXMQ-READ:/q`, `POSIXMQ-SEND:/q` | Linux POSIX message queues |

## Options

These are **address** options (`TYPE:params,option=value`), not CLI flags.
`./socat -hh` lists every honored name (authoritative). `./socat -hhh` adds
aliases and termios / baud names.

| Area | Options |
|------|---------|
| Listen / connect | `reuseaddr`, `so-reuseport`, `fork`, `max-children`, `bind`, `connect-timeout`, `accept-timeout`, `listen-timeout`, `pf`, `ai-addrconfig`, `ipv6-v6only`, `backlog`, `so-linger`/`linger`, `setsockopt-listen` / `sockopt-listen`, `setsockopt` |
| Security filters | `range`, `sourceport`/`sp` (listen = peer filter; connect = bind), `lowport`, `tcpwrap` / `libwrap` / `hosts-allow` / `hosts-deny` / `tcpwrap-etc` |
| TUN / INTERFACE | `tun-name`, `tun-type`, `tun-device`, `iff-up`, `iff-no-pi`, `if-mtu` / `interface-mtu`, other `iff-*` flags |
| Files | `rdonly`, `wronly`, `creat`, `excl`, `append`, `trunc`, `mode`, `perm`, `umask`, `nonblock`, `o-noatime`/`noatime`, `f-setpipe-sz`/`pipesz` (Linux), `setlk` / `setlkw` (read/write variants) |
| UNIX | `unlink-early`, `unlink-close`, `unix-bind-tempname` / `bind-tempname`, `socktype` / `so-type` |
| POSIX MQ | `mq-prio` / `posixmq-priority`, `mq-flush`, `mq-maxmsg`, `mq-msgsize` |
| EXEC / PROCESS | `pipes`, `pty`, `fdin`, `fdout`, `setsid`, `stderr`, `shut-none`, `shut-close`, `children-shutup`/`child-shutup`, `chdir`, `umask` (child inherits, then parent restores) |
| PTY / TERMIOS | `link`, `cfmakeraw`/`raw`/`rawer`, `echo`, `opost`, baud/`ispeed`/`ospeed`, `tiocswinsz`, `pty-wait-slave`, `ctty`; restore tty on close |
| Transfer | `crnl`, `crlf`, `ignoreeof`, `readbytes`, `retry`/`forever`/`interval` |
| TLS | `cert`, `key`, `cafile`/`ca`, `capath`, `verify`, `commonname`, `snihost`, `nosni`, `ciphers`, `openssl-min-proto-version`/`min-version`, `openssl-max-proto-version`/`max-version` (also classic `cipher`, `openssl-*`, and `tls-*` aliases) |
| WebSocket | `path`, `origin`, `protocol` (binary frames; WSS reuses TLS options) |
| QUIC | `alpn` (default `socat`; not `h3`); reuses TLS options; one bidirectional stream |
| PROXY / SOCKS | `proxyport`, `http-version` (`1.0`/`1.1`/`2`/`3`), `h2c`, `proxy-authorization` / `proxy-authorization-file`, `socksport`, `socksuser` |
| Namespaces | `netns=` (Linux `WITH_NAMESPACES`; one address open; root/`CAP_SYS_ADMIN`; `--experimental`) |

**`max-children`:** limits concurrent `fork` sessions on **LISTEN** and on **CONNECT** / **TLS-CONNECT** client reconnect loops. Requires `fork`. Parent redials after `interval` (default 1s).

**`perm=` / `mode=`:** after create/open, `chmod`/`fchmod` sets the exact mode (classic NAMED group). **`umask=`** applies only during open (or child `Start` for EXEC/SHELL), then restores.

## TLS notes

- **Stream TLS only** — see [Unsupported / security-related](#unsupported--security-related) for DTLS.
- **Listen requires `cert=`** — `TLS-LISTEN`, `WSS-LISTEN`, and `QUIC-LISTEN` refuse to start without `cert=`. Classic `OPENSSL-LISTEN` warns (`no certificate given; consider option "cert"`), binds, then `SSL_accept` fails (`no shared cipher`). We fail at open instead of inventing a dummy certificate. Classic `V1800_OPENSSL_LISTEN_*` (bind/range only) and `ciphers=aNULL` without `cert=` therefore fail here.
- **No DSA** — see [Unsupported / security-related](#unsupported--security-related).
- **Version bounds** — `openssl-min-proto-version` / `openssl-max-proto-version` accept `TLS1.0`–`TLS1.3`. QUIC requires TLS 1.3 (RFC 9001); a lower maximum is rejected at address open instead of failing mid-handshake.
- **`ciphers=` / `cipher=`** — accepts colon-, comma-, or whitespace-separated secure TLS 1.2 suite names in OpenSSL or Go form. TLS 1.3 suites remain Go-managed, matching OpenSSL's separation between its legacy cipher list and TLS 1.3 cipher suites. Weak, obsolete, and unknown names are rejected.
- **`verify` (TLS, WSS, QUIC)** — default on. `verify=0` skips trust and name checks. `verify=1` uses `crypto/x509` (not OpenSSL `SSL_get_verify_result`). With no `cafile`/`capath`, the **system** CA pool is used on both client and listen (classic `SSL_CTX_set_default_verify_paths`).
- **`capath`** — directory of CA certificates (PEM or DER). We load every regular file that parses as a certificate, including OpenSSL hashed names and symlinks. Classic OpenSSL only looks up hashed names.
- **Peer name** — [RFC 6125](https://www.rfc-editor.org/rfc/rfc6125) via Go `Certificate.VerifyHostname` (case-insensitive, modern wildcard rules). Classic OPENSSL address types use `strcmp` and treat `*.example.com` as a match for `example.com`. For old test certs with no SAN, we still accept a CN match. No `commonname` → check the dial host. `commonname=foo` → check `foo`. Empty `commonname=` → skip the name check (classic). `verify=1` still checks trust. `verify=0` skips name and trust.
- **Post-quantum key exchange** — Go 1.24+ `crypto/tls` defaults to hybrid **X25519MLKEM768**. We inherit that. Classic `test.sh` has no PQC tests; we cover PQC in unit/e2e tests.
- **Multi-address connect** — try every resolved address; log `opening connection to AF=…`; match `bind=` to remote family; `-4`/`-6` reorder dual-stack results.
- **IPv6 peer filters** on `TLS-LISTEN`: `range`, `sourceport`, `lowport` (CN check accepts `::1` vs `[::1]`).

## Intentional differences from classic socat

- **WebSocket (WS/WSS)** is a Go extra (classic has no WS). Uses `github.com/coder/websocket` (`NetConn` + binary frames), not frozen `golang.org/x/net/websocket`.
- **QUIC** is a Go extra (classic has no QUIC). Uses `github.com/quic-go/quic-go` (same stack as HTTP/3 CONNECT). One **client-initiated** bidirectional stream as a byte pipe. A receive-only client (`-u`/`-U`) still opens that stream and half-closes write so the listener can send. Not HTTP/3 (`alpn` default `socat`). 0-RTT is off.
- **PROXY `http-version=2` / `3`** is a Go extra (classic PROXY is HTTP/1.x). HTTP/2 uses `net/http`. HTTP/3 uses `github.com/quic-go/quic-go/http3` because `golang.org/x/net/http3` is not a public client API.
- **`fork`** uses **goroutines**, not `fork(2)` process isolation
- Companion tools aim for useful parity, not bit-identical C ifdef output
- Unknown options and malformed option values are rejected instead of being silently ignored
- Security-deprecated crypto (DSA, DTLS, etc.) is documented above rather than forced in
- **TLS listen without `cert=`** fails at start (classic warns, listens, then handshake fails). See [TLS notes](#tls-notes).
- **TLS address names** are `TLS` / `TLS-CONNECT` / `TLS-LISTEN`. `OPENSSL*` and `SSL*` remain aliases so classic command lines still work.

## Unsupported / security-related

We do **not** re-implement features that Go’s standard libraries removed or never offered for security (or crypto-policy) reasons. Prefer modern alternatives.

| Topic | Status | Why / reference |
|-------|--------|------------------|
| **DSA certificates / keys** | Rejected | DSA is obsolete; Go `crypto/tls` does not parse DSA keys. Classic `OPENSSLLISTENDSA` fails by design. Use RSA, ECDSA, or Ed25519. See [Go crypto/tls](https://pkg.go.dev/crypto/tls) and [NIST SP 800-57 / deprecation of DSA](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final). |
| **DCCP, readline** | Not implemented | `#undef` in `-V`. No DCCP or GNU readline address type. |
| **DTLS** | Not implemented | Not available in Go `crypto/tls` (stream TLS only). `openssl-method=DTLS*` is rejected instead of silently using TCP TLS. See [crypto/tls package docs](https://pkg.go.dev/crypto/tls). |
| **SSLv3 / weak ciphers** | Not offered | Go TLS defaults reject obsolete protocols/ciphers. Unsupported `openssl-method=` selections are rejected. See [Go TLS cipher suites](https://go.dev/blog/tls-cipher-suites) and [crypto/tls Config](https://pkg.go.dev/crypto/tls#Config). |
| **libwrap / TCP wrappers** | Implemented (pure Go) | No CGO/libwrap0; reads `hosts.allow`/`hosts.deny` (or `tcpwrap-etc=`). Subset: daemon ALL/name, client ALL/IP/hostname/`[ipv6]`. |

## Environment compatibility

- Inputs: `SOCAT_DEFAULT_LISTEN_IP`, `SOCAT_PREFERRED_RESOLVE_IP`, `SOCAT_MAIN_WAIT`, `SOCAT_TRANSFER_WAIT`, and `SOCAT_FORK_WAIT` are supported. `HOSTNAME` supplies `-lh`; SOCKS4 uses `LOGNAME`, then `USER`, when `socksuser=` is absent; `SHELL` is used by the `SHELL` address.
- Child outputs: `SOCAT_VERSION`, `SOCAT_PID`, `SOCAT_PPID`, socket/peer address and port variables, ancillary packet variables, and Linux `SOCAT_POSIXMQ_PRIO` are supported. With `-lp`, matching upper-case program-name variables are emitted as well while `SOCAT_*` names remain compatibility aliases.
- TLS outputs use `SOCAT_TLS_*`, including protocol, cipher, peer subject fields, and DNS/IP subjectAltName values. Equivalent `SOCAT_OPENSSL_*` names are emitted as aliases for classic socat and existing scripts.

## Test

```bash
make check         # complete pre-commit: lint, gosec, unit tests, and e2e
make test          # gofmt + unit tests
make e2e           # after build; local processes on 127.0.0.1
make test-netns-docker  # root netns= tests in a privileged container
make lint          # gofmt, go vet, golangci-lint, gosec
```

Per-commit CI runs lint, gosec, unit tests, and e2e on Linux amd64/arm64,
macOS, and Windows amd64/arm64. linux-amd64 uploads unit and e2e coverage
to [Codecov](https://codecov.io/gh/oittaa/socat) (file-level reports and
PR comments) and as HTML artifacts. A weekly workflow additionally runs
native fuzz campaigns and the live relay matrix, and can be dispatched
manually.

Parser fuzz campaigns and the live relay matrix also run locally:

```bash
go run ./scripts/fuzzall                 # 30s per parser / protocol-byte target
go run ./scripts/fuzzall -fuzztime=5m
make fuzz FUZZTIME=5m                    # same; needs make
go test -tags=e2e,relaymatrix -run TestRelayMatrix ./e2e/ -count=1 -timeout=10m
make fuzz-matrix                         # same after make build
```

`scripts/fuzzall` works on Linux, macOS, and Windows (`go run`). It skips unix-only targets on Windows. Generated corpus stays in `testdata/fuzz/` (gitignored). If a campaign finds a crash, add a minimized `f.Add(...)` seed and fix the bug.

The relay matrix is not every address pair. It covers enabled byte-pipe families (TCP4, UNIX, TLS, WS, QUIC, SCTP when the kernel allows it) in three directions, plus FILE, one UDP one-way case, and a few TCP bridges. Skip EXEC, TUN, RAWIP, PROXY/SOCKS, and POSIXMQ here.

Classic `test.sh` is not in GitHub CI (runners are sandboxed). Compatibility
is tracked with the scorecard instead:
[testdata/scorecard/README.md](testdata/scorecard/README.md).

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

Optional loopback measures against classic C socat. See
[testdata/bench/README.md](testdata/bench/README.md).
Reproduce: `make bench` (set `CLASSIC_SOCAT` for classic columns).

## Layout

```
cmd/socat   cmd/filan   cmd/procan
internal/parse  internal/xio/{netopen,tlsopen,proxyopen,fileopen,tunopen,all}
internal/relay  internal/cli  internal/logx
scripts/classic-scorecard.sh  scripts/scorecard-parse.py  scripts/scorecard-compare.py
scripts/bench.sh              # optional loopback benches
scripts/fuzzall               # optional local parser fuzz campaigns
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
