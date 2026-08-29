# socat (Go)

A Go implementation of [socat](http://www.dest-unreach.org/socat/): a
multipurpose relay for moving data between files, sockets, processes, and
other endpoints.

[![CI](https://github.com/oittaa/socat/actions/workflows/ci.yml/badge.svg)](https://github.com/oittaa/socat/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/oittaa/socat/branch/master/graph/badge.svg)](https://codecov.io/gh/oittaa/socat)
[![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The command line and address syntax follow classic socat except for the
documented differences below. The project supports Linux, macOS, and Windows,
and also includes WebSocket, QUIC, and HTTP/2 and HTTP/3 proxy support.

## Build

Go 1.27 or newer is required.

```bash
make build
```

Without `make`:

```bash
go build -o socat ./cmd/socat
go build -o filan ./cmd/filan
go build -o procan ./cmd/procan
```

## Usage

```text
socat [options] <address> <address>
socat -V | -h | -hh | -hhh
```

Each address has the form `TYPE:parameters,option=value,...`. Use `-` for
standard input and output.

- `socat -h` lists available address types.
- `socat -hh` lists supported options.
- `socat -hhh` also lists aliases and termios names.

Common flags include `-d`, `-v`, `-x`, `-b`, `-t`, `-T`, `-u`/`-U`,
`-4`/`-6`/`-0`, and `--statistics`.

The command output is the authoritative feature list for the current
platform.

### Examples

Connect standard input and output to a TCP service:

```bash
printf 'GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' |
  ./socat - TCP4:127.0.0.1:80
```

Publish a Unix socket over TCP:

```bash
./socat TCP4-LISTEN:5432,reuseaddr,fork \
  UNIX-CONNECT:/var/run/postgresql/.s.PGSQL.5432
```

Expose a TCP service through a Unix socket:

```bash
./socat UNIX-LISTEN:/tmp/app.sock,fork,unlink-early,mode=600 \
  TCP4:127.0.0.1:8080
```

Run an interactive program on a pseudo-terminal:

```bash
./socat -,pty,cfmakeraw EXEC:'python3 -i',setsid,stderr
```

## Address types

The following groups summarize the implemented address families. Run
`socat -h` for the exact names and aliases available on your platform.

| Group | Address types |
|---|---|
| Standard streams and descriptors | `STDIO`, `STDIN`, `STDOUT`, `STDERR`, `FD`; `ACCEPT-FD` on Linux and macOS |
| Files and local I/O | `OPEN`, `CREATE`, `GOPEN`, `PIPE`, `FIFO`, `ECHO`, `SOCKETPAIR`, `TEXT`, `STALL`, `PTY` |
| IP networking | TCP connect/listen, UDP connect/listen/send/receive/datagram, raw IP, generic `SOCKET` |
| Local networking | Unix stream/datagram sockets on Linux and macOS; Linux abstract sockets |
| Processes | `EXEC`, `SYSTEM`, `SHELL` |
| Encryption and proxies | TLS, HTTP CONNECT, SOCKS4/4A/5, SOCKS5 BIND |
| Go extensions | WebSocket (`WS`/`WSS`), QUIC, HTTP/2 and HTTP/3 CONNECT |
| Linux networking | SCTP, VSOCK, TUN/TAP, AF_PACKET `INTERFACE`, POSIX message queues |

Common forms include:

```text
TCP4:host:port                 TCP4-LISTEN:port
UDP4:host:port                 UDP4-RECVFROM:port
UNIX-CONNECT:path              UNIX-LISTEN:path
TLS:host:port                  TLS-LISTEN:port
WS:host:port                   WSS-LISTEN:port
QUIC:host:port                 QUIC-LISTEN:port
EXEC:command                   SYSTEM:shell-command
```

`OPENSSL-*` and `SSL-*` remain aliases for the corresponding TLS addresses.
QUIC is a byte stream over one bidirectional QUIC stream; it is not HTTP/3.

## Options

Address options are written after the address parameters:

```text
TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1
```

Major option groups include:

- listener and socket configuration, timeouts, retry, and peer filters;
- file modes, ownership, locking, seeking, truncation, and unlink behavior;
- process descriptors, PTYs, signals, working directories, and terminal flags;
- IPv4/IPv6, multicast, ancillary data, TUN, and interface settings;
- TLS certificates, verification, protocol versions, ciphers, and SNI;
- proxy, SOCKS, WebSocket, QUIC, and namespace settings;
- transfer conversions such as `cr`, `crnl`, `ignoreeof`, and `readbytes`.

Options are advertised only where they are implemented. Unsupported
platform/address combinations are rejected rather than silently ignored.
Use `socat -hh` instead of this README as the complete option reference.

## TLS and QUIC

TLS listeners require a certificate. `verify=1` is the default; clients use
the system trust store unless `cafile=` or `capath=` is supplied.

```bash
# Create a test certificate with an ECDSA P-256 key.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -sha256 -days 365 -nodes -keyout server.key -out server.crt \
  -subj "/CN=server.example" -addext "subjectAltName=DNS:server.example"

# Publish a local TCP service over TLS.
./socat TLS-LISTEN:8443,reuseaddr,fork,cert=server.crt,key=server.key,verify=0 \
  TCP4:127.0.0.1:8080

# Connect to it and verify the server certificate.
./socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  TLS:server.example:8443,cafile=server.crt,verify=1
```

`verify=0` disables certificate trust and name checks. On a listener it also
disables client-certificate verification.

QUIC uses TLS 1.3 and otherwise accepts the same certificate and verification
options:

```bash
./socat QUIC-LISTEN:4433,reuseaddr,fork,cert=server.crt,key=server.key,verify=0 \
  TCP4:127.0.0.1:8080
```

The default QUIC ALPN is `socat`. Use `alpn=` when both endpoints require a
different value.

## Intentional differences from classic socat

Compatibility is checked against the latest classic socat release and current
master from the [official repository](https://repo.or.cz/socat.git). Public
address and option spellings are audited automatically. The
[scorecard](testdata/scorecard/README.md) tracks the classic `test.sh` suite.

- `fork` sessions use goroutines rather than worker processes.
- Unknown options, malformed values, and unsupported combinations fail
  explicitly instead of becoming no-ops.
- DNS overrides use a per-address resolver and never mutate process-global
  resolver state.
- `ai-v4mapped` is off unless requested, matching classic runtime behavior
  rather than the man-page default. Go dials mapped results as IPv4.
- `handshake-timeout` separately limits TLS, WebSocket, proxy, SOCKS, and QUIC
  negotiation.
- WebSocket, QUIC, and HTTP/2 and HTTP/3 CONNECT are Go-specific extensions.
- TLS listeners fail immediately when `cert=` is missing.
- TLS peer names use `VerifyHostname`; empty `commonname=` skips only the name
  check, and `capath=` loads every parseable certificate file rather than only
  OpenSSL hash-named entries.
- Child descriptor remapping happens in the child, so a failed `EXEC` cannot
  leave the parent process partially remapped.
- Omitted `setpgid`, `setpgid=0`, and `setpgid=1` all create a new process
  group as documented.
- Lock files and unlink-on-close paths are removed only if they still refer to
  the object created by this process.
- Boolean unlink options honor `=0`; they do not delete merely because the
  option was present.
- `ACCEPT-FD` supports `fork`, `range`, `sourceport`, `lowport`, and `tcpwrap`
  matching classic runtime behavior despite the narrower man page. It is
  Linux/macOS only.
- `TUN,retrieve-vlan` is rejected instead of succeeding without restoring VLAN
  tags; `retrieve-vlan` is supported on Linux `INTERFACE` addresses.
- Windows rejects simultaneously enabled `binary` and `text` modes instead of
  relying on an unspecified conversion order.
- Generic ioctl request and integer values outside their 32-bit range are
  rejected instead of wrapping into a different operation.
- Multicast membership rejects unresolved interface names instead of falling
  back to an unintended interface.
- On macOS, SIGILL follows the Go runtime's fatal-signal behavior rather than
  the classic caught-signal exit code.

## Unsupported / security-related

Unsupported names are omitted from help and rejected if used. They are not
silently emulated with a different protocol.

| Feature | Status |
|---|---|
| DCCP and UDP-Lite | Not supported. Both were removed from modern Linux kernels and have no native macOS or Windows equivalent. |
| GNU readline address | Not implemented. |
| DTLS | Not available through Go's stream-oriented `crypto/tls`. |
| DSA, SSLv3, and weak TLS ciphers | Rejected; use current TLS versions and RSA, ECDSA, Ed25519, or ML-DSA keys. |
| OpenSSL engines, FIPS mode, EGD, pseudo-random mode, custom DH parameters, and fragment controls | Enabling these features is rejected where Go's TLS stack has no equivalent. |
| Process-wide `setuid`, `setgid`, `chroot`, and `substuser` options | Not implemented because changing credentials or root from a goroutine would affect every session. They require process isolation. |
| Process-global libc resolver flags | Not implemented. `res-nsaddr` and `res-usevc` are supported per address. |
| Read-only, obsolete, or structurally unsafe socket options | Rejected rather than advertised as setters. This includes get-only socket state and options that require structures the classic integer syntax cannot represent safely. |
| `ip-recverr` / `ipv6-recverr` | Not advertised because the relay does not consume the kernel error queue. |
| `udp-ignore-peerport` | Not implemented because classic documents the name but does not expose or implement it. UDP datagram receive behavior follows the working classic implementation. |

Go's TLS defaults also intentionally keep TLS compression disabled. The
accepted `openssl-compress=none` spelling can be used by compatible command
lines; enabling compression is rejected.

## Environment

The main classic environment inputs are supported, including
`SOCAT_DEFAULT_LISTEN_IP`, `SOCAT_PREFERRED_RESOLVE_IP`,
`SOCAT_MAIN_WAIT`, `SOCAT_TRANSFER_WAIT`, and `SOCAT_FORK_WAIT`.

Child processes receive `SOCAT_*` connection metadata. TLS metadata is exposed
as `SOCAT_TLS_*`, with `SOCAT_OPENSSL_*` aliases for compatible scripts.

## Testing

```bash
make check              # platform policy, lint, security, unit, and e2e tests
make test               # formatting and unit tests
make e2e                # local end-to-end tests
make test-netns-docker  # privileged Linux namespace and raw-IP tests
make classic-parity     # native Go vs official release and reviewed master
```

`make check` does not contact repo.or.cz. `make classic-parity` does: it
syncs the official repository into a gitignored working directory.

CI runs unit and end-to-end tests on Linux amd64/arm64, macOS, and Windows
amd64/arm64. Weekly jobs run fuzzing and the live relay matrix. Official
classic parity is weekly and manual only.

Classic `test.sh` is run separately because hosted CI cannot provide every
required kernel feature and privilege. Results and reproduction instructions
are in [testdata/scorecard/README.md](testdata/scorecard/README.md).

## Examples and benchmarks

- [Docker Compose lab](examples/lab/README.md): TLS, QUIC, WSS, HTTP, and
  SOCKS examples (`make lab`).
- [Benchmarks](testdata/bench/README.md): optional loopback comparisons with
  classic socat (`make bench`).
- `go run ./scripts/fuzzall`: local parser and protocol fuzz campaigns.

## Repository layout

```text
cmd/                  socat, filan, and procan commands
internal/parse/       address and option parsing
internal/xio/         endpoint implementations
internal/relay/       transfer engine
e2e/                  end-to-end tests
examples/lab/         container examples
testdata/scorecard/   classic compatibility results
testdata/bench/       benchmark snapshots
```

## License

MIT. See [LICENSE](LICENSE).

This is an independent reimplementation and does not copy classic socat's C
sources.
