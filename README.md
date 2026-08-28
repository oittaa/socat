# socat (Go)

A modern [Go](https://go.dev) reimplementation of classic [socat](http://www.dest-unreach.org/socat/) — a multipurpose relay for bidirectional data transfer between two independent channels.

[![CI](https://github.com/oittaa/socat/actions/workflows/ci.yml/badge.svg)](https://github.com/oittaa/socat/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/oittaa/socat/branch/master/graph/badge.svg)](https://codecov.io/gh/oittaa/socat)
[![Go](https://img.shields.io/badge/Go-1.27%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
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

Requires **Go 1.27+** (the `toolchain` directive will fetch it if needed):

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

Implemented types only. Directly registered names (including `TCP-L` style
spellings) share a `-h` row. Classic `addressnames[]` aliases of those types
(`INET`, `LOCAL`, `UDP-DGRAM`, …) open the canonical type and appear in
`./socat -hhh` as `alias of <canonical>`. DCCP and readline are not implemented (see
[Unsupported / security-related](#unsupported--security-related)).

| Type | Syntax | Notes |
|------|--------|--------|
| STDIO | `-` or `STDIO` | stdin and stdout together |
| STDIN, STDOUT, STDERR | `STDIN` / `STDOUT` / `STDERR` | one standard stream |
| FD | `FD:<n>` | already-open file descriptor |
| ACCEPT-FD, ACCEPT | `ACCEPT-FD:<fdnum>` | accept on an inherited **listening** socket (Unix; systemd `inetd` / `ExtraFiles`). Public alias `ACCEPT`. Honors `fork`, `range`, `sourceport`, `lowport`, `tcpwrap`. Not advertised on Windows. Man/C group mismatch: [Intentional differences](#intentional-differences-from-classic-socat) |
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
| UDPLITE | `UDPLITE4:host:port`, `UDPLITE4-LISTEN:port`, … | Linux UDP-Lite (`IPPROTO_UDPLITE`); `udplite-send-cscov` / `udplite-recv-cscov` |
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
| VSOCK | `VSOCK-CONNECT:<cid>:<port>`, `VSOCK-LISTEN:<port>` | Linux AF_VSOCK stream (`x/sys/unix`; no extra module). Loopback is CID `1`. Listen port `0` matches classic (`EACCES`); ephemeral listen is `VSOCK-LISTEN:-1` |
| POSIXMQ | `POSIXMQ-READ:/q`, `POSIXMQ-SEND:/q` | Linux POSIX message queues |

## Options

These are **address** options (`TYPE:params,option=value`), not CLI flags.
`./socat -hh` lists every honored name (authoritative). `./socat -hhh` adds
aliases and termios / baud names.

| Area | Options |
|------|---------|
| Listen / connect | `reuseaddr` (TCP listen default on; UDP-LISTEN / UDPLITE-LISTEN with `fork` or this option), `so-reuseport`, `fork`, `max-children`, `bind`, `connect-timeout`, `handshake-timeout` (Go extra; TLS/WS/QUIC/PROXY/SOCKS), `accept-timeout`, `listen-timeout`, `pf`, `ai-addrconfig`, `ipv6-v6only`, `backlog`, `so-linger`/`linger`, `sndbuf`/`so-sndbuf`, `rcvbuf`/`so-rcvbuf`, `sndbuf-late`/`so-sndbuf-late`, `rcvbuf-late`/`so-rcvbuf-late`, `bindtodevice`/`so-bindtodevice`/`if`/`interface` (Linux), `so-debug`/`debug`, `so-dontroute`/`dontroute`, `so-oobinline`/`oobinline`, `so-priority`/`priority`, `so-passcred`/`passcred`, `so-no-check`/`no-check`/`nocheck` (Linux), `tcp-cork`/`cork`, `tcp-defer-accept`/`defer-accept`, `tcp-linger2`/`linger2`, `tcp-maxseg`/`maxseg`/`mss` (PH_PASTSOCKET), `tcp-maxseg-late`/`maxseg-late`/`mss-late` (PH_CONNECTED), `tcp-quickack`/`quickack`, `tcp-syncnt`/`syncnt`, `tcp-window-clamp`/`window-clamp` (Linux TCP_* except `tcp-maxseg`, which is also honored on other Unix), `sctp-nodelay` / `sctp-maxseg` (Linux SCTP, `PH_PASTSOCKET`; not `TCP_NODELAY`), `udplite-send-cscov` / `udplite-recv-cscov` (Linux UDP-Lite, `PH_FD`), `setsockopt` / `sockopt` (PH_CONNECTED, dalan value), `setsockopt-int` / `sockopt-int`, `setsockopt-bin` / `sockopt-bin`, `setsockopt-string` / `sockopt-string`, `setsockopt-connected` / `sockopt-conn`, `setsockopt-socket` / `sockopt-sock` (PH_PASTSOCKET), `setsockopt-listen` / `sockopt-listen` (PH_PREBIND) |
| Security filters | `range`, `sourceport`/`sp` (listen = peer filter; connect/SENDTO = bind; DATAGRAM = dest-port receive filter, not local bind), `lowport`, `tcpwrap` / `libwrap` / `hosts-allow` / `hosts-deny` / `tcpwrap-etc` |
| TUN / INTERFACE | `tun-name`, `tun-type`, `tun-device`, `iff-up`, `iff-no-pi`, `if-mtu` / `interface-mtu`, other `iff-*` flags |
| Files | `rdonly`, `wronly`, `rdwr`, `creat`, `excl`, `append`/`o-append` (open(2) on FILE/OPEN/CREATE/GOPEN; `fcntl` `O_APPEND` on FD/STDIO/EXEC/sockets, including `append=0` to clear), `trunc`, `ftruncate`/`truncate`/`ftruncate32`/`ftruncate64` (regular files only), `lseek`/`lseek64`/`seek`/`lseek32` and `-cur`/`-end`/`-set` variants (regular files; applied in command-line order), `perm`/`mode`, `perm-late`, `user`/`uid`/`owner`, `user-late`/`uid-l`, `group`/`gid`, `group-late`/`gid-l`, `perm-early`, `user-early`/`uid-e`, `group-early`/`gid-e` (pre-open chmod/chown of an existing OPEN/CREATE/GOPEN/PIPE name, and chmod/chown of a UNIX socket after bind), `umask`, `nonblock`, Windows `binary`/`bin`/`o-binary`, `text`/`o-text`, `noinherit`/`o-noinherit`, `o-direct`/`direct` (Linux), `o-sync`/`sync`, `o-dsync`/`dsync`, `o-rsync`/`rsync` (Linux), `o-noctty`/`noctty`, `o-nofollow`/`nofollow`, `o-directory`/`directory`, `o-largefile`/`largefile`, `async`/`o-async`, `o-noatime`/`noatime`, Linux `FS_IOC_*` flags `fs-append` (not `O_APPEND`), `fs-compr`, `fs-dirsync`, `fs-immutable`, `fs-journal-data`, `fs-noatime`, `fs-nodump`, `fs-notail`, `fs-secrm`, `fs-sync`, `fs-topdir`, `fs-unrm` (and classic `ext2-*`/`ext3-*`/short aliases), `unlink-early`, `unlink`/`delete`/`remove`, `unlink-late`, `unlink-close`, `f-setpipe-sz`/`pipesz` (Linux), `setlk` / `setlkw` (read/write variants), `flock`/`flock-ex` / `flock-nb`/`flock-ex-nb` / `flock-sh` / `flock-sh-nb`, `ioctl-void`/`ioctl`, `ioctl-int`, `ioctl-intp`, `ioctl-bin`, `ioctl-string` (Unix generic ioctl at `PH_FD`) |
| UNIX | `unlink-early` (required to replace a leftover path; `reuseaddr` does not unlink), `unlink-close`, `unix-bind-tempname` / `bind-tempname`, `unix-tightsocklen` / `tightsocklen` (classic `xiosetunix` socklen for both modes; default tight except FreeBSD/OpenBSD; Windows hides and rejects the option), `socktype` / `so-type` |
| POSIX MQ | `mq-prio` / `posixmq-priority`, `mq-flush`, `mq-maxmsg`, `mq-msgsize` |
| EXEC / PROCESS | `pipes`, `pty`, `fdin`, `fdout`, `setsid`, `stderr`, `shut-none`, `shut-down`, `shut-close`, `shut-null`, `children-shutup`/`child-shutup`, `chdir`, `umask` (child inherits, then parent restores), `sighup`/`sigint`/`sigquit` (pass that signal to the child instead of exiting) |
| PTY / TERMIOS | `link`, `cfmakeraw` (distinct from `raw`), `raw`, `rawer`, `sane`, complete Linux flags and fields (`icanon`, `crtscts`, `nl0`/`nl1`, `nldly`, `crdly`, `csize`, `iuclc`, `pendin`, …), control characters (`vintr`/`intr`, `vswtc`/`swtch`, …), `termios-setflags`, baud/`ispeed`/`ospeed` (including Linux `b7200` through `BOTHER`), `tiocswinsz`, `pty-wait-slave`, `ctty`; restore tty on close. Applied in command-line order at classic `PH_FD`. Windows rejects GROUP_TERMIOS options instead of no-op. |
| Transfer | `cr`, `crnl`, `crlf`, `crorlf` (Go extra), `ignoreeof`, `readbytes`, `retry`/`forever`/`interval` |
| IP send | `ip-ttl`/`ttl`/`ipttl`, `ip-tos`/`tos`/`iptos`, `ip-options`/`ipoptions`, `ipv6-unicast-hops`, `ipv6-tclass` on TCP, UDP, raw IP, SCTP, TLS/WS/PROXY, and QUIC’s UDP PacketConn. `ip-ttl`/`ip-tos` use `SOL_IP`; family mismatches and Windows-unimplemented send opts error |
| IP multicast / MTU | `ip-multicast-if`/`multicast-if`, `ip-multicast-loop`/`mcloop`, `ip-multicast-ttl`/`multicast-ttl` (`PH_PASTSOCKET`, `SOL_IP`), `ipv6-multicast-loop`/`mcloop6` (`GROUP_IP6`), IPv4 `ip-add-source-membership`/`source-membership`, IPv6 `ipv6-join-source-group`/`join-source-group`. Linux `ip-freebind` (`PH_PASTSOCKET`), `ip-transparent` (`PH_PREBIND`), and `ip-mtu-discover`/`mtudiscover` plus `ipv6-mtu-discover`/`mtudiscover6` (`0..2`, `PH_PASTSOCKET`). Other platforms reject unsupported Linux-only options rather than no-op. `ip-recverr`/`ipv6-recverr` are recognized and rejected (no `MSG_ERRQUEUE` ReadMsg path) |
| IP recv ancillary | `so-timestamp`, `ip-pktinfo`/`ippktinfo`, `ip-recvttl`/`iprecvttl`/`ip-recvtos`/`ip-recvopts`, `ipv6-recvpktinfo`/`ipv6-recvhoplimit`/`ipv6-recvtclass` on Unix UDP and raw IP (`ReadMsg`). Rejected on TCP/QUIC/stream sockets, Windows, and the wrong IP family instead of being accepted as no-ops |
| TLS | `cert`/`certificate`/`openssl-certificate`, `key`/`openssl-key`, `cafile`/`ca`/`openssl-cafile`, `capath`, `verify`/`openssl-verify`, `commonname`/`cn`, `snihost`, `nosni`/`no-sni`, `ciphers`/`cipher`/`cipherlist`, `openssl-compress=none`/`compress=none`, `openssl-min-proto-version`/`min-proto-version`/`min-version`, `openssl-max-proto-version`/`max-proto-version`/`max-version` (also classic `openssl-*` and Go `tls-*` aliases of the same options) |
| WebSocket | `path`, `origin`, `protocol` (binary frames; WSS reuses TLS options) |
| QUIC | `alpn` (default `socat`; not `h3`); reuses TLS options; one bidirectional stream |
| PROXY / SOCKS | `proxyport`, `http-version` (`1.0`/`1.1`/`2`/`3`), `h2c`, `proxy-authorization` / `proxy-authorization-file`, `socksport`, `socksuser` |
| Namespaces | `netns=` (Linux `WITH_NAMESPACES`; one address open; root/`CAP_SYS_ADMIN`; `--experimental`) |

**`max-children`:** limits concurrent `fork` sessions on **LISTEN** and on **CONNECT** / **TLS-CONNECT** client reconnect loops. Requires `fork`. Parent redials after `interval` (default 1s).

**`sighup` / `sigint` / `sigquit`:** classic `GROUP_PARENT` / `PH_LATE` / `TYPE_CONST` / `OFUNC_SIGNAL` (`xio-progcall.c` / `xioopts.c` / `xiosignal.c`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). After the EXEC/SYSTEM/SHELL child pid is known, each occurrence registers that pid. The four-slot limit (`SOCAT_MAXPIDS`) is per logical session (classic per-process table); further registrations on that session fail with classic `too many sub processes registered for signal N`. A later SIGHUP/SIGINT/SIGQUIT is `kill`'d to every live registered pid and socat keeps running (`socatsignalpass`) while any pid remains. With no registered pids, socat still exits `128+n`. Assignments (`sighup=0`) are `no value permitted`. CLI rejects these on non-PARENT addresses. Windows hides the names with EXEC. See [Intentional differences](#intentional-differences-from-classic-socat) for goroutine `fork` session tables, pid-0, and unregister.

**`sndbuf-late` / `rcvbuf-late`:** classic `PH_LATE`. Applied on the raw TCP socket after connect or accept (before TLS/PROXY handshake), on the raw UDP/UNIX datagram socket after bind or connect (before session wrapping), and on QUIC's transport UDP socket. `WrapCommon` still applies them on streams that expose a socket fd.

**Named TCP / SOL_SOCKET:** classic `PH_PASTSOCKET` `so-debug`/`so-dontroute`/`so-oobinline` and Linux `so-priority`/`priority`, `so-passcred`/`passcred`, `so-no-check`/`no-check`/`nocheck`, `tcp-cork`/`tcp-defer-accept`/`tcp-linger2`/`tcp-maxseg`/`tcp-quickack`/`tcp-syncnt`/`tcp-window-clamp` are applied in `DialControl` / `ListenControl` after `socket()`, and also on inherited STDIO descriptors and the EXEC socketpair child endpoint (classic `popts` on `sv[1]` after `moveopts`; the parent stream is unchanged). Explicit EXEC `pipes`, `pty`, and `nofork` never apply PASTSOCKET; leftover GROUP_SOCKET options fail with `option "…" not inquired` (classic `showleft` / `leftopts`). Forked EXEC/SYSTEM/SHELL defaults to that socketpair, including unidirectional mode and `fdin`/`fdout`; the child gets the data fd only on the used `-u` direction and on the selected `fdi`/`fdo` numbers, and inherits unrelated 0/1/2. `nofork` with `fdin`/`fdout` applies that same child-side mapping to the already-open peer (classic `xio-progcall.c` `!withfork` Dup2 of WRFD onto `fdo`, then RDFD onto `fdi`, then `stderr` from `fdo`; `fdin==fdout` therefore keeps the input). Explicit `pipes` stay pipes with the same descriptor mapping. `pty,fdin`/`fdout` keep the PTY (classic does not let `fdin`/`fdout` select pipes). `end-close` still uses that socketpair (classic `howtoend=END_CLOSE` is not `usepipes`) and applies PASTSOCKET on the child endpoint; LISTEN,fork sessions that share the EXEC stream are serialized so a session Close poke cannot leave an expired read deadline on the next accept. Standalone SOCKETPAIR still applies options to both descriptors (tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same `optdesc` tree). Official man documents `priority=<priority>` while `passcred`/`nocheck` are COMMENT’d out; C `optionnames[]` and `-hhh` nevertheless expose all spellings as `TYPE_INT` (bare stores 1). This port follows C. `tcp-maxseg-late` is `PH_CONNECTED` and rides `ApplyTCPConnOpts` on the unwrapped TCP fd (TLS/WS/PROXY/SOCKS included) so `WrapCommon` does not apply CONNECTED generic `setsockopt` twice. TCP/TLS/WS listen and `DialTCPAll` disable Go's default Multipath TCP so the socket stays `IPPROTO_TCP` like classic; MPTCP would silently no-op `SO_DONTROUTE` and reject `TCP_MAXSEG`. GROUP_IP_TCP options are rejected on UDP. SCTP is SOCK_STREAM+IPPROTO_SCTP and does not have GROUP_IP_TCP; CLI rejects TCP_* there. Applying `TCP_CORK` on an SCTP socket fails with a kernel error rather than no-op. `so-bsdcompat` is not advertised: this kernel accepts the setsockopt and leaves getsockopt at 0. `tcp-info` / `tcp-md5sig` are not in this port yet.

**Named SCTP (Linux):** `sctp-nodelay` and `sctp-maxseg=<bytes>` are classic `GROUP_IP_SCTP` `PH_PASTSOCKET` `TYPE_INT` `OFUNC_SOCKOPT` `SOL_SCTP` (`SCTP_NODELAY` / `SCTP_MAXSEG`; tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). Applied on SCTP connect and listen sockets after `socket()`, not via `TCP_NODELAY`. The man page shows `sctp-nodelay` as a bare flag while C is `TYPE_INT`: no `=` stores 1 (enables Nagle-off); `=` uses `Strtoul`. CLI rejects these on TCP/UDP/QUIC. Other platforms hide and reject them. `sctp-maxseg-late` is not implemented.

**`perm=` / `mode=`:** classic `applyopts` applies every occurrence in command-line order at `PH_FD` (`tag-1.8.1.3` `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a`). `mode` maps onto `opt_perm`. The last `fchmod`/`chmod` wins for the resulting bits, but `user=`/`group=` `fchown(2)`/`chown(2)` in between can clear setuid/setgid (`perm=04755,user=` vs `user=,perm=04755`). Regular files and FIFOs use the last specified value as the `open`/`mkfifo` creation mode, so `umask=` still masks it (`umask=077,perm=0666` → `0600`). `FD`, `STDIO`, `EXEC` pipes, anonymous sockets, `UNIX-CONNECT`, `UNIX-SENDTO`, and ABSTRACT endpoints apply `perm=`/`mode=` with `fchmod(2)` and `user=`/`uid=`/`owner=` / `group=`/`gid=` with `fchown(2)` at classic `PH_FD` (tag-1.8.1.3 `xio-fd.c` / `_xioopen_connect`). Filesystem `UNIX-LISTEN` / `UNIX-RECV` / `UNIX-RECVFROM` and PTY slaves still `chmod`/`chown` the path (`applyopts_named` PH_FD). Darwin `fchmod` on UNIX connect sockets may return `EINVAL`; that error is reported, not swallowed. Anonymous sockets propagate `fchmod`/`fchown` errors. UDP/UNIX datagram session wrappers, POSIX MQ, and QUIC streams do not expose an fd to `WrapCommon`; lifecycle options are applied on the raw socket or mqd before wrapping (once on a shared parent datagram socket). Combinations that still have no descriptor are rejected instead of silently ignored. On Windows, inherited FDs reject `perm`/`user`/`group`/`append` (no `fchmod`/`F_SETFL`); named OPEN still uses `os.O_APPEND` at open. **`perm-early` / `user-early` (`uid-e`) / `group-early` (`gid-e`)** chmod/chown an existing filesystem name before open (`PH_PREOPEN` in classic `xio-named.c`); a missing OPEN/CREATE/GOPEN name drops them. On UNIX listen/recv and a bound UNIX client they also chmod/chown the new socket after bind (classic `xio-listen.c` / `xio-socket.c`: `PH_FD` then `PH_PREOPEN` on listen/recv names, so `perm-early` wins over `perm=`; connect/sendto apply `perm=` to the descriptor). They are not create-mode bits. **`umask=`** applies during open (or child `Start` for EXEC/SHELL), then restores.

**`ftruncate=` / `truncate=` / `ftruncate32=` / `ftruncate64=`:** classic `GROUP_REG` / `PH_LATE`. Applied with `ftruncate(2)` on `FD:n` pointing at a regular file, and on named OPEN/CREATE/GOPEN files. Every occurrence is applied in command-line order (classic `applyopts`); the last length wins. Not a silent no-op on sockets: CLI rejects `TCP,ftruncate=` (no `REG` group), and a non-regular fd fails at apply time. Windows inherited FDs truncate via `SetEndOfFile` on the handle. `ftruncate32`/`ftruncate64` fold onto `ftruncate`; they do not truncate twice.

**`o-sync` / `o-dsync` / `o-rsync` / `o-noctty` / `o-nofollow` / `o-directory` / `o-largefile`:** classic `GROUP_OPEN` / `PH_OPEN` `OFUNC_FLAG` (`xio-file.c`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same tree). Applied as `open(2)` bits, not `F_SETFL` on inherited FDs. `CREATE` has no `OPEN` group and is rejected. Unnamed `PIPE` uses `pipe(2)` and leftover `GROUP_OPEN` flags are rejected. Linux glibc advertises `o-rsync` (`O_RSYNC` equals `O_SYNC`). HP-UX-only `nshare` / `rshare` stay docs-only.

**Windows `binary` / `text` / `noinherit`:** classic Cygwin defines these as `GROUP_OPEN|GROUP_FD`, `PH_OPEN`, `TYPE_BOOL` `O_BINARY` / `O_TEXT` / `O_NOINHERIT` options (`xio-fd.c`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). Native Go uses Win32 handles rather than Cygwin CRT descriptors: `binary` is the native raw mode, `text` translates external CRLF to LF on read and LF to CRLF on write, and `noinherit` changes `HANDLE_FLAG_INHERIT`. The Cygwin `-hhh` aliases `bin`, `o-binary`, `o-text`, and `o-noinherit` are supported. Unix hides and rejects this family. Active `binary` and `text` together are rejected as ambiguous; classic passes both platform flags through without defining a portable result.

**`async` / `o-async`:** classic `GROUP_OPEN|GROUP_FD` / `PH_LATE` `OFUNC_FCNTL` `O_ASYNC`. Named OPEN/GOPEN also OR `O_ASYNC` into `open(2)` (`_xioopen_open`). Inherited FDs use `F_SETFL`; `async=0` clears the bit.

**`lseek` / `seek-cur` / `seek-end`:** classic `GROUP_REG|GROUP_BLK` / `PH_LATE`. Every occurrence is applied in command-line order; aliases (`lseek`/`lseek64`/`seek`/`lseek32` and the `-set`/`-cur`/`-end` spellings) retain their individual operations.

**`flock` / `flock-nb` / `flock-sh` / `flock-sh-nb`:** classic `GROUP_FD` / `PH_FD` `flock(2)`. Independent of `setlk*` `fcntl` locks; both families are applied. `flock=0` is a no-op (same as `setlk=0` here).

**`ioctl-void` / `ioctl` / `ioctl-int` / `ioctl-intp` / `ioctl-bin` / `ioctl-string`:** classic `GROUP_FD` / `PH_FD` `OFUNC_IOCTL_GENERIC` (`xio-fd.c` `opt_ioctl_*` and `xioopts.c` `applyopt_ioctl_generic`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). Applied in the same `PH_FD` applyopts walk as `perm`/`user`/`group`/`flock`/`o-noatime`/`fs-*`, so mixed families keep command-line order. `ioctl` is the `optionnames[]` alias of `ioctl-void` (NULL third argument). `ioctl-int` passes the integer by value; `ioctl-intp` passes a pointer to a C `int`; `ioctl-bin` passes dalan bytes; `ioctl-string` passes a pointer to a NUL-terminated C string. Official man `ioctl-string` has a stray “dalan form” line copied from `ioctl-bin`; C is `TYPE_INT_STRING` (plain string after the first colon, including empty). Official man `ioctl-void=<request>` requires a request; classic `TYPE_INT` without `=` stores 1 and would invoke `ioctl` request 1. This port requires a request. Integer request and `ioctl-int`/`ioctl-intp` payload fields are overflow-safe C `int` (32-bit); overflow is rejected rather than wrapping like classic `Strtoul`/`strtoul` into `int`. Unix including Darwin; Windows hides the names and rejects them instead of a no-op.

**`fs-append` / `fs-nodump` / …:** classic `GROUP_REG` / `PH_FD` `OFUNC_IOCTL_MASK_LONG` (`xio-fs.c`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same tree). `FS_IOC_GETFLAGS`, change only the requested `FS_*_FL` bit, `FS_IOC_SETFLAGS`. They share the `PH_FD` applyopts walk with `perm`/`user`/`group`/`flock`/`o-noatime`/`f-setpipe-sz`, so mixed families keep command-line order. `=0` clears that bit. `fs-append` is `FS_APPEND_FL`, not `open(2)`/`fcntl` `O_APPEND`. Privileged flags return the kernel permission error. Hidden on Darwin/Windows. The documented `notail` nickname is advertised on Linux even though classic `optionnames[]` omits it.

**`shut-none` / `shut-down` / `shut-close` / `shut-null`:** classic `GROUP_FD` / `PH_OFFSET` `howtoshut` (`xio-fd.c` / `xioshutdown.c`, tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same tree). One ordered field: last active occurrence wins, including Go-only `shut=none|down|close|null`. Man documents `shut-none[=<bool>]`; C `TYPE_CONST` rejects any assignment. This port follows the documented bool form with classic `TYPE_BOOL` values: omitted or `=1` selects; `=0` does not; `false`/`no`/`off`/other assignments are rejected. `none` makes `ShutdownWrite` a no-op (and EXEC does not kill the child). `down` calls `shutdown(fd, SHUT_WR)` (Windows: `shutdown(SD_SEND)`) on the underlying socket, including through `crypto/tls.Conn` via `NetConn()`; it does not fall back to `CloseWrite`/pipe close, and non-sockets return `ENOTSOCK` (Windows: `WSAENOTSOCK`). On Windows, `ShutdownWrite` queries `SO_TYPE` first so a pipe returns `WSAENOTSOCK` rather than a flaky `WSAENOTCONN`; a real unconnected socket still returns `WSAENOTCONN`. `close` fully closes. `null` sends a zero-length datagram, ignores that write result (classic `xiowrite(..., 0)` then `return 0`), and does not also half-close.

**`cr` / `crnl` / `crlf`:** classic `GROUP_APPL` `lineterm` (`xiolayer.c` / `cv_newline`, same SHAs). One ordered field: last active `cr` or `crnl`/`crlf` wins. Write converts NL→CR (`cr`) or NL→CRLF (`crnl`); read converts CR→NL (`cr`) or strips CR (`crnl`). Go-only `crorlf` is a distinct CR-or-LF conversion and is not folded into `cr`/`crnl`. Man documents `cr` and `crnl` as bare flags; C `TYPE_CONST` rejects assignments (`cr=0`, `crnl=false`, …).

**`perm-late` / `user-late` / `group-late`:** classic `GROUP_FD` / `PH_LATE` `fchmod`/`fchown`, after `PH_FD` `perm`/`user`/`group`. Command-line order within the phase. The public classic aliases are `uid-l` and `gid-l`; classic does not advertise `mode-late` or `owner-late`.

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
- **Post-quantum signatures** — Go 1.27 `crypto/mldsa` (ML-DSA-44/65/87) works on **TLS 1.3** (and QUIC) when `cert=`/`key=` are ML-DSA PEMs. TLS 1.2 does not advertise ML-DSA. Classic OpenSSL DSA (`OPENSSLLISTENDSA`) is unrelated and still rejected.
- **Multi-address connect** — try every resolved address; log `opening connection to AF=…`; match `bind=` to remote family; `-4`/`-6` reorder dual-stack results.
- **IPv6 peer filters** on `TLS-LISTEN`: `range`, `sourceport`, `lowport` (CN check accepts `::1` vs `[::1]`).

## Intentional differences from classic socat

- **Windows `binary,text` conflict** — classic passes both `O_BINARY` and `O_TEXT` through to Cygwin without defining which conversion wins. This port rejects the conflicting active modes instead of depending on CRT-specific flag resolution; `binary,text=0` and `binary=0,text` remain valid.
- **WebSocket (WS/WSS)** is a Go extra (classic has no WS). Uses `github.com/coder/websocket` (`NetConn` + binary frames), not frozen `golang.org/x/net/websocket`.
- **QUIC** is a Go extra (classic has no QUIC). Uses `github.com/quic-go/quic-go` (same stack as HTTP/3 CONNECT). One **client-initiated** bidirectional stream as a byte pipe. A receive-only client (`-u`/`-U`) still opens that stream and half-closes write so the listener can send. Not HTTP/3 (`alpn` default `socat`). 0-RTT is off.
- **`handshake-timeout`** is a Go extra (not in classic `optionnames[]` / `-hhh`). Classic `connect-timeout` (`OPTION_CONNECT_TIMEOUT`, `TYPE_TIMEVAL`, `GROUP_SOCKET`, `PH_PASTSOCKET` at `tag-1.8.1.3` `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is unchanged) aborts the TCP/UDP **connection attempt** (`connect(2)`), not `accept(2)`. This port keeps that split: `connect-timeout` bounds dialing/connection establishment; `accept-timeout` is the accept-side bound; `handshake-timeout` bounds protocol negotiation after the connection is up. TCP-backed clients (TLS, WS/WSS, PROXY HTTP/1, PROXY HTTP/2 including h2c, SOCKS) apply `connect-timeout` only to the TCP dial. `handshake-timeout` starts after TCP is established and covers TLS (including WSS), HTTP/2 protocol negotiation and CONNECT, WebSocket HTTP Upgrade, PROXY HTTP/1 CONNECT, and SOCKS. `handshake-timeout=0` disables only that handshake bound and does not shorten TCP connect. PROXY HTTP/3 is like direct QUIC: path establishment and the cryptographic handshake run together, so `connect-timeout` caps the whole remote attempt (QUIC `Transport.Dial` + stream open, HTTP/3 `RoundTrip`) as well as local UDP bind on QUIC; it is not used as `HandshakeIdleTimeout`. When both apply, the earlier positive deadline wins (fresh per retry). `handshake-timeout=0` drops only the handshake candidate. quic-go treats `HandshakeIdleTimeout=0` as a 5s default, so this port maps the disabled case to a long explicit duration (1 year) instead of 0. The option is rejected on addresses that do not handshake (TCP, UDP, OPEN, EXEC, …). Omitted `handshake-timeout` uses a 30s default so a stalled handshake cannot hang forever.
- **PROXY `http-version=2` / `3`** is a Go extra (classic PROXY is HTTP/1.x). HTTP/2 uses `net/http`. HTTP/3 uses `github.com/quic-go/quic-go/http3` because `golang.org/x/net/http3` is not a public client API. Classic `ignorecr` (`xio-proxy.c` at tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same file) applies only to HTTP/1 CONNECT response parsing. Enabled `ignorecr` is rejected on `http-version=2`/`3` rather than ignored. Requests still use CR+NL. `doc/socat.yo` presents a flag; C and this port treat it as `TYPE_BOOL` (`=0` disables; last occurrence wins).
- **`fork`** uses **goroutines**, not `fork(2)` process isolation.
- **`LISTEN,fork` + `sighup`/`sigint`/`sigquit`** — classic forks a worker process before opening the session EXEC address, so each worker has its own `SOCAT_MAXPIDS=4` table (`xiosignal.c` at tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same) and the listener parent never installs `socatsignalpass`. This port keeps that four-slot limit per `forkSession` (five `sighup` flags on one EXEC still fail with `too many sub processes registered for signal 1`; five concurrent `LISTEN,fork` sessions each using one `sighup` all succeed). The process handler aggregates every live session's pids. A SIGHUP/SIGINT/SIGQUIT to the listener while any EXEC child is registered is forwarded to those children and does not terminate socat. With no registered pids (before the first session or after the last child is reaped), the listener still exits `128+n` like classic's parent. Classic's sticky handler lived in a worker that exited with the session; exact parent isolation would need worker processes.
- **EXEC OFUNC_SIGNAL pid 0** — classic withfork+pipes applies `PH_LATE` before fork while `para.exec.pid` is still 0 (`kill(0, sig)` would signal the process group). This port registers the real child pid after `Start` on socketpair, pipes, pty, and nofork. Go nofork still `Wait`s in the parent and maps a signaled child to POSIX `128+signum` (`ExitCode` is `-1`); classic nofork `exec`s in-place.
- **EXEC `nofork` `fdin`/`fdout`** — classic Dup2's the peer onto `fdi`/`fdo` in the socat process then `exec`s (`xio-progcall.c` `!withfork` at tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). A failed `exec` can leave that process half-remapped. This port applies the mapping only in the child (ExtraFiles plus the same `dup2` helper used for every custom forked `fdin`/`fdout`) so a failed start leaves socat's descriptors unchanged. Unrelated 0/1/2 stay inherited. The helper is used for every remapping, not only descriptors above 9, so bare `SHELL` keeps its argv and `dash`/`login` rewrite the target rather than a `/bin/sh` wrapper.
- **OFUNC_SIGNAL unregister** — classic leaves completed pids in the four-slot table until the process exits. This port unregisters on `Wait`, post-Start PTY failure, and WrapCommon failure so a later `LISTEN,fork` session cannot inherit a stale slot or a reused pid.
- Companion tools aim for useful parity, not bit-identical C ifdef output
- Unknown options and malformed option values are rejected instead of being silently ignored
- **Generic ioctl integer overflow** — classic `TYPE_INT` / `TYPE_INT_INT` / `TYPE_INT_INTP` parse request and integer payloads with `Strtoul`/`strtoul` into `int` (`xioopts.c` parseopts_table; tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). A value that does not fit in C `int` wraps and can issue an unintended `ioctl`. This port rejects overflow (`strconv` bitSize 32). Request numbers are passed as the 32-bit pattern zero-extended to the kernel ioctl ABI; classic sign-extends a negative stored `int` to `unsigned long` on LP64. Combined with overflow rejection, this is an intentional security difference.
- **Man `ioctl-string` vs C** — official `doc/socat.yo` says “pointer to the given string” then a stray “dalan form” line copied from `ioctl-bin`. C `TYPE_INT_STRING` (`opt_ioctl_string` / `applyopt_ioctl_generic`) passes `u_string`, not dalan. This port follows C.
- **Man `ioctl-void` vs C** — official man is `ioctl-void=<request>`. C `TYPE_INT` without `=` stores 1 (`xioopts.c` parseopts_table) and would call `ioctl(fd, 1, NULL)`. This port requires a request.
- **`setpgid` / `pgid` omitted, 0, and 1** — official `doc/socat.yo` OPTION_SETPGID says those three make the process leader of a new process group. Classic C is `TYPE_INT` (bare stores 1) and calls `setpgid(0, value)` (`xioopts.c` OPT_SETPGID at tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same). On Linux `setpgid(0, 1)` fails with EPERM; classic Warn()s and continues without a new group. Go `SysProcAttr.Setpgid` turns that into a hard `Start` failure (`operation not permitted`). This port maps omitted, 0, and 1 to `Pgid=0` (new group) so the documented behavior works. Other values still request that process group.
- **IP/ancillary no-ops** — recv ancillary options (`ip-pktinfo`, `so-timestamp`, `ip-recvttl`, …) are honored only on UDP and raw IP on Unix, where the I/O path uses `recvmsg`. They are rejected on TCP, QUIC, UNIX, other stream sockets, and Windows (no ReadMsg cmsg path) rather than accepted as no-ops. Send-side `ip-ttl`/`ip-tos`/`ip-options` use classic `SOL_IP` `IP_TTL`/`IP_TOS`/`IP_OPTIONS` (`xio-ip.c`) on IPv4 and IPv6; `ip-ttl` is not translated to `IPV6_UNICAST_HOPS`, and `ip-tos` is not skipped on TCP6. `ip-options` uses classic `OFUNC_SOCKOPT_APPEND` (getsockopt existing `IP_OPTIONS`, append the new occurrence, setsockopt). `ipv6-unicast-hops`/`ipv6-tclass` and ipv6 recv opts error on IPv4. Windows `ip-options` / `ipv6-unicast-hops` / `ipv6-tclass` error instead of being ignored. Concatenated aliases (`ippktinfo`, `iprecvttl`, `ipoptions`, …) fold onto the canonical name so `OptionNamed` last-wins still applies at parse; APPLY walks every occurrence in command-line order (classic `applyopts`). Send and recv IP/ancillary options are applied together at `PH_PASTSOCKET` in that order (`DialControl` / `ListenControl`, including raw IP and PROXY `http-version=3` on an explicit UDP PacketConn), not split across bind. Classic baseline: tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same tree for these `optdesc`s.
- Security-deprecated crypto (DSA, DTLS, etc.) is documented above rather than forced in
- **TLS listen without `cert=`** fails at start (classic warns, listens, then handshake fails). See [TLS notes](#tls-notes).
- **TLS address names** are `TLS` / `TLS-CONNECT` / `TLS-LISTEN`. `OPENSSL*` and `SSL*` remain aliases so classic command lines still work.
- **SIGILL on Darwin** — classic `EXITCODESIGILL` expects exit `128+4` from a caught SIGILL. Linux matches that. On Darwin, Go’s runtime treats SIGILL as a crash dump (`exit 2`, `SIGILL: illegal instruction`); `os/signal.Notify` cannot intercept it. SIGTERM still exits `128+15`.
- **Signal-exit unlink identity** — classic `xio_close` calls `unlink(2)` on the stored name with no identity check. If `lstat` shows a different file than at registration (`os.SameFile`), we skip the name instead of removing a replacement. We do not hold extra descriptors to pin inodes: Linux `unlink(2)` removes the name while the endpoint fd already holds the object; Darwin `O_EVTONLY` is a kqueue monitor flag and `open` of a FIFO with it waits for a writer; Windows `DeleteFile` fails while a handle is open without `FILE_SHARE_DELETE`. Address `lockfile=` / `waitlock=` and CLI `-L` / `-W` use the same identity-safe release on normal exit, failed-open cleanup, and signal exit (classic `xiounlock` is a blind `unlink(2)`).
- **`lockfile=` / `waitlock=` / `-L` / `-W` acquire** — classic `xiogetlock` (tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same `xiolockfile.c`) creates via mkstemp + write pid + chmod 0644 + `link(2)` + unlink temp, and `xiowaitlock` polls every 1s (`xioopts.c` `OPT_WAITLOCK` sets `lock.intervall.tv_sec = 1`). Address `lockfile=` / `waitlock=` reuse `O_CREATE|O_EXCL` then `fchmod(0644)` on the still-open descriptor (so umask cannot leave the lock at 0600) with `pid\n`. Identity is `f.Stat()` while that descriptor is open; the pathname must still name that object before success is returned, and signal cleanup is registered with that identity rather than a later `Lstat`. Address `waitlock=` polls every 1s like classic; CLI `-W` keeps this port’s 100ms interval. Applied at classic `PH_INIT` (`GROUP_APPL`) during address open, after `chdir=` rewrites relative lock paths and before the opener. CLI `-L`/`-W` are acquired before any address opens; each address then acquires its own PH_INIT lock; both addresses may hold different paths; same-path combinations fail or wait according to the selected mode; a later open failure releases every previously acquired address lock (`RunOpened` closes the left side). Classic `OPT_LOCKFILE`/`OPT_WAITLOCK` `Error()` a second occurrence per address then continue and overwrite the stored pointer; this port validates all occurrences first and fails before acquiring. Classic CLI allows only one of `-L`/`-W` (same Error-then-continue pattern); this port still accepts both CLI flags (not changed in this work). Combining CLI `-L pathA` with address `lockfile=pathB` holds both.
- **`unlink=0` / `unlink-late=0`** — documented `TYPE_BOOL`; `=0` disables deletion. Classic `applyopts_named` ignores the stored bool and unlinks because the option is present (`tag-1.8.1.3` / master). Adjacent `unlink-early` and `unlink-close` already honor `=0` via `retropt_bool`. Copying the presence bug would delete files the user asked not to remove.
- **Multicast membership interface handling** — the documented three-field `ip-add-membership=<group:interface-address:interface-name-or-index>` form is implemented safely. Classic `tag-1.8.1.3` (`12c08bf66d709fba17035ce95d85bd218428d9ba`) and official master (`af5388c898c7bb60997935aee93c223deba60c4a`) write the third field through an uninitialized pointer and can crash. This port also rejects an unresolved interface name instead of continuing with interface index `0`, which could join on an unintended default interface. The same unresolved-name rejection applies to `ipv6-join-source-group`.
- **ACCEPT-FD man vs C groups** — official man `ACCEPT-FD:<fdnum>` lists groups FD, SOCKET, TCP, CHILD, RETRY. Classic C `xioaddr_accept_fd` (`xio-fdnum.c` at tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same) is `GROUP_FD|GROUP_SOCKET|GROUP_SOCK_UNIX|GROUP_SOCK_IP|GROUP_IPAPP|GROUP_CHILD|GROUP_RANGE|GROUP_RETRY`. `GROUP_IPAPP` is the C union of UDP, TCP, SCTP, DCCP, and UDP-Lite (`xioopts.h`); it is broader than man GROUP_TCP, not a short form of TCP. This port follows C so `fork`, `range`, `sourceport`, `lowport`, and `tcpwrap` work for IP and UNIX listeners. `ACCEPT` is the public `addressnames[]` alias. The address wraps an inherited *listening* fd and `accept(2)`s; a connected socket, pipe, or datagram fd is rejected.
- **UDP-Lite is Linux-only** — classic `xio-udplite.c` (tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same file) enables named `UDPLITE*` addresses whenever `IPPROTO_UDPLITE` is in the platform headers, including FreeBSD. This port implements them only on Linux. The rest of the tree does not yet compile for FreeBSD (`unix.IP_PKTINFO` / `unix.SizeofInet4Pktinfo` are missing from ancillary code), so UDP-Lite is not advertised there.
- **`udp-ignore-peerport`** — documented in official `doc/socat.yo` (`OPTION_UDP_IGNORE_PEERPORT`) but never registered in `optionnames[]` and never implemented in classic C (tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a`). Classic UDP-DATAGRAM accepts any sender by default (`xio-udp.c` / `xioread.c`). This port matches C: the spelling is unknown (rejected) and is not advertised. Advertising a no-op or inventing default peer-port filtering would diverge from classic. Do not implement without an explicit compatibility decision.
- **`ip-recverr` / `ipv6-recverr`** — classic `OFUNC_SOCKOPT` `IP_RECVERR` / `IPV6_RECVERR` only enables the kernel error queue. This port’s `ReadMsg` path does not drain `MSG_ERRQUEUE` or surface those cmsgs, so the options are rejected instead of being advertised as honored (including on TCP). Baseline: tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a` is the same tree. `ipv6-multicast-hops` is not in that catalog.
- **EXEC `fdin` / `fdout` range** — official `doc/socat.yo` describes `fdnum` as an unsigned integer, while classic's compiled catalog advertises `UNSIGNED-SHORT` and `xioopts.c` stores the parsed value in an unsigned short. This port follows the advertised `0..65535` range (including base-0 hex/octal input) but rejects overflow instead of silently truncating it as C does. Forked and `nofork` EXEC/SYSTEM/SHELL map every custom `fdin`/`fdout` in the child with `dup2` (ExtraFiles plus helper) so bare `SHELL` and `dash` stay on the target instead of a `/bin/sh` reconstruction.

## Unsupported / security-related

We do **not** re-implement features that Go’s standard libraries removed or never offered for security (or crypto-policy) reasons. Prefer modern alternatives.

| Topic | Status | Why / reference |
|-------|--------|------------------|
| **DSA certificates / keys** | Rejected | DSA is obsolete; Go `crypto/tls` does not parse DSA keys. Classic `OPENSSLLISTENDSA` fails by design. Use RSA, ECDSA, Ed25519, or ML-DSA (TLS 1.3 / QUIC). See [Go crypto/tls](https://pkg.go.dev/crypto/tls), [crypto/mldsa](https://pkg.go.dev/crypto/mldsa), and [NIST SP 800-57 / deprecation of DSA](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final). |
| **DCCP, readline** | Not implemented | `#undef` in `-V`. No DCCP or GNU readline address type. |
| **DTLS** | Not implemented | Not available in Go `crypto/tls` (stream TLS only). `method=` / `openssl-method=DTLS*` is rejected instead of silently using TCP TLS. Classic `OPENSSL-DTLS-*` address types are not implemented. See [crypto/tls package docs](https://pkg.go.dev/crypto/tls). |
| **SSLv3 / weak ciphers** | Not offered | Go TLS defaults reject obsolete protocols/ciphers. Unsupported `method=` / `openssl-method=` selections are rejected. See [Go TLS cipher suites](https://go.dev/blog/tls-cipher-suites) and [crypto/tls Config](https://pkg.go.dev/crypto/tls#Config). |
| **OpenSSL `method` / `fips`** | Rejected when enabled | Classic `method=` needs `--enable-openssl-method`; `fips=` needs `--enable-fips`. This port has no OpenSSL engine or FIPS module. `method` / `openssl-method` and enabled `fips` / `openssl-fips` are parsed and rejected; `fips=0` is honored as disabled. They are not advertised in `-hhh` as honored. |
| **TLS compression** | Disabled only | Classic `openssl-compress=none` / `compress=none` disables TLS compression and is honored here. `auto` or any other value is rejected because Go `crypto/tls` has no TLS compression (CRIME). |
| **EGD / OpenSSL pseudo-random** | Rejected when enabled | `openssl-egd` / `egd` and enabled `openssl-pseudo` / `pseudo` feed OpenSSL's RNG. Go uses `crypto/rand`; `pseudo=0` is honored as disabled, while an EGD path or enabled pseudo-random mode is rejected. |
| **DH parameters** | Rejected | `openssl-dhparam` / `dhparam` / `dh` / `dhparams` load an OpenSSL DH PEM for `SSL_CTX_set_tmp_dh`. Go `crypto/tls` does not load DH params. Rejected instead of a no-op. |
| **Max fragment length** | Rejected | `openssl-maxfraglen` / `maxfraglen` (`SSL_CTX_set_tlsext_max_fragment_length`) and `openssl-maxsendfrag` / `maxsendfrag` (`SSL_CTX_set_max_send_fragment`) are not exposed by Go `crypto/tls`. Rejected instead of a no-op. |
| **libwrap / TCP wrappers** | Implemented (pure Go) | No CGO/libwrap0; reads `hosts.allow`/`hosts.deny` (or `tcpwrap-etc=`). Subset: daemon ALL/name, client ALL/IP/hostname/`[ipv6]`. |
| **Lock file unlink identity** | Identity-safe | Classic `xiounlock` (tag-1.8.1.3 `12c08bf66d709fba17035ce95d85bd218428d9ba`; official master `af5388c898c7bb60997935aee93c223deba60c4a`) blindly `unlink(2)`s the stored name. This port snapshots `f.Stat()` while the created descriptor is still open, verifies the pathname still names that object before reporting success, and unlinks `lockfile=` / `waitlock=` / `-L` / `-W` only when `lstat` + `os.SameFile` still match, on normal cleanup, failed-open cleanup, and signal cleanup, so a replacement at the old name is not deleted. |

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
PR comments) when `CODECOV_TOKEN` is set, and as HTML artifacts. A weekly workflow additionally runs
native fuzz campaigns and the live relay matrix, and can be dispatched
manually.

Classic option and address parity is enforced in `go test`. Expected gaps
are classified by family (implementation backlog vs unsupported vs
foreign-platform). CI fails if an implemented public spelling disappears, a
new unclassified gap appears, an exclusion lacks a reason, or an implemented
name remains in a missing manifest. OpenSSL `method`/`fips`/EGD/pseudo/DH/max-fragment
options and documented-but-never-implemented `udp-ignore-peerport` are
unsupported exclusions, not backlog items.

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
