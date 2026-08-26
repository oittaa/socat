# Compose lab

Optional check that this socat works between two hosts. It is not `make test`
and not `make e2e`.

The lab starts two containers on one Compose bridge. The HTTP app listens on
`127.0.0.1` inside `server`. Socat publishes TLS, QUIC, WSS, or SOCKS on the
bridge. The client uses the name `server`, not loopback.

The same commands are examples you can copy.

## Requirements

- Docker Engine
- OpenSSL on the host (to make short-lived lab certificates)
- Go 1.27+ only if you set `USE_HOST_BIN=1`

`compose.yaml` is optional. Use it if you have Compose v2. `run.sh` uses
`docker network` and two containers so Compose is not required.

## Run

```bash
# From the repo root
./examples/lab/run.sh
make lab

# One or more scenarios
./examples/lab/run.sh tls
./examples/lab/run.sh quic wss

# Mount a host-built ./socat (skip the image compile of socat)
USE_HOST_BIN=1 ./examples/lab/run.sh tls
```

A scenario passes only when the client exits 0 and the HTTP body contains
`lab-ok`.

## Scenarios

| Name | What it proves | Server | Client |
|------|----------------|--------|--------|
| `tls` | Real HTTPS to TLS-LISTEN | httpd + TLS-LISTEN:443 | `curl --cacert ca.pem https://server/` |
| `quic` | HTTP over a QUIC **tunnel** (not HTTP/3) | httpd + QUIC-LISTEN:4433 | local TCP-LISTEN + QUIC:server:4433, then curl |
| `socks5` | SOCKS5 **client** to a real daemon | httpd + microsocks :1080 | local TCP-LISTEN + SOCKS5:server:127.0.0.1:8080 |
| `wss` | HTTP over a WSS tunnel | httpd + WSS-LISTEN:443 | local TCP-LISTEN + WSS:server:443, then curl |

### TLS

```bash
# server
python3 -m http.server 8080 --bind 127.0.0.1
socat TLS-LISTEN:443,reuseaddr,fork,bind=0.0.0.0,cert=server.crt,key=server.key,verify=0 \
  TCP:127.0.0.1:8080

# client
curl --cacert ca.pem https://server/
```

`verify=0` on the listener means the server does not check a client certificate.
The client still verifies the server certificate (SAN `DNS:server`).

### QUIC tunnel

Few programs speak our QUIC ALPN (`socat`). This is a byte tunnel, **not** HTTP/3.

```bash
# server
socat QUIC-LISTEN:4433,reuseaddr,fork,bind=0.0.0.0,cert=server.crt,key=server.key,verify=0 \
  TCP:127.0.0.1:8080

# client
socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  QUIC:server:4433,verify=1,cafile=ca.pem
curl http://127.0.0.1:8080/
```

### SOCKS5 client

This socat is a SOCKS5 client. **microsocks** is the SOCKS daemon.

The target `127.0.0.1:8080` is the HTTP app **on the SOCKS host**.

```bash
# server
microsocks -i 0.0.0.0 -p 1080

# client
socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  SOCKS5:server:127.0.0.1:8080,socksport=1080
curl http://127.0.0.1:8080/
```

### WSS tunnel

```bash
# server
socat WSS-LISTEN:443,reuseaddr,fork,bind=0.0.0.0,cert=server.crt,key=server.key,verify=0 \
  TCP:127.0.0.1:8080

# client
socat TCP4-LISTEN:8080,reuseaddr,fork,bind=127.0.0.1 \
  WSS:server:443,verify=1,cafile=ca.pem
curl http://127.0.0.1:8080/
```

## Certificates

`certs/gen.sh` writes a lab CA and a server certificate (`SAN DNS:server`)
into `certs/out/` (gitignored). `run.sh` calls it.

## Not in this lab

TUN/INTERFACE, PROXY HTTP/2 and HTTP/3 CONNECT, SCTP, POSIXMQ, DTLS.
