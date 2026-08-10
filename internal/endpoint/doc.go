// Package endpoint opens socat address endpoints and runs bidirectional transfer.
//
// File groups (single package, no subpackages):
//
//   - Core: endpoint.go (types, OpenSpec, registry), run.go (Run, fork/listen loops)
//   - Streams: stream.go (wrap/half-close/ignoreeof), sniff.go, retry.go
//   - IP transport: tcp, dial, udp, rawip, unix, socket, ancillary, peersec, tcpwrap
//   - TLS: tls.go — classic OPENSSL/SSL address types via crypto/tls (not OpenSSL CGO)
//   - Proxies: proxy.go, socks.go
//   - Local I/O: file, stdio, exec, pty*, text_stall, owner, umask
//   - Linux: tun_linux.go / tun_stub.go (TUN, INTERFACE)
//
// Classic-facing names (OPENSSL address types, SOCAT_OPENSSL_X509_* env, option
// names) stay as in Gerhard’s socat so test.sh and scripts keep matching.
package endpoint
