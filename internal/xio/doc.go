// Package xio is the socat extended-I/O core: session state, stream helpers,
// peer filters, dial utilities, and Run orchestration.
//
// Address openers live in subpackages and register via Register (init):
//
//	netopen   — TCP, UDP, UNIX, SOCKET, raw IP
//	tlsopen   — TLS (OPENSSL/SSL aliases) via crypto/tls
//	proxyopen — PROXY, SOCKS4/4A/5
//	fileopen  — STDIO, FILE, PIPE, PTY, TEXT, STALL
//	tunopen   — TUN, INTERFACE (Linux)
//	wsopen    — WS / WSS (coder/websocket)
//	quicopen  — QUIC (quic-go; not HTTP/3)
//
// EXEC/SYSTEM/SHELL stay in this package (tightly coupled to Run / nofork).
// Import internal/xio/all from main/cli so opener registration runs.
//
// OPENSSL/SSL type names and SOCAT_OPENSSL_X509_* env stay as aliases
// so existing scripts keep matching.
package xio
