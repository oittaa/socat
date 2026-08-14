// Package xio is the socat extended-I/O core: session state, stream helpers,
// peer filters, dial utilities, and Run orchestration.
//
// Address openers live in subpackages and register via Register (init):
//
//	netopen   — TCP, UDP, UNIX, SOCKET, raw IP
//	tlsopen   — classic OPENSSL/SSL via crypto/tls
//	proxyopen — PROXY, SOCKS4/4A/5
//	fileopen  — STDIO, FILE, PIPE, PTY, TEXT, STALL
//	tunopen   — TUN, INTERFACE (Linux)
//	wsopen    — WS / WSS (coder/websocket; not in classic socat)
//	quicopen  — QUIC (quic-go; not in classic socat; not HTTP/3)
//
// EXEC/SYSTEM/SHELL stay in this package (tightly coupled to Run / nofork).
// Import internal/xio/all from main/cli so opener registration runs.
//
// Classic-facing names (OPENSSL types, SOCAT_OPENSSL_X509_* env, option names)
// stay as in Gerhard’s socat so test.sh keeps matching.
package xio
