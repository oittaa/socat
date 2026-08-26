package xio

import (
	"net"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

const defaultHandshakeTimeout = 30 * time.Second

// HandshakeTimeout bounds protocol negotiation after a connection is
// established. This is a Go extra (not classic OPTION_CONNECT_TIMEOUT).
// handshake-timeout=0 explicitly disables the bound. When the option is
// omitted, a 30s default applies so a stalled TLS/WS/QUIC/PROXY/SOCKS
// handshake cannot hang forever. connect-timeout is never reused here; it
// remains the dial/accept-establishment bound only.
func HandshakeTimeout(s parse.Spec) time.Duration {
	if s.HasOption("handshake-timeout") {
		return ParseTimeval(s.OptionValue("handshake-timeout", ""))
	}
	return defaultHandshakeTimeout
}

// WithHandshakeDeadline applies and then clears a whole-connection deadline.
// It covers both reads and writes because TLS, WebSocket, HTTP CONNECT, and
// SOCKS negotiation are all bidirectional.
func WithHandshakeDeadline(c net.Conn, timeout time.Duration, fn func() error) error {
	if timeout <= 0 {
		return fn()
	}
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	return fn()
}
