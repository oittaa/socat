package xio

import (
	"net"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

const defaultHandshakeTimeout = 30 * time.Second

// HandshakeTimeout bounds protocol negotiation after a connection is
// established. handshake-timeout=0 explicitly disables the bound; otherwise
// connect-timeout is reused when supplied and a safe default is applied.
func HandshakeTimeout(s parse.Spec) time.Duration {
	if s.HasOption("handshake-timeout") {
		return ParseTimeval(s.OptionValue("handshake-timeout", ""))
	}
	if timeout := ConnectTimeout(s); timeout > 0 {
		return timeout
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
