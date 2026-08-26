package xio

import (
	"net"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

const defaultHandshakeTimeout = 30 * time.Second

// QUICHandshakeIdleTimeoutDisabled is HandshakeIdleTimeout when
// handshake-timeout=0 (disable the bound). quic-go v0.61.0 populateConfig
// substitutes protocol.DefaultHandshakeIdleTimeout (5s) when the field is
// 0, and handshakeTimeout() returns 2*HandshakeIdleTimeout, so this must be
// nonzero and 2*duration must not overflow int64. One year is effectively
// unbounded for a handshake.
const QUICHandshakeIdleTimeoutDisabled = 365 * 24 * time.Hour

// HandshakeTimeout bounds protocol negotiation after a connection is
// established. This is a Go extra (not classic OPTION_CONNECT_TIMEOUT).
// handshake-timeout=0 explicitly disables the bound. When the option is
// omitted, a 30s default applies so a stalled TLS/WS/QUIC/PROXY/SOCKS
// handshake cannot hang forever. connect-timeout is never reused here; it
// remains the dialing/connection-establishment bound only. accept-timeout
// is the accept-side bound.
func HandshakeTimeout(s parse.Spec) time.Duration {
	if s.HasOption("handshake-timeout") {
		return ParseTimeval(s.OptionValue("handshake-timeout", ""))
	}
	return defaultHandshakeTimeout
}

// CombinedConnectHandshakeTimeout is the earlier of connect-timeout and
// handshake-timeout when both are positive. handshake-timeout=0 drops only
// the handshake candidate; an explicit connect-timeout may still apply.
// A zero result means no extra attempt-context timeout. Used where path
// establishment and the cryptographic handshake are combined (QUIC Dial,
// PROXY HTTP/3 RoundTrip).
func CombinedConnectHandshakeTimeout(s parse.Spec) time.Duration {
	connect := ConnectTimeout(s)
	handshake := HandshakeTimeout(s)
	switch {
	case connect <= 0:
		return handshake
	case handshake <= 0:
		return connect
	case connect < handshake:
		return connect
	default:
		return handshake
	}
}

// QUICHandshakeIdleTimeout maps handshake-timeout onto quic-go
// HandshakeIdleTimeout. handshake-timeout=0 is not passed through as 0
// (quic-go would substitute 5s); it becomes QUICHandshakeIdleTimeoutDisabled.
func QUICHandshakeIdleTimeout(s parse.Spec) time.Duration {
	if d := HandshakeTimeout(s); d > 0 {
		return d
	}
	return QUICHandshakeIdleTimeoutDisabled
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
