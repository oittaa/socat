package xio

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

// SocketTimeoutConn applies rcvtimeo/sndtimeo below framed transports
// such as crypto/tls. Its own deadline expirations are retried internally so a
// record layer never observes and permanently latches a transient socket
// timeout. Deadlines explicitly set by the transport remain terminating.
type SocketTimeoutConn struct {
	net.Conn
	readTimeout  time.Duration
	writeTimeout time.Duration
	enabled      atomic.Bool

	mu            sync.Mutex
	readDeadline  time.Time
	writeDeadline time.Time
}

func NewSocketTimeoutConn(s parse.Spec, conn net.Conn) (*SocketTimeoutConn, error) {
	wrapped := &SocketTimeoutConn{Conn: conn}
	for _, item := range []struct {
		name string
		dst  *time.Duration
	}{
		{name: "rcvtimeo", dst: &wrapped.readTimeout},
		{name: "sndtimeo", dst: &wrapped.writeTimeout},
	} {
		value := s.OptionValue(item.name, "")
		if value == "" {
			continue
		}
		d, err := parseTimeval(value)
		if err != nil || d < 0 {
			return nil, &socketTimeoutConfigError{name: item.name, value: value}
		}
		*item.dst = d
	}
	return wrapped, nil
}

type socketTimeoutConfigError struct {
	name  string
	value string
}

func (e *socketTimeoutConfigError) Error() string {
	return e.name + ": invalid timeout " + e.value
}

// EnableSocketTimeouts starts applying the configured per-operation timeouts.
// TLS openers call this only after the handshake has completed, leaving the
// independent handshake timeout authoritative.
func (c *SocketTimeoutConn) EnableSocketTimeouts() { c.enabled.Store(true) }

func (c *SocketTimeoutConn) NetConn() net.Conn { return c.Conn }

func EnableSocketTimeouts(conn net.Conn) {
	for conn != nil {
		if timeoutConn, ok := conn.(interface{ EnableSocketTimeouts() }); ok {
			timeoutConn.EnableSocketTimeouts()
			return
		}
		unwrapper, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			return
		}
		next := unwrapper.NetConn()
		if next == nil || next == conn {
			return
		}
		conn = next
	}
}

func (c *SocketTimeoutConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func (c *SocketTimeoutConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(deadline)
}

func (c *SocketTimeoutConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(deadline)
}

func (c *SocketTimeoutConn) Read(p []byte) (int, error) {
	for {
		ownDeadline, err := c.armReadDeadline()
		if err != nil {
			return 0, err
		}
		n, err := c.Conn.Read(p)
		if c.retryOwnTimeout(true, ownDeadline, err) {
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (c *SocketTimeoutConn) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		ownDeadline, err := c.armWriteDeadline()
		if err != nil {
			return written, err
		}
		n, err := c.Conn.Write(p[written:])
		remaining := len(p) - written
		if n < 0 || n > remaining {
			return written, io.ErrShortWrite
		}
		written += n
		if c.retryOwnTimeout(false, ownDeadline, err) {
			continue
		}
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func (c *SocketTimeoutConn) armReadDeadline() (bool, error) {
	c.mu.Lock()
	external := c.readDeadline
	timeout := c.readTimeout
	enabled := c.enabled.Load()
	c.mu.Unlock()
	if !enabled || timeout <= 0 {
		return false, nil
	}
	deadline, own := earliestSocketDeadline(time.Now().Add(timeout), external)
	return own, c.Conn.SetReadDeadline(deadline)
}

func (c *SocketTimeoutConn) armWriteDeadline() (bool, error) {
	c.mu.Lock()
	external := c.writeDeadline
	timeout := c.writeTimeout
	enabled := c.enabled.Load()
	c.mu.Unlock()
	if !enabled || timeout <= 0 {
		return false, nil
	}
	deadline, own := earliestSocketDeadline(time.Now().Add(timeout), external)
	return own, c.Conn.SetWriteDeadline(deadline)
}

func earliestSocketDeadline(internal, external time.Time) (time.Time, bool) {
	if !external.IsZero() && !internal.Before(external) {
		return external, false
	}
	return internal, true
}

func (c *SocketTimeoutConn) retryOwnTimeout(read, ownDeadline bool, err error) bool {
	if !ownDeadline || !IsTimeoutErr(err) {
		return false
	}
	c.mu.Lock()
	external := c.writeDeadline
	if read {
		external = c.readDeadline
	}
	c.mu.Unlock()
	return external.IsZero() || time.Now().Before(external)
}
