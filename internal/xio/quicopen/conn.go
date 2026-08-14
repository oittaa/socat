package quicopen

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/quic"
)

// quicNetConn presents one QUIC stream as a net.Conn for the socat relay.
type quicNetConn struct {
	qc *quic.Conn
	st *quic.Stream

	mu      sync.Mutex
	rcancel context.CancelFunc
	wcancel context.CancelFunc
}

func wrapQUIC(qc *quic.Conn, st *quic.Stream) *quicNetConn {
	return &quicNetConn{qc: qc, st: st}
}

func (c *quicNetConn) Read(p []byte) (int, error) { return c.st.Read(p) }
func (c *quicNetConn) Write(p []byte) (int, error) {
	n, err := c.st.Write(p)
	if n > 0 {
		if ferr := c.st.Flush(); ferr != nil && err == nil {
			return n, ferr
		}
	}
	return n, err
}

func (c *quicNetConn) CloseWrite() error {
	// CloseWrite already sends the write buffer. Do not Flush after it.
	c.st.CloseWrite()
	return nil
}

func (c *quicNetConn) Close() error {
	c.mu.Lock()
	if c.rcancel != nil {
		c.rcancel()
		c.rcancel = nil
	}
	if c.wcancel != nil {
		c.wcancel()
		c.wcancel = nil
	}
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.st.SetWriteContext(ctx)
	_ = c.st.Close()
	return c.qc.Close()
}

func (c *quicNetConn) LocalAddr() net.Addr  { return udpAddr(c.qc.LocalAddr()) }
func (c *quicNetConn) RemoteAddr() net.Addr { return udpAddr(c.qc.RemoteAddr()) }

func (c *quicNetConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *quicNetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rcancel != nil {
		c.rcancel()
		c.rcancel = nil
	}
	if t.IsZero() {
		c.st.SetReadContext(context.Background())
		return nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), t)
	c.rcancel = cancel
	c.st.SetReadContext(ctx)
	return nil
}

func (c *quicNetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wcancel != nil {
		c.wcancel()
		c.wcancel = nil
	}
	if t.IsZero() {
		c.st.SetWriteContext(context.Background())
		return nil
	}
	ctx, cancel := context.WithDeadline(context.Background(), t)
	c.wcancel = cancel
	c.st.SetWriteContext(ctx)
	return nil
}

func udpAddr(ap netip.AddrPort) *net.UDPAddr {
	if !ap.IsValid() {
		return &net.UDPAddr{}
	}
	a := ap.Addr()
	if a.Is4() || a.Is4In6() {
		ip4 := a.As4()
		return &net.UDPAddr{IP: net.IP(ip4[:]), Port: int(ap.Port())}
	}
	ip16 := a.As16()
	return &net.UDPAddr{IP: net.IP(ip16[:]), Port: int(ap.Port())}
}
