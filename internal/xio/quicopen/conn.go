package quicopen

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

// Longer than default linger and e2e -t 2 so CONNECTION_CLOSE does not
// drop the last STREAM bytes.
const quicConnDrain = 5 * time.Second

// quicNetConn presents one QUIC stream as a net.Conn for the socat relay.
type quicNetConn struct {
	qc   *quic.Conn
	st   *quic.Stream
	once sync.Once
	// waitPeerClose keeps write-only senders alive until the receiver has
	// consumed the stream FIN and closed the connection.
	waitPeerClose bool
	// wrote: payload was written, so outbound STREAM frames may still be
	// unACKed and must not be discarded by an early CONNECTION_CLOSE.
	wrote atomic.Bool
	// readEOF means the peer's stream finished cleanly, so closing the
	// connection also acknowledges that all inbound bytes were consumed.
	readEOF atomic.Bool
	// fin: a FIN was queued on this stream (half-close), either via
	// CloseWrite or at dial time for receive-only clients. Dropping it would
	// surface as an application error on the peer instead of a clean EOF.
	fin atomic.Bool
	// transportDrain: shared flag on the owning client Opened. Set whenever
	// this conn used the stream so the transport teardown in client.go
	// delays until the drain elapses instead of killing the connection.
	transportDrain *atomic.Bool
}

func wrapQUIC(qc *quic.Conn, st *quic.Stream) *quicNetConn {
	return &quicNetConn{qc: qc, st: st}
}

func (c *quicNetConn) markUsed() {
	if c.transportDrain != nil {
		c.transportDrain.Store(true)
	}
}

// markFinSent records a dial-time half-close performed directly on the
// quic.Stream before this wrapper existed.
func (c *quicNetConn) markFinSent() {
	c.fin.Store(true)
	c.markUsed()
}

func (c *quicNetConn) Read(p []byte) (int, error) {
	n, err := c.st.Read(p)
	if n == 0 && errors.Is(err, io.EOF) {
		c.readEOF.Store(true)
	}
	return n, err
}
func (c *quicNetConn) Write(p []byte) (int, error) {
	n, err := c.st.Write(p)
	if n > 0 {
		c.wrote.Store(true)
		c.markUsed()
	}
	return n, err
}

func (c *quicNetConn) CloseWrite() error {
	c.fin.Store(true)
	c.markUsed()
	// quic-go Stream.Close half-closes the write side.
	if err := c.st.Close(); err != nil {
		return err
	}
	if !c.waitPeerClose {
		return nil
	}
	timer := time.NewTimer(quicConnDrain)
	defer timer.Stop()
	select {
	case <-c.qc.Context().Done():
	case <-timer.C:
	}
	return nil
}

// Close closes the stream and schedules connection teardown. A connection
// that never carried payload data and never queued a FIN has nothing in
// flight and is closed immediately; otherwise CONNECTION_CLOSE is delayed so
// linger can deliver the last STREAM bytes (quic-go stops retransmitting
// stream data once the connection enters the draining state).
func (c *quicNetConn) Close() error {
	_ = c.st.Close()
	c.once.Do(func() {
		if !c.wrote.Load() && (c.readEOF.Load() || !c.fin.Load()) {
			_ = c.qc.CloseWithError(0, "")
			return
		}
		time.AfterFunc(quicConnDrain, func() { _ = c.qc.CloseWithError(0, "") })
	})
	return nil
}

func (c *quicNetConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicNetConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

func (c *quicNetConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *quicNetConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *quicNetConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
