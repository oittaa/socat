package quicopen

import (
	"net"
	"sync"
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
}

func wrapQUIC(qc *quic.Conn, st *quic.Stream) *quicNetConn {
	return &quicNetConn{qc: qc, st: st}
}

func (c *quicNetConn) Read(p []byte) (int, error)  { return c.st.Read(p) }
func (c *quicNetConn) Write(p []byte) (int, error) { return c.st.Write(p) }

func (c *quicNetConn) CloseWrite() error {
	// quic-go Stream.Close half-closes the write side.
	return c.st.Close()
}

func (c *quicNetConn) Close() error {
	_ = c.st.Close()
	// Delay CONNECTION_CLOSE so linger can deliver the last STREAM bytes.
	c.once.Do(func() {
		go func() {
			time.Sleep(quicConnDrain)
			_ = c.qc.CloseWithError(0, "")
		}()
	})
	return nil
}

func (c *quicNetConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicNetConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

func (c *quicNetConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *quicNetConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *quicNetConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
