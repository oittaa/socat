package quicopen

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicNetConn presents one QUIC stream as a net.Conn for the socat relay.
type quicNetConn struct {
	qc *quic.Conn
	st *quic.Stream
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
	// Close the stream only. CONNECTION_CLOSE would drop in-flight STREAM
	// bytes (stdin EOF + linger). The QUIC conn ends when the Transport
	// or Listener closes, or after MaxIdleTimeout.
	return c.st.Close()
}

func (c *quicNetConn) LocalAddr() net.Addr  { return c.qc.LocalAddr() }
func (c *quicNetConn) RemoteAddr() net.Addr { return c.qc.RemoteAddr() }

func (c *quicNetConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *quicNetConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *quicNetConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }
