package wsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/xio"
)

// wsReadBuffer is the read pump's backlog. Past this it waits so a stalled
// consumer applies backpressure without dropping frames.
const wsReadBuffer = 32 << 10

// wsNetConn exposes binary WebSocket messages as a byte stream.
// A pump owns the WebSocket read so read deadlines stay recoverable:
// a timeout does not close the connection. Write deadlines still apply
// to the raw connection; a timed-out write cannot resume a partial frame.
type wsNetConn struct {
	ws *websocket.Conn
	// For WSS clients, raw is the TCP connection beneath TLS.
	raw net.Conn

	readMu       sync.Mutex
	readCond     *sync.Cond
	buf          []byte
	readErr      error
	readDeadline time.Time
	stop         bool

	writeMu sync.Mutex

	tlsState    tls.ConnectionState
	hasTLSState bool
}

func newWSNetConn(raw net.Conn, ws *websocket.Conn) *wsNetConn {
	ws.SetReadLimit(-1)
	c := &wsNetConn{ws: ws, raw: raw}
	c.readCond = sync.NewCond(&c.readMu)
	go c.readFrames()
	return c
}

func (c *wsNetConn) rememberTLSState(st tls.ConnectionState) {
	c.tlsState = st
	c.hasTLSState = true
}

func (c *wsNetConn) TLSConnectionState() (tls.ConnectionState, bool) {
	return c.tlsState, c.hasTLSState
}

func (c *wsNetConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if len(c.buf) > 0 {
			n := copy(p, c.buf)
			c.buf = c.buf[n:]
			if len(c.buf) == 0 {
				c.buf = nil
			}
			c.readCond.Broadcast()
			return n, nil
		}
		if c.readErr != nil {
			return 0, c.readErr
		}
		if err := wsDeadlineErr(c.readDeadline); err != nil {
			return 0, err
		}
		c.waitRead()
	}
}

func (c *wsNetConn) readFrames() {
	buf := make([]byte, wsReadBuffer)
	for {
		typ, r, err := c.ws.Reader(context.Background())
		if err != nil {
			c.noteReadErr(err)
			return
		}
		if typ != websocket.MessageBinary {
			err := fmt.Errorf("unexpected WebSocket message type %d", typ)
			_ = c.ws.Close(websocket.StatusUnsupportedData, err.Error())
			c.finishRead(err)
			return
		}
		for {
			if c.readBlocked() {
				return
			}
			n, err := r.Read(buf)
			if n > 0 {
				c.readMu.Lock()
				c.buf = append(c.buf, buf[:n]...)
				c.readCond.Broadcast()
				c.readMu.Unlock()
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				c.noteReadErr(err)
				return
			}
		}
	}
}

func (c *wsNetConn) readBlocked() bool {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for len(c.buf) >= wsReadBuffer && !c.stop {
		c.readCond.Wait()
	}
	return c.stop
}

func (c *wsNetConn) noteReadErr(err error) {
	if normalWebSocketClose(err) {
		err = io.EOF
	} else {
		c.abortOnTimeout(err)
	}
	c.finishRead(err)
}

func (c *wsNetConn) finishRead(err error) {
	if err == nil {
		err = io.ErrUnexpectedEOF
	}
	c.readMu.Lock()
	if c.readErr == nil {
		c.readErr = err
	}
	c.readCond.Broadcast()
	c.readMu.Unlock()
}

func (c *wsNetConn) waitRead() {
	deadline := c.readDeadline
	if deadline.IsZero() {
		c.readCond.Wait()
		return
	}
	remain := time.Until(deadline)
	if remain <= 0 {
		return
	}
	timer := time.AfterFunc(remain, func() {
		c.readMu.Lock()
		c.readCond.Broadcast()
		c.readMu.Unlock()
	})
	c.readCond.Wait()
	timer.Stop()
}

func wsDeadlineErr(dl time.Time) error {
	if dl.IsZero() || time.Now().Before(dl) {
		return nil
	}
	return os.ErrDeadlineExceeded
}

func (c *wsNetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.ws.Write(context.Background(), websocket.MessageBinary, p); err != nil {
		c.abortOnTimeout(err)
		return 0, err
	}
	return len(p), nil
}

func (c *wsNetConn) Close() error {
	c.readMu.Lock()
	c.stop = true
	if c.readErr == nil {
		c.readErr = net.ErrClosed
	}
	c.readCond.Broadcast()
	c.readMu.Unlock()
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *wsNetConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *wsNetConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsNetConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDeadline = t
	c.readCond.Broadcast()
	c.readMu.Unlock()
	return nil
}

func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func (c *wsNetConn) abortOnTimeout(err error) {
	if xio.IsTimeoutErr(err) {
		_ = c.raw.Close()
	}
}

func normalWebSocketClose(err error) bool {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	default:
		return false
	}
}
