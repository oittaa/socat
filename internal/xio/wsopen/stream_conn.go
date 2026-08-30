package wsopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// wsNetConn exposes binary WebSocket messages as a byte stream. Deadlines are
// applied to the owned network connection, avoiding a cancellation context for
// every WebSocket frame when no deadline is active.
type wsNetConn struct {
	ws  *websocket.Conn
	raw net.Conn

	readMu  sync.Mutex
	writeMu sync.Mutex
	reader  io.Reader
	readEOF bool
}

func newWSNetConn(raw net.Conn, ws *websocket.Conn) net.Conn {
	ws.SetReadLimit(-1)
	return &wsNetConn{ws: ws, raw: raw}
}

func (c *wsNetConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.readEOF {
			return 0, io.EOF
		}
		if c.reader == nil {
			typ, reader, err := c.ws.Reader(context.Background())
			if err != nil {
				if normalWebSocketClose(err) {
					c.readEOF = true
					return 0, io.EOF
				}
				return 0, err
			}
			if typ != websocket.MessageBinary {
				err := fmt.Errorf("unexpected WebSocket message type %d", typ)
				_ = c.ws.Close(websocket.StatusUnsupportedData, err.Error())
				return 0, err
			}
			c.reader = reader
		}

		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		if isTimeout(err) {
			_ = c.raw.Close()
		}
		return n, err
	}
}

func (c *wsNetConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.ws.Write(context.Background(), websocket.MessageBinary, p); err != nil {
		if isTimeout(err) {
			_ = c.raw.Close()
		}
		return 0, err
	}
	return len(p), nil
}

func (c *wsNetConn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

func (c *wsNetConn) LocalAddr() net.Addr  { return c.raw.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr { return c.raw.RemoteAddr() }

func (c *wsNetConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	type timeout interface{ Timeout() bool }
	var target timeout
	return errors.As(err, &target) && target.Timeout()
}

func normalWebSocketClose(err error) bool {
	switch websocket.CloseStatus(err) {
	case websocket.StatusNormalClosure, websocket.StatusGoingAway:
		return true
	default:
		return false
	}
}
