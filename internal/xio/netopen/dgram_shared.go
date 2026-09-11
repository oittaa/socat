package netopen

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func ancillaryBuffer(buf *[]byte, enabled bool) []byte {
	if !enabled {
		return nil
	}
	if *buf == nil {
		*buf = make([]byte, xio.AncillaryBufferSize)
	}
	return *buf
}

// copyOneshotFirst delivers a buffered *-RECVFROM datagram. An empty packet
// is EOF (null-eof, or a raw IPv4 header with no payload).
func copyOneshotFirst(p, first []byte) (int, error) {
	if len(first) == 0 {
		return 0, io.EOF
	}
	return copy(p, first), nil
}

// firstPacket is a datagram captured before the session conn is handed to
// the relay. pending is true even for a zero-length datagram.
type firstPacket struct {
	data    []byte
	pending bool
}

func newFirstPacket(data []byte) firstPacket {
	return firstPacket{data: data, pending: true}
}

func (f *firstPacket) take() (data []byte, ok bool) {
	if f == nil || !f.pending {
		return nil, false
	}
	f.pending = false
	data = f.data
	f.data = nil
	return data, true
}

// sharedWriteDeadline is the per-child write deadline for sockets shared
// across fork sessions. The listener's write lock is separate.
type sharedWriteDeadline struct {
	mu       sync.Mutex
	deadline time.Time
}

func (w *sharedWriteDeadline) set(t time.Time) {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
}

func (w *sharedWriteDeadline) get() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deadline
}

// writeSharedPacket serializes writes that share a listener socket. The
// deadline belongs to the child session, so install it only while that child
// owns the write lock and clear it before another child can write.
func writeSharedPacket(
	mu *sync.Mutex,
	deadline time.Time,
	setDeadline func(time.Time) error,
	write func() (int, error),
) (int, error) {
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	if setDeadline != nil {
		if err := setDeadline(deadline); err != nil {
			return 0, err
		}
	}
	n, writeErr := write()
	var clearErr error
	if setDeadline != nil {
		clearErr = setDeadline(time.Time{})
	}
	return n, errors.Join(writeErr, clearErr)
}

func writeToUDPWithFallback(c *net.UDPConn, p []byte, peer *net.UDPAddr) (int, error) {
	n, err := c.WriteToUDP(p, peer)
	if err == nil {
		return n, nil
	}
	if n2, err2 := c.Write(p); err2 == nil {
		return n2, nil
	}
	return n, err
}

// oneshotForkConn is one *-RECVFROM,fork child: deliver the opener, then EOF.
// Replies use the parent listen socket; Close does not close it.
type oneshotForkConn struct {
	first            firstPacket
	local, remote    net.Addr
	env              map[string]string
	g                *xio.Global
	writeMu          *sync.Mutex
	writeDL          sharedWriteDeadline
	setWriteDeadline func(time.Time) error
	writeTo          func([]byte) (int, error)
	drain            func(error)
}

func newOneshotForkConn(
	data []byte,
	local, remote net.Addr,
	session *xio.Global,
	writeMu *sync.Mutex,
	setWriteDeadline func(time.Time) error,
	writeTo func([]byte) (int, error),
	drain func(error),
) *oneshotForkConn {
	var env map[string]string
	if session != nil {
		env = session.SessionVarsSnapshot()
	}
	return &oneshotForkConn{
		first:            newFirstPacket(data),
		local:            local,
		remote:           remote,
		env:              env,
		g:                session,
		writeMu:          writeMu,
		setWriteDeadline: setWriteDeadline,
		writeTo:          writeTo,
		drain:            drain,
	}
}

func (c *oneshotForkConn) SessionEnvironment() map[string]string {
	if c.g != nil {
		return c.g.SessionVarsSnapshot()
	}
	return c.env
}

func (c *oneshotForkConn) Read(p []byte) (int, error) {
	if first, ok := c.first.take(); ok {
		return copyOneshotFirst(p, first)
	}
	return 0, io.EOF
}

func (c *oneshotForkConn) Write(p []byte) (int, error) {
	if c.writeTo == nil {
		return 0, net.ErrClosed
	}
	n, err := writeSharedPacket(c.writeMu, c.writeDL.get(), c.setWriteDeadline, func() (int, error) {
		return c.writeTo(p)
	})
	if c.drain != nil {
		c.drain(err)
	}
	return n, err
}

func (c *oneshotForkConn) Close() error { return nil }

func (c *oneshotForkConn) LocalAddr() net.Addr  { return c.local }
func (c *oneshotForkConn) RemoteAddr() net.Addr { return c.remote }
func (c *oneshotForkConn) SetDeadline(t time.Time) error {
	return c.SetWriteDeadline(t)
}
func (c *oneshotForkConn) SetReadDeadline(time.Time) error { return nil }
func (c *oneshotForkConn) SetWriteDeadline(t time.Time) error {
	c.writeDL.set(t)
	return nil
}
