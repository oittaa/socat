package netopen

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/sockopt"
)

func ancillaryBuffer(buf *[]byte, enabled bool) []byte {
	if !enabled {
		return nil
	}
	if *buf == nil {
		*buf = make([]byte, sockopt.AncillaryBufferSize)
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
	return &oneshotForkConn{
		first:            newFirstPacket(data),
		local:            local,
		remote:           remote,
		g:                session,
		writeMu:          writeMu,
		setWriteDeadline: setWriteDeadline,
		writeTo:          writeTo,
		drain:            drain,
	}
}

func (c *oneshotForkConn) Session() *xio.Global { return c.g }

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

// filteredPacketReader reads datagrams until one is accepted.
// read receives into the caller buffer. accept keeps the packet or, with a
// non-nil stop, ends the read. onReadErr maps a receive failure. deliver
// maps an accepted packet; without it the received count is returned as-is.
type filteredPacketReader[A any] struct {
	read      func(p []byte) (n int, oob []byte, addr A, err error)
	accept    func(n int, oob []byte, addr A) (keep bool, stop error)
	onReadErr func(n int, err error) (int, error)
	deliver   func(p []byte, n int, oob []byte) (int, error)
}

func (r filteredPacketReader[A]) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := r.read(p)
		if err != nil {
			if r.onReadErr != nil {
				return r.onReadErr(n, err)
			}
			return n, err
		}
		if r.accept != nil {
			keep, stop := r.accept(n, oob, addr)
			if stop != nil {
				return 0, stop
			}
			if !keep {
				continue
			}
		}
		if r.deliver != nil {
			return r.deliver(p, n, oob)
		}
		return n, nil
	}
}

// refusePacket logs a peer rejection and continues, unless the session
// context is done.
func refusePacket(ctx context.Context, g *xio.Global, err error) (keep bool, stop error) {
	if err == nil {
		return true, nil
	}
	if stop = logOrStopPeerFilter(ctx, g, err); stop != nil {
		return false, stop
	}
	return false, nil
}

// readScratchFiltered receives into storage owned by this call, then copies
// an accepted datagram into p. A receive error is returned without that
// copy: the count is the kernel count, and p is left untouched.
func readScratchFiltered[A any](
	ctx context.Context,
	p []byte,
	recv func(buf []byte) (int, A, error),
	accept func(A) (keep bool, stop error),
) (int, error) {
	scratch := make([]byte, len(p))
	return filteredPacketReader[A]{
		read: func([]byte) (int, []byte, A, error) {
			n, _, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, A, error) {
				nn, a, e := recv(scratch)
				return nn, nil, a, e
			})
			return n, nil, addr, err
		},
		accept: func(_ int, _ []byte, addr A) (bool, error) {
			return accept(addr)
		},
		deliver: func(dst []byte, n int, _ []byte) (int, error) {
			return copy(dst, scratch[:n]), nil
		},
	}.Read(p)
}

// oneshotPacket is the datagram that completed a one-shot opener wait.
// readFailed means err came from the receive, including cancellation.
// A filter refusal sets err and leaves readFailed false.
type oneshotPacket[A any] struct {
	n          int
	oob        []byte
	addr       A
	err        error
	readFailed bool
}

// waitOneshotPacket blocks until one datagram is accepted. nullEOF keeps a
// zero-length datagram; otherwise it is discarded and the wait continues.
// allow nil accepts every address.
func waitOneshotPacket[A any](
	ctx context.Context,
	g *xio.Global,
	buf []byte,
	read func(buf []byte) (n int, oob []byte, addr A, err error),
	allow func(A) error,
	nullEOF bool,
) oneshotPacket[A] {
	for {
		n, oob, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, A, error) {
			return read(buf)
		})
		if err != nil {
			return oneshotPacket[A]{n: n, oob: oob, addr: addr, err: err, readFailed: true}
		}
		if allow != nil {
			if ferr := allow(addr); ferr != nil {
				if _, stop := refusePacket(ctx, g, ferr); stop != nil {
					return oneshotPacket[A]{err: stop}
				}
				continue
			}
		}
		if xio.IgnoreEmptyDatagram(n, nil, nullEOF) {
			continue
		}
		return oneshotPacket[A]{n: n, oob: oob, addr: addr}
	}
}

// recvCanceled reports that err is the context ending the receive, so the
// caller did not observe a socket error.
func recvCanceled(ctx context.Context, err error) bool {
	return ctx != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())
}

// recvfromForkAcceptor is the shared *-RECVFROM,fork accept loop. A receive
// timeout retries. Context cancellation is returned as-is. onReadErr runs
// for every other receive error, before that error is returned.
type recvfromForkAcceptor[A any] struct {
	ctx             context.Context
	rcvTimeout      time.Duration
	setReadDeadline func(time.Time) error
	onReadErr       func(error)
}

func (a recvfromForkAcceptor[A]) acceptLoop(
	buf []byte,
	read func(buf []byte) (n int, oob []byte, addr A, err error),
	handle func(n int, oob []byte, buf []byte, addr A) acceptNext,
) (net.Conn, error) {
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if a.rcvTimeout > 0 && a.setReadDeadline != nil {
			_ = a.setReadDeadline(time.Now().Add(a.rcvTimeout))
		}
		n, oob, addr, err := xio.RecvOneCtx(ctx, func() (int, []byte, A, error) {
			return read(buf)
		})
		if err != nil {
			if a.ctx != nil && a.ctx.Err() != nil {
				return nil, err
			}
			if a.rcvTimeout > 0 && xio.IsTimeoutErr(err) {
				continue
			}
			if a.onReadErr != nil {
				a.onReadErr(err)
			}
			return nil, err
		}
		next := handle(n, oob, buf, addr)
		if next.again {
			continue
		}
		return next.conn, next.err
	}
}
