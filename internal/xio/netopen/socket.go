//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// SOCKET-CONNECT:<domain>:<protocol>:<remote-address>
// Generic raw sockaddr connect. Address is hex/data without sa_family.
func openSocketConnect(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	call, err := parseSocketStreamCall(s)
	if err != nil {
		return nil, err
	}
	sa, err := packRawSockaddr(call.domain, call.addr)
	if err != nil {
		return nil, err
	}
	timeout := xio.ConnectTimeout(s)
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, "socket connect", func() error {
			c, e := dialRawSocket(dctx, call, sa, s, timeout)
			if e != nil {
				return e
			}
			conn = c
			return nil
		})
		return conn, err
	}
	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: "SOCKET-CONNECT",
		Dial:  dialOnce,
		LogOK: true,
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	})
}

func dialRawSocket(ctx context.Context, call socketCall, sa rawSockaddr, s parse.Spec, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	fd, err := newSocket(call.domain, call.typ, call.proto)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if err := applySocketOpts(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		bdata, berr := xio.ParseSocatData(bind)
		if berr != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, berr
		}
		bsa, err := packRawSockaddr(call.domain, bdata)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
		if err := bindRaw(ctx, fd, bsa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if err := connectRaw(ctx, fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhaseConnected); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	return connFromFD(fd, "socket-connect")
}

func connFromFD(fd int, name string) (net.Conn, error) {
	// os.File deadlines and poller reads require O_NONBLOCK before NewFile.
	if err := unix.SetNonblock(fd, true); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("invalid fd")
	}
	c, err := net.FileConn(f)
	if err == nil {
		logx.CloseQuiet(f)
		return c, nil
	}
	local, remote := addrsFromFD(fd)
	return &rawFileConn{f: f, local: local, remote: remote}, nil
}

type rawFileConn struct {
	f             *os.File
	local, remote net.Addr
}

func (c *rawFileConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *rawFileConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *rawFileConn) Close() error                       { return c.f.Close() }
func (c *rawFileConn) LocalAddr() net.Addr                { return c.local }
func (c *rawFileConn) RemoteAddr() net.Addr               { return c.remote }
func (c *rawFileConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *rawFileConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *rawFileConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
func (c *rawFileConn) SyscallConn() (syscall.RawConn, error) {
	return c.f.SyscallConn()
}

func (c *rawFileConn) CloseWrite() error {
	sc, err := c.f.SyscallConn()
	if err != nil {
		return err
	}
	var shutErr error
	if err := sc.Control(func(fd uintptr) {
		shutErr = unix.Shutdown(int(fd), unix.SHUT_WR)
	}); err != nil {
		return err
	}
	return shutErr
}

func addrsFromFD(fd int) (local, remote net.Addr) {
	if sa, err := unix.Getsockname(fd); err == nil {
		local = sockAddrToNetAddr(sa)
	}
	if sa, err := unix.Getpeername(fd); err == nil {
		remote = sockAddrToNetAddr(sa)
	}
	if local == nil {
		local = &net.IPAddr{}
	}
	if remote == nil {
		remote = &net.IPAddr{}
	}
	return local, remote
}

func sockAddrToNetAddr(sa unix.Sockaddr) net.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		return &net.TCPAddr{IP: net.IP(a.Addr[:]), Port: a.Port}
	case *unix.SockaddrInet6:
		return &net.TCPAddr{IP: net.IP(a.Addr[:]), Port: a.Port}
	case *unix.SockaddrUnix:
		return &net.UnixAddr{Name: a.Name, Net: "unix"}
	default:
		return &net.IPAddr{}
	}
}

// SOCKET-LISTEN:<domain>:<protocol>:<local-address>
func openSocketListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	c, err := parseSocketStreamCall(s)
	if err != nil {
		return nil, err
	}
	sa, err := packRawSockaddr(c.domain, c.addr)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(c.domain, c.typ, c.proto)
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyReuse(fd, s, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := applySocketOpts(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := bindRaw(ctx, fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("bind: %w", err)
	}
	backlog := 5
	if v := s.OptionValue("backlog", ""); v != "" {
		n, e := xio.ParseIntAny(v)
		if e != nil || n <= 0 {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("backlog: invalid value %q", v)
		}
		backlog = n
	}
	if err := unix.Listen(fd, backlog); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	ln := &rawListener{fd: fd, domain: c.domain}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    "SOCKET-LISTEN",
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapAccepted(s, c, func(c net.Conn) error {
				return xio.ApplyGenericSetsockoptToNetConn(c, s, xio.SockoptPhaseConnected)
			})
		},
	})
}

// rawListener adapts a listening FD to net.Listener.
// FileListener is used when Go recognizes the family so SetDeadline and
// Accept are interruptible. Unknown families stay on the raw fd: nonblocking
// poll honors deadlines/cancel, and accepted sockets go through connFromFD.
type rawListener struct {
	mu       sync.Mutex
	fd       int
	domain   int
	ln       net.Listener // lazy FileListener
	raw      bool         // FileListener unsupported; use poll/accept
	deadline time.Time
}

func (l *rawListener) fileLn() (net.Listener, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return l.ln, nil
	}
	if l.raw {
		if l.fd < 0 {
			return nil, net.ErrClosed
		}
		return nil, errNotNetFileListener
	}
	if l.fd < 0 {
		return nil, net.ErrClosed
	}
	// os.NewFile does not dup; FileListener copies internally, then Close
	// of *os.File closes the NewFile fd. Dup first so a FileListener error
	// does not close l.fd, which Accept's raw fallback and Close still own.
	nfd, err := dupFD(l.fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(nfd), "socket-listen")
	ln, err := net.FileListener(f)
	logx.CloseQuiet(f)
	if err != nil {
		if e := l.enterRawLocked(); e != nil {
			return nil, e
		}
		return nil, err
	}
	if err := unix.Close(l.fd); err != nil {
		l.fd = -1
		logx.CloseQuiet(ln)
		return nil, err
	}
	l.fd = -1
	l.ln = ln
	return l.ln, nil
}

func (l *rawListener) enterRawLocked() error {
	if l.raw {
		return nil
	}
	if l.fd < 0 {
		return net.ErrClosed
	}
	if err := unix.SetNonblock(l.fd, true); err != nil {
		return err
	}
	l.raw = true
	return nil
}

var errNotNetFileListener = errors.New("socket listener is not a net file listener")

func dupFD(fd int) (int, error) {
	nfd, err := unix.Dup(fd)
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(nfd)
	return nfd, nil
}

func (l *rawListener) Accept() (net.Conn, error) {
	ln, err := l.fileLn()
	if err == nil {
		return ln.Accept()
	}
	return l.acceptRaw()
}

func (l *rawListener) acceptRaw() (net.Conn, error) {
	for {
		l.mu.Lock()
		if l.fd < 0 {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		fd := l.fd
		deadline := l.deadline
		l.mu.Unlock()
		if err := rawAcceptDeadlineErr(deadline); err != nil {
			return nil, err
		}
		timeout := rawAcceptPollMs(deadline)
		pfd := []unix.PollFd{{Fd: unixConnectPollFd(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfd, timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		l.mu.Lock()
		closed := l.fd < 0
		deadline = l.deadline
		l.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if err := rawAcceptDeadlineErr(deadline); err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLNVAL != 0 {
			return nil, net.ErrClosed
		}
		nfd, err := acceptCloexec(fd)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				l.mu.Lock()
				closed := l.fd < 0
				l.mu.Unlock()
				if closed {
					return nil, net.ErrClosed
				}
			}
			return nil, err
		}
		l.mu.Lock()
		closed = l.fd < 0
		l.mu.Unlock()
		if closed {
			_ = unix.Close(nfd)
			return nil, net.ErrClosed
		}
		return connFromFD(nfd, "socket-accept")
	}
}

func rawAcceptDeadlineErr(deadline time.Time) error {
	if deadline.IsZero() || time.Now().Before(deadline) {
		return nil
	}
	return os.ErrDeadlineExceeded
}

func rawAcceptPollMs(deadline time.Time) int {
	timeout := unixConnectCancelPollMs
	if deadline.IsZero() {
		return timeout
	}
	rem := time.Until(deadline)
	if rem <= 0 {
		return 0
	}
	ms := int(rem / time.Millisecond)
	if ms < 1 {
		return 1
	}
	if ms < timeout {
		return ms
	}
	return timeout
}

func (l *rawListener) Close() error {
	l.mu.Lock()
	ln := l.ln
	fd := l.fd
	l.fd = -1
	l.mu.Unlock()
	if ln != nil {
		return ln.Close()
	}
	if fd >= 0 {
		return unix.Close(fd)
	}
	return nil
}

func (l *rawListener) SetDeadline(t time.Time) error {
	ln, err := l.fileLn()
	if err == nil {
		if d, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
			return d.SetDeadline(t)
		}
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd < 0 {
		return net.ErrClosed
	}
	l.deadline = t
	return nil
}

func (l *rawListener) Addr() net.Addr {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.ln != nil {
		return l.ln.Addr()
	}
	if l.fd < 0 {
		return &net.IPAddr{}
	}
	sa, err := unix.Getsockname(l.fd)
	if err != nil {
		return &net.IPAddr{}
	}
	return sockAddrToNetAddr(sa)
}
