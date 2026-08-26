//go:build linux

package netopen

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func init() {
	xio.FeatureVSOCK = true
}

func listenVSOCK(_ context.Context, port uint32, s parse.Spec, g *xio.Global) (net.Listener, error) {
	cid := uint32(unix.VMADDR_CID_ANY)
	bind, set, err := parseVsockBindOption(s, false)
	if err != nil {
		return nil, err
	}
	if set {
		cid = bind.cid
	}
	fd, err := vsockSocket(s)
	if err != nil {
		return nil, err
	}
	// Classic opt_so_reuseaddr has no default; do not turn SO_REUSEADDR on
	// unless reuseaddr is present (unlike TCP/SCTP listen in this port).
	if err := xio.ApplyReuse(fd, s, false); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := xio.ApplyNetworkSocketOptions(fd, s, "vsock"); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhasePrebind); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("vsock bind: %w", err)
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
		return nil, fmt.Errorf("vsock listen: %w", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("vsock getsockname: %w", err)
	}
	addr := vsockAddrFromSockaddr(sa)
	logVsockCID(g)
	return newVsockListener(fd, addr)
}

func vsockSocket(s parse.Spec) (int, error) {
	args, err := parseVsockSocketArgs(s)
	if err != nil {
		return -1, err
	}
	fd, err := newSocket(args.family, args.socktype, args.protocol)
	if err != nil {
		return -1, fmt.Errorf("vsock socket: %w", err)
	}
	return fd, nil
}

func dialVSOCK(ctx context.Context, remote vsockEndpoint, s parse.Spec, g *xio.Global, timeout time.Duration, control func(string, string, syscall.RawConn) error) (net.Conn, error) {
	args, err := parseVsockSocketArgs(s)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(args.family, args.socktype, args.protocol)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	if err := xio.ApplyReuse(fd, s, false); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := xio.ApplyNetworkSocketOptions(fd, s, "vsock"); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if control != nil {
		if err := control("vsock", remote.String(), rawFD(fd)); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
	}
	bind, set, err := parseVsockBindOption(s, true)
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if set {
		if err := unix.Bind(fd, &unix.SockaddrVM{CID: bind.cid, Port: bind.port}); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("vsock bind: %w", err)
		}
	}
	logVsockCID(g)
	cctx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		cctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	if g != nil && g.Log != nil {
		g.Log.Noticef("opening connection to AF=%d cid:%d port:%d", args.family, remote.cid, remote.port)
	}
	if err := connectVSOCK(cctx, fd, &unix.SockaddrVM{CID: remote.cid, Port: remote.port}); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	local := vsockAddrFromSockaddr(mustSockname(fd))
	peer, err := unix.Getpeername(fd)
	remoteAddr := &vsockAddr{CID: remote.cid, Port: remote.port}
	if err == nil {
		remoteAddr = vsockAddrFromSockaddr(peer)
	}
	return newVsockConn(fd, local, remoteAddr)
}

func connectVSOCK(ctx context.Context, fd int, sa unix.Sockaddr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- unix.Connect(fd, sa)
	}()
	select {
	case <-ctx.Done():
		_ = unix.Shutdown(fd, unix.SHUT_RDWR)
		<-done
		return ctx.Err()
	case err := <-done:
		if err == nil {
			return nil
		}
		if errors.Is(err, unix.EISCONN) {
			if _, e := unix.Getpeername(fd); e == nil {
				return nil
			}
		}
		return err
	}
}

func mustSockname(fd int) unix.Sockaddr {
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return &unix.SockaddrVM{}
	}
	return sa
}

func logVsockCID(g *xio.Global) {
	if g == nil || g.Log == nil {
		return
	}
	f, err := os.Open("/dev/vsock")
	if err != nil {
		g.Log.Warningf("open(\"/dev/vsock\", ...): %s", err)
		return
	}
	defer logx.CloseQuiet(f)
	cid, err := unix.IoctlGetInt(int(f.Fd()), unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID)
	if err != nil {
		g.Log.Warningf("ioctl(%d, IOCTL_VM_SOCKETS_GET_LOCAL_CID, ...): %s", int(f.Fd()), err)
		return
	}
	g.Log.Noticef("VSOCK CID=%d", uint32(cid)) // #nosec G115 -- ioctl writes a u32 CID
}

type vsockAddr struct {
	CID  uint32
	Port uint32
}

func (a *vsockAddr) Network() string { return "vsock" }

func (a *vsockAddr) String() string {
	if a == nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", a.CID, a.Port)
}

func vsockAddrFromSockaddr(sa unix.Sockaddr) *vsockAddr {
	if vm, ok := sa.(*unix.SockaddrVM); ok {
		return &vsockAddr{CID: vm.CID, Port: vm.Port}
	}
	return &vsockAddr{}
}

type vsockConn struct {
	f      *os.File
	rawFD  int
	local  *vsockAddr
	remote *vsockAddr
}

func newVsockConn(fd int, local, remote *vsockAddr) (*vsockConn, error) {
	// os.File deadlines require a nonblocking descriptor. Accept already
	// passes SOCK_NONBLOCK; connect() uses a blocking fd until here.
	if err := unix.SetNonblock(fd, true); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("vsock setnonblock: %w", err)
	}
	f := os.NewFile(uintptr(fd), "vsock")
	if f == nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("vsock: invalid fd")
	}
	return &vsockConn{f: f, rawFD: fd, local: local, remote: remote}, nil
}

func (c *vsockConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *vsockConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *vsockConn) Close() error                       { return c.f.Close() }
func (c *vsockConn) LocalAddr() net.Addr                { return c.local }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.remote }
func (c *vsockConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }

func (c *vsockConn) CloseWrite() error {
	return unix.Shutdown(c.rawFD, unix.SHUT_WR)
}

func (c *vsockConn) CloseRead() error {
	return unix.Shutdown(c.rawFD, unix.SHUT_RD)
}

func (c *vsockConn) SyscallConn() (syscall.RawConn, error) {
	return rawFD(c.rawFD), nil
}

type vsockListener struct {
	mu       sync.Mutex
	fd       int
	wakeR    int
	wakeW    int
	closed   bool
	deadline time.Time
	addr     *vsockAddr
}

func newVsockListener(fd int, addr *vsockAddr) (*vsockListener, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	wakeR, wakeW, err := newVsockWake()
	if err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	return &vsockListener{fd: fd, wakeR: wakeR, wakeW: wakeW, addr: addr}, nil
}

func newVsockWake() (r, w int, err error) {
	fd, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err == nil {
		return fd, fd, nil
	}
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return 0, 0, err
	}
	return p[0], p[1], nil
}

func (l *vsockListener) Addr() net.Addr { return l.addr }

func (l *vsockListener) SetDeadline(t time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return net.ErrClosed
	}
	l.deadline = t
	l.signalWakeLocked()
	return nil
}

func (l *vsockListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	fd, wakeR, wakeW := l.fd, l.wakeR, l.wakeW
	l.fd, l.wakeR, l.wakeW = -1, -1, -1
	l.mu.Unlock()
	signalWake(wakeW)
	var err error
	if fd >= 0 {
		err = unix.Close(fd)
	}
	closeWake(wakeR, wakeW)
	return err
}

func (l *vsockListener) signalWakeLocked() {
	signalWake(l.wakeW)
}

func signalWake(wakeW int) {
	if wakeW < 0 {
		return
	}
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], 1)
	_, _ = unix.Write(wakeW, buf[:])
}

func closeWake(wakeR, wakeW int) {
	if wakeR >= 0 {
		_ = unix.Close(wakeR)
	}
	if wakeW >= 0 && wakeW != wakeR {
		_ = unix.Close(wakeW)
	}
}

func (l *vsockListener) Accept() (net.Conn, error) {
	for {
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return nil, net.ErrClosed
		}
		deadline := l.deadline
		fd, wakeR := l.fd, l.wakeR
		l.mu.Unlock()
		if fd < 0 || wakeR < 0 {
			return nil, net.ErrClosed
		}
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			return nil, os.ErrDeadlineExceeded
		}
		timeout := vsockPollTimeoutMs(deadline)
		n, err := unix.Poll([]unix.PollFd{
			{Fd: pollFD(fd), Events: unix.POLLIN},
			{Fd: pollFD(wakeR), Events: unix.POLLIN},
		}, timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.ECONNABORTED) {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		drainWake(wakeR)
		l.mu.Lock()
		closed := l.closed
		deadline = l.deadline
		l.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if n == 0 || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			return nil, os.ErrDeadlineExceeded
		}
		nfd, sa, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) {
				return nil, net.ErrClosed
			}
			return nil, err
		}
		local := l.addr
		if lsa, e := unix.Getsockname(nfd); e == nil {
			local = vsockAddrFromSockaddr(lsa)
		}
		return newVsockConn(nfd, local, vsockAddrFromSockaddr(sa))
	}
}

func drainWake(wakeR int) {
	if wakeR < 0 {
		return
	}
	var buf [8]byte
	for {
		_, err := unix.Read(wakeR, buf[:])
		if err != nil {
			return
		}
	}
}

func vsockPollTimeoutMs(deadline time.Time) int {
	if deadline.IsZero() {
		return -1
	}
	d := time.Until(deadline)
	if d <= 0 {
		return 0
	}
	ms := d / time.Millisecond
	if ms < 1 {
		return 1
	}
	const maxMs = 1 << 30
	if ms > maxMs {
		return maxMs
	}
	return int(ms)
}

func pollFD(fd int) int32 {
	if fd < 0 || fd > math.MaxInt32 {
		return -1
	}
	return int32(fd) // #nosec G115 -- bounded to MaxInt32
}
