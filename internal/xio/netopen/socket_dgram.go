//go:build linux || darwin

package netopen

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

// SOCKET-SENDTO stays unconnected and only accepts replies from the configured
// peer. SOCKET-DATAGRAM stays unconnected and accepts any sender unless
// range/tcpwrap restricts them.
func openSocketSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, true)
}

func openSocketDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, false)
}

func openSocketDgram(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, exactPeer bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := parseSocketDgramCall(s)
	if err != nil {
		return nil, err
	}
	dest, err := packRawSockaddr(c.domain, c.addr)
	if err != nil {
		return nil, err
	}
	var filter *xio.PeerFilter
	if !exactPeer {
		filter, err = socketIPFilterOrError(ctx, s, g, c.domain)
		if err != nil {
			return nil, err
		}
	}
	fd, err := newSocket(c.domain, c.typ, c.proto)
	if err != nil {
		return nil, err
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
		bsa, err := packRawSockaddr(c.domain, bdata)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := bindRaw(ctx, fd, bsa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhaseConnected); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f, err := fileFromFD(fd, "socket-dgram")
	if err != nil {
		return nil, err
	}
	st, err := xio.WrapCommonAfterConnected(s, &socketDgramStream{
		f:         f,
		dest:      dest,
		exactPeer: exactPeer,
		filter:    filter,
		g:         g,
		ctx:       ctx,
		local:     filePacketAddr(f),
	})
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

func openSocketRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, false)
}

func openSocketRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, true)
}

func openSocketRecvCommon(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, from bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !from && mode == xio.ModeWrite {
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	c, err := parseSocketDgramCall(s)
	if err != nil {
		return nil, err
	}
	sa, err := packRawSockaddr(c.domain, c.addr)
	if err != nil {
		return nil, err
	}
	filter, err := socketIPFilterOrError(ctx, s, g, c.domain)
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
	if err := xio.ApplySocketOptions(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhasePrebind); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := bindRaw(ctx, fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := xio.ApplyGenericSetsockopt(fd, s, xio.SockoptPhaseConnected); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f, err := fileFromFD(fd, "socket-recv")
	if err != nil {
		return nil, err
	}
	local := filePacketAddr(f)
	xio.NoteListenBound(local)

	if from && s.BoolOption("fork") {
		return openSocketRecvfromFork(ctx, s, g, f, filter)
	}
	if from {
		return openSocketRecvfromOneShot(ctx, s, g, f, filter, local)
	}

	st, err := xio.WrapCommonAfterConnected(s, &socketDgramStream{
		f:      f,
		filter: filter,
		g:      g,
		ctx:    ctx,
		local:  local,
		recv:   true,
	})
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

func openSocketRecvfromFork(ctx context.Context, s parse.Spec, g *xio.Global, f *os.File, filter *xio.PeerFilter) (*xio.Opened, error) {
	_, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		logx.CloseQuiet(f)
		return nil, ferr
	}
	rcvTimeout, err := xio.RecvTimeoutFromSpec(s)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	ln := &socketRecvfromListener{
		f:          f,
		spec:       s,
		g:          g,
		ctx:        ctx,
		filter:     filter,
		rcvTimeout: rcvTimeout,
	}
	return &xio.Opened{
		Kind:        xio.KindListen,
		Listener:    ln,
		Label:       s.Type,
		MaxChildren: maxChildren,
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	}, nil
}

func openSocketRecvfromOneShot(ctx context.Context, s parse.Spec, g *xio.Global, f *os.File, filter *xio.PeerFilter, local net.Addr) (*xio.Opened, error) {
	buf := make([]byte, dgramBufSize(g))
	n, from, err := recvSocketFiltered(ctx, f, buf, filter, g, local)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	rememberSocketPeer(g, from, local)
	st, err := xio.WrapCommonAfterConnected(s, &socketRecvfromStream{
		f:            f,
		peer:         cloneSockaddr(from),
		first:        append([]byte(nil), buf[:n]...),
		firstPending: true,
		local:        local,
		remote:       packetAddrFromSockaddr(from),
	})
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

func recvSocketFiltered(ctx context.Context, f *os.File, buf []byte, filter *xio.PeerFilter, g *xio.Global, local net.Addr) (int, unix.Sockaddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		n, _, from, err := xio.RecvOneCtx(ctx, func() (int, []byte, unix.Sockaddr, error) {
			nn, a, e := recvfromFile(f, buf)
			return nn, nil, a, e
		})
		if err != nil {
			return 0, nil, err
		}
		if err := filter.AllowAddr(packetAddrFromSockaddr(from), local); err != nil {
			if stop := logOrStopPeerFilter(ctx, g, err); stop != nil {
				return 0, nil, stop
			}
			continue
		}
		return n, from, nil
	}
}

func socketIPFilterOrError(ctx context.Context, s parse.Spec, g *xio.Global, domain int) (*xio.PeerFilter, error) {
	if err := socketFilterFamilyOK(s, domain); err != nil {
		return nil, err
	}
	return xio.NewPeerFilter(ctx, s, g), nil
}

func socketFilterFamilyOK(s parse.Spec, domain int) error {
	opt := socketFilterOptionName(s)
	if opt == "" {
		return nil
	}
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return fmt.Errorf("%s option not supported with address family %d", opt, domain)
	}
	return nil
}

func socketFilterOptionName(s parse.Spec) string {
	if _, ok := s.OptionNamed("range"); ok {
		return "range"
	}
	for _, name := range []string{
		"tcpwrap", "tcpwrap-etc", "tcpwrap-dir",
		"hosts-allow", "hosts-deny", "allow-table", "deny-table",
	} {
		if s.HasOption(name) {
			return name
		}
	}
	return ""
}

func fileFromFD(fd int, name string) (*os.File, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("invalid fd")
	}
	return f, nil
}

func dgramBufSize(g *xio.Global) int {
	n := 65535
	if g != nil && g.BlockSize > n {
		n = g.BlockSize
	}
	return n
}

func recvfromFile(f *os.File, p []byte) (int, unix.Sockaddr, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, nil, err
	}
	var n int
	var from unix.Sockaddr
	var readErr error
	err = sc.Read(func(fd uintptr) bool {
		n, from, readErr = unix.Recvfrom(int(fd), p, 0)
		if readErr == unix.EAGAIN || readErr == unix.EWOULDBLOCK || readErr == unix.EINTR {
			return false
		}
		return true
	})
	if err != nil {
		return 0, nil, err
	}
	return n, from, readErr
}

func sendtoFileRaw(f *os.File, p []byte, sa rawSockaddr) (int, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var writeErr error
	err = sc.Write(func(fd uintptr) bool {
		writeErr = sendtoRaw(int(fd), p, sa)
		if writeErr == unix.EAGAIN || writeErr == unix.EWOULDBLOCK || writeErr == unix.EINTR {
			return false
		}
		if writeErr == nil {
			n = len(p)
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	return n, writeErr
}

func sendtoFileSock(f *os.File, p []byte, to unix.Sockaddr) (int, error) {
	if to == nil {
		return 0, fmt.Errorf("no peer")
	}
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var writeErr error
	err = sc.Write(func(fd uintptr) bool {
		writeErr = unix.Sendto(int(fd), p, 0, to)
		if writeErr == unix.EAGAIN || writeErr == unix.EWOULDBLOCK || writeErr == unix.EINTR {
			return false
		}
		if writeErr == nil {
			n = len(p)
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	return n, writeErr
}

func filePacketAddr(f *os.File) net.Addr {
	if f == nil {
		return &net.IPAddr{}
	}
	sc, err := f.SyscallConn()
	if err != nil {
		return &net.IPAddr{}
	}
	var addr net.Addr
	_ = sc.Control(func(fd uintptr) {
		sa, err := unix.Getsockname(int(fd))
		if err != nil {
			addr = &net.IPAddr{}
			return
		}
		addr = packetAddrFromSockaddr(sa)
	})
	if addr == nil {
		return &net.IPAddr{}
	}
	return addr
}

func packetAddrFromSockaddr(sa unix.Sockaddr) net.Addr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		ip := make(net.IP, 4)
		copy(ip, a.Addr[:])
		return &net.UDPAddr{IP: ip, Port: a.Port}
	case *unix.SockaddrInet6:
		ip := make(net.IP, 16)
		copy(ip, a.Addr[:])
		zone := ""
		if a.ZoneId != 0 {
			zone = strconv.FormatUint(uint64(a.ZoneId), 10)
		}
		return &net.UDPAddr{IP: ip, Port: a.Port, Zone: zone}
	case *unix.SockaddrUnix:
		return &net.UnixAddr{Name: a.Name, Net: "unixgram"}
	default:
		return sockAddrToNetAddr(sa)
	}
}

func cloneSockaddr(sa unix.Sockaddr) unix.Sockaddr {
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		c := *a
		return &c
	case *unix.SockaddrInet6:
		c := *a
		return &c
	case *unix.SockaddrUnix:
		c := *a
		return &c
	default:
		return sa
	}
}

func rememberSocketPeer(g *xio.Global, from unix.Sockaddr, local net.Addr) {
	if g == nil {
		return
	}
	switch a := packetAddrFromSockaddr(from).(type) {
	case *net.UDPAddr:
		if a.IP != nil {
			g.PeerAddr = xio.FormatSocatAddr(a.IP.String())
			g.PeerPort = strconv.Itoa(a.Port)
		}
	case *net.UnixAddr:
		if a.Name != "" {
			g.PeerAddr = a.Name
		} else {
			g.PeerAddr = a.String()
		}
	default:
		if s := a.String(); s != "" {
			g.PeerAddr = s
		}
	}
	switch a := local.(type) {
	case *net.UDPAddr:
		if a != nil && a.IP != nil {
			g.SockAddr = xio.FormatSocatAddr(a.IP.String())
			g.SockPort = strconv.Itoa(a.Port)
		}
	case *net.TCPAddr:
		if a != nil && a.IP != nil {
			g.SockAddr = xio.FormatSocatAddr(a.IP.String())
			g.SockPort = strconv.Itoa(a.Port)
		}
	}
}

func sendtoPeerMatches(want rawSockaddr, got unix.Sockaddr) bool {
	if got == nil {
		return true
	}
	switch a := got.(type) {
	case *unix.SockaddrInet4:
		port, ip, ok := packedIPv4(want)
		return ok && port == a.Port && ip == a.Addr
	case *unix.SockaddrInet6:
		port, ip, ok := packedIPv6(want)
		return ok && port == a.Port && ip == a.Addr
	case *unix.SockaddrUnix:
		if unixgramUnnamed(a.Name) {
			return true
		}
		return unixAddr(packedUnixPath(want)) == unixAddr(a.Name)
	default:
		return false
	}
}

func packedIPv4(sa rawSockaddr) (port int, ip [4]byte, ok bool) {
	const hdr = 2
	if sockaddrFamily(sa.buf) != unix.AF_INET || len(sa.buf) < hdr+6 {
		return 0, ip, false
	}
	port = int(sa.buf[hdr])<<8 | int(sa.buf[hdr+1])
	copy(ip[:], sa.buf[hdr+2:hdr+6])
	return port, ip, true
}

func packedIPv6(sa rawSockaddr) (port int, ip [16]byte, ok bool) {
	const hdr = 2
	// port(2) + flowinfo(4) + addr(16)
	if sockaddrFamily(sa.buf) != unix.AF_INET6 || len(sa.buf) < hdr+22 {
		return 0, ip, false
	}
	port = int(sa.buf[hdr])<<8 | int(sa.buf[hdr+1])
	copy(ip[:], sa.buf[hdr+6:hdr+22])
	return port, ip, true
}

func packedUnixPath(sa rawSockaddr) string {
	const hdr = 2
	if len(sa.buf) <= hdr {
		return ""
	}
	data := sa.buf[hdr:]
	if sockaddrFamily(sa.buf) != unix.AF_UNIX {
		return ""
	}
	if len(data) > 0 && data[0] == 0 {
		return string(data)
	}
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}

type socketDgramStream struct {
	f         *os.File
	dest      rawSockaddr
	exactPeer bool
	filter    *xio.PeerFilter
	g         *xio.Global
	ctx       context.Context
	local     net.Addr
	recv      bool
}

func (r *socketDgramStream) Read(p []byte) (int, error) {
	ctx := r.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	scratch := make([]byte, len(p))
	for {
		n, _, from, err := xio.RecvOneCtx(ctx, func() (int, []byte, unix.Sockaddr, error) {
			nn, a, e := recvfromFile(r.f, scratch)
			return nn, nil, a, e
		})
		if err != nil {
			return n, err
		}
		if r.exactPeer && !sendtoPeerMatches(r.dest, from) {
			if stop := logOrStopPeerFilter(ctx, r.g, fmt.Errorf("recvfrom(): wrong peer address, ignoring packet")); stop != nil {
				return 0, stop
			}
			continue
		}
		if !r.exactPeer {
			if err := r.filter.AllowAddr(packetAddrFromSockaddr(from), r.local); err != nil {
				if stop := logOrStopPeerFilter(ctx, r.g, err); stop != nil {
					return 0, stop
				}
				continue
			}
		}
		return copy(p, scratch[:n]), nil
	}
}

func (r *socketDgramStream) Write(p []byte) (int, error) {
	if r.recv {
		return 0, fmt.Errorf("SOCKET-RECV is read-only")
	}
	return sendtoFileRaw(r.f, p, r.dest)
}

func (r *socketDgramStream) Close() error                       { return r.f.Close() }
func (r *socketDgramStream) ShutdownWrite() error               { return nil }
func (r *socketDgramStream) LocalAddr() net.Addr                { return r.local }
func (r *socketDgramStream) RemoteAddr() net.Addr               { return packetAddrFromRaw(r.dest) }
func (r *socketDgramStream) SetDeadline(t time.Time) error      { return r.f.SetDeadline(t) }
func (r *socketDgramStream) SetReadDeadline(t time.Time) error  { return r.f.SetReadDeadline(t) }
func (r *socketDgramStream) SetWriteDeadline(t time.Time) error { return r.f.SetWriteDeadline(t) }
func (r *socketDgramStream) SyscallConn() (syscall.RawConn, error) {
	return r.f.SyscallConn()
}

func packetAddrFromRaw(sa rawSockaddr) net.Addr {
	if port, ip, ok := packedIPv4(sa); ok {
		out := make(net.IP, 4)
		copy(out, ip[:])
		return &net.UDPAddr{IP: out, Port: port}
	}
	if port, ip, ok := packedIPv6(sa); ok {
		out := make(net.IP, 16)
		copy(out, ip[:])
		return &net.UDPAddr{IP: out, Port: port}
	}
	if path := packedUnixPath(sa); path != "" || sockaddrFamily(sa.buf) == unix.AF_UNIX {
		return &net.UnixAddr{Name: path, Net: "unixgram"}
	}
	return &net.IPAddr{}
}

type socketRecvfromStream struct {
	f            *os.File
	peer         unix.Sockaddr
	first        []byte
	firstPending bool
	local        net.Addr
	remote       net.Addr
}

func (r *socketRecvfromStream) Read(p []byte) (int, error) {
	if r.firstPending {
		r.firstPending = false
		n := copy(p, r.first)
		r.first = nil
		return n, nil
	}
	return 0, io.EOF
}

func (r *socketRecvfromStream) Write(p []byte) (int, error) {
	return sendtoFileSock(r.f, p, r.peer)
}

func (r *socketRecvfromStream) Close() error                       { return r.f.Close() }
func (r *socketRecvfromStream) ShutdownWrite() error               { return nil }
func (r *socketRecvfromStream) LocalAddr() net.Addr                { return r.local }
func (r *socketRecvfromStream) RemoteAddr() net.Addr               { return r.remote }
func (r *socketRecvfromStream) SetDeadline(t time.Time) error      { return r.f.SetDeadline(t) }
func (r *socketRecvfromStream) SetReadDeadline(t time.Time) error  { return r.f.SetReadDeadline(t) }
func (r *socketRecvfromStream) SetWriteDeadline(t time.Time) error { return r.f.SetWriteDeadline(t) }
func (r *socketRecvfromStream) NetConn() net.Conn {
	return &rawFileConn{f: r.f, local: r.local, remote: r.remote}
}

type socketRecvfromListener struct {
	f          *os.File
	spec       parse.Spec
	g          *xio.Global
	ctx        context.Context
	filter     *xio.PeerFilter
	rcvTimeout time.Duration
	writeMu    sync.Mutex
}

func (l *socketRecvfromListener) Addr() net.Addr { return filePacketAddr(l.f) }

func (l *socketRecvfromListener) Close() error {
	if l.f == nil {
		return nil
	}
	return l.f.Close()
}

func (l *socketRecvfromListener) Accept() (net.Conn, error) {
	buf := make([]byte, dgramBufSize(l.g))
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if l.rcvTimeout > 0 {
			_ = l.f.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		n, _, from, err := xio.RecvOneCtx(ctx, func() (int, []byte, unix.Sockaddr, error) {
			nn, a, e := recvfromFile(l.f, buf)
			return nn, nil, a, e
		})
		if err != nil {
			if l.ctx != nil && l.ctx.Err() != nil {
				return nil, err
			}
			if l.rcvTimeout > 0 && xio.IsTimeoutErr(err) {
				continue
			}
			return nil, err
		}
		local := filePacketAddr(l.f)
		if err := l.filter.AllowAddr(packetAddrFromSockaddr(from), local); err != nil {
			if stop := logOrStopPeerFilter(ctx, l.g, err); stop != nil {
				return nil, stop
			}
			continue
		}
		session := &xio.Global{}
		if l.g != nil {
			session.Log = l.g.Log
			session.Progname = l.g.Progname
		}
		rememberSocketPeer(session, from, local)
		return &socketPacketConn{
			f:            l.f,
			peer:         cloneSockaddr(from),
			first:        append([]byte(nil), buf[:n]...),
			firstPending: true,
			local:        local,
			remote:       packetAddrFromSockaddr(from),
			env:          session.SessionVars,
			writeMu:      &l.writeMu,
		}, nil
	}
}

type socketPacketConn struct {
	f             *os.File
	peer          unix.Sockaddr
	first         []byte
	firstPending  bool
	local         net.Addr
	remote        net.Addr
	env           map[string]string
	writeMu       *sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func (c *socketPacketConn) SessionEnvironment() map[string]string { return c.env }

func (c *socketPacketConn) Read(p []byte) (int, error) {
	if c.firstPending {
		c.firstPending = false
		n := copy(p, c.first)
		c.first = nil
		return n, nil
	}
	return 0, io.EOF
}

func (c *socketPacketConn) Write(p []byte) (int, error) {
	c.deadlineMu.Lock()
	deadline := c.writeDeadline
	c.deadlineMu.Unlock()
	return writeSharedPacket(c.writeMu, deadline, c.f.SetWriteDeadline, func() (int, error) {
		return sendtoFileSock(c.f, p, c.peer)
	})
}

func (c *socketPacketConn) Close() error { return nil }

func (c *socketPacketConn) LocalAddr() net.Addr  { return c.local }
func (c *socketPacketConn) RemoteAddr() net.Addr { return c.remote }
func (c *socketPacketConn) SetDeadline(t time.Time) error {
	return c.SetWriteDeadline(t)
}
func (c *socketPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *socketPacketConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = t
	c.deadlineMu.Unlock()
	return nil
}
