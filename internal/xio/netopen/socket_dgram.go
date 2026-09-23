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

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/sockopt"
	"golang.org/x/sys/unix"
)

// SOCKET-SENDTO stays unconnected and only accepts replies from the configured
// peer. SOCKET-DATAGRAM stays unconnected and accepts any sender unless
// range/tcpwrap restricts them.
func openSocketSendto(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, true)
}

func openSocketDatagram(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, false)
}

func openSocketDgram(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, exactPeer bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := socketCallFromConfig(s)
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
	if s.Network.RawBindSet {
		bsa, err := packRawSockaddr(c.domain, s.Network.RawBind)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := bindRaw(ctx, fd, bsa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if err := sockopt.ApplyGenericSetsockopt(fd, s, sockopt.SockoptPhaseConnected); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f, err := fileFromFD(fd, "socket-dgram")
	if err != nil {
		return nil, err
	}
	st, err := xio.SetupConnectedStream(s, &socketDgramStream{
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
	return xio.NewReady(s.Type, st)
}

func openSocketRecv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, false)
}

func openSocketRecvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, true)
}

func openSocketRecvCommon(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global, from bool) (*xio.Opened, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !from && mode == xio.ModeWrite {
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	fork := from && xio.ForkRequested(s)
	c, err := socketCallFromConfig(s)
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
	if err := sockopt.ApplySocketOptions(fd, s); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := sockopt.ApplyGenericSetsockopt(fd, s, sockopt.SockoptPhasePrebind); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := bindRaw(ctx, fd, sa); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if err := sockopt.ApplyGenericSetsockopt(fd, s, sockopt.SockoptPhaseConnected); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	if fork {
		if err := xio.ApplyFDLifecycleOnFD(fd, s); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := sockopt.ApplyLateSocketOptions(fd, s); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
	}
	f, err := fileFromFD(fd, "socket-recv")
	if err != nil {
		return nil, err
	}
	local := filePacketAddr(f)

	if fork {
		return openSocketRecvfromFork(ctx, s, g, f, filter)
	}
	if from {
		return openSocketRecvfromOneShot(ctx, s, g, f, filter, local)
	}

	st, err := xio.SetupConnectedStream(s, &socketDgramStream{
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
	return xio.NewReady(s.Type, st)
}

func openSocketRecvfromFork(ctx context.Context, s addrconfig.Address, g *xio.Global, f *os.File, filter *xio.PeerFilter) (*xio.Opened, error) {
	_, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		logx.CloseQuiet(f)
		return nil, ferr
	}
	rcvTimeout, err := xio.RecvTimeout(s)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	ln := &socketRecvfromListener{
		f:          f,
		g:          g,
		ctx:        ctx,
		filter:     filter,
		rcvTimeout: rcvTimeout,
		nullEOF:    s.Transfer.NullEOF.Value,
	}
	return xio.NewAcceptParent(s.Type, xio.AcceptParent{
		ForkSocketpair: true,
		Listener:       ln,
		MaxChildren:    maxChildren,
		WrapDial:       xio.DefaultWrapOpened(s),
	})
}

func openSocketRecvfromOneShot(ctx context.Context, s addrconfig.Address, g *xio.Global, f *os.File, filter *xio.PeerFilter, local net.Addr) (*xio.Opened, error) {
	buf := make([]byte, dgramBufSize(g.Options()))
	n, from, err := recvSocketFiltered(ctx, f, buf, filter, g, local, emptyDatagramPolicy{NullEOF: s.Transfer.NullEOF.Value})
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	rememberSocketPeer(g, from, local)
	st, err := xio.SetupConnectedStream(s, &socketRecvfromStream{
		f:      f,
		peer:   cloneSockaddr(from),
		first:  newFirstPacket(append([]byte(nil), buf[:n]...)),
		local:  local,
		remote: packetAddrFromSockaddr(from),
	})
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	return xio.NewReady(s.Type, st)
}

// emptyDatagramPolicy is how a SOCK_DGRAM receive treats a zero-length packet.
type emptyDatagramPolicy struct {
	NullEOF bool
}

func recvSocketFiltered(ctx context.Context, f *os.File, buf []byte, filter *xio.PeerFilter, g *xio.Global, local net.Addr, empty emptyDatagramPolicy) (int, unix.Sockaddr, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	got := waitOneshotPacket(ctx, g, buf, func(buf []byte) (int, []byte, unix.Sockaddr, error) {
		n, from, err := recvfromFile(f, buf)
		return n, nil, from, err
	}, func(from unix.Sockaddr) error {
		return filter.AllowAddr(packetAddrFromSockaddr(from), local)
	}, empty.NullEOF)
	if got.err != nil {
		return 0, nil, got.err
	}
	return got.n, got.addr, nil
}

func socketIPFilterOrError(ctx context.Context, s addrconfig.Address, g *xio.Global, domain int) (*xio.PeerFilter, error) {
	if err := socketFilterFamilyOK(s, domain); err != nil {
		return nil, err
	}
	return xio.PreparedPeerFilter(ctx, s, g.Options(), g.Logger())
}

func socketFilterFamilyOK(config addrconfig.Address, domain int) error {
	opt := socketFilterOptionName(config)
	if opt == "" {
		return nil
	}
	if domain != unix.AF_INET && domain != unix.AF_INET6 {
		return fmt.Errorf("%s option not supported with address family %d", opt, domain)
	}
	return nil
}

func socketFilterOptionName(config addrconfig.Address) string {
	n := config.Network
	if n.RangeSet {
		return "range"
	}
	if n.TCPWrap.Set {
		return "tcpwrap"
	}
	if n.TCPWrapEtc.Set {
		return "tcpwrap-etc"
	}
	if n.HostsAllow.Set {
		return "hosts-allow"
	}
	if n.HostsDeny.Set {
		return "hosts-deny"
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

func dgramBufSize(opts xio.Options) int {
	n := 65535
	if opts.BlockSize > n {
		n = opts.BlockSize
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
	return writeFileSyscall(f, p, func(fd int) error {
		return sendtoRaw(fd, p, sa)
	})
}

func sendtoFileSock(f *os.File, p []byte, to unix.Sockaddr) (int, error) {
	if to == nil {
		return 0, fmt.Errorf("no peer")
	}
	return writeFileSyscall(f, p, func(fd int) error {
		return unix.Sendto(fd, p, 0, to)
	})
}

func writeFileSyscall(f *os.File, p []byte, write func(fd int) error) (int, error) {
	sc, err := f.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var writeErr error
	err = sc.Write(func(fd uintptr) bool {
		writeErr = write(int(fd))
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
			g.Peer.PeerAddr = xio.FormatSocatAddr(a.IP.String())
			g.Peer.PeerPort = strconv.Itoa(a.Port)
		}
	case *net.UnixAddr:
		if a.Name != "" {
			g.Peer.PeerAddr = a.Name
		} else {
			g.Peer.PeerAddr = a.String()
		}
	default:
		if s := a.String(); s != "" {
			g.Peer.PeerAddr = s
		}
	}
	switch a := local.(type) {
	case *net.UDPAddr:
		if a != nil && a.IP != nil {
			g.Peer.SockAddr = xio.FormatSocatAddr(a.IP.String())
			g.Peer.SockPort = strconv.Itoa(a.Port)
		}
	case *net.TCPAddr:
		if a != nil && a.IP != nil {
			g.Peer.SockAddr = xio.FormatSocatAddr(a.IP.String())
			g.Peer.SockPort = strconv.Itoa(a.Port)
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
	return readScratchFiltered(ctx, p, func(buf []byte) (int, unix.Sockaddr, error) {
		return recvfromFile(r.f, buf)
	}, func(from unix.Sockaddr) (bool, error) {
		if r.exactPeer && !sendtoPeerMatches(r.dest, from) {
			return refusePacket(ctx, r.g, fmt.Errorf("recvfrom(): wrong peer address, ignoring packet"))
		}
		if !r.exactPeer {
			return refusePacket(ctx, r.g, r.filter.AllowAddr(packetAddrFromSockaddr(from), r.local))
		}
		return true, nil
	})
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
	f      *os.File
	peer   unix.Sockaddr
	first  firstPacket
	local  net.Addr
	remote net.Addr
}

func (r *socketRecvfromStream) Read(p []byte) (int, error) {
	if first, ok := r.first.take(); ok {
		return copyOneshotFirst(p, first)
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
	g          *xio.Global
	ctx        context.Context
	filter     *xio.PeerFilter
	rcvTimeout time.Duration
	nullEOF    bool
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
	buf := make([]byte, dgramBufSize(l.g.Options()))
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return recvfromForkAcceptor[unix.Sockaddr]{
		ctx:             l.ctx,
		rcvTimeout:      l.rcvTimeout,
		setReadDeadline: l.f.SetReadDeadline,
	}.acceptLoop(buf, func(buf []byte) (int, []byte, unix.Sockaddr, error) {
		n, from, err := recvfromFile(l.f, buf)
		return n, nil, from, err
	}, func(n int, _ []byte, buf []byte, from unix.Sockaddr) acceptNext {
		if xio.IgnoreEmptyDatagram(n, nil, l.nullEOF) {
			return acceptAgain()
		}
		local := filePacketAddr(l.f)
		if err := l.filter.AllowAddr(packetAddrFromSockaddr(from), local); err != nil {
			if stop := logOrStopPeerFilter(ctx, l.g, err); stop != nil {
				return acceptFail(stop)
			}
			return acceptAgain()
		}
		session := l.g.ForkSession()
		rememberSocketPeer(session, from, local)
		peer := cloneSockaddr(from)
		return acceptChild(newOneshotForkConn(
			append([]byte(nil), buf[:n]...),
			local,
			packetAddrFromSockaddr(from),
			session,
			&l.writeMu,
			l.f.SetWriteDeadline,
			func(p []byte) (int, error) { return sendtoFileSock(l.f, p, peer) },
			nil,
		), nil)
	})
}
