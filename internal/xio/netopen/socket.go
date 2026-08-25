//go:build unix

package netopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// SOCKET-CONNECT:<domain>:<protocol>:<remote-address>
// Generic raw sockaddr connect (classic). Address is hex/data without sa_family.
func openSocketConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	domain, proto, addrData, err := parseSocketParams(s, 3)
	if err != nil {
		return nil, err
	}
	if len(addrData) == 0 {
		return nil, fmt.Errorf("SOCKET-CONNECT requires remote address")
	}
	sa, salen, err := buildSockaddr(domain, addrData)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(domain, unix.SOCK_STREAM, proto)
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
		bsa, _, err := buildSockaddr(domain, bdata)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
		if err := unix.Bind(fd, bsa); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if err := connectRaw(fd, sa, salen); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("connect: %w", err)
	}
	f := osNewFile(fd, "socket-connect")
	st := xio.FileStream(f)
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: st, Label: "SOCKET-CONNECT"}, nil
}

// SOCKET-LISTEN:<domain>:<protocol>:<local-address>
func openSocketListen(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global) (*xio.Opened, error) {
	domain, proto, addrData, err := parseSocketParams(s, 3)
	if err != nil {
		return nil, err
	}
	// testaddrs probes SOCKET-LISTEN::::: — must fail fast, not hang on accept.
	if len(addrData) == 0 {
		return nil, fmt.Errorf("SOCKET-LISTEN requires local address")
	}
	sa, salen, err := buildSockaddr(domain, addrData)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(domain, unix.SOCK_STREAM, proto)
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
	if err := bindRaw(fd, sa, salen); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, fmt.Errorf("bind: %w", err)
	}
	backlog := 5
	if v := s.OptionValue("backlog", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			backlog = n
		}
	}
	if err := unix.Listen(fd, backlog); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	ln := &rawListener{fd: fd, domain: domain}
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    "SOCKET-LISTEN",
		WrapDial: wrapConn,
	})
}

// SOCKET-SENDTO / SOCKET-DATAGRAM: domain:type:protocol:remote
func openSocketSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, false)
}

func openSocketDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketDgram(ctx, s, mode, g, true)
}

func openSocketDgram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, connected bool) (*xio.Opened, error) {
	if len(s.Params) < 4 {
		return nil, fmt.Errorf("%s requires domain:type:protocol:address", s.Type)
	}
	domain, err := strconv.Atoi(s.Params[0])
	if err != nil {
		return nil, fmt.Errorf("domain: %w", err)
	}
	// Empty type (SOCKET-SENDTO:2::17:...) → SOCK_DGRAM
	typ := unix.SOCK_DGRAM
	if s.Params[1] != "" {
		typ, err = strconv.Atoi(s.Params[1])
		if err != nil {
			return nil, fmt.Errorf("type: %w", err)
		}
	}
	proto, err := strconv.Atoi(s.Params[2])
	if err != nil {
		// empty protocol → 0
		if s.Params[2] != "" {
			return nil, fmt.Errorf("protocol: %w", err)
		}
		proto = 0
	}
	addrText := rawSocketAddress(s, 3)
	if addrText == "" {
		addrText = strings.Join(s.Params[3:], ":")
	}
	addrData, err := xio.ParseSocatData(addrText)
	if err != nil {
		return nil, err
	}
	sa, salen, err := buildSockaddr(domain, addrData)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(domain, typ, proto)
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
		bsa, blen, err := buildSockaddr(domain, bdata)
		if err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
		if err := bindRaw(fd, bsa, blen); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if connected {
		if err := connectRaw(fd, sa, salen); err != nil {
			logx.CloseErr(unix.Close(fd))
			return nil, err
		}
	}
	f := osNewFile(fd, "socket-dgram")
	var st relay.Stream
	if connected {
		st = xio.FileStream(f)
	} else {
		st = &rawDgramStream{f: f, sa: sa, salen: salen}
	}
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

// SOCKET-RECV / SOCKET-RECVFROM
func openSocketRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, false)
}
func openSocketRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openSocketRecvCommon(ctx, s, mode, g, true)
}

func openSocketRecvCommon(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, from bool) (*xio.Opened, error) {
	if len(s.Params) < 4 {
		return nil, fmt.Errorf("%s requires domain:type:protocol:address", s.Type)
	}
	domain, _ := strconv.Atoi(s.Params[0])
	typ := unix.SOCK_DGRAM
	if s.Params[1] != "" {
		typ, _ = strconv.Atoi(s.Params[1])
	}
	proto := 0
	if s.Params[2] != "" {
		proto, _ = strconv.Atoi(s.Params[2])
	}
	addrText := rawSocketAddress(s, 3)
	if addrText == "" {
		addrText = strings.Join(s.Params[3:], ":")
	}
	addrData, err := xio.ParseSocatData(addrText)
	if err != nil {
		return nil, err
	}
	sa, salen, err := buildSockaddr(domain, addrData)
	if err != nil {
		return nil, err
	}
	fd, err := newSocket(domain, typ, proto)
	if err != nil {
		return nil, err
	}
	if err := xio.ApplyReuse(fd, s, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if err := bindRaw(fd, sa, salen); err != nil {
		logx.CloseErr(unix.Close(fd))
		return nil, err
	}
	f := osNewFile(fd, "socket-recv")
	// First packet then connected reply for RECVFROM; RECV is read-only merge.
	st := &rawRecvStream{f: f, from: from}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(f)
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: wrapped, Label: s.Type}, nil
}

// rawListener adapts a listening FD to net.Listener.
// Uses net.FileListener so SetDeadline works and Accept is interruptible
// (hang-free under fork+retry and scorecard cleanup).
type rawListener struct {
	fd     int
	domain int
	ln     net.Listener // lazy FileListener
}

func (l *rawListener) fileLn() (net.Listener, error) {
	if l.ln != nil {
		return l.ln, nil
	}
	f := os.NewFile(uintptr(l.fd), "socket-listen")
	ln, err := net.FileListener(f)
	logx.CloseQuiet(f)
	if err != nil {
		return nil, err
	}
	l.ln = ln
	// Ownership of fd transferred to FileListener's dup; do not Close l.fd twice.
	l.fd = -1
	return l.ln, nil
}

func (l *rawListener) Accept() (net.Conn, error) {
	ln, err := l.fileLn()
	if err != nil {
		// Fallback: raw accept
		nfd, _, err := unix.Accept(l.fd)
		if err != nil {
			return nil, err
		}
		f := os.NewFile(uintptr(nfd), "socket-accept")
		c, err := net.FileConn(f)
		logx.CloseQuiet(f)
		if err != nil {
			logx.CloseErr(unix.Close(nfd))
			return nil, err
		}
		return c, nil
	}
	return ln.Accept()
}

func (l *rawListener) Close() error {
	if l.ln != nil {
		return l.ln.Close()
	}
	if l.fd >= 0 {
		return unix.Close(l.fd)
	}
	return nil
}

func (l *rawListener) SetDeadline(t time.Time) error {
	ln, err := l.fileLn()
	if err != nil {
		return err
	}
	if d, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		return d.SetDeadline(t)
	}
	return nil
}

func (l *rawListener) Addr() net.Addr {
	if l.ln != nil {
		return l.ln.Addr()
	}
	sa, err := unix.Getsockname(l.fd)
	if err != nil {
		return &net.IPAddr{}
	}
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

type rawDgramStream struct {
	f     *os.File
	sa    unix.Sockaddr
	salen int
}

// Read uses *os.File so SetReadDeadline / idle -T can unblock hung Recvfrom.
func (r *rawDgramStream) Read(p []byte) (int, error) {
	return r.f.Read(p)
}
func (r *rawDgramStream) Write(p []byte) (int, error) {
	fd := int(r.f.Fd())
	err := unix.Sendto(fd, p, 0, r.sa)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (r *rawDgramStream) Close() error         { return r.f.Close() }
func (r *rawDgramStream) ShutdownWrite() error { return nil }
func (r *rawDgramStream) SetReadDeadline(t time.Time) error {
	return r.f.SetReadDeadline(t)
}
func (r *rawDgramStream) SetDeadline(t time.Time) error {
	return r.f.SetDeadline(t)
}
func (r *rawDgramStream) Fd() uintptr { return r.f.Fd() }

type rawRecvStream struct {
	f    *os.File
	from bool
	peer unix.Sockaddr
	got  bool
}

func (r *rawRecvStream) Read(p []byte) (int, error) {
	// Need peer address for RECVFROM replies: use Recvfrom once, then File.Read.
	if r.from && !r.got {
		fd := int(r.f.Fd())
		n, from, err := unix.Recvfrom(fd, p, 0)
		if err != nil {
			return n, err
		}
		r.peer = from
		r.got = true
		return n, nil
	}
	return r.f.Read(p)
}
func (r *rawRecvStream) Write(p []byte) (int, error) {
	if !r.from || r.peer == nil {
		return 0, fmt.Errorf("SOCKET-RECV is read-only")
	}
	fd := int(r.f.Fd())
	err := unix.Sendto(fd, p, 0, r.peer)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (r *rawRecvStream) Close() error         { return r.f.Close() }
func (r *rawRecvStream) ShutdownWrite() error { return nil }
func (r *rawRecvStream) SetReadDeadline(t time.Time) error {
	return r.f.SetReadDeadline(t)
}
func (r *rawRecvStream) SetDeadline(t time.Time) error {
	return r.f.SetDeadline(t)
}
func (r *rawRecvStream) Fd() uintptr { return r.f.Fd() }
