package netopen

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oittaa/socat/internal/xio"

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
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		bdata, berr := xio.ParseSocatData(bind)
		if berr != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, berr
		}
		bsa, _, err := buildSockaddr(domain, bdata)
		if err != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, fmt.Errorf("bind: %w", err)
		}
		if err := unix.Bind(fd, bsa); err != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if err := connectRaw(fd, sa, salen); err != nil {
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, fmt.Errorf("connect: %w", err)
	}
	f := osNewFile(fd, "socket-connect")
	st := xio.FileStream(f)
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: st, Label: "SOCKET-CONNECT"}, nil
}

// SOCKET-LISTEN:<domain>:<protocol>:<local-address>
func openSocketListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
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
	xio.ApplyReuse(fd, s, true)
	if err := applySocketOpts(fd, s); err != nil {
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	if err := bindRaw(fd, sa, salen); err != nil {
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, fmt.Errorf("bind: %w", err)
	}
	backlog := 5
	if v := s.OptionValue("backlog", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			backlog = n
		}
	}
	if err := unix.Listen(fd, backlog); err != nil {
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	ln := &rawListener{fd: fd, domain: domain}
	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 {
			maxChildren = n
		}
	}
	if fork {
		return &xio.Opened{
			Listener:    ln,
			Fork:        true,
			Label:       "SOCKET-LISTEN",
			MaxChildren: maxChildren,
			PeerFilter:  func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) },
		}, nil
	}
	// accept one
	c, err := ln.Accept()
	if err != nil {
		_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	st := relay.Stream(relay.NetStream{Conn: c})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: st, Label: "SOCKET-LISTEN"}, nil
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
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		bdata, berr := xio.ParseSocatData(bind)
		if berr != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, berr
		}
		bsa, blen, err := buildSockaddr(domain, bdata)
		if err != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
		if err := bindRaw(fd, bsa, blen); err != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, fmt.Errorf("bind: %w", err)
		}
	}
	if connected {
		if err := connectRaw(fd, sa, salen); err != nil {
			_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
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
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
	xio.ApplyReuse(fd, s, true)
	if err := bindRaw(fd, sa, salen); err != nil {
		_ = unix.Close(fd) // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	f := osNewFile(fd, "socket-recv")
	// First packet then connected reply for RECVFROM; RECV is read-only merge.
	st := &rawRecvStream{f: f, from: from}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	_ = ctx
	_ = mode
	_ = g
	return &xio.Opened{Stream: wrapped, Label: s.Type}, nil
}

func parseSocketParams(s parse.Spec, n int) (domain, proto int, addr []byte, err error) {
	if len(s.Params) < n {
		return 0, 0, nil, fmt.Errorf("%s requires %d parameters", s.Type, n)
	}
	// Empty domain is tolerated (classic tests expand $PF_INET6 from procan -c;
	// if empty, infer from address length).
	if s.Params[0] == "" {
		domain = 0
	} else {
		domain, err = strconv.Atoi(s.Params[0])
		if err != nil {
			return 0, 0, nil, fmt.Errorf("domain: %w", err)
		}
	}
	if s.Params[1] == "" {
		proto = 0
	} else {
		proto, err = strconv.Atoi(s.Params[1])
		if err != nil {
			return 0, 0, nil, fmt.Errorf("protocol: %w", err)
		}
	}
	// Prefer raw address text so classic dalan quote forms (and syntax errors)
	// survive parse unquote. Fall back to joined Params.
	addrText := rawSocketAddress(s, 2)
	if addrText == "" {
		addrText = strings.Join(s.Params[2:], ":")
	}
	// testaddrs uses TYPE::::: — joined params become ":"/"::" with no real data.
	if strings.Trim(addrText, ":") == "" {
		return 0, 0, nil, fmt.Errorf("%s requires address", s.Type)
	}
	addr, err = xio.ParseSocatData(addrText)
	if err != nil {
		return 0, 0, nil, err
	}
	if domain == 0 {
		// Heuristic: xio.IPv6 sockaddr data is ~26 bytes; xio.IPv4 ~14; else UNIX path.
		switch {
		case len(addr) >= 22:
			domain = unix.AF_INET6
		case len(addr) >= 6 && len(addr) <= 16:
			domain = unix.AF_INET
		default:
			domain = unix.AF_UNIX
		}
	}
	return domain, proto, addr, nil
}

// rawSocketAddress extracts the address parameter from Spec.Raw without unquote.
// paramIndex is 0-based among TYPE:p0:p1:p2... (e.g. 2 for CONNECT domain:proto:addr).
// Strips trailing ,options only.
func rawSocketAddress(s parse.Spec, paramIndex int) string {
	raw := s.Raw
	// Drop TYPE: prefix (case-insensitive match of type name).
	up := strings.ToUpper(raw)
	prefix := s.Type + ":"
	if strings.HasPrefix(up, strings.ToUpper(prefix)) {
		raw = raw[len(prefix):]
	} else if i := strings.Index(raw, ":"); i >= 0 {
		raw = raw[i+1:]
	}
	// Cut options at top-level comma (not inside quotes).
	raw = cutTopLevelComma(raw)
	// Walk colon-separated params without unquote; respect quotes.
	parts := splitColonNoUnquote(raw)
	if paramIndex >= len(parts) {
		return ""
	}
	// Address may itself contain colons (xio.IPv6 hex form uses x not : usually).
	// Join remaining params with ':' if more than one (hex uses x separators).
	if paramIndex < len(parts)-1 {
		return strings.Join(parts[paramIndex:], ":")
	}
	return parts[paramIndex]
}

func cutTopLevelComma(s string) string {
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case ',':
			return s[:i]
		}
	}
	return s
}

func splitColonNoUnquote(s string) []string {
	if s == "" {
		return nil
	}
	var parts []string
	start := 0
	inSingle, inDouble := false, false
	escape := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && !inSingle {
			escape = true
			continue
		}
		if inSingle {
			if c == '\'' {
				inSingle = false
			}
			continue
		}
		if inDouble {
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case ':':
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// buildSockaddr builds unix.Sockaddr from domain + classic data (without family).
func buildSockaddr(domain int, data []byte) (unix.Sockaddr, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("empty socket address")
	}
	switch domain {
	case unix.AF_INET:
		// sockaddr_in data: port(2 BE) + addr(4) + zero(8) = 14 bytes typically
		if len(data) < 6 {
			return nil, 0, fmt.Errorf("AF_INET address too short")
		}
		port := binary.BigEndian.Uint16(data[0:2])
		ip := net.IPv4(data[2], data[3], data[4], data[5])
		sa := &unix.SockaddrInet4{Port: int(port)}
		copy(sa.Addr[:], ip.To4())
		return sa, unix.SizeofSockaddrInet4, nil
	case unix.AF_INET6:
		// port(2) + flowinfo(4) + addr(16) + scope(4) — classic may omit family
		if len(data) < 2+4+16 {
			return nil, 0, fmt.Errorf("AF_INET6 address too short (%d)", len(data))
		}
		port := binary.BigEndian.Uint16(data[0:2])
		// skip flowinfo at 2:6
		var addr [16]byte
		copy(addr[:], data[6:22])
		scope := uint32(0)
		if len(data) >= 26 {
			scope = binary.BigEndian.Uint32(data[22:26])
		}
		sa := &unix.SockaddrInet6{Port: int(port), ZoneId: scope, Addr: addr}
		return sa, unix.SizeofSockaddrInet6, nil
	case unix.AF_UNIX:
		// path bytes, often NUL-terminated
		path := string(data)
		if i := strings.IndexByte(path, 0); i >= 0 {
			path = path[:i]
		}
		return &unix.SockaddrUnix{Name: path}, 2 + len(path) + 1, nil
	default:
		return nil, 0, fmt.Errorf("unsupported socket domain %d", domain)
	}
}

func bindRaw(fd int, sa unix.Sockaddr, _ int) error {
	return unix.Bind(fd, sa)
}

func connectRaw(fd int, sa unix.Sockaddr, _ int) error {
	return unix.Connect(fd, sa)
}

func applySocketOpts(fd int, s parse.Spec) error {
	xio.ApplyReuse(fd, s, false)
	return nil
}

func osNewFile(fd int, name string) *os.File {
	return os.NewFile(uintptr(fd), name)
}

func newSocket(domain, typ, proto int) (int, error) {
	fd, err := unix.Socket(domain, typ|sockCloexec, proto)
	if err != nil {
		return -1, err
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(fd)
	}
	return fd, nil
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
	_ = f.Close() // #nosec G104 -- FileListener dups the fd; close the original
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
		_ = f.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		if err != nil {
			_ = unix.Close(nfd) // #nosec G104 -- Close on cleanup; the first error is already returned
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
