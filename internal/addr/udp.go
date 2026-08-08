package addr

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

func openUDPConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"))
}
func openUDP4Connect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Connect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp6")
}

func openUDPConnectNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	host, port, err := hostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	addr := net.JoinHostPort(stripBrackets(host), port)
	var d net.Dialer
	bind := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	if bind != "" || sp != "" {
		if bind == "" {
			if network == "udp6" {
				bind = "::"
			} else {
				bind = "0.0.0.0"
			}
		}
		if sp == "" {
			sp = "0"
		}
		ba, err := net.ResolveUDPAddr(network, bindPort(bind, sp))
		if err != nil {
			return nil, err
		}
		d.LocalAddr = ba
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Opened{Stream: st, Label: "UDP:" + addr}, nil
}

func openUDPListen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"))
}
func openUDP4Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp6")
}

func openUDPListenNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UDP-LISTEN requires port")
	}
	port := s.Params[0]
	host := s.OptionValue("bind", "")
	if host == "" {
		if network == "udp6" {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	laddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(stripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	pc, err := listenUDP(network, laddr, s)
	if err != nil {
		return nil, err
	}

	// fork: keep listening and spawn a session per first-packet "connection".
	if s.BoolOption("fork") {
		maxChildren := 0
		if v := s.OptionValue("max-children", ""); v != "" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				maxChildren = n
			}
		}
		ln := &udpForkListener{
			pc:      pc,
			network: network,
			laddr:   laddr,
			spec:    s,
			g:       g,
			ctx:     ctx,
		}
		return &Opened{
			Listener:    ln,
			Fork:        true,
			Label:       "UDP-LISTEN",
			MaxChildren: maxChildren,
			PeerFilter:  func(c net.Conn) error { return peerAllowed(s, c) },
		}, nil
	}

	// Non-fork: one session then done (keep listen socket for reply like RECVFROM).
	buf := make([]byte, max(g.BlockSize, 8192))
	type res struct {
		n int
		a *net.UDPAddr
		e error
	}
	var n int
	var raddr *net.UDPAddr
	for {
		ch := make(chan res, 1)
		go func() {
			n, a, err := pc.ReadFromUDP(buf)
			ch <- res{n, a, err}
		}()
		select {
		case <-ctx.Done():
			pc.Close()
			return nil, ctx.Err()
		case r := <-ch:
			if r.e != nil {
				pc.Close()
				return nil, r.e
			}
			fake := &udpPeerConn{addr: r.a}
			if err := peerAllowed(s, fake); err != nil {
				if g != nil && g.Log != nil {
					g.Log.Noticef("%s", err)
				}
				continue
			}
			n, raddr = r.n, r.a
		}
		break
	}
	// SOCAT_* env for EXEC/SYSTEM children (UDP6LISTENENV etc.).
	// When bound to unspecified (:: / 0.0.0.0), classic still reports the
	// local address used for this peer (loopback peer → loopback sock).
	if g != nil {
		if raddr != nil {
			g.PeerAddr = formatSocatAddr(raddr.IP.String())
			g.PeerPort = strconv.Itoa(raddr.Port)
		}
		if la := pc.LocalAddr(); la != nil {
			if host, p, e := net.SplitHostPort(la.String()); e == nil {
				g.SockPort = p
				lip := net.ParseIP(stripBrackets(host))
				if lip != nil && lip.IsUnspecified() && raddr != nil {
					g.SockAddr = formatSocatAddr(raddr.IP.String())
				} else {
					g.SockAddr = formatSocatAddr(host)
				}
			}
		}
	}
	st := relay.Stream(&udpRecvFromConn{
		uc:    pc,
		peer:  raddr,
		first: append([]byte(nil), buf[:n]...),
	})
	st, err = wrapCommon(s, st)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Opened{Stream: st, Label: "UDP-LISTEN"}, nil
}

// udpForkListener implements net.Listener for UDP-LISTEN/RECVFROM,fork:
// each Accept waits for a datagram and returns a session Conn for that peer.
type udpForkListener struct {
	pc         *net.UDPConn
	network    string
	laddr      *net.UDPAddr
	spec       parse.Spec
	g          *Global
	ctx        context.Context
	rcvTimeout time.Duration
}

func (l *udpForkListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65535)
	for {
		type res struct {
			n int
			a *net.UDPAddr
			e error
		}
		ch := make(chan res, 1)
		if l.rcvTimeout > 0 {
			_ = l.pc.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		go func() {
			n, a, err := l.pc.ReadFromUDP(buf)
			ch <- res{n, a, err}
		}()
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		case r := <-ch:
			if r.e != nil {
				return nil, r.e
			}
			if err := peerAllowed(l.spec, &udpPeerConn{addr: r.a}); err != nil {
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("%s", err)
				}
				continue
			}
			// Prefer connected child socket (REUSEADDR) so parent keeps listening.
			conn, err := dialUDPSession(l.network, l.laddr, r.a)
			if err != nil {
				if l.g != nil && l.g.Log != nil {
					l.g.Log.Noticef("UDP fork session dial: %s", err)
				}
				return nil, err
			}
			return &udpSessionConn{
				conn:  conn,
				peer:  r.a,
				first: append([]byte(nil), buf[:r.n]...),
			}, nil
		}
	}
}

func (l *udpForkListener) Close() error   { return l.pc.Close() }
func (l *udpForkListener) Addr() net.Addr { return l.pc.LocalAddr() }

func dialUDPSession(network string, local, remote *net.UDPAddr) (*net.UDPConn, error) {
	// SO_REUSEADDR so we can bind the same local port as the parent listener.
	d := net.Dialer{
		LocalAddr: local,
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
		},
	}
	c, err := d.Dial(network, remote.String())
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("UDP session: unexpected conn type")
	}
	return uc, nil
}

// udpSessionConn is one UDP "connection" for fork children.
// Do NOT embed *net.UDPConn: poll would wait for POLLIN while the first
// datagram is only in first[] (already consumed from the listen socket).
type udpSessionConn struct {
	conn   *net.UDPConn // connected child socket (preferred)
	pc     *net.UDPConn // shared parent when conn is nil
	peer   *net.UDPAddr
	first  []byte
	got    bool
	shared bool
}

func (u *udpSessionConn) Read(p []byte) (int, error) {
	if !u.got && len(u.first) > 0 {
		u.got = true
		n := copy(p, u.first)
		if n < len(u.first) {
			u.first = u.first[n:]
			u.got = false
		}
		return n, nil
	}
	if u.conn != nil {
		return u.conn.Read(p)
	}
	for {
		n, addr, err := u.pc.ReadFromUDP(p)
		if err != nil {
			return n, err
		}
		if u.peer != nil && addr != nil && addr.String() == u.peer.String() {
			return n, nil
		}
	}
}

func (u *udpSessionConn) Write(p []byte) (int, error) {
	if u.conn != nil {
		return u.conn.Write(p)
	}
	return u.pc.WriteToUDP(p, u.peer)
}

func (u *udpSessionConn) Close() error {
	if u.shared {
		return nil // parent owns listen socket
	}
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

func (u *udpSessionConn) LocalAddr() net.Addr {
	if u.conn != nil {
		return u.conn.LocalAddr()
	}
	return u.pc.LocalAddr()
}
func (u *udpSessionConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpSessionConn) SetDeadline(t time.Time) error {
	if u.conn != nil {
		return u.conn.SetDeadline(t)
	}
	return nil
}
func (u *udpSessionConn) SetReadDeadline(t time.Time) error {
	if u.conn != nil {
		return u.conn.SetReadDeadline(t)
	}
	return nil
}
func (u *udpSessionConn) SetWriteDeadline(t time.Time) error {
	if u.conn != nil {
		return u.conn.SetWriteDeadline(t)
	}
	return nil
}

// udpPeerConn is a minimal net.Conn exposing only RemoteAddr for peer filters.
type udpPeerConn struct {
	addr net.Addr
}

func (c *udpPeerConn) Read([]byte) (int, error)         { return 0, net.ErrClosed }
func (c *udpPeerConn) Write([]byte) (int, error)        { return 0, net.ErrClosed }
func (c *udpPeerConn) Close() error                     { return nil }
func (c *udpPeerConn) LocalAddr() net.Addr              { return nil }
func (c *udpPeerConn) RemoteAddr() net.Addr             { return c.addr }
func (c *udpPeerConn) SetDeadline(time.Time) error      { return nil }
func (c *udpPeerConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpPeerConn) SetWriteDeadline(time.Time) error { return nil }

// udpRecvFromConn: first datagram already received; further Read/Write use the
// listening socket with WriteTo to the peer (no rebinding).
// Named field (not embed) so poll does not wait for POLLIN while first is buffered.
type udpRecvFromConn struct {
	uc    *net.UDPConn
	peer  *net.UDPAddr
	first []byte
	got   bool
}

func (u *udpRecvFromConn) Read(p []byte) (int, error) {
	if !u.got && len(u.first) > 0 {
		u.got = true
		n := copy(p, u.first)
		if n < len(u.first) {
			u.first = u.first[n:]
			u.got = false
		}
		return n, nil
	}
	for {
		n, addr, err := u.uc.ReadFromUDP(p)
		if err != nil {
			return n, err
		}
		if u.peer != nil && addr != nil && addr.String() == u.peer.String() {
			return n, nil
		}
	}
}

func (u *udpRecvFromConn) Write(p []byte) (int, error) {
	if u.peer == nil {
		return 0, net.ErrClosed
	}
	return u.uc.WriteToUDP(p, u.peer)
}

func (u *udpRecvFromConn) Close() error              { return u.uc.Close() }
func (u *udpRecvFromConn) ShutdownWrite() error      { return nil }
func (u *udpRecvFromConn) LocalAddr() net.Addr       { return u.uc.LocalAddr() }
func (u *udpRecvFromConn) RemoteAddr() net.Addr      { return u.peer }
func (u *udpRecvFromConn) SetDeadline(t time.Time) error {
	return u.uc.SetDeadline(t)
}
func (u *udpRecvFromConn) SetReadDeadline(t time.Time) error {
	return u.uc.SetReadDeadline(t)
}
func (u *udpRecvFromConn) SetWriteDeadline(t time.Time) error {
	return u.uc.SetWriteDeadline(t)
}

// Legacy name used by listen path
type udpFirstPacket = udpRecvFromConn

// UDP*-SENDTO is classic unconnected sendto/recvfrom (not connect).
func openUDPSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"))
}
func openUDP4Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6")
}

// UDP*-DATAGRAM: unconnected datagram to address (broadcast/multicast capable).
func openUDPDatagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"))
}
func openUDP4Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6")
}

func openUDPDatagramNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	host, port, err := hostPortParams(s)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(stripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	bind := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	var laddr *net.UDPAddr
	// classic lowport: bind an ephemeral port in 640..1023 (log even if EACCES).
	if s.BoolOption("lowport") && sp == "" {
		if bind == "" {
			if network == "udp6" {
				bind = "::"
			} else {
				bind = "0.0.0.0"
			}
		}
		c, port, berr := bindUDPLowport(ctx, network, bind, s, g)
		if berr == nil && c != nil {
			// use this bound conn as the packet socket
			if s.BoolOption("broadcast") {
				raw, e := c.SyscallConn()
				if e == nil {
					_ = raw.Control(func(fd uintptr) {
						_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
					})
				}
			}
			st := &udpDatagramConn{UDPConn: c, raddr: raddr}
			wrapped, err := wrapCommon(s, st)
			if err != nil {
				c.Close()
				return nil, err
			}
			_ = port
			return &Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
		}
		// Fall through: still emit classic-style bind log if bindUDPLowport logged.
		if berr != nil && g != nil && g.Log != nil {
			// bindUDPLowport already logged attempts
		}
	}
	if bind != "" || sp != "" {
		if bind == "" {
			if network == "udp6" {
				bind = "::"
			} else {
				bind = "0.0.0.0"
			}
		}
		if sp == "" {
			// bind may already be host:port
			if _, _, e := net.SplitHostPort(bind); e != nil {
				sp = "0"
			}
		}
		ba := bind
		if sp != "" {
			ba = bindPort(bind, sp)
		}
		laddr, err = net.ResolveUDPAddr(network, ba)
		if err != nil {
			return nil, err
		}
	}
	// SO_REUSEADDR on bind so rapid retests / paired ports work.
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if s.BoolOption("broadcast") {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}
			})
		},
	}
	pc, err := cfg.ListenPacket(ctx, network, laddrString(network, laddr))
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		pc.Close()
		return nil, fmt.Errorf("UDP: unexpected packet conn type")
	}
	if s.BoolOption("broadcast") {
		raw, err := c.SyscallConn()
		if err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
			})
		}
	}
	st := &udpDatagramConn{UDPConn: c, raddr: raddr}
	wrapped, err := wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	_ = g
	return &Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
}

func laddrString(network string, laddr *net.UDPAddr) string {
	if laddr == nil {
		if network == "udp6" {
			return "[::]:0"
		}
		return "0.0.0.0:0"
	}
	return laddr.String()
}

// udpDatagramConn writes always to raddr; reads from anyone (optional filter later).
type udpDatagramConn struct {
	*net.UDPConn
	raddr *net.UDPAddr
}

func (u *udpDatagramConn) Write(p []byte) (int, error) {
	// Allow 0-byte writes (shut-null sends empty datagram).
	return u.UDPConn.WriteToUDP(p, u.raddr)
}

// bindUDPLowport tries ports 1023..640 (classic lowport). Logs bind like SYCLS for tests.
func bindUDPLowport(ctx context.Context, network, bind string, s parse.Spec, g *Global) (*net.UDPConn, int, error) {
	_ = s
	var last error
	for port := 1023; port >= 640; port-- {
		// Classic test greps: [DE] bind(.*:PORT
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=2 %s:%d}, 16)", bind, port)
		}
		addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(stripBrackets(bind), strconv.Itoa(port)))
		if err != nil {
			last = err
			continue
		}
		cfg := net.ListenConfig{}
		pc, err := cfg.ListenPacket(ctx, network, addr.String())
		if err != nil {
			last = err
			continue
		}
		c, ok := pc.(*net.UDPConn)
		if !ok {
			pc.Close()
			last = fmt.Errorf("not UDPConn")
			continue
		}
		return c, port, nil
	}
	return nil, 0, last
}
func (u *udpDatagramConn) ShutdownWrite() error { return nil }

func openUDPRecv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"), false)
}
func openUDP4Recv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Recv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPRecvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, networkUDP(g, s, "udp4"), true)
}
func openUDP4Recvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", true)
}
func openUDP6Recvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", true)
}

func openUDPRecvNetwork(ctx context.Context, s parse.Spec, mode Mode, g *Global, network string, recvfrom bool) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UDP-RECV requires port")
	}
	port := s.Params[0]
	host := s.OptionValue("bind", "")
	if host == "" {
		if network == "udp6" {
			host = "::"
		} else {
			host = "0.0.0.0"
		}
	}
	laddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(stripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	pc, err := listenUDP(network, laddr, s)
	if err != nil {
		return nil, err
	}
	if recvfrom {
		// fork: keep listening, one SYSTEM/child per datagram (classic UDP4_FORK).
		if s.BoolOption("fork") {
			maxChildren := 0
			if v := s.OptionValue("max-children", ""); v != "" {
				if n, e := strconv.Atoi(v); e == nil && n > 0 {
					maxChildren = n
				}
			}
			// Optional SO_RCVTIMEO
			if v := s.OptionValue("so-rcvtimeo", ""); v != "" {
				if d := parseTimeval(v); d > 0 {
					_ = pc.SetReadDeadline(time.Time{}) // clear; per-accept deadline set in Accept
					_ = d
				}
			}
			ln := &udpForkListener{
				pc:      pc,
				network: network,
				laddr:   laddr,
				spec:    s,
				g:       g,
				ctx:     ctx,
			}
			// so-rcvtimeo for Accept reads
			if v := s.OptionValue("so-rcvtimeo", ""); v != "" {
				ln.rcvTimeout = parseTimeval(v)
			}
			return &Opened{
				Listener:    ln,
				Fork:        true,
				Label:       "UDP-RECVFROM",
				MaxChildren: maxChildren,
				PeerFilter:  func(c net.Conn) error { return peerAllowed(s, c) },
			}, nil
		}
		// One permitted packet, then use the *same* listening socket for replies
		// (classic). DialUDP(local, peer) after Close fails with EADDRINUSE.
		buf := make([]byte, max(g.BlockSize, 65535))
		type res struct {
			n int
			a *net.UDPAddr
			e error
		}
		var n int
		var raddr *net.UDPAddr
		for {
			ch := make(chan res, 1)
			go func() {
				n, a, err := pc.ReadFromUDP(buf)
				ch <- res{n, a, err}
			}()
			select {
			case <-ctx.Done():
				pc.Close()
				return nil, ctx.Err()
			case r := <-ch:
				if r.e != nil {
					pc.Close()
					return nil, r.e
				}
				if err := peerAllowed(s, &udpPeerConn{addr: r.a}); err != nil {
					if g != nil && g.Log != nil {
						g.Log.Noticef("%s", err)
					}
					continue
				}
				n, raddr = r.n, r.a
			}
			break
		}
		st := relay.Stream(&udpRecvFromConn{
			uc:    pc,
			peer:  raddr,
			first: append([]byte(nil), buf[:n]...),
		})
		st, err = wrapCommon(s, st)
		if err != nil {
			pc.Close()
			return nil, err
		}
		return &Opened{
			Stream: st,
			Label:  "UDP-RECVFROM",
		}, nil
	}
	// RECV: merge all packets, read-only, with peer filters.
	if mode == ModeWrite {
		pc.Close()
		return nil, fmt.Errorf("UDP-RECV is read-only")
	}
	st := relay.Stream(&udpFilteredRecv{conn: pc, spec: s, log: g})
	st, err = wrapCommon(s, st)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Opened{
		Stream: st,
		Label:  "UDP-RECV",
	}, nil
}

// udpFilteredRecv drops packets that fail range/sourceport/lowport checks.
type udpFilteredRecv struct {
	conn *net.UDPConn
	spec parse.Spec
	log  *Global
}

func (u *udpFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, addr, err := u.conn.ReadFromUDP(p)
		if err != nil {
			return n, err
		}
		if err := peerAllowed(u.spec, &udpPeerConn{addr: addr}); err != nil {
			if u.log != nil && u.log.Log != nil {
				u.log.Log.Noticef("%s", err)
			}
			continue
		}
		return n, nil
	}
}

func (u *udpFilteredRecv) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (u *udpFilteredRecv) Close() error              { return u.conn.Close() }
func (u *udpFilteredRecv) ShutdownWrite() error      { return nil }
func (u *udpFilteredRecv) LocalAddr() net.Addr       { return u.conn.LocalAddr() }
func (u *udpFilteredRecv) RemoteAddr() net.Addr      { return nil }

func listenUDP(network string, laddr *net.UDPAddr, s parse.Spec) (*net.UDPConn, error) {
	// Default reuseaddr for listen-like UDP (classic often implies it with explicit option).
	reuse := true
	if s.HasOption("reuseaddr") {
		reuse = s.BoolOption("reuseaddr")
	}
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if reuse {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				}
				if s.BoolOption("broadcast") {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}
			})
		},
	}
	pc, err := cfg.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	// ip-add-membership=mcastaddr:interfaceaddr (classic form).
	if v := s.OptionValue("ip-add-membership", ""); v != "" {
		if err := joinMulticast(c, network, v); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

// joinMulticast parses classic "mcast:iface" or "mcast%iface" and joins the group.
func joinMulticast(c *net.UDPConn, network, spec string) error {
	// Forms: 224.x.x.x:ifaceIP  or  224.x.x.x:ifaceName
	mcast, iface, ok := strings.Cut(spec, ":")
	if !ok {
		mcast, iface, ok = strings.Cut(spec, "%")
	}
	if !ok {
		return fmt.Errorf("ip-add-membership: expected mcast:iface, got %q", spec)
	}
	gip := net.ParseIP(strings.TrimSpace(mcast))
	if gip == nil {
		return fmt.Errorf("ip-add-membership: bad group %q", mcast)
	}
	var ifi *net.Interface
	iface = strings.TrimSpace(iface)
	if ip := net.ParseIP(iface); ip != nil {
		// Find interface with this address.
		ifaces, _ := net.Interfaces()
		for _, cand := range ifaces {
			addrs, _ := cand.Addrs()
			for _, a := range addrs {
				var ipn net.IP
				switch v := a.(type) {
				case *net.IPNet:
					ipn = v.IP
				case *net.IPAddr:
					ipn = v.IP
				}
				if ipn != nil && ipn.Equal(ip) {
					ifi = &cand
					break
				}
			}
			if ifi != nil {
				break
			}
		}
		// Even without ifi, IP_ADD_MEMBERSHIP can use interface IP via IPv4mreq.
		if gip.To4() != nil && ip.To4() != nil {
			return setIPv4Membership(c, gip.To4(), ip.To4())
		}
	} else {
		var err error
		ifi, err = net.InterfaceByName(iface)
		if err != nil {
			return fmt.Errorf("ip-add-membership: interface %q: %w", iface, err)
		}
	}
	if gip.To4() != nil {
		var ifaceIP net.IP
		if ifi != nil {
			addrs, _ := ifi.Addrs()
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
					ifaceIP = ipn.IP.To4()
					break
				}
			}
		}
		if ifaceIP == nil {
			ifaceIP = net.IPv4zero.To4()
		}
		return setIPv4Membership(c, gip.To4(), ifaceIP)
	}
	return setIPv6Membership(c, gip, ifi)
}

func setIPv4Membership(c *net.UDPConn, group, ifaceIP net.IP) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		var mreq unix.IPMreq
		copy(mreq.Multiaddr[:], group.To4())
		copy(mreq.Interface[:], ifaceIP.To4())
		serr = unix.SetsockoptIPMreq(int(fd), unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, &mreq)
	})
	if err != nil {
		return err
	}
	return serr
}

func setIPv6Membership(c *net.UDPConn, group net.IP, ifi *net.Interface) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	idx := 0
	if ifi != nil {
		idx = ifi.Index
	}
	err = raw.Control(func(fd uintptr) {
		var mreq unix.IPv6Mreq
		copy(mreq.Multiaddr[:], group.To16())
		mreq.Interface = uint32(idx)
		serr = unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, &mreq)
	})
	if err != nil {
		return err
	}
	return serr
}

func networkUDP(g *Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch pf {
		case "ip4", "ipv4", "inet":
			return "udp4"
		case "ip6", "ipv6", "inet6":
			return "udp6"
		}
	}
	switch g.IPVersion {
	case IPv4:
		return "udp4"
	case IPv6:
		return "udp6"
	case IPvAny:
		return "udp"
	default:
		return def
	}
}
