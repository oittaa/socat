package netopen

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"))
}
func openUDP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPListenNetwork(ctx, s, mode, g, "udp6")
}

func openUDPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
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
	laddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(xio.StripBrackets(host), port))
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
		return &xio.Opened{
			Listener:    ln,
			Fork:        true,
			Label:       "UDP-LISTEN",
			MaxChildren: maxChildren,
			PeerFilter:  func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) },
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
			_ = pc.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, ctx.Err()
		case r := <-ch:
			if r.e != nil {
				_ = pc.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				return nil, r.e
			}
			fake := &udpPeerConn{addr: r.a}
			if err := xio.PeerAllowedG(s, fake, g); err != nil {
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
			g.PeerAddr = xio.FormatSocatAddr(raddr.IP.String())
			g.PeerPort = strconv.Itoa(raddr.Port)
		}
		if la := pc.LocalAddr(); la != nil {
			if host, p, e := net.SplitHostPort(la.String()); e == nil {
				g.SockPort = p
				lip := net.ParseIP(xio.StripBrackets(host))
				if lip != nil && lip.IsUnspecified() && raddr != nil {
					g.SockAddr = xio.FormatSocatAddr(raddr.IP.String())
				} else {
					g.SockAddr = xio.FormatSocatAddr(host)
				}
			}
		}
	}
	// One-shot listen (UDP_CONNECT_EOF): after first packet, do not keep the
	// socket open forever waiting for more. Connected-style session ends on EOF.
	st := relay.Stream(&udpRecvFromConn{
		uc:       pc,
		peer:     raddr,
		first:    append([]byte(nil), buf[:n]...),
		closeEOF: true, // next read after first payload → EOF (unidirectional capture)
	})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = pc.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "UDP-LISTEN"}, nil
}

// udpForkListener implements net.Listener for UDP-LISTEN/RECVFROM,fork:
// each Accept waits for a datagram and returns a session Conn for that peer.
type udpForkListener struct {
	pc         *net.UDPConn
	network    string
	laddr      *net.UDPAddr
	spec       parse.Spec
	g          *xio.Global
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
			if err := xio.PeerAllowedG(l.spec, &udpPeerConn{addr: r.a}, l.g); err != nil {
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
		_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
	uc       *net.UDPConn
	peer     *net.UDPAddr
	first    []byte
	closeEOF bool // after first payload: further Read → EOF (one-shot UDP-LISTEN)
	wantCtrl bool
	g        *xio.Global
}

func (u *udpRecvFromConn) Read(p []byte) (int, error) {
	if len(u.first) > 0 {
		n := copy(p, u.first)
		u.first = u.first[n:]
		return n, nil
	}
	if u.closeEOF {
		// UDP_CONNECT_EOF: one-shot listen ends after the first datagram.
		return 0, io.EOF
	}
	for {
		n, oob, addr, err := xio.ReadUDPMsg(u.uc, p, u.wantCtrl)
		if err != nil {
			return n, err
		}
		if u.peer != nil && addr != nil && addr.String() == u.peer.String() {
			if u.wantCtrl {
				xio.ProcessAncillary(oob, u.g)
			}
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

func (u *udpRecvFromConn) Close() error         { return u.uc.Close() }
func (u *udpRecvFromConn) ShutdownWrite() error { return nil }
func (u *udpRecvFromConn) LocalAddr() net.Addr  { return u.uc.LocalAddr() }
func (u *udpRecvFromConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpRecvFromConn) SetDeadline(t time.Time) error {
	return u.uc.SetDeadline(t)
}
func (u *udpRecvFromConn) SetReadDeadline(t time.Time) error {
	return u.uc.SetReadDeadline(t)
}
func (u *udpRecvFromConn) SetWriteDeadline(t time.Time) error {
	return u.uc.SetWriteDeadline(t)
}
