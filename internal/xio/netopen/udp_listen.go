package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
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

func applyUDPAcceptTimeout(pc *net.UDPConn, s parse.Spec) (bool, error) {
	timeout := xio.AcceptTimeout(s)
	if timeout <= 0 {
		return false, nil
	}
	if err := pc.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return false, fmt.Errorf("accept-timeout: %w", err)
	}
	return true, nil
}

func clearUDPAcceptTimeout(pc *net.UDPConn, set bool) error {
	if !set {
		return nil
	}
	return pc.SetReadDeadline(time.Time{})
}

func udpAcceptError(err error, timeoutSet bool) error {
	if timeoutSet && xio.IsTimeoutErr(err) {
		return xio.ErrAcceptTimeout
	}
	return err
}

func openUDPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("UDP-LISTEN requires port")
	}
	port := s.Params[0]
	host := xio.ListenBindHost(network, s.OptionValue("bind", ""))
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
		_, maxChildren, ferr := xio.ForkLimits(s)
		if ferr != nil {
			logx.CloseQuiet(pc)
			return nil, ferr
		}
		ln := &udpForkListener{
			pc:            pc,
			network:       network,
			laddr:         laddr,
			spec:          s,
			g:             g,
			ctx:           ctx,
			rcvTimeout:    xio.ParseTimeval(s.OptionValue("rcvtimeo", "")),
			acceptTimeout: xio.AcceptTimeout(s),
		}
		return &xio.Opened{
			Kind:        xio.KindListen,
			Listener:    ln,
			Label:       "UDP-LISTEN",
			MaxChildren: maxChildren,
			PeerFilter:  func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) },
			WrapDial: func(c net.Conn) (relay.Stream, error) {
				return xio.WrapCommon(s, relay.NetStream{Conn: c})
			},
		}, nil
	}
	timeoutSet, err := applyUDPAcceptTimeout(pc, s)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}

	// Non-fork: one session then done (keep listen socket for reply like RECVFROM).
	buf := make([]byte, max(g.BlockSize, 8192))
	wantCtrl := xio.NeedAncillary(s)
	var n int
	var raddr *net.UDPAddr
	for {
		rn, oob, a, err := xio.RecvOneCtx(ctx, func() (int, []byte, *net.UDPAddr, error) {
			return xio.ReadUDPMsg(pc, buf, wantCtrl)
		})
		if err != nil {
			logx.CloseQuiet(pc)
			return nil, udpAcceptError(err, timeoutSet)
		}
		fake := &udpPeerConn{addr: a}
		if ferr := xio.PeerAllowedG(s, fake, g); ferr != nil {
			if g != nil && g.Log != nil {
				g.Log.Noticef("%s", ferr)
			}
			continue
		}
		n, raddr = rn, a
		xio.ProcessAncillary(oob, g)
		break
	}
	if err := clearUDPAcceptTimeout(pc, timeoutSet); err != nil {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("accept-timeout: clear deadline: %w", err)
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
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "UDP-LISTEN"}, nil
}

// udpForkListener implements net.Listener for UDP-LISTEN/RECVFROM,fork:
// each Accept waits for a datagram and returns a session Conn for that peer.
type udpForkListener struct {
	pc            *net.UDPConn
	network       string
	laddr         *net.UDPAddr
	spec          parse.Spec
	g             *xio.Global
	ctx           context.Context
	rcvTimeout    time.Duration
	acceptTimeout time.Duration
	oneShot       bool // UDP-RECVFROM,fork: XIODATA_RECVFROM_ONE
}

func (l *udpForkListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65535)
	wantCtrl := xio.NeedAncillary(l.spec)
	for {
		switch {
		case l.acceptTimeout > 0:
			// accept-timeout aborts waiting entirely (classic accept-timeout).
			_ = l.pc.SetReadDeadline(time.Now().Add(l.acceptTimeout))
		case l.rcvTimeout > 0:
			_ = l.pc.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		rn, oob, a, err := xio.RecvOneCtx(l.ctx, func() (int, []byte, *net.UDPAddr, error) {
			return xio.ReadUDPMsg(l.pc, buf, wantCtrl)
		})
		if err != nil {
			if l.ctx.Err() != nil {
				return nil, err
			}
			// Keep the listener alive across its periodic receive deadline;
			// classic's poll loop likewise continues waiting while idle.
			if l.rcvTimeout > 0 && l.acceptTimeout == 0 && xio.IsTimeoutErr(err) {
				continue
			}
			if l.acceptTimeout > 0 && xio.IsTimeoutErr(err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, err
		}
		if err := xio.PeerAllowedG(l.spec, &udpPeerConn{addr: a}, l.g); err != nil {
			if l.g != nil && l.g.Log != nil {
				l.g.Log.Noticef("%s", err)
			}
			continue
		}
		// Prefer connected child socket (REUSEADDR) so parent keeps listening.
		conn, err := dialUDPSession(l.network, l.laddr, a)
		if err != nil {
			if l.g != nil && l.g.Log != nil {
				l.g.Log.Noticef("UDP fork session dial: %s", err)
			}
			return nil, err
		}
		session := &xio.Global{}
		if l.g != nil {
			session.Log = l.g.Log
			session.Progname = l.g.Progname
		}
		xio.ProcessAncillary(oob, session)
		return &udpSessionConn{
			conn:    conn,
			peer:    a,
			first:   append([]byte(nil), buf[:rn]...),
			env:     session.SessionVars,
			oneShot: l.oneShot,
		}, nil
	}
}

func (l *udpForkListener) Close() error   { return l.pc.Close() }
func (l *udpForkListener) Addr() net.Addr { return l.pc.LocalAddr() }

func dialUDPSession(network string, local, remote *net.UDPAddr) (*net.UDPConn, error) {
	// SO_REUSEADDR so we can bind the same local port as the parent listener.
	d := net.Dialer{
		LocalAddr: local,
		Control: func(network, address string, c syscall.RawConn) error {
			var optionErr error
			controlErr := c.Control(func(fd uintptr) {
				optionErr = xio.SetSockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if optionErr == nil {
					optionErr = enableUDPForkPortReuse(int(fd))
				}
			})
			return errors.Join(controlErr, optionErr)
		},
	}
	c, err := d.Dial(network, remote.String())
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(c)
		return nil, fmt.Errorf("UDP session: unexpected conn type")
	}
	return uc, nil
}

// udpSessionConn is one UDP "connection" for fork children.
// Do NOT embed *net.UDPConn: poll would wait for POLLIN while the first
// datagram is only in first[] (already consumed from the listen socket).
// Accept always dials a connected child socket; there is no shared-parent path.
type udpSessionConn struct {
	conn    *net.UDPConn
	peer    *net.UDPAddr
	first   []byte
	got     bool
	oneShot bool
	env     map[string]string
}

func (u *udpSessionConn) SessionEnvironment() map[string]string { return u.env }

func (u *udpSessionConn) Read(p []byte) (int, error) {
	if !u.got && len(u.first) > 0 {
		u.got = true
		n := copy(p, u.first)
		if n < len(u.first) {
			u.first = u.first[n:]
			u.got = false
		} else {
			u.first = nil
		}
		return n, nil
	}
	if u.oneShot {
		// Classic UDP-RECVFROM,fork is XIODATA_RECVFROM_ONE.
		return 0, io.EOF
	}
	return u.conn.Read(p)
}

func (u *udpSessionConn) Write(p []byte) (int, error) {
	return u.conn.Write(p)
}

func (u *udpSessionConn) Close() error {
	return u.conn.Close()
}

func (u *udpSessionConn) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}
func (u *udpSessionConn) RemoteAddr() net.Addr { return u.peer }
func (u *udpSessionConn) SetDeadline(t time.Time) error {
	return u.conn.SetDeadline(t)
}
func (u *udpSessionConn) SetReadDeadline(t time.Time) error {
	return u.conn.SetReadDeadline(t)
}
func (u *udpSessionConn) SetWriteDeadline(t time.Time) error {
	return u.conn.SetWriteDeadline(t)
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
