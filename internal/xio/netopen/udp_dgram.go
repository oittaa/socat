package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"))
}
func openUDP4Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6")
}

// UDP*-DATAGRAM: unconnected datagram to address (broadcast/multicast capable).
func openUDPDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"))
}
func openUDP4Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6")
}

func openUDPDatagramNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	raddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(xio.StripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	bind := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	var laddr *net.UDPAddr
	// classic lowport: bind a port in 640..1023 (log even if EACCES).
	if s.BoolOption("lowport") && sp == "" {
		bind, err = xio.ListenBindHost(network, bind)
		if err != nil {
			return nil, err
		}
		c, port, berr := bindUDPLowport(ctx, network, bind, s, g)
		if berr == nil && c != nil {
			// use this bound conn as the packet socket
			if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
				_ = c.Close()
				return nil, err
			}
			st := &udpDatagramConn{UDPConn: c, raddr: raddr, g: g, wantCtrl: xio.NeedAncillary(s)}
			wrapped, err := xio.WrapCommonAfterConnected(s, st)
			if err != nil {
				logx.CloseQuiet(c)
				return nil, err
			}
			_ = port
			return &xio.Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
		}
		if berr == nil {
			berr = fmt.Errorf("all ports in use")
		}
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, berr)
	}
	if bind != "" || sp != "" {
		bind, err = xio.ListenBindHost(network, bind)
		if err != nil {
			return nil, err
		}
		if sp == "" {
			// bind may already be host:port
			if _, _, e := net.SplitHostPort(bind); e != nil {
				sp = "0"
			}
		}
		ba := bind
		if sp != "" {
			ba = xio.BindPort(bind, sp)
		}
		laddr, err = net.ResolveUDPAddr(network, ba)
		if err != nil {
			return nil, err
		}
	}
	pc, err := listenPacketForSpec(ctx, network, laddrString(network, laddr), s)
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP: unexpected packet conn type")
	}
	// PH_LATE buffers. Send and recv IP/ancillary options were applied
	// at PH_PASTSOCKET by ListenControl.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	st := &udpDatagramConn{UDPConn: c, raddr: raddr, g: g, wantCtrl: xio.NeedAncillary(s)}
	wrapped, err := xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	return &xio.Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
}

func udpListenConfig(s parse.Spec) net.ListenConfig {
	return net.ListenConfig{
		Control: udpListenControl(s),
	}
}

// udpListenControl applies classic PH_PASTSOCKET then PH_PREBIND after
// socket() and before bind() (tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba; official master
// af5388c898c7bb60997935aee93c223deba60c4a is the same). Go's
// ListenConfig.Control runs in that window.
func udpListenControl(s parse.Spec) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		if err := xio.ListenControl(s)(network, address, c); err != nil {
			return err
		}
		if !xio.UDPForkPortReuse(s) {
			return nil
		}
		var optionErr error
		controlErr := c.Control(func(fd uintptr) {
			optionErr = enableUDPForkPortReuse(int(fd))
		})
		return errors.Join(controlErr, optionErr)
	}
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
	raddr    *net.UDPAddr
	g        *xio.Global
	wantCtrl bool
}

func (u *udpDatagramConn) Read(p []byte) (int, error) {
	n, oob, _, err := xio.ReadUDPMsg(u.UDPConn, p, u.wantCtrl)
	if err != nil {
		return n, err
	}
	if u.wantCtrl {
		xio.ProcessAncillary(oob, u.g)
	}
	return n, nil
}

func (u *udpDatagramConn) Write(p []byte) (int, error) {
	// Allow 0-byte writes (shut-null sends empty datagram).
	return u.WriteToUDP(p, u.raddr)
}

// bindUDPLowport binds a classic lowport via FirstAvailableLowport. Logs bind like SYCLS for tests.
func bindUDPLowport(ctx context.Context, network, bind string, s parse.Spec, g *xio.Global) (*net.UDPConn, int, error) {
	var conn *net.UDPConn
	port, err := xio.FirstAvailableLowport(func(port int) error {
		// Classic test greps: [DE] bind(.*:PORT
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=2 %s:%d}, 16)", bind, port)
		}
		addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(xio.StripBrackets(bind), strconv.Itoa(port)))
		if err != nil {
			return err
		}
		pc, err := listenPacketForSpec(ctx, network, addr.String(), s)
		if err != nil {
			return err
		}
		c, ok := pc.(*net.UDPConn)
		if !ok {
			logx.CloseQuiet(pc)
			return fmt.Errorf("not UDPConn")
		}
		conn = c
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return conn, port, nil
}
func (u *udpDatagramConn) ShutdownWrite() error { return nil }

func openUDPRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"), false)
}
func openUDP4Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"), true)
}
func openUDP4Recvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", true)
}
func openUDP6Recvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", true)
}

func openUDPRecvNetwork(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, network string, recvfrom bool) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	host, err := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	laddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(xio.StripBrackets(host), port))
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
			_, maxChildren, ferr := xio.ForkLimits(s)
			if ferr != nil {
				logx.CloseQuiet(pc)
				return nil, ferr
			}
			ln := &udpForkListener{
				pc:      pc,
				network: network,
				laddr:   laddr,
				spec:    s,
				g:       g,
				ctx:     ctx,
				oneShot: true,
			}
			if err := applyUDPForkTimeouts(ln, s); err != nil {
				logx.CloseQuiet(pc)
				return nil, err
			}
			return &xio.Opened{
				Kind:        xio.KindListen,
				Listener:    ln,
				Label:       "UDP-RECVFROM",
				MaxChildren: maxChildren,
				PeerFilter:  func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) },
				WrapDial: func(c net.Conn) (relay.Stream, error) {
					return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
				},
			}, nil
		}
		// Classic UDP-RECVFROM is not GROUP_LISTEN: wait for the first
		// permitted datagram with no accept-timeout.
		// One permitted packet, then use the *same* listening socket for replies
		// (classic). DialUDP(local, peer) after Close fails with EADDRINUSE.
		// When ancillary options are set, use recvmsg so we can log/set env
		// before SYSTEM/EXEC children start (UDP*ENV tests).
		buf := make([]byte, max(g.BlockSize, 65535))
		wantCtrl := xio.NeedAncillary(s)
		type res struct {
			n   int
			a   *net.UDPAddr
			oob []byte
			e   error
		}
		var n int
		var raddr *net.UDPAddr
		for {
			ch := make(chan res, 1)
			go func() {
				nn, oob, a, err := xio.ReadUDPMsg(pc, buf, wantCtrl)
				ch <- res{nn, a, oob, err}
			}()
			select {
			case <-ctx.Done():
				logx.CloseQuiet(pc)
				return nil, ctx.Err()
			case r := <-ch:
				if r.e != nil {
					logx.CloseQuiet(pc)
					return nil, udpAcceptError(r.e, false)
				}
				if err := xio.PeerAllowedG(s, &udpPeerConn{addr: r.a}, g); err != nil {
					if g != nil && g.Log != nil {
						g.Log.Noticef("%s", err)
					}
					continue
				}
				n, raddr = r.n, r.a
				// Process before returning so SYSTEM sees SOCAT_* env.
				xio.ProcessAncillary(r.oob, g)
			}
			break
		}
		// Classic non-fork RECVFROM: one datagram then EOF on further reads
		// (so RECVFROM|PIPE echo servers exit after one client exchange).
		st := relay.Stream(&udpRecvFromConn{
			uc:       pc,
			peer:     raddr,
			first:    append([]byte(nil), buf[:n]...),
			closeEOF: true,
			wantCtrl: wantCtrl,
			g:        g,
		})
		st, err = xio.WrapCommonAfterConnected(s, st)
		if err != nil {
			logx.CloseQuiet(pc)
			return nil, err
		}
		return &xio.Opened{
			Stream: st,
			Label:  "UDP-RECVFROM",
		}, nil
	}
	// RECV: merge all packets, read-only, with peer filters.
	if mode == xio.ModeWrite {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP-RECV is read-only")
	}
	st := relay.Stream(&udpFilteredRecv{
		conn:     pc,
		spec:     s,
		g:        g,
		wantCtrl: xio.NeedAncillary(s),
	})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{
		Stream: st,
		Label:  "UDP-RECV",
	}, nil
}

// udpFilteredRecv drops packets that fail range/sourceport/lowport checks.
// When wantCtrl is set, uses ReadMsgUDP and logs/sets ancillary env.
type udpFilteredRecv struct {
	conn     *net.UDPConn
	spec     parse.Spec
	g        *xio.Global
	wantCtrl bool
}

func (u *udpFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := xio.ReadUDPMsg(u.conn, p, u.wantCtrl)
		if err != nil {
			return n, err
		}
		if err := xio.PeerAllowedG(u.spec, &udpPeerConn{addr: addr}, u.g); err != nil {
			if u.g != nil && u.g.Log != nil {
				u.g.Log.Noticef("%s", err)
			}
			continue
		}
		if u.wantCtrl {
			xio.ProcessAncillary(oob, u.g)
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
	// Classic UDP-LISTEN sets SO_REUSEADDR when fork is on or reuseaddr is
	// present; UDP-RECV/RECVFROM only when the option is present.
	// BSD SO_REUSEPORT is enabled only for UDP-LISTEN fork when reuseaddr is
	// not explicitly disabled, so reuseaddr=0 stays exclusive.
	// PH_PASTSOCKET then PH_PREBIND run in Control after socket() and before
	// bind() (tag-1.8.1.3 12c08bf66d709fba17035ce95d85bd218428d9ba;
	// official master af5388c898c7bb60997935aee93c223deba60c4a is the same).
	pc, err := listenPacketForSpec(context.Background(), network, laddr.String(), s)
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	// PH_LATE buffers. Send and recv IP/ancillary options were applied
	// at PH_PASTSOCKET by ListenControl.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
