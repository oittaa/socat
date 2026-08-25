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
	// classic lowport: bind an ephemeral port in 640..1023 (log even if EACCES).
	if s.BoolOption("lowport") && sp == "" {
		bind = xio.ListenBindHost(network, bind)
		c, port, berr := bindUDPLowport(ctx, network, bind, s, g)
		if berr == nil && c != nil {
			// use this bound conn as the packet socket
			if s.BoolOption("broadcast") {
				raw, e := c.SyscallConn()
				if e != nil {
					_ = c.Close()
					return nil, e
				}
				var optionErr error
				if e = raw.Control(func(fd uintptr) {
					optionErr = xio.SetSockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}); e != nil || optionErr != nil {
					_ = c.Close()
					return nil, errors.Join(e, optionErr)
				}
			}
			if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
				_ = c.Close()
				return nil, err
			}
			st := &udpDatagramConn{UDPConn: c, raddr: raddr}
			wrapped, err := xio.WrapCommon(s, st)
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
		bind = xio.ListenBindHost(network, bind)
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
	// SO_REUSEADDR on bind so rapid retests / paired ports work.
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optionErr error
			controlErr := c.Control(func(fd uintptr) {
				optionErr = xio.ApplyListenOptions(int(fd), s, network)
				if optionErr != nil {
					return
				}
				if s.BoolOption("broadcast") {
					optionErr = xio.SetSockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}
			})
			return errors.Join(controlErr, optionErr)
		},
	}
	pc, err := cfg.ListenPacket(ctx, network, laddrString(network, laddr))
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP: unexpected packet conn type")
	}
	// Send-side IP options (ip-ttl, ip-tos, ipv6-tclass, …) for SENDTO/DATAGRAM.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	st := &udpDatagramConn{UDPConn: c, raddr: raddr}
	wrapped, err := xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	_ = g
	return &xio.Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
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
	return u.WriteToUDP(p, u.raddr)
}

// bindUDPLowport tries ports 1023..640 (classic lowport). Logs bind like SYCLS for tests.
func bindUDPLowport(ctx context.Context, network, bind string, s parse.Spec, g *xio.Global) (*net.UDPConn, int, error) {
	_ = s
	var last error
	for port := 1023; port >= 640; port-- {
		// Classic test greps: [DE] bind(.*:PORT
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=2 %s:%d}, 16)", bind, port)
		}
		addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(xio.StripBrackets(bind), strconv.Itoa(port)))
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
			logx.CloseQuiet(pc)
			last = fmt.Errorf("not UDPConn")
			continue
		}
		return c, port, nil
	}
	return nil, 0, last
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
		return nil, fmt.Errorf("UDP-RECV requires port")
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
					return xio.WrapCommon(s, relay.NetStream{Conn: c})
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
		st, err = xio.WrapCommon(s, st)
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
	st, err = xio.WrapCommon(s, st)
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
	// Default reuseaddr for listen-like UDP (classic often implies it with explicit option).
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var optionErr error
			controlErr := c.Control(func(fd uintptr) {
				optionErr = xio.ApplyListenOptions(int(fd), s, network)
				if optionErr != nil {
					return
				}
				if s.BoolOption("fork") {
					optionErr = enableUDPForkPortReuse(int(fd))
					if optionErr != nil {
						return
					}
				}
				if s.BoolOption("broadcast") {
					optionErr = xio.SetSockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				}
			})
			return errors.Join(controlErr, optionErr)
		},
	}
	pc, err := cfg.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	// Ancillary recv opts (so-timestamp, ip-recvttl, …) and send-side IP opts.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	// ip-add-membership=mcastaddr:interfaceaddr (classic form).
	if v := s.OptionValue("ip-add-membership", ""); v != "" {
		if err := joinMulticast(c, v); err != nil {
			logx.CloseQuiet(c)
			return nil, err
		}
	}
	return c, nil
}
