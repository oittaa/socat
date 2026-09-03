package netopen

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"), true)
}
func openUDP4Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4", true)
}
func openUDP6Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6", true)
}

// UDP*-DATAGRAM: unconnected datagram to address (broadcast/multicast capable).
func openUDPDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), false)
}
func openUDP4Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPDatagramNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string, exactPeer bool) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	stripped := xio.StripBrackets(host)
	netw, ip, err := xio.LookupDialIP(ctx, s, network, stripped)
	if err != nil {
		return nil, err
	}
	if ip == nil {
		return nil, fmt.Errorf("%s: invalid host", s.Type)
	}
	if net.ParseIP(stripped) == nil {
		network = netw
	}
	portNum, err := xio.ResolvePortNum(network, port)
	if err != nil {
		return nil, err
	}
	raddr := &net.UDPAddr{IP: ip, Port: portNum}
	if ip4 := ip.To4(); ip4 != nil && strings.HasSuffix(network, "4") {
		raddr.IP = ip4
	}
	bind := s.OptionValue("bind", "")
	// DATAGRAM ignores sourceport for the local bind; SENDTO uses it as the local port.
	sp := ""
	if exactPeer {
		sp = s.OptionValue("sourceport", "")
	}
	var laddr *net.UDPAddr
	// lowport: bind a port in 640..1023 (log even if EACCES).
	if s.BoolOption("lowport") && sp == "" {
		bind, err = xio.ListenBindHost(s, network, bind)
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
			st, err := newUDPDatagramConn(ctx, c, raddr, s, g, exactPeer)
			if err != nil {
				logx.CloseQuiet(c)
				return nil, err
			}
			wrapped, err := xio.WrapCommonAfterConnected(s, st)
			if err != nil {
				logx.CloseQuiet(c)
				return nil, err
			}
			_ = port
			return &xio.Opened{Stream: wrapped, Label: datagramLabel(exactPeer, raddr)}, nil
		}
		if berr == nil {
			berr = fmt.Errorf("all ports in use")
		}
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, berr)
	}
	if bind != "" || sp != "" {
		bind, err = xio.ListenBindHost(s, network, bind)
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
		laddr, err = xio.ResolveUDPAddr(ctx, s, network, ba)
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
	// Late buffers. Send and recv IP/ancillary options were applied
	// after socket() by ListenControl.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	st, err := newUDPDatagramConn(ctx, c, raddr, s, g, exactPeer)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	wrapped, err := xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	return &xio.Opened{Stream: wrapped, Label: datagramLabel(exactPeer, raddr)}, nil
}

func udpListenConfig(s parse.Spec) net.ListenConfig {
	return net.ListenConfig{
		Control: udpListenControl(s),
	}
}

// udpListenControl runs after socket() and before bind().
// Go's ListenConfig.Control is that window.
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

// udpDatagramConn writes always to raddr.
// SENDTO (exactPeer) accepts only the configured peer.
// DATAGRAM accepts any sender by default and applies range/tcpwrap/lowport
// filters; sourceport means dest-port of the sender.
type udpDatagramConn struct {
	*net.UDPConn
	raddr            *net.UDPAddr
	filter           *xio.PeerFilter
	g                *xio.Global
	ctx              context.Context
	wantCtrl         bool
	recvErr          bool
	exactPeer        bool
	sourcePortFilter bool
	oob              []byte
}

func newUDPDatagramConn(ctx context.Context, c *net.UDPConn, raddr *net.UDPAddr, s parse.Spec, g *xio.Global, exactPeer bool) (*udpDatagramConn, error) {
	_, sourcePortFilter := s.OptionNamed("sourceport")
	filter, err := xio.NewPeerFilter(ctx, specWithoutSourceport(s), g)
	if err != nil {
		return nil, err
	}
	return &udpDatagramConn{
		UDPConn:          c,
		raddr:            raddr,
		filter:           filter,
		g:                g,
		ctx:              ctx,
		wantCtrl:         xio.NeedAncillary(s),
		recvErr:          xio.NeedRecvErr(s),
		exactPeer:        exactPeer,
		sourcePortFilter: sourcePortFilter,
	}, nil
}

func datagramLabel(exactPeer bool, raddr *net.UDPAddr) string {
	kind := "UDP-DATAGRAM"
	if exactPeer {
		kind = "UDP-SENDTO"
	}
	return kind + ":" + raddr.String()
}

func logOrStopPeerFilter(ctx context.Context, g *xio.Global, err error) error {
	// Stop only when the session itself is done. A resolver timeout can
	// surface as context.DeadlineExceeded while the listener is still live.
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if g != nil && g.Log != nil {
		g.Log.Noticef("%s", err)
	}
	return nil
}

func (u *udpDatagramConn) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.UDPConn, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			xio.DrainRecvErrOnError(err, u.recvErr, u.UDPConn, u.g)
			return n, err
		}
		if err := u.checkPeer(addr); err != nil {
			if stop := logOrStopPeerFilter(u.ctx, u.g, err); stop != nil {
				return 0, stop
			}
			continue
		}
		if u.wantCtrl {
			xio.ProcessAncillary(oob, u.g)
		}
		return n, nil
	}
}

func (u *udpDatagramConn) checkPeer(addr *net.UDPAddr) error {
	if u.exactPeer {
		if !udpAddrIsPeer(addr, u.raddr) {
			return fmt.Errorf("recvfrom(): wrong peer address, ignoring packet")
		}
		return nil
	}
	// DATAGRAM sourceport is the configured destination port, not the local bind.
	if u.sourcePortFilter {
		if addr == nil || u.raddr == nil || addr.Port != u.raddr.Port {
			return fmt.Errorf("refusing connection from %s, sourceport mismatch", addr)
		}
	}
	return u.filter.AllowAddr(addr, u.LocalAddr())
}

func udpAddrIsPeer(got, want *net.UDPAddr) bool {
	if got == nil || want == nil {
		return false
	}
	if got.Port != want.Port {
		return false
	}
	gi, wi := got.IP, want.IP
	if len(gi) == 0 {
		gi = net.IPv4zero
	}
	if len(wi) == 0 {
		wi = net.IPv4zero
	}
	return gi.Equal(wi)
}

func specWithoutSourceport(s parse.Spec) parse.Spec {
	if !s.HasOption("sourceport") {
		return s
	}
	opts := make([]parse.Option, 0, len(s.Options))
	for _, o := range s.Options {
		name := strings.ToLower(o.Name)
		if name == "sourceport" || name == "sp" {
			continue
		}
		opts = append(opts, o)
	}
	s.Options = opts
	return s
}

func (u *udpDatagramConn) Write(p []byte) (int, error) {
	// Allow 0-byte writes (shut-null sends empty datagram).
	n, err := u.WriteToUDP(p, u.raddr)
	xio.DrainRecvErrOnError(err, u.recvErr, u.UDPConn, u.g)
	return n, err
}

// bindUDPLowport binds a port in 640..1023 via FirstAvailableLowport. Logs bind for tests.
func bindUDPLowport(ctx context.Context, network, bind string, s parse.Spec, g *xio.Global) (*net.UDPConn, int, error) {
	var conn *net.UDPConn
	port, err := xio.FirstAvailableLowport(func(port int) error {
		// test.sh greps: [DE] bind(.*:PORT
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=2 %s:%d}, 16)", bind, port)
		}
		addr, err := xio.ResolveUDPAddr(ctx, s, network, net.JoinHostPort(xio.StripBrackets(bind), strconv.Itoa(port)))
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
	return openUDPRecvNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), false)
}
func openUDP4Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), true)
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
	host, err := xio.ListenBindHost(s, network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	laddr, err := xio.ResolveUDPAddr(ctx, s, network, net.JoinHostPort(xio.StripBrackets(host), port))
	if err != nil {
		return nil, err
	}
	pc, err := listenUDP(network, laddr, s)
	if err != nil {
		return nil, err
	}
	if recvfrom {
		// fork: keep listening, one SYSTEM/child per datagram.
		if s.BoolOption("fork") {
			_, maxChildren, ferr := xio.ForkLimits(s)
			if ferr != nil {
				logx.CloseQuiet(pc)
				return nil, ferr
			}
			peerFilter, err := xio.NewPeerFilter(ctx, s, g)
			if err != nil {
				logx.CloseQuiet(pc)
				return nil, err
			}
			ln := &udpForkListener{
				pc:      pc,
				network: network,
				laddr:   laddr,
				spec:    s,
				g:       g,
				ctx:     ctx,
				oneShot: true,
				filter:  peerFilter,
			}
			if err := applyUDPForkTimeouts(ln, s); err != nil {
				logx.CloseQuiet(pc)
				return nil, err
			}
			xio.NoteListenBound(pc.LocalAddr())
			return &xio.Opened{
				Kind:        xio.KindListen,
				Listener:    ln,
				Label:       "UDP-RECVFROM",
				MaxChildren: maxChildren,
				PeerFilter:  peerFilter.AllowConn,
				WrapDial: func(c net.Conn) (relay.Stream, error) {
					return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
				},
			}, nil
		}
		xio.NoteListenBound(pc.LocalAddr())
		// UDP-RECVFROM is not a listen address: wait for the first permitted
		// datagram with no accept-timeout.
		// One permitted packet, then use the *same* listening socket for replies.
		// DialUDP(local, peer) after Close fails with EADDRINUSE.
		// When ancillary options are set, use recvmsg so we can log/set env
		// before SYSTEM/EXEC children start (UDP*ENV tests).
		buf := make([]byte, max(g.BlockSize, 65535))
		wantCtrl := xio.NeedAncillary(s)
		recvErr := xio.NeedRecvErr(s)
		type res struct {
			n   int
			a   *net.UDPAddr
			oob []byte
			e   error
		}
		var n int
		var raddr *net.UDPAddr
		peerFilter, err := xio.NewPeerFilter(ctx, s, g)
		if err != nil {
			logx.CloseQuiet(pc)
			return nil, err
		}
		var oobBuffer [xio.AncillaryBufferSize]byte
		for {
			ch := make(chan res, 1)
			go func() {
				nn, oob, a, err := xio.ReadUDPMsgWithBuffer(pc, buf, wantCtrl, oobBuffer[:])
				ch <- res{nn, a, oob, err}
			}()
			select {
			case <-ctx.Done():
				logx.CloseQuiet(pc)
				return nil, ctx.Err()
			case r := <-ch:
				if r.e != nil {
					xio.DrainRecvErrOnError(r.e, recvErr, pc, g)
					logx.CloseQuiet(pc)
					return nil, udpAcceptError(r.e, false)
				}
				if err := peerFilter.AllowAddr(r.a, pc.LocalAddr()); err != nil {
					if stop := logOrStopPeerFilter(ctx, g, err); stop != nil {
						logx.CloseQuiet(pc)
						return nil, stop
					}
					continue
				}
				if xio.IgnoreEmptyDatagram(r.n, r.e, s.BoolOption("null-eof")) {
					continue
				}
				n, raddr = r.n, r.a
				// Process before returning so SYSTEM sees SOCAT_* env.
				xio.ProcessAncillary(r.oob, g)
			}
			break
		}
		// Non-fork RECVFROM: one datagram then EOF on further reads
		// (so RECVFROM|PIPE echo servers exit after one client exchange).
		st := relay.Stream(&udpRecvFromConn{
			uc:           pc,
			peer:         raddr,
			first:        append([]byte(nil), buf[:n]...),
			firstPending: true,
			closeEOF:     true,
			wantCtrl:     wantCtrl,
			recvErr:      recvErr,
			g:            g,
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
	filter, err := xio.NewPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	st := relay.Stream(&udpFilteredRecv{
		conn:     pc,
		filter:   filter,
		g:        g,
		ctx:      ctx,
		wantCtrl: xio.NeedAncillary(s),
		recvErr:  xio.NeedRecvErr(s),
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
	filter   *xio.PeerFilter
	g        *xio.Global
	ctx      context.Context
	wantCtrl bool
	recvErr  bool
	oob      []byte
}

func (u *udpFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := xio.ReadUDPMsgWithBuffer(u.conn, p, u.wantCtrl, ancillaryBuffer(&u.oob, u.wantCtrl))
		if err != nil {
			xio.DrainRecvErrOnError(err, u.recvErr, u.conn, u.g)
			return n, err
		}
		if err := u.filter.AllowAddr(addr, u.conn.LocalAddr()); err != nil {
			if stop := logOrStopPeerFilter(u.ctx, u.g, err); stop != nil {
				return 0, stop
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
	// UDP-LISTEN sets SO_REUSEADDR when fork is on or reuseaddr is
	// present; UDP-RECV/RECVFROM only when the option is present.
	// macOS SO_REUSEPORT is enabled only for UDP-LISTEN fork when reuseaddr is
	// not explicitly disabled, so reuseaddr=0 stays exclusive.
	// After-socket then before-bind options run in Control.
	pc, err := listenPacketForSpec(context.Background(), network, laddr.String(), s)
	if err != nil {
		return nil, err
	}
	c := pc.(*net.UDPConn)
	// Late buffers. Send and recv IP/ancillary options were applied
	// after socket() by ListenControl.
	if err := xio.ApplyUDPConnOpts(c, s, network); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}
