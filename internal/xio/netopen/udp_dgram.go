package netopen

import (
	"context"
	"errors"
	"fmt"
	"github.com/oittaa/socat/internal/addrconfig"
	"net"
	"strconv"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPSendto(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"), true)
}
func openUDP4Sendto(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4", true)
}
func openUDP6Sendto(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6", true)
}

// UDP*-DATAGRAM: unconnected datagram to address (broadcast/multicast capable).
func openUDPDatagram(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), false)
}
func openUDP4Datagram(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Datagram(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPDatagramNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPDatagramNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string, exactPeer bool) (*xio.Opened, error) {
	network, raddr, err := resolveUDPDatagramRemote(ctx, s, network)
	if err != nil {
		return nil, err
	}
	sp := ""
	if exactPeer {
		sp = xio.SourcePortText(s)
	}
	var laddr *net.UDPAddr
	if s.Network.LowPort.Value && sp == "" {
		bind, bindErr := xio.ListenBindHost(s, network)
		if bindErr != nil {
			return nil, bindErr
		}
		c, port, berr := bindUDPLowport(ctx, network, bind, s, g)
		if berr == nil && c != nil {
			_ = port
			return wrapUDPDatagram(ctx, s, g, c, raddr, network, exactPeer)
		}
		if berr == nil {
			berr = fmt.Errorf("all ports in use")
		}
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, berr)
	}
	if s.Network.BindSet || sp != "" {
		bind, bindErr := xio.ListenBindHost(s, network)
		if bindErr != nil {
			return nil, bindErr
		}
		p := addrconfig.PortFromText("0")
		if s.Network.BindPortSet {
			p = s.Network.BindPort
		} else if exactPeer && s.Network.SourcePortSet {
			p = s.Network.SourcePort
		}
		laddr, err = xio.ResolveUDPTarget(ctx, s, network, bind, p)
		if err != nil {
			return nil, err
		}
	}
	pc, err := listenPacketForSpec(ctx, network, laddr, s)
	if err != nil {
		return nil, err
	}
	c, ok := pc.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP: unexpected packet conn type")
	}
	return wrapUDPDatagram(ctx, s, g, c, raddr, network, exactPeer)
}

func resolveUDPDatagramRemote(ctx context.Context, s addrconfig.Address, network string) (string, *net.UDPAddr, error) {
	if !s.Network.TargetSet {
		return "", nil, fmt.Errorf("%s requires host and port", s.Type)
	}
	if !s.Network.Target.IsLiteral() {
		netw, err := xio.PacketNetworkForHost(ctx, s, network, s.Network.Target)
		if err != nil {
			return "", nil, err
		}
		network = netw
	}
	raddr, err := xio.ResolveUDPTarget(ctx, s, network, s.Network.Target, s.Network.TargetPort)
	if err != nil {
		return "", nil, err
	}
	return network, raddr, nil
}

func wrapUDPDatagram(ctx context.Context, s addrconfig.Address, g *xio.Global, c *net.UDPConn, raddr *net.UDPAddr, network string, exactPeer bool) (*xio.Opened, error) {
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
	wrapped, err := xio.WrapOpened(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	return &xio.Opened{Stream: wrapped, Label: datagramLabel(exactPeer, raddr)}, nil
}

func udpListenConfig(s addrconfig.Address) net.ListenConfig {
	return net.ListenConfig{
		Control: udpListenControl(s),
	}
}

// udpListenControl runs after socket() and before bind().
// Go's ListenConfig.Control is that window.
func udpListenControl(s addrconfig.Address) func(network, address string, c syscall.RawConn) error {
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

func newUDPDatagramConn(ctx context.Context, c *net.UDPConn, raddr *net.UDPAddr, s addrconfig.Address, g *xio.Global, exactPeer bool) (*udpDatagramConn, error) {
	sourcePortFilter := s.Network.SourcePortSet
	filter, err := xio.NewPeerFilter(ctx, s.Network.WithoutSourcePort(), xio.LookupResolver(s), g)
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

func (u *udpDatagramConn) Write(p []byte) (int, error) {
	// Allow 0-byte writes (shut-null sends empty datagram).
	n, err := u.WriteToUDP(p, u.raddr)
	xio.DrainRecvErrOnError(err, u.recvErr, u.UDPConn, u.g)
	return n, err
}

// bindUDPLowport binds a port in 640..1023 via FirstAvailableLowport. Logs bind for tests.
func bindUDPLowport(ctx context.Context, network string, bind addrconfig.HostTarget, s addrconfig.Address, g *xio.Global) (*net.UDPConn, int, error) {
	var conn *net.UDPConn
	port, err := xio.FirstAvailableLowport(func(port int) error {
		// test.sh greps: [DE] bind(.*:PORT
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind({AF=2 %s:%d}, 16)", bind.Original(), port)
		}
		addr, err := xio.ResolveUDPTarget(ctx, s, network, bind, addrconfig.PortFromText(strconv.Itoa(port)))
		if err != nil {
			return err
		}
		pc, err := listenPacketForSpec(ctx, network, addr, s)
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

func openUDPRecv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), false)
}
func openUDP4Recv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", false)
}
func openUDP6Recv(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", false)
}

func openUDPRecvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, udpNetworkWithListenDefault(g, s), true)
}
func openUDP4Recvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp4", true)
}
func openUDP6Recvfrom(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPRecvNetwork(ctx, s, mode, g, "udp6", true)
}

func openUDPRecvNetwork(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global, network string, recvfrom bool) (*xio.Opened, error) {
	pc, laddr, err := bindUDPPort(ctx, s, network)
	if err != nil {
		return nil, err
	}
	if recvfrom {
		if xio.ForkRequested(s) {
			return openUDPRecvfromFork(ctx, s, g, pc, laddr, network)
		}
		return openUDPRecvfromOne(ctx, s, g, pc)
	}
	return openUDPRecvAll(ctx, s, g, pc, mode)
}

func openUDPRecvfromFork(ctx context.Context, s addrconfig.Address, g *xio.Global, pc *net.UDPConn, laddr *net.UDPAddr, network string) (*xio.Opened, error) {
	_, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		logx.CloseQuiet(pc)
		return nil, ferr
	}
	peerFilter, err := xio.PreparedPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	ln := &udpForkListener{
		pc:      pc,
		network: network,
		laddr:   laddr,
		config:  s,
		g:       g,
		ctx:     ctx,
		oneShot: true,
		nullEOF: s.Transfer.NullEOF.Value,
		filter:  peerFilter,
	}
	if err := applyUDPForkTimeouts(ln, s); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	xio.NoteListenBound(pc.LocalAddr())
	return &xio.Opened{
		Kind:           xio.KindListen,
		Listener:       ln,
		Label:          "UDP-RECVFROM",
		ForkSocketpair: true,
		MaxChildren:    maxChildren,
		PeerFilter:     peerFilter.AllowConn,
		WrapDial:       xio.DefaultWrapOpened(s),
	}, nil
}

func openUDPRecvfromOne(ctx context.Context, s addrconfig.Address, g *xio.Global, pc *net.UDPConn) (*xio.Opened, error) {
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
	peerFilter, err := xio.PreparedPeerFilter(ctx, s, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	nullEOF := s.Transfer.NullEOF.Value
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
			if xio.IgnoreEmptyDatagram(r.n, r.e, nullEOF) {
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
		uc:       pc,
		peer:     raddr,
		first:    newFirstPacket(append([]byte(nil), buf[:n]...)),
		closeEOF: true,
		wantCtrl: wantCtrl,
		recvErr:  recvErr,
		g:        g,
	})
	st, err = xio.WrapOpened(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{
		Stream: st,
		Label:  "UDP-RECVFROM",
	}, nil
}

func openUDPRecvAll(ctx context.Context, s addrconfig.Address, g *xio.Global, pc *net.UDPConn, mode xio.Mode) (*xio.Opened, error) {
	if mode == xio.ModeWrite {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("UDP-RECV is read-only")
	}
	filter, err := xio.PreparedPeerFilter(ctx, s, g)
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
	st, err = xio.WrapOpened(s, st)
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
func (u *udpFilteredRecv) ShutdownWrite() error      { return u.Close() }
func (u *udpFilteredRecv) LocalAddr() net.Addr       { return u.conn.LocalAddr() }
func (u *udpFilteredRecv) RemoteAddr() net.Addr      { return nil }

func listenUDP(network string, laddr *net.UDPAddr, s addrconfig.Address) (*net.UDPConn, error) {
	// UDP-LISTEN sets SO_REUSEADDR when fork is on or reuseaddr is
	// present; UDP-RECV/RECVFROM only when the option is present.
	// macOS SO_REUSEPORT is enabled only for UDP-LISTEN fork when reuseaddr is
	// not explicitly disabled, so reuseaddr=0 stays exclusive.
	// After-socket then before-bind options run in Control.
	pc, err := listenPacketForSpec(context.Background(), network, laddr, s)
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
