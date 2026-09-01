package netopen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// Raw IP (SOCK_RAW) addresses: IP4/IP6-SENDTO/RECV/RECVFROM.
// Requires CAP_NET_RAW (root). Used by ancillary SCM/ENV tests with KEYW=IP4/IP6.

func openIPSendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, NetworkIP(g, s, "ip4"))
}
func openIP4Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip4")
}
func openIP6Sendto(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip6")
}

// IP*-DATAGRAM is unconnected (sendto/recvfrom), not DialIP.
// Required for broadcast/multicast and for bind= to a local addr with a remote host.
func openIPDatagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, NetworkIP(g, s, "ip4"))
}
func openIP4Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, "ip4")
}
func openIP6Datagram(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, "ip6")
}

func openIPRecv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, NetworkIP(g, s, "ip4"), false)
}
func openIP4Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip4", false)
}
func openIP6Recv(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip6", false)
}

func openIPRecvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, NetworkIP(g, s, "ip4"), true)
}
func openIP4Recvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip4", true)
}
func openIP6Recvfrom(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip6", true)
}

// IP:host:proto — family from pf=, host address, or global -4/-6.
func openIP(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	netw := NetworkIPFromHost(g, s, "ip4")
	return openIPSendtoNetwork(ctx, s, mode, g, netw)
}
func openIP4(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip4")
}
func openIP6(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip6")
}

func NetworkIP(g *xio.Global, s parse.Spec, def string) string {
	if s.HasOption("pf") {
		if n := xio.NetworkFromPF(s.OptionValue("pf", ""), "ip", ""); n != "" {
			return n
		}
	}
	if g != nil {
		switch g.IPVersion {
		case xio.IPv6:
			return "ip6"
		case xio.IPv4:
			return "ip4"
		}
	}
	return def
}

// NetworkIPFromHost prefers an explicit IPv6 host (e.g. IP:[::1]:proto).
func NetworkIPFromHost(g *xio.Global, s parse.Spec, def string) string {
	if s.HasOption("pf") {
		return NetworkIP(g, s, def)
	}
	if len(s.Params) >= 1 {
		host := xio.StripBrackets(s.Params[0])
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil {
				return "ip6"
			}
			return "ip4"
		}
	}
	return NetworkIP(g, s, def)
}

func ipNetwork(network string, proto int) string {
	// net.ListenIP / DialIP: "ip4:89" or "ip6:89"
	return fmt.Sprintf("%s:%d", network, proto)
}

func parseProtoParam(s parse.Spec, idx int) (int, error) {
	if len(s.Params) <= idx || s.Params[idx] == "" {
		return 0, fmt.Errorf("%s: missing protocol number", s.Type)
	}
	n, err := strconv.ParseUint(s.Params[idx], 0, 8)
	if err != nil {
		return 0, fmt.Errorf("%s: bad protocol %q: %w", s.Type, s.Params[idx], err)
	}
	if n >= 256 {
		return 0, fmt.Errorf("%s: protocol number exceeds 255 (%d)", s.Type, n)
	}
	return int(n), nil
}

// resolveRawIPTarget parses a literal IP or resolves a hostname for raw
// SOCK_RAW addresses, honoring the resolver options.
func resolveRawIPTarget(ctx context.Context, s parse.Spec, network, host string) (*net.IPAddr, error) {
	if ip := net.ParseIP(host); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}
	ips, err := xio.LookupIP(ctx, s, ipLookupNet(network), host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%s: resolve %q: %w", s.Type, host, err)
	}
	return &net.IPAddr{IP: ips[0]}, nil
}

// resolveRawIPBind resolves bind= with the address-local resolver. Literals skip DNS.
func resolveRawIPBind(ctx context.Context, s parse.Spec, network, bind string) (*net.IPAddr, error) {
	addr, err := resolveRawIPTarget(ctx, s, network, xio.StripBrackets(bind))
	if err != nil {
		return nil, fmt.Errorf("%s: bad bind %q: %w", s.Type, bind, err)
	}
	return addr, nil
}

// requireRawIPFamily rejects a target whose family does not match the forced
// ip4/ip6 network of an explicit IP4/IP6 address type.
func requireRawIPFamily(typ, network string, raddr *net.IPAddr, host string) error {
	if network == "ip4" && raddr.IP.To4() == nil {
		return fmt.Errorf("%s: address %s: non-IPv4 address", typ, host)
	}
	if network == "ip6" && raddr.IP.To4() != nil {
		return fmt.Errorf("%s: address %s: non-IPv6 address", typ, host)
	}
	return nil
}

func openIPSendtoNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	// IP4-SENDTO:host:proto
	if len(s.Params) < 2 {
		return nil, fmt.Errorf("%s: requires host:protocol", s.Type)
	}
	host := xio.StripBrackets(s.Params[0])
	proto, err := parseProtoParam(s, 1)
	if err != nil {
		return nil, err
	}
	raddr, err := resolveRawIPTarget(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		network = xio.DialNetwork(network, raddr.IP)
		if ip4 := raddr.IP.To4(); ip4 != nil {
			raddr = &net.IPAddr{IP: ip4}
		}
	}
	var laddr *net.IPAddr
	if bind := s.OptionValue("bind", ""); bind != "" {
		laddr, err = resolveRawIPBind(ctx, s, network, bind)
		if err != nil {
			return nil, err
		}
	}
	laddr = matchRawLocalIP(network, laddr)
	if err := requireRawIPFamily(s.Type, network, raddr, host); err != nil {
		return nil, err
	}
	netw := ipNetwork(network, proto)
	c, err := dialRawIP(ctx, netw, network, laddr, raddr, s)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(c, s, network); err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	// Connected IPv4 Read() keeps the IP header; strip so user data starts at payload.
	v4 := network == "ip4" || raddr.IP.To4() != nil
	st := relay.Stream(&rawIPConn{IPConn: c, peer: raddr, v4: v4, wantCtrl: xio.NeedAncillary(s), g: g})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(c)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type + ":" + host + ":" + strconv.Itoa(proto)}, nil
}

// openIPDatagramNetwork: unconnected SOCK_RAW for IP*-DATAGRAM (broadcast/multicast).
func openIPDatagramNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 2 {
		return nil, fmt.Errorf("%s: requires host:protocol", s.Type)
	}
	host := xio.StripBrackets(s.Params[0])
	proto, err := parseProtoParam(s, 1)
	if err != nil {
		return nil, err
	}
	raddr, err := resolveRawIPTarget(ctx, s, network, host)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(host) == nil {
		network = xio.DialNetwork(network, raddr.IP)
		if ip4 := raddr.IP.To4(); ip4 != nil {
			raddr = &net.IPAddr{IP: ip4}
		}
	}
	if err := requireRawIPFamily(s.Type, network, raddr, host); err != nil {
		return nil, err
	}
	laddr := &net.IPAddr{IP: net.IPv4zero}
	if network == "ip6" {
		laddr = &net.IPAddr{IP: net.IPv6zero}
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		laddr, err = resolveRawIPBind(ctx, s, network, bind)
		if err != nil {
			return nil, err
		}
	}
	laddr = matchRawLocalIP(network, laddr)
	netw := ipNetwork(network, proto)
	pc, err := listenRawIP(ctx, netw, network, laddr, s)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(pc, s, network); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	v4 := network == "ip4" || raddr.IP.To4() != nil
	st := relay.Stream(&rawIPDatagramConn{
		c:        pc,
		raddr:    raddr,
		v4:       v4,
		wantCtrl: xio.NeedAncillary(s),
		g:        g,
		ctx:      ctx,
		filter:   xio.NewPeerFilter(ctx, s, g),
	})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type + ":" + host + ":" + strconv.Itoa(proto)}, nil
}

func openIPRecvNetwork(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global, network string, recvfrom bool) (*xio.Opened, error) {
	// IP4-RECV:proto  /  IP4-RECVFROM:proto
	proto, err := parseProtoParam(s, 0)
	if err != nil {
		return nil, err
	}
	laddr := &net.IPAddr{IP: net.IPv4zero}
	if network == "ip6" {
		laddr = &net.IPAddr{IP: net.IPv6zero}
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		laddr, err = resolveRawIPBind(ctx, s, network, bind)
		if err != nil {
			return nil, err
		}
	}
	netw := ipNetwork(network, proto)
	pc, err := listenRawIP(ctx, netw, network, laddr, s)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(pc, s, network); err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}

	wantCtrl := xio.NeedAncillary(s)
	if recvfrom {
		if s.BoolOption("fork") {
			return openIPRecvfromFork(ctx, s, g, pc, network)
		}
		return openIPRecvfromOneShot(ctx, s, g, pc, network, wantCtrl)
	}

	// RECV: merge packets, read-only
	if mode == xio.ModeWrite {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	st := relay.Stream(&rawIPFilteredRecv{
		c:        pc,
		filter:   xio.NewPeerFilter(ctx, s, g),
		g:        g,
		ctx:      ctx,
		wantCtrl: wantCtrl,
		v4:       network == "ip4",
	})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

func openIPRecvfromFork(ctx context.Context, s parse.Spec, g *xio.Global, pc *net.IPConn, network string) (*xio.Opened, error) {
	_, maxChildren, ferr := xio.ForkLimits(s)
	if ferr != nil {
		logx.CloseQuiet(pc)
		return nil, ferr
	}
	rcvTimeout, err := xio.RecvTimeoutFromSpec(s)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	peerFilter := xio.NewPeerFilter(ctx, s, g)
	ln := &rawIPForkListener{
		pc:         pc,
		spec:       s,
		g:          g,
		ctx:        ctx,
		filter:     peerFilter,
		rcvTimeout: rcvTimeout,
		v4:         network == "ip4",
	}
	xio.NoteListenBound(pc.LocalAddr())
	return &xio.Opened{
		Kind:        xio.KindListen,
		Listener:    ln,
		Label:       s.Type,
		MaxChildren: maxChildren,
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnected(s, relay.NetStream{Conn: c})
		},
	}, nil
}

func openIPRecvfromOneShot(ctx context.Context, s parse.Spec, g *xio.Global, pc *net.IPConn, network string, wantCtrl bool) (*xio.Opened, error) {
	// One permitted packet, then EOF. Keep the socket for reply writes.
	buf := make([]byte, max(g.BlockSize, 65535))
	stripV4 := network == "ip4"
	peerFilter := xio.NewPeerFilter(ctx, s, g)
	n, oob, raddr, err := recvRawIPFiltered(ctx, pc, buf, wantCtrl, stripV4, peerFilter, g)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	xio.ProcessAncillary(oob, g)
	peerIP := ipAddrFromNet(raddr)
	rememberRawIPPeer(g, peerIP, pc.LocalAddr())
	st := relay.Stream(&rawIPRecvFrom{
		c:            pc,
		peer:         peerIP,
		first:        append([]byte(nil), buf[:n]...),
		firstPending: true,
		closeEOF:     true,
		wantCtrl:     wantCtrl,
		v4:           stripV4,
		g:            g,
	})
	st, err = xio.WrapCommonAfterConnected(s, st)
	if err != nil {
		logx.CloseQuiet(pc)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: s.Type}, nil
}

func recvRawIPFiltered(ctx context.Context, pc *net.IPConn, buf []byte, wantCtrl, stripV4 bool, filter *xio.PeerFilter, g *xio.Global) (int, []byte, net.Addr, error) {
	var oobBuffer [xio.AncillaryBufferSize]byte
	for {
		rn, oob, a, err := xio.RecvOneCtx(ctx, func() (int, []byte, net.Addr, error) {
			return ReadIPMsgWithBuffer(pc, buf, wantCtrl, stripV4, oobBuffer[:])
		})
		if err != nil {
			return 0, nil, nil, err
		}
		if ferr := filter.AllowAddr(a, pc.LocalAddr()); ferr != nil {
			if stop := logOrStopPeerFilter(ctx, g, ferr); stop != nil {
				return 0, nil, nil, stop
			}
			continue
		}
		return rn, oob, a, nil
	}
}

func ipLookupNet(network string) string {
	if network == "ip6" {
		return "ip6"
	}
	return "ip4"
}

func matchRawLocalIP(network string, laddr *net.IPAddr) *net.IPAddr {
	if laddr == nil {
		return nil
	}
	want4 := network == "ip4"
	if laddr.IP == nil || laddr.IP.IsUnspecified() {
		if want4 {
			return &net.IPAddr{IP: net.IPv4zero, Zone: laddr.Zone}
		}
		if network == "ip6" {
			return &net.IPAddr{IP: net.IPv6zero, Zone: laddr.Zone}
		}
	}
	return laddr
}

func rawIPListenAddr(netw string, laddr *net.IPAddr) string {
	if laddr != nil && laddr.IP != nil {
		return laddr.String()
	}
	if strings.HasPrefix(netw, "ip6") {
		return "::"
	}
	return "0.0.0.0"
}

// testHookAfterRawIPPastSocket, when set, runs inside Dialer/ListenConfig
// Control after socket() options and before bind/connect.
var testHookAfterRawIPPastSocket func(network, address string, c syscall.RawConn) error

func dialRawIP(ctx context.Context, netw, network string, laddr, raddr *net.IPAddr, s parse.Spec) (*net.IPConn, error) {
	d := net.Dialer{
		Timeout:   xio.ConnectTimeout(s),
		LocalAddr: laddr,
		Control:   xio.DialControl(s, network, testHookAfterRawIPPastSocket),
	}
	c, err := d.DialContext(ctx, netw, raddr.String())
	if err != nil {
		return nil, err
	}
	ic, ok := c.(*net.IPConn)
	if !ok {
		logx.CloseQuiet(c)
		return nil, fmt.Errorf("%s: unexpected conn type %T", netw, c)
	}
	return ic, nil
}

func listenRawIP(ctx context.Context, netw, _ string, laddr *net.IPAddr, s parse.Spec) (*net.IPConn, error) {
	inner := xio.ListenControl(s)
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if err := inner(network, address, c); err != nil {
				return err
			}
			if h := testHookAfterRawIPPastSocket; h != nil {
				return h(network, address, c)
			}
			return nil
		},
	}
	pc, err := lc.ListenPacket(ctx, netw, rawIPListenAddr(netw, laddr))
	if err != nil {
		return nil, err
	}
	ic, ok := pc.(*net.IPConn)
	if !ok {
		logx.CloseQuiet(pc)
		return nil, fmt.Errorf("%s: unexpected packet conn type %T", netw, pc)
	}
	return ic, nil
}

// applyIPConnOpts applies remaining connected-phase SOL_SOCKET options.
// Send and recv IP/ancillary options and multicast joins apply after socket()
// (dialRawIP/listenRawIP Control → ApplyPastSocketPhase) and must not be
// re-applied here after DialIP/ListenIP-equivalent bind/connect.
// SO_BROADCAST is applied with other after-socket SOL_SOCKET options via
// ApplySocketOptions (bare flag → 1; broadcast=0 still setsockopt).
func applyIPConnOpts(c *net.IPConn, s parse.Spec, _ string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	controlErr := raw.Control(func(fd uintptr) {
		if optionErr = xio.ApplyGenericSetsockopt(int(fd), s, xio.SockoptPhaseConnected); optionErr != nil {
			return
		}
		// reuseaddr applies on raw sockets too when present.
		optionErr = xio.ApplyReuse(int(fd), s, true)
	})
	if err := errors.Join(controlErr, optionErr); err != nil {
		return err
	}
	return xio.ApplyFDLifecycleToConn(c, s)
}

func ReadIPMsg(c *net.IPConn, p []byte, wantCtrl bool, stripV4 bool) (n int, oob []byte, addr net.Addr, err error) {
	return ReadIPMsgWithBuffer(c, p, wantCtrl, stripV4, nil)
}

// ReadIPMsgWithBuffer returns control data backed by oobBuffer.
// Callers must consume it before reusing the buffer.
func ReadIPMsgWithBuffer(c *net.IPConn, p []byte, wantCtrl bool, stripV4 bool, oobBuffer []byte) (n int, oob []byte, addr net.Addr, err error) {
	if !wantCtrl {
		n, addr, err = c.ReadFrom(p)
		if err != nil {
			return n, nil, addr, err
		}
		// ReadFrom usually strips IPv4 already; only strip when a full header is present.
		if stripV4 {
			n = skipIPv4HeaderIfPresent(p, n)
		}
		return n, nil, addr, err
	}
	// ReadMsgIP returns the full IPv4 packet (header + payload). Strip the
	// header so user data starts at payload.
	if len(oobBuffer) < xio.AncillaryBufferSize {
		oobBuffer = make([]byte, xio.AncillaryBufferSize)
	}
	var oobn, flags int
	n, oobn, flags, addr, err = c.ReadMsgIP(p, oobBuffer)
	if err != nil {
		return n, nil, nil, err
	}
	if stripV4 {
		n = skipIPv4HeaderIfPresent(p, n)
	}
	return n, xio.ControlMessageBytes(oobBuffer, oobn, flags), addr, nil
}

// skipIPv4HeaderIfPresent drops a leading IPv4 header when the buffer looks like
// a complete IP packet. Connected IPConn.Read() on Linux returns header+payload;
// unconnected ReadFrom often returns payload only.
func skipIPv4HeaderIfPresent(p []byte, n int) int {
	if n < 20 {
		return n
	}
	if p[0]>>4 != 4 {
		return n
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || ihl > n {
		return n
	}
	total := int(p[2])<<8 | int(p[3])
	// Require IP total length to match the received size (full packet).
	if total != n {
		return n
	}
	copy(p, p[ihl:n])
	return n - ihl
}

// rawIPDatagramConn: unconnected SOCK_RAW; writes always go to raddr.
// Reads accept any sender unless range/tcpwrap (and related filters) refuse.
type rawIPDatagramConn struct {
	c        *net.IPConn
	raddr    *net.IPAddr
	v4       bool
	wantCtrl bool
	g        *xio.Global
	ctx      context.Context
	filter   *xio.PeerFilter
	oob      []byte
}

func (r *rawIPDatagramConn) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := ReadIPMsgWithBuffer(r.c, p, r.wantCtrl, r.v4, ancillaryBuffer(&r.oob, r.wantCtrl))
		if err != nil {
			return n, err
		}
		if err := r.filter.AllowAddr(addr, r.c.LocalAddr()); err != nil {
			if stop := logOrStopPeerFilter(r.ctx, r.g, err); stop != nil {
				return 0, stop
			}
			continue
		}
		if r.wantCtrl {
			xio.ProcessAncillary(oob, r.g)
		}
		return n, nil
	}
}

func (r *rawIPDatagramConn) Write(p []byte) (int, error) {
	return r.c.WriteToIP(p, r.raddr)
}

func (r *rawIPDatagramConn) Close() error         { return r.c.Close() }
func (r *rawIPDatagramConn) ShutdownWrite() error { return nil }
func (r *rawIPDatagramConn) LocalAddr() net.Addr  { return r.c.LocalAddr() }
func (r *rawIPDatagramConn) RemoteAddr() net.Addr { return r.raddr }
func (r *rawIPDatagramConn) SetDeadline(t time.Time) error {
	return r.c.SetDeadline(t)
}
func (r *rawIPDatagramConn) SetReadDeadline(t time.Time) error {
	return r.c.SetReadDeadline(t)
}
func (r *rawIPDatagramConn) SetWriteDeadline(t time.Time) error {
	return r.c.SetWriteDeadline(t)
}
func (r *rawIPDatagramConn) SyscallConn() (syscall.RawConn, error) {
	return r.c.SyscallConn()
}

// rawIPConn: sendto-style connected IPConn (SELF echo, SENDTO client).
// Do not embed Read from *net.IPConn — connected Read keeps the IPv4 header.
type rawIPConn struct {
	*net.IPConn
	peer     *net.IPAddr
	v4       bool
	wantCtrl bool
	g        *xio.Global
	oob      []byte
}

func (r *rawIPConn) Read(p []byte) (int, error) {
	if r.wantCtrl {
		n, oob, _, err := ReadIPMsgWithBuffer(r.IPConn, p, true, r.v4, ancillaryBuffer(&r.oob, true))
		if err != nil {
			return n, err
		}
		xio.ProcessAncillary(oob, r.g)
		return n, nil
	}
	n, err := r.IPConn.Read(p)
	if err != nil {
		return n, err
	}
	if r.v4 {
		n = skipIPv4HeaderIfPresent(p, n)
	}
	return n, nil
}

func (r *rawIPConn) ShutdownWrite() error { return nil }

// rawIPRecvFrom: first datagram buffered; further reads EOF when one-shot.
type rawIPRecvFrom struct {
	c            *net.IPConn
	peer         *net.IPAddr
	first        []byte
	firstPending bool
	closeEOF     bool
	wantCtrl     bool
	v4           bool
	g            *xio.Global
	oob          []byte
}

func (r *rawIPRecvFrom) Read(p []byte) (int, error) {
	if r.firstPending {
		r.firstPending = false
		n := copy(p, r.first)
		r.first = nil
		return n, nil
	}
	if r.closeEOF {
		return 0, io.EOF
	}
	for {
		n, oob, addr, err := ReadIPMsgWithBuffer(r.c, p, r.wantCtrl, r.v4, ancillaryBuffer(&r.oob, r.wantCtrl))
		if err != nil {
			return n, err
		}
		if r.peer != nil {
			if ia, ok := addr.(*net.IPAddr); ok && !ia.IP.Equal(r.peer.IP) {
				continue
			}
		}
		if r.wantCtrl {
			xio.ProcessAncillary(oob, r.g)
		}
		return n, nil
	}
}

func (r *rawIPRecvFrom) Write(p []byte) (int, error) {
	if r.peer == nil {
		return 0, net.ErrClosed
	}
	return r.c.WriteToIP(p, r.peer)
}

func (r *rawIPRecvFrom) Close() error         { return r.c.Close() }
func (r *rawIPRecvFrom) ShutdownWrite() error { return nil }
func (r *rawIPRecvFrom) LocalAddr() net.Addr  { return r.c.LocalAddr() }
func (r *rawIPRecvFrom) RemoteAddr() net.Addr { return r.peer }
func (r *rawIPRecvFrom) SetDeadline(t time.Time) error {
	return r.c.SetDeadline(t)
}
func (r *rawIPRecvFrom) SetReadDeadline(t time.Time) error {
	return r.c.SetReadDeadline(t)
}
func (r *rawIPRecvFrom) SetWriteDeadline(t time.Time) error {
	return r.c.SetWriteDeadline(t)
}

// NetConn exposes the socket to xio's option lifecycle without making this
// pre-buffered stream a syscall.Conn. The relay must consume first before it
// polls the underlying socket, which is no longer readable after the opener's
// initial recvfrom.
func (r *rawIPRecvFrom) NetConn() net.Conn { return r.c }

// rawIPFilteredRecv: continuous RECV with peer filters + ancillary.
type rawIPFilteredRecv struct {
	c        *net.IPConn
	filter   *xio.PeerFilter
	g        *xio.Global
	ctx      context.Context
	wantCtrl bool
	v4       bool
	oob      []byte
}

func (r *rawIPFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := ReadIPMsgWithBuffer(r.c, p, r.wantCtrl, r.v4, ancillaryBuffer(&r.oob, r.wantCtrl))
		if err != nil {
			return n, err
		}
		if err := r.filter.AllowAddr(addr, r.c.LocalAddr()); err != nil {
			if stop := logOrStopPeerFilter(r.ctx, r.g, err); stop != nil {
				return 0, stop
			}
			continue
		}
		if r.wantCtrl {
			xio.ProcessAncillary(oob, r.g)
		}
		return n, nil
	}
}

func (r *rawIPFilteredRecv) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (r *rawIPFilteredRecv) Close() error              { return r.c.Close() }
func (r *rawIPFilteredRecv) ShutdownWrite() error      { return nil }
func (r *rawIPFilteredRecv) LocalAddr() net.Addr       { return r.c.LocalAddr() }
func (r *rawIPFilteredRecv) RemoteAddr() net.Addr      { return nil }
func (r *rawIPFilteredRecv) SyscallConn() (syscall.RawConn, error) {
	return r.c.SyscallConn()
}

func cloneIPAddr(a *net.IPAddr) *net.IPAddr {
	if a == nil {
		return nil
	}
	c := *a
	if a.IP != nil {
		c.IP = append(net.IP(nil), a.IP...)
	}
	return &c
}

func ipAddrFromNet(addr net.Addr) *net.IPAddr {
	switch a := addr.(type) {
	case *net.IPAddr:
		return cloneIPAddr(a)
	case *net.UDPAddr:
		if a == nil {
			return nil
		}
		ip := append(net.IP(nil), a.IP...)
		return &net.IPAddr{IP: ip, Zone: a.Zone}
	default:
		return nil
	}
}

func rememberRawIPPeer(g *xio.Global, peer *net.IPAddr, local net.Addr) {
	if g == nil {
		return
	}
	if peer != nil && peer.IP != nil {
		g.PeerAddr = xio.FormatSocatAddr(peer.IP.String())
		g.PeerPort = ""
	}
	if local == nil {
		return
	}
	if ia, ok := local.(*net.IPAddr); ok && ia.IP != nil {
		g.SockAddr = xio.FormatSocatAddr(ia.IP.String())
		return
	}
	if host, _, err := net.SplitHostPort(local.String()); err == nil {
		g.SockAddr = xio.FormatSocatAddr(host)
	}
}

// rawIPForkListener is IP*-RECVFROM,fork: one session per permitted datagram.
type rawIPForkListener struct {
	pc         *net.IPConn
	spec       parse.Spec
	g          *xio.Global
	ctx        context.Context
	filter     *xio.PeerFilter
	rcvTimeout time.Duration
	writeMu    sync.Mutex
	v4         bool
}

func (l *rawIPForkListener) Addr() net.Addr { return l.pc.LocalAddr() }

func (l *rawIPForkListener) Close() error {
	if l.pc == nil {
		return nil
	}
	return l.pc.Close()
}

func (l *rawIPForkListener) Accept() (net.Conn, error) {
	buf := make([]byte, 65535)
	wantCtrl := xio.NeedAncillary(l.spec)
	var oobBuffer [xio.AncillaryBufferSize]byte
	ctx := l.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	for {
		if l.rcvTimeout > 0 {
			_ = l.pc.SetReadDeadline(time.Now().Add(l.rcvTimeout))
		}
		rn, oob, a, err := xio.RecvOneCtx(ctx, func() (int, []byte, net.Addr, error) {
			return ReadIPMsgWithBuffer(l.pc, buf, wantCtrl, l.v4, oobBuffer[:])
		})
		if err != nil {
			if l.ctx != nil && l.ctx.Err() != nil {
				return nil, err
			}
			if l.rcvTimeout > 0 && xio.IsTimeoutErr(err) {
				continue
			}
			return nil, err
		}
		if err := l.filter.AllowAddr(a, l.pc.LocalAddr()); err != nil {
			if stop := logOrStopPeerFilter(ctx, l.g, err); stop != nil {
				return nil, stop
			}
			continue
		}
		session := &xio.Global{}
		if l.g != nil {
			session.Log = l.g.Log
			session.Progname = l.g.Progname
		}
		xio.ProcessAncillary(oob, session)
		peer := ipAddrFromNet(a)
		rememberRawIPPeer(session, peer, l.pc.LocalAddr())
		return &rawIPSessionConn{
			pc:           l.pc,
			peer:         peer,
			first:        append([]byte(nil), buf[:rn]...),
			firstPending: true,
			env:          session.SessionVars,
			writeMu:      &l.writeMu,
		}, nil
	}
}

// rawIPSessionConn is one IP-RECVFROM,fork datagram: drain first, then EOF,
// and reply with WriteToIP. The parent owns the listen socket.
type rawIPSessionConn struct {
	pc            *net.IPConn
	peer          *net.IPAddr
	first         []byte
	firstPending  bool
	env           map[string]string
	writeMu       *sync.Mutex
	deadlineMu    sync.Mutex
	writeDeadline time.Time
}

func (r *rawIPSessionConn) SessionEnvironment() map[string]string { return r.env }

func (r *rawIPSessionConn) Read(p []byte) (int, error) {
	if r.firstPending {
		r.firstPending = false
		n := copy(p, r.first)
		r.first = nil
		return n, nil
	}
	return 0, io.EOF
}

func (r *rawIPSessionConn) Write(p []byte) (int, error) {
	if r.pc == nil || r.peer == nil {
		return 0, net.ErrClosed
	}
	r.deadlineMu.Lock()
	deadline := r.writeDeadline
	r.deadlineMu.Unlock()
	return writeSharedPacket(r.writeMu, deadline, r.pc.SetWriteDeadline, func() (int, error) {
		return r.pc.WriteToIP(p, r.peer)
	})
}

func (r *rawIPSessionConn) Close() error { return nil }

func (r *rawIPSessionConn) LocalAddr() net.Addr  { return r.pc.LocalAddr() }
func (r *rawIPSessionConn) RemoteAddr() net.Addr { return r.peer }
func (r *rawIPSessionConn) SetDeadline(t time.Time) error {
	return r.SetWriteDeadline(t)
}
func (r *rawIPSessionConn) SetReadDeadline(time.Time) error { return nil }
func (r *rawIPSessionConn) SetWriteDeadline(t time.Time) error {
	r.deadlineMu.Lock()
	r.writeDeadline = t
	r.deadlineMu.Unlock()
	return nil
}
