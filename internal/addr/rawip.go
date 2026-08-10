package addr

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"golang.org/x/sys/unix"
)

// Raw IP (SOCK_RAW) addresses — classic IP4/IP6-SENDTO/RECV/RECVFROM.
// Requires CAP_NET_RAW (root). Used by ancillary SCM/ENV tests with KEYW=IP4/IP6.

func openIPSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, networkIP(g, s, "ip4"))
}
func openIP4Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip4")
}
func openIP6Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip6")
}

// IP*-DATAGRAM is unconnected (classic sendto/recvfrom), not DialIP.
// Required for broadcast/multicast and for bind= to a local addr with a remote host.
func openIPDatagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, networkIP(g, s, "ip4"))
}
func openIP4Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, "ip4")
}
func openIP6Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPDatagramNetwork(ctx, s, mode, g, "ip6")
}

func openIPRecv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, networkIP(g, s, "ip4"), false)
}
func openIP4Recv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip4", false)
}
func openIP6Recv(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip6", false)
}

func openIPRecvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, networkIP(g, s, "ip4"), true)
}
func openIP4Recvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip4", true)
}
func openIP6Recvfrom(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPRecvNetwork(ctx, s, mode, g, "ip6", true)
}

// Classic bare IP:host:proto — family from pf=, host address, or global -4/-6.
func openIP(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	netw := networkIPFromHost(g, s, "ip4")
	return openIPSendtoNetwork(ctx, s, mode, g, netw)
}
func openIP4(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip4")
}
func openIP6(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip6")
}

func networkIP(g *Global, s parse.Spec, def string) string {
	if s.HasOption("pf") {
		v := s.OptionValue("pf", "")
		switch v {
		case "ip6", "6", "ipv6":
			return "ip6"
		case "ip4", "4", "ipv4":
			return "ip4"
		}
	}
	if g != nil {
		switch g.IPVersion {
		case IPv6:
			return "ip6"
		case IPv4:
			return "ip4"
		}
	}
	return def
}

// networkIPFromHost prefers an explicit IPv6 host (e.g. IP:[::1]:proto).
func networkIPFromHost(g *Global, s parse.Spec, def string) string {
	if s.HasOption("pf") {
		return networkIP(g, s, def)
	}
	if len(s.Params) >= 1 {
		host := stripBrackets(s.Params[0])
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() == nil {
				return "ip6"
			}
			return "ip4"
		}
	}
	return networkIP(g, s, def)
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

func openIPSendtoNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	// IP4-SENDTO:host:proto
	if len(s.Params) < 2 {
		return nil, fmt.Errorf("%s: requires host:protocol", s.Type)
	}
	host := stripBrackets(s.Params[0])
	proto, err := parseProtoParam(s, 1)
	if err != nil {
		return nil, err
	}
	raddr := &net.IPAddr{IP: net.ParseIP(host)}
	if raddr.IP == nil {
		// resolve name
		ips, err := net.DefaultResolver.LookupIP(ctx, ipLookupNet(network), host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%s: resolve %q: %w", s.Type, host, err)
		}
		raddr.IP = ips[0]
	}
	var laddr *net.IPAddr
	if bind := s.OptionValue("bind", ""); bind != "" {
		lip := net.ParseIP(stripBrackets(bind))
		if lip == nil {
			return nil, fmt.Errorf("%s: bad bind %q", s.Type, bind)
		}
		laddr = &net.IPAddr{IP: lip}
	}
	// Enforce family match for explicit IP4/IP6 types.
	if network == "ip4" && raddr.IP.To4() == nil {
		return nil, fmt.Errorf("%s: address %s: non-IPv4 address", s.Type, host)
	}
	if network == "ip6" && raddr.IP.To4() != nil {
		return nil, fmt.Errorf("%s: address %s: non-IPv6 address", s.Type, host)
	}
	netw := ipNetwork(network, proto)
	c, err := net.DialIP(netw, laddr, raddr)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(c, s, network); err != nil {
		c.Close()
		return nil, err
	}
	// Connected IPv4 Read() keeps the IP header; strip for classic parity.
	v4 := network == "ip4" || raddr.IP.To4() != nil
	st := relay.Stream(&rawIPConn{IPConn: c, peer: raddr, v4: v4})
	st, err = wrapCommon(s, st)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &Opened{Stream: st, Label: s.Type + ":" + host + ":" + strconv.Itoa(proto)}, nil
}

// openIPDatagramNetwork: unconnected SOCK_RAW for IP*-DATAGRAM (broadcast/multicast).
func openIPDatagramNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	if len(s.Params) < 2 {
		return nil, fmt.Errorf("%s: requires host:protocol", s.Type)
	}
	host := stripBrackets(s.Params[0])
	proto, err := parseProtoParam(s, 1)
	if err != nil {
		return nil, err
	}
	raddr := &net.IPAddr{IP: net.ParseIP(host)}
	if raddr.IP == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, ipLookupNet(network), host)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%s: resolve %q: %w", s.Type, host, err)
		}
		raddr.IP = ips[0]
	}
	if network == "ip4" && raddr.IP.To4() == nil {
		return nil, fmt.Errorf("%s: address %s: non-IPv4 address", s.Type, host)
	}
	if network == "ip6" && raddr.IP.To4() != nil {
		return nil, fmt.Errorf("%s: address %s: non-IPv6 address", s.Type, host)
	}
	laddr := &net.IPAddr{IP: net.IPv4zero}
	if network == "ip6" {
		laddr = &net.IPAddr{IP: net.IPv6zero}
	}
	if bind := s.OptionValue("bind", ""); bind != "" {
		lip := net.ParseIP(stripBrackets(bind))
		if lip == nil {
			return nil, fmt.Errorf("%s: bad bind %q", s.Type, bind)
		}
		laddr = &net.IPAddr{IP: lip}
	}
	netw := ipNetwork(network, proto)
	pc, err := net.ListenIP(netw, laddr)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(pc, s, network); err != nil {
		pc.Close()
		return nil, err
	}
	v4 := network == "ip4" || raddr.IP.To4() != nil
	st := relay.Stream(&rawIPDatagramConn{c: pc, raddr: raddr, v4: v4})
	st, err = wrapCommon(s, st)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Opened{Stream: st, Label: s.Type + ":" + host + ":" + strconv.Itoa(proto)}, nil
}

func openIPRecvNetwork(ctx context.Context, s parse.Spec, mode Mode, g *Global, network string, recvfrom bool) (*Opened, error) {
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
		lip := net.ParseIP(stripBrackets(bind))
		if lip == nil {
			return nil, fmt.Errorf("%s: bad bind %q", s.Type, bind)
		}
		laddr = &net.IPAddr{IP: lip}
	}
	netw := ipNetwork(network, proto)
	pc, err := net.ListenIP(netw, laddr)
	if err != nil {
		return nil, err
	}
	if err := applyIPConnOpts(pc, s, network); err != nil {
		pc.Close()
		return nil, err
	}

	wantCtrl := needAncillary(s)
	if recvfrom {
		// One packet then connected-style session (classic RECVFROM).
		buf := make([]byte, max(g.BlockSize, 65535))
		type res struct {
			n   int
			a   net.Addr
			oob []byte
			e   error
		}
		var n int
		var raddr net.Addr
		for {
			ch := make(chan res, 1)
			stripV4 := network == "ip4"
			go func() {
				nn, oob, a, err := readIPMsg(pc, buf, wantCtrl, stripV4)
				ch <- res{nn, a, oob, err}
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
				// peer filter uses UDP-style helper via fake addr when possible
				if ia, ok := r.a.(*net.IPAddr); ok {
					if err := peerAllowedG(s, &udpPeerConn{addr: &net.UDPAddr{IP: ia.IP}}, g); err != nil {
						if g != nil && g.Log != nil {
							g.Log.Noticef("%s", err)
						}
						continue
					}
				}
				n, raddr = r.n, r.a
				processAncillary(r.oob, g)
			}
			break
		}
		peerIP := (*net.IPAddr)(nil)
		if ia, ok := raddr.(*net.IPAddr); ok {
			peerIP = ia
		}
		st := relay.Stream(&rawIPRecvFrom{
			c:        pc,
			peer:     peerIP,
			first:    append([]byte(nil), buf[:n]...),
			// Keep socket open for reply writes (RECVFROM|PIPE echo); further
			// reads return EOF after the first datagram (classic one-shot).
			closeEOF: true,
			wantCtrl: wantCtrl,
			v4:       network == "ip4",
			g:        g,
		})
		st, err = wrapCommon(s, st)
		if err != nil {
			pc.Close()
			return nil, err
		}
		return &Opened{Stream: st, Label: s.Type}, nil
	}

	// RECV: merge packets, read-only
	if mode == ModeWrite {
		pc.Close()
		return nil, fmt.Errorf("%s is read-only", s.Type)
	}
	st := relay.Stream(&rawIPFilteredRecv{
		c:        pc,
		spec:     s,
		g:        g,
		wantCtrl: wantCtrl,
		v4:       network == "ip4",
	})
	st, err = wrapCommon(s, st)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Opened{Stream: st, Label: s.Type}, nil
}

func ipLookupNet(network string) string {
	if network == "ip6" {
		return "ip6"
	}
	return "ip4"
}

// applyIPConnOpts sets ancillary recv, send IP options, broadcast, and multicast join.
func applyIPConnOpts(c *net.IPConn, s parse.Spec, network string) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	if err := raw.Control(func(fd uintptr) {
		applyAncillaryRecvOpts(int(fd), s)
		applyIPSendOpts(int(fd), s, network)
		// classic often sets reuse on raw too
		if s.BoolOption("reuseaddr") || s.HasOption("reuseaddr") {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
		if s.BoolOption("broadcast") || s.HasOption("broadcast") {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
		}
	}); err != nil {
		return err
	}
	// Multicast join (IP4MULTICAST_* classic tests).
	if v := s.OptionValue("ip-add-membership", ""); v != "" {
		if err := joinMulticastIP(c, network, v); err != nil {
			return err
		}
	}
	return nil
}

// joinMulticastIP is like joinMulticast for *net.IPConn (raw IP).
func joinMulticastIP(c *net.IPConn, network, spec string) error {
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
	iface = strings.TrimSpace(iface)
	var ifi *net.Interface
	if ip := net.ParseIP(iface); ip != nil {
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
		if gip.To4() != nil && ip.To4() != nil {
			return setIPv4MembershipRaw(c, gip.To4(), ip.To4())
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
		return setIPv4MembershipRaw(c, gip.To4(), ifaceIP)
	}
	return setIPv6MembershipRaw(c, gip, ifi)
}

func setIPv4MembershipRaw(c *net.IPConn, group, ifaceIP net.IP) error {
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

func setIPv6MembershipRaw(c *net.IPConn, group net.IP, ifi *net.Interface) error {
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

func readIPMsg(c *net.IPConn, p []byte, wantCtrl bool, stripV4 bool) (n int, oob []byte, addr net.Addr, err error) {
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
	// ReadMsgIP returns the full IPv4 packet (header + payload). Classic
	// XIODATA_RECV_SKIPIP strips the header so user data starts at payload.
	oob = make([]byte, 1024)
	var oobn int
	n, oobn, _, addr, err = c.ReadMsgIP(p, oob)
	if err != nil {
		return n, nil, nil, err
	}
	if stripV4 {
		n = skipIPv4HeaderIfPresent(p, n)
	}
	return n, oob[:oobn], addr, nil
}

// skipIPv4HeaderIfPresent drops a leading IPv4 header when the buffer looks like
// a complete IP packet (classic RECV_SKIPIP). Connected IPConn.Read() on Linux
// returns header+payload; unconnected ReadFrom often returns payload only.
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
type rawIPDatagramConn struct {
	c     *net.IPConn
	raddr *net.IPAddr
	v4    bool
}

func (r *rawIPDatagramConn) Read(p []byte) (int, error) {
	n, _, err := r.c.ReadFrom(p)
	if err != nil {
		return n, err
	}
	if r.v4 {
		n = skipIPv4HeaderIfPresent(p, n)
	}
	return n, nil
}

func (r *rawIPDatagramConn) Write(p []byte) (int, error) {
	return r.c.WriteToIP(p, r.raddr)
}

func (r *rawIPDatagramConn) Close() error         { return r.c.Close() }
func (r *rawIPDatagramConn) ShutdownWrite() error { return nil }
func (r *rawIPDatagramConn) LocalAddr() net.Addr  { return r.c.LocalAddr() }
func (r *rawIPDatagramConn) RemoteAddr() net.Addr { return r.raddr }

// rawIPConn: sendto-style connected IPConn (SELF echo, SENDTO client).
// Do not embed Read from *net.IPConn — connected Read keeps the IPv4 header.
type rawIPConn struct {
	*net.IPConn
	peer *net.IPAddr
	v4   bool
}

func (r *rawIPConn) Read(p []byte) (int, error) {
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
	c        *net.IPConn
	peer     *net.IPAddr
	first    []byte
	closeEOF bool
	wantCtrl bool
	v4       bool
	g        *Global
}

func (r *rawIPRecvFrom) Read(p []byte) (int, error) {
	if len(r.first) > 0 {
		n := copy(p, r.first)
		r.first = r.first[n:]
		return n, nil
	}
	if r.closeEOF {
		return 0, io.EOF
	}
	for {
		n, oob, addr, err := readIPMsg(r.c, p, r.wantCtrl, r.v4)
		if err != nil {
			return n, err
		}
		if r.peer != nil {
			if ia, ok := addr.(*net.IPAddr); ok && !ia.IP.Equal(r.peer.IP) {
				continue
			}
		}
		if r.wantCtrl {
			processAncillary(oob, r.g)
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

func (r *rawIPRecvFrom) Close() error              { return r.c.Close() }
func (r *rawIPRecvFrom) ShutdownWrite() error      { return nil }
func (r *rawIPRecvFrom) LocalAddr() net.Addr       { return r.c.LocalAddr() }
func (r *rawIPRecvFrom) RemoteAddr() net.Addr      { return r.peer }
func (r *rawIPRecvFrom) SetDeadline(t time.Time) error {
	return r.c.SetDeadline(t)
}
func (r *rawIPRecvFrom) SetReadDeadline(t time.Time) error {
	return r.c.SetReadDeadline(t)
}
func (r *rawIPRecvFrom) SetWriteDeadline(t time.Time) error {
	return r.c.SetWriteDeadline(t)
}

// rawIPFilteredRecv: continuous RECV with peer filters + ancillary.
type rawIPFilteredRecv struct {
	c        *net.IPConn
	spec     parse.Spec
	g        *Global
	wantCtrl bool
	v4       bool
}

func (r *rawIPFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := readIPMsg(r.c, p, r.wantCtrl, r.v4)
		if err != nil {
			return n, err
		}
		if ia, ok := addr.(*net.IPAddr); ok {
			if err := peerAllowedG(r.spec, &udpPeerConn{addr: &net.UDPAddr{IP: ia.IP}}, r.g); err != nil {
				if r.g != nil && r.g.Log != nil {
					r.g.Log.Noticef("%s", err)
				}
				continue
			}
		}
		if r.wantCtrl {
			processAncillary(oob, r.g)
		}
		return n, nil
	}
}

func (r *rawIPFilteredRecv) Write([]byte) (int, error) { return 0, net.ErrClosed }
func (r *rawIPFilteredRecv) Close() error              { return r.c.Close() }
func (r *rawIPFilteredRecv) ShutdownWrite() error      { return nil }
func (r *rawIPFilteredRecv) LocalAddr() net.Addr       { return r.c.LocalAddr() }
func (r *rawIPFilteredRecv) RemoteAddr() net.Addr      { return nil }
