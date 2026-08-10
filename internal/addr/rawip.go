package addr

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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

func openIPDatagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, networkIP(g, s, "ip4"))
}
func openIP4Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip4")
}
func openIP6Datagram(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openIPSendtoNetwork(ctx, s, mode, g, "ip6")
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

// Classic also uses bare IP4/IP6 as sendto-style to host:proto.
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
	netw := ipNetwork(network, proto)
	c, err := net.DialIP(netw, laddr, raddr)
	if err != nil {
		return nil, err
	}
	applyIPConnOpts(c, s, network)
	st := relay.Stream(&rawIPConn{IPConn: c, peer: raddr, oneShot: false})
	st, err = wrapCommon(s, st)
	if err != nil {
		c.Close()
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
	applyIPConnOpts(pc, s, network)

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
			go func() {
				nn, oob, a, err := readIPMsg(pc, buf, wantCtrl)
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
					if err := peerAllowed(s, &udpPeerConn{addr: &net.UDPAddr{IP: ia.IP}}); err != nil {
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
			closeEOF: true,
			wantCtrl: wantCtrl,
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

// applyIPConnOpts sets ancillary recv + send IP options on a raw *net.IPConn.
func applyIPConnOpts(c *net.IPConn, s parse.Spec, network string) {
	raw, err := c.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		applyAncillaryRecvOpts(int(fd), s)
		applyIPSendOpts(int(fd), s, network)
		// classic often sets reuse on raw too
		if s.BoolOption("reuseaddr") || s.HasOption("reuseaddr") {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		}
	})
}

func readIPMsg(c *net.IPConn, p []byte, wantCtrl bool) (n int, oob []byte, addr net.Addr, err error) {
	if !wantCtrl {
		n, addr, err = c.ReadFrom(p)
		// Go's ReadFrom already strips IPv4 header on Linux; keep as-is.
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
	n = skipIPv4Header(p, n)
	return n, oob[:oobn], addr, nil
}

// skipIPv4Header drops the IP header when present (classic RECV_SKIPIP).
func skipIPv4Header(p []byte, n int) int {
	if n < 20 {
		return n
	}
	// IPv4: version nibble == 4
	if p[0]>>4 != 4 {
		return n
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || ihl > n {
		return n
	}
	copy(p, p[ihl:n])
	return n - ihl
}

// rawIPConn: sendto-style connected IPConn.
type rawIPConn struct {
	*net.IPConn
	peer    *net.IPAddr
	oneShot bool
}

func (r *rawIPConn) ShutdownWrite() error { return nil }

// rawIPRecvFrom: first datagram buffered; further reads EOF when one-shot.
type rawIPRecvFrom struct {
	c        *net.IPConn
	peer     *net.IPAddr
	first    []byte
	closeEOF bool
	wantCtrl bool
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
		n, oob, addr, err := readIPMsg(r.c, p, r.wantCtrl)
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
}

func (r *rawIPFilteredRecv) Read(p []byte) (int, error) {
	for {
		n, oob, addr, err := readIPMsg(r.c, p, r.wantCtrl)
		if err != nil {
			return n, err
		}
		if ia, ok := addr.(*net.IPAddr); ok {
			if err := peerAllowed(r.spec, &udpPeerConn{addr: &net.UDPAddr{IP: ia.IP}}); err != nil {
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
