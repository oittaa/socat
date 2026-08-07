package addr

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
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
	// Wait for first permitted packet, then dial a connected UDP socket back.
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
			// Temporary conn for peer filter (range/sourceport/lowport).
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
	local := pc.LocalAddr().(*net.UDPAddr)
	pc.Close()
	conn, err := net.DialUDP(network, local, raddr)
	if err != nil {
		return nil, err
	}
	return &Opened{
		Stream: &udpFirstPacket{UDPConn: conn, first: append([]byte(nil), buf[:n]...)},
		Label:  "UDP-LISTEN",
	}, nil
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

type udpFirstPacket struct {
	*net.UDPConn
	first []byte
	got   bool
}

func (u *udpFirstPacket) Read(p []byte) (int, error) {
	if !u.got && len(u.first) > 0 {
		u.got = true
		n := copy(p, u.first)
		if n < len(u.first) {
			u.first = u.first[n:]
			u.got = false
		}
		return n, nil
	}
	return u.UDPConn.Read(p)
}

func (u *udpFirstPacket) ShutdownWrite() error { return nil }

func openUDPSendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDPConnect(ctx, s, mode, g)
}
func openUDP4Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDP4Connect(ctx, s, mode, g)
}
func openUDP6Sendto(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openUDP6Connect(ctx, s, mode, g)
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
	sp := s.OptionValue("sourceport", "0")
	var laddr *net.UDPAddr
	if bind != "" || sp != "0" {
		if bind == "" {
			if network == "udp6" {
				bind = "::"
			} else {
				bind = "0.0.0.0"
			}
		}
		laddr, err = net.ResolveUDPAddr(network, bindPort(bind, sp))
		if err != nil {
			return nil, err
		}
	}
	c, err := net.ListenUDP(network, laddr)
	if err != nil {
		return nil, err
	}
	if s.BoolOption("broadcast") {
		// SO_BROADCAST
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
	_ = ctx
	_ = g
	return &Opened{Stream: wrapped, Label: "UDP-DATAGRAM:" + raddr.String()}, nil
}

// udpDatagramConn writes always to raddr; reads from anyone (optional filter later).
type udpDatagramConn struct {
	*net.UDPConn
	raddr *net.UDPAddr
}

func (u *udpDatagramConn) Write(p []byte) (int, error) {
	return u.UDPConn.WriteToUDP(p, u.raddr)
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
		// one permitted packet, then reply to sender — honour ctx so SIGTERM unblocks.
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
		conn, err := net.DialUDP(network, laddr, raddr)
		pc.Close()
		if err != nil {
			return nil, err
		}
		return &Opened{
			Stream: &udpFirstPacket{UDPConn: conn, first: append([]byte(nil), buf[:n]...)},
			Label:  "UDP-RECVFROM",
		}, nil
	}
	// RECV: merge all packets, read-only, with peer filters.
	if mode == ModeWrite {
		pc.Close()
		return nil, fmt.Errorf("UDP-RECV is read-only")
	}
	return &Opened{
		Stream: &udpFilteredRecv{conn: pc, spec: s, log: g},
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
	cfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if s.BoolOption("reuseaddr") {
				return c.Control(func(fd uintptr) {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				})
			}
			return nil
		},
	}
	pc, err := cfg.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}
	return pc.(*net.UDPConn), nil
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
