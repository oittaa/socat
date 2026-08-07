package addr

import (
	"context"
	"fmt"
	"net"
	"syscall"

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
	addr := net.JoinHostPort(stripBrackets(host), port)
	var d net.Dialer
	if bind := s.OptionValue("bind", ""); bind != "" {
		ba, err := net.ResolveUDPAddr(network, bindPort(bind, s.OptionValue("sourceport", "0")))
		if err != nil {
			return nil, err
		}
		d.LocalAddr = ba
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &Opened{Stream: relay.NetStream{Conn: conn}, Label: "UDP:" + addr}, nil
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
	// Wait for first packet, then dial a connected UDP socket back to the sender.
	buf := make([]byte, max(g.BlockSize, 8192))
	n, raddr, err := pc.ReadFromUDP(buf)
	if err != nil {
		pc.Close()
		return nil, err
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
		// one packet, then reply to sender
		buf := make([]byte, max(g.BlockSize, 65535))
		n, raddr, err := pc.ReadFromUDP(buf)
		if err != nil {
			pc.Close()
			return nil, err
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
	// RECV: merge all packets, read-only
	if mode == ModeWrite {
		pc.Close()
		return nil, fmt.Errorf("UDP-RECV is read-only")
	}
	return &Opened{Stream: relay.NetStream{Conn: pc}, Label: "UDP-RECV"}, nil
}

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
