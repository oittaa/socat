package netopen

import (
	"context"
	"fmt"
	"net"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openUDPConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, NetworkUDP(g, s, "udp4"))
}
func openUDP4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp4")
}
func openUDP6Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openUDPConnectNetwork(ctx, s, mode, g, "udp6")
}

func openUDPConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)
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
		ba, err := net.ResolveUDPAddr(network, xio.BindPort(bind, sp))
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
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "UDP:" + addr}, nil
}

func NetworkUDP(g *xio.Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		if n := xio.NetworkFromPF(pf, "udp", ""); n != "" {
			return n
		}
	}
	ver := xio.IPv4Default
	if g != nil {
		ver = g.IPVersion
	}
	switch ver {
	case xio.IPv4:
		return "udp4"
	case xio.IPv6:
		return "udp6"
	case xio.IPvAny:
		return "udp"
	default:
		return def
	}
}
