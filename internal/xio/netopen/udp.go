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
	bind := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	lowport := s.BoolOption("lowport") && (sp == "" || sp == "0")
	var conn net.Conn
	if lowport {
		bind, err = xio.BindHostForListen(network, bind)
		if err != nil {
			return nil, err
		}
		conn, err = dialUDPLowport(ctx, network, bind, addr, s, g)
	} else {
		d := net.Dialer{
			Timeout: xio.ConnectTimeout(s),
			Control: xio.DialControl(s, network, nil),
		}
		if bind != "" || sp != "" {
			bind, err = xio.BindHostForListen(network, bind)
			if err != nil {
				return nil, err
			}
			if sp == "" {
				sp = "0"
			}
			ba, resolveErr := net.ResolveUDPAddr(network, xio.BindPort(bind, sp))
			if resolveErr != nil {
				return nil, resolveErr
			}
			d.LocalAddr = ba
		}
		conn, err = d.DialContext(ctx, network, addr)
	}
	if err != nil {
		return nil, err
	}
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		logx.CloseQuiet(conn)
		return nil, fmt.Errorf("UDP: unexpected connection type %T", conn)
	}
	if err := xio.ApplyUDPConnOpts(udpConn, s, network); err != nil {
		logx.CloseQuiet(conn)
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

func dialUDPLowport(ctx context.Context, network, bind, remote string, s parse.Spec, g *xio.Global) (net.Conn, error) {
	var conn net.Conn
	_, err := xio.FirstAvailableLowport(func(port int) error {
		if g != nil && g.Log != nil {
			g.Log.Debugf("bind(%s:%d)", bind, port)
		}
		laddr, err := net.ResolveUDPAddr(network, xio.BindPort(bind, fmt.Sprintf("%d", port)))
		if err != nil {
			return err
		}
		d := net.Dialer{
			Timeout:   xio.ConnectTimeout(s),
			LocalAddr: laddr,
			Control:   xio.DialControl(s, network, nil),
		}
		conn, err = d.DialContext(ctx, network, remote)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("lowport: cannot bind a port in %d-%d: %w", xio.LowportMin, xio.LowportMax, err)
	}
	return conn, nil
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
