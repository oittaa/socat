package addr

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openTCPConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, networkTCP(g, s, ""))
}

func openTCP4Connect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Connect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp6")
}

func openTCPConnectNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	host, port, err := hostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	addr := net.JoinHostPort(stripBrackets(host), port)

	timeout := connectTimeout(s)
	dialer := &net.Dialer{Timeout: timeout}
	if bind := s.OptionValue("bind", ""); bind != "" {
		ba, err := net.ResolveTCPAddr(network, bindPort(bind, s.OptionValue("sourceport", "0")))
		if err != nil {
			return nil, fmt.Errorf("bind: %w", err)
		}
		dialer.LocalAddr = ba
	}

	dctx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		dctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := dialer.DialContext(dctx, network, addr)
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if s.BoolOption("nodelay") {
			_ = tc.SetNoDelay(true)
		}
		if s.BoolOption("keepalive") || s.HasOption("keepidle") {
			_ = tc.SetKeepAlive(true)
		}
	}
	g.Log.Infof("successfully connected from %s to %s", conn.LocalAddr(), conn.RemoteAddr())
	return &Opened{
		Stream: relay.NetStream{Conn: conn},
		Label:  fmt.Sprintf("%s:%s", network, addr),
	}, nil
}

func openTCPListen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, networkTCP(g, s, "tcp"))
}

func openTCP4Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp6")
}

func openTCPListenNetwork(ctx context.Context, s parse.Spec, _ Mode, g *Global, network string) (*Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	// Reject non-numeric/service empties used by test.sh probes (TYPE:::::)
	if port == "" || strings.Trim(port, ":") == "" {
		return nil, fmt.Errorf("%s: invalid port %q", s.Type, port)
	}
	host := s.OptionValue("bind", "")
	if host == "" {
		switch network {
		case "tcp4":
			host = "0.0.0.0"
		case "tcp6":
			host = "::"
		default:
			host = ""
		}
	}
	addr := net.JoinHostPort(stripBrackets(host), port)

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if s.BoolOption("reuseaddr") {
				return c.Control(func(fd uintptr) {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				})
			}
			return nil
		},
	}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	fork := s.BoolOption("fork")
	o := &Opened{
		Listener: ln,
		Fork:     fork,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port),
	}
	o.addCleanup(func() { ln.Close() })

	if fork {
		// Parent keeps listening; Run handles accept loop.
		return o, nil
	}

	// Non-fork: accept one connection (blocking)
	if at := acceptTimeout(s); at > 0 {
		if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
			_ = dl.SetDeadline(time.Now().Add(at))
		}
	}
	g.Log.Noticef("listening on %s", ln.Addr())
	conn, err := ln.Accept()
	if err != nil {
		ln.Close()
		return nil, err
	}
	ln.Close()
	o.Listener = nil
	g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	o.Stream = relay.NetStream{Conn: conn}
	return o, nil
}

func networkTCP(g *Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch strings.ToLower(pf) {
		case "ip4", "ipv4", "inet":
			return "tcp4"
		case "ip6", "ipv6", "inet6":
			return "tcp6"
		}
	}
	switch g.IPVersion {
	case IPv4:
		return "tcp4"
	case IPv6:
		return "tcp6"
	case IPvAny:
		return "tcp"
	default:
		if def != "" {
			return def
		}
		return "tcp4" // classic default since 1.8.0.1
	}
}

func hostPortParams(s parse.Spec) (host, port string, err error) {
	if len(s.Params) < 2 {
		// Maybe host:port as one param was split wrong, or combined
		if len(s.Params) == 1 {
			h, p, e := net.SplitHostPort(s.Params[0])
			if e == nil {
				return h, p, nil
			}
		}
		return "", "", fmt.Errorf("%s requires host and port", s.Type)
	}
	return s.Params[0], s.Params[1], nil
}

func stripBrackets(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

func bindPort(bind, sourceport string) string {
	if strings.Contains(bind, ":") {
		// might already be host:port or [ipv6]:port
		if _, _, err := net.SplitHostPort(bind); err == nil {
			return bind
		}
	}
	return net.JoinHostPort(stripBrackets(bind), sourceport)
}

func connectTimeout(s parse.Spec) time.Duration {
	v := s.OptionValue("connect-timeout", "")
	if v == "" {
		return 0
	}
	return parseTimeval(v)
}

func acceptTimeout(s parse.Spec) time.Duration {
	v := s.OptionValue("accept-timeout", "")
	if v == "" {
		return 0
	}
	return parseTimeval(v)
}

func parseTimeval(v string) time.Duration {
	// classic timeval: seconds with optional fractional part
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		d, err2 := time.ParseDuration(v)
		if err2 != nil {
			return 0
		}
		return d
	}
	return time.Duration(f * float64(time.Second))
}
