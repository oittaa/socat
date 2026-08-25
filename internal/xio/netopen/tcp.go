package netopen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openTCPConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	host := ""
	if len(s.Params) >= 1 {
		host = s.Params[0]
	}
	// Generic TCP: dual-stack resolve; -4/-6 only reorder (classic preference).
	return openTCPConnectNetwork(ctx, s, mode, g, xio.ConnectNetworkForType(g, s, host, "tcp"))
}

func openTCP4Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Connect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPConnectNetwork(ctx, s, mode, g, "tcp6")
}

func openTCPConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	// Honour pf= even when called from TCP4/TCP6 openers.
	network = xio.ConnectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	timeout := xio.ConnectTimeout(s)

	// Apply setsockopt before connect when possible via Control (level:opt:val).
	// Fail the open if setsockopt returns an error (classic SETSOCKOPT MSS=1).
	var setSockErr error
	var control func(network, address string, c syscall.RawConn) error
	if raw := s.OptionValue("setsockopt", ""); raw != "" {
		control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setSockErr = xio.ApplySetsockoptFD(int(fd), raw)
			})
		}
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, network+" connect", func() error {
			setSockErr = nil
			c, e := xio.DialTCPAll(dctx, network, xio.StripBrackets(host), port, s, g, timeout, control)
			if e != nil {
				return e
			}
			if setSockErr != nil {
				logx.CloseQuiet(c)
				return setSockErr
			}
			conn = c
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label: fmt.Sprintf("%s:%s", network, addr),
		Dial:  dialOnce,
		LogOK: true,
	})
}

func openTCPListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Classic precedence for listen address family:
	//   1) address option pf=
	//   2) explicit -4 / -6 / -0
	//   3) env SOCAT_DEFAULT_LISTEN_IP
	//   4) default IPv4
	netw := xio.ListenNetwork(g, s)
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Go's "tcp6" forces IPV6_V6ONLY=1 after our Control hook. For
	// ipv6-v6only=0 use dual-stack "tcp" on :: so IPv4 clients work.
	netw := "tcp6"
	if s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "tcp"
	}
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCPListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	// Reject non-numeric/service empties used by test.sh probes (TYPE:::::)
	if port == "" || strings.Trim(port, ":") == "" {
		return nil, fmt.Errorf("%s: invalid port %q", s.Type, port)
	}
	host := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if value := s.OptionValue("backlog", ""); value != "" {
		backlog, parseErr := xio.ParseIntAny(value)
		if parseErr != nil || backlog <= 0 {
			logx.CloseQuiet(ln)
			return nil, fmt.Errorf("backlog: invalid value %q", value)
		}
		if err := xio.ApplyListenBacklog(ln, backlog); err != nil {
			logx.CloseQuiet(ln)
			return nil, fmt.Errorf("backlog: %w", err)
		}
	}

	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener: ln,
		Label:    fmt.Sprintf("%s-LISTEN:%s", network, port),
		WrapDial: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapAccepted(s, c, func(c net.Conn) error {
				return xio.ApplyTCPConnOpts(s, c)
			})
		},
	})
}

// xio.ApplyTCPConnOpts sets classic TCP/socket options on an accepted or dialed conn.
