package addr

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func openTCPConnect(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	host := ""
	if len(s.Params) >= 1 {
		host = s.Params[0]
	}
	return openTCPConnectNetwork(ctx, s, mode, g, networkTCPForHost(g, s, host))
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
	bind := s.OptionValue("bind", "")
	sp := s.OptionValue("sourceport", "")
	if bind != "" || sp != "" {
		if bind == "" {
			if network == "tcp6" {
				bind = "::"
			} else {
				bind = "0.0.0.0"
			}
		}
		if sp == "" {
			sp = "0"
		}
		ba, err := net.ResolveTCPAddr(network, bindPort(bind, sp))
		if err != nil {
			return nil, fmt.Errorf("bind: %w", err)
		}
		dialer.LocalAddr = ba
	}

	var conn net.Conn
	err = withRetry(ctx, s, g, network+" connect", func() error {
		dctx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			dctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		c, e := dialer.DialContext(dctx, network, addr)
		if e != nil {
			return e
		}
		conn = c
		return nil
	})
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
	rememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &Opened{
		Stream: st,
		Label:  fmt.Sprintf("%s:%s", network, addr),
	}, nil
}

func openTCPListen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Classic precedence for listen address family:
	//   1) address option pf=
	//   2) explicit -4 / -6 / -0
	//   3) env SOCAT_DEFAULT_LISTEN_IP
	//   4) default IPv4
	netw := listenNetwork(g, s)
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func listenNetwork(g *Global, s parse.Spec) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch strings.ToLower(pf) {
		case "ip4", "ipv4", "inet", "4":
			return "tcp4"
		case "ip6", "ipv6", "inet6", "6":
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
	}
	// IPvDefault: honor listen env, else IPv4
	if v := strings.TrimSpace(os.Getenv("SOCAT_DEFAULT_LISTEN_IP")); v != "" {
		switch strings.ToLower(v) {
		case "4", "ip4", "ipv4":
			return "tcp4"
		case "6", "ip6", "ipv6":
			return "tcp6"
		}
	}
	return "tcp4"
}

func openTCP4Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s parse.Spec, mode Mode, g *Global) (*Opened, error) {
	// Go's "tcp6" forces IPV6_V6ONLY=1 after our Control hook. For
	// ipv6-v6only=0 use dual-stack "tcp" on :: so IPv4 clients work.
	netw := "tcp6"
	if s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "tcp"
	}
	return openTCPListenNetwork(ctx, s, mode, g, netw)
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
		case "tcp":
			// Dual-stack default bind
			host = "::"
		default:
			host = ""
		}
	}
	addr := net.JoinHostPort(stripBrackets(host), port)

	// Classic default: SO_REUSEADDR is on for listen unless reuseaddr=0.
	reuse := true
	if s.HasOption("reuseaddr") {
		reuse = s.BoolOption("reuseaddr")
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if reuse {
					_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				}
				// Must set before bind. For dual-stack (tcp / ipv6-v6only=0) clear V6ONLY.
				if network == "tcp" || network == "tcp6" {
					if s.HasOption("ipv6-v6only") {
						v := 0
						if s.BoolOption("ipv6-v6only") {
							v = 1
						}
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, v)
					} else if network == "tcp" {
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
					}
				}
			})
		},
	}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	fork := s.BoolOption("fork")
	filter := func(c net.Conn) error { return peerAllowed(s, c) }
	o := &Opened{
		Listener:   ln,
		Fork:       fork,
		Label:      fmt.Sprintf("%s-LISTEN:%s", network, port),
		PeerFilter: filter,
	}
	o.addCleanup(func() { ln.Close() })

	if fork {
		// Parent keeps listening; Run handles accept loop.
		// Close listener when ctx cancelled so Accept unblocks on SIGTERM.
		go func() {
			<-ctx.Done()
			ln.Close()
		}()
		return o, nil
	}

	// Non-fork: accept one permitted connection; honour ctx and accept-timeout.
	// Classic Exit(0) on accept-timeout with no connection.
	g.Log.Noticef("listening on %s", ln.Addr())
	at := acceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	var conn net.Conn
	for {
		if !deadline.IsZero() {
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		type acc struct {
			c   net.Conn
			err error
		}
		ch := make(chan acc, 1)
		go func() {
			c, err := ln.Accept()
			ch <- acc{c, err}
		}()
		select {
		case <-ctx.Done():
			ln.Close()
			o.Listener = nil
			return nil, ctx.Err()
		case a := <-ch:
			if a.err != nil {
				ln.Close()
				o.Listener = nil
				if isTimeoutErr(a.err) {
					g.Log.Warningf("accept: %v", a.err)
					return nil, ErrAcceptTimeout
				}
				return nil, a.err
			}
			if err := filter(a.c); err != nil {
				g.Log.Noticef("%s", err)
				a.c.Close()
				continue // keep waiting for a permitted peer
			}
			conn = a.c
		}
		break
	}
	ln.Close()
	o.Listener = nil
	g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	rememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = wrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout") ||
		strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

// rememberAddrs fills SOCAT_* environment fields on g from a live connection.
func rememberAddrs(g *Global, c net.Conn) {
	if g == nil || c == nil {
		return
	}
	if la := c.LocalAddr(); la != nil {
		host, port, err := net.SplitHostPort(la.String())
		if err == nil {
			g.SockAddr = formatSocatAddr(host)
			g.SockPort = port
		} else {
			g.SockAddr = la.String()
		}
	}
	if ra := c.RemoteAddr(); ra != nil {
		host, port, err := net.SplitHostPort(ra.String())
		if err == nil {
			g.PeerAddr = formatSocatAddr(host)
			g.PeerPort = port
		} else {
			g.PeerAddr = ra.String()
		}
	}
}

// formatSocatAddr matches classic env formatting (IPv6 in brackets).
func formatSocatAddr(host string) string {
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		// Expand to full form when possible for test comparisons.
		return "[" + expandIPv6(ip) + "]"
	}
	return host
}

func expandIPv6(ip net.IP) string {
	if ip == nil {
		return ""
	}
	ip = ip.To16()
	if ip == nil {
		return ""
	}
	// Classic often prints full zero-padded form for ::1
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15])
}

func networkTCP(g *Global, s parse.Spec, def string) string {
	if pf := s.OptionValue("pf", ""); pf != "" {
		switch strings.ToLower(pf) {
		case "ip4", "ipv4", "inet", "4":
			return "tcp4"
		case "ip6", "ipv6", "inet6", "6":
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
	default: // IPvDefault
		if def != "" {
			return def
		}
		return "tcp4" // classic default since 1.8.0.1
	}
}

// networkTCPForHost picks tcp/tcp4/tcp6 using options, then host literal shape.
func networkTCPForHost(g *Global, s parse.Spec, host string) string {
	// Explicit pf / global version first (except when host is clearly the other family)
	n := networkTCP(g, s, "")
	h := stripBrackets(host)
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() != nil {
			return "tcp4"
		}
		return "tcp6"
	}
	if strings.Contains(h, ":") {
		return "tcp6"
	}
	if n != "" {
		return n
	}
	return "tcp4"
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
