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
	// Generic TCP: dual-stack resolve; -4/-6 only reorder (classic preference).
	return openTCPConnectNetwork(ctx, s, mode, g, connectNetworkForType(g, s, host, "tcp"))
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
	// Honour pf= even when called from TCP4/TCP6 openers.
	network = connectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(stripBrackets(host), port)

	timeout := connectTimeout(s)

	// Apply setsockopt before connect when possible via Control (level:opt:val).
	// Fail the open if setsockopt returns an error (classic SETSOCKOPT MSS=1).
	var setSockErr error
	var control func(network, address string, c syscall.RawConn) error
	if raw := s.OptionValue("setsockopt", ""); raw != "" {
		control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setSockErr = applySetsockoptFD(int(fd), raw)
			})
		}
	}

	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := withRetry(dctx, s, g, network+" connect", func() error {
			setSockErr = nil
			c, e := dialTCPAll(dctx, network, stripBrackets(host), port, s, g, timeout, control)
			if e != nil {
				return e
			}
			if setSockErr != nil {
				c.Close()
				return setSockErr
			}
			if tc, ok := c.(*net.TCPConn); ok {
				if s.BoolOption("nodelay") {
					_ = tc.SetNoDelay(true)
				}
				if s.BoolOption("keepalive") || s.HasOption("keepidle") {
					_ = tc.SetKeepAlive(true)
				}
			}
			conn = c
			return nil
		})
		return conn, err
	}

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := parsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	if maxChildren > 0 && !fork {
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}
	if fork {
		// Classic CONNECT,fork parent loop (TCP_CONNECT_MAXCHILDREN).
		return &Opened{
			ConnectFork: true,
			Fork:        true,
			MaxChildren: maxChildren,
			Interval:    parseRetry(s).interval,
			Label:       fmt.Sprintf("%s:%s", network, addr),
			Dial:        dialOnce,
		}, nil
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
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
	filter := func(c net.Conn) error { return peerAllowedG(s, c, g) }
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxChildren = n
		}
	}
	// Per-connection wrap for fork accept (crlf, escape, keepalive, …).
	// Non-fork applies the same via wrapCommon after the single accept below.
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		applyTCPConnOpts(s, c)
		return wrapCommon(s, relay.NetStream{Conn: c})
	}
	o := &Opened{
		Listener:    ln,
		Fork:        fork,
		Label:       fmt.Sprintf("%s-LISTEN:%s", network, port),
		PeerFilter:  filter,
		MaxChildren: maxChildren,
		WrapDial:    wrapConn,
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
					// Phrase "timed out" matches classic test.sh REUSEADDR_NULL CANT path.
					g.Log.Warningf("accept: Connection timed out")
					return nil, ErrAcceptTimeout
				}
				return nil, a.err
			}
			if err := filter(a.c); err != nil {
				g.Log.Noticef("%s", err)
				closeRefusedPeer(a.c)
				continue // keep waiting for a permitted peer
			}
			conn = a.c
		}
		break
	}
	ln.Close()
	o.Listener = nil
	g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	// Classic: socket options on LISTEN apply to the accepted connection
	// (so-keepalive, nodelay, …). LISTEN_KEEPALIVE checks filan on the conn.
	applyTCPConnOpts(s, conn)
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

// applyTCPConnOpts sets classic TCP/socket options on an accepted or dialed conn.
func applyTCPConnOpts(s parse.Spec, c net.Conn) {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	if s.BoolOption("keepalive") || s.BoolOption("so-keepalive") || s.HasOption("keepidle") {
		_ = tc.SetKeepAlive(true)
	}
	if s.BoolOption("nodelay") || s.BoolOption("tcp-nodelay") {
		_ = tc.SetNoDelay(true)
	}
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

// applySetsockoptFD parses classic setsockopt=level:optname:value (ints) and applies it.
// SETSOCKOPT test uses setsockopt=6:TCP_MAXSEG:512 (IPPROTO_TCP + TCP_MAXSEG).
func applySetsockoptFD(fd int, spec string) error {
	parts := strings.Split(spec, ":")
	if len(parts) < 3 {
		return fmt.Errorf("setsockopt requires level:optname:value")
	}
	level, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("setsockopt level: %w", err)
	}
	opt, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("setsockopt optname: %w", err)
	}
	val, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Errorf("setsockopt value: %w", err)
	}
	return syscall.SetsockoptInt(fd, level, opt, val)
}

// rememberAddrs fills SOCAT_* environment fields on g from a live connection.
// Also exports classic process env used by -r/-R path expansion ($SERVER0_PEERADDR).
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
	// Classic xiosetenv: PROGNAME_PEERADDR / PROGNAME_PEERPORT (and SOCAT_*).
	exportSocatEnv(g)
}

// exportSocatEnv sets process environment for sniff-path expansion and children.
func exportSocatEnv(g *Global) {
	if g == nil {
		return
	}
	prog := g.Progname
	if prog == "" {
		prog = "socat"
	}
	// Uppercase progname like classic xiosetenv.
	up := strings.ToUpper(prog)
	_ = os.Setenv("SOCAT_SOCKADDR", g.SockAddr)
	_ = os.Setenv("SOCAT_PEERADDR", g.PeerAddr)
	_ = os.Setenv("SOCAT_SOCKPORT", g.SockPort)
	_ = os.Setenv("SOCAT_PEERPORT", g.PeerPort)
	_ = os.Setenv(up+"_SOCKADDR", g.SockAddr)
	_ = os.Setenv(up+"_PEERADDR", g.PeerAddr)
	_ = os.Setenv(up+"_SOCKPORT", g.SockPort)
	_ = os.Setenv(up+"_PEERPORT", g.PeerPort)
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
