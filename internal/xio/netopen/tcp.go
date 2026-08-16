package netopen

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

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
				_ = c.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
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
	//   4) default xio.IPv4
	netw := xio.ListenNetwork(g, s)
	return openTCPListenNetwork(ctx, s, mode, g, netw)
}

func openTCP4Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openTCPListenNetwork(ctx, s, mode, g, "tcp4")
}

func openTCP6Listen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Go's "tcp6" forces IPV6_V6ONLY=1 after our Control hook. For
	// ipv6-v6only=0 use dual-stack "tcp" on :: so xio.IPv4 clients work.
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

	fork := s.BoolOption("fork")
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxChildren = n
		}
	}
	// Per-connection wrap for fork accept (crlf, escape, keepalive, …).
	// Non-fork applies the same via xio.WrapCommon after the single accept below.
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		xio.ApplyTCPConnOpts(s, c)
		return xio.WrapCommon(s, relay.NetStream{Conn: c})
	}
	o := &xio.Opened{
		Kind:        xio.ListenKind(fork),
		Listener:    ln,
		Label:       fmt.Sprintf("%s-LISTEN:%s", network, port),
		PeerFilter:  filter,
		MaxChildren: maxChildren,
		WrapDial:    wrapConn,
	}
	o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned

	if fork {
		// Parent keeps listening; xio.Run handles accept loop.
		// xio.Close listener when ctx cancelled so xio.Accept unblocks on SIGTERM.
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}()
		return o, nil
	}

	// Non-fork: accept one permitted connection; honour ctx and accept-timeout.
	// Classic Exit(0) on accept-timeout with no connection.
	g.Log.Noticef("listening on %s", ln.Addr())
	at := xio.AcceptTimeout(s)
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
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			o.Listener = nil
			return nil, ctx.Err()
		case a := <-ch:
			if a.err != nil {
				_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
				o.Listener = nil
				if xio.IsTimeoutErr(a.err) {
					// Phrase "timed out" matches classic test.sh REUSEADDR_NULL CANT path.
					g.Log.Warningf("accept: Connection timed out")
					return nil, xio.ErrAcceptTimeout
				}
				return nil, a.err
			}
			if err := filter(a.c); err != nil {
				g.Log.Noticef("%s", err)
				xio.CloseRefusedPeer(a.c)
				continue // keep waiting for a permitted peer
			}
			conn = a.c
		}
		break
	}
	_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	o.Listener = nil
	g.Log.Infof("accepted connection from %s", conn.RemoteAddr())
	// Classic: socket options on LISTEN apply to the accepted connection
	// (so-keepalive, nodelay, …). LISTEN_KEEPALIVE checks filan on the conn.
	xio.ApplyTCPConnOpts(s, conn)
	xio.RememberAddrs(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o.Stream = st
	return o, nil
}

// xio.ApplyTCPConnOpts sets classic TCP/socket options on an accepted or dialed conn.
