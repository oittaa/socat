package wsopen

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/tlsopen"
)

func openWSListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openWSListenTLS(ctx, s, mode, g, false)
}

func openWSSListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	return openWSListenTLS(ctx, s, mode, g, true)
}

func openWSListenTLS(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, useTLS bool) (*xio.Opened, error) {
	_, port, wpath, err := wsTarget(s, true)
	if err != nil {
		return nil, err
	}
	network := xio.ListenNetwork(g, s)
	if network == "tcp6" && s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		network = "tcp"
	}
	host := s.OptionValue("bind", "")
	if host == "" {
		switch network {
		case "tcp4":
			host = "0.0.0.0"
		default:
			host = "::"
		}
	}
	if network == "tcp4" && (host == "::" || host == "") {
		host = "0.0.0.0"
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				xio.ApplyReuse(int(fd), s, true)
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
	rawLn, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	ln := net.Listener(rawLn)
	if useTLS {
		tlsCfg, err := tlsopen.TLSServerConfig(s)
		if err != nil {
			_ = rawLn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			return nil, err
		}
		ln = tls.NewListener(rawLn, tlsCfg)
	}

	origin := s.OptionValue("origin", "")
	proto := s.OptionValue("protocol", "")
	fork, maxChildren := xio.ForkLimits(s)
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }
	// Upgrade after peer filter (TCP-level range/sourceport/tcpwrap).
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		xio.ApplyTCPConnOpts(s, c)
		uc, err := upgradeConn(c, wpath, origin, proto)
		if err != nil {
			return nil, err
		}
		return xio.WrapCommon(s, relay.NetStream{Conn: uc})
	}

	o := &xio.Opened{
		Listener:    ln,
		Fork:        fork,
		Label:       s.Type + ":" + port + wpath,
		PeerFilter:  filter,
		MaxChildren: maxChildren,
		WrapDial:    wrapConn,
	}
	o.AddCleanup(func() { _ = ln.Close() }) // #nosec G104 -- Close on cleanup; the first error is already returned

	if fork {
		go func() {
			<-ctx.Done()
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		}()
		return o, nil
	}

	if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s (websocket %s)", ln.Addr(), wpath)
	}
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	var conn net.Conn
	for {
		if !deadline.IsZero() {
			// tls.Listener has no SetDeadline; use the TCP listener.
			if dl, ok := rawLn.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := ln.Accept()
		if err != nil {
			_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
			o.Listener = nil
			if xio.IsTimeoutErr(err) {
				return nil, xio.ErrAcceptTimeout
			}
			return nil, err
		}
		if err := filter(c); err != nil {
			if g != nil && g.Log != nil {
				g.Log.Noticef("%s", err)
			}
			xio.CloseRefusedPeer(c)
			continue
		}
		conn = c
		break
	}
	_ = ln.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
	o.Listener = nil
	xio.RememberAddrs(g, conn)
	st, err := wrapConn(conn)
	if err != nil {
		_ = conn.Close() // #nosec G104 -- Close on cleanup; the first error is already returned
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func upgradeConn(c net.Conn, wantPath, origin, proto string) (net.Conn, error) {
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, err
	}
	got := path.Clean("/" + strings.TrimPrefix(req.URL.Path, "/"))
	want := path.Clean(wantPath)
	if got != want {
		_, _ = fmt.Fprintf(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return nil, fmt.Errorf("websocket path %q does not match %q", req.URL.Path, wantPath)
	}
	opts := &websocket.AcceptOptions{
		InsecureSkipVerify: origin == "",
	}
	if origin != "" {
		opts.OriginPatterns = []string{origin}
	}
	if proto != "" {
		opts.Subprotocols = []string{proto}
	}
	w := newWSHijacker(c, br)
	wc, err := websocket.Accept(w, req, opts)
	if err != nil {
		return nil, err
	}
	return websocket.NetConn(context.Background(), wc, websocket.MessageBinary), nil
}
