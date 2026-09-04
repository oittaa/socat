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
	"time"

	"github.com/coder/websocket"

	"github.com/oittaa/socat/internal/logx"
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
	addr, err := xio.TCPListenAddress(ctx, s, network, port)
	if err != nil {
		return nil, err
	}

	rawLn, err := xio.ListenTCP(ctx, s, network, addr)
	if err != nil {
		return nil, err
	}
	ln := net.Listener(rawLn)
	if useTLS {
		tlsCfg, err := tlsopen.TLSServerConfig(s)
		if err != nil {
			logx.CloseQuiet(rawLn)
			return nil, err
		}
		ln = tls.NewListener(rawLn, tlsCfg)
	}

	origin := s.OptionValue("origin", "")
	proto := s.OptionValue("protocol", "")
	handshakeTimeout := xio.HandshakeTimeout(s)
	// Upgrade after peer filter (TCP-level range/sourceport/tcpwrap).
	wrapConn := func(c net.Conn) (relay.Stream, error) {
		if err := xio.ApplyTCPConnOpts(s, c); err != nil {
			return nil, err
		}
		uc, err := upgradeConn(c, wpath, origin, proto, handshakeTimeout)
		if err != nil {
			return nil, err
		}
		return xio.SetupConnectedStream(s, relay.NetStream{Conn: uc})
	}

	var setAcceptDeadline func(time.Time) error
	if dl, ok := rawLn.(interface{ SetDeadline(time.Time) error }); ok {
		setAcceptDeadline = dl.SetDeadline
	}
	sess := xio.ListenSession{
		Listener:          ln,
		Label:             s.Type + ":" + port + wpath,
		WrapDial:          wrapConn,
		SetAcceptDeadline: setAcceptDeadline,
		HandshakeTimeout:  handshakeTimeout,
		ListeningLog:      fmt.Sprintf("listening on %s (websocket %s)", ln.Addr(), wpath),
	}
	if useTLS {
		sess.AfterAccept = func(g *xio.Global, c net.Conn) error {
			return xio.RememberTLSPeer(g, c, handshakeTimeout)
		}
	}
	return xio.OpenListenSession(ctx, s, g, sess)
}

func upgradeConn(c net.Conn, wantPath, origin, proto string, timeout time.Duration) (net.Conn, error) {
	var upgraded net.Conn
	err := xio.WithHandshakeDeadline(c, timeout, func() error {
		var err error
		upgraded, err = upgradeConnNow(c, wantPath, origin, proto)
		return err
	})
	return upgraded, err
}

func upgradeConnNow(c net.Conn, wantPath, origin, proto string) (net.Conn, error) {
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
	return newWSNetConn(c, wc), nil
}
