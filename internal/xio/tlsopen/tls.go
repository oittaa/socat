// TLS endpoints via crypto/tls — not OpenSSL/CGO.
// Canonical types: TLS, TLS-CONNECT, TLS-LISTEN.
// OPENSSL/SSL names are classic aliases.
package tlsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// openTLSConnect implements TLS/TLS-CONNECT (and OPENSSL/SSL aliases).
func openTLSConnect(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Dual-stack like TCP-CONNECT; pf=ip4/ip6 still forces a family.
	return openTLSConnectNetwork(ctx, s, mode, g, xio.ConnectNetworkForType(g, s, xio.FirstHost(s), "tcp"))
}

func openTLSConnectNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	host, port, err := xio.HostPortParams(s)
	if err != nil {
		return nil, err
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("%s: invalid host/port", s.Type)
	}
	// Dual-stack + pf= like TCP-CONNECT.
	network = xio.ConnectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsClientConfig(s, host)
	if err != nil {
		return nil, err
	}

	timeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)

	// Classic OPENSSL-CONNECT (alias of TLS-CONNECT) forks after the handshake.
	// TCP multi-address walk first, then TLS on the winning socket.
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			if timeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, timeout)
				defer cancel()
			}
			raw, e := xio.DialTCPAll(cctx, network, xio.StripBrackets(host), port, s, g, timeout, nil)
			if e != nil {
				return e
			}
			// Clone config per dial so concurrent handshake state stays isolated.
			cfg := tlsCfg.Clone()
			tc := tls.Client(raw, cfg)
			hctx := dctx
			var handshakeCancel context.CancelFunc
			if handshakeTimeout > 0 {
				hctx, handshakeCancel = context.WithTimeout(dctx, handshakeTimeout)
				defer handshakeCancel()
			}
			if e := tc.HandshakeContext(hctx); e != nil {
				logx.CloseQuiet(raw)
				return e
			}
			conn = tc
			return nil
		})
		return conn, err
	}

	return xio.OpenDialed(ctx, s, g, xio.Dialed{
		Label:       s.Type + ":" + addr,
		Dial:        dialOnce,
		RememberTLS: true,
		LogOK:       true,
		LogSuffix:   " (TLS)",
	})
}

// openTLSListen implements TLS-LISTEN (and OPENSSL-LISTEN/SSL-LISTEN aliases).
// Family selection matches TCP-LISTEN: pf=, -4/-6/-0, SOCAT_DEFAULT_LISTEN_IP, else xio.IPv4.
func openTLSListen(ctx context.Context, s parse.Spec, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	netw := xio.ListenNetwork(g, s)
	// Same dual-stack rule as TCP6-LISTEN when ipv6-v6only=0.
	if netw == "tcp6" && s.HasOption("ipv6-v6only") && !s.BoolOption("ipv6-v6only") {
		netw = "tcp"
	}
	return openTLSListenNetwork(ctx, s, mode, g, netw)
}

func openTLSListenNetwork(ctx context.Context, s parse.Spec, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	if len(s.Params) < 1 || s.Params[0] == "" {
		return nil, fmt.Errorf("%s requires port", s.Type)
	}
	port := s.Params[0]
	host := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsServerConfig(s)
	if err != nil {
		return nil, err
	}

	lc := net.ListenConfig{Control: xio.ListenControl(s)}
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsLn := tls.NewListener(ln, tlsCfg)

	fork, maxChildren, err := xio.ForkLimits(s)
	if err != nil {
		logx.CloseQuiet(tlsLn)
		return nil, err
	}
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }

	o := &xio.Opened{
		Kind:             xio.ListenKind(fork),
		Listener:         tlsLn,
		Label:            s.Type + ":" + port,
		PeerFilter:       filter,
		MaxChildren:      maxChildren,
		HandshakeTimeout: xio.HandshakeTimeout(s),
	}
	o.AddCleanup(func() { logx.CloseQuiet(tlsLn) })

	if fork {
		go func() {
			<-ctx.Done()
			logx.CloseQuiet(tlsLn)
		}()
		return o, nil
	}

	// xio.Accept one connection (with optional accept-timeout).
	if g != nil && g.Log != nil {
		g.Log.Noticef("listening on %s (TLS)", tlsLn.Addr())
	}
	at := xio.AcceptTimeout(s)
	var deadline time.Time
	if at > 0 {
		deadline = time.Now().Add(at)
	}
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		if !deadline.IsZero() {
			// tls.Listener has no xio.SetDeadline; use underlying TCP listener.
			if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
				_ = dl.SetDeadline(deadline)
			}
		}
		c, err := tlsLn.Accept()
		ch <- acc{c, err}
	}()
	var conn net.Conn
	select {
	case <-ctx.Done():
		logx.CloseQuiet(tlsLn)
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		// Keep listener closed after one accept (classic non-fork).
		logx.CloseQuiet(tlsLn)
		o.Listener = nil
		if a.err != nil {
			logx.CloseQuiet(o)
			if xio.IsTimeoutErr(a.err) {
				if g != nil && g.Log != nil {
					g.Log.Warningf("accept: Connection timed out")
				}
				return nil, xio.ErrAcceptTimeout
			}
			return nil, a.err
		}
		conn = a.c
	}
	if err := filter(conn); err != nil {
		xio.CloseRefusedPeer(conn)
		return nil, err
	}
	xio.RememberAddrs(g, conn)
	if err := xio.RememberTLSPeer(g, conn, xio.HandshakeTimeout(s)); err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	o.Stream = st
	return o, nil
}

// TLSClientConfig builds a crypto/tls client config from TLS/WSS options.
func TLSClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	return tlsClientConfig(s, serverName)
}

// TLSServerConfig builds a crypto/tls server config from TLS/WSS-LISTEN options.
func TLSServerConfig(s parse.Spec) (*tls.Config, error) {
	return tlsServerConfig(s)
}

func rejectUnsupportedTLSMethod(s parse.Spec) error {
	// crypto/tls implements stream TLS only. Silently accepting this classic
	// socat option could turn a requested DTLS transport into TCP TLS, or make
	// an obsolete SSL method appear to have been selected when it was not.
	for _, name := range []string{"openssl-method", "opensslmethod"} {
		if option, ok := s.OptionNamed(name); ok {
			typ := s.Type
			if typ == "" {
				typ = "TLS"
			}
			return fmt.Errorf("%s: option %q is not supported (stream TLS only)", typ, option.Name)
		}
	}
	return nil
}

func tlsClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	if err := rejectUnsupportedTLSMethod(s); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := applyCipherSuites(cfg, s); err != nil {
		return nil, err
	}
	// Name used for hostname check / SNI.
	// OPENSSL_CN_CLIENT_SECURITY: commonname=$LOCALHOST while connecting to 127.0.0.1.
	// Without commonname, verify against the dial host (IP must not auto-pass).
	// Empty commonname= skips the name check (classic openssl-commonname="").
	dialHost := xio.StripBrackets(serverName)
	cnOpt, cnSet := commonNameOption(s)
	checkName := dialHost
	if cnSet {
		checkName = cnOpt
	}

	// SNI: nosni / snihost (openssl-no-sni / openssl-snihost aliases).
	// OPENSSL_SNI / OPENSSL_NO_SNI: badssl.com needs SNI to succeed / fail.
	// Empty commonname= does not clear SNI; use snihost= / nosni for that.
	noSNI := s.BoolOption("openssl-no-sni") || s.BoolOption("nosni")
	sniHost := s.OptionValue("openssl-snihost", "")
	if sniHost == "" {
		sniHost = s.OptionValue("snihost", "")
	}
	if !noSNI {
		if sniHost != "" {
			cfg.ServerName = sniHost
		} else if sni := sniName(checkName, dialHost); sni != "" {
			cfg.ServerName = sni
		}
	}

	if !verifyEnabled(s) {
		cfg.InsecureSkipVerify = true
	} else {
		roots, err := loadVerifyRoots(s)
		if err != nil {
			return nil, err
		}
		// Manual verify: classic CN-only certs + RFC 6125 name (no IP→any-CN shortcut).
		// VerifyConnection is required as well: VerifyPeerCertificate is not
		// called on a resumed session (gosec G123).
		cfg.InsecureSkipVerify = true
		attachPeerVerify(cfg, makeVerifyPeer(roots, checkName))
		if roots != nil {
			cfg.RootCAs = roots
		}
	}

	// Client certificate (mutual TLS)
	certPath := s.OptionValue("cert", "")
	keyPath := s.OptionValue("key", "")
	if certPath != "" {
		cert, err := loadKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func tlsServerConfig(s parse.Spec) (*tls.Config, error) {
	if err := rejectUnsupportedTLSMethod(s); err != nil {
		return nil, err
	}
	certPath := s.OptionValue("cert", "")
	keyPath := s.OptionValue("key", "")
	if certPath == "" {
		typ := s.Type
		if typ == "" {
			typ = "TLS-LISTEN"
		}
		// Classic warns, binds, then SSL_accept fails ("no shared cipher").
		// We refuse to start. Go crypto/tls cannot serve without a certificate,
		// and we do not invent a dummy cert.
		return nil, fmt.Errorf("%s: option \"cert\" is required", typ)
	}
	cert, err := loadKeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if err := applyCipherSuites(cfg, s); err != nil {
		return nil, err
	}

	// Classic: verify=0 is SSL_VERIFY_NONE. The server does not request a
	// client certificate, and commonname is ignored (name check runs only
	// when openssl-verify is on).
	if !verifyEnabled(s) {
		cfg.ClientAuth = tls.NoClientCert
		return cfg, nil
	}

	cnWant, _ := commonNameOption(s)
	// Classic: SSL_CTX_set_default_verify_paths when cafile/capath are unset.
	roots, err := loadVerifyRoots(s)
	if err != nil {
		return nil, err
	}
	if roots == nil {
		return nil, fmt.Errorf("tls: no CA roots for verify")
	}
	cfg.ClientCAs = roots
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	attachPeerVerify(cfg, makeServerVerifyPeer(roots, cnWant, true, cfg.VerifyPeerCertificate))
	return cfg, nil
}
