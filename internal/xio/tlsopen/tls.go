// TLS endpoints via crypto/tls — not OpenSSL/CGO.
// Canonical types: TLS, TLS-CONNECT, TLS-LISTEN.
// OPENSSL/SSL names are classic aliases.
package tlsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
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
			timeoutRaw, e := xio.NewSocketTimeoutConn(s, raw)
			if e != nil {
				logx.CloseQuiet(raw)
				return e
			}
			// Clone config per dial so concurrent handshake state stays isolated.
			cfg := tlsCfg.Clone()
			tc := tls.Client(timeoutRaw, cfg)
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
			timeoutRaw.EnableSocketTimeouts()
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
		Wrap: func(c net.Conn) (relay.Stream, error) {
			return xio.WrapCommonAfterConnectedTimeoutsApplied(s, relay.NetStream{Conn: c})
		},
	})
}

// openTLSListen implements TLS-LISTEN (and OPENSSL-LISTEN/SSL-LISTEN aliases).
// Family selection matches TCP-LISTEN: pf=, -4/-6/-0, SOCAT_DEFAULT_LISTEN_IP, else IPv4.
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
	host, err := xio.ListenBindHost(network, s.OptionValue("bind", ""))
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsServerConfig(s)
	if err != nil {
		return nil, err
	}

	lc := xio.NewTCPListenConfig(s)
	ln, err := lc.Listen(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tlsLn := tls.NewListener(&socketTimeoutListener{Listener: ln, spec: s}, tlsCfg)

	wrapConn := func(c net.Conn) (relay.Stream, error) {
		xio.EnableSocketTimeouts(c)
		if err := xio.ApplyTCPConnOpts(s, c); err != nil {
			return nil, err
		}
		return xio.WrapCommonAfterConnectedTimeoutsApplied(s, relay.NetStream{Conn: c})
	}

	var setAcceptDeadline func(time.Time) error
	if dl, ok := ln.(interface{ SetDeadline(time.Time) error }); ok {
		setAcceptDeadline = dl.SetDeadline
	}
	handshakeTimeout := xio.HandshakeTimeout(s)
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener:          tlsLn,
		Label:             s.Type + ":" + port,
		WrapDial:          wrapConn,
		SetAcceptDeadline: setAcceptDeadline,
		HandshakeTimeout:  handshakeTimeout,
		ListeningLog:      fmt.Sprintf("listening on %s (TLS)", tlsLn.Addr()),
		AfterAccept: func(g *xio.Global, c net.Conn) error {
			return xio.RememberTLSPeer(g, c, handshakeTimeout)
		},
	})
}

type socketTimeoutListener struct {
	net.Listener
	spec parse.Spec
}

func (l *socketTimeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	wrapped, err := xio.NewSocketTimeoutConn(l.spec, conn)
	if err != nil {
		logx.CloseQuiet(conn)
		return nil, err
	}
	return wrapped, nil
}

// TLSClientConfig builds a crypto/tls client config from TLS/WSS options.
func TLSClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	return tlsClientConfig(s, serverName)
}

// TLSServerConfig builds a crypto/tls server config from TLS/WSS-LISTEN options.
func TLSServerConfig(s parse.Spec) (*tls.Config, error) {
	return tlsServerConfig(s)
}

// unsupportedOpenSSLReason maps Go-canonical OPENSSL option names onto the
// reason they are rejected. Classic tag-1.8.1.3
// 12c08bf66d709fba17035ce95d85bd218428d9ba and official master
// af5388c898c7bb60997935aee93c223deba60c4a implement these via OpenSSL;
// Go crypto/tls cannot honor them. Accepting enabled requests as no-ops would
// hide a requested DTLS method, FIPS mode, compression, DH params, or fragment
// bound. Disabled bool values and compress=none are compatible because Go TLS
// already leaves those features off. method/fips also need classic
// --enable-openssl-method/--enable-fips.
var unsupportedOpenSSLReason = map[string]string{
	"openssl-method":      "stream TLS only",
	"openssl-fips":        "Go crypto/tls has no OpenSSL FIPS module",
	"openssl-compress":    "Go crypto/tls has no TLS compression",
	"openssl-egd":         "Go does not use EGD for randomness",
	"openssl-pseudo":      "Go crypto/tls does not use OpenSSL pseudo-random bytes",
	"openssl-dhparam":     "Go crypto/tls does not load DH parameters",
	"openssl-maxfraglen":  "Go crypto/tls has no max fragment length option",
	"openssl-maxsendfrag": "Go crypto/tls has no max send fragment option",
}

func rejectUnsupportedOpenSSLOptions(s parse.Spec) error {
	typ := s.Type
	if typ == "" {
		typ = "TLS"
	}
	seen := make(map[string]struct{})
	for i := len(s.Options) - 1; i >= 0; i-- {
		option := s.Options[i]
		canonical := parse.CanonicalOptionName(option.Name)
		reason, ok := unsupportedOpenSSLReason[canonical]
		if !ok {
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		if compatibleDisabledOpenSSLOption(canonical, option) {
			continue
		}
		return fmt.Errorf("%s: option %q is not supported (%s)", typ, option.OriginalSpelling(), reason)
	}
	return nil
}

func compatibleDisabledOpenSSLOption(canonical string, option parse.Option) bool {
	switch canonical {
	case "openssl-fips", "openssl-pseudo":
		one := parse.Spec{Options: []parse.Option{option}}
		return !one.BoolOption(canonical)
	case "openssl-compress":
		return option.Has && strings.EqualFold(strings.TrimSpace(option.Value), "none")
	default:
		return false
	}
}

func tlsClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	if err := rejectUnsupportedOpenSSLOptions(s); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := applyProtocolVersions(cfg, s); err != nil {
		return nil, err
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
	noSNI := s.BoolOption("nosni")
	sniHost := s.OptionValue("snihost", "")
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
	if err := rejectUnsupportedOpenSSLOptions(s); err != nil {
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
	if err := applyProtocolVersions(cfg, s); err != nil {
		return nil, err
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

func applyProtocolVersions(cfg *tls.Config, s parse.Spec) error {
	if opt, ok := s.OptionNamed("openssl-min-proto-version"); ok {
		version, err := parseProtocolVersion(opt.Value)
		if err != nil {
			return fmt.Errorf("openssl-min-proto-version: %w", err)
		}
		cfg.MinVersion = version
	}
	if opt, ok := s.OptionNamed("openssl-max-proto-version"); ok {
		version, err := parseProtocolVersion(opt.Value)
		if err != nil {
			return fmt.Errorf("openssl-max-proto-version: %w", err)
		}
		cfg.MaxVersion = version
	}
	if cfg.MaxVersion != 0 && cfg.MinVersion > cfg.MaxVersion {
		return fmt.Errorf("minimum TLS protocol version exceeds maximum")
	}
	return nil
}

func parseProtocolVersion(value string) (uint16, error) {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "TLS1", "TLS1.0", "TLSV1", "TLSV1.0":
		return tls.VersionTLS10, nil
	case "TLS1.1", "TLSV1.1":
		return tls.VersionTLS11, nil
	case "TLS1.2", "TLSV1.2":
		return tls.VersionTLS12, nil
	case "TLS1.3", "TLSV1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported protocol version %q", value)
	}
}
