// TLS endpoints via crypto/tls — not OpenSSL/CGO.
// Canonical types: TLS, TLS-CONNECT, TLS-LISTEN.
// OPENSSL/SSL names are aliases of those types.
package tlsopen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/relay"
)

// openTLSConnect implements TLS/TLS-CONNECT (and OPENSSL/SSL aliases).
func openTLSConnect(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	// Dual-stack like TCP-CONNECT; pf=ip4/ip6 still forces a family.
	return openTLSConnectNetwork(ctx, s, mode, g, xio.ConnectNetworkForType(g, s, xio.FirstHost(s), "tcp"))
}

func openTLSConnectNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
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

	tlsCfg, err := tlsClientConfigForContext(ctx, s, host)
	if err != nil {
		return nil, err
	}

	timeout := xio.ConnectTimeout(s)
	handshakeTimeout := xio.HandshakeTimeout(s)

	// TLS-CONNECT forks after the handshake. TCP multi-address walk first,
	// then TLS on the winning socket.
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, g, s.Type, func() error {
			cctx := dctx
			var cancel context.CancelFunc
			if timeout > 0 {
				cctx, cancel = context.WithTimeout(dctx, timeout)
				defer cancel()
			}
			raw, e := xio.DialTCPAll(cctx, xio.DialTarget{Network: network, Host: host, Port: port}, s, g, timeout, nil)
			if e != nil {
				return e
			}
			timeoutRaw := xio.NewSocketTimeoutConn(raw, s.Common.ReadTimeout.Value, s.Common.WriteTimeout.Value)
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
			stream := relay.NetStream{Conn: c}
			if err := xio.ApplyStreamFDOptions(s, stream); err != nil {
				return nil, err
			}
			return xio.WrapStream(s, stream, xio.TransportSocketTimeouts)
		},
	})
}

// openTLSListen implements TLS-LISTEN (and OPENSSL-LISTEN/SSL-LISTEN aliases).
// Family selection matches TCP-LISTEN: pf=, -4/-6/-0, SOCAT_DEFAULT_LISTEN_IP, else IPv4.
func openTLSListen(ctx context.Context, s addrconfig.Address, mode xio.Mode, g *xio.Global) (*xio.Opened, error) {
	netw := xio.ListenNetwork(g, s)
	// Same dual-stack rule as TCP6-LISTEN when ipv6-v6only=0.
	return openTLSListenNetwork(ctx, s, mode, g, xio.DualStackListenNetwork(s, netw))
}

func openTLSListenNetwork(ctx context.Context, s addrconfig.Address, _ xio.Mode, g *xio.Global, network string) (*xio.Opened, error) {
	port, err := xio.ListenPortText(s)
	if err != nil {
		return nil, err
	}
	addr, err := xio.TCPListenAddress(ctx, s, network, port)
	if err != nil {
		return nil, err
	}

	tlsCfg, err := tlsServerConfigForContext(ctx, s)
	if err != nil {
		return nil, err
	}

	ln, err := xio.ListenTCP(ctx, s, network, addr)
	if err != nil {
		return nil, err
	}
	tlsLn := tls.NewListener(&socketTimeoutListener{
		Listener:     ln,
		readTimeout:  s.Common.ReadTimeout.Value,
		writeTimeout: s.Common.WriteTimeout.Value,
	}, tlsCfg)

	wrapConn := func(c net.Conn) (relay.Stream, error) {
		xio.EnableSocketTimeouts(c)
		if err := xio.ApplyTCPConnOpts(s, c); err != nil {
			return nil, err
		}
		stream := relay.NetStream{Conn: c}
		if err := xio.ApplyStreamFDOptions(s, stream); err != nil {
			return nil, err
		}
		return xio.WrapStream(s, stream, xio.TransportSocketTimeouts)
	}

	handshakeTimeout := xio.HandshakeTimeout(s)
	return xio.OpenListenSession(ctx, s, g, xio.ListenSession{
		Listener:         tlsLn,
		Label:            s.Type + ":" + port,
		WrapDial:         wrapConn,
		HandshakeTimeout: handshakeTimeout,
		ListeningLog:     fmt.Sprintf("listening on %s (TLS)", tlsLn.Addr()),
		AfterAccept: func(g *xio.Global, c net.Conn) error {
			return xio.RememberTLSPeer(g, c, handshakeTimeout)
		},
	})
}

type socketTimeoutListener struct {
	net.Listener
	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (l *socketTimeoutListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return xio.NewSocketTimeoutConn(conn, l.readTimeout, l.writeTimeout), nil
}

// TLSClientConfig builds a crypto/tls client config from TLS/WSS options.
func TLSClientConfig(s addrconfig.Address, serverName string) (*tls.Config, error) {
	return TLSClientConfigSettings(s.Type, s.TLS, serverName)
}

func tlsClientConfig(s addrconfig.Address, serverName string) (*tls.Config, error) {
	return TLSClientConfig(s, serverName)
}

// TLSServerConfig builds a crypto/tls server config from TLS/WSS-LISTEN options.
func TLSServerConfig(s addrconfig.Address) (*tls.Config, error) {
	return TLSServerConfigSettings(s.Type, s.TLS)
}

func tlsServerConfig(s addrconfig.Address) (*tls.Config, error) {
	return TLSServerConfig(s)
}

func rejectUnsupportedOpenSSLOptions(settings addrconfig.TLS, typ string) error {
	if typ == "" {
		typ = "TLS"
	}
	if settings.UnsupportedSet {
		return fmt.Errorf("%s: option %q is not supported (%s)", typ, settings.UnsupportedName, settings.UnsupportedReason)
	}
	return nil
}

func rejectTLSNamesOnPlaintext(typ string, settings addrconfig.TLS, includePublic bool) error {
	if typ == "" {
		typ = "address"
	}
	name := settings.LastHiddenName
	if includePublic {
		name = settings.LastPlaintextName
	}
	if name == "" {
		return nil
	}
	return fmt.Errorf("%s: option %q does not apply to a plaintext transport", typ, name)
}

// RejectHiddenTLSOnPlaintext fails when a hidden OpenSSL family is present on
// a path that will not configure TLS. Call after the opener has chosen a
// plaintext transport. Last-wins selects the spelling in the error.
func RejectHiddenTLSOnPlaintext(typ string, settings addrconfig.TLS) error {
	return rejectTLSNamesOnPlaintext(typ, settings, false)
}

// RejectPROXYTLSOnPlaintext fails when a hidden or public TLS family is present
// on plaintext PROXY (HTTP/1 CONNECT or h2c). Call after HTTP-version / h2c
// dispatch. Last-wins selects the spelling in the error.
func RejectPROXYTLSOnPlaintext(typ string, settings addrconfig.TLS) error {
	return rejectTLSNamesOnPlaintext(typ, settings, true)
}

func tlsClientConfigForContext(ctx context.Context, s addrconfig.Address, serverName string) (*tls.Config, error) {
	return TLSClientConfigSettings(s.Type, s.TLS, serverName)
}

// TLSClientConfigSettings builds a client config from prepared TLS settings.
// s remains only for the temporary compatibility rejection adapter.
func TLSClientConfigSettings(typ string, settings addrconfig.TLS, serverName string) (*tls.Config, error) {
	if err := rejectUnsupportedOpenSSLOptions(settings, typ); err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if err := applyProtocolVersions(cfg, settings); err != nil {
		return nil, err
	}
	if len(settings.CipherSuites) != 0 {
		cfg.CipherSuites = append([]uint16(nil), settings.CipherSuites...)
	}
	// Name used for hostname check / SNI.
	// Without commonname, verify against the dial host (IP must not auto-pass).
	// Empty commonname= skips the name check.
	dialHost := xio.StripBrackets(serverName)
	cnOpt, cnSet := settings.CommonName.Value, settings.CommonName.Set
	checkName := dialHost
	if cnSet {
		checkName = cnOpt
	}

	// SNI: nosni / snihost (openssl-no-sni / openssl-snihost aliases).
	// Empty commonname= does not clear SNI; use snihost= / nosni for that.
	noSNI := settings.NoSNI.Set && settings.NoSNI.Value
	sniHost := settings.SNIHost.Value
	if !noSNI {
		if sniHost != "" {
			cfg.ServerName = sniHost
		} else if sni := sniName(checkName, dialHost); sni != "" {
			cfg.ServerName = sni
		}
	}

	if settings.Verify.Set && !settings.Verify.Value {
		cfg.InsecureSkipVerify = true
	} else {
		roots, err := loadVerifyRootsForPaths(settings.CAFile.Value, settings.CAPath.Value)
		if err != nil {
			return nil, err
		}
		// Manual verify: CN-only certs still match when there are no SANs;
		// IP literals must not match any CN. VerifyConnection is required:
		// VerifyPeerCertificate is not called on a resumed session (gosec G123).
		cfg.InsecureSkipVerify = true
		attachPeerVerify(cfg, makeVerifyPeer(roots, checkName))
		if roots != nil {
			cfg.RootCAs = roots
		}
	}

	// Client certificate (mutual TLS)
	certPath := settings.Certificate.Value
	keyPath := settings.Key.Value
	if certPath != "" {
		cert, err := loadKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func tlsServerConfigForContext(ctx context.Context, s addrconfig.Address) (*tls.Config, error) {
	return TLSServerConfigSettings(s.Type, s.TLS)
}

// TLSServerConfigSettings builds a server config from prepared TLS settings.
// s remains only for the temporary compatibility rejection adapter.
func TLSServerConfigSettings(typ string, settings addrconfig.TLS) (*tls.Config, error) {
	if err := rejectUnsupportedOpenSSLOptions(settings, typ); err != nil {
		return nil, err
	}
	certPath := settings.Certificate.Value
	keyPath := settings.Key.Value
	if certPath == "" {
		if typ == "" {
			typ = "TLS-LISTEN"
		}
		// crypto/tls cannot serve without a certificate; refuse to start
		// rather than bind and fail later. Do not invent a dummy cert.
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
	if err := applyProtocolVersions(cfg, settings); err != nil {
		return nil, err
	}
	if len(settings.CipherSuites) != 0 {
		cfg.CipherSuites = append([]uint16(nil), settings.CipherSuites...)
	}

	// verify=0 does not request a client cert; commonname is ignored
	// (name check runs only when verify is on).
	if settings.Verify.Set && !settings.Verify.Value {
		cfg.ClientAuth = tls.NoClientCert
		return cfg, nil
	}

	cnWant := settings.CommonName.Value
	// Empty cafile/capath uses the system verify pool.
	roots, err := loadVerifyRootsForPaths(settings.CAFile.Value, settings.CAPath.Value)
	if err != nil {
		return nil, err
	}
	if roots == nil {
		return nil, fmt.Errorf("tls: no CA roots for verify")
	}
	cfg.ClientCAs = roots
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	attachPeerVerify(cfg, makeServerVerifyPeer(roots, cnWant))
	return cfg, nil
}

func applyProtocolVersions(cfg *tls.Config, settings addrconfig.TLS) error {
	if settings.MinVersion != 0 {
		cfg.MinVersion = settings.MinVersion
	}
	if settings.MaxVersion != 0 {
		cfg.MaxVersion = settings.MaxVersion
	}
	if cfg.MaxVersion != 0 && cfg.MinVersion > cfg.MaxVersion {
		return fmt.Errorf("minimum TLS protocol version exceeds maximum")
	}
	return nil
}
