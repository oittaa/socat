// TLS endpoints (classic OPENSSL/SSL address types) via crypto/tls — not OpenSSL/CGO.
package tlsopen

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

// openTLSConnect implements classic OPENSSL/OPENSSL-CONNECT/SSL/SSL-CONNECT (TLS client over TCP).
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
	// Dual-stack + pf= like TCP-CONNECT (OPENSSL inherits IP app connect).
	network = xio.ConnectNetworkForType(g, s, host, network)
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsClientConfig(s, host)
	if err != nil {
		return nil, err
	}

	timeout := xio.ConnectTimeout(s)

	// Classic OPENSSL-CONNECT forks after the TLS handshake; Dial returns a live TLS conn.
	// TCP multi-address walk first, then TLS on the winning socket.
	dialOnce := func(dctx context.Context) (net.Conn, error) {
		var conn net.Conn
		err := xio.WithRetry(dctx, s, g, "OPENSSL-CONNECT", func() error {
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
			if e := tc.HandshakeContext(cctx); e != nil {
				raw.Close()
				return e
			}
			conn = tc
			return nil
		})
		return conn, err
	}

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	if maxChildren > 0 && !fork {
		return nil, fmt.Errorf("%s: option max-children not allowed without option fork", s.Type)
	}
	if fork {
		return &xio.Opened{
			ConnectFork: true,
			Fork:        true,
			MaxChildren: maxChildren,
			Interval:    xio.ParseRetry(s).Interval,
			Label:       "OPENSSL:" + addr,
			Dial:        dialOnce,
		}, nil
	}

	conn, err := dialOnce(ctx)
	if err != nil {
		return nil, err
	}
	xio.RememberAddrs(g, conn)
	xio.RememberTLSPeer(g, conn)
	if g != nil && g.Log != nil {
		g.Log.Infof("successfully connected from %s to %s (TLS)", conn.LocalAddr(), conn.RemoteAddr())
	}
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &xio.Opened{Stream: st, Label: "OPENSSL:" + addr}, nil
}

// openTLSListen implements classic OPENSSL-LISTEN/SSL-LISTEN (TLS server over TCP).
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
	host := s.OptionValue("bind", "")
	if host == "" {
		switch network {
		case "tcp4":
			host = "0.0.0.0"
		case "tcp6", "tcp":
			host = "::"
		default:
			host = "::"
		}
	}
	// If bind was left as dual-stack default but pf/network is xio.IPv4, force v4 any.
	if network == "tcp4" && (host == "::" || host == "") {
		host = "0.0.0.0"
	}
	addr := net.JoinHostPort(xio.StripBrackets(host), port)

	tlsCfg, err := tlsServerConfig(s)
	if err != nil {
		return nil, err
	}

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
				// Match TCP-LISTEN: set IPV6_V6ONLY before bind for tcp/tcp6.
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
	tlsLn := tls.NewListener(ln, tlsCfg)

	fork := s.BoolOption("fork")
	maxChildren := 0
	if v := s.OptionValue("max-children", ""); v != "" {
		if n, e := xio.ParsePositiveInt(v); e == nil {
			maxChildren = n
		}
	}
	filter := func(c net.Conn) error { return xio.PeerAllowedG(s, c, g) }

	o := &xio.Opened{
		Listener:    tlsLn,
		Fork:        fork,
		Label:       "OPENSSL-LISTEN:" + port,
		PeerFilter:  filter,
		MaxChildren: maxChildren,
	}
	o.AddCleanup(func() { tlsLn.Close() })

	if fork {
		go func() {
			<-ctx.Done()
			tlsLn.Close()
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
		tlsLn.Close()
		o.Listener = nil
		return nil, ctx.Err()
	case a := <-ch:
		// Keep listener closed after one accept (classic non-fork).
		tlsLn.Close()
		o.Listener = nil
		if a.err != nil {
			o.Close()
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
	xio.RememberTLSPeer(g, conn)
	st := relay.Stream(relay.NetStream{Conn: conn})
	st, err = xio.WrapCommon(s, st)
	if err != nil {
		conn.Close()
		return nil, err
	}
	o.Stream = st
	return o, nil
}

func verifyEnabled(s parse.Spec) bool {
	// Classic default verify=1; verify=0 disables peer verification.
	// Bare "verify" without value is true (flag).
	if !s.HasOption("verify") {
		return true
	}
	return s.BoolOption("verify")
}

// commonNameOption returns classic openssl-commonname / commonname if set.
func commonNameOption(s parse.Spec) string {
	if v := s.OptionValue("commonname", ""); v != "" {
		return v
	}
	return s.OptionValue("openssl-commonname", "")
}

// TLSClientConfig builds a crypto/tls client config from classic OPENSSL/WSS options.
func TLSClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	return tlsClientConfig(s, serverName)
}

// TLSServerConfig builds a crypto/tls server config from classic OPENSSL/WSS-LISTEN options.
func TLSServerConfig(s parse.Spec) (*tls.Config, error) {
	return tlsServerConfig(s)
}

func tlsClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	// Name used for hostname check / SNI.
	// OPENSSL_CN_CLIENT_SECURITY: commonname=$LOCALHOST while connecting to 127.0.0.1.
	// Without commonname, verify against the dial host (IP must not auto-pass).
	cnOpt := commonNameOption(s)
	checkName := xio.StripBrackets(serverName)
	if cnOpt != "" {
		checkName = cnOpt
	}

	// SNI: classic openssl-no-sni / openssl-snihost (alias snihost).
	// OPENSSL_SNI / OPENSSL_NO_SNI: badssl.com needs SNI to succeed / fail.
	noSNI := s.BoolOption("openssl-no-sni") || s.BoolOption("nosni")
	sniHost := s.OptionValue("openssl-snihost", "")
	if sniHost == "" {
		sniHost = s.OptionValue("snihost", "")
	}
	if !noSNI {
		if sniHost != "" {
			cfg.ServerName = sniHost
		} else if ip := net.ParseIP(checkName); ip == nil {
			cfg.ServerName = checkName
		} else if cnOpt != "" {
			// commonname is hostname while dial target may be IP — still set SNI
			cfg.ServerName = cnOpt
		}
	}

	if !verifyEnabled(s) {
		cfg.InsecureSkipVerify = true
	} else {
		roots, err := loadCAPool(s)
		if err != nil {
			return nil, err
		}
		// Manual verify: classic CN-only certs + strict name (no IP→any-CN shortcut).
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = makeVerifyPeer(roots, checkName, cnOpt != "")
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
	certPath := s.OptionValue("cert", "")
	keyPath := s.OptionValue("key", "")
	var cert tls.Certificate
	var err error
	if certPath == "" {
		// Classic allows OPENSSL-LISTEN without cert for option-parse regression
		// tests (V1800_OPENSSL_LISTEN_*). Generate an ephemeral self-signed cert.
		cert, err = ephemeralSelfSigned()
		if err != nil {
			return nil, err
		}
	} else {
		cert, err = loadKeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	cnWant := commonNameOption(s)
	needClientCert := verifyEnabled(s) || cnWant != ""

	if needClientCert {
		roots, err := loadCAPool(s)
		if err != nil {
			return nil, err
		}
		if roots != nil {
			cfg.ClientCAs = roots
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else if verifyEnabled(s) {
			cfg.ClientAuth = tls.RequireAnyClientCert
		} else {
			// commonname check only: request a client cert if offered
			cfg.ClientAuth = tls.RequestClientCert
		}
		if cnWant != "" || roots != nil {
			// Verify client chain + optional CN match (OPENSSL_CN_SERVER_SECURITY).
			cfg.InsecureSkipVerify = false // N/A for server
			prev := cfg.VerifyPeerCertificate
			cfg.VerifyPeerCertificate = makeServerVerifyPeer(roots, cnWant, verifyEnabled(s), prev)
		}
	} else {
		cfg.ClientAuth = tls.NoClientCert
	}
	return cfg, nil
}

// makeServerVerifyPeer checks client certificate chain and optional commonname.
func makeServerVerifyPeer(roots *x509.CertPool, cnWant string, doVerify bool, prev func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
		if prev != nil {
			if err := prev(rawCerts, chains); err != nil {
				return err
			}
		}
		if len(rawCerts) == 0 {
			if cnWant != "" || doVerify {
				return fmt.Errorf("tls: no client certificate")
			}
			return nil
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		if doVerify && roots != nil {
			opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageAny}}
			inter := x509.NewCertPool()
			for i := 1; i < len(rawCerts); i++ {
				if c, e := x509.ParseCertificate(rawCerts[i]); e == nil {
					inter.AddCert(c)
				}
			}
			opts.Intermediates = inter
			if _, err := leaf.Verify(opts); err != nil {
				return err
			}
		}
		if cnWant != "" {
			if !cnMatches(leaf, cnWant) {
				return fmt.Errorf("tls: client commonName %q does not match %q", leaf.Subject.CommonName, cnWant)
			}
		}
		return nil
	}
}

// errDSAUnsupported is returned when a PEM contains a DSA private key.
// DSA is deprecated; Go crypto/tls does not support DSA keys.
var errDSAUnsupported = fmt.Errorf("DSA private keys are not supported (deprecated)")

// loadKeyPair loads cert+key from separate files or a combined PEM (classic .pem).
func loadKeyPair(certPath, keyPath string) (tls.Certificate, error) {
	if keyPath == "" {
		// Combined PEM: PRIVATE KEY + CERTIFICATE (+ optional DH)
		data, err := os.ReadFile(certPath)
		if err != nil {
			return tls.Certificate{}, err
		}
		if pemHasDSAPrivateKey(data) {
			return tls.Certificate{}, fmt.Errorf("cert %s: %w", certPath, errDSAUnsupported)
		}
		// tls.X509KeyPair accepts cert PEM then key PEM, or we try both orders.
		certPEM, keyPEM := splitCertKeyPEM(data)
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return tls.Certificate{}, fmt.Errorf("cert %s: need both certificate and private key in PEM", certPath)
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if pemHasDSAPrivateKey(keyData) {
		return tls.Certificate{}, fmt.Errorf("key %s: %w", keyPath, errDSAUnsupported)
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func pemHasDSAPrivateKey(data []byte) bool {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == "DSA PRIVATE KEY" {
			return true
		}
	}
}

func splitCertKeyPEM(data []byte) (certPEM, keyPEM []byte) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		b := pem.EncodeToMemory(block)
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, b...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
			// DSA PRIVATE KEY intentionally omitted — rejected in loadKeyPair.
			keyPEM = append(keyPEM, b...)
		}
	}
	return certPEM, keyPEM
}

func loadCAPool(s parse.Spec) (*x509.CertPool, error) {
	cafile := s.OptionValue("cafile", "")
	if cafile == "" {
		cafile = s.OptionValue("ca", "")
	}
	if cafile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(cafile)
	if err != nil {
		return nil, fmt.Errorf("cafile: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		// try as single DER? or key+cert pem — extract certs only
		rest := data
		ok := false
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type == "CERTIFICATE" {
				if c, e := x509.ParseCertificate(block.Bytes); e == nil {
					pool.AddCert(c)
					ok = true
				}
			}
		}
		if !ok {
			return nil, fmt.Errorf("cafile %s: no certificates found", cafile)
		}
	}
	return pool, nil
}

// makeVerifyPeer verifies the leaf against roots and checks name via SAN or CN.
// wantCN: when true (commonname= set), only that name may match — no IP shortcuts.
// Classic test certs often lack SANs; we still allow CN match for the check name.
func makeVerifyPeer(roots *x509.CertPool, checkName string, wantCN bool) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("tls: no peer certificates")
		}
		certs := make([]*x509.Certificate, 0, len(rawCerts))
		for _, raw := range rawCerts {
			c, err := x509.ParseCertificate(raw)
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		leaf := certs[0]
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: x509.NewCertPool(),
		}
		for _, c := range certs[1:] {
			opts.Intermediates.AddCert(c)
		}
		if roots == nil {
			sys, err := x509.SystemCertPool()
			if err != nil {
				return err
			}
			opts.Roots = sys
		}
		if _, err := leaf.Verify(opts); err != nil {
			return err
		}
		if checkName == "" {
			return nil
		}
		// Prefer SANs (modern).
		if err := leaf.VerifyHostname(checkName); err == nil {
			return nil
		}
		// CN match for classic test certs / commonname= option.
		if cnMatches(leaf, checkName) {
			return nil
		}
		// Without explicit commonname, do NOT accept arbitrary CN for IP dials
		// (OPENSSL_CN_CLIENT_SECURITY: connect 127.0.0.1 without commonname must fail).
		return fmt.Errorf("tls: certificate hostname mismatch (CN=%q name=%q)", leaf.Subject.CommonName, checkName)
	}
}

func cnMatches(leaf *x509.Certificate, want string) bool {
	if leaf == nil || want == "" {
		return false
	}
	// OPENSSLTCP6_*: classic test certs use CN="[::1]" while dial name is ::1.
	want = xio.StripBrackets(want)
	cn := xio.StripBrackets(leaf.Subject.CommonName)
	if strings.EqualFold(cn, want) {
		return true
	}
	if strings.EqualFold(leaf.Subject.CommonName, want) {
		return true
	}
	for _, n := range leaf.DNSNames {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

// ephemeralSelfSigned builds a short-lived RSA cert for OPENSSL-LISTEN without cert=.
func ephemeralSelfSigned() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "socat-ephemeral"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
