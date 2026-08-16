// TLS endpoints via crypto/tls — not OpenSSL/CGO.
// Canonical types: TLS, TLS-CONNECT, TLS-LISTEN.
// OPENSSL/SSL names are classic aliases.
package tlsopen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/oittaa/socat/internal/xio"

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
			Label:       s.Type + ":" + addr,
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
	return &xio.Opened{Stream: st, Label: s.Type + ":" + addr}, nil
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

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				xio.ApplyReuse(int(fd), s, true)
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
		Label:       s.Type + ":" + port,
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

// commonNameOption returns openssl-commonname / commonname when the option
// is present with an explicit value, including the empty string.
// Classic: unset → check the dial host; commonname= (empty) → skip the name
// check; commonname=foo → check foo. verify=1 still checks trust.
func commonNameOption(s parse.Spec) (name string, set bool) {
	o, ok := s.OptionNamed("commonname")
	if !ok || !o.Has {
		return "", false
	}
	return o.Value, true
}

// TLSClientConfig builds a crypto/tls client config from TLS/WSS options.
func TLSClientConfig(s parse.Spec, serverName string) (*tls.Config, error) {
	return tlsClientConfig(s, serverName)
}

// TLSServerConfig builds a crypto/tls server config from TLS/WSS-LISTEN options.
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

	cnWant, _ := commonNameOption(s)
	doVerify := verifyEnabled(s)
	needClientCert := doVerify || cnWant != ""

	if needClientCert {
		var roots *x509.CertPool
		if doVerify {
			// Classic: SSL_CTX_set_default_verify_paths when cafile/capath are unset.
			roots, err = loadVerifyRoots(s)
			if err != nil {
				return nil, err
			}
			if roots == nil {
				return nil, fmt.Errorf("tls: no CA roots for verify")
			}
			cfg.ClientCAs = roots
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			roots, err = loadCAPool(s)
			if err != nil {
				return nil, err
			}
			if roots != nil {
				cfg.ClientCAs = roots
			}
			// commonname check only: request a client cert if offered
			cfg.ClientAuth = tls.RequestClientCert
		}
		prev := cfg.VerifyPeerCertificate
		attachPeerVerify(cfg, makeServerVerifyPeer(roots, cnWant, doVerify, prev))
	} else {
		cfg.ClientAuth = tls.NoClientCert
	}
	return cfg, nil
}

// attachPeerVerify sets both VerifyPeerCertificate and VerifyConnection.
// crypto/tls skips VerifyPeerCertificate on session resume; VerifyConnection
// still runs, so a resumed session cannot skip the name/trust check.
func attachPeerVerify(cfg *tls.Config, fn func([][]byte, [][]*x509.Certificate) error) {
	if cfg == nil || fn == nil {
		return
	}
	cfg.VerifyPeerCertificate = fn
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		raws := make([][]byte, len(cs.PeerCertificates))
		for i, c := range cs.PeerCertificates {
			raws[i] = c.Raw
		}
		return fn(raws, nil)
	}
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
		if doVerify {
			if roots == nil {
				return fmt.Errorf("tls: no CA roots for client certificate")
			}
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
	capath := s.OptionValue("capath", "")
	if cafile == "" && capath == "" {
		return nil, nil
	}
	pool := x509.NewCertPool()
	n := 0
	if cafile != "" {
		added, err := appendCABytes(pool, cafile)
		if err != nil {
			return nil, fmt.Errorf("cafile: %w", err)
		}
		n += added
	}
	if capath != "" {
		added, err := appendCAPath(pool, capath)
		if err != nil {
			return nil, err
		}
		n += added
	}
	if n == 0 {
		return nil, fmt.Errorf("cafile/capath: no certificates found")
	}
	return pool, nil
}

// loadVerifyRoots is the trust store for verify=1: cafile/capath, else the system pool
// (classic SSL_CTX_set_default_verify_paths).
func loadVerifyRoots(s parse.Spec) (*x509.CertPool, error) {
	pool, err := loadCAPool(s)
	if err != nil {
		return nil, err
	}
	if pool != nil {
		return pool, nil
	}
	return x509.SystemCertPool()
}

func appendCABytes(pool *x509.CertPool, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if pool.AppendCertsFromPEM(data) {
		return 1, nil
	}
	n := 0
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			continue
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		if c, e := x509.ParseCertificate(data); e == nil {
			pool.AddCert(c)
			return 1, nil
		}
		return 0, fmt.Errorf("%s: no certificates found", path)
	}
	return n, nil
}

func appendCAPath(pool *x509.CertPool, dir string) (int, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("capath: %w", err)
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		p := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			// Hashed OpenSSL capath often uses symlinks; resolve those.
			st, e2 := os.Stat(p)
			if e2 != nil || !st.Mode().IsRegular() {
				continue
			}
		}
		added, err := appendCABytes(pool, p)
		if err != nil {
			continue
		}
		n += added
	}
	if n == 0 {
		return 0, fmt.Errorf("capath %s: no certificates found", dir)
	}
	return n, nil
}

// sniName is the TLS ServerName. Prefer a non-IP check name (commonname=),
// else the dial host when that is not an IP.
func sniName(checkName, dialHost string) string {
	if checkName != "" {
		if ip := net.ParseIP(checkName); ip == nil {
			return checkName
		}
	}
	if dialHost != "" {
		if ip := net.ParseIP(dialHost); ip == nil {
			return dialHost
		}
	}
	return ""
}

// makeVerifyPeer verifies the leaf against roots and checks name via SAN or CN.
// Empty checkName skips the name check (classic empty commonname=).
// Classic test certs often lack SANs; we still allow CN match for the check name.
func makeVerifyPeer(roots *x509.CertPool, checkName string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
			// Classic: empty commonname / empty peername skips the name check.
			return nil
		}
		// RFC 6125 name check (Go VerifyHostname). Classic OPENSSL uses strcmp
		// plus a looser *.domain rule; we keep the Go rules.
		if err := leaf.VerifyHostname(checkName); err == nil {
			return nil
		}
		// CN match for classic test certs / commonname= option.
		if cnMatches(leaf, checkName) {
			return nil
		}
		// Without a matching SAN/CN, fail (OPENSSL_CN_CLIENT_SECURITY:
		// connect 127.0.0.1 without commonname must fail).
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

// WriteTempListenCert writes a short-lived self-signed Ed25519 server
// certificate and key as one PEM file. Listen addresses require this via cert=.
func WriteTempListenCert(dir string) (string, error) {
	cert, err := ephemeralSelfSigned()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "listen.pem")
	if err := writeCertKeyPEM(path, cert); err != nil {
		return "", err
	}
	return path, nil
}

func writeCertKeyPEM(path string, cert tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("tls: empty certificate")
	}
	var b []byte
	for _, der := range cert.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return err
	}
	b = append(b, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	return os.WriteFile(path, b, 0o600)
}

// ephemeralSelfSigned builds a short-lived Ed25519 certificate for tests.
func ephemeralSelfSigned() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "socat-ephemeral"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}
