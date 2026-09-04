package tlsopen

import (
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testcert"
	"github.com/oittaa/socat/internal/xio"
)

func TestSocketTimeoutsDoNotPoisonTLSConnection(t *testing.T) {
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	clientRaw, serverRaw := net.Pipe()
	defer func() { _ = clientRaw.Close() }()
	defer func() { _ = serverRaw.Close() }()

	spec := parse.Spec{Options: []parse.Option{
		{Name: "rcvtimeo", Value: "0.02", Has: true},
		{Name: "sndtimeo", Value: "0.02", Has: true},
	}}
	timeoutRaw, err := xio.NewSocketTimeoutConn(spec, clientRaw)
	if err != nil {
		t.Fatal(err)
	}
	client := tls.Client(timeoutRaw, &tls.Config{InsecureSkipVerify: true})
	server := tls.Server(serverRaw, &tls.Config{Certificates: []tls.Certificate{cert}})

	serverHandshake := make(chan error, 1)
	go func() { serverHandshake <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	timeoutRaw.EnableSocketTimeouts()

	readBuf := make([]byte, len("late-read"))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(client, readBuf)
		readDone <- err
	}()
	time.Sleep(80 * time.Millisecond)
	if _, err := server.Write([]byte("late-read")); err != nil {
		t.Fatalf("server.Write: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("client ReadFull after receive timeouts: %v", err)
	}

	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("late-write"))
		writeDone <- err
	}()
	time.Sleep(80 * time.Millisecond)
	writeBuf := make([]byte, len("late-write"))
	if _, err := io.ReadFull(server, writeBuf); err != nil {
		t.Fatalf("server ReadFull: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("client Write after send timeouts: %v", err)
	}
	if string(readBuf) != "late-read" || string(writeBuf) != "late-write" {
		t.Fatalf("payloads read=%q write=%q", readBuf, writeBuf)
	}
}

func TestLoadKeyPairRejectsDSA(t *testing.T) {
	// Type label alone is enough for our early rejection (body need not parse).
	pemData := []byte(`-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHH0V2o0X3dMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3RjYTAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBExDzANBgNVBAMM
BnRlc3RjYTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAu1SU1F4ByV2/9b0E
-----END CERTIFICATE-----
-----BEGIN DSA PRIVATE KEY-----
MIIBuwIBAAKBgQDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
-----END DSA PRIVATE KEY-----
`)
	dir := t.TempDir()
	path := filepath.Join(dir, "dsa.pem")
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadKeyPair(path, "")
	if err == nil {
		t.Fatal("expected DSA rejection")
	}
	if !errors.Is(err, errDSAUnsupported) {
		t.Fatalf("got %v want errDSAUnsupported", err)
	}
}

func TestPostQuantumHybridKeyExchange(t *testing.T) {
	// Classic test.sh has no post-quantum coverage. Go 1.24+ crypto/tls
	// defaults to the X25519MLKEM768 hybrid KEM; assert we negotiate it.
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srvCfg := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}
	cliCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
	}

	errCh := make(chan error, 1)
	var srvCurve tls.CurveID
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, srvCfg)
		if err := tc.Handshake(); err != nil {
			_ = c.Close()
			errCh <- err
			return
		}
		srvCurve = tc.ConnectionState().CurveID
		_, _ = tc.Write([]byte("pq-ok"))
		_ = tc.Close()
		errCh <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, cliCfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	cliCurve := tc.ConnectionState().CurveID
	buf := make([]byte, 16)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = tc.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "pq-ok" {
		t.Fatalf("payload %q", buf[:n])
	}
	if cliCurve != tls.X25519MLKEM768 {
		t.Fatalf("client CurveID=%v want X25519MLKEM768", cliCurve)
	}
	if srvCurve != tls.X25519MLKEM768 {
		t.Fatalf("server CurveID=%v want X25519MLKEM768", srvCurve)
	}
}

func TestHandshakeMLDSA(t *testing.T) {
	// Go 1.27 crypto/tls advertises ML-DSA signature schemes on TLS 1.3.
	// loadKeyPair must accept the PKCS#8 PEMs and the handshake must use them.
	bundle, err := testcert.WriteMLDSA44Trust(t.TempDir())
	if err != nil {
		if strings.Contains(err.Error(), "unavailable") {
			t.Skip(err.Error())
		}
		t.Fatal(err)
	}
	srvCert, err := loadKeyPair(bundle.ServerCert, bundle.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := srvCert.PrivateKey.(*mldsa.PrivateKey); !ok {
		t.Fatalf("server key %T, want *mldsa.PrivateKey", srvCert.PrivateKey)
	}
	cliCert, err := loadKeyPair(bundle.ClientCert, bundle.ClientKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(bundle.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("cafile: no certificates")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	srvCfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	cliCfg := &tls.Config{
		Certificates: []tls.Certificate{cliCert},
		RootCAs:      roots,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS13,
	}

	errCh := make(chan error, 1)
	var srvPeer *x509.Certificate
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, srvCfg)
		if err := tc.Handshake(); err != nil {
			_ = c.Close()
			errCh <- err
			return
		}
		st := tc.ConnectionState()
		if len(st.PeerCertificates) > 0 {
			srvPeer = st.PeerCertificates[0]
		}
		_, _ = tc.Write([]byte("mldsa-ok"))
		_ = tc.Close()
		errCh <- nil
	}()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(raw, cliCfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	st := tc.ConnectionState()
	buf := make([]byte, 16)
	n, err := tc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	_ = tc.Close()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "mldsa-ok" {
		t.Fatalf("payload %q", buf[:n])
	}
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("version=%#x want TLS 1.3", st.Version)
	}
	if len(st.PeerCertificates) == 0 {
		t.Fatal("client saw no peer certificate")
	}
	assertMLDSA44Cert(t, "server leaf", st.PeerCertificates[0])
	if srvPeer == nil {
		t.Fatal("server saw no client certificate")
	}
	assertMLDSA44Cert(t, "client leaf", srvPeer)
}

func assertMLDSA44Cert(t *testing.T, what string, cert *x509.Certificate) {
	t.Helper()
	if cert.SignatureAlgorithm != x509.MLDSA44 {
		t.Fatalf("%s SignatureAlgorithm=%v want MLDSA44", what, cert.SignatureAlgorithm)
	}
	if cert.PublicKeyAlgorithm != x509.MLDSA {
		t.Fatalf("%s PublicKeyAlgorithm=%v want MLDSA", what, cert.PublicKeyAlgorithm)
	}
	if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
		t.Fatalf("%s public key %T, want *mldsa.PublicKey", what, cert.PublicKey)
	}
}

func TestTLSClientVerifyConnectionSet(t *testing.T) {
	ca, _, err := testCAAndLeaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "verify", Value: "1", Has: true},
			{Name: "cafile", Value: caPath, Has: true},
			{Name: "commonname", Value: "localhost", Has: true},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("VerifyPeerCertificate is nil")
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("VerifyConnection is nil; resume would skip the name check")
	}
}

func TestTLSServerVerifyConnectionSet(t *testing.T) {
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writeTLSCert(t, dir, "srv", cert)
	cfg, err := tlsServerConfig(parse.Spec{
		Type: "TLS-LISTEN",
		Options: []parse.Option{
			{Name: "cert", Value: certPath, Has: true},
			{Name: "verify", Value: "1", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyPeerCertificate == nil || cfg.VerifyConnection == nil {
		t.Fatal("server verify hooks missing; resume would skip client name/trust check")
	}
}

func TestTLSServerVerifyRequiresClientAuthUsage(t *testing.T) {
	tests := []struct {
		name    string
		usage   x509.ExtKeyUsage
		wantErr bool
	}{
		{name: "client-auth", usage: x509.ExtKeyUsageClientAuth},
		{name: "server-auth", usage: x509.ExtKeyUsageServerAuth, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca, leaf, _, err := testCAAndLeafKeyUsage("peer", tc.usage)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			err = makeServerVerifyPeer(roots, "", true, nil)([][]byte{leaf.Raw}, nil)
			if tc.wantErr && err == nil {
				t.Fatal("server accepted a certificate without the client-auth usage")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("server rejected a client-auth certificate: %v", err)
			}
		})
	}
}

func TestTLSClientEmptyCommonNameKeepsDialSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "commonname", Value: "", Has: true},
			{Name: "verify", Value: "0"},
		},
	}, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "example.com" {
		t.Fatalf("ServerName=%q want example.com", cfg.ServerName)
	}
}

func TestTLSClientNoSNI(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "openssl-no-sni"},
			{Name: "verify", Value: "0"},
		},
	}, "badssl.com")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "" {
		t.Fatalf("openssl-no-sni: ServerName=%q want empty", cfg.ServerName)
	}
}

func TestTLSServerConfigWithoutCert(t *testing.T) {
	cfg, err := tlsServerConfig(parse.Spec{Type: "TLS-LISTEN", Params: []string{"443"}})
	if err != nil {
		t.Fatalf("unexpected error without cert=: %v", err)
	}
	if len(cfg.Certificates) != 0 {
		t.Fatalf("expected empty Certificates, got %d", len(cfg.Certificates))
	}
}

func TestTLSListenWithoutCertAcceptTimeout(t *testing.T) {
	spec, err := parse.ParseSpec("TLS-LISTEN:0,reuseaddr,bind=127.0.0.1,verify=0,accept-timeout=0.01")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	o, err := openTLSListen(ctx, spec, xio.ModeRDWR, g)
	if o != nil {
		defer func() { _ = o.Close() }()
	}
	if !errors.Is(err, xio.ErrAcceptTimeout) {
		t.Fatalf("got err=%v, want ErrAcceptTimeout", err)
	}
}

func TestTLSConfigsRejectOpenSSLMethod(t *testing.T) {
	for _, optionName := range []string{"openssl-method", "opensslmethod"} {
		for _, method := range []string{"SSL3", "SSL23", "DTLS1", "DTLS1.2"} {
			name := optionName + "=" + method
			t.Run("client/"+name, func(t *testing.T) {
				spec := parse.Spec{
					Type: "OPENSSL",
					Options: []parse.Option{{
						Name:  optionName,
						Value: method,
						Has:   true,
					}},
				}
				_, err := tlsClientConfig(spec, "localhost")
				if err == nil {
					t.Fatal("expected unsupported method error")
				}
				if !strings.Contains(err.Error(), optionName) || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("unexpected error: %v", err)
				}
			})

			t.Run("server/"+name, func(t *testing.T) {
				spec := parse.Spec{
					Type: "OPENSSL-LISTEN",
					Options: []parse.Option{{
						Name:  optionName,
						Value: method,
						Has:   true,
					}},
				}
				_, err := tlsServerConfig(spec)
				if err == nil {
					t.Fatal("expected unsupported method error")
				}
				if !strings.Contains(err.Error(), optionName) || !strings.Contains(err.Error(), "not supported") {
					t.Fatalf("unexpected error: %v", err)
				}
			})
		}
	}
}

func TestTLSClientSNIHost(t *testing.T) {
	cfg, err := tlsClientConfig(parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "openssl-snihost", Value: "sni.example", Has: true},
			{Name: "verify", Value: "0"},
		},
	}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerName != "sni.example" {
		t.Fatalf("ServerName=%q", cfg.ServerName)
	}
}

func TestTLSServerVerifyUsesSystemRoots(t *testing.T) {
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writeTLSCert(t, dir, "srv", cert)
	cfg, err := tlsServerConfig(parse.Spec{
		Type:   "TLS-LISTEN",
		Params: []string{"443"},
		Options: []parse.Option{
			{Name: "cert", Value: certPath, Has: true},
			{Name: "verify", Value: "1", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth=%v want RequireAndVerifyClientCert", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs is nil; want system or explicit pool")
	}
}

func TestTLSServerVerify0IgnoresCommonName(t *testing.T) {
	// Classic SSL_VERIFY_NONE: no client cert request; commonname is ignored.
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := writeTLSCert(t, dir, "srv", cert)
	cfg, err := tlsServerConfig(parse.Spec{
		Type: "TLS-LISTEN",
		Options: []parse.Option{
			{Name: "cert", Value: certPath, Has: true},
			{Name: "verify", Value: "0", Has: true},
			{Name: "commonname", Value: "onlyyou", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth=%v want NoClientCert", cfg.ClientAuth)
	}
	if cfg.VerifyPeerCertificate != nil || cfg.VerifyConnection != nil {
		t.Fatal("verify=0 must not attach client-cert hooks")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, cfg)
		errCh <- tc.Handshake()
		_ = tc.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	cli := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := cli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = cli.Close()
	if herr := <-errCh; herr != nil {
		t.Fatalf("server handshake with verify=0,commonname=onlyyou: %v", herr)
	}
}

func TestTLSServerVerifyRejectsUntrustedClient(t *testing.T) {
	srv, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	dir := t.TempDir()
	srvPath := writeTLSCert(t, dir, "srv", srv)
	sCfg, err := tlsServerConfig(parse.Spec{
		Type: "TLS-LISTEN",
		Options: []parse.Option{
			{Name: "cert", Value: srvPath, Has: true},
			{Name: "verify", Value: "1", Has: true},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, sCfg)
		errCh <- tc.Handshake()
		_ = tc.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	tc := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{cli},
	})
	_ = tc.Handshake()
	_ = tc.Close()
	herr := <-errCh
	if herr == nil {
		t.Fatal("server accepted untrusted client cert")
	}
}

func TestCommonNameOption(t *testing.T) {
	unset, err := parse.ParseSpec("TLS:127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(unset); set || name != "" {
		t.Fatalf("unset: name=%q set=%v", name, set)
	}

	empty, err := parse.ParseSpec("TLS:127.0.0.1:443,commonname=")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(empty); !set || name != "" {
		t.Fatalf("empty: name=%q set=%v", name, set)
	}

	alias, err := parse.ParseSpec("TLS:127.0.0.1:443,openssl-commonname=")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(alias); !set || name != "" {
		t.Fatalf("openssl-commonname=: name=%q set=%v", name, set)
	}

	named, err := parse.ParseSpec("TLS:127.0.0.1:443,commonname=localhost")
	if err != nil {
		t.Fatal(err)
	}
	if name, set := commonNameOption(named); !set || name != "localhost" {
		t.Fatalf("named: name=%q set=%v", name, set)
	}
}

func TestTLSClientCommonNameCheck(t *testing.T) {
	// Cert is for DNS:localhost only. Dial target is 127.0.0.1.
	// Classic: no commonname → name check fails; commonname=localhost → pass;
	// empty commonname= → skip name check, still verify the CA.
	ca, leaf, leafKey, err := testCAAndLeafKey("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	srvCert := tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey}

	cases := []struct {
		name    string
		opts    []parse.Option
		wantErr bool
	}{
		{
			name: "unset-checks-dial-host",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
			},
			wantErr: true,
		},
		{
			name: "commonname-localhost",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
				{Name: "commonname", Value: "localhost", Has: true},
			},
		},
		{
			name: "empty-commonname-skips-name",
			opts: []parse.Option{
				{Name: "verify", Value: "1", Has: true},
				{Name: "cafile", Value: caPath, Has: true},
				{Name: "commonname", Value: "", Has: true},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handshakeClientToLocal(t, srvCert, parse.Spec{Type: "TLS", Options: tc.opts}, "127.0.0.1")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected name-check failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
		})
	}
}

func TestTLSClientEmptyCommonNameStillVerifiesTrust(t *testing.T) {
	// Empty commonname= must not become verify=0: an untrusted leaf still fails.
	leaf, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ca, _, err := testCAAndLeaf("other")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	err = handshakeClientToLocal(t, leaf, parse.Spec{
		Type: "TLS",
		Options: []parse.Option{
			{Name: "verify", Value: "1", Has: true},
			{Name: "cafile", Value: caPath, Has: true},
			{Name: "commonname", Value: "", Has: true},
		},
	}, "127.0.0.1")
	if err == nil {
		t.Fatal("expected trust failure with empty commonname=")
	}
}

func handshakeClientToLocal(t *testing.T, srvCert tls.Certificate, spec parse.Spec, dialName string) error {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{srvCert}})
		errCh <- tc.Handshake()
		_ = tc.Close()
	}()
	cfg, err := tlsClientConfig(spec, dialName)
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	cli := tls.Client(raw, cfg)
	herr := cli.Handshake()
	_ = cli.Close()
	<-errCh
	return herr
}

func TestLoadCAPath(t *testing.T) {
	ca, leaf, err := testCAAndLeaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	pool, err := loadCAPool(parse.Spec{Options: []parse.Option{{Name: "capath", Value: dir, Has: true}}})
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: pool, DNSName: "localhost"}
	if _, err := leaf.Verify(opts); err != nil {
		t.Fatalf("capath verify: %v", err)
	}
}

func TestTLSCipherListCompatibility(t *testing.T) {
	spec, err := parse.ParseSpec("OPENSSL:localhost:443,cipher=ECDHE-ECDSA-AES256-GCM-SHA384")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(spec, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	if !slices.Equal(cfg.CipherSuites, want) {
		t.Fatalf("CipherSuites=%#v want %#v", cfg.CipherSuites, want)
	}
	if cfg.MaxVersion != 0 {
		t.Fatalf("cipher list must not disable TLS 1.3; MaxVersion=%#x", cfg.MaxVersion)
	}
}

func TestTLSProtocolVersionOptions(t *testing.T) {
	spec, err := parse.ParseSpec("TLS:localhost:443,min-version=TLSv1.1,openssl-max-proto-version=TLS1.3,verify=0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := tlsClientConfig(spec, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS11 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("protocol bounds=%#x..%#x", cfg.MinVersion, cfg.MaxVersion)
	}
}

func TestTLSProtocolVersionOptionsRejectInvalidBounds(t *testing.T) {
	for _, text := range []string{
		"TLS:localhost:443,min-version=DTLS1.2,verify=0",
		"TLS:localhost:443,min-version=TLS1.3,max-version=TLS1.2,verify=0",
	} {
		spec, err := parse.ParseSpec(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tlsClientConfig(spec, "localhost"); err == nil {
			t.Fatalf("tlsClientConfig(%q) succeeded", text)
		}
	}
}

func TestTLSCipherListRejectsUnsupportedPolicy(t *testing.T) {
	for _, value := range []string{"aNULL", "DEFAULT", "TLS_AES_128_GCM_SHA256"} {
		spec, err := parse.ParseSpec("TLS:localhost:443,ciphers=" + value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tlsClientConfig(spec, "localhost"); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("ciphers=%q error=%v", value, err)
		}
	}
}

func writeTLSCert(t *testing.T, dir, name string, cert tls.Certificate) string {
	t.Helper()
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
	path := filepath.Join(dir, name+".pem")
	var b []byte
	for _, der := range cert.Certificate {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey); err == nil {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})...)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testCAAndLeaf(dns string) (*x509.Certificate, *x509.Certificate, error) {
	ca, leaf, _, err := testCAAndLeafKey(dns)
	return ca, leaf, err
}

func testCAAndLeafKey(dns string) (*x509.Certificate, *x509.Certificate, ed25519.PrivateKey, error) {
	return testCAAndLeafKeyUsage(dns, x509.ExtKeyUsageServerAuth)
}

// testCAAndLeafKeyUsage delegates to the shared testcert generators; the
// returned shapes keep the historical helper signature.
func testCAAndLeafKeyUsage(dns string, usage x509.ExtKeyUsage) (*x509.Certificate, *x509.Certificate, ed25519.PrivateKey, error) {
	a, err := testcert.NewAuthority("test-ca")
	if err != nil {
		return nil, nil, nil, err
	}
	l, err := a.Leaf(dns, []x509.ExtKeyUsage{usage}, nil, []string{dns})
	if err != nil {
		return nil, nil, nil, err
	}
	return a.Cert, l.Cert, l.Key, nil
}

// cnGateLeaf builds a server certificate with explicit CN/SAN control so the
// CN-fallback gating can be exercised.
func cnGateLeaf(t *testing.T, a *testcert.Authority, cn string, dns []string, ips []net.IP) tls.Certificate {
	t.Helper()
	l, err := a.Leaf(cn, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ips, dns)
	if err != nil {
		t.Fatal(err)
	}
	return l.TLS()
}

func TestTLSClientCNFallbackGatedOnSANs(t *testing.T) {
	// RFC 6125 §6.4.4 / OpenSSL X509_check_host parity: the CN is consulted
	// only when the certificate has no subjectAltName entries at all.
	a, err := testcert.NewAuthority("cn-gate-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := testcert.WriteCertPEM(caPath, a.DER); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		cert    tls.Certificate
		wantErr bool
	}{
		{
			// Classic testcert.conf shape: CN only, no SANs → CN match works.
			name: "cn-only-cert-matches",
			cert: cnGateLeaf(t, a, "localhost", nil, nil),
		},
		{
			// SAN present and matching → normal path.
			name: "matching-dns-san-passes",
			cert: cnGateLeaf(t, a, "localhost", []string{"localhost"}, nil),
		},
		{
			// Mixed-cert bypass: matching CN beside a non-matching DNS SAN.
			name:    "cn-beside-other-dns-san-fails",
			cert:    cnGateLeaf(t, a, "localhost", []string{"other.example.com"}, nil),
			wantErr: true,
		},
		{
			// An IP SAN also blocks the CN fallback even when it matches the
			// dial address; the name check asked for "localhost".
			name:    "cn-beside-ip-san-fails",
			cert:    cnGateLeaf(t, a, "localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}),
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handshakeClientToLocal(t, tc.cert, parse.Spec{
				Type: "TLS",
				Options: []parse.Option{
					{Name: "verify", Value: "1", Has: true},
					{Name: "cafile", Value: caPath, Has: true},
					{Name: "commonname", Value: "localhost", Has: true},
				},
			}, "127.0.0.1")
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected hostname mismatch failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
		})
	}
}
