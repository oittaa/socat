package addr

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

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
	cert, err := ephemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

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
			c.Close()
			errCh <- err
			return
		}
		srvCurve = tc.ConnectionState().CurveID
		_, _ = tc.Write([]byte("pq-ok"))
		tc.Close()
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
	tc.Close()
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
