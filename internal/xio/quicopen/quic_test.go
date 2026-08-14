package quicopen

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/fileopen"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	pc.Close()
	return port
}

func waitUDPPort(t *testing.T, port int, d time.Duration) {
	t.Helper()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		pc, err := net.ListenPacket("udp4", addr)
		if err != nil {
			return
		}
		pc.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("listen not ready")
}

func startListenPIPE(t *testing.T, ctx context.Context, spec string) {
	t.Helper()
	ls, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	pipe, err := parse.ParseChannel("PIPE")
	if err != nil {
		t.Fatal(err)
	}
	g := &xio.Global{Log: logx.New(), Linger: 200 * time.Millisecond}
	go func() { _ = xio.Run(ctx, ls, pipe, g) }()
}

func echoRoundtrip(t *testing.T, st io.ReadWriter, payload []byte) {
	t.Helper()
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

func TestQUICListenConnectEcho(t *testing.T) {
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0", port))
	waitUDPPort(t, port, 2*time.Second)

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	echoRoundtrip(t, o.Stream, []byte("quic-roundtrip"))
}

func TestQUICVerifyFailsWithoutTrust(t *testing.T) {
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0", port))
	waitUDPPort(t, port, 2*time.Second)

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=1", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected verify failure against ephemeral cert")
	}
}

func TestQUICVerifySucceedsWithTrustedCerts(t *testing.T) {
	certs := writeTrustCerts(t)
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf(
		"QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=1,cert=%s,key=%s,cafile=%s",
		port, certs.serverCert, certs.serverKey, certs.caFile,
	))
	waitUDPPort(t, port, 2*time.Second)

	cs, err := parse.ParseSpec(fmt.Sprintf(
		"QUIC:127.0.0.1:%d,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
		port, certs.clientCert, certs.clientKey, certs.caFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	echoRoundtrip(t, o.Stream, []byte("quic-verify-ok"))
}

func TestQUICALPNMismatch(t *testing.T) {
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,alpn=socat", port))
	waitUDPPort(t, port, 2*time.Second)

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0,alpn=other", port))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected ALPN mismatch")
	}
}

func TestQUICListenForkTwoClients(t *testing.T) {
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0", port))
	waitUDPPort(t, port, 2*time.Second)

	for i, msg := range []string{"one", "two"} {
		cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
		if err != nil {
			t.Fatal(err)
		}
		o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
		if err != nil {
			t.Fatalf("client %d: %v", i, err)
		}
		echoRoundtrip(t, o.Stream, []byte(msg))
		o.Close()
	}
}

func TestQUICHalfClose(t *testing.T) {
	port := freeUDPPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	startListenPIPE(t, ctx, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0", port))
	waitUDPPort(t, port, 2*time.Second)

	cs, err := parse.ParseSpec(fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	o, err := openQUICConnect(ctx, cs, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	payload := []byte("half-close")
	if _, err := o.Stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := o.Stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(o.Stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("got %q", got)
	}
}

type trustCerts struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
}

func writeTrustCerts(t *testing.T) trustCerts {
	t.Helper()
	dir := t.TempDir()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "socat-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	writePEM := func(name, typ string, der []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	leaf := func(cn string, serial int64, usage []x509.ExtKeyUsage, ips []net.IP, dns []string) (certPath, keyPath string) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  usage,
			IPAddresses:  ips,
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return writePEM(cn+".crt", "CERTIFICATE", der),
			writePEM(cn+".key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	}

	srvCert, srvKey := leaf("localhost", 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	cliCert, cliKey := leaf("client", 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	return trustCerts{
		caFile:     writePEM("ca.crt", "CERTIFICATE", caDER),
		serverCert: srvCert,
		serverKey:  srvKey,
		clientCert: cliCert,
		clientKey:  cliKey,
	}
}
