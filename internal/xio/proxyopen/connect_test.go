package proxyopen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func connectEchoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		buf := make([]byte, 8192)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	})
}

func connectForbidHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	})
}

func echoViaPROXY(t *testing.T, spec string) {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	o, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	payload := []byte("proxy-connect-ok")
	if _, err := o.Stream.Write(payload); err != nil {
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

func TestH2CONNECTEcho(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0", port))
}

func TestH2CONNECTNon200(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectForbidHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec(fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=0", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected CONNECT failure")
	}
}

func TestH2CONNECTVerifyFail(t *testing.T) {
	srv := httptest.NewUnstartedServer(connectEchoHandler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s, err := parse.ParseSpec(fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=1", port))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()}); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestH2CONNECTVerifySuccess(t *testing.T) {
	certs := writeTrustCerts(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{certs.serverTLS},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certs.pool,
	})
	srv := &http.Server{Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(tlsLn) }()
	defer func() { _ = srv.Close() }()

	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=2,proxyport=%s,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
		port, certs.clientCert, certs.clientKey, certs.caFile,
	))
}

func TestH2cCONNECTEcho(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	var p http.Protocols
	p.SetHTTP1(false)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: connectEchoHandler(), Protocols: &p}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	echoViaPROXY(t, fmt.Sprintf("PROXY:127.0.0.1:127.0.0.1:9,http-version=2,h2c,proxyport=%s", port))
}

func TestH3CONNECTEcho(t *testing.T) {
	certs := writeTrustCerts(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certs.serverTLS},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(pc) }()
	defer func() { _ = srv.Close() }()

	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%s,verify=0",
		port,
	))
}

func TestH3CONNECTInvalidMembershipInterface(t *testing.T) {
	const missing = "no-such-iface-socat-test"
	s, err := parse.ParseSpec(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=1,verify=0,ipv6-join-group=[ff02::1]:" + missing,
	)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	_, err = openProxyConnect(ctx, s, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("HTTP/3 PROXY ignored ipv6-join-group (silent no-op)")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("membership error took %v; option was processed after HTTP/3 negotiation", elapsed)
	}
	if !strings.Contains(err.Error(), missing) && !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v want %q or Windows unsupported", err, missing)
	}
}

func TestH3CONNECTVerifySuccess(t *testing.T) {
	certs := writeTrustCerts(t)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(pc.LocalAddr().(*net.UDPAddr).Port)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{certs.serverTLS},
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certs.pool,
	}
	srv := &http3.Server{TLSConfig: tlsCfg, Handler: connectEchoHandler()}
	go func() { _ = srv.Serve(pc) }()
	defer func() { _ = srv.Close() }()

	echoViaPROXY(t, fmt.Sprintf(
		"PROXY:127.0.0.1:127.0.0.1:9,http-version=3,proxyport=%s,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
		port, certs.clientCert, certs.clientKey, certs.caFile,
	))
}

type trustCerts struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
	serverTLS                                            tls.Certificate
	pool                                                 *x509.CertPool
}

func writeTrustCerts(t *testing.T) trustCerts {
	t.Helper()
	dir := t.TempDir()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "socat-proxy-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caKey)
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
	leaf := func(cn string, serial int64, usage []x509.ExtKeyUsage, ips []net.IP, dns []string) (string, string, tls.Certificate) {
		t.Helper()
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  usage,
			IPAddresses:  ips,
			DNSNames:     dns,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		certPath := writePEM(cn+".crt", "CERTIFICATE", der)
		keyPath := writePEM(cn+".key", "PRIVATE KEY", keyDER)
		tc, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath, tc
	}
	srvCert, srvKey, srvTLS := leaf("localhost", 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	cliCert, cliKey, _ := leaf("client", 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return trustCerts{
		caFile:     writePEM("ca.crt", "CERTIFICATE", caDER),
		serverCert: srvCert,
		serverKey:  srvKey,
		clientCert: cliCert,
		clientKey:  cliKey,
		serverTLS:  srvTLS,
		pool:       pool,
	}
}
