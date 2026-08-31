//go:build e2e

package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQUICVersionFeature(t *testing.T) {
	out := capabilityOutput(t, "-V")
	if !bytes.Contains(out, []byte("#define WITH_QUIC 1")) {
		t.Fatalf("missing WITH_QUIC in -V:\n%s", out)
	}
}

func TestQUICHelpTypes(t *testing.T) {
	out := capabilityOutput(t, "-h")
	for _, name := range []string{"QUIC", "QUIC-CONNECT", "QUIC-LISTEN"} {
		if !bytes.Contains(out, []byte(name)) {
			t.Fatalf("-h missing %s:\n%s", name, out)
		}
	}
	hh := capabilityOutput(t, "-hh")
	if !bytes.Contains(hh, []byte(" alpn ")) {
		t.Fatalf("-hh missing alpn:\n%s", hh)
	}
}

func TestQUICEcho(t *testing.T) {
	bin := socatBin(t)
	cert := listenCert(t)
	port, srv := startQUICTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, "-t", "2", fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
	})

	payload := fmt.Sprintf("quic-echo %d\n", time.Now().UnixNano())
	var out []byte
	var cliErr bytes.Buffer
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		cliErr.Reset()
		cli := exec.Command(bin, "-t", "2", "stdin!!stdout", fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port))
		cli.Stdin = bytes.NewBufferString(payload)
		cli.Stderr = &cliErr
		out, err = cli.Output()
		if err == nil && string(out) == payload {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
	}
	t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
}

func TestQUICOneWaySenderWaitsForCompleteSink(t *testing.T) {
	bin := socatBin(t)
	path := filepath.Join(t.TempDir(), "sink.bin")
	cert := listenCert(t)
	port, srv := startQUICTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, "-t", "5", "-u",
			fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert),
			"CREATE:"+path,
		)
	})

	payload := bytes.Repeat([]byte{0xa5}, 8<<20)
	cli := exec.Command(bin, "-t", "5", "-u", "STDIN",
		fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", port),
	)
	cli.Stdin = bytes.NewReader(payload)
	if out, err := cli.CombinedOutput(); err != nil {
		t.Fatalf("client: %v: %s (server: %s)", err, out, srv.stderr.String())
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("sink received %d bytes, want %d (server: %s)", len(got), len(payload), srv.stderr.String())
	}
}

func TestQUICVerifyFail(t *testing.T) {
	bin := socatBin(t)
	cert := listenCert(t)
	port, _ := startQUICTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
	})

	cli := exec.Command(bin, "stdin!!stdout", fmt.Sprintf("QUIC:127.0.0.1:%d,verify=1", port))
	cli.Stdin = bytes.NewBufferString("nope")
	if out, err := cli.CombinedOutput(); err == nil {
		t.Fatalf("expected verify failure, got %q", out)
	}
}

func TestQUICVerifySuccess(t *testing.T) {
	bin := socatBin(t)
	certs := writeE2ETrustCerts(t)
	port, srv := startQUICTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, "-t", "2", fmt.Sprintf(
			"QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=1,cert=%s,key=%s,cafile=%s",
			port, certs.serverCert, certs.serverKey, certs.caFile,
		), "PIPE")
	})

	payload := "quic-mtls\n"
	cli := exec.Command(bin, "-t", "2", "stdin!!stdout", fmt.Sprintf(
		"QUIC:127.0.0.1:%d,verify=1,cert=%s,key=%s,cafile=%s,commonname=localhost",
		port, certs.clientCert, certs.clientKey, certs.caFile,
	))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s srv=%s", err, cliErr.String(), srv.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q (srv=%s)", out, payload, srv.stderr.String())
	}
}

func TestTCPToQUICBridge(t *testing.T) {
	bin := socatBin(t)
	cert := listenCert(t)
	quicPort, echo := startQUICTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, "-t", "2", fmt.Sprintf("QUIC-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork,verify=0,cert=%s", port, cert), "PIPE")
	})
	tcpPort, bridge := startTCPTestServer(t, func(port int) *exec.Cmd {
		return exec.Command(bin, "-t", "2",
			fmt.Sprintf("TCP-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			fmt.Sprintf("QUIC:127.0.0.1:%d,verify=0", quicPort),
		)
	})

	payload := fmt.Sprintf("tcp-quic %d\n", time.Now().UnixNano())
	cli := exec.Command(bin, "-t", "2", "stdin!!stdout", fmt.Sprintf("TCP:127.0.0.1:%d", tcpPort))
	var cliErr bytes.Buffer
	cli.Stdin = bytes.NewBufferString(payload)
	cli.Stderr = &cliErr
	out, err := cli.Output()
	if err != nil {
		t.Fatalf("client: %v cli=%s bridge=%s echo=%s", err, cliErr.String(), bridge.stderr.String(), echo.stderr.String())
	}
	if string(out) != payload {
		t.Fatalf("got %q want %q bridge=%s echo=%s", out, payload, bridge.stderr.String(), echo.stderr.String())
	}
}

func TestWaitUDPListenDetectsEarlyExit(t *testing.T) {
	bin := socatBin(t)
	port := 9
	cmd := exec.Command(bin, "NOT-A-REAL-ADDRESS", "PIPE")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	time.Sleep(200 * time.Millisecond)
	err := errWaitUDPListen(port, 2*time.Second, cmd)
	if err == nil {
		t.Fatal("waitUDPListen succeeded after the UDP server exited")
	}
	if !strings.Contains(err.Error(), "exited before listening") {
		t.Fatalf("error=%v", err)
	}
}

type e2eTrustCerts struct {
	caFile, serverCert, serverKey, clientCert, clientKey string
}

func writeE2ETrustCerts(t *testing.T) e2eTrustCerts {
	t.Helper()
	dir := t.TempDir()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "socat-e2e-ca"},
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
	leaf := func(cn string, serial int64, usage []x509.ExtKeyUsage, ips []net.IP, dns []string) (string, string) {
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
		return writePEM(cn+".crt", "CERTIFICATE", der),
			writePEM(cn+".key", "PRIVATE KEY", keyDER)
	}
	srvCert, srvKey := leaf("localhost", 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		[]net.IP{net.ParseIP("127.0.0.1")}, []string{"localhost"})
	cliCert, cliKey := leaf("client", 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil)
	return e2eTrustCerts{
		caFile:     writePEM("ca.crt", "CERTIFICATE", caDER),
		serverCert: srvCert,
		serverKey:  srvKey,
		clientCert: cliCert,
		clientKey:  cliKey,
	}
}
