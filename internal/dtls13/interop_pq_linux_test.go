//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInteropOpenSSLMLDSA(t *testing.T) {
	tools := loadOracleTools(t)
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			cert, roots := mldsaCertificate(t, parameters)
			testOpenSSLClientMTU(t, tools, cert, roots, 4096, &parameters)
		})
	}
}

func TestInteropOpenSSLClientSmallMTUPQ(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("ecdsa/"+strconv.Itoa(mtu), func(t *testing.T) {
			testOpenSSLClientMTU(t, tools, cert, roots, mtu, nil)
		})
	}
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		for _, mtu := range []int{1200, 512, 256} {
			t.Run(parameters.String()+"/"+strconv.Itoa(mtu), func(t *testing.T) {
				cert, roots := mldsaCertificate(t, parameters)
				p := parameters
				testOpenSSLClientMTU(t, tools, cert, roots, mtu, &p)
			})
		}
	}
}

func TestInteropOpenSSLServer(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, suite := range defaultCipherSuites() {
		for _, group := range defaultGroups() {
			t.Run(fmt.Sprintf("%x/%s", suite, group), func(t *testing.T) {
				testOpenSSLServer(t, tools, cert, roots, suite, group)
			})
		}
	}
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			cert, roots := mldsaCertificate(t, parameters)
			testOpenSSLServer(t, tools, cert, roots, chaCha20Poly1305, tls.X25519MLKEM768)
		})
	}
}

func TestInteropOpenSSLServerSmallMTUPQ(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("ecdsa/"+strconv.Itoa(mtu), func(t *testing.T) {
			testOpenSSLServerMTU(t, tools, cert, roots, chaCha20Poly1305, tls.X25519MLKEM768, mtu)
		})
	}
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		for _, mtu := range []int{1200, 512, 256} {
			t.Run(parameters.String()+"/"+strconv.Itoa(mtu), func(t *testing.T) {
				cert, roots := mldsaCertificate(t, parameters)
				testOpenSSLServerMTU(t, tools, cert, roots, chaCha20Poly1305, tls.X25519MLKEM768, mtu)
			})
		}
	}
}

func TestInteropOpenSSLServerSmallMTUPQHandshakeLoss(t *testing.T) {
	tools := loadOracleTools(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("ML-DSA-44/"+strconv.Itoa(mtu), func(t *testing.T) {
			cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
			testOpenSSLServerMTULoss(t, tools, cert, roots, chaCha20Poly1305, tls.X25519MLKEM768, mtu, 1)
		})
	}
}

type dropFirstPlainHandshake struct {
	net.PacketConn
	remaining int
}

func (c *dropFirstPlainHandshake) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.remaining > 0 && len(p) > 0 && p[0] == contentHandshake {
		c.remaining--
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

type loggedPacketConn struct {
	net.PacketConn
	sent, recv []int
}

func (c *loggedPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err == nil {
		c.sent = append(c.sent, n)
	}
	return n, err
}

func (c *loggedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.recv = append(c.recv, n)
	}
	return n, addr, err
}

func summarizeSizes(sizes []int) string {
	if len(sizes) == 0 {
		return "none"
	}
	minSize, maxSize, total := sizes[0], sizes[0], 0
	for _, n := range sizes {
		minSize = min(minSize, n)
		maxSize = max(maxSize, n)
		total += n
	}
	return fmt.Sprintf("n=%d min=%d max=%d total=%d last=%d", len(sizes), minSize, maxSize, total, sizes[len(sizes)-1])
}

func testOpenSSLServerMTULoss(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, group tls.CurveID, mtu, drop int) {
	t.Helper()
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	mtuArg := strconv.Itoa(mtu)
	msgFile := ""
	if os.Getenv("SOCAT_DTLS13_OPENSSL_MSG") != "" {
		msgFile = t.TempDir() + "/openssl.msg"
	}
	args := []string{"s_server", "-dtls1_3", "-quiet", "-ign_eof", "-mtu", mtuArg, "-naccept", "1", "-accept", address.String(), "-Verify", "1", "-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile, "-groups", oracleGroupName(group), "-ciphersuites", tls.CipherSuiteName(suite)}
	if msgFile != "" {
		args = append(args, "-msg", "-msgfile", msgFile)
	}
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, args...)
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = stdin
	runOracle(t, command)
	logged := &loggedPacketConn{PacketConn: udpForOracle(t)}
	transport := net.PacketConn(logged)
	if drop > 0 {
		transport = &dropFirstPlainHandshake{PacketConn: transport, remaining: drop}
	}
	t.Cleanup(func() {
		t.Logf("client UDP sent %s recv %s mtu=%d", summarizeSizes(logged.sent), summarizeSizes(logged.recv), mtu)
		if msgFile != "" {
			if data, err := os.ReadFile(msgFile); err == nil && len(data) != 0 {
				t.Logf("openssl -msg:\n%s", data)
			}
		}
	})
	client, err := Client(ctx, transport, address, &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{group}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if state.Version != version13 || state.CipherSuite != suite || state.CurveID != group || len(state.VerifiedChains) == 0 {
		t.Fatal("negotiated algorithms or certificate verification missing")
	}
	marker := []byte("openssl-server-echo\n")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := client.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("OpenSSL echo: %q, %v", buffer[:n], err)
	}
}

func testOpenSSLServer(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, group tls.CurveID) {
	t.Helper()
	testOpenSSLServerMTU(t, tools, cert, roots, suite, group, 4096)
}

func testOpenSSLServerMTU(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, group tls.CurveID, mtu int) {
	t.Helper()
	testOpenSSLServerMTULoss(t, tools, cert, roots, suite, group, mtu, 0)
}

func testOpenSSLClientMTU(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, mtu int, parameters *mldsa.Parameters) {
	t.Helper()
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn := udpForOracle(t)
	logged := &loggedPacketConn{PacketConn: conn}
	listener, err := Listen(logged, &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, CipherSuites: []uint16{chaCha20Poly1305}, MTU: mtu})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Cleanup(func() {
		t.Logf("listener UDP sent %s recv %s mtu=%d", summarizeSizes(logged.sent), summarizeSizes(logged.recv), mtu)
	})
	marker := []byte("openssl-client-echo\n")
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, "s_client", "-dtls1_3", "-quiet", "-ign_eof", "-mtu", strconv.Itoa(mtu), "-connect", conn.LocalAddr().String(), "-verify_hostname", "localhost", "-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile, "-groups", "X25519MLKEM768", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256")
	command.Stdin = strings.NewReader(string(marker))
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	state := peer.(*Conn).ConnectionState()
	if state.Version != version13 || state.CurveID != tls.X25519MLKEM768 || state.CipherSuite != chaCha20Poly1305 || len(state.VerifiedChains) == 0 {
		t.Fatal("negotiated algorithms or certificate verification missing")
	}
	if parameters != nil {
		key, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey)
		if !ok || key.Parameters() != *parameters {
			t.Fatal("ML-DSA client authentication missing")
		}
	}
	buffer := make([]byte, 1024)
	n, err := peer.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("data: %q, %v", buffer[:n], err)
	}
	if _, err := peer.Write(marker); err != nil {
		t.Fatal(err)
	}
	if err := peer.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), marker) {
		t.Fatal("OpenSSL did not verify and decrypt our response")
	}
}
