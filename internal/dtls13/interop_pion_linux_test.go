//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

func pionPQArgs(suite uint16, mtu int, extra ...string) []string {
	return append(extra, "-mtu", strconv.Itoa(mtu), "-group", "X25519MLKEM768", "-cipher", tls.CipherSuiteName(suite), "-migrate=false")
}

func pionPQConfig(cert tls.Certificate, roots *x509.CertPool, suite uint16, mtu int) *Config {
	return &Config{
		Certificates:     []tls.Certificate{cert},
		RootCAs:          roots,
		ServerName:       "localhost",
		ClientCAs:        roots,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		CipherSuites:     []uint16{suite},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		MTU:              mtu,
		DisableMigration: true,
	}
}

func TestInteropPionSmallMTUPQ(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("client/"+strconv.Itoa(mtu), func(t *testing.T) {
			for _, suite := range defaultCipherSuites() {
				t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
					testPionServerMTU(t, tools, cert, roots, suite, mtu, 0)
				})
			}
		})
		t.Run("listener/"+strconv.Itoa(mtu), func(t *testing.T) {
			for _, suite := range defaultCipherSuites() {
				t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
					testPionClientMTU(t, tools, cert, roots, suite, mtu, 0)
				})
			}
		})
	}
}

func TestInteropPionSmallMTUPQHandshakeLoss(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, _, _ := oracleCertificate(t)
	for _, mtu := range []int{1200, 512, 256} {
		t.Run("client/"+strconv.Itoa(mtu), func(t *testing.T) {
			for _, suite := range defaultCipherSuites() {
				t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
					testPionServerMTU(t, tools, cert, roots, suite, mtu, 1)
				})
			}
		})
		t.Run("listener/"+strconv.Itoa(mtu), func(t *testing.T) {
			for _, suite := range defaultCipherSuites() {
				t.Run(tls.CipherSuiteName(suite), func(t *testing.T) {
					testPionClientMTU(t, tools, cert, roots, suite, mtu, 1)
				})
			}
		})
	}
}

type dropFirstInboundHandshake struct {
	net.PacketConn
	remaining int
}

func (c *dropFirstInboundHandshake) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil || c.remaining == 0 || n == 0 || p[0] != contentHandshake {
			return n, addr, err
		}
		c.remaining--
	}
}

func verifyPionPQ(t *testing.T, c *Conn, suite uint16, mtu int) {
	t.Helper()
	state := c.ConnectionState()
	if state.Version != version13 || state.CipherSuite != suite || state.CurveID != tls.X25519MLKEM768 || len(state.VerifiedChains) == 0 {
		t.Fatalf("negotiated version=%x suite=%x group=%s chains=%d mtu=%d", state.Version, state.CipherSuite, state.CurveID, len(state.VerifiedChains), mtu)
	}
	if c.session.handshake.cidNegotiated || c.session.handshake.rrc {
		t.Fatal("PQ case negotiated CID/RRC")
	}
}

func testPionServerMTU(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, mtu, drop int) {
	t.Helper()
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.Pion.Server, pionPQArgs(suite, mtu, "-listen", address.String(), "-cert", certFile, "-key", keyFile)...)
	runOracle(t, command)
	logged := &capturePacketConn{PacketConn: udpForOracle(t)}
	transport := net.PacketConn(logged)
	if drop > 0 {
		transport = &dropFirstPlainHandshake{PacketConn: transport, remaining: drop}
	}
	t.Cleanup(func() {
		sent, recv := logged.snapshot()
		t.Logf("client UDP sent %s recv %s mtu=%d drop=%d", summarizeSizes(sizesOf(sent)), summarizeSizes(sizesOf(recv)), mtu, drop)
	})
	client, err := Client(ctx, transport, address, pionPQConfig(cert, roots, suite, mtu))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := client.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	verifyPionPQ(t, client, suite, mtu)
	marker := []byte("pion-server-echo\n")
	if _, err := client.Write(marker); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1024)
	n, err := client.Read(buffer)
	if err != nil || !bytes.Equal(buffer[:n], marker) {
		t.Fatalf("Pion echo: %q, %v", buffer[:n], err)
	}
}

func testPionClientMTU(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, mtu, drop int) {
	t.Helper()
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	logged := &capturePacketConn{PacketConn: udpForOracle(t)}
	transport := net.PacketConn(logged)
	if drop > 0 {
		transport = &dropFirstInboundHandshake{PacketConn: transport, remaining: drop}
	}
	listener, err := Listen(transport, pionPQConfig(cert, roots, suite, mtu))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Cleanup(func() {
		sent, recv := logged.snapshot()
		t.Logf("listener UDP sent %s recv %s mtu=%d drop=%d", summarizeSizes(sizesOf(sent)), summarizeSizes(sizesOf(recv)), mtu, drop)
	})
	command := exec.CommandContext(ctx, tools.Pion.Server, pionPQArgs(suite, mtu, "-connect", logged.LocalAddr().String(), "-cert", certFile, "-key", keyFile)...)
	output, wait := runOracle(t, command)
	peer, err := listener.AcceptContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = peer.Close() }()
	if err := peer.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server := peer.(*Conn)
	verifyPionPQ(t, server, suite, mtu)
	buffer := make([]byte, 1024)
	n, err := server.Read(buffer)
	if err != nil || string(buffer[:n]) != "pion-pq-echo" {
		t.Fatalf("Pion data: %q, %v", buffer[:n], err)
	}
	if _, err := server.Write(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte("client verified both echoes")) {
		t.Fatal("Pion client did not verify the echo")
	}
}
