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
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestInteropOpenSSLMLDSA(t *testing.T) {
	// The pinned OpenSSL snapshot does not ACK partial server flights.
	// Keep this algorithm check within one ten-record transmission.
	tools := loadOracleTools(t)
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			cert, roots := mldsaCertificate(t, parameters)
			cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			conn := udpForOracle(t)
			listener, err := Listen(conn, &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, CipherSuites: []uint16{chaCha20Poly1305}, MTU: 4096})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			marker := []byte("mldsa-mutual-authentication\n")
			command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, "s_client", "-dtls1_3", "-quiet", "-ign_eof", "-mtu", "4096", "-connect", conn.LocalAddr().String(), "-verify_hostname", "localhost", "-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile, "-groups", "X25519MLKEM768", "-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256")
			command.Stdin = strings.NewReader(string(marker))
			output, wait := runOracle(t, command)
			peer, err := listener.AcceptContext(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = peer.Close() }()
			if err := peer.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			state := peer.(*Conn).ConnectionState()
			if state.Version != version13 || state.CurveID != tls.X25519MLKEM768 || state.CipherSuite != chaCha20Poly1305 || len(state.VerifiedChains) == 0 {
				t.Fatal("post-quantum algorithms were not negotiated")
			}
			key, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey)
			if !ok || key.Parameters() != parameters {
				t.Fatal("ML-DSA client authentication missing")
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
		})
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

func testOpenSSLServer(t *testing.T, tools oracleTools, cert tls.Certificate, roots *x509.CertPool, suite uint16, group tls.CurveID) {
	t.Helper()
	// Larger datagrams avoid the reference's incomplete handshake ACK support.
	cert, roots, certFile, keyFile := writeOracleCertificate(t, cert, roots)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, "s_server", "-dtls1_3", "-quiet", "-ign_eof", "-mtu", "4096", "-naccept", "1", "-accept", address.String(), "-Verify", "1", "-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile, "-groups", oracleGroupName(group), "-ciphersuites", tls.CipherSuiteName(suite))
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stdout = stdin
	runOracle(t, command)
	client, err := Client(ctx, udpForOracle(t), address, &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{group}, MTU: 4096})
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
