//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type oracleTools struct {
	OpenSSL struct{ OpenSSL string }                      `json:"openssl"`
	WolfSSL struct{ Client, Server, Certificates string } `json:"wolfssl"`
	Pion    struct{ Server string }                       `json:"pion"`
}

func loadOracleTools(t *testing.T) oracleTools {
	t.Helper()
	manifest := os.Getenv("SOCAT_DTLS13_TOOLS")
	if manifest == "" {
		t.Fatal("dtlsinterop requires SOCAT_DTLS13_TOOLS pointing to the pinned lab tools.json")
	}
	data, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var tools oracleTools
	if err := json.Unmarshal(data, &tools); err != nil {
		t.Fatal(err)
	}
	return tools
}

func oracleCertificate(t *testing.T) (tls.Certificate, *x509.CertPool, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots, certFile, keyFile
}

func runOracle(t *testing.T, command *exec.Cmd) (*bytes.Buffer, func() error) {
	t.Helper()
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var waitErr error
	wait := func() error { once.Do(func() { waitErr = command.Wait() }); return waitErr }
	t.Cleanup(func() {
		if command.Process != nil && command.ProcessState == nil {
			_ = command.Process.Kill()
		}
		_ = wait()
		if t.Failed() {
			t.Logf("oracle output:\n%s", output.String())
		}
	})
	return &output, wait
}

func udpForOracle(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readOracleSession(t *testing.T, ctx context.Context, conn *net.UDPConn, s *session, peer *net.UDPAddr, expect []byte) {
	t.Helper()
	buffer := make([]byte, 65535)
	sent := false
	updated := false
	received := false
	for {
		if s.handshake.complete && !updated {
			if err := s.requestKeyUpdate(true, time.Now()); err != nil {
				t.Fatal(err)
			}
			updated = true
		}
		if s.handshake.complete && !sent && !s.updating && !s.updatePending {
			if s.handshake.state.Version != version13 || len(s.handshake.state.VerifiedChains) == 0 {
				t.Fatal("oracle handshake did not verify DTLS 1.3 and the certificate")
			}
			if err := s.application(expect); err != nil {
				t.Fatal(err)
			}
			sent = true
		}
		deadline, _ := ctx.Deadline()
		if protocol := s.deadline(); !protocol.IsZero() && protocol.Before(deadline) {
			deadline = protocol
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		n, from, err := conn.ReadFromUDP(buffer)
		now := time.Now()
		if err != nil {
			if !now.Before(deadline) {
				if ctx.Err() != nil {
					t.Fatalf("oracle exchange timed out: %v", ctx.Err())
				}
				if err := s.tick(now); err != nil {
					t.Fatal(err)
				}
				continue
			}
			t.Fatal(err)
		}
		if from.String() != peer.String() {
			continue
		}
		data, err := s.receive(buffer[:n], now)
		if err != nil {
			t.Fatalf("DTLS receive: %v", err)
		}
		for _, message := range data {
			if !bytes.Equal(message, expect) {
				t.Fatalf("oracle data %q; want %q", message, expect)
			}
			received = true
		}
		if received && s.currentWriteEpoch() >= 4 && s.readApplicationEpoch >= 4 {
			return
		}
	}
}

func TestInteropWolfSSLServer(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, certFile, keyFile := oracleCertificate(t)
	for _, suite := range []uint16{aes128GCM, aes256GCM} {
		t.Run(fmt.Sprintf("%x", suite), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			reservation := udpForOracle(t)
			address := reservation.LocalAddr().(*net.UDPAddr)
			port := address.Port
			if err := reservation.Close(); err != nil {
				t.Fatal(err)
			}
			cipher := "TLS_AES_128_GCM_SHA256"
			if suite == aes256GCM {
				cipher = "TLS_AES_256_GCM_SHA384"
			}
			command := exec.CommandContext(ctx, tools.WolfSSL.Server, "-u", "-v", "4", "-Y", "-e", "-p", strconv.Itoa(port), "-c", certFile, "-k", keyFile, "-A", certFile, "-l", cipher)
			command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
			runOracle(t, command)
			client, err := Client(ctx, udpForOracle(t), address, &Config{
				Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost",
				CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{tls.CurveP256},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if err := client.UpdateKeys(true); err != nil {
				t.Fatal(err)
			}
			marker := []byte("dtls13-independent-echo\n")
			if _, err := client.Write(marker); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 1024)
			n, err := client.Read(buffer)
			if err != nil || !bytes.Equal(buffer[:n], marker) {
				t.Fatalf("wolfSSL echo = %q, %v", buffer[:n], err)
			}
			state := client.ConnectionState()
			if state.Version != version13 || len(state.VerifiedChains) == 0 {
				t.Fatal("unverified DTLS 1.3 handshake")
			}
			// Stop the event loop before inspecting its negotiated traffic epochs.
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			if client.session.currentWriteEpoch() < 4 || client.session.readApplicationEpoch < 4 {
				t.Fatal("wolfSSL did not complete both key updates")
			}
			t.Log("verified public client API, mutual authentication, bidirectional key updates, and wolfSSL echo")
		})
	}
}

func TestInteropOpenSSLClient(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, certFile, keyFile := oracleCertificate(t)
	for _, suite := range []uint16{aes128GCM, aes256GCM} {
		for _, group := range []string{"P-256", "X25519"} {
			t.Run(fmt.Sprintf("%x/%s", suite, group), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				conn := udpForOracle(t)
				cipher := "TLS_AES_128_GCM_SHA256"
				if suite == aes256GCM {
					cipher = "TLS_AES_256_GCM_SHA384"
				}
				marker := []byte("openssl-independent-echo\n")
				command := exec.CommandContext(ctx, tools.OpenSSL.OpenSSL, "s_client", "-dtls1_3", "-quiet", "-ign_eof", "-connect", conn.LocalAddr().String(),
					"-verify_hostname", "localhost", "-verify_return_error", "-CAfile", certFile, "-cert", certFile, "-key", keyFile, "-groups", group, "-ciphersuites", cipher)
				command.Stdin = strings.NewReader(string(marker))
				output, wait := runOracle(t, command)
				listener, err := Listen(conn, &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, CipherSuites: []uint16{suite}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				peer, err := listener.AcceptContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				server := peer.(*Conn)
				if err := server.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 1024)
				n, err := server.Read(buffer)
				if err != nil || !bytes.Equal(buffer[:n], marker) {
					t.Fatalf("OpenSSL data = %q, %v", buffer[:n], err)
				}
				state := server.ConnectionState()
				if state.Version != version13 || len(state.VerifiedChains) == 0 {
					t.Fatal("client certificate was not verified")
				}
				if _, err := server.Write(buffer[:n]); err != nil {
					t.Fatal(err)
				}
				if err := server.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := wait(); err != nil {
					t.Fatalf("OpenSSL client failed: %v", err)
				}
				if !bytes.Contains(output.Bytes(), marker) {
					t.Fatal("OpenSSL did not receive the echoed datagram")
				}
				t.Log("verified public listener API, mutual authentication, and OpenSSL echo")
			})
		}
	}
}

func TestInteropPionCIDAndRebinding(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, certFile, keyFile := oracleCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reservation := udpForOracle(t)
	address := reservation.LocalAddr().(*net.UDPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, tools.Pion.Server, "-listen", address.String(), "-cert", certFile, "-key", keyFile)
	runOracle(t, command)
	conn := udpForOracle(t)
	s, err := newClientSession(&Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost"},
		func(data []byte) error { _, err := conn.WriteToUDP(data, address); return err }, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	responses := 0
	s.path = &pathState{session: s, peer: packetPath{netip.MustParseAddrPort(address.String()), 1},
		send: func(to packetPath, data []byte) error {
			responses++
			_, err := conn.WriteToUDPAddrPort(data, to.remote)
			return err
		}}
	readOracleSession(t, ctx, conn, s, address, []byte("pion-before-rebind\n"))
	if !s.handshake.cidNegotiated || !s.handshake.rrc {
		t.Fatal("Pion did not negotiate CID and RRC")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	conn = udpForOracle(t)
	s.path.peer.local = 2
	readOracleSession(t, ctx, conn, s, address, []byte("pion-after-rebind\n"))
	if responses == 0 {
		t.Fatal("Pion did not challenge the rebinding before the post-migration echo")
	}
	t.Log("verified Pion mutual authentication, CID/RRC negotiation, bidirectional key updates, and UDP rebinding")
}

func TestInteropPionClientEnhancedMigration(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, certFile, keyFile := oracleCertificate(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn := udpForOracle(t)
	command := exec.CommandContext(ctx, tools.Pion.Server, "-connect", conn.LocalAddr().String(), "-cert", certFile, "-key", keyFile)
	output, wait := runOracle(t, command)
	// Pion's pinned post-handshake handler rejects RequestConnectionID.
	// Drive the protocol directly to isolate RRC with the initial CIDs.
	var protocol *session
	protocol, err := newServerSession(&Config{
		Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert,
	}, func(data []byte) error {
		_, err := conn.WriteToUDPAddrPort(data, protocol.path.peer.remote)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var previous netip.AddrPort
	var pending []byte
	replies := 0
	for replies < 2 {
		if err := protocol.tick(time.Now()); err != nil {
			t.Fatal(err)
		}
		if pending != nil {
			if err := protocol.application(pending); err == nil {
				pending = nil
				replies++
				continue
			} else if !errors.Is(err, errPathPending) {
				t.Fatal(err)
			}
		}
		deadline, _ := ctx.Deadline()
		if next := protocol.deadline(); !next.IsZero() && next.Before(deadline) {
			deadline = next
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 65535)
		n, from, err := conn.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if end, _ := ctx.Deadline(); !time.Now().Before(end) {
				t.Fatal("Pion enhanced migration timed out")
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			t.Fatal(err)
		}
		if protocol.path == nil {
			previous = from
			protocol.path = &pathState{session: protocol, peer: packetPath{from, 1},
				send: func(to packetPath, data []byte) error {
					_, err := conn.WriteToUDPAddrPort(data, to.remote)
					return err
				}}
		}
		data, err := protocol.receiveFrom(buffer[:n], packetPath{from, 1}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if len(data) == 0 {
			continue
		}
		message := "before"
		if replies == 1 {
			message = "after"
		}
		if len(data) != 1 || string(data[0]) != message || pending != nil {
			t.Fatalf("Pion datagrams = %q; want %q", data, message)
		}
		pending = data[0]

	}
	state := protocol.handshake.state
	if state.Version != version13 || len(state.VerifiedChains) == 0 || !protocol.handshake.rrc {
		t.Fatal("Pion did not negotiate authenticated DTLS 1.3 with RRC")
	}
	if got := protocol.path.peer.remote; !got.IsValid() || got == previous {
		t.Fatalf("peer did not migrate to the validated address: %s", got)
	}
	if err := wait(); err != nil {
		t.Fatalf("Pion client: %v", err)
	}
	if !bytes.Contains(output.Bytes(), []byte("client verified both echoes")) {
		t.Fatal("Pion did not verify the post-migration response")
	}
	t.Log("verified Pion client authentication and our enhanced old-path/new-path validation after NAT rebinding")
}
