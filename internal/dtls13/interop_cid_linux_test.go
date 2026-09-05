//go:build linux && dtlsinterop

package dtls13

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// cidOracleTransport drops the first datagram using each replacement CID.
// This loses wolfSSL's rotation ACK without depending on packet timing.
type cidOracleTransport struct {
	net.PacketConn
	mu      sync.Mutex
	cid     []byte
	drop    bool
	dropped int
}

func (c *cidOracleTransport) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, peer, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, peer, err
		}
		r, _, parseErr := parseRecord(data[:n], 8)
		if parseErr != nil || len(r.cid) == 0 {
			return n, peer, nil
		}
		c.mu.Lock()
		changed := c.cid != nil && !bytes.Equal(c.cid, r.cid)
		c.cid = bytes.Clone(r.cid)
		drop := changed && c.drop
		if drop {
			c.dropped++
		}
		c.mu.Unlock()
		if !drop {
			return n, peer, nil
		}
	}
}

func verifyWolfSSLCID(t *testing.T, conn *Conn, transport *cidOracleTransport, suite uint16, rotations int) {
	t.Helper()
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	// Close joins the event loop before the protocol-state assertions.
	s := conn.session
	state := conn.ConnectionState()
	if state.Version != version13 || state.CipherSuite != suite || len(state.VerifiedChains) == 0 {
		t.Fatal("wolfSSL did not negotiate authenticated DTLS 1.3 with the requested cipher")
	}
	if !s.handshake.cidNegotiated || len(s.handshake.peerCID) == 0 {
		t.Fatal("wolfSSL did not negotiate nonempty CIDs")
	}
	if s.handshake.rrc {
		t.Fatal("wolfSSL now negotiates RRC; extend the independent migration tests")
	}
	if !s.cidRequested || s.post[msgRequestConnectionID] != nil {
		t.Fatal("wolfSSL did not acknowledge our proactive CID request")
	}
	if len(s.peerSpareCIDs) != 0 {
		t.Fatal("wolfSSL now issues spare CIDs; extend the independent pool tests")
	}
	if len(s.localCIDs) != 1 || len(s.immediateCIDs) != 0 || bytes.Equal(s.localCIDs[0], s.handshake.localCID) {
		t.Fatal("wolfSSL did not authenticate a record using the replacement CID")
	}
	if s.currentWriteEpoch() < 4 || s.readApplicationEpoch < 4 {
		t.Fatal("wolfSSL did not complete bidirectional key updates")
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if transport.drop && transport.dropped != rotations {
		t.Fatalf("lost rotation datagrams = %d; want %d", transport.dropped, rotations)
	}
	t.Logf("verified CID request ACK, %d immediate rotations, bidirectional key updates, application data, and %d lost rotation ACKs; no spare issuance or RRC", rotations, transport.dropped)
}

func TestInteropWolfSSLCID(t *testing.T) {
	tools := loadOracleTools(t)
	cert, roots, certFile, keyFile := oracleCertificate(t)
	for _, suite := range defaultCipherSuites() {
		for _, role := range []string{"server", "client"} {
			for _, loss := range []bool{false, true} {
				t.Run(fmt.Sprintf("%x/%s/loss=%t", suite, role, loss), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					transport := &cidOracleTransport{PacketConn: udpForOracle(t), drop: loss}
					config := &Config{
						Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost",
						ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert,
						CipherSuites: []uint16{suite}, CurvePreferences: []tls.CurveID{tls.CurveP256},
						ConnectionIDLength: 8,
					}
					args := []string{"-u", "-v", "4", "-Y", "--cid", "wolf-cid", "-c", certFile, "-k", keyFile, "-A", certFile, "-l", tls.CipherSuiteName(suite)}
					var conn *Conn
					var err error
					var output *bytes.Buffer
					var wait func() error
					if role == "server" {
						reservation := udpForOracle(t)
						address := reservation.LocalAddr().(*net.UDPAddr)
						if err := reservation.Close(); err != nil {
							t.Fatal(err)
						}
						command := exec.CommandContext(ctx, tools.WolfSSL.Server, append(args, "-e", "-p", strconv.Itoa(address.Port))...)
						command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
						runOracle(t, command)
						conn, err = Client(ctx, transport, address, config)
					} else {
						listener, listenErr := Listen(transport, config)
						if listenErr != nil {
							t.Fatal(listenErr)
						}
						t.Cleanup(func() { _ = listener.Close() })
						port := listener.Addr().(*net.UDPAddr).Port
						command := exec.CommandContext(ctx, tools.WolfSSL.Client, append(args, "-h", "localhost", "-m", "-w", "-p", strconv.Itoa(port))...)
						command.Dir = filepath.Dir(tools.WolfSSL.Certificates)
						output, wait = runOracle(t, command)
						var accepted net.Conn
						accepted, err = listener.AcceptContext(ctx)
						if err == nil {
							conn = accepted.(*Conn)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = conn.Close() })
					deadline, _ := ctx.Deadline()
					if err := conn.SetDeadline(deadline); err != nil {
						t.Fatal(err)
					}
					for range 2 {
						if err := conn.RotateConnectionID(); err != nil {
							t.Fatalf("CID rotation: %v", err)
						}
						if err := conn.UpdateKeys(true); err != nil {
							t.Fatalf("key update after CID rotation: %v", err)
						}
					}
					buffer := make([]byte, 1024)
					if role == "server" {
						marker := []byte("wolfssl-rotated-cid-echo\n")
						if _, err := conn.Write(marker); err != nil {
							t.Fatal(err)
						}
						n, err := conn.Read(buffer)
						if err != nil || !bytes.Equal(buffer[:n], marker) {
							t.Fatalf("wolfSSL echo after CID rotation = %q, %v", buffer[:n], err)
						}
					} else {
						n, err := conn.Read(buffer)
						if err != nil || n == 0 {
							t.Fatalf("wolfSSL client data = %q, %v", buffer[:n], err)
						}
						if _, err := conn.Write(buffer[:n]); err != nil {
							t.Fatal(err)
						}
						if err := conn.CloseWrite(); err != nil {
							t.Fatal(err)
						}
						if err := wait(); err != nil {
							t.Fatalf("wolfSSL client: %v", err)
						}
						if !bytes.Contains(output.Bytes(), buffer[:n]) {
							t.Fatal("wolfSSL client did not report the echoed data")
						}
					}
					verifyWolfSSLCID(t, conn, transport, suite, 2)
				})
			}
		}
	}
}
