package dtls13

import (
	"bytes"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testcert"
)

type testDatagram struct {
	fromClient bool
	data       []byte
}

func driveSessions(t *testing.T, clientConfig, serverConfig *Config, loss, reorder bool) (*session, *session, *[]testDatagram) {
	t.Helper()
	var packets []testDatagram
	var client, server *session
	droppedClient, droppedServer, droppedFinal := false, false, false
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			if loss {
				if fromClient && !droppedClient {
					droppedClient = true
					return nil
				}
				if !fromClient && !droppedServer {
					droppedServer = true
					return nil
				}
				// Disruption ACKs can complete or flush the peer flight before
				// finish(), so drop the first server packet after that flight.
				if !fromClient && !droppedFinal && server != nil &&
					(server.handshake.complete || server.outbound != nil && server.outbound.complete) {
					droppedFinal = true
					return nil
				}
			}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	var err error
	now := time.Unix(100, 0)
	server, err = newTestServerSession(serverConfig, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2000; step++ {
		if len(packets) != 0 {
			index := 0
			if reorder {
				index = len(packets) - 1
			}
			packet := packets[index]
			packets = append(packets[:index], packets[index+1:]...)
			destination := client
			if packet.fromClient {
				destination = server
			}
			data, err := destination.receive(packet.data, now)
			if err != nil {
				t.Fatalf("receive (client=%t): %v", destination.handshake.client, err)
			}
			if len(data) != 0 {
				t.Fatal("handshake delivered application data")
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			if loss && (!droppedClient || !droppedServer || !droppedFinal) {
				t.Fatal("fault injection did not exercise all selected losses")
			}
			return client, server, &packets
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled without a recovery timer")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake exceeded deterministic event bound")
	return nil, nil, nil
}

func TestSessionLargeCertificateFlight(t *testing.T) {
	ca, err := testcert.NewAuthority("large certificate CA")
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"localhost"}
	for i := range 200 {
		names = append(names, fmt.Sprintf("host%03d.example.test", i))
	}
	leaf, err := ca.Leaf("localhost", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, nil, names)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	client := &Config{ServerName: "localhost", RootCAs: roots, MTU: 256}
	server := &Config{Certificates: []tls.Certificate{leaf.TLS()}, MTU: 256}
	driveSessions(t, client, server, true, true)
}

func TestSmallMTUCertificateFlightDoesNotWaitRetransmitForNewBytes(t *testing.T) {
	cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
	client := &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	server := &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	elapsed := handshakeProtocolTime(t, client, server)
	if elapsed >= initialRetransmit {
		t.Fatalf("new-byte bursts waited %s; RFC 9147 §5.8.2 timer is for retransmission", elapsed)
	}
}

func handshakeProtocolTime(t *testing.T, clientConfig, serverConfig *Config) time.Duration {
	t.Helper()
	start := time.Unix(100, 0)
	var packets []testDatagram
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	now := start
	server, err := newTestServerSession(serverConfig, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientSession(clientConfig, sender(true), now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2000; step++ {
		if len(packets) != 0 {
			packet := packets[0]
			packets = packets[1:]
			destination := client
			if packet.fromClient {
				destination = server
			}
			if _, err := destination.receive(packet.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.outbound.complete {
			return now.Sub(start)
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled without a recovery timer")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake exceeded deterministic event bound")
	return 0
}
