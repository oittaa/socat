package dtls13

import (
	"bytes"
	"crypto/mldsa"
	"crypto/tls"
	"errors"
	"testing"
	"time"
)

func TestApplicationWaitsForUnsentHandshakeFlight(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, _, _ := driveSessions(t, a, b, false, false)
	client.outbound = &flight{complete: false, sentOnce: false}
	if err := client.application([]byte("too-early")); !errors.Is(err, errOperationPending) {
		t.Fatalf("application during unsent handshake flight: %v", err)
	}
	client.outbound.sentOnce = true
	if err := client.application([]byte("after-finished")); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedHandshakeFlightExceedsEpochZeroBurst(t *testing.T) {
	cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
	clientConfig := &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	serverConfig := &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	var clientRecords int
	var packets []testDatagram
	now := time.Unix(100, 0)
	server, err := newTestServerSession(serverConfig, func(data []byte) error {
		packets = append(packets, testDatagram{false, bytes.Clone(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientSession(clientConfig, func(data []byte) error {
		clientRecords++
		packets = append(packets, testDatagram{true, bytes.Clone(data)})
		return nil
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 4000; step++ {
		if len(packets) != 0 {
			p := packets[0]
			packets = packets[1:]
			destination := client
			if p.fromClient {
				destination = server
			}
			if _, err := destination.receive(p.data, now); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if client.handshake.complete && server.handshake.complete && client.handshakeFlightSent() {
			if clientRecords <= flightBurst {
				t.Fatalf("ML-DSA client records = %d; want more than epoch-0 burst %d", clientRecords, flightBurst)
			}
			if err := client.application([]byte("ok")); err != nil {
				t.Fatal(err)
			}
			return
		}
		next := client.deadline()
		if candidate := server.deadline(); next.IsZero() || !candidate.IsZero() && candidate.Before(next) {
			next = candidate
		}
		if next.IsZero() {
			t.Fatal("handshake stalled")
		}
		now = next
		if err := client.tick(now); err != nil {
			t.Fatal(err)
		}
		if err := server.tick(now); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("handshake did not finish")
}
