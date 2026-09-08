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

func TestHandshakeACKFollowsFinalFlight(t *testing.T) {
	cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
	clientConfig := &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	serverConfig := &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
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
		packets = append(packets, testDatagram{true, bytes.Clone(data)})
		return nil
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	var records []struct {
		typ, handshake byte
	}
	client.observeRecord = func(_ uint64, typ byte, body []byte) {
		item := struct{ typ, handshake byte }{typ: typ}
		if typ == contentHandshake && len(body) > 0 {
			item.handshake = body[0]
		}
		records = append(records, item)
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
			var epoch2Handshake, finished, ackDuringResponse, ackAfterFinished bool
			for _, r := range records {
				if r.typ == contentHandshake && r.handshake != msgClientHello {
					epoch2Handshake = true
					if r.handshake == msgFinished {
						finished = true
					}
				}
				if r.typ == contentACK {
					if epoch2Handshake && !finished {
						ackDuringResponse = true
					}
					if finished {
						ackAfterFinished = true
					}
				}
			}
			if !epoch2Handshake || !finished {
				t.Fatal("client did not send the authenticated handshake flight")
			}
			if ackDuringResponse {
				t.Fatal("client ACK interleaved with Certificate/Finished; OpenSSL SSL_accept treats that as unexpected_message")
			}
			if !ackAfterFinished {
				t.Fatal("client did not ACK the server flight after sending Finished")
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

func TestAcknowledgementQueueBoundedWhileFinalFlightUnsent(t *testing.T) {
	s := newSession(&handshakeState{complete: true, config: &Config{MTU: 1200}}, nil, func([]byte) error { return nil })
	s.outbound = &flight{}
	body, err := (handshakeMessage{typ: msgCertificate, body: bytes.Repeat([]byte{1}, 200)}).fragment(0, 1)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0)
	for i := range 1000 {
		if err := s.receiveHandshake(recordNumber{2, uint64(i)}, body, now); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.acknowledgements); n == 0 || n > maxQueuedAcknowledgements {
		t.Fatalf("queued ACK records = %d; want 1..%d while Finished is unsent", n, maxQueuedAcknowledgements)
	}
}

func TestLostProtectedHandshakeRecordRecovers(t *testing.T) {
	cert, roots := mldsaCertificate(t, mldsa.MLDSA44())
	clientConfig := &Config{Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "localhost", MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	serverConfig := &Config{Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MTU: 256, CipherSuites: []uint16{chaCha20Poly1305}}
	var packets []testDatagram
	var client, server *session
	var serverProtected int
	dropped := false
	start := time.Unix(100, 0)
	now := start
	sender := func(fromClient bool) func([]byte) error {
		return func(data []byte) error {
			if !fromClient && server != nil && server.outbound != nil && !server.outbound.complete && server.currentWriteEpoch() >= 2 {
				serverProtected++
				if !dropped && serverProtected == 15 {
					dropped = true
					return nil
				}
			}
			packets = append(packets, testDatagram{fromClient, bytes.Clone(data)})
			return nil
		}
	}
	var err error
	server, err = newTestServerSession(serverConfig, sender(false))
	if err != nil {
		t.Fatal(err)
	}
	client, err = newClientSession(clientConfig, sender(true), now)
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
			if !dropped || serverProtected < 16 {
				t.Fatalf("loss did not land in a multi-record server flight: dropped=%t records=%d", dropped, serverProtected)
			}
			if now.Sub(start) > 20*time.Second {
				t.Fatalf("handshake recovered too slowly: %s", now.Sub(start))
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
