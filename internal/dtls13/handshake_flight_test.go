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
			var epoch2Handshake, finished, ackAfterHandshake, ackBeforeFinished bool
			for _, r := range records {
				if r.typ == contentHandshake && r.handshake != msgClientHello {
					epoch2Handshake = true
					if r.handshake == msgFinished {
						finished = true
					}
				}
				if r.typ == contentACK {
					if !finished {
						ackBeforeFinished = true
					} else {
						ackAfterHandshake = true
					}
				}
			}
			if !epoch2Handshake || !finished {
				t.Fatal("client did not send the authenticated handshake flight")
			}
			if ackBeforeFinished {
				t.Fatal("client ACK preceded Finished; OpenSSL SSL_accept treats that as unexpected_message")
			}
			if !ackAfterHandshake {
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
