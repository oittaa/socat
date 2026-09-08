package dtls13

import (
	"bytes"
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
	if n := len(s.ack.pending); n == 0 || n > maxQueuedAcknowledgements {
		t.Fatalf("queued ACK records = %d; want 1..%d while Finished is unsent", n, maxQueuedAcknowledgements)
	}
}

func TestHandshakeStallACKSuppressedDuringResponse(t *testing.T) {
	s := newSession(&handshakeState{config: &Config{MTU: 1200}}, nil, func([]byte) error { return nil })
	s.ack.pending = []recordNumber{{2, 1}}
	s.ack.deadline = time.Unix(1, 0)
	s.outbound = &flight{}
	now := s.ack.deadline.Add(time.Second)
	if s.handshakeACKScheduled() {
		t.Fatal("responding flight scheduled a stall ACK")
	}
	if s.handshakeFlightStalled(now) {
		t.Fatal("responding flight sent a stall ACK")
	}
}
