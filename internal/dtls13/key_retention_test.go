package dtls13

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"
)

func TestHandshakeReadKeyRetention(t *testing.T) {
	a, b := handshakeConfigs(t)
	var packets []testDatagram
	now := time.Unix(100, 0)
	server, err := newServerSession(b, func(p []byte) error {
		packets = append(packets, testDatagram{false, bytes.Clone(p)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientSession(a, func(p []byte) error {
		packets = append(packets, testDatagram{true, bytes.Clone(p)})
		return nil
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	// Stop before delivering the server's final ACK.
	for step := 0; !server.handshake.complete; step++ {
		if step == 1000 || len(packets) == 0 {
			t.Fatal("handshake stalled")
		}
		p := packets[0]
		packets = packets[1:]
		destination := client
		if p.fromClient {
			destination = server
		}
		if _, err := destination.receive(p.data, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(packets) == 0 || client.outbound.complete || client.read[2] == nil || server.read[2] == nil {
		t.Fatal("test must leave the final flight unacknowledged")
	}
	clientSecret, serverSecret := client.read[2].secret, server.read[2].secret
	packets = nil // Lose the final ACK.
	if err := server.application([]byte("before final ACK")); err != nil {
		t.Fatal(err)
	}
	if got := deliverSessionPackets(t, client, server, &packets, now); len(got) != 1 {
		t.Fatal("application traffic failed while final ACK was outstanding")
	}
	if client.read[2] == nil {
		t.Fatal("application traffic discarded unacknowledged handshake keys")
	}
	// RFC 9147 section 5.8.1: retain final-flight ACK recovery for twice MSL.
	expiry := now.Add(4 * time.Minute)
	if server.deadline() != expiry {
		t.Fatalf("handshake key expiry = %v; want %v", server.deadline(), expiry)
	}
	if err := client.transmitFlight(expiry.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	late := append([]testDatagram(nil), packets...)
	deliverSessionPackets(t, client, server, &packets, expiry.Add(-time.Second))
	if !client.outbound.complete || client.read[2] != nil || !bytes.Equal(clientSecret, make([]byte, len(clientSecret))) {
		t.Fatal("recovered final ACK did not retire the client's handshake read secret")
	}
	if server.read[2] == nil || server.deadline() != expiry {
		t.Fatal("retransmission changed the server's absolute retention bound")
	}
	for _, p := range late {
		if data, err := server.receive(p.data, expiry); err != nil || len(data) != 0 {
			t.Fatalf("expired handshake record: %v, %v", data, err)
		}
	}
	if server.read[2] != nil || !server.deadline().IsZero() || !bytes.Equal(serverSecret, make([]byte, len(serverSecret))) {
		t.Fatal("expired handshake read key or timer retained")
	}
	if len(packets) != 0 {
		t.Fatal("expired handshake record produced a reply")
	}
	if err := client.application([]byte("after expiry")); err != nil {
		t.Fatal(err)
	}
	if got := deliverSessionPackets(t, client, server, &packets, expiry); len(got) != 1 || string(got[0]) != "after expiry" {
		t.Fatalf("application keys did not survive handshake cleanup: %q", got)
	}
}

func TestConnIdleHandshakeReadKeyExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _ := syntheticConnectionPair(t)
		advanceHandshakeClock(4 * time.Minute)
		if server.session.read[2] != nil || !server.session.handshakeReadExpiry.IsZero() {
			t.Fatal("idle connection did not expire handshake read keys")
		}
		if _, err := client.Write([]byte("still connected")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 64)
		if n, err := server.Read(b); err != nil || string(b[:n]) != "still connected" {
			t.Fatalf("application after idle cleanup: %q, %v", b[:n], err)
		}
	})
}

func TestKeyUpdateCancelsHandshakeReadExpiry(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	if server.read[2] == nil {
		t.Fatal("test requires retained server handshake keys")
	}
	now := time.Unix(101, 0)
	if err := client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if server.read[2] != nil || !server.deadline().IsZero() {
		t.Fatal("peer KeyUpdate retained handshake keys or their expiry timer")
	}
}
