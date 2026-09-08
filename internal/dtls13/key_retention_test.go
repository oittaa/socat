package dtls13

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestConnIdleHandshakeReadKeyExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server, _ := syntheticConnectionPair(t)
		advanceHandshakeClock(4 * time.Minute)
		if server.session.epochs.read[2] != nil || !server.session.handshakeReadExpiry.IsZero() {
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
	if server.epochs.read[2] == nil {
		t.Fatal("test requires retained server handshake keys")
	}
	now := time.Unix(101, 0)
	if err := client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if server.epochs.read[2] != nil || !server.deadline().IsZero() {
		t.Fatal("peer KeyUpdate retained handshake keys or their expiry timer")
	}
}
