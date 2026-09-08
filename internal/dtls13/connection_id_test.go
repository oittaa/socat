package dtls13

import (
	"errors"
	"testing"
	"time"
)

func FuzzConnectionIDs(f *testing.F) {
	f.Add([]byte{0, 0, 1})
	f.Add([]byte{0, 2, 1, 42, 0})
	f.Add([]byte{0, 1, 0, 0})
	f.Add([]byte{0, 4, 1, 42, 1, 42, 1})
	f.Add([]byte{0, 18, 1, 10, 1, 11, 1, 12, 1, 13, 1, 14, 1, 15, 1, 16, 1, 17, 2, 18, 1})
	f.Fuzz(func(t *testing.T, body []byte) {
		ids, immediate, err := parseCIDs(body)
		if err != nil {
			return
		}
		if len(ids) > maxConnectionIDs {
			t.Fatal("CID pool exceeds bound")
		}
		for i, id := range ids {
			if len(id) > 255 || containsCID(ids[:i], id) {
				t.Fatal("invalid or duplicate retained CID")
			}
		}
		encoded, err := encodeCIDs(ids, immediate)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := parseCIDs(encoded); err != nil {
			t.Fatal(err)
		}
	})
}

// Model a peer that ACKs a request without returning any NewConnectionId.
func ackCIDRequestWithoutResponse(t *testing.T, client, server *session, packets *[]testDatagram, now time.Time) {
	t.Helper()
	if err := client.requestCIDs(4, now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != 1 {
		t.Fatal("expected one request record")
	}
	packet := (*packets)[0]
	*packets = nil
	r, _, err := parseRecord(packet.data, len(server.handshake.localCID))
	if err != nil {
		t.Fatal(err)
	}
	number, typ, body, ok, err := server.openRecord(r, true)
	if err != nil || !ok || typ != contentHandshake {
		t.Fatalf("request decode: %v, accepted=%t, type=%d", err, ok, typ)
	}
	if err := server.receiveHandshake(number, body, now); err != nil {
		t.Fatal(err)
	}
	server.cid.response = nil // The modeled peer deliberately supplies no spares.
	deliverSessionPackets(t, client, server, packets, now)
	if !client.cid.requested || client.post[msgRequestConnectionID] != nil {
		t.Fatal("ACK-only setup did not leave an unfulfilled, acknowledged request")
	}
}

func TestCIDACKWithoutResponseRemainsPending(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	ackCIDRequestWithoutResponse(t, client, server, packets, now)
	now = now.Add(10 * time.Minute)
	if err := client.tick(now); err != nil {
		t.Fatalf("ACK-only response timed out the association: %v", err)
	}
	if err := client.requestCIDs(1, now); !errors.Is(err, errOperationPending) {
		t.Fatalf("unfulfilled request allowed another request: %v", err)
	}
	if err := client.application([]byte("still usable")); err != nil {
		t.Fatal(err)
	}
	data := deliverSessionPackets(t, client, server, packets, now)
	if len(data) != 1 || string(data[0]) != "still usable" {
		t.Fatal("ACK-only peer could not exchange application data")
	}
}

func TestCIDEmptySpareResponseFulfillsRequest(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	ackCIDRequestWithoutResponse(t, client, server, packets, now)
	// Empty uint16-length CID vector followed by cid_spare usage.
	if err := server.startPost(msgNewConnectionID, []byte{0, 0, 1}, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if err := client.requestCIDs(1, now); err != nil {
		t.Fatalf("empty spare response prevented a later request: %v", err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.cid.requested || len(client.cid.peerSpare) != 1 {
		t.Fatal("later spare request did not complete")
	}
}
