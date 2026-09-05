package dtls13

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestConnectionIDSparePoolAndImmediateRotation(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	initial := bytes.Clone(client.handshake.peerCID)
	if err := client.requestCIDs(255, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if len(client.peerSpareCIDs) != maxConnectionIDs-1 || len(server.localCIDs) != maxConnectionIDs || client.cidRequested {
		t.Fatal("spare CID request did not respect the bounded pool")
	}
	client.useSpareCID()
	if bytes.Equal(initial, client.handshake.peerCID) {
		t.Fatal("path change did not select a spare CID")
	}
	if err := client.application([]byte("spare CID")); err != nil {
		t.Fatal(err)
	}
	if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 1 {
		t.Fatal("spare CID did not identify the existing association")
	}
	for i := 0; i < 12; i++ {
		old := bytes.Clone(client.handshake.peerCID)
		if err := server.provideCIDs(1, true, now); err != nil {
			t.Fatal(err)
		}
		deliverSessionPackets(t, client, server, packets, now)
		if bytes.Equal(old, client.handshake.peerCID) || len(server.localCIDs) != 1 || server.acceptCID(old) {
			t.Fatal("immediate CID rotation did not retire the previous pool")
		}
		if err := client.application([]byte("rotated")); err != nil {
			t.Fatal(err)
		}
		if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 1 {
			t.Fatal("rotated CID lost application traffic")
		}
	}
}

func TestKeyUpdateWaitsForPrecedingCIDMessage(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestCIDs(1, now); err != nil {
		t.Fatal(err)
	}
	if err := client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	request, update := (*packets)[0], (*packets)[1]
	*packets = nil
	// The receiver can ACK a buffered KeyUpdate before its predecessor arrives.
	if _, err := server.receive(update.data, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 3 || server.readApplicationEpoch != 3 {
		t.Fatal("key update overtook an unacknowledged preceding message")
	}
	if _, err := server.receive(request.data, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 4 || server.readApplicationEpoch != 4 || client.cidRequested {
		t.Fatal("key update/CID flights did not complete after predecessor arrived")
	}
	if err := client.application([]byte("after reordered control messages")); err != nil {
		t.Fatal(err)
	}
	if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 1 {
		t.Fatal("control message reordering broke the new epoch")
	}
}

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

func TestCIDRequestWaitsForImmediateRotationToBeUsed(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := server.provideCIDs(1, true, now); err != nil {
		t.Fatal(err)
	}
	// An ACK can have been prepared before the peer switched its sending CID.
	server.post[msgNewConnectionID].finish()
	count := byte(2)
	server.cidResponse = &count
	if err := server.advancePost(now); err != nil {
		t.Fatalf("queued spare request aborted immediate rotation: %v", err)
	}
	if server.cidResponse == nil {
		t.Fatal("spare request was lost before the immediate CID was used")
	}
	deliverSessionPackets(t, client, server, packets, now)
	if err := server.advancePost(now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if server.cidResponse != nil || len(client.peerSpareCIDs) != 2 {
		t.Fatal("queued request did not complete after the immediate rotation")
	}
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
	server.cidResponse = nil // The modeled peer deliberately supplies no spares.
	deliverSessionPackets(t, client, server, packets, now)
	if !client.cidRequested || client.post[msgRequestConnectionID] != nil {
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
	if err := client.requestCIDs(1, now); !errors.Is(err, errUpdatePending) {
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
	if client.cidRequested || len(client.peerSpareCIDs) != 1 {
		t.Fatal("later spare request did not complete")
	}
}

func TestCIDImmediateDoesNotFulfillSpareRequest(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	// Generate the unrelated immediate update before the request even exists.
	if err := server.provideCIDs(1, true, now); err != nil {
		t.Fatal(err)
	}
	rotation := (*packets)[0]
	*packets = nil
	ackCIDRequestWithoutResponse(t, client, server, packets, now)
	*packets = append(*packets, rotation)
	deliverSessionPackets(t, client, server, packets, now)
	if err := client.requestCIDs(1, now); !errors.Is(err, errUpdatePending) {
		t.Fatalf("immediate rotation allowed a second request without a spare response: %v", err)
	}
	if err := server.provideCIDs(4, false, now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.cidRequested || len(client.peerSpareCIDs) != 4 {
		t.Fatal("delayed spare response did not fulfill the original request")
	}
}
