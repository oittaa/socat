package dtls13

import (
	"bytes"
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

func TestCIDWireLimitsAndUnknownUsage(t *testing.T) {
	for _, body := range [][]byte{nil, {0, 0}, {0, 0, 0}, {0, 1, 2, 1}, {0, 0, 2}, {0, 0, 1, 0}} {
		if _, _, err := parseCIDs(body); err == nil {
			t.Fatalf("accepted malformed CID update %x", body)
		}
	}
	body, err := encodeCIDs(nil, false)
	if err != nil {
		t.Fatal(err)
	}
	ids, immediate, err := parseCIDs(body)
	if err != nil || len(ids) != 0 || immediate {
		t.Fatal("empty response to an excessive CID request was rejected")
	}
	var many [][]byte
	for i := range 255 {
		many = append(many, []byte{byte(i)})
	}
	body, err = encodeCIDs(many, false)
	if err != nil {
		t.Fatal(err)
	}
	ids, _, err = parseCIDs(body)
	if err != nil || len(ids) != maxConnectionIDs {
		t.Fatal("peer-provided spare CID pool was not bounded")
	}
}

func FuzzConnectionIDs(f *testing.F) {
	f.Add([]byte{0, 0, 1})
	f.Add([]byte{0, 2, 1, 42, 0})
	f.Fuzz(func(t *testing.T, body []byte) {
		ids, immediate, err := parseCIDs(body)
		if err != nil {
			return
		}
		if len(ids) > maxConnectionIDs {
			t.Fatal("CID pool exceeds bound")
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
