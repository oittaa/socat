package dtls13

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func deliverSessionPackets(t *testing.T, client, server *session, packets *[]testDatagram, now time.Time) [][]byte {
	t.Helper()
	var application [][]byte
	for step := 0; len(*packets) != 0; step++ {
		if step > 1000 {
			t.Fatal("session packet loop exceeded event bound")
		}
		p := (*packets)[0]
		*packets = (*packets)[1:]
		destination := client
		if p.fromClient {
			destination = server
		}
		data, err := destination.receive(p.data, now)
		if err != nil {
			t.Fatalf("receive (client=%t): %v", destination.handshake.client, err)
		}
		application = append(application, data...)
	}
	return application
}

func TestKeyUpdateLostACK(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if err := client.application([]byte("wait")); !errors.Is(err, errUpdatePending) {
		t.Fatalf("write did not wait for key acknowledgement: %v", err)
	}
	update := (*packets)[0].data
	*packets = nil
	if _, err := server.receive(update, now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != 1 {
		t.Fatal("key update was not acknowledged")
	}
	*packets = nil // Lose the ACK, forcing a fresh old-epoch transmission.
	if server.read[3] == nil || client.currentWriteEpoch() != 3 {
		t.Fatal("old keys removed before acknowledgement")
	}
	now = client.deadline()
	if err := client.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(*packets) != 1 || bytes.Equal((*packets)[0].data, update) {
		t.Fatal("retransmission did not use a fresh record number")
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 4 || !client.deadline().IsZero() {
		t.Fatal("acknowledged update did not activate new keys and cancel retry")
	}
	if err := client.application([]byte("new epoch")); err != nil {
		t.Fatal(err)
	}
	data := deliverSessionPackets(t, client, server, packets, now)
	if len(data) != 1 || string(data[0]) != "new epoch" || server.read[3] != nil {
		t.Fatal("new key traffic failed or obsolete keys remained")
	}
}

func TestApplicationRotatesKeysBeforeRecordLimit(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	client.write[3].sequence = 1<<24 - 1024
	// Bring the receiver's truncated record-number window to the same point.
	if !server.read[3].window.accept(1<<24 - 1025) {
		t.Fatal("could not advance the receiver's record window")
	}
	if err := client.application([]byte("limit")); !errors.Is(err, errUpdatePending) {
		t.Fatalf("application write at the key limit = %v", err)
	}
	if err := client.advancePost(now); err != nil {
		t.Fatal(err)
	}
	deliverSessionPackets(t, client, server, packets, now)
	if client.currentWriteEpoch() != 4 {
		t.Fatal("key usage limit did not advance the write epoch")
	}
	if err := client.application([]byte("fresh keys")); err != nil {
		t.Fatal(err)
	}
	data := deliverSessionPackets(t, client, server, packets, now)
	if len(data) != 1 || string(data[0]) != "fresh keys" {
		t.Fatal("application write did not resume with fresh keys")
	}
}

func TestKeyUpdateSimultaneousRequestsAndEpochBits(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	for i := 0; i < 6; i++ {
		if err := client.requestKeyUpdate(true, now); err != nil {
			t.Fatal(err)
		}
		if err := server.requestKeyUpdate(true, now); err != nil {
			t.Fatal(err)
		}
		deliverSessionPackets(t, client, server, packets, now)
		for _, s := range []*session{client, server} {
			if s.updating || s.updatePending || !s.deadline().IsZero() {
				t.Fatal("simultaneous key updates did not settle")
			}
			if err := s.application([]byte("epoch transition")); err != nil {
				t.Fatal(err)
			}
		}
		if data := deliverSessionPackets(t, client, server, packets, now); len(data) != 2 {
			t.Fatal("application traffic failed across epoch bit rollover")
		}
		if len(client.read) > 2 || len(server.read) > 2 || len(client.write) != 1 || len(server.write) != 1 {
			t.Fatal("key updates accumulated obsolete key material")
		}
	}
}

func TestKeyUpdateMalformedAndWrongEpoch(t *testing.T) {
	for _, body := range [][]byte{nil, {0, 0}, {2}} {
		a, b := handshakeConfigs(t)
		client, server, packets := driveSessions(t, a, b, false, false)
		m, err := client.handshake.message(msgKeyUpdate, 3, body)
		if err != nil {
			t.Fatal(err)
		}
		fragment := fragmentFor(t, m, 0, len(body))
		if _, err := client.sendRecord(3, contentHandshake, fragment); err != nil {
			t.Fatal(err)
		}
		if _, err := server.receive((*packets)[0].data, time.Unix(1000, 0)); err == nil {
			t.Fatalf("accepted malformed KeyUpdate %x", body)
		}
	}
}

func TestClosureUsesRecordOrder(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	if err := client.application([]byte("before close")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.sendRecord(3, contentAlert, []byte{1, 0}); err != nil {
		t.Fatal(err)
	}
	if err := client.application([]byte("after close")); err != nil {
		t.Fatal(err)
	}
	ordered := *packets
	*packets = nil
	for _, index := range []int{1, 2, 0} {
		data, err := server.receive(ordered[index].data, time.Unix(1000, 0))
		if err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			if len(data) != 1 || string(data[0]) != "before close" {
				t.Fatal("closure discarded reordered earlier record")
			}
		} else if len(data) != 0 {
			t.Fatal("closure allowed a later application record")
		}
	}
}

func TestCompletedSessionIgnoresPlaintextAfterSecretCleanup(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	if server.handshake.schedule != nil || client.handshake.schedule != nil {
		t.Fatal("acknowledged handshake retained its master and ephemeral state")
	}
	forged, err := encodePlainRecord(contentAlert, 600, []byte{1, 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.receive(forged, time.Unix(1000, 0)); err != nil || server.peerClosed != nil {
		t.Fatalf("plaintext alert affected an authenticated session: %v", err)
	}
	if err := client.application([]byte("still authenticated")); err != nil {
		t.Fatal(err)
	}
	if data := deliverSessionPackets(t, client, server, packets, time.Unix(1000, 0)); len(data) != 1 {
		t.Fatal("plaintext injection prevented authenticated application traffic")
	}
}
