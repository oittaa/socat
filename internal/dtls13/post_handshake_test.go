package dtls13

import (
	"encoding/binary"
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

const rfc9147HandshakeHeader = 12

func rfc9147Uint24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

// rfc9147KeyUpdateFlag reads the KeyUpdateRequest from a DTLSHandshake body
// (RFC 9147 §5.2 / RFC 9846 §4.7.3). It does not use handshakeMessage.fragment.
func rfc9147KeyUpdateFlag(plaintext []byte) (byte, bool) {
	if len(plaintext) < rfc9147HandshakeHeader+1 || plaintext[0] != msgKeyUpdate {
		return 0, false
	}
	length := rfc9147Uint24(plaintext[1:4])
	offset := rfc9147Uint24(plaintext[6:9])
	fragLen := rfc9147Uint24(plaintext[9:12])
	if offset != 0 || fragLen != length || length != 1 || len(plaintext) < rfc9147HandshakeHeader+fragLen {
		return 0, false
	}
	flag := plaintext[rfc9147HandshakeHeader]
	if flag > 1 {
		return 0, false
	}
	return flag, true
}

func TestRFC9147KeyUpdateFlagRejectsNonKeyUpdate(t *testing.T) {
	header := make([]byte, rfc9147HandshakeHeader+1)
	header[0] = msgFinished
	binary.BigEndian.PutUint16(header[2:4], 1)
	header[11] = 1
	if _, ok := rfc9147KeyUpdateFlag(header); ok {
		t.Fatal("Finished parsed as KeyUpdate")
	}
	header[0] = msgKeyUpdate
	header[rfc9147HandshakeHeader] = 2
	if _, ok := rfc9147KeyUpdateFlag(header); ok {
		t.Fatal("illegal KeyUpdateRequest parsed")
	}
}
