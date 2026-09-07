package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func protectRecord(t *testing.T, keys *trafficKeys, number recordNumber, cid []byte, typ byte, content []byte) []byte {
	t.Helper()
	first := byte(0x2c) | byte(number.epoch&3)
	if len(cid) != 0 {
		first |= 0x10
	}
	seqOffset := 1 + len(cid)
	headerLen := seqOffset + unifiedSeqLen + unifiedLengthLen
	innerLen := len(content) + 1
	protectedLen := innerLen + keys.aead.Overhead()
	packet := make([]byte, headerLen+protectedLen)
	packet[0] = first
	copy(packet[1:seqOffset], cid)
	binary.BigEndian.PutUint16(packet[seqOffset:], uint16(number.sequence&0xffff))
	binary.BigEndian.PutUint16(packet[seqOffset+unifiedSeqLen:], uint16(protectedLen))
	copy(packet[headerLen:], content)
	packet[headerLen+len(content)] = typ
	header := packet[:headerLen]
	inner := packet[headerLen : headerLen+innerLen]
	keys.seal(inner[:0], header, number.sequence, inner)
	mask, err := keys.mask(packet[headerLen:])
	if err != nil {
		t.Fatal(err)
	}
	for i := range unifiedSeqLen {
		packet[seqOffset+i] ^= mask[i]
	}
	return packet
}

func surviveApplication(t *testing.T, client, server *session, packets *[]testDatagram, now time.Time, marker string) {
	t.Helper()
	if err := client.application([]byte(marker)); err != nil {
		t.Fatal(err)
	}
	got := deliverSessionPackets(t, client, server, packets, now)
	if len(got) != 1 || string(got[0]) != marker {
		t.Fatalf("authenticated exchange after injection: %q", got)
	}
}

func TestEstablishedSessionSurvivesUnauthenticatedRecords(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	if err := client.application([]byte("baseline")); err != nil {
		t.Fatal(err)
	}
	first := bytes.Clone((*packets)[0].data)
	if got := deliverSessionPackets(t, client, server, packets, now); len(got) != 1 || string(got[0]) != "baseline" {
		t.Fatalf("baseline: %q", got)
	}
	plaintextAlert, err := encodePlainRecord(contentAlert, 600, []byte{2, 10})
	if err != nil {
		t.Fatal(err)
	}
	plaintextHandshake, err := encodePlainRecord(contentHandshake, 601, []byte{msgKeyUpdate, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1})
	if err != nil {
		t.Fatal(err)
	}
	forged := bytes.Clone(first)
	forged[len(forged)-1] ^= 1
	for i, datagram := range [][]byte{
		{0xff},
		{contentHandshake, 0xfe, 0xfd},
		forged,
		first,
		plaintextAlert,
		plaintextHandshake,
	} {
		if _, err := server.receive(datagram, now); err != nil {
			t.Fatalf("unauthenticated datagram %d terminated the association: %v", i, err)
		}
		surviveApplication(t, client, server, packets, now, "after-"+string(rune('a'+i)))
	}
}

func TestAuthenticatedInvalidInnerContentAborts(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, _ := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	w := client.write[client.currentWriteEpoch()]
	cid := client.handshake.peerCID
	packet := protectRecord(t, w.keys, recordNumber{client.currentWriteEpoch(), w.sequence}, cid, 99, []byte("x"))
	if _, err := server.receive(packet, now); !errors.Is(err, errUnexpectedMessage) {
		t.Fatalf("invalid inner content type: %v", err)
	}
}

func TestAuthenticatedMalformedAlertAndACKAbort(t *testing.T) {
	a, b := handshakeConfigs(t)
	client, server, _ := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	w := client.write[client.currentWriteEpoch()]
	cid := client.handshake.peerCID
	epoch := client.currentWriteEpoch()
	alert := protectRecord(t, w.keys, recordNumber{epoch, w.sequence}, cid, contentAlert, []byte{2})
	if _, err := server.receive(alert, now); !errors.Is(err, errDecode) {
		t.Fatalf("truncated authenticated alert: %v", err)
	}
	client2, server2, _ := driveSessions(t, a, b, false, false)
	w2 := client2.write[client2.currentWriteEpoch()]
	ack := protectRecord(t, w2.keys, recordNumber{client2.currentWriteEpoch(), w2.sequence}, client2.handshake.peerCID, contentACK, []byte{0, 1, 0})
	if _, err := server2.receive(ack, now); !errors.Is(err, errACK) {
		t.Fatalf("malformed authenticated ACK: %v", err)
	}
}
