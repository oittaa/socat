package dtls13

import (
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
