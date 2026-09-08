package dtls13

import (
	"bytes"
	"testing"
	"time"
)

func TestParseACKRejectsMalformedLengths(t *testing.T) {
	records := make([]recordNumber, 48)
	for i := range records {
		records[i] = recordNumber{2, uint64(i + 1)}
	}
	wire, err := encodeACK(records)
	if err != nil {
		t.Fatal(err)
	}
	overstated := append([]byte{0, 32}, make([]byte, 16)...)
	understated := append([]byte{0, 16}, make([]byte, 32)...)
	notAligned := append([]byte{0, 17}, make([]byte, 17)...)
	for _, data := range [][]byte{wire[:2+460], overstated, understated, notAligned} {
		if _, err := parseACK(data); err == nil {
			t.Fatalf("accepted malformed ACK %x", data[:min(len(data), 8)])
		}
	}
}

func TestFlightOneTransmissionIsTenRecords(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: msgCertificate, body: bytes.Repeat([]byte{1}, 5000), epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	if err := f.transmit(time.Unix(1, 0), 200, func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(f.sent) != flightBurst || !f.pendingSend() {
		t.Fatalf("transmission sent %d records pending=%v", len(f.sent), f.pendingSend())
	}
	covered := 0
	first := make(map[recordNumber]sentFragment, len(f.sent))
	for n, p := range f.sent {
		first[n] = p
		covered = max(covered, p.end)
	}
	if err := f.transmit(time.Unix(1, 0), 200, func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}); err != nil {
		t.Fatal(err)
	}
	for n, p := range f.sent {
		if _, dup := first[n]; !dup && p.start < covered {
			t.Fatalf("new-byte send overlapped [%d,%d) already covered to %d", p.start, p.end, covered)
		}
	}
}

func TestFlightAcknowledgesOlderTransmission(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: msgCertificate, body: bytes.Repeat([]byte{1}, 400), epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var seq uint64
	send := func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}
	now := time.Unix(1, 0)
	if err := f.transmit(now, 50, send); err != nil {
		t.Fatal(err)
	}
	first := make([]recordNumber, 0, len(f.sent))
	for n := range f.sent {
		first = append(first, n)
	}
	retransmit, err := f.expire(now.Add(f.interval))
	if err != nil || !retransmit {
		t.Fatalf("expire: %v %v", retransmit, err)
	}
	if err := f.transmit(now.Add(f.interval), 50, send); err != nil {
		t.Fatal(err)
	}
	if !f.acknowledge(first, true) {
		t.Fatal("older transmission ACK made no progress")
	}
	for _, n := range first {
		if _, ok := f.sent[n]; ok {
			t.Fatalf("acked record %v still mapped", n)
		}
	}
}
