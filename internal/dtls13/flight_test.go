package dtls13

import (
	"testing"
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
