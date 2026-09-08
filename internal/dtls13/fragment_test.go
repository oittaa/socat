package dtls13

import (
	"bytes"
	"testing"
)

func fragmentFor(t testing.TB, m handshakeMessage, offset, length int) []byte {
	t.Helper()
	b, err := m.fragment(offset, length)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHandshakeFragmentWireAndTranscript(t *testing.T) {
	m := handshakeMessage{typ: 11, sequence: 0x1234, epoch: 2, body: []byte("abcdef")}
	fragment := fragmentFor(t, m, 2, 3)
	want := decodeHex(t, "0b0000061234000002000003636465")
	if !bytes.Equal(fragment, want) {
		t.Fatalf("fragment %x; want %x", fragment, want)
	}
	f, rest, err := parseFragment(append(fragment, 99))
	if err != nil || len(rest) != 1 || rest[0] != 99 || f.total != 6 || f.offset != 2 || f.sequence != m.sequence || !bytes.Equal(f.body, []byte("cde")) {
		t.Fatalf("fragment parse: %+v, rest %x, error %v", f, rest, err)
	}
	transcript, err := m.transcript()
	if err != nil || !bytes.Equal(transcript, decodeHex(t, "0b000006616263646566")) {
		t.Fatalf("transcript %x, error %v", transcript, err)
	}
}

func TestHandshakeFragmentEmptyAndConcatenated(t *testing.T) {
	a := handshakeMessage{typ: 9, epoch: 3}
	b := handshakeMessage{typ: 24, sequence: 1, epoch: 3, body: []byte{0}}
	packet := append(fragmentFor(t, a, 0, 0), fragmentFor(t, b, 0, 1)...)
	r := reassembler{}
	if accepted, err := r.add(packet, 3); !accepted || err != nil {
		t.Fatalf("combined record: %t, %v", accepted, err)
	}
	for _, want := range []handshakeMessage{a, b} {
		got, ok := r.pop()
		if !ok || got.typ != want.typ || !bytes.Equal(got.body, want.body) {
			t.Fatalf("pop: %+v, %t", got, ok)
		}
	}
}

func TestHandshakeFragmentRejectsTruncation(t *testing.T) {
	m := handshakeMessage{typ: 1, body: []byte("hello")}
	packet := fragmentFor(t, m, 0, 5)
	for i := range len(packet) {
		if _, _, err := parseFragment(packet[:i]); err == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	packet[8] = 1
	if _, _, err := parseFragment(packet); err == nil {
		t.Fatal("accepted fragment ending beyond the message")
	}
	for _, span := range [][2]int{{-1, 1}, {0, -1}, {6, 0}, {4, 2}} {
		if _, err := m.fragment(span[0], span[1]); err == nil {
			t.Fatalf("encoded invalid span %v", span)
		}
	}
}

func FuzzHandshakeFragments(f *testing.F) {
	f.Add(decodeHex(f, "01000005000000000000000568656c6c6f"))
	f.Add(decodeHex(f, "090000000000000000000000"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxContent {
			return
		}
		r := reassembler{}
		_, _ = r.add(data, 2)
		for {
			m, ok := r.pop()
			if !ok {
				break
			}
			if len(m.body) > maxHandshakeBody {
				t.Fatal("message exceeds limit")
			}
		}
		if r.buffered < 0 || r.buffered > 2*maxHandshakeBody || len(r.pending) > maxPendingMessages {
			t.Fatal("reassembly exceeds limits")
		}
	})
}
