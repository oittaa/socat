package dtls13

import (
	"bytes"
	"errors"
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

func TestHandshakeReassemblyReorderAndOverlap(t *testing.T) {
	r := reassembler{}
	messages := []handshakeMessage{
		{typ: 8, epoch: 2, body: []byte("extensions")},
		{typ: 11, sequence: 1, epoch: 2, body: []byte("certificate")},
	}
	for _, part := range []struct{ message, offset, length int }{
		{1, 3, 8}, {0, 5, 5}, {1, 0, 6}, {0, 2, 6}, {0, 0, 4},
	} {
		m := messages[part.message]
		packet := fragmentFor(t, m, part.offset, part.length)
		if accepted, err := r.add(packet, m.epoch); !accepted || err != nil {
			t.Fatalf("add: %t, %v", accepted, err)
		}
		// Reassembly must own buffered bytes independently of receive buffers.
		clear(packet)
	}
	for _, want := range messages {
		got, ok := r.pop()
		if !ok || got.typ != want.typ || got.sequence != want.sequence || got.epoch != want.epoch || !bytes.Equal(got.body, want.body) {
			t.Fatalf("pop: %+v, %t; want %+v", got, ok, want)
		}
	}
	if _, ok := r.pop(); ok || r.buffered != 0 || len(r.pending) != 0 {
		t.Fatal("completed messages retained")
	}
	if accepted, err := r.add(fragmentFor(t, messages[0], 0, len(messages[0].body)), 2); !accepted || err != nil {
		t.Fatalf("previously processed message: %t, %v", accepted, err)
	}
	if _, ok := r.pop(); ok {
		t.Fatal("processed a retransmission twice")
	}
}

func TestHandshakeReassemblyIncompleteAndConflicting(t *testing.T) {
	m := handshakeMessage{typ: 11, epoch: 2, body: []byte("abcdef")}
	for _, change := range []string{"byte", "type", "length", "epoch"} {
		t.Run(change, func(t *testing.T) {
			r := reassembler{}
			if _, err := r.add(fragmentFor(t, m, 0, 3), 2); err != nil {
				t.Fatal(err)
			}
			if _, ok := r.pop(); ok {
				t.Fatal("returned a message with missing bytes")
			}
			packet := fragmentFor(t, m, 2, 3)
			epoch := uint64(2)
			switch change {
			case "byte":
				packet[handshakeHeader] ^= 1
			case "type":
				packet[0]++
			case "length":
				packet[3]++
			case "epoch":
				epoch++
			}
			if _, err := r.add(packet, epoch); !errors.Is(err, errFragmentConflict) {
				t.Fatalf("conflict: %v", err)
			}
		})
	}
}

func TestHandshakeReassemblyBoundsAndReservation(t *testing.T) {
	r := reassembler{}
	large := handshakeMessage{typ: 11, sequence: 1, epoch: 2, body: make([]byte, maxHandshakeBody)}
	if accepted, err := r.add(fragmentFor(t, large, 0, 1), 2); !accepted || err != nil {
		t.Fatalf("future fragment: %t, %v", accepted, err)
	}
	more := handshakeMessage{typ: 11, sequence: 2, epoch: 2, body: []byte{1}}
	if accepted, err := r.add(fragmentFor(t, more, 0, 1), 2); accepted || err != nil {
		t.Fatalf("over-budget future fragment: %t, %v", accepted, err)
	}
	large.sequence = 0
	if accepted, err := r.add(fragmentFor(t, large, 0, 1), 2); !accepted || err != nil {
		t.Fatalf("reserved next message: %t, %v", accepted, err)
	}
	if r.buffered != 2*maxHandshakeBody {
		t.Fatalf("buffer accounting: %d", r.buffered)
	}
	more.sequence = maxPendingMessages
	if accepted, err := r.add(fragmentFor(t, more, 0, 1), 2); accepted || err != nil {
		t.Fatalf("distant future message: %t, %v", accepted, err)
	}
	oversized := fragmentFor(t, large, 0, 1)
	oversized[3]++
	if _, err := r.add(oversized, 2); !errors.Is(err, errHandshakeLimit) {
		t.Fatalf("oversized declaration: %v", err)
	}
	if r.buffered != 2*maxHandshakeBody {
		t.Fatal("discarded fragments allocated storage")
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
