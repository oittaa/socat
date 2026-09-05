package dtls13

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type capturedFragment struct {
	number   recordNumber
	fragment handshakeFragment
}

func flightSender(t *testing.T, output *[]capturedFragment) func(uint64, []byte) (recordNumber, error) {
	t.Helper()
	var sequence uint64
	return func(epoch uint64, data []byte) (recordNumber, error) {
		f, rest, err := parseFragment(data)
		if err != nil || len(rest) != 0 {
			t.Fatalf("invalid sent fragment: %v", err)
		}
		n := recordNumber{epoch, sequence}
		sequence++
		*output = append(*output, capturedFragment{n, f})
		return n, nil
	}
}

func TestFlightSelectiveACKAndChangedMTU(t *testing.T) {
	body := []byte("abcdefghijkl")
	f, err := newFlight([]handshakeMessage{{typ: 11, epoch: 2, body: body}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	clear(body)
	var output []capturedFragment
	send := flightSender(t, &output)
	now := time.Unix(100, 0)
	if err := f.transmit(now, 4, send); err != nil {
		t.Fatal(err)
	}
	if len(output) != 3 {
		t.Fatalf("sent %d fragments", len(output))
	}
	first, middle, last := output[0].number, output[1].number, output[2].number
	if f.acknowledge([]recordNumber{first, last}, false) {
		t.Fatal("plaintext ACK covered encrypted data")
	}
	if f.acknowledge([]recordNumber{{2, 999}}, true) {
		t.Fatal("ACK covered an unsent record")
	}
	if !f.acknowledge([]recordNumber{first, last}, true) {
		t.Fatal("valid ACK did not advance flight")
	}
	if err := f.transmit(now.Add(time.Second), 2, send); err != nil {
		t.Fatal(err)
	}
	if len(output) != 5 || output[3].fragment.offset != 4 || output[4].fragment.offset != 6 || !bytes.Equal(output[3].fragment.body, []byte("ef")) || !bytes.Equal(output[4].fragment.body, []byte("gh")) {
		t.Fatalf("retransmissions: %+v", output)
	}
	if !f.acknowledge([]recordNumber{middle}, true) || !f.complete || !f.deadline.IsZero() {
		t.Fatal("delayed ACK of original transmission failed to complete flight")
	}
	if err := f.transmit(now, 2, send); err != nil || len(output) != 5 {
		t.Fatal("completed flight retransmitted")
	}
}

func TestFlightBurstAndPartialACKs(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: 11, epoch: 2, body: make([]byte, 25)}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var output []capturedFragment
	send := flightSender(t, &output)
	now := time.Unix(100, 0)
	for _, count := range []int{10, 10, 5} {
		start := len(output)
		if err := f.transmit(now, 1, send); err != nil {
			t.Fatal(err)
		}
		if len(output)-start != count {
			t.Fatalf("burst size %d, want %d", len(output)-start, count)
		}
		acks := make([]recordNumber, 0, count)
		for _, packet := range output[start:] {
			acks = append(acks, packet.number)
		}
		if !f.acknowledge(acks, true) {
			t.Fatal("ACK failed to advance burst")
		}
	}
	if !f.complete {
		t.Fatal("large flight not completed")
	}
}

func TestFlightEmptyMessageAndImplicitACK(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: 9, epoch: 3}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var output []capturedFragment
	if err := f.transmit(time.Unix(100, 0), 1, flightSender(t, &output)); err != nil {
		t.Fatal(err)
	}
	if len(output) != 1 || f.complete {
		t.Fatal("empty handshake was not transmitted")
	}
	if !f.acknowledge([]recordNumber{output[0].number}, true) || !f.complete {
		t.Fatal("empty message was not acknowledged")
	}
	g, err := newFlight([]handshakeMessage{{typ: 1, body: []byte{1}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.finish()
	if retry, err := g.expire(time.Unix(200, 0)); retry || err != nil {
		t.Fatal("implicit acknowledgement retained timer")
	}
}

func TestFlightTimerBackoffAndExhaustion(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: 1, body: []byte{1}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var output []capturedFragment
	send := flightSender(t, &output)
	now := time.Unix(100, 0)
	if err := f.transmit(now, 1, send); err != nil {
		t.Fatal(err)
	}
	for i := range maxFlightRetries {
		if retry, err := f.expire(f.deadline.Add(-time.Nanosecond)); retry || err != nil {
			t.Fatal("timer fired early")
		}
		now = f.deadline
		if retry, err := f.expire(now); !retry || err != nil {
			t.Fatalf("expiry %d: %t, %v", i, retry, err)
		}
		want := min(time.Duration(1<<(i+1))*time.Second, time.Minute)
		if f.interval != want {
			t.Fatalf("interval %s, want %s", f.interval, want)
		}
		if err := f.transmit(now, 1, send); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.expire(f.deadline); !errors.Is(err, errHandshakeTimeout) {
		t.Fatalf("retry exhaustion: %v", err)
	}
	for i, packet := range output {
		if packet.number.sequence != uint64(i) || packet.fragment.sequence != 0 {
			t.Fatal("record and handshake sequences confused")
		}
	}
}

func TestACKWire(t *testing.T) {
	numbers := []recordNumber{{2, 9}, {0, 1}, {2, 9}, {2, 3}}
	wire, err := encodeACK(numbers)
	if err != nil {
		t.Fatal(err)
	}
	want := decodeHex(t, "0030000000000000000000000000000000010000000000000002000000000000000300000000000000020000000000000009")
	if !bytes.Equal(wire, want) {
		t.Fatalf("ACK %x; want %x", wire, want)
	}
	got, err := parseACK(wire)
	if err != nil || len(got) != 3 || got[0] != (recordNumber{0, 1}) || got[1] != (recordNumber{2, 3}) || got[2] != (recordNumber{2, 9}) {
		t.Fatalf("decoded ACK: %v, %v", got, err)
	}
	if numbers[0] != (recordNumber{2, 9}) {
		t.Fatal("encoder mutated caller's records")
	}
	for i := range len(wire) {
		if _, err := parseACK(wire[:i]); err == nil {
			t.Fatalf("accepted truncated ACK at %d", i)
		}
	}
	for _, data := range [][]byte{{0, 1, 0}, {0, 0, 0}, make([]byte, maxContent+1)} {
		if _, err := parseACK(data); err == nil {
			t.Fatal("accepted malformed ACK")
		}
	}
	if _, err := encodeACK(make([]recordNumber, maxContent/16)); err == nil {
		t.Fatal("encoded oversized ACK")
	}
	if got, err := parseACK([]byte{0, 0}); err != nil || len(got) != 0 {
		t.Fatal("empty ACK rejected")
	}
}
