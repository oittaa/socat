package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestRecordFraming(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("test-cid")
	for _, size := range []int{1, 2} {
		for _, length := range []bool{false, true} {
			for _, id := range [][]byte{nil, cid} {
				raw := testRecordForm(t, keys, size, length, id, contentData, []byte("message"))
				original := bytes.Clone(raw)
				r, rest, err := parseRecord(raw, len(id))
				if err != nil || len(rest) != 0 {
					t.Fatalf("parse record: %v, rest %x", err, rest)
				}
				var window replayWindow
				number, typ, content, err := keys.decodeRecord(r, 3, id, &window)
				if err != nil || typ != contentData || number != (recordNumber{3, 7}) || string(content) != "message" {
					t.Fatalf("decode: %v, %d, %v, %q", err, typ, number, content)
				}
				if !bytes.Equal(raw, original) {
					t.Fatal("decryption mutated the datagram")
				}
			}
		}
	}
	first, err := encodePlainRecord(contentHandshake, 0, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	last := testRecordForm(t, keys, 1, false, nil, contentData, []byte("final"))
	datagram := append(first, last...)
	r, rest, err := parseRecord(datagram, 0)
	if err != nil || r.encrypted || r.typ != contentHandshake || string(r.body) != "hello" || !bytes.Equal(rest, last) {
		t.Fatalf("first record: %v, rest %x", err, rest)
	}
	r, rest, err = parseRecord(rest, 0)
	if err != nil || !r.encrypted || len(rest) != 0 {
		t.Fatalf("last record: %v, rest %x", err, rest)
	}
}

func TestRecordEncodingAndReplay(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("test-cid")
	var window replayWindow
	for _, sequence := range []uint64{0, 2, 1, 63, 3, 66, 65} {
		payload := []byte{0, byte(sequence), 0}
		raw, err := keys.encodeRecord(recordNumber{3, sequence}, cid, contentData, payload, 7)
		if err != nil {
			t.Fatal(err)
		}
		r, rest, err := parseRecord(raw, len(cid))
		if err != nil || len(rest) != 0 {
			t.Fatal("record framing:", err)
		}
		number, typ, content, err := keys.decodeRecord(r, 3, cid, &window)
		if err != nil || number.sequence != sequence || typ != contentData || !bytes.Equal(content, payload) {
			t.Fatalf("decode sequence %d: %v, %v, %x", sequence, err, number, content)
		}
		before := window
		if _, _, _, err := keys.decodeRecord(r, 3, cid, &window); !errors.Is(err, errReplay) {
			t.Fatalf("accepted duplicate %d: %v", sequence, err)
		}
		if window != before {
			t.Fatal("duplicate advanced replay window")
		}
	}
	raw, err := keys.encodeRecord(recordNumber{3, 1}, cid, contentData, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := parseRecord(raw, len(cid))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := keys.decodeRecord(r, 3, cid, &window); !errors.Is(err, errReplay) {
		t.Fatalf("accepted record outside replay window: %v", err)
	}
}

func TestUnauthenticatedRecordDoesNotAdvanceWindow(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("test-cid")
	window := replayWindow{highest: 5, bits: 1}
	before := window
	raw, err := keys.encodeRecord(recordNumber{3, 30000}, cid, contentData, []byte("forged"), 0)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	r, _, err := parseRecord(raw, len(cid))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := keys.decodeRecord(r, 3, cid, &window); !errors.Is(err, errAuthentication) {
		t.Fatalf("accepted forged record: %v", err)
	}
	if window != before {
		t.Fatal("unauthenticated input advanced replay window")
	}
}

func TestRecordRejectsWrongAssociationAndEpoch(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("test-cid")
	raw, err := keys.encodeRecord(recordNumber{3, 0}, cid, contentData, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err := parseRecord(raw, len(cid))
	if err != nil {
		t.Fatal(err)
	}
	var window replayWindow
	if _, _, _, err := keys.decodeRecord(r, 3, []byte("othercid"), &window); !errors.Is(err, errAuthentication) {
		t.Fatalf("accepted wrong CID: %v", err)
	}
	if _, _, _, err := keys.decodeRecord(r, 4, cid, &window); !errors.Is(err, errAuthentication) {
		t.Fatalf("accepted wrong epoch: %v", err)
	}
}

func TestRecordRejectsMalformedFraming(t *testing.T) {
	keys := testTrafficKeys(t)
	raw := testRecordForm(t, keys, 2, true, []byte("test-cid"), contentData, []byte("message"))
	for n := 0; n < len(raw); n++ {
		if _, _, err := parseRecord(raw[:n], 8); err == nil {
			t.Fatalf("accepted truncated record of length %d", n)
		}
	}
	for _, data := range [][]byte{
		{20}, {23}, {24}, {25}, {64},
		decodeHex(t, "16fefd00010000000000000000"),
		append([]byte{0x2f, 0, 0, 0xff, 0xff}, make([]byte, 16)...),
		append([]byte{0x2f, 0, 0, 0, 15}, make([]byte, 15)...),
	} {
		if _, _, err := parseRecord(data, 0); err == nil {
			t.Fatalf("accepted invalid framing: %x", data)
		}
	}
	if _, _, err := parseRecord(raw, 0); err == nil {
		t.Fatal("accepted unnegotiated CID")
	}
}

func TestRecordIgnoresLegacyVersion(t *testing.T) {
	for _, version := range []uint16{0, 0x0304, 0xfefc, 0xfefd, 0xfeff, 0xffff} {
		packet, err := encodePlainRecord(contentHandshake, 7, []byte("hello"))
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint16(packet[1:3], version)
		r, rest, err := parseRecord(packet, 0)
		if err != nil || len(rest) != 0 || r.number.sequence != 7 || string(r.body) != "hello" {
			t.Fatalf("legacy record version %x influenced parsing: %v", version, err)
		}
	}
}

func TestRecordContentLimits(t *testing.T) {
	keys := testTrafficKeys(t)
	for _, typ := range []byte{contentAlert, contentHandshake, contentData, contentACK, contentRRC} {
		for _, size := range []int{0, 1, maxContent} {
			content := bytes.Repeat([]byte{0}, size)
			raw, err := keys.encodeRecord(recordNumber{3, 0}, nil, typ, content, 0)
			if err != nil {
				t.Fatal(err)
			}
			r, _, err := parseRecord(raw, 0)
			if err != nil {
				t.Fatal(err)
			}
			var window replayWindow
			_, gotType, got, err := keys.decodeRecord(r, 3, nil, &window)
			if err != nil || gotType != typ || !bytes.Equal(got, content) {
				t.Fatalf("type %d, size %d: %v", typ, size, err)
			}
		}
	}
	if _, err := keys.encodeRecord(recordNumber{3, 0}, nil, contentData, make([]byte, maxContent+1), 0); !errors.Is(err, errRecordOverflow) {
		t.Fatalf("accepted oversized content: %v", err)
	}
	if _, err := keys.encodeRecord(recordNumber{3, 0}, nil, contentData, nil, maxContent+1); !errors.Is(err, errRecordOverflow) {
		t.Fatalf("accepted oversized padding: %v", err)
	}
	if _, err := encodePlainRecord(contentHandshake, 1<<48, nil); !errors.Is(err, errSequence) {
		t.Fatalf("accepted wrapped plaintext sequence: %v", err)
	}
}

func TestSequenceReconstruction(t *testing.T) {
	for _, test := range []struct {
		truncated uint64
		size      int
		expected  uint64
		want      uint64
	}{
		{0, 1, 0, 0}, {255, 1, 0, 255}, {0, 1, 255, 256},
		{255, 1, 256, 255}, {0, 2, 65535, 65536}, {65535, 2, 65536, 65535},
		{0, 1, 128, 256}, {255, 1, math.MaxUint64, math.MaxUint64},
		{0, 1, math.MaxUint64, math.MaxUint64 - 255},
	} {
		if got := reconstructSequence(test.truncated, test.size, test.expected); got != test.want {
			t.Fatalf("%+v: got %d", test, got)
		}
	}
	var window replayWindow
	if !window.accept(math.MaxUint64) || window.next() != math.MaxUint64 || window.accept(math.MaxUint64) {
		t.Fatal("replay window wrapped at maximum sequence")
	}
}

func FuzzRecord(f *testing.F) {
	f.Add(decodeHex(f, "16fefd00000000000000000000"))
	f.Add(append([]byte{0x23, 0}, make([]byte, 17)...))
	f.Add([]byte{})
	keys, err := newTrafficKeys(aes128GCM, make([]byte, 32))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		for _, cidLen := range []int{0, 8, 255} {
			r, rest, err := parseRecord(input, cidLen)
			if err != nil {
				continue
			}
			if len(rest) >= len(input) || len(r.header)+len(r.body)+len(rest) != len(input) {
				t.Fatal("record parser made no progress")
			}
			if r.encrypted {
				var window replayWindow
				_, _, _, _ = keys.decodeRecord(r, r.number.epoch, r.cid, &window)
			}
		}
	})
}

func testTrafficKeys(t *testing.T) *trafficKeys {
	t.Helper()
	keys, err := newTrafficKeys(aes128GCM, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func testRecordForm(t *testing.T, keys *trafficKeys, seqSize int, includeLength bool, cid []byte, typ byte, content []byte) []byte {
	t.Helper()
	first := byte(0x23)
	if seqSize == 2 {
		first |= 0x08
	}
	if includeLength {
		first |= 0x04
	}
	if len(cid) != 0 {
		first |= 0x10
	}
	header := append([]byte{first}, cid...)
	offset := len(header)
	if seqSize == 2 {
		header = append(header, 0)
	}
	header = append(header, 7)
	inner := append(bytes.Clone(content), typ)
	if includeLength {
		header = binary.BigEndian.AppendUint16(header, uint16(len(inner)+16))
	}
	ciphertext := keys.seal(header, 7, inner)
	mask, err := keys.mask(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	for i := range seqSize {
		header[offset+i] ^= mask[i]
	}
	return append(header, ciphertext...)
}
