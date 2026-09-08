package dtls13

import (
	"encoding/binary"
	"errors"
	"testing"
)

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

func testTrafficKeys(t testing.TB) *trafficKeys {
	t.Helper()
	keys, err := newTrafficKeys(aes128GCM, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return keys
}
