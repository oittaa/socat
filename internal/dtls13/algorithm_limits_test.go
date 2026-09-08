package dtls13

import (
	"bytes"
	"errors"
	"testing"
)

func TestChaChaSequenceMaskRFC8439(t *testing.T) {
	// RFC 8439 section 2.3.2, with the DTLS counter/nonce sample layout.
	keys := &trafficKeys{sn: (*chaChaSequenceKey)(decodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))}
	sample := decodeHex(t, "01000000000000090000004a00000000")
	mask, err := keys.mask(sample)
	if err != nil || !bytes.Equal(mask[:], decodeHex(t, "10f1e7e4d13b5915500fdd1fa32071c4")) {
		t.Fatalf("ChaCha20 sequence mask: %x, %v", mask, err)
	}
	for _, n := range []int{0, 4, 15} {
		if _, err := keys.mask(sample[:n]); !errors.Is(err, errAuthentication) {
			t.Fatalf("accepted short sample: %v", err)
		}
	}
	copy(sample[:4], []byte{255, 255, 255, 255})
	if _, err := keys.mask(sample); err != nil {
		t.Fatal(err)
	}
}
