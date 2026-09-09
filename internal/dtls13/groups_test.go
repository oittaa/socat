package dtls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

func TestClientShareEntryLenMatchesEncoding(t *testing.T) {
	for _, group := range defaultGroups() {
		private, err := generateShare(uint16(group))
		if err != nil {
			t.Fatal(err)
		}
		share, err := encodeKeyShare(uint16(group), private.public)
		n, sizeErr := clientShareEntryLen(uint16(group))
		if err != nil || sizeErr != nil || n != len(share) {
			t.Fatalf("%s: entry %d, wire %d, %v %v", group, n, len(share), err, sizeErr)
		}
	}
}

func TestKeyExchangeRejectsUnknownSelectors(t *testing.T) {
	unknownKEM := keyExchangeGroup{curve: ecdh.X25519(), kem: kemKind(1)}
	if _, _, err := unknownKEM.split(make([]byte, 32), shareFromClient); !errors.Is(err, errIllegalParameter) {
		t.Fatalf("unknown KEM accepted: %v", err)
	}
	unknownCurve := keyExchangeGroup{kem: kemNone}
	if _, _, err := unknownCurve.split(nil, shareFromClient); !errors.Is(err, errIllegalParameter) {
		t.Fatalf("unknown curve accepted: %v", err)
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	share := &keyShare{group: unknownKEM, ecdh: key}
	if _, err := share.shared(make([]byte, 32)); !errors.Is(err, errIllegalParameter) {
		t.Fatalf("shared accepted unknown KEM: %v", err)
	}
}
