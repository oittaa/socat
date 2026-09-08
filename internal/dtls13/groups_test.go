package dtls13

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
)

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
