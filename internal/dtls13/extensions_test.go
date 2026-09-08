package dtls13

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

func TestX25519RFC7748(t *testing.T) {
	// RFC 7748 Section 6.1.
	private, err := ecdh.X25519().NewPrivateKey(decodeHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	public := decodeHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	secret, err := computeShared(private, public)
	if err != nil || !bytes.Equal(secret, decodeHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")) {
		t.Fatalf("RFC shared secret: %x, %v", secret, err)
	}
}

func FuzzExtensions(f *testing.F) {
	f.Add([]byte{0, 2, 0, 23})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxContent {
			return
		}
		_, _ = parseList16(data)
		_, _ = parseVersions(data)
		_, _ = parseClientShares(data, []uint16{groupP256, groupX25519})
		_, _, _ = parseServerShare(data)
		_, _ = parseServerName(data)
		_, _ = parseALPN(data)
		_, _ = parseCookie(data)
		_, _ = parseConnectionID(data)
	})
}
