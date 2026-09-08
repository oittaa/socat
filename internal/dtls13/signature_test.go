package dtls13

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"testing"
)

func TestCertificateVerifyContextVector(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	transcript := sha256.Sum256([]byte("handshake transcript"))
	wire, err := signCertificateVerify(key, uint16(tls.Ed25519), transcript[:], true)
	if err != nil {
		t.Fatal(err)
	}
	input := append(bytes.Repeat([]byte{' '}, 64), []byte("TLS 1.3, server CertificateVerify\x00")...)
	input = append(input, transcript[:]...)
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), input, wire[4:]) {
		t.Fatal("signature does not cover the TLS 1.3 CertificateVerify context")
	}
	if _, err := signCertificateVerify(key, uint16(tls.PKCS1WithSHA256), transcript[:], true); err == nil {
		t.Fatal("selected obsolete CertificateVerify algorithm")
	}
	if _, _, err := signatureInput(uint16(tls.Ed25519), []byte{1}, true); err == nil {
		t.Fatal("accepted invalid transcript hash size")
	}
}
