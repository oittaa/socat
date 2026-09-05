package dtls13

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"testing"
)

func TestCertificateVerifyAlgorithms(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		scheme uint16
		signer crypto.Signer
	}{
		{uint16(tls.PSSWithSHA256), rsaKey}, {uint16(tls.PSSWithSHA384), rsaKey},
		{uint16(tls.PSSWithSHA512), rsaKey}, {uint16(tls.Ed25519), edKey},
	}
	for _, tc := range []struct {
		scheme tls.SignatureScheme
		curve  elliptic.Curve
	}{
		{tls.ECDSAWithP256AndSHA256, elliptic.P256()},
		{tls.ECDSAWithP384AndSHA384, elliptic.P384()},
		{tls.ECDSAWithP521AndSHA512, elliptic.P521()},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			scheme uint16
			signer crypto.Signer
		}{uint16(tc.scheme), key})
	}
	hash := sha256.Sum256([]byte("handshake transcript"))
	for _, tc := range cases {
		t.Run(tls.SignatureScheme(tc.scheme).String(), func(t *testing.T) {
			selected, err := selectSignature(tc.signer.Public(), []uint16{tc.scheme})
			if err != nil || selected != tc.scheme {
				t.Fatalf("signature selection: %x, %v", selected, err)
			}
			wire, err := signCertificateVerify(tc.signer, tc.scheme, hash[:], true)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyCertificateVerify(tc.signer.Public(), signatureSchemes, wire, hash[:], true); err != nil {
				t.Fatal(err)
			}
			if err := verifyCertificateVerify(tc.signer.Public(), signatureSchemes, wire, hash[:], false); err == nil {
				t.Fatal("server signature accepted in client context")
			}
			otherHash := hash
			otherHash[0] ^= 1
			if err := verifyCertificateVerify(tc.signer.Public(), signatureSchemes, wire, otherHash[:], true); err == nil {
				t.Fatal("signature accepted with altered transcript")
			}
			if err := verifyCertificateVerify(tc.signer.Public(), nil, wire, hash[:], true); err == nil {
				t.Fatal("unoffered signature scheme accepted")
			}
			changed := bytes.Clone(wire)
			changed[len(changed)-1] ^= 1
			if err := verifyCertificateVerify(tc.signer.Public(), signatureSchemes, changed, hash[:], true); err == nil {
				t.Fatal("corrupted signature accepted")
			}
			for n := 0; n < len(wire); n++ {
				if err := verifyCertificateVerify(tc.signer.Public(), signatureSchemes, wire[:n], hash[:], true); err == nil {
					t.Fatalf("truncated signature accepted at %d", n)
				}
			}
		})
	}
}

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
	if _, _, err := signatureDigest(uint16(tls.Ed25519), []byte{1}, true); err == nil {
		t.Fatal("accepted invalid transcript hash size")
	}
}

func TestCertificateVerifyEnforcesCurveAndPSSSalt(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if keySupportsSignature(ecdsaKey.Public(), uint16(tls.ECDSAWithP384AndSHA384)) {
		t.Fatal("signature scheme accepted on wrong named curve")
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	transcript := sha256.Sum256([]byte("handshake transcript"))
	digest, _, err := signatureDigest(uint16(tls.PSSWithSHA256), transcript[:], true)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	w := wireWriter{}
	w.uint16(uint16(tls.PSSWithSHA256))
	w.vector16(sig)
	if err := verifyCertificateVerify(rsaKey.Public(), signatureSchemes, w.data, transcript[:], true); err == nil {
		t.Fatal("accepted PSS salt shorter than the hash")
	}
}
