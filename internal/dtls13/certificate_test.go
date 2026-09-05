package dtls13

import (
	"bytes"
	"testing"

	"github.com/oittaa/socat/internal/testcert"
)

func TestCertificateWire(t *testing.T) {
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeCertificate(cert.Certificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := parseCertificate(wire, nil)
	if err != nil || len(chain) != 1 || !bytes.Equal(chain[0], cert.Certificate[0]) {
		t.Fatalf("certificate parse: %v", err)
	}
	parsed, err := parseCertificateChain(chain)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("X.509 parse: %v", err)
	}
	for n := 0; n < len(wire); n++ {
		if _, err := parseCertificate(wire[:n], nil); err == nil {
			t.Fatalf("accepted truncated certificate at %d", n)
		}
	}
	if _, err := parseCertificate(wire, []byte{1}); err == nil {
		t.Fatal("accepted mismatched request context")
	}
	empty, err := encodeCertificate(nil, nil)
	if err != nil || !bytes.Equal(empty, []byte{0, 0, 0, 0}) {
		t.Fatalf("empty certificate: %x, %v", empty, err)
	}
	if chain, err := parseCertificate(empty, nil); err != nil || len(chain) != 0 {
		t.Fatal("rejected empty client certificate list")
	}
}

func TestCertificateWireLimitsAndExtensions(t *testing.T) {
	if _, err := encodeCertificate([][]byte{nil}, nil); err == nil {
		t.Fatal("encoded empty certificate entry")
	}
	if _, err := encodeCertificate(make([][]byte, maxCertificates+1), nil); err == nil {
		t.Fatal("encoded excessive chain length")
	}
	if _, err := encodeCertificate([][]byte{make([]byte, maxHandshakeBody)}, nil); err == nil {
		t.Fatal("encoded excessive certificate body")
	}
	if _, err := encodeCertificate(nil, make([]byte, 256)); err == nil {
		t.Fatal("encoded excessive request context")
	}
	if _, err := parseCertificate(decodeHex(t, "0000000a000001010006000100020304"), nil); err == nil {
		t.Fatal("accepted malformed list length")
	}
	if _, err := parseCertificate(decodeHex(t, "0000000c000001010006000100020304"), nil); err == nil {
		t.Fatal("accepted unrequested certificate extension")
	}
	if _, err := parseCertificateChain([][]byte{{1, 2, 3}}); err == nil {
		t.Fatal("accepted malformed DER")
	}
}

func FuzzCertificate(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	cert, err := testcert.EphemeralSelfSigned()
	if err != nil {
		f.Fatal(err)
	}
	wire, err := encodeCertificate(cert.Certificate, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxContent {
			return
		}
		if chain, err := parseCertificate(data, nil); err == nil {
			if len(chain) > maxCertificates {
				t.Fatal("certificate count exceeds bound")
			}
			_, _ = parseCertificateChain(chain)
		}
	})
}
