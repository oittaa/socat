package dtls13

import (
	"testing"

	"github.com/oittaa/socat/internal/testcert"
)

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
