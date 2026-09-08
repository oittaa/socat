package dtls13

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"hash"
	"testing"
)

func BenchmarkExpandLabel(b *testing.B) {
	for _, tc := range []struct {
		name, label string
		hash        func() hash.Hash
		contextLen  int
		length      int
	}{
		{"Key", "key", sha256.New, 0, 16},
		{"DerivedSHA256", "derived", sha256.New, sha256.Size, sha256.Size},
		{"DerivedSHA384", "derived", sha512.New384, sha512.Size384, sha512.Size384},
	} {
		b.Run(tc.name, func(b *testing.B) {
			secret := make([]byte, tc.hash().Size())
			context := make([]byte, tc.contextLen)
			b.ReportAllocs()
			for b.Loop() {
				if _, err := expandLabel(tc.hash, secret, tc.label, context, tc.length); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTrafficKeys(b *testing.B) {
	for _, suite := range cipherSuites {
		b.Run(tls.CipherSuiteName(suite.id), func(b *testing.B) {
			secret := make([]byte, suite.hash().Size())
			b.Run("New", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := newTrafficKeys(suite.id, secret); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("Mask", func(b *testing.B) {
				keys, err := newTrafficKeys(suite.id, secret)
				if err != nil {
					b.Fatal(err)
				}
				sample := make([]byte, seqNumMaskLen)
				b.ReportAllocs()
				for b.Loop() {
					if _, err := keys.mask(sample); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
