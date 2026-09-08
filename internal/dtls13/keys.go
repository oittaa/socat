// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtls13 implements the DTLS 1.3 protocol over datagrams.
package dtls13

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/sys/cpu"
)

const (
	aes128GCM        = uint16(tls.TLS_AES_128_GCM_SHA256)
	aes256GCM        = uint16(tls.TLS_AES_256_GCM_SHA384)
	chaCha20Poly1305 = uint16(tls.TLS_CHACHA20_POLY1305_SHA256)
)

var (
	errCipherSuite = errors.New("dtls: unsupported cipher suite")
	errKeyMaterial = errors.New("dtls: invalid key material")
	errHKDFLabel   = errors.New("dtls: invalid HKDF label")
)

type cipherSuite struct {
	id          uint16
	hash        func() hash.Hash
	keyLen      int
	recordLimit uint64
}

var cipherSuites = []cipherSuite{
	{aes128GCM, sha256.New, 16, 1 << 24},
	{aes256GCM, sha512.New384, 32, 1 << 24},
	{chaCha20Poly1305, sha256.New, 32, 1 << 48},
}

// Preference order matches crypto/tls. AES-first when AES-GCM hardware is available.
var (
	defaultCipherSuitesTLS13      = []uint16{aes128GCM, aes256GCM, chaCha20Poly1305}
	defaultCipherSuitesTLS13NoAES = []uint16{chaCha20Poly1305, aes128GCM, aes256GCM}
)

func hasAESGCMHardware() bool {
	return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ || cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
}

func defaultCipherSuites() []uint16 {
	if hasAESGCMHardware() {
		return defaultCipherSuitesTLS13
	}
	return defaultCipherSuitesTLS13NoAES
}

func suiteFor(id uint16) (cipherSuite, error) {
	for _, suite := range cipherSuites {
		if suite.id == id {
			return suite, nil
		}
	}
	return cipherSuite{}, errCipherSuite
}

// expandLabel uses DTLS's label prefix, without a trailing space.
func expandLabel(newHash func() hash.Hash, secret []byte, label string, context []byte, length int) ([]byte, error) {
	const prefix = "dtls13"
	labelLen, contextLen := len(label), len(context)
	if newHash == nil || labelLen == 0 || labelLen > 255-len(prefix) || contextLen > 255 || length < 0 || length > 65535 {
		return nil, errHKDFLabel
	}
	if length > 255*newHash().Size() {
		return nil, errHKDFLabel
	}
	// uint16 output length, followed by two uint8-length vectors.
	var buffer [2 + 1 + 255 + 1 + 255]byte
	info := binary.BigEndian.AppendUint16(buffer[:0], uint16(length))
	info = append(info, byte(labelLen)+byte(len(prefix)))
	info = append(info, prefix...)
	info = append(info, label...)
	info = append(info, byte(contextLen))
	info = append(info, context...)
	return hkdf.Expand(newHash, secret, string(info), length)
}
