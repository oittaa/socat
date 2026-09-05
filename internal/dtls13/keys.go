// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package dtls13 implements the DTLS 1.3 protocol over datagrams.
package dtls13

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
)

const (
	aes128GCM = uint16(0x1301)
	aes256GCM = uint16(0x1302)
)

var (
	errCipherSuite = errors.New("dtls: unsupported cipher suite")
	errKeyMaterial = errors.New("dtls: invalid key material")
	errHKDFLabel   = errors.New("dtls: invalid HKDF label")
)

type cipherSuite struct {
	hash   func() hash.Hash
	keyLen int
}

func suiteFor(id uint16) (cipherSuite, error) {
	switch id {
	case aes128GCM:
		return cipherSuite{sha256.New, 16}, nil
	case aes256GCM:
		return cipherSuite{sha512.New384, 32}, nil
	default:
		return cipherSuite{}, errCipherSuite
	}
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
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(labelLen)+byte(len(prefix)))
	info = append(info, prefix...)
	info = append(info, label...)
	info = append(info, byte(contextLen))
	info = append(info, context...)
	return hkdf.Expand(newHash, secret, string(info), length)
}
