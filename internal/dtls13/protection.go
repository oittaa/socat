// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

var errAuthentication = errors.New("dtls: record authentication failed")

const (
	// seqNumMaskLen is the DTLS 1.3 sequence-number sample and mask (RFC 9147 §4.2.3).
	seqNumMaskLen = 16
	// aeadNonceLen is the per-record nonce for AES-GCM and ChaCha20-Poly1305 (RFC 8446 §5.3).
	aeadNonceLen = 12
)

type trafficKeys struct {
	aead        cipher.AEAD
	sn          cipher.Block
	snChaCha    []byte
	recordLimit uint64
	iv          [aeadNonceLen]byte
	// Session record processing owns these buffers; traffic keys are not shared between goroutines.
	nonceBuffer  [aeadNonceLen]byte
	maskBuffer   [seqNumMaskLen]byte
	headerBuffer [maxUnifiedHeader]byte
}

func newTrafficKeys(id uint16, secret []byte) (*trafficKeys, error) {
	suite, err := suiteFor(id)
	if err != nil {
		return nil, err
	}
	if len(secret) != suite.hash().Size() {
		return nil, errKeyMaterial
	}
	key, err := expandLabel(suite.hash, secret, "key", nil, suite.keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := expandLabel(suite.hash, secret, "iv", nil, aeadNonceLen)
	if err != nil {
		return nil, err
	}
	snKey, err := expandLabel(suite.hash, secret, "sn", nil, suite.keyLen)
	if err != nil {
		return nil, err
	}
	if id == chaCha20Poly1305 {
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, err
		}
		keys := &trafficKeys{aead: aead, snChaCha: snKey, recordLimit: suite.recordLimit}
		copy(keys.iv[:], iv)
		return keys, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sn, err := aes.NewCipher(snKey)
	if err != nil {
		return nil, err
	}
	keys := &trafficKeys{aead: aead, sn: sn, recordLimit: suite.recordLimit}
	copy(keys.iv[:], iv)
	return keys, nil
}

func (k *trafficKeys) nonce(sequence uint64) [aeadNonceLen]byte {
	nonce := k.iv
	val := binary.BigEndian.Uint64(nonce[4:]) ^ sequence
	binary.BigEndian.PutUint64(nonce[4:], val)
	return nonce
}

func (k *trafficKeys) mask(ciphertext []byte) ([seqNumMaskLen]byte, error) {
	if len(ciphertext) < seqNumMaskLen {
		return [seqNumMaskLen]byte{}, errAuthentication
	}
	if k.snChaCha != nil {
		sample := ciphertext[:seqNumMaskLen]
		stream, err := chacha20.NewUnauthenticatedCipher(k.snChaCha, sample[len(sample)-chacha20.NonceSize:])
		if err != nil {
			return [seqNumMaskLen]byte{}, err
		}
		stream.SetCounter(binary.LittleEndian.Uint32(sample))
		clear(k.maskBuffer[:])
		stream.XORKeyStream(k.maskBuffer[:], k.maskBuffer[:])
	} else {
		k.sn.Encrypt(k.maskBuffer[:], ciphertext[:seqNumMaskLen])
	}
	return k.maskBuffer, nil
}

// The caller owns sequence allocation and enforces record/key usage limits.
func (k *trafficKeys) seal(dst, header []byte, sequence uint64, plaintext []byte) []byte {
	k.nonceBuffer = k.nonce(sequence)
	return k.aead.Seal(dst, k.nonceBuffer[:], plaintext, header)
}

func (k *trafficKeys) open(header []byte, sequence uint64, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < k.aead.Overhead() {
		return nil, errAuthentication
	}
	k.nonceBuffer = k.nonce(sequence)
	plaintext, err := k.aead.Open(nil, k.nonceBuffer[:], ciphertext, header)
	if err != nil {
		return nil, errAuthentication
	}
	return plaintext, nil
}
