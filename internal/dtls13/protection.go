// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

var errAuthentication = errors.New("dtls: record authentication failed")

type trafficKeys struct {
	aead cipher.AEAD
	sn   cipher.Block
	iv   [12]byte
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
	iv, err := expandLabel(suite.hash, secret, "iv", nil, 12)
	if err != nil {
		return nil, err
	}
	snKey, err := expandLabel(suite.hash, secret, "sn", nil, suite.keyLen)
	if err != nil {
		return nil, err
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
	keys := &trafficKeys{aead: aead, sn: sn}
	copy(keys.iv[:], iv)
	return keys, nil
}

func (k *trafficKeys) nonce(sequence uint64) [12]byte {
	nonce := k.iv
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], sequence)
	for i, b := range encoded {
		nonce[4+i] ^= b
	}
	return nonce
}

func (k *trafficKeys) mask(ciphertext []byte) ([16]byte, error) {
	var mask [16]byte
	if len(ciphertext) < aes.BlockSize {
		return mask, errAuthentication
	}
	k.sn.Encrypt(mask[:], ciphertext[:aes.BlockSize])
	return mask, nil
}

// The caller owns sequence allocation and enforces record/key usage limits.
func (k *trafficKeys) seal(header []byte, sequence uint64, plaintext []byte) []byte {
	nonce := k.nonce(sequence)
	return k.aead.Seal(nil, nonce[:], plaintext, header)
}

func (k *trafficKeys) open(header []byte, sequence uint64, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errAuthentication
	}
	nonce := k.nonce(sequence)
	plaintext, err := k.aead.Open(nil, nonce[:], ciphertext, header)
	if err != nil {
		return nil, errAuthentication
	}
	return plaintext, nil
}
