// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls13

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// Pion's independently encoded AES vectors use a CID and a 64-bit sequence.
func TestRecordProtectionVectors(t *testing.T) {
	for _, test := range []struct {
		name       string
		suite      uint16
		secretLen  int
		key        string
		iv         string
		snKey      string
		nonce      string
		ciphertext string
		mask       string
	}{
		{
			name: "AES128", suite: aes128GCM, secretLen: 32,
			key:        "cc95abc258d309424ddbf7cba68bd77e",
			iv:         "6d3299305dd209fc865cf8f1",
			snKey:      "c5b1a0649ea4fdafbe7e256665068222",
			nonce:      "6d3299305dd30bff8259fef6",
			ciphertext: "82bacfceae1035329372dbcbdce0240faf434e68077fb4df25edc71ddd89db18b510ccd2518b77499d7e",
			mask:       "adc05ac9d6be3e1570d34d94457bdb31",
		},
		{
			name: "AES256", suite: aes256GCM, secretLen: 48,
			key:        "d6732c55efc102933ffe3af6922bdb7fe44d18f2b7307173758bfeb457a6f9bb",
			iv:         "8ae6b315daa064c6dfa5f10a",
			snKey:      "fc6f78156052e019518fb3ea0d77c796ca2da8796cc26b8e42c5b5395a72af1d",
			nonce:      "8ae6b315daa166c5dba0f70d",
			ciphertext: "799936beea392e94f73b56ad19e96f5ff607481e8abf5aa6895414e222eea46b4e2385ac65b6fc516ede",
			mask:       "cdefbbfbc4863ce5602213c2290c989e",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			secret := make([]byte, test.secretLen)
			for i := range secret {
				secret[i] = byte(i)
			}
			suite, err := suiteFor(test.suite)
			if err != nil {
				t.Fatal(err)
			}
			for label, expected := range map[string]string{"key": test.key, "iv": test.iv, "sn": test.snKey} {
				want := decodeHex(t, expected)
				got, err := expandLabel(suite.hash, secret, label, nil, len(want))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("%s = %x, %v; want %x", label, got, err, want)
				}
			}
			keys, err := newTrafficKeys(test.suite, secret)
			if err != nil {
				t.Fatal(err)
			}
			const sequence = uint64(0x0001020304050607)
			nonce := keys.nonce(sequence)
			if !bytes.Equal(nonce[:], decodeHex(t, test.nonce)) {
				t.Fatalf("nonce = %x; want %s", nonce, test.nonce)
			}
			text := "dtls13 aes-128-gcm vector"
			if test.suite == aes256GCM {
				text = "dtls13 aes-256-gcm vector"
			}
			plaintext := append([]byte(text), 23)
			header := decodeHex(t, "3fcafebabe0607002a")
			ciphertext := keys.seal(header, sequence, plaintext)
			if !bytes.Equal(ciphertext, decodeHex(t, test.ciphertext)) {
				t.Fatalf("ciphertext = %x; want %s", ciphertext, test.ciphertext)
			}
			mask, err := keys.mask(ciphertext)
			if err != nil || !bytes.Equal(mask[:], decodeHex(t, test.mask)) {
				t.Fatalf("mask = %x, %v; want %s", mask, err, test.mask)
			}
			opened, err := keys.open(header, sequence, ciphertext)
			if err != nil || !bytes.Equal(opened, plaintext) {
				t.Fatalf("open = %x, %v; want %x", opened, err, plaintext)
			}
			for i := range ciphertext {
				mutated := bytes.Clone(ciphertext)
				mutated[i] ^= 1
				if _, err := keys.open(header, sequence, mutated); !errors.Is(err, errAuthentication) {
					t.Fatalf("accepted ciphertext mutation at %d: %v", i, err)
				}
			}
			for i := range header {
				mutated := bytes.Clone(header)
				mutated[i] ^= 1
				if _, err := keys.open(mutated, sequence, ciphertext); !errors.Is(err, errAuthentication) {
					t.Fatalf("accepted header mutation at %d: %v", i, err)
				}
			}
			if _, err := keys.open(header, sequence+1, ciphertext); !errors.Is(err, errAuthentication) {
				t.Fatalf("accepted wrong sequence: %v", err)
			}
			for n := 0; n < len(ciphertext); n++ {
				if _, err := keys.open(header, sequence, ciphertext[:n]); !errors.Is(err, errAuthentication) {
					t.Fatalf("accepted truncated ciphertext at %d: %v", n, err)
				}
			}
		})
	}
}

func TestExpandLabelRejectsInvalidInput(t *testing.T) {
	for _, test := range []struct {
		name    string
		label   string
		context []byte
		length  int
	}{
		{name: "empty label", length: 16},
		{name: "long label", label: strings.Repeat("a", 250), length: 16},
		{name: "long context", label: "key", context: make([]byte, 256), length: 16},
		{name: "negative length", label: "key", length: -1},
		{name: "HKDF limit", label: "key", length: 255*sha256.Size + 1},
		{name: "wire limit", label: "key", length: 65536},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := expandLabel(sha256.New, make([]byte, 32), test.label, test.context, test.length); !errors.Is(err, errHKDFLabel) {
				t.Fatalf("invalid label accepted: %v", err)
			}
		})
	}
	if _, err := expandLabel(nil, nil, "key", nil, 16); !errors.Is(err, errHKDFLabel) {
		t.Fatalf("nil hash accepted: %v", err)
	}
}

func TestTrafficKeysRejectInvalidParameters(t *testing.T) {
	if _, err := newTrafficKeys(0, make([]byte, 32)); !errors.Is(err, errCipherSuite) {
		t.Fatalf("unknown suite accepted: %v", err)
	}
	for _, id := range []uint16{aes128GCM, aes256GCM} {
		if _, err := newTrafficKeys(id, []byte("short")); !errors.Is(err, errKeyMaterial) {
			t.Fatalf("short secret accepted: %v", err)
		}
	}
}

func decodeHex(t testing.TB, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
