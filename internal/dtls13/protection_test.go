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

type stubOverheadAEAD struct {
	overhead int
}

func (s stubOverheadAEAD) NonceSize() int { return aeadNonceLen }
func (s stubOverheadAEAD) Overhead() int  { return s.overhead }
func (s stubOverheadAEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	return append(dst, plaintext...)
}
func (s stubOverheadAEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	return []byte("opened"), nil
}

func TestOpenUsesAEADOverhead(t *testing.T) {
	keys := &trafficKeys{aead: stubOverheadAEAD{overhead: 32}}
	if _, err := keys.open(nil, 0, make([]byte, 31)); !errors.Is(err, errAuthentication) {
		t.Fatalf("accepted ciphertext shorter than AEAD overhead: %v", err)
	}
}

func TestExpandLabelMaximumFields(t *testing.T) {
	secret := make([]byte, sha256.Size)
	for i := range secret {
		secret[i] = byte(i)
	}
	// Independent HMAC-SHA256 vector for a 514-byte HkdfLabel and counter 1.
	want := decodeHex(t, "2b6ba7480f5f9759e8d2299be4886d10b1e91371deaab0c9b553f22294fabe7b")
	got, err := expandLabel(sha256.New, secret, strings.Repeat("a", 249), bytes.Repeat([]byte{'c'}, 255), sha256.Size)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("maximum label/context = %x, %v; want %x", got, err, want)
	}
}

func TestTrafficKeysRejectInvalidParameters(t *testing.T) {
	if _, err := newTrafficKeys(0, make([]byte, 32)); !errors.Is(err, errCipherSuite) {
		t.Fatalf("unknown suite accepted: %v", err)
	}
	for _, id := range defaultCipherSuites() {
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
