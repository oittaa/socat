package dtls13

import (
	"bytes"
	"errors"
	"testing"
)

func TestChaChaSequenceMaskRFC8439(t *testing.T) {
	// RFC 8439 section 2.3.2, with the DTLS counter/nonce sample layout.
	keys := &trafficKeys{snChaCha: decodeHex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")}
	sample := decodeHex(t, "01000000000000090000004a00000000")
	mask, err := keys.mask(sample)
	if err != nil || !bytes.Equal(mask[:], decodeHex(t, "10f1e7e4d13b5915500fdd1fa32071c4")) {
		t.Fatalf("ChaCha20 sequence mask: %x, %v", mask, err)
	}
	for _, n := range []int{0, 4, 15} {
		if _, err := keys.mask(sample[:n]); !errors.Is(err, errAuthentication) {
			t.Fatalf("accepted short sample: %v", err)
		}
	}
	copy(sample[:4], []byte{255, 255, 255, 255})
	if _, err := keys.mask(sample); err != nil {
		t.Fatal(err)
	}
}

func TestCipherSpecificKeyUsageLimits(t *testing.T) {
	for _, tc := range []struct {
		suite uint16
		limit uint64
	}{
		{aes128GCM, 1 << 24}, {aes256GCM, 1 << 24}, {chaCha20Poly1305, 1 << 48},
	} {
		clientConfig, serverConfig := handshakeConfigs(t)
		clientConfig.CipherSuites = []uint16{tc.suite}
		serverConfig.CipherSuites = []uint16{tc.suite}
		client, _, _ := driveSessions(t, clientConfig, serverConfig, false, false)
		writer := client.write[client.currentWriteEpoch()]
		writer.sequence = tc.limit - 1025
		if err := client.application([]byte("last record before update margin")); err != nil {
			t.Fatal(err)
		}
		if err := client.application([]byte("triggers update")); !errors.Is(err, errUpdatePending) {
			t.Fatalf("cipher %x did not request key update: %v", tc.suite, err)
		}
		writer.sequence = tc.limit
		if _, err := client.sendRecord(client.currentWriteEpoch(), contentData, nil); !errors.Is(err, errSequence) {
			t.Fatalf("cipher %x exceeded its key usage limit: %v", tc.suite, err)
		}
	}
}
