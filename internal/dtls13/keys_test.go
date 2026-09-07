package dtls13

import (
	"slices"
	"testing"
)

func TestDefaultCipherSuitesPreference(t *testing.T) {
	catalog := make([]uint16, 0, len(cipherSuites))
	for _, suite := range cipherSuites {
		catalog = append(catalog, suite.id)
	}
	aesFirst := []uint16{aes128GCM, aes256GCM, chaCha20Poly1305}
	chachaFirst := []uint16{chaCha20Poly1305, aes128GCM, aes256GCM}
	if !slices.Equal(defaultCipherSuitesTLS13, aesFirst) || !slices.Equal(defaultCipherSuitesTLS13NoAES, chachaFirst) {
		t.Fatalf("preference lists: AES %x; no-AES %x", defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES)
	}
	for _, list := range [][]uint16{defaultCipherSuitesTLS13, defaultCipherSuitesTLS13NoAES} {
		got := slices.Clone(list)
		slices.Sort(got)
		want := slices.Clone(catalog)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Fatalf("list %x is not the catalog %x", list, catalog)
		}
	}
	got := defaultCipherSuites()
	want := defaultCipherSuitesTLS13
	if !hasAESGCMHardware() {
		want = defaultCipherSuitesTLS13NoAES
	}
	if &got[0] != &want[0] {
		t.Fatal("defaultCipherSuites copied the preference list")
	}
	_, server := handshakeConfigs(t)
	prepared, err := prepareConfig(server, true)
	if err != nil {
		t.Fatal(err)
	}
	if &prepared.CipherSuites[0] != &got[0] {
		t.Fatal("prepareConfig copied the preference list")
	}
}
