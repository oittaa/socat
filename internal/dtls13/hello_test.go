package dtls13

import (
	"bytes"
	"testing"
)

func helloVector(t testing.TB) []byte {
	t.Helper()
	return decodeHex(t, "fefd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000041301130201000017000a000600040017001d002b000302fefc003300020000")
}

func TestClientHelloWire(t *testing.T) {
	wire := helloVector(t)
	h, err := parseClientHello(wire)
	if err != nil {
		t.Fatal(err)
	}
	if h.random[0] != 0 || h.random[31] != 31 || len(h.sessionID) != 0 || len(h.suites) != 2 || h.suites[0] != aes128GCM || h.suites[1] != aes256GCM || len(h.extensions) != 3 {
		t.Fatalf("decoded hello: %+v", h)
	}
	got, err := h.marshal()
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("ClientHello: %x, %v", got, err)
	}
	for i := range len(wire) {
		if _, err := parseClientHello(wire[:i]); err == nil {
			t.Fatalf("accepted truncated hello at %d", i)
		}
	}
	if _, err := parseClientHello(append(wire, 0)); err == nil {
		t.Fatal("accepted trailing hello bytes")
	}
}

func TestClientHelloLegacyFields(t *testing.T) {
	for _, kind := range []string{"version", "cookie", "compression", "suites"} {
		t.Run(kind, func(t *testing.T) {
			wire := helloVector(t)
			switch kind {
			case "version":
				wire[1] = 0xff
			case "cookie":
				wire = append(wire[:35], append([]byte{1, 99}, wire[36:]...)...)
			case "compression":
				wire[43] = 1
			case "suites":
				wire[37] = 3
			}
			if _, err := parseClientHello(wire); err == nil {
				t.Fatal("accepted invalid legacy field")
			}
		})
	}
}

func TestServerHelloAndRetryWire(t *testing.T) {
	for _, retry := range []bool{false, true} {
		h := serverHello{suite: aes128GCM, extensions: extensions{extSupportedVersions: {0xfe, 0xfc}, extKeyShare: {0, 23}}}
		if retry {
			h.random = retryRandom
		}
		wire, err := h.marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseServerHello(wire)
		if err != nil || got.retry() != retry || got.suite != h.suite || got.random != h.random || !bytes.Equal(got.extensions[extSupportedVersions], []byte{0xfe, 0xfc}) {
			t.Fatalf("ServerHello: %+v, %v", got, err)
		}
		for i := range len(wire) {
			if _, err := parseServerHello(wire[:i]); err == nil {
				t.Fatalf("accepted truncated ServerHello at %d", i)
			}
		}
	}
}

func TestExtensionBoundaries(t *testing.T) {
	unknown := decodeHex(t, "fafa0003010203002b000302fefc")
	got, err := parseExtensions(unknown, msgClientHello)
	if err != nil || !bytes.Equal(got[0xfafa], []byte{1, 2, 3}) {
		t.Fatalf("unknown extension: %v", err)
	}
	for _, wire := range [][]byte{
		{0}, {0, 1, 0}, {0, 1, 0, 2, 0}, {0, 1, 0, 0, 0, 1, 0, 0},
	} {
		if _, err := parseExtensions(wire, msgClientHello); err == nil {
			t.Fatalf("accepted extensions %x", wire)
		}
	}
	pskFirst := []byte{0, 41, 0, 0, 0, 43, 0, 2, 0xfe, 0xfc}
	if _, err := parseExtensions(pskFirst, msgClientHello); err == nil {
		t.Fatal("ClientHello PSK was not last")
	}
	if _, err := parseExtensions(pskFirst, msgServerHello); err != nil {
		t.Fatal("applied ClientHello PSK ordering to ServerHello")
	}
	if _, err := (extensions{1: make([]byte, 65536)}).marshal(); err == nil {
		t.Fatal("encoded oversized extension")
	}
	list, err := uint16List([]byte{0, 23, 0, 29})
	if err != nil || len(list) != 2 || list[0] != 23 || list[1] != 29 {
		t.Fatalf("uint16 list: %v, %v", list, err)
	}
	if _, err := uint16List([]byte{1}); err == nil {
		t.Fatal("accepted odd uint16 list")
	}
}

func FuzzHello(f *testing.F) {
	f.Add(helloVector(f))
	f.Add([]byte{0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxContent {
			return
		}
		if hello, err := parseClientHello(data); err == nil {
			wire, err := hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseClientHello(wire); err != nil {
				t.Fatal(err)
			}
		}
		if hello, err := parseServerHello(data); err == nil {
			wire, err := hello.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseServerHello(wire); err != nil {
				t.Fatal(err)
			}
		}
		_, _ = parseACK(data)
	})
}
