package dtls13

import (
	"testing"
)

func helloVector(t testing.TB) []byte {
	t.Helper()
	return decodeHex(t, "fefd000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000000041301130201000017000a000600040017001d002b000302fefc003300020000")
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
