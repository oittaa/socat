package dtls13

import (
	"bytes"
	"crypto/ecdh"
	"testing"
)

func TestKeySharesAndInvalidPoints(t *testing.T) {
	for _, group := range []uint16{groupP256, groupX25519} {
		local, err := generateShare(group)
		if err != nil {
			t.Fatal(err)
		}
		peer, err := generateShare(group)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := encodeKeyShare(group, peer.public)
		if err != nil {
			t.Fatal(err)
		}
		gotGroup, public, err := parseServerShare(wire)
		if err != nil || gotGroup != group {
			t.Fatalf("key share: %d, %v", gotGroup, err)
		}
		secret, err := computeShared(local.ecdh, public)
		if err != nil {
			t.Fatal(err)
		}
		want, err := peer.ecdh.ECDH(local.ecdh.PublicKey())
		if err != nil || !bytes.Equal(secret, want) {
			t.Fatal("shared-secret disagreement")
		}
		list := wireWriter{}
		list.vector16(wire)
		shares, err := parseClientShares(list.data, []uint16{group})
		if err != nil || !bytes.Equal(shares[group], public) {
			t.Fatalf("client shares: %v", err)
		}
		if _, err := parseClientShares(list.data, nil); err == nil {
			t.Fatal("accepted key share outside supported_groups")
		}
		duplicate := wireWriter{}
		duplicate.vector16(append(wire, wire...))
		if _, err := parseClientShares(duplicate.data, []uint16{group}); err == nil {
			t.Fatal("accepted duplicate group share")
		}
		for _, invalid := range [][]byte{nil, {0}, make([]byte, len(public))} {
			if _, err := computeShared(local.ecdh, invalid); err == nil {
				t.Fatal("accepted invalid point or noncontributory share")
			}
		}
	}
	if _, err := groupFor(0); err == nil {
		t.Fatal("accepted unsupported group")
	}
}

func TestX25519RFC7748(t *testing.T) {
	// RFC 7748 Section 6.1.
	private, err := ecdh.X25519().NewPrivateKey(decodeHex(t, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	public := decodeHex(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	secret, err := computeShared(private, public)
	if err != nil || !bytes.Equal(secret, decodeHex(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")) {
		t.Fatalf("RFC shared secret: %x, %v", secret, err)
	}
}

func TestNameAndProtocolExtensions(t *testing.T) {
	wire, err := encodeServerName("example.test")
	if err != nil {
		t.Fatal(err)
	}
	name, err := parseServerName(wire)
	if err != nil || name != "example.test" {
		t.Fatalf("SNI: %q, %v", name, err)
	}
	for _, name := range []string{"", "example.test.", "127.0.0.1", "::1", "[::1]", "test\x00invalid"} {
		if _, err := encodeServerName(name); err == nil {
			t.Fatalf("encoded invalid SNI %q", name)
		}
	}
	wire, err = encodeALPN([]string{"one", "two\x00three"})
	if err != nil {
		t.Fatal(err)
	}
	protocols, err := parseALPN(wire)
	if err != nil || len(protocols) != 2 || protocols[0] != "one" || protocols[1] != "two\x00three" {
		t.Fatalf("ALPN: %v, %v", protocols, err)
	}
	for n := 0; n < len(wire); n++ {
		if _, err := parseALPN(wire[:n]); err == nil {
			t.Fatalf("truncated ALPN accepted at %d", n)
		}
	}
	if _, err := encodeALPN([]string{""}); err == nil {
		t.Fatal("encoded empty ALPN identifier")
	}
	if _, err := parseALPN([]byte{0, 1, 0}); err == nil {
		t.Fatal("decoded empty ALPN identifier")
	}
}

func TestVersionCookieAndCIDExtensions(t *testing.T) {
	versions, err := parseVersions([]byte{4, 0xfe, 0xfc, 0xfe, 0xfd})
	if err != nil || len(versions) != 2 || versions[0] != version13 {
		t.Fatalf("versions: %v, %v", versions, err)
	}
	groups, err := encodeList16([]uint16{groupP256, groupX25519})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := parseList16(groups)
	if err != nil || len(decoded) != 2 || decoded[1] != groupX25519 {
		t.Fatalf("groups: %v, %v", decoded, err)
	}
	for _, wire := range [][]byte{nil, {0}, {1, 0}, {2, 0}, {2, 0xfe, 0xfc, 0}} {
		if _, err := parseVersions(wire); err == nil {
			t.Fatal("accepted malformed versions")
		}
	}
	if _, err := parseCookie([]byte{0, 0}); err == nil {
		t.Fatal("accepted empty retry cookie")
	}
	cookie, err := parseCookie([]byte{0, 2, 1, 2})
	if err != nil || !bytes.Equal(cookie, []byte{1, 2}) {
		t.Fatalf("cookie: %x, %v", cookie, err)
	}
	for _, wire := range [][]byte{{0}, {2, 1, 2}} {
		cid, err := parseConnectionID(wire)
		if err != nil || !bytes.Equal(cid, wire[1:]) {
			t.Fatalf("CID: %x, %v", cid, err)
		}
	}
	if _, err := parseConnectionID([]byte{0, 1}); err == nil {
		t.Fatal("accepted trailing CID data")
	}
}

func FuzzExtensions(f *testing.F) {
	f.Add([]byte{0, 2, 0, 23})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxContent {
			return
		}
		_, _ = parseList16(data)
		_, _ = parseVersions(data)
		_, _ = parseClientShares(data, []uint16{groupP256, groupX25519})
		_, _, _ = parseServerShare(data)
		_, _ = parseServerName(data)
		_, _ = parseALPN(data)
		_, _ = parseCookie(data)
		_, _ = parseConnectionID(data)
	})
}
