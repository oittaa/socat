package dtls13

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func testPSKOffer(names ...string) []byte {
	identities, binders := wireWriter{}, wireWriter{}
	for _, name := range names {
		identities.vector16([]byte(name))
		identities.data = append(identities.data, 0, 0, 0, 1)
		binders.vector8(bytes.Repeat([]byte{1}, 32))
	}
	w := wireWriter{}
	w.vector16(identities.data)
	w.vector16(binders.data)
	return w.data
}

func cookieTestHello(t *testing.T, suite uint16, request bool) (*Config, *clientHandshake, handshakeMessage) {
	t.Helper()
	a, b := handshakeConfigs(t)
	a.CipherSuites, b.CipherSuites = []uint16{suite}, []uint16{suite}
	a.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	b.CurvePreferences = []tls.CurveID{tls.X25519}
	if request {
		b.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	client, messages, err := newClientHandshake(a)
	if err != nil {
		t.Fatal(err)
	}
	client.hello.extensions[extPSKModes] = []byte{1, 1}
	client.hello.extensions[extPreSharedKey] = testPSKOffer("first", "second", "third")
	messages[0].body, err = client.hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	client.firstHello, err = messages[0].transcript()
	if err != nil {
		t.Fatal(err)
	}
	b, err = prepareConfig(b, true)
	if err != nil {
		t.Fatal(err)
	}
	return b, client, messages[0]
}

func TestStatelessCookieTranscriptAndRetryFields(t *testing.T) {
	for _, suiteID := range []uint16{aes128GCM, aes256GCM, tls.TLS_CHACHA20_POLY1305_SHA256} {
		for _, request := range []bool{false, true} {
			t.Run(fmt.Sprintf("suite=%x/request=%t", suiteID, request), func(t *testing.T) {
				config, client, first := cookieTestHello(t, suiteID, request)
				key, peer, now := cookieKey{1}, netip.MustParseAddrPort("192.0.2.1:1234"), time.Unix(100, 0)
				offer, err := parseClientOffer(client.hello)
				if err != nil {
					t.Fatal(err)
				}
				retry, err := key.issue(config, peer, first, client.hello, offer, now)
				if err != nil {
					t.Fatal(err)
				}
				messages, err := client.handle(retry)
				if err != nil || len(messages) != 1 {
					t.Fatalf("retry response: %v", err)
				}
				secondWire := messages[0].body
				for _, change := range []string{"none", "padding", "psk_remove", "psk_absent", "random", "suites", "sni", "cid", "extension", "share", "early_data", "psk_add", "psk_reorder"} {
					hello, err := parseClientHello(bytes.Clone(secondWire))
					if err != nil {
						t.Fatal(err)
					}
					want := change == "none" || change == "padding" || change == "psk_remove" || change == "psk_absent" || change == "share" && request
					switch change {
					case "padding":
						hello.extensions[21] = make([]byte, 10)
					case "psk_remove":
						hello.extensions[extPreSharedKey] = testPSKOffer("first", "third")
					case "psk_absent":
						delete(hello.extensions, extPreSharedKey)
					case "psk_add":
						hello.extensions[extPreSharedKey] = testPSKOffer("fourth")
					case "psk_reorder":
						hello.extensions[extPreSharedKey] = testPSKOffer("third", "first")
					case "random":
						hello.random[0] ^= 1
					case "suites":
						hello.suites = append(hello.suites, 0xffff)
					case "sni":
						hello.extensions[extServerName], _ = encodeServerName("different.example")
					case "cid":
						hello.extensions[extConnectionID] = []byte{1, 99}
					case "extension":
						hello.extensions[0xfafa] = []byte{1}
					case "share":
						share := hello.extensions[extKeyShare]
						share[len(share)-1] ^= 1
					case "early_data":
						hello.extensions[extEarlyData] = nil
					}
					offer, err = parseClientOffer(hello)
					if err != nil {
						t.Fatal(err)
					}
					server, err := key.verify(config, peer, hello, offer, now)
					if (err == nil) != want {
						t.Fatalf("%s retry accepted=%t; want %t (%v)", change, err == nil, want, err)
					}
					if change == "none" {
						firstWire, _ := first.transcript()
						retryWire, _ := retry.transcript()
						second, _ := messages[0].transcript()
						wantTranscript, err := retryTranscript(suiteID, firstWire, retryWire, second)
						if err != nil {
							t.Fatal(err)
						}
						got, err := retryTranscriptHash(suiteID, server.firstHelloHash, server.retryHello, second)
						if err != nil || !bytes.Equal(got, wantTranscript) || server.sequence != 1 {
							t.Fatal("stateless retry changed the transcript or handshake sequence")
						}
					}
				}
			})
		}
	}
}

func TestStatelessCookieAuthenticationAndExpiry(t *testing.T) {
	config, client, first := cookieTestHello(t, aes128GCM, false)
	key, peer, now := cookieKey{1}, netip.MustParseAddrPort("[2001:db8::1]:1234"), time.Unix(100, 0)
	offer, err := parseClientOffer(client.hello)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := key.issue(config, peer, first, client.hello, offer, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.handle(retry); err != nil {
		t.Fatal(err)
	}
	offer, err = parseClientOffer(client.hello)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		key  cookieKey
		peer netip.AddrPort
		time time.Time
		want bool
	}{
		{"valid", key, peer, now, true},
		{"before_expiry", key, peer, now.Add(cookieLifetime - time.Second), true},
		{"expired", key, peer, now.Add(cookieLifetime), false},
		{"future", key, peer, now.Add(-time.Second), false},
		{"other_listener", cookieKey{2}, peer, now, false},
		{"other_ip", key, netip.MustParseAddrPort("[2001:db8::2]:1234"), now, false},
		{"other_port", key, netip.MustParseAddrPort("[2001:db8::1]:1235"), now, false},
		{"other_family", key, netip.MustParseAddrPort("192.0.2.1:1234"), now, false},
	} {
		if _, err := test.key.verify(config, test.peer, client.hello, offer, test.time); (err == nil) != test.want {
			t.Fatalf("%s: %v", test.name, err)
		}
	}
	for i := range len(offer.cookie) {
		changed := offer
		changed.cookie = bytes.Clone(offer.cookie)
		changed.cookie[i] ^= 1
		if _, err := key.verify(config, peer, client.hello, changed, now); !errors.Is(err, errIllegalParameter) {
			t.Fatalf("accepted modified cookie byte %d: %v", i, err)
		}
		changed.cookie = offer.cookie[:i]
		if _, err := key.verify(config, peer, client.hello, changed, now); !errors.Is(err, errIllegalParameter) {
			t.Fatalf("accepted truncated cookie at %d: %v", i, err)
		}
	}
	// Exercise payload parsing even with an authentic tag (future format errors).
	payload := offer.cookie[:len(offer.cookie)-sha256.Size]
	for i := range len(payload) {
		changed := offer
		changed.cookie = append(bytes.Clone(payload[:i]), key.mac(peer, payload[:i])...)
		if _, err := key.verify(config, peer, client.hello, changed, now); !errors.Is(err, errIllegalParameter) {
			t.Fatalf("accepted truncated authenticated cookie payload at %d: %v", i, err)
		}
	}
}
