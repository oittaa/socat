package dtls13

import (
	"bytes"
	"errors"
	"testing"
)

func TestLegacySessionIDInDTLSHello(t *testing.T) {
	clientConfig, serverConfig := handshakeConfigs(t)
	client, messages, err := newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	client.hello.sessionID = []byte("previous DTLS 1.2 session")
	messages[0].body, err = client.hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	client.firstHello, err = messages[0].transcript()
	if err != nil {
		t.Fatal(err)
	}
	server, err := newServerHandshake(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	a, b := client.handle, server.handle
	for step := 0; step < 8 && len(messages) != 0; step++ {
		var next []handshakeMessage
		for _, m := range messages {
			if m.typ == msgServerHello {
				hello, err := parseServerHello(m.body)
				if err != nil || len(hello.sessionID) != 0 {
					t.Fatalf("server echoed legacy session ID: %v", err)
				}
			}
			response, err := b(m)
			if err != nil {
				t.Fatal(err)
			}
			next = append(next, response...)
		}
		messages, a, b = next, b, a
	}
	if !client.complete || !server.complete {
		t.Fatal("legacy session ID prevented a DTLS 1.3 handshake")
	}
}

func TestClientRejectsEchoedLegacySessionID(t *testing.T) {
	clientConfig, _ := handshakeConfigs(t)
	client, _, err := newClientHandshake(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	client.hello.sessionID = []byte("cached session")
	hello := serverHello{random: retryRandom, sessionID: client.hello.sessionID, suite: aes128GCM,
		extensions: extensions{extSupportedVersions: {0xfe, 0xfc}, extCookie: {0, 1, 1}}}
	body, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.handle(handshakeMessage{typ: msgServerHello, body: body}); !errors.Is(err, errIllegalParameter) {
		t.Fatalf("accepted echoed session ID: %v", err)
	}
}

func TestRetryPSKIdentities(t *testing.T) {
	encode := func(names ...string) []byte {
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
	first := encode("first", "second", "third")
	for _, test := range []struct {
		names []string
		want  bool
	}{
		{[]string{"first", "second", "third"}, true},
		{[]string{"second"}, true},
		{[]string{"first", "third"}, true},
		{[]string{"third", "first"}, false},
		{[]string{"new"}, false},
		{[]string{"first", "first"}, false},
	} {
		if got := retryPSKIdentities(first, encode(test.names...)); got != test.want {
			t.Fatalf("retry identities %v: %t", test.names, got)
		}
	}
	if !retryPSKIdentities(first, nil) || retryPSKIdentities(nil, first) {
		t.Fatal("PSK extension addition/removal mishandled")
	}
}
