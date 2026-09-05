package dtls13

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Literal ServerHello fields and extension vectors keep these alert cases
// independent of our encoder (RFC 9147 section 5; RFC 9846 sections 4.2-4.3).
func serverHelloWireMessage(t *testing.T, retry bool, sequence uint16, extensionHex string) handshakeMessage {
	t.Helper()
	random := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	if retry {
		random = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
	}
	return handshakeMessage{typ: msgServerHello, sequence: sequence,
		body: decodeHex(t, "fefd"+random+"00130100"+extensionHex)}
}

func TestClientHelloVersionAlerts(t *testing.T) {
	config, _ := handshakeConfigs(t)
	for _, stage := range []string{"retry", "server_hello", "server_hello_after_retry"} {
		for _, test := range []struct {
			name, extensions string
			alert            byte
		}{
			{"dtls12", "0006002b0002fefd", 47},
			{"unoffered_version", "0006002b00020a0a", 47},
			{"empty_version", "0004002b0000", 50},
			{"short_version", "0005002b0001fe", 50},
			{"long_version", "0007002b0003fefc00", 50},
			{"missing_version", "0000", 70},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				client, _, err := newClientHandshake(config)
				if err != nil {
					t.Fatal(err)
				}
				var sequence uint16
				if stage == "server_hello_after_retry" {
					retry := serverHelloWireMessage(t, true, 0, "000d002b0002fefc002c0003000101")
					messages, err := client.handle(retry)
					if err != nil || len(messages) != 1 || messages[0].typ != msgClientHello {
						t.Fatalf("cookie retry: messages %v, error %v", messages, err)
					}
					sequence = 1
				}
				_, err = client.handle(serverHelloWireMessage(t, stage == "retry", sequence, test.extensions))
				if err == nil || !bytes.Equal(errorAlert(err), []byte{2, test.alert}) {
					t.Fatalf("alert = %x (%v), want fatal %d", errorAlert(err), err, test.alert)
				}
			})
		}
	}
}

func TestClientHelloExtensionAlerts(t *testing.T) {
	config, _ := handshakeConfigs(t)
	for _, stage := range []string{"retry", "server_hello"} {
		for _, test := range []struct {
			name, extensions string
			offerALPN        bool
			alert            byte
		}{
			{"signature_algorithms", "000d0000", false, 47},
			{"supported_groups", "000a0000", false, 47},
			{"server_name", "00000000", false, 47},
			{"offered_alpn", "00100000", true, 47},
			{"unsolicited_alpn", "00100000", false, 110},
			{"unknown_extension", "fafa0000", false, 110},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				clientConfig := *config
				if test.offerALPN {
					clientConfig.NextProtos = []string{"test"}
				}
				client, _, err := newClientHandshake(&clientConfig)
				if err != nil {
					t.Fatal(err)
				}
				extensions := "000a002b0002fefc" + test.extensions
				if stage == "retry" {
					extensions = "0011002b0002fefc002c0003000101" + test.extensions
				}
				_, err = client.handle(serverHelloWireMessage(t, stage == "retry", 0, extensions))
				if err == nil || !bytes.Equal(errorAlert(err), []byte{2, test.alert}) {
					t.Fatalf("alert = %x (%v), want fatal %d", errorAlert(err), err, test.alert)
				}
			})
		}
	}
}

func TestClientEncryptedExtensionAlerts(t *testing.T) {
	clientConfig, serverConfig := handshakeConfigs(t)
	for _, test := range []struct {
		name, extensions string
		alert            byte
	}{
		// RFC 9846 section 4.4.1 forbids these extensions in EncryptedExtensions.
		{"key_share", "000600330002001d", 47},
		{"supported_versions", "0006002b0002fefc", 47},
		{"signature_algorithms", "0004000d0000", 47},
		{"cookie_after_retry", "0007002c0003000101", 47},
		{"unsolicited_alpn", "0009001000050003026832", 110},
		{"unknown_extension", "0004fafa0000", 110},
		{"empty", "0000", 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, messages, err := newClientHandshake(clientConfig)
			if err != nil {
				t.Fatal(err)
			}
			server, err := newTestServerHandshake(serverConfig)
			if err != nil {
				t.Fatal(err)
			}
			peer, now := netip.MustParseAddrPort("127.0.0.1:10001"), time.Unix(100, 0)
			// Complete the cookie exchange and consume ServerHello before testing EE.
			for range 2 {
				if len(messages) != 1 || messages[0].typ != msgClientHello {
					t.Fatalf("expected ClientHello, got %v", messages)
				}
				flight, err := server.receive(messages[0], peer, now)
				if err != nil || len(flight) == 0 {
					t.Fatalf("server flight: messages %v, error %v", flight, err)
				}
				messages, err = client.handle(flight[0])
				if err != nil {
					t.Fatal(err)
				}
			}
			// Literal extension vectors exercise decoding independently of our encoder.
			_, err = client.handle(handshakeMessage{typ: msgEncryptedExtensions, epoch: 2, sequence: 2,
				body: decodeHex(t, test.extensions)})
			if test.alert == 0 {
				if err != nil {
					t.Fatalf("valid EncryptedExtensions: %v", err)
				}
			} else if err == nil || !bytes.Equal(errorAlert(err), []byte{2, test.alert}) {
				t.Fatalf("alert = %x (%v), want fatal %d", errorAlert(err), err, test.alert)
			}
		})
	}
}

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
	server, err := newTestServerHandshake(serverConfig)
	if err != nil {
		t.Fatal(err)
	}
	a, b := client.handle, func(m handshakeMessage) ([]handshakeMessage, error) {
		return server.receive(m, netip.MustParseAddrPort("127.0.0.1:10001"), time.Unix(100, 0))
	}
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
	first := pskIdentityHashes(testPSKOffer("first", "second", "third"))
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
		if got := retryIdentitySubset(first, pskIdentityHashes(testPSKOffer(test.names...))); got != test.want {
			t.Fatalf("retry identities %v: %t", test.names, got)
		}
	}
	if !retryIdentitySubset(first, nil) || retryIdentitySubset(nil, first) {
		t.Fatal("PSK extension addition/removal mishandled")
	}
}
