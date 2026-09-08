package dtls13

import (
	"errors"
	"testing"
)

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
