package dtls13

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func issuedCookie(t *testing.T, secrets *cookieSecrets, now time.Time) (*Config, netip.AddrPort, handshakeMessage) {
	t.Helper()
	clientCfg, serverCfg := handshakeConfigs(t)
	prepared, err := prepareConfig(serverCfg, true)
	if err != nil {
		t.Fatal(err)
	}
	client, messages, err := newClientHandshake(clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("client hello count = %d", len(messages))
	}
	ch0 := messages[0]
	hello, err := parseClientHello(ch0.body)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := parseClientOffer(hello)
	if err != nil {
		t.Fatal(err)
	}
	peer := netip.MustParseAddrPort("192.0.2.1:4433")
	retry, err := secrets.issue(prepared, peer, ch0, hello, offer, now)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := client.handle(retry)
	if err != nil {
		t.Fatal(err)
	}
	if len(replies) != 1 {
		t.Fatalf("retry replies = %d", len(replies))
	}
	return prepared, peer, replies[0]
}

func TestCookieSecretsOverlapAfterRotation(t *testing.T) {
	secrets := cookieSecrets{current: [32]byte{1}}
	config, peer, ch1 := issuedCookie(t, &secrets, time.Unix(159, 0))
	secrets.rotateTo([32]byte{2}, time.Unix(160, 0))
	if _, err := secrets.verify(config, peer, ch1, time.Unix(161, 0)); err != nil {
		t.Fatalf("cookie minted before rotation: %v", err)
	}
}

func TestCookieSecretsRejectsAfterTwoRotations(t *testing.T) {
	secrets := cookieSecrets{current: [32]byte{1}}
	now := time.Unix(100, 0)
	config, peer, ch1 := issuedCookie(t, &secrets, now)
	secrets.rotateTo([32]byte{2}, now.Add(cookieLifetime))
	secrets.rotateTo([32]byte{3}, now.Add(2*cookieLifetime))
	if _, err := secrets.verify(config, peer, ch1, now.Add(30*time.Second)); !errors.Is(err, errIllegalParameter) {
		t.Fatalf("cookie after two rotations: %v", err)
	}
}

func TestCookieSecretsIssueAfterRotation(t *testing.T) {
	secrets := cookieSecrets{current: [32]byte{1}}
	now := time.Unix(100, 0)
	secrets.rotateTo([32]byte{2}, now)
	config, peer, ch1 := issuedCookie(t, &secrets, now)
	if _, err := secrets.verify(config, peer, ch1, now); err != nil {
		t.Fatalf("cookie minted after rotation: %v", err)
	}
}

func TestCookieSecretsMaybeRotateInitializesWithoutRotating(t *testing.T) {
	secrets := cookieSecrets{current: [32]byte{1}}
	now := time.Unix(100, 0)
	secrets.maybeRotate(now)
	if secrets.current != [32]byte{1} || secrets.previous != [32]byte{} || !secrets.lastRotate.Equal(now) {
		t.Fatal("initialized by rotating the first key")
	}
}

func TestCookieSecretsMaybeRotateInterval(t *testing.T) {
	secrets := cookieSecrets{current: [32]byte{1}, lastRotate: time.Unix(100, 0)}
	secrets.maybeRotate(secrets.lastRotate.Add(cookieLifetime - time.Second))
	if secrets.current != [32]byte{1} || secrets.previous != [32]byte{} {
		t.Fatal("rotated before cookieLifetime")
	}
	secrets.maybeRotate(secrets.lastRotate.Add(cookieLifetime))
	if secrets.current == [32]byte{1} || secrets.previous != [32]byte{1} {
		t.Fatal("did not retain the previous HMAC key after cookieLifetime")
	}
}
