package dtls13

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

// Deterministic protocol drivers use the production cookies without a listener.
// Admission limits, address routing and transport ownership are tested via Listen.
type testServerHandshake struct {
	*handshakeState
	server *serverHandshake
	key    cookieKey
}

func newTestServerHandshake(config *Config) (*testServerHandshake, error) {
	prepared, err := prepareConfig(config, true)
	if err != nil {
		return nil, err
	}
	return &testServerHandshake{handshakeState: &handshakeState{config: prepared}, key: cookieKey{1}}, nil
}

func (d *testServerHandshake) receive(m handshakeMessage, peer netip.AddrPort, now time.Time) ([]handshakeMessage, error) {
	if d.server != nil {
		return d.server.handle(m)
	}
	if m.typ == msgClientHello && m.epoch == 0 && m.sequence == 0 {
		hello, err := parseClientHello(m.body)
		if err != nil {
			return nil, err
		}
		offer, err := parseClientOffer(hello)
		if err != nil {
			return nil, err
		}
		if len(offer.cookie) != 0 {
			return nil, errIllegalParameter
		}
		retry, err := d.key.issue(d.config, peer, m, hello, offer, now)
		return []handshakeMessage{retry}, err
	}
	server, err := d.key.verify(d.config, peer, m, now)
	if err != nil {
		return nil, err
	}
	// Preserve the state pointer observed by the record/flight driver.
	*d.handshakeState = *server.handshakeState
	server.handshakeState = d.handshakeState
	d.server = server
	return server.handle(m)
}

func newTestServerSession(config *Config, send func([]byte) error) (*session, error) {
	d, err := newTestServerHandshake(config)
	if err != nil {
		return nil, err
	}
	var s *session
	s = newSession(d.handshakeState, func(m handshakeMessage) ([]handshakeMessage, error) {
		peer := netip.MustParseAddrPort("127.0.0.1:10001")
		if s.path != nil {
			peer = s.path.peer.remote
		}
		return d.receive(m, peer, s.handshakeReceived)
	}, send)
	return s, nil
}

func TestServerDriverValidatesStatelessCookies(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "other_peer", "other_key"} {
		t.Run(mode, func(t *testing.T) {
			a, b := handshakeConfigs(t)
			client, messages, err := newClientHandshake(a)
			if err != nil {
				t.Fatal(err)
			}
			d, err := newTestServerHandshake(b)
			if err != nil {
				t.Fatal(err)
			}
			peer, now := netip.MustParseAddrPort("192.0.2.1:1234"), time.Unix(100, 0)
			retry, err := d.receive(messages[0], peer, now)
			if err != nil || len(retry) != 1 || d.server != nil || len(d.localCID) != 0 {
				t.Fatalf("unvalidated ClientHello: retry count=%d, error=%v", len(retry), err)
			}
			messages, err = client.handle(retry[0])
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "expired":
				now = now.Add(cookieLifetime)
			case "other_peer":
				peer = netip.MustParseAddrPort("192.0.2.2:1234")
			case "other_key":
				d.key = cookieKey{2}
			}
			flight, err := d.receive(messages[0], peer, now)
			if mode == "valid" {
				if err != nil || len(flight) == 0 || flight[0].typ != msgServerHello || flight[0].sequence != 1 || len(d.localCID) == 0 {
					t.Fatalf("validated cookie did not start the server flight: %v", err)
				}
			} else if !errors.Is(err, errIllegalParameter) || len(flight) != 0 || d.server != nil || len(d.localCID) != 0 {
				t.Fatalf("invalid cookie started a server handshake: %v", err)
			}
		})
	}
}
