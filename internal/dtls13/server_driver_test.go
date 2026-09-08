package dtls13

import (
	"net/netip"
	"time"
)

// Deterministic protocol drivers use the production cookies without a listener.
// Admission limits, address routing and transport ownership are tested via Listen.
type testServerHandshake struct {
	*handshakeState
	server *serverHandshake
	key    cookieSecrets
}

func newTestServerHandshake(config *Config) (*testServerHandshake, error) {
	prepared, err := prepareConfig(config, true)
	if err != nil {
		return nil, err
	}
	return &testServerHandshake{handshakeState: &handshakeState{config: prepared}, key: cookieSecrets{current: [32]byte{1}}}, nil
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
