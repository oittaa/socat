package dtls13

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

type routedDatagram struct {
	from, to netip.AddrPort
	data     []byte
}

type testPaths struct {
	client, server               *session
	clientAddress, serverAddress netip.AddrPort
	packets                      []routedDatagram
}

func newTestPaths(t *testing.T) *testPaths {
	t.Helper()
	a, b := handshakeConfigs(t)
	client, server, packets := driveSessions(t, a, b, false, false)
	now := time.Unix(1000, 0)
	for _, s := range []*session{client, server} {
		if err := s.requestCIDs(3, now); err != nil {
			t.Fatal(err)
		}
	}
	deliverSessionPackets(t, client, server, packets, now)
	p := &testPaths{client: client, server: server,
		clientAddress: netip.MustParseAddrPort("192.0.2.1:1000"),
		serverAddress: netip.MustParseAddrPort("192.0.2.2:2000")}
	client.path = &pathState{session: client, peer: packetPath{p.serverAddress, 1}}
	server.path = &pathState{session: server, peer: packetPath{p.clientAddress, 1}}
	client.path.send = func(to packetPath, data []byte) error {
		p.packets = append(p.packets, routedDatagram{p.clientAddress, to.remote, bytes.Clone(data)})
		return nil
	}
	server.path.send = func(to packetPath, data []byte) error {
		p.packets = append(p.packets, routedDatagram{p.serverAddress, to.remote, bytes.Clone(data)})
		return nil
	}
	client.send = func(data []byte) error { return client.path.send(client.path.peer, data) }
	server.send = func(data []byte) error { return server.path.send(server.path.peer, data) }
	return p
}

func (p *testPaths) deliver(t *testing.T, now time.Time) [][]byte {
	t.Helper()
	var application [][]byte
	for step := 0; len(p.packets) != 0; step++ {
		if step > 100 {
			t.Fatal("path exchange exceeded deterministic event bound")
		}
		packet := p.packets[0]
		p.packets = p.packets[1:]
		var destination *session
		switch packet.to {
		case p.clientAddress:
			destination = p.client
		case p.serverAddress:
			destination = p.server
		default:
			continue // The old NAT binding and attacker path have no receiver.
		}
		data, err := destination.receiveFrom(packet.data, packetPath{packet.from, 1}, now)
		if err != nil {
			t.Fatalf("receive from %s: %v", packet.from, err)
		}
		application = append(application, data...)
	}
	return application
}

func TestEnhancedRRCRejectsOffPathForwarder(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	if err := p.client.application([]byte("copied ciphertext")); err != nil {
		t.Fatal(err)
	}
	original := p.packets[0]
	p.packets[0].from = netip.MustParseAddrPort("192.0.2.99:9999")
	p.deliver(t, now)
	if p.server.path.peer.remote != p.clientAddress || p.server.path.probe != nil {
		t.Fatal("forwarded record moved an association off its working preferred path")
	}
	p.packets = append(p.packets, original)
	if data := p.deliver(t, now); len(data) != 0 {
		t.Fatal("forwarded record was delivered twice")
	}
}

func cidRotationDuringProbe(t *testing.T) (*testPaths, routedDatagram, []byte, time.Time) {
	t.Helper()
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	if err := p.client.application([]byte("move")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	now = p.server.deadline()
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 || p.server.path.probe == nil || p.server.path.probe.phase != pathValidateCandidate {
		t.Fatal("basic path challenge was not queued")
	}
	challenge := p.packets[0]
	p.packets = nil
	if err := p.client.provideCIDs(1, true, now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	return p, challenge, bytes.Clone(p.server.handshake.peerCID), now
}

func TestCIDPathCompletionDoesNotUndoRotation(t *testing.T) {
	p, challenge, newCID, now := cidRotationDuringProbe(t)
	p.packets = append(p.packets, challenge)
	p.deliver(t, now)
	if p.server.path.probe != nil || p.server.path.peer.remote != p.clientAddress {
		t.Fatal("held challenge did not complete address validation")
	}
	if !bytes.Equal(p.server.handshake.peerCID, newCID) {
		t.Fatalf("path completion restored stale CID %x; want immediate CID %x", p.server.handshake.peerCID, newCID)
	}
	if err := p.server.application([]byte("rotated and migrated")); err != nil {
		t.Fatal(err)
	}
	data := p.deliver(t, now)
	if len(data) != 1 || string(data[0]) != "rotated and migrated" {
		t.Fatal("application traffic did not resume with the immediate CID")
	}
}
