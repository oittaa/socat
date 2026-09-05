package dtls13

import (
	"bytes"
	"errors"
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

func TestEnhancedRRCNATRebinding(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	old := p.clientAddress
	oldCID := bytes.Clone(p.server.handshake.peerCID)
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	p.client.useSpareCID()
	if err := p.client.application([]byte("new binding")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.server.path.peer.remote != old || p.server.path.probe == nil || !p.server.path.probe.old {
		t.Fatal("address changed before testing the old path")
	}
	if err := p.server.application([]byte("wait for validation")); !errors.Is(err, errPathPending) {
		t.Fatalf("write did not wait for path validation: %v", err)
	}
	oldCookie := p.server.path.probe.cookie
	now = p.server.deadline()
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe.old || p.server.path.probe.cookie == oldCookie || len(p.packets) != 1 || p.packets[0].to != p.clientAddress {
		t.Fatal("old-path timeout did not start a fresh challenge on the new path")
	}
	p.deliver(t, now)
	if p.server.path.peer.remote != p.clientAddress || p.server.path.probe != nil || !p.server.deadline().IsZero() {
		t.Fatal("verified new path was not installed")
	}
	if bytes.Equal(oldCID, p.server.handshake.peerCID) {
		t.Fatal("new path reused the old CID despite an available spare")
	}
	if err := p.server.application([]byte("migrated")); err != nil {
		t.Fatal(err)
	}
	data := p.deliver(t, now)
	if len(data) != 1 || string(data[0]) != "migrated" {
		t.Fatal("application did not resume on the validated path")
	}
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

func TestRRCRejectedPeerPreservesRecord(t *testing.T) {
	for _, role := range []string{"client", "server"} {
		t.Run(role, func(t *testing.T) {
			p := newTestPaths(t)
			sender, receiver, source := p.client, p.server, p.clientAddress
			if role == "client" {
				sender, receiver, source = p.server, p.client, p.serverAddress
			}
			receiver.path.allowPeer = func(address netip.AddrPort) bool { return address == source }
			marker := []byte("accepted source")
			if err := sender.application(marker); err != nil {
				t.Fatal(err)
			}
			packet := p.packets[0].data
			now := time.Unix(1000, 0)
			rejected := packetPath{netip.MustParseAddrPort("192.0.2.99:9999"), 1}
			if data, err := receiver.receiveFrom(packet, rejected, now); err != nil || len(data) != 0 {
				t.Fatalf("rejected source delivered %q: %v", data, err)
			}
			// The rejected copy must not consume the original record's replay slot.
			data, err := receiver.receiveFrom(packet, packetPath{source, 1}, now)
			if err != nil || len(data) != 1 || !bytes.Equal(data[0], marker) {
				t.Fatalf("accepted source after rejected copy delivered %q: %v", data, err)
			}
		})
	}
}

func TestRRCRejectsForgedResponseAndNestedRebinding(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	old := p.clientAddress
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	if err := p.client.application([]byte("rebind")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	now = p.server.deadline()
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	p.packets = nil
	probe := p.server.path.probe
	wrong := append([]byte{pathResponse}, probe.cookie[:]...)
	wrong[1] ^= 1
	if _, err := p.client.sendRecord(3, contentRRC, wrong); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.server.path.peer.remote != old || p.server.path.probe != probe {
		t.Fatal("wrong cookie changed path state")
	}
	response := append([]byte{pathResponse}, probe.cookie[:]...)
	if _, err := p.client.sendRecord(3, contentRRC, response); err != nil {
		t.Fatal(err)
	}
	p.packets[0].from = netip.MustParseAddrPort("192.0.2.4:4000")
	p.deliver(t, now)
	if p.server.path.peer.remote != old || p.server.path.probe != probe {
		t.Fatal("a cookie returned from a different address validated the candidate")
	}
	if err := p.server.tick(probe.deadline); err != nil {
		t.Fatal(err)
	}
	if p.server.path.peer.remote != old || p.server.path.probe != nil {
		t.Fatal("failed basic check changed the address or retained candidate state")
	}
}

func TestRRCAuthenticationReplayAndAmplification(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	if err := p.client.application(nil); err != nil {
		t.Fatal(err)
	}
	packet := p.packets[0]
	p.packets = nil
	forged := bytes.Clone(packet.data)
	forged[len(forged)-1] ^= 1
	from := packetPath{p.clientAddress, 1}
	if _, err := p.server.receiveFrom(forged, from, now); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe != nil || len(p.packets) != 0 {
		t.Fatal("forged record initiated path validation")
	}
	if _, err := p.server.receiveFrom(packet.data, from, now); err != nil {
		t.Fatal(err)
	}
	credit := p.server.path.probe.credit
	if _, err := p.server.receiveFrom(packet.data, from, now); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe.credit != credit {
		t.Fatal("replayed record added amplification credit")
	}
	p.packets = nil
	if err := p.server.tick(p.server.deadline()); err != nil {
		t.Fatal(err)
	}
	// Further probes without accepted inbound records cannot exceed the budget.
	for i := 0; i < 20; i++ {
		if err := p.server.path.challenge(now); err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for _, sent := range p.packets {
		if sent.to == p.clientAddress {
			total += len(sent.data)
		}
	}
	if total == 0 || total > 3*len(packet.data) {
		t.Fatalf("unvalidated address received %d bytes for %d received bytes", total, len(packet.data))
	}
}

func TestRRCResponderUnknownTypesAndPathDrop(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	for _, body := range [][]byte{{3}, {255, 1, 2}} {
		if err := p.client.path.receive(p.client.path.peer, body, 32, now); err != nil || len(p.packets) != 0 {
			t.Fatal("unknown RRC type was not ignored")
		}
	}
	cookie := []byte("12345678")
	from := packetPath{p.serverAddress, 2}
	if err := p.client.path.receive(from, append([]byte{pathChallenge}, cookie...), 64, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 || p.packets[0].to != from.remote {
		t.Fatal("challenge did not receive exactly one immediate reply")
	}
	r, _, err := parseRecord(p.packets[0].data, len(p.server.handshake.localCID))
	if err != nil {
		t.Fatal(err)
	}
	_, typ, body, ok, err := p.server.openRecord(r, true)
	if err != nil || !ok || typ != contentRRC || !bytes.Equal(body, append([]byte{pathDrop}, cookie...)) {
		t.Fatal("challenge on a non-preferred local path did not return path_drop")
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
	if len(p.packets) != 1 || p.server.path.probe == nil || p.server.path.probe.old {
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

func TestCIDImmediateAppliesToRRCRecords(t *testing.T) {
	p, _, newCID, now := cidRotationDuringProbe(t)
	// A peer challenge arrives while our candidate-path check is pending.
	body := append([]byte{pathChallenge}, []byte("12345678")...)
	if _, err := p.client.sendRecord(p.client.currentWriteEpoch(), contentRRC, body); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("expected a peer RRC challenge")
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("expected an RRC response")
	}
	r, _, err := parseRecord(p.packets[0].data, len(p.client.handshake.localCID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.cid, newCID) {
		t.Fatalf("RRC after immediate rotation used stale CID %x; want %x", r.cid, newCID)
	}
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
