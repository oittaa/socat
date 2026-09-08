package dtls13

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func probeDatagramSize(s *session, extra int) int {
	return rrcProbeOverhead(len(s.probeCID()), s.recordTagLen()) + extra
}

func TestMTUProbeRequiresCapabilityAndRRC(t *testing.T) {
	p := newTestPaths(t)
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 64)
	if err := p.client.startMTUProbe(size, now); !errors.Is(err, errProbeDisabled) {
		t.Fatalf("probe without capability: %v", err)
	}
	p.client.canProbe = true
	p.client.handshake.rrc = false
	if err := p.client.startMTUProbe(size, now); !errors.Is(err, errProbeDisabled) {
		t.Fatalf("probe without RRC: %v", err)
	}

	a, b := handshakeConfigs(t)
	a.DisableMigration, b.DisableMigration = true, true
	client, _, _ := driveSessions(t, a, b, false, false)
	client.canProbe = true
	client.path = &pathState{session: client, peer: packetPath{netip.MustParseAddrPort("192.0.2.2:2000"), 1}}
	if client.handshake.rrc || client.handshake.cidNegotiated {
		t.Fatal("DisableMigration still negotiated RRC")
	}
	if err := client.startMTUProbe(256, now); !errors.Is(err, errProbeDisabled) {
		t.Fatalf("probe without CID/RRC: %v", err)
	}
}

func TestMTUProbeExactDatagramAndUnpaddedResponse(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 200)
	spares := len(p.client.peerSpareCIDs)
	working := p.client.effectiveMTU()
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	if p.client.path.probe != nil {
		t.Fatal("discovery used the migration probe slot")
	}
	if len(p.packets) != 1 || len(p.packets[0].data) != size {
		t.Fatalf("challenge datagram %d packets size %d want %d", len(p.packets), len(p.packets[0].data), size)
	}
	if p.packets[0].to != p.serverAddress {
		t.Fatal("probe used a different destination tuple")
	}
	if len(p.client.peerSpareCIDs) != spares {
		t.Fatal("probe consumed a spare CID")
	}
	p.deliver(t, now)
	if len(p.packets) != 0 {
		t.Fatal("response was not delivered")
	}
	if p.client.mtu.lastAckedSize != size {
		t.Fatalf("acked %d want %d", p.client.mtu.lastAckedSize, size)
	}
	if p.client.effectiveMTU() != working || p.client.pathMTU != 0 {
		t.Fatalf("usable MTU changed to %d (pathMTU=%d)", p.client.effectiveMTU(), p.client.pathMTU)
	}
	if err := p.client.application([]byte("after probe")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUProbeResponseIsUnpadded(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 180)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = p.packets[1:]
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatalf("responses %d", len(p.packets))
	}
	want := rrcProbeOverhead(len(p.server.probeCID()), p.server.recordTagLen())
	if len(p.packets[0].data) != want {
		t.Fatalf("path_response %d bytes, want unpadded %d", len(p.packets[0].data), want)
	}
	if len(p.packets[0].data) >= size {
		t.Fatal("responder echoed the padded probe size")
	}
}

func TestMTUProbeExceedsWorkingSize(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	size := 800
	if size <= p.client.effectiveMTU() || size > p.client.mtuCeiling() {
		t.Fatalf("probe %d not between working %d and ceiling %d", size, p.client.effectiveMTU(), p.client.mtuCeiling())
	}
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 || len(p.packets[0].data) != size {
		t.Fatalf("oversized probe not sent: %d", len(p.packets[0].data))
	}
	if p.client.effectiveMTU() != 400 {
		t.Fatal("sending a larger probe raised the working size")
	}
}

func TestMTUProbeDoesNotStallApplication(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 80), now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.application([]byte("still writable")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUProbeIgnoresUnmatchedResponses(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	response := p.packets[0]
	p.packets = nil
	wrong := packetPath{netip.MustParseAddrPort("198.51.100.9:9"), 1}
	if _, err := p.client.receiveFrom(response.data, wrong, now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != 0 || p.client.mtu.outstanding == nil {
		t.Fatal("wrong-path response completed the probe")
	}
	forged := append([]byte{pathResponse}, bytes.Repeat([]byte{0x11}, 8)...)
	if _, err := p.server.sendRecord(p.server.currentWriteEpoch(), contentRRC, forged); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.client.mtu.lastAckedSize != 0 || p.client.mtu.outstanding == nil {
		t.Fatal("wrong cookie completed the probe")
	}
}

func TestMTUProbePathDropDoesNotRaise(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	cookie := p.client.mtu.outstanding.cookie
	p.packets = nil
	drop := append([]byte{pathDrop}, cookie[:]...)
	if _, err := p.server.sendRecord(p.server.currentWriteEpoch(), contentRRC, drop); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.client.mtu.lastAckedSize != 0 || p.client.effectiveMTU() != working {
		t.Fatal("path_drop increased the usable MTU")
	}
	if p.client.path.probe != nil {
		t.Fatal("path_drop started a migration exchange")
	}
	if !p.client.mtu.lastFailed {
		t.Fatal("path_drop did not fail the discovery probe")
	}
}

func TestMTUProbeTimeoutLeavesWorkingSize(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 40), now); err != nil {
		t.Fatal(err)
	}
	p.packets = nil
	later := now.Add(probeTimeout)
	if err := p.client.tick(later); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil || !p.client.mtu.lastFailed {
		t.Fatal("expired probe still outstanding")
	}
	if p.client.effectiveMTU() != working {
		t.Fatal("probe loss changed the working size")
	}
	if err := p.client.application([]byte("after loss")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUProbeDuplicateAndDelayedResponses(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	response := p.packets[0]
	p.packets = nil
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != size {
		t.Fatal("first response was not accepted")
	}
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != working || p.client.mtu.lastAckedSize != size {
		t.Fatal("duplicate response changed usable MTU")
	}

	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge = p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	late := p.packets[0]
	p.packets = nil
	if err := p.client.tick(now.Add(probeTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.receiveFrom(late.data, packetPath{late.from, 1}, now.Add(probeTimeout+time.Second)); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != 0 {
		t.Fatal("delayed response after timeout counted as success")
	}
}

func TestMTUProbeTransportErrorIsNotFatal(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	orig := p.client.send
	p.client.send = func(data []byte) error {
		if len(data) > 80 {
			return messageTooLongError()
		}
		return orig(data)
	}
	err := p.client.startMTUProbe(probeDatagramSize(p.client, 200), now)
	if !errors.Is(err, errProbeTooBig) {
		t.Fatalf("EMSGSIZE: %v", err)
	}
	if p.client.mtu.outstanding != nil || !p.client.mtu.lastFailed {
		t.Fatal("failed probe still outstanding")
	}
	if p.client.effectiveMTU() != working {
		t.Fatal("local EMSGSIZE changed the working size")
	}
	if err := p.client.application([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUProbeDefersToKeyUpdate(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 40), now); !errors.Is(err, errProbeBusy) {
		t.Fatalf("probe during KeyUpdate: %v", err)
	}
}

func TestMTUProbeKeyUpdateDoesNotRaiseMTU(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 40), now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.client.effectiveMTU() != working {
		t.Fatal("KeyUpdate with an in-flight probe changed the working MTU")
	}
}

func TestMTUProbeOneOutstanding(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.startMTUProbe(size, now); !errors.Is(err, errProbePending) {
		t.Fatalf("second probe: %v", err)
	}
}

func TestMTUProbeCeilingAndAboveWorking(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.startMTUProbe(p.client.mtuCeiling()+1, now); !errors.Is(err, errProbeSize) {
		t.Fatalf("above ceiling: %v", err)
	}
	if err := p.client.startMTUProbe(8, now); !errors.Is(err, errProbeSize) {
		t.Fatalf("below RRC minimum: %v", err)
	}
}

func TestStaleMTUProbeAfterMigrationIgnored(t *testing.T) {
	p := newTestPaths(t)
	p.server.canProbe = true
	now := time.Unix(1000, 0)
	working := p.server.effectiveMTU()
	size := probeDatagramSize(p.server, 40)
	if err := p.server.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	oldCookie := p.server.mtu.outstanding.cookie
	p.packets = nil

	old := p.clientAddress
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	p.client.useSpareCID()
	if err := p.client.application([]byte("new binding")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.server.path.peer.remote != old || p.server.path.probe == nil {
		t.Fatal("expected enhanced RRC before installing the new path")
	}
	now = p.server.deadline()
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.server.path.peer.remote != p.clientAddress || p.server.path.probe != nil {
		t.Fatal("new path was not installed")
	}
	if p.server.mtu.outstanding != nil || p.server.mtu.lastAckedSize != 0 {
		t.Fatal("migration kept the old discovery probe")
	}
	if _, err := p.client.sendRecord(p.client.currentWriteEpoch(), contentRRC, append([]byte{pathResponse}, oldCookie[:]...)); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.server.mtu.lastAckedSize != 0 || p.server.effectiveMTU() != working {
		t.Fatal("old-path response changed the new path budget")
	}
}

func TestMTUProbeDeadlineIsOwnedBySession(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 40), now); err != nil {
		t.Fatal(err)
	}
	want := now.Add(probeTimeout)
	got := p.client.deadline()
	if got.IsZero() || got.After(want) {
		t.Fatalf("session deadline %v does not include probe timeout %v", got, want)
	}
	if err := p.client.tick(want); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil {
		t.Fatal("probe still outstanding after deadline tick")
	}
}

func TestMTUProbeIgnoresWrongLocalSocket(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	response := p.packets[0]
	p.packets = nil
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 2}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != 0 || p.client.mtu.outstanding == nil {
		t.Fatal("response on a different local socket completed the probe")
	}
}

func TestMTUProbeIgnoredDuringMigration(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	response := p.packets[0]
	p.packets = nil
	p.client.path.probe = &pathProbe{
		candidate: packetPath{netip.MustParseAddrPort("192.0.2.9:9"), 1},
		phase:     pathValidateCandidate,
		deadline:  now.Add(time.Second),
	}
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != 0 || p.client.mtu.outstanding == nil {
		t.Fatal("discovery completed while a migration probe was outstanding")
	}
	if p.client.effectiveMTU() != working {
		t.Fatal("usable MTU changed during migration")
	}
}

func TestMTUProbeIgnoredDuringKeyUpdate(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	size := probeDatagramSize(p.client, 40)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	response := p.packets[0]
	p.packets = nil
	if err := p.client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.lastAckedSize != 0 || p.client.mtu.outstanding == nil {
		t.Fatal("discovery completed while KeyUpdate was in flight")
	}
	if p.client.effectiveMTU() != working {
		t.Fatal("usable MTU changed during KeyUpdate")
	}
}

func TestMTUProbeIsolatedFromSecondAssociation(t *testing.T) {
	a := newTestPaths(t)
	b := newTestPaths(t)
	a.client.canProbe = true
	now := time.Unix(1000, 0)
	working := b.client.effectiveMTU()
	if err := a.client.startMTUProbe(probeDatagramSize(a.client, 40), now); err != nil {
		t.Fatal(err)
	}
	a.deliver(t, now)
	if a.client.mtu.lastAckedSize == 0 {
		t.Fatal("first association did not complete a probe")
	}
	if b.client.mtu.lastAckedSize != 0 || b.client.effectiveMTU() != working || b.client.mtu.outstanding != nil {
		t.Fatal("probe state leaked across associations")
	}
}

func TestPaddedRRCInnerPaddingIsNotMessage(t *testing.T) {
	keys := testTrafficKeys(t)
	cid := []byte("cid-pad!!")
	cookie := []byte("cookie08")
	pad := 17
	raw := packedPaddedRRC(t, keys, recordNumber{3, 9}, cid, pathChallenge, cookie, pad)
	if len(raw) != rrcProbeOverhead(len(cid), keys.aead.Overhead())+pad {
		t.Fatalf("wire length %d", len(raw))
	}
	r, rest, err := parseRecord(raw, len(cid))
	if err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	var window replayWindow
	number, typ, body, err := keys.decodeRecord(r, 3, cid, &window)
	if err != nil || typ != contentRRC || number.sequence != 9 {
		t.Fatalf("decode: %v typ=%d seq=%d", err, typ, number.sequence)
	}
	if len(body) != rrcMessageLen || body[0] != pathChallenge || !bytes.Equal(body[1:], cookie) {
		t.Fatalf("padding leaked into RRC body %x", body)
	}
}

func packedPaddedRRC(t *testing.T, keys *trafficKeys, number recordNumber, cid []byte, typ byte, cookie []byte, pad int) []byte {
	t.Helper()
	first := byte(0x2c) | byte(number.epoch&3)
	if len(cid) != 0 {
		first |= 0x10
	}
	inner := append(append([]byte{typ}, cookie...), contentRRC)
	inner = append(inner, make([]byte, pad)...)
	seqOffset := 1 + len(cid)
	header := make([]byte, seqOffset+unifiedSeqLen+unifiedLengthLen)
	header[0] = first
	copy(header[1:seqOffset], cid)
	binary.BigEndian.PutUint16(header[seqOffset:], uint16(number.sequence&0xffff))
	binary.BigEndian.PutUint16(header[seqOffset+unifiedSeqLen:], uint16(len(inner)+keys.aead.Overhead()))
	ciphertext := keys.seal(nil, header, number.sequence, inner)
	mask, err := keys.mask(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	for i := range unifiedSeqLen {
		header[seqOffset+i] ^= mask[i]
	}
	return append(header, ciphertext...)
}
