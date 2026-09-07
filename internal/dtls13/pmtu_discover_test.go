package dtls13

import (
	"net/netip"
	"testing"
	"time"
)

func enableMTUDiscovery(s *session) {
	s.canProbe = true
	if s.handshake != nil && s.handshake.config != nil {
		s.handshake.config.UnfragmentedProbes = true
	}
}

func newDiscoveryPaths(t *testing.T) *testPaths {
	t.Helper()
	p := newTestPaths(t)
	enableMTUDiscovery(p.client)
	return p
}

func (p *testPaths) tickClient(t *testing.T, now time.Time) {
	t.Helper()
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
}

func (p *testPaths) discoverUntilWatch(t *testing.T, now *time.Time) {
	t.Helper()
	for i := 0; i < 64; i++ {
		p.tickClient(t, *now)
		if p.client.mtu.outstanding == nil && p.client.mtu.phase == mtuWatch {
			return
		}
		if p.client.mtu.outstanding != nil {
			t.Fatalf("probe size %d still outstanding after deliver", p.client.mtu.outstanding.size)
		}
		if p.client.mtu.phase == mtuWatch {
			return
		}
		if p.client.mtu.nextProbe.IsZero() || !p.client.mtu.nextProbe.After(*now) {
			t.Fatalf("discovery stalled phase=%d mtu=%d", p.client.mtu.phase, p.client.effectiveMTU())
		}
		*now = p.client.mtu.nextProbe
	}
	t.Fatalf("did not reach watch: phase=%d mtu=%d", p.client.mtu.phase, p.client.effectiveMTU())
}

func (p *testPaths) deliverAtMost(t *testing.T, now time.Time, maxSize int) {
	t.Helper()
	kept := p.packets[:0]
	for _, pkt := range p.packets {
		if len(pkt.data) > maxSize {
			continue
		}
		kept = append(kept, pkt)
	}
	p.packets = kept
	p.deliver(t, now)
}

func TestMTUDiscoveryRequiresUnfragmentedProbes(t *testing.T) {
	p := newTestPaths(t)
	p.client.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 0 || p.client.mtu.phase != mtuDisabled || p.client.mtu.outstanding != nil {
		t.Fatal("search started without UnfragmentedProbes")
	}
}

func TestMTUDiscoveryRequiresRRC(t *testing.T) {
	a, b := handshakeConfigs(t)
	a.DisableMigration, b.DisableMigration = true, true
	a.UnfragmentedProbes = true
	client, _, _ := driveSessions(t, a, b, false, false)
	client.canProbe = true
	client.path = &pathState{session: client, peer: packetPath{netip.MustParseAddrPort("192.0.2.2:2000"), 1}}
	now := time.Unix(1000, 0)
	if err := client.tick(now); err != nil {
		t.Fatal(err)
	}
	if client.mtu.outstanding != nil || client.mtuDiscoveryEnabled() {
		t.Fatal("search started without CID/RRC")
	}
}

func TestMTUDiscoveryGrowsAfterHandshakeShrink(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	p.client.mtuReductions = 2
	working := p.client.effectiveMTU()
	if working != 400 {
		t.Fatalf("working %d", working)
	}
	now := time.Unix(1000, 0)
	p.discoverUntilWatch(t, &now)
	got := p.client.effectiveMTU()
	if got <= working || got < p.client.mtuCeiling()-maxMTUDiff-1 {
		t.Fatalf("recovered MTU %d from %d, ceiling %d", got, working, p.client.mtuCeiling())
	}
	if p.client.mtuReductions != 0 {
		t.Fatalf("successful raise left reductions=%d", p.client.mtuReductions)
	}
	if err := p.client.application([]byte("after search")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUDiscoveryIsolatedProbeLossDoesNotDropWorking(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	if p.client.mtu.outstanding != nil || p.client.effectiveMTU() != 400 {
		t.Fatal("confirm of the working size failed")
	}
	now = p.client.mtu.nextProbe
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding == nil || p.client.mtu.outstanding.kind != probeSearch {
		t.Fatal("expected a search probe")
	}
	lostSize := p.client.mtu.outstanding.size
	p.packets = nil
	later := p.client.mtu.outstanding.deadline
	if err := p.client.tick(later); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != 400 {
		t.Fatalf("isolated loss changed working size to %d", p.client.effectiveMTU())
	}
	if p.client.mtu.finder.max() != p.client.mtuProbeCeiling() {
		t.Fatalf("isolated loss dropped search max to %d", p.client.mtu.finder.max())
	}
	if lostSize <= 400 {
		t.Fatalf("lost probe %d was not larger than working size", lostSize)
	}
}

func TestMTUDiscoveryConfirmLossShrinksThenSearches(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 800
	now := time.Unix(1000, 0)
	for i := 0; i < maxConfirmFails; i++ {
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		if p.client.mtu.outstanding == nil || p.client.mtu.outstanding.kind != probeConfirm {
			t.Fatalf("confirm %d not sent", i)
		}
		p.packets = nil
		now = p.client.mtu.outstanding.deadline
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		now = p.client.mtu.nextProbe
	}
	if p.client.effectiveMTU() >= 800 {
		t.Fatalf("confirm black-hole left working size %d", p.client.effectiveMTU())
	}
	shrunk := p.client.effectiveMTU()
	p.discoverUntilWatch(t, &now)
	if p.client.effectiveMTU() <= shrunk {
		t.Fatalf("search did not grow after confirm shrink: %d", p.client.effectiveMTU())
	}
}

func TestMTUDiscoveryConfirmLossAtFloorStops(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = minPathMTU
	p.client.mtuReductions = maxMTUReductions
	now := time.Unix(1000, 0)
	for i := 0; i < maxConfirmFails; i++ {
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		if p.client.mtu.outstanding == nil || p.client.mtu.outstanding.kind != probeConfirm {
			t.Fatalf("confirm %d not sent", i)
		}
		p.packets = nil
		now = p.client.mtu.outstanding.deadline
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		if i+1 < maxConfirmFails {
			now = p.client.mtu.nextProbe
		}
	}
	if p.client.effectiveMTU() != minPathMTU {
		t.Fatalf("floor confirm loss changed working size to %d", p.client.effectiveMTU())
	}
	if p.client.mtu.phase != mtuWatch {
		t.Fatalf("confirm black-hole at the floor kept phase %d", p.client.mtu.phase)
	}
	later := now.Add(probePace)
	if err := p.client.tick(later); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil {
		t.Fatal("kept probing after confirm black-hole at the floor")
	}
}

func TestMTUDiscoverySearchEMSGSIZEDoesNotShrinkWorking(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	now = p.client.mtu.nextProbe
	orig := p.client.send
	p.client.send = func(data []byte) error {
		if len(data) > 500 {
			return messageTooLongError()
		}
		return orig(data)
	}
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != 400 {
		t.Fatalf("search EMSGSIZE changed working size to %d", p.client.effectiveMTU())
	}
	if p.client.mtu.finder.max() >= p.client.mtuProbeCeiling() {
		t.Fatal("search EMSGSIZE left the original ceiling")
	}
	if p.client.mtu.finder.max() > 800 {
		t.Fatalf("search EMSGSIZE left ceiling %d", p.client.mtu.finder.max())
	}
	if err := p.client.application([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUDiscoverySearchEMSGSIZENearWorkingGoesToWatch(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 1170
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	now = p.client.mtu.nextProbe
	p.client.send = func([]byte) error { return messageTooLongError() }
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != 1170 {
		t.Fatalf("near-ceiling EMSGSIZE changed working size to %d", p.client.effectiveMTU())
	}
	if p.client.mtu.phase != mtuWatch {
		t.Fatalf("near-ceiling search EMSGSIZE left phase %d", p.client.mtu.phase)
	}
}

func TestMTUDiscoveryConfirmEMSGSIZEShrinks(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 800
	now := time.Unix(1000, 0)
	p.client.send = func([]byte) error { return messageTooLongError() }
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() >= 800 {
		t.Fatalf("confirm EMSGSIZE left working size %d", p.client.effectiveMTU())
	}
}

func TestMTUDiscoveryBlackHoleStopsBelowLimit(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	limit := 700
	for i := 0; i < 48; i++ {
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		p.deliverAtMost(t, now, limit)
		if p.client.mtu.outstanding == nil {
			if p.client.mtu.phase == mtuWatch {
				break
			}
			if p.client.mtu.nextProbe.IsZero() || !p.client.mtu.nextProbe.After(now) {
				t.Fatalf("stalled phase=%d mtu=%d", p.client.mtu.phase, p.client.effectiveMTU())
			}
			now = p.client.mtu.nextProbe
			continue
		}
		now = p.client.mtu.outstanding.deadline
	}
	if p.client.mtu.phase != mtuWatch {
		t.Fatalf("phase %d after black-hole search", p.client.mtu.phase)
	}
	got := p.client.effectiveMTU()
	if got > limit {
		t.Fatalf("working size %d exceeded black-hole limit %d", got, limit)
	}
	if got < 400 {
		t.Fatalf("black-hole search shrank below the confirmed floor: %d", got)
	}
}

func TestMTUDiscoveryRaiseRestartsSearchNotCeiling(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	limit := 700
	for i := 0; i < 48; i++ {
		if err := p.client.tick(now); err != nil {
			t.Fatal(err)
		}
		p.deliverAtMost(t, now, limit)
		if p.client.mtu.outstanding == nil {
			if p.client.mtu.phase == mtuWatch {
				break
			}
			if p.client.mtu.nextProbe.IsZero() {
				t.Fatal("search stalled")
			}
			now = p.client.mtu.nextProbe
			continue
		}
		now = p.client.mtu.outstanding.deadline
	}
	if p.client.mtu.phase != mtuWatch {
		t.Fatal("did not reach watch")
	}
	before := p.client.effectiveMTU()
	if before >= p.client.mtuCeiling() {
		t.Fatal("black-hole search reached the configured ceiling")
	}
	if err := p.client.application([]byte("traffic")); err != nil {
		t.Fatal(err)
	}
	now = p.client.mtu.raiseAt
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != before {
		t.Fatalf("raise timer restored the ceiling: %d -> %d", before, p.client.effectiveMTU())
	}
	if p.client.mtu.phase != mtuSearch || p.client.mtu.outstanding == nil {
		t.Fatalf("raise did not restart search phase=%d outstanding=%v", p.client.mtu.phase, p.client.mtu.outstanding != nil)
	}
	if p.client.mtu.outstanding.size <= before {
		t.Fatalf("raise probe %d was not above working %d", p.client.mtu.outstanding.size, before)
	}
	if p.client.mtu.outstanding.size > p.client.mtuCeiling() {
		t.Fatal("raise probe exceeded the configured ceiling")
	}
}

func TestMTUDiscoveryWatchTimersNeedActivity(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.discoverUntilWatch(t, &now)
	later := now.Add(raiseTimer)
	if err := p.client.tick(later); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil || p.client.mtu.phase != mtuWatch {
		t.Fatal("idle watch sent a probe")
	}
	if err := p.client.application([]byte("in use")); err != nil {
		t.Fatal(err)
	}
	if err := p.client.tick(p.client.mtu.confirmAt); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding == nil || p.client.mtu.outstanding.kind != probeConfirm {
		t.Fatal("in-use path did not confirm")
	}
}

func TestMTUDiscoveryPeriodicConfirmDoesNotRestartSearch(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.discoverUntilWatch(t, &now)
	raiseAt := p.client.mtu.raiseAt
	if err := p.client.application([]byte("in use")); err != nil {
		t.Fatal(err)
	}
	p.tickClient(t, p.client.mtu.confirmAt)
	if p.client.mtu.phase != mtuWatch {
		t.Fatalf("periodic confirm started search phase=%d", p.client.mtu.phase)
	}
	if !p.client.mtu.raiseAt.Equal(raiseAt) {
		t.Fatal("periodic confirm reset the raise timer")
	}
}

func TestMTUDiscoveryStaleProbeAfterMigrationDoesNotRaise(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.server.canProbe = true
	p.server.handshake.config.UnfragmentedProbes = true
	p.server.pathMTU = 400
	now := time.Unix(1000, 0)
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	now = p.server.mtu.nextProbe
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.server.mtu.outstanding == nil || p.server.mtu.outstanding.kind != probeSearch {
		t.Fatal("expected server search probe")
	}
	searchSize := p.server.mtu.outstanding.size
	var challenge routedDatagram
	for _, pkt := range p.packets {
		if pkt.from == p.serverAddress && len(pkt.data) == searchSize {
			challenge = pkt
			break
		}
	}
	if len(challenge.data) == 0 {
		t.Fatal("missing search challenge")
	}
	p.packets = nil
	if _, err := p.client.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing path_response")
	}
	late := p.packets[0]
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
	generation := p.server.mtu.generation
	if _, err := p.server.receiveFrom(late.data, packetPath{late.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.server.mtu.generation != generation {
		t.Fatal("stale response changed generation")
	}
	if p.server.effectiveMTU() >= searchSize {
		t.Fatalf("old-path search ack raised the new path to %d", p.server.effectiveMTU())
	}
	if p.server.mtu.lastAckedSize == searchSize {
		t.Fatal("stale search ack was accepted")
	}
}

func TestMTUDiscoveryPathDropIsLoss(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	now = p.client.mtu.nextProbe
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	probe := p.client.mtu.outstanding
	if probe == nil {
		t.Fatal("missing search probe")
	}
	cookie := probe.cookie
	size := probe.size
	p.packets = nil
	drop := append([]byte{pathDrop}, cookie[:]...)
	if _, err := p.server.sendRecord(p.server.currentWriteEpoch(), contentRRC, drop); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.client.effectiveMTU() != 400 {
		t.Fatal("path_drop raised the working size")
	}
	if p.client.mtu.lastAckedSize == size {
		t.Fatal("path_drop counted as an ack")
	}
}

func TestMTUDiscoveryDuplicateAckDoesNotRaiseTwice(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	now = p.client.mtu.nextProbe
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) != 1 {
		t.Fatal("missing search probe")
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
	after := p.client.effectiveMTU()
	if after <= 400 {
		t.Fatal("search ack did not raise")
	}
	if _, err := p.client.receiveFrom(response.data, packetPath{response.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != after {
		t.Fatal("duplicate ack raised again")
	}
}

func TestMTUDiscoveryDefersToKeyUpdate(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	if err := p.client.requestKeyUpdate(false, now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil {
		t.Fatal("discovery probed during KeyUpdate")
	}
}

func TestMTUDiscoveryManualProbeStillDoesNotRaise(t *testing.T) {
	p := newDiscoveryPaths(t)
	now := time.Unix(1000, 0)
	working := p.client.effectiveMTU()
	size := probeDatagramSize(p.client, 80)
	if err := p.client.startMTUProbe(size, now); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if p.client.effectiveMTU() != working || p.client.pathMTU != 0 {
		t.Fatalf("manual probe raised usable MTU to %d", p.client.effectiveMTU())
	}
}

func TestMTUDiscoveryReductionBudgetResetsOnRaise(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = minPathMTU
	p.client.mtuReductions = maxMTUReductions
	if p.client.reduceHandshakeMTU(0) {
		t.Fatal("reduction cap should block further shrink")
	}
	now := time.Unix(1000, 0)
	p.discoverUntilWatch(t, &now)
	if p.client.effectiveMTU() <= minPathMTU {
		t.Fatal("search did not grow")
	}
	if p.client.mtuReductions != 0 {
		t.Fatalf("raise left reductions=%d", p.client.mtuReductions)
	}
	if !p.client.reduceHandshakeMTU(0) {
		t.Fatal("raise did not restore the shrink budget")
	}
}

func TestMTUDiscoveryDeadlineIncludesPace(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	got := p.client.deadline()
	if got.IsZero() || got.After(p.client.mtu.nextProbe) {
		t.Fatalf("session deadline %v missing probe pace %v", got, p.client.mtu.nextProbe)
	}
}

func TestMTUDiscoveryDisabledWithoutCapability(t *testing.T) {
	p := newTestPaths(t)
	p.client.handshake.config.UnfragmentedProbes = true
	now := time.Unix(1000, 0)
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.client.mtu.outstanding != nil {
		t.Fatal("search started without canProbe")
	}
}

func TestMTUDiscoveryApplicationWriteStillFails(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.send = func([]byte) error { return messageTooLongError() }
	if err := p.client.application([]byte("app")); !isMessageTooLong(err) {
		t.Fatalf("application EMSGSIZE: %v", err)
	}
	if p.client.effectiveMTU() >= p.client.mtuCeiling() {
		t.Fatal("application EMSGSIZE did not reduce the advertised budget")
	}
}

func TestMTUDiscoveryNoRetransmitOnApplicationEMSGSIZE(t *testing.T) {
	p := newDiscoveryPaths(t)
	var sent int
	orig := p.client.send
	p.client.send = func(data []byte) error {
		sent++
		if len(data) > 80 {
			return messageTooLongError()
		}
		return orig(data)
	}
	err := p.client.application(make([]byte, 200))
	if !isMessageTooLong(err) {
		t.Fatalf("application: %v", err)
	}
	if sent != 1 {
		t.Fatalf("application write retried %d times", sent)
	}
}

func TestSetWorkingMTUDoesNotLower(t *testing.T) {
	p := newTestPaths(t)
	p.client.pathMTU = 800
	p.client.setWorkingMTU(500)
	if p.client.effectiveMTU() != 800 {
		t.Fatal("setWorkingMTU lowered the working size")
	}
	p.client.setWorkingMTU(900)
	if p.client.effectiveMTU() != 900 {
		t.Fatalf("setWorkingMTU did not raise: %d", p.client.effectiveMTU())
	}
}

func TestMTUDiscoveryIgnoresSharedListener(t *testing.T) {
	p := newTestPaths(t)
	p.server.handshake.config.UnfragmentedProbes = true
	p.server.canProbe = false
	now := time.Unix(1000, 0)
	if err := p.server.tick(now); err != nil {
		t.Fatal(err)
	}
	if p.server.mtu.outstanding != nil {
		t.Fatal("listener association started discovery")
	}
}

func TestMTUDiscoveryDelayedResponseAfterTimeout(t *testing.T) {
	p := newDiscoveryPaths(t)
	p.client.pathMTU = 400
	now := time.Unix(1000, 0)
	p.tickClient(t, now)
	now = p.client.mtu.nextProbe
	if err := p.client.tick(now); err != nil {
		t.Fatal(err)
	}
	if len(p.packets) == 0 {
		t.Fatal("missing search probe")
	}
	challenge := p.packets[0]
	p.packets = nil
	if _, err := p.server.receiveFrom(challenge.data, packetPath{challenge.from, 1}, now); err != nil {
		t.Fatal(err)
	}
	late := p.packets[0]
	p.packets = nil
	working := p.client.effectiveMTU()
	if err := p.client.tick(now.Add(probeTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.receiveFrom(late.data, packetPath{late.from, 1}, now.Add(probeTimeout+time.Second)); err != nil {
		t.Fatal(err)
	}
	if p.client.effectiveMTU() != working {
		t.Fatal("delayed response after timeout raised the working size")
	}
}
