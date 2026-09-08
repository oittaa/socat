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
