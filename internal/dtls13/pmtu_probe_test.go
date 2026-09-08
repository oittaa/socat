package dtls13

import (
	"errors"
	"testing"
	"time"
)

func probeDatagramSize(s *session, extra int) int {
	return rrcProbeOverhead(len(s.probeCID()), s.recordTagLen()) + extra
}

func TestMTUProbeExceedsWorkingSize(t *testing.T) {
	p := newTestPaths(t)
	p.client.working.canProbe = true
	p.client.working.pathMTU = 400
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
	p.client.working.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.startMTUProbe(probeDatagramSize(p.client, 80), now); err != nil {
		t.Fatal(err)
	}
	if err := p.client.application([]byte("still writable")); err != nil {
		t.Fatal(err)
	}
}

func TestMTUProbeDefersToKeyUpdate(t *testing.T) {
	p := newTestPaths(t)
	p.client.working.canProbe = true
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
	p.client.working.canProbe = true
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
	p.client.working.canProbe = true
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
	p.client.working.canProbe = true
	now := time.Unix(1000, 0)
	if err := p.client.startMTUProbe(p.client.mtuCeiling()+1, now); !errors.Is(err, errProbeSize) {
		t.Fatalf("above ceiling: %v", err)
	}
	if err := p.client.startMTUProbe(8, now); !errors.Is(err, errProbeSize) {
		t.Fatalf("below RRC minimum: %v", err)
	}
}

func TestMTUProbeDeadlineIsOwnedBySession(t *testing.T) {
	p := newTestPaths(t)
	p.client.working.canProbe = true
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

func TestMTUProbeIsolatedFromSecondAssociation(t *testing.T) {
	a := newTestPaths(t)
	b := newTestPaths(t)
	a.client.working.canProbe = true
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
