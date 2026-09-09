package dtls13

import (
	"net/netip"
	"testing"
	"time"
)

func ackableFlight(t *testing.T, now time.Time) (*flight, []recordNumber) {
	t.Helper()
	f, err := newFlight([]handshakeMessage{{typ: msgFinished, body: []byte{1}, epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	n := recordNumber{2, 1}
	if err := f.transmit(now, 50, func(uint64, []byte) (recordNumber, error) { return n, nil }); err != nil {
		t.Fatal(err)
	}
	return f, []recordNumber{n}
}

func TestRetransmitTimerDefaultsToOneSecond(t *testing.T) {
	if got := (&session{}).retransmitTimer(); got != initialRetransmit {
		t.Fatalf("got %s", got)
	}
}

func TestPathChallengeTimerDefaultsToOneSecond(t *testing.T) {
	if got := (&session{}).pathChallengeTimer(); got != time.Second {
		t.Fatalf("got %s", got)
	}
}

func TestRetransmitTimerFloorsSmallRTT(t *testing.T) {
	s := &session{rtt: time.Millisecond}
	if got := s.retransmitTimer(); got != minRetransmit {
		t.Fatalf("got %s want %s", got, minRetransmit)
	}
}

func TestRetransmitTimerIsOneAndAHalfRTT(t *testing.T) {
	s := &session{rtt: 200 * time.Millisecond}
	if got := s.retransmitTimer(); got != 300*time.Millisecond {
		t.Fatalf("got %s", got)
	}
}

func TestAckDelayIsQuarterRetransmitTimer(t *testing.T) {
	s := &session{rtt: 200 * time.Millisecond}
	if got := s.ackDelay(); got != 75*time.Millisecond {
		t.Fatalf("got %s", got)
	}
}

func TestPathChallengeTimerIsThreeRTT(t *testing.T) {
	s := &session{rtt: 50 * time.Millisecond}
	if got := s.pathChallengeTimer(); got != 150*time.Millisecond {
		t.Fatalf("got %s", got)
	}
}

func TestUnambiguousACKMeasuresRTT(t *testing.T) {
	now := time.Unix(1, 0)
	f, records := ackableFlight(t, now)
	progress, rtt := f.acknowledge(records, true, now.Add(50*time.Millisecond))
	if !progress || rtt != 50*time.Millisecond {
		t.Fatalf("progress=%v RTT %s", progress, rtt)
	}
}

func TestRetransmitSuppressesRTTSample(t *testing.T) {
	now := time.Unix(1, 0)
	f, first := ackableFlight(t, now)
	if _, err := f.expire(now.Add(f.interval)); err != nil {
		t.Fatal(err)
	}
	if err := f.transmit(now.Add(f.interval), 50, func(uint64, []byte) (recordNumber, error) {
		return recordNumber{2, 2}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, rtt := f.acknowledge(first, true, now.Add(2*time.Second)); rtt != 0 {
		t.Fatalf("got %s", rtt)
	}
}

func TestSameTimestampACKDoesNotSampleRTT(t *testing.T) {
	now := time.Unix(1, 0)
	f, records := ackableFlight(t, now)
	if _, rtt := f.acknowledge(records, true, now); rtt != 0 {
		t.Fatalf("got %s", rtt)
	}
}

func TestNoteFlightRTTIgnoresRetransmit(t *testing.T) {
	s := &session{}
	now := time.Unix(10, 0)
	s.noteFlightRTT(&flight{firstSent: now.Add(-time.Second), resent: true}, now)
	if s.rtt != 0 {
		t.Fatal("sampled after retransmit")
	}
}

func TestNoteFlightRTTIgnoresBurstWait(t *testing.T) {
	s := &session{}
	now := time.Unix(10, 0)
	s.noteFlightRTT(&flight{firstSent: now.Add(-time.Second), burstWait: true}, now)
	if s.rtt != 0 {
		t.Fatal("sampled after burst wait")
	}
}

func TestNoteFlightRTTFromImplicitACK(t *testing.T) {
	s := &session{}
	now := time.Unix(10, 0)
	s.noteFlightRTT(&flight{firstSent: now.Add(-80 * time.Millisecond)}, now)
	if s.rtt != 80*time.Millisecond {
		t.Fatalf("got %s", s.rtt)
	}
}

func TestPathChallengeDeadlineIsThreeRTT(t *testing.T) {
	p := newTestPaths(t)
	p.server.rtt = 50 * time.Millisecond
	now := time.Unix(1000, 0)
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	if err := p.client.application([]byte("move")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	if got := p.server.path.probe.deadline.Sub(now); got != 150*time.Millisecond {
		t.Fatalf("got %s", got)
	}
}
