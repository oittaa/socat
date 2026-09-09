package dtls13

import (
	"bytes"
	"net/netip"
	"testing"
	"time"
)

func TestRetransmitTimerUsesOneAndAHalfRTT(t *testing.T) {
	s := &session{}
	if got := s.retransmitTimer(); got != initialRetransmit {
		t.Fatalf("unmeasured retransmit timer %s want %s", got, initialRetransmit)
	}
	if got := s.pathChallengeTimer(); got != time.Second {
		t.Fatalf("unmeasured path timer %s want 1s", got)
	}
	s.rtt = time.Millisecond
	if got := s.retransmitTimer(); got != minRetransmit {
		t.Fatalf("LAN retransmit timer %s want floor %s", got, minRetransmit)
	}
	if got := s.pathChallengeTimer(); got != 3*time.Millisecond {
		t.Fatalf("LAN path timer %s want 3ms", got)
	}
	s.rtt = 200 * time.Millisecond
	if got := s.retransmitTimer(); got != 300*time.Millisecond {
		t.Fatalf("retransmit timer %s want 300ms", got)
	}
	if got := s.ackDelay(); got != 75*time.Millisecond {
		t.Fatalf("ACK delay %s want 75ms", got)
	}
	if got := s.pathChallengeTimer(); got != 600*time.Millisecond {
		t.Fatalf("path timer %s want 600ms", got)
	}
}

func TestUnambiguousACKMeasuresRTT(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: msgCertificate, body: bytes.Repeat([]byte{1}, 40), epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0)
	var seq uint64
	if err := f.transmit(now, 50, func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var records []recordNumber
	for n := range f.sent {
		records = append(records, n)
	}
	progress, rtt := f.acknowledge(records, true, now.Add(50*time.Millisecond))
	if !progress {
		t.Fatal("ACK made no progress")
	}
	if rtt != 50*time.Millisecond {
		t.Fatalf("RTT %s want 50ms", rtt)
	}
}

func TestRetransmitSuppressesRTTSample(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: msgCertificate, body: bytes.Repeat([]byte{1}, 40), epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0)
	var seq uint64
	send := func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}
	if err := f.transmit(now, 50, send); err != nil {
		t.Fatal(err)
	}
	first := make([]recordNumber, 0, len(f.sent))
	for n := range f.sent {
		first = append(first, n)
	}
	retransmit, err := f.expire(now.Add(f.interval))
	if err != nil || !retransmit {
		t.Fatalf("expire: %v %v", retransmit, err)
	}
	if err := f.transmit(now.Add(f.interval), 50, send); err != nil {
		t.Fatal(err)
	}
	_, rtt := f.acknowledge(first, true, now.Add(2*time.Second))
	if rtt != 0 {
		t.Fatalf("retransmitted message still sampled RTT %s", rtt)
	}
}

func TestSameTimestampACKDoesNotSampleRTT(t *testing.T) {
	f, err := newFlight([]handshakeMessage{{typ: msgFinished, body: []byte{1}, epoch: 2}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1, 0)
	var seq uint64
	if err := f.transmit(now, 50, func(epoch uint64, _ []byte) (recordNumber, error) {
		seq++
		return recordNumber{epoch, seq}, nil
	}); err != nil {
		t.Fatal(err)
	}
	var records []recordNumber
	for n := range f.sent {
		records = append(records, n)
	}
	_, rtt := f.acknowledge(records, true, now)
	if rtt != 0 {
		t.Fatalf("zero-elapsed ACK sampled RTT %s", rtt)
	}
}

func TestNoteFlightRTTIgnoresRetransmitAndBurstWait(t *testing.T) {
	s := &session{}
	now := time.Unix(10, 0)
	s.noteFlightRTT(&flight{firstSent: now.Add(-time.Second), resent: true}, now)
	if s.rtt != 0 {
		t.Fatal("sampled RTT after retransmission")
	}
	s.noteFlightRTT(&flight{firstSent: now.Add(-time.Second), burstWait: true}, now)
	if s.rtt != 0 {
		t.Fatal("sampled RTT after new-byte burst wait")
	}
	s.noteFlightRTT(&flight{firstSent: now.Add(-80 * time.Millisecond)}, now)
	if s.rtt != 80*time.Millisecond {
		t.Fatalf("implicit ACK RTT %s want 80ms", s.rtt)
	}
	if s.retransmitTimer() != 120*time.Millisecond {
		t.Fatalf("1.5×80ms timer %s want 120ms", s.retransmitTimer())
	}
}

func TestPathChallengeTimerFollowsThreeRTT(t *testing.T) {
	p := newTestPaths(t)
	rtt := 50 * time.Millisecond
	p.server.rtt = rtt
	now := time.Unix(1000, 0)
	p.clientAddress = netip.MustParseAddrPort("192.0.2.3:3000")
	if err := p.client.application([]byte("move")); err != nil {
		t.Fatal(err)
	}
	p.deliver(t, now)
	probe := p.server.path.probe
	if probe == nil || probe.phase != pathValidateOld {
		t.Fatal("expected enhanced path challenge")
	}
	want := now.Add(3 * rtt)
	if !probe.deadline.Equal(want) {
		t.Fatalf("path deadline %v want %v", probe.deadline, want)
	}
	if err := p.server.tick(want.Add(-time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe == nil || p.server.path.probe.phase != pathValidateOld {
		t.Fatal("path timer fired before 3×RTT")
	}
	if err := p.server.tick(want); err != nil {
		t.Fatal(err)
	}
	if p.server.path.probe == nil || p.server.path.probe.phase != pathValidateCandidate {
		t.Fatal("path timer did not fall back after 3×RTT")
	}
}
