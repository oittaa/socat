package dtls13

import (
	"errors"
	"time"
)

type mtuPhase byte

const (
	mtuDisabled mtuPhase = iota
	mtuConfirm
	mtuSearch
	mtuWatch
)

type mtuProbeKind byte

const (
	probeManual mtuProbeKind = iota
	probeConfirm
	probeSearch
)

func (s *session) mtuDiscoveryEnabled() bool {
	h := s.handshake
	return s.canProbe && h != nil && h.config != nil && h.config.UnfragmentedProbes &&
		h.complete && h.rrc && h.cidNegotiated && s.path != nil
}

func (s *session) mtuProbeMin() int {
	return rrcProbeOverhead(len(s.probeCID()), s.recordTagLen())
}

func (s *session) mtuProbeCeiling() int {
	maxPad := maxContent - rrcMessageLen
	encoded := rrcProbeOverhead(len(s.probeCID()), s.recordTagLen()) + maxPad
	return min(s.mtuCeiling(), encoded)
}

func (s *session) restartMTUConfirm() {
	if !s.mtuDiscoveryEnabled() {
		s.mtu.phase = mtuDisabled
		s.mtu.searchAfterConfirm = false
		return
	}
	s.mtu.phase = mtuConfirm
	s.mtu.searchAfterConfirm = true
	s.mtu.confirmFails = 0
	s.mtu.nextProbe = time.Time{}
	s.mtu.raiseAt = time.Time{}
	s.mtu.confirmAt = time.Time{}
}

func (s *session) noteMTUActivity() {
	s.mtu.appSinceProbe = true
}

func (s *session) onApplicationTooBig() {
	_ = s.reduceHandshakeMTU(s.lastSendSize)
	if s.mtuDiscoveryEnabled() {
		s.restartMTUConfirm()
	}
}

func (s *session) beginMTUSearch(now time.Time) {
	s.mtu.raiseAt = time.Time{}
	start := s.effectiveMTU()
	ceiling := s.mtuProbeCeiling()
	s.mtu.finder.init(start, ceiling)
	if s.mtu.finder.done() {
		s.scheduleMTUWatch(now)
		return
	}
	s.mtu.phase = mtuSearch
}

func (s *session) scheduleMTUWatch(now time.Time) {
	s.mtu.phase = mtuWatch
	if s.mtu.raiseAt.IsZero() || !now.Before(s.mtu.raiseAt) {
		s.mtu.raiseAt = now.Add(raiseTimer)
	}
	s.mtu.confirmAt = now.Add(confirmTimer)
	s.mtu.nextProbe = time.Time{}
}

func (s *session) onMTUProbeAcked(probe *mtuProbe, now time.Time) {
	s.mtu.lastFailed = false
	s.mtu.lastAckedSize = probe.size
	s.mtu.nextProbe = now.Add(probePace)
	switch probe.kind {
	case probeManual:
		return
	case probeConfirm:
		s.mtu.confirmFails = 0
		if probe.size > s.effectiveMTU() {
			s.setWorkingMTU(probe.size)
		}
		if s.mtu.searchAfterConfirm {
			s.beginMTUSearch(now)
			return
		}
		s.scheduleMTUWatch(now)
	case probeSearch:
		s.mtu.finder.onAcked(probe.size)
		if probe.size > s.effectiveMTU() {
			s.setWorkingMTU(probe.size)
		}
		if s.mtu.finder.done() {
			s.scheduleMTUWatch(now)
		}
	}
}

func (s *session) onMTUProbeLost(probe *mtuProbe, now time.Time, hard bool) {
	s.mtu.lastFailed = true
	s.mtu.nextProbe = now.Add(probePace)
	switch probe.kind {
	case probeManual:
		return
	case probeConfirm:
		s.mtu.confirmFails++
		if hard {
			s.mtu.confirmFails = maxConfirmFails
		}
		if s.mtu.confirmFails < maxConfirmFails {
			return
		}
		s.mtu.confirmFails = 0
		if !s.reduceHandshakeMTU(probe.size) {
			s.scheduleMTUWatch(now)
			return
		}
		s.mtu.searchAfterConfirm = true
		s.mtu.phase = mtuConfirm
	case probeSearch:
		s.mtu.finder.onLost(probe.size)
		if s.mtu.finder.done() {
			s.scheduleMTUWatch(now)
		}
	}
}

func (s *session) tickMTUDiscovery(now time.Time) {
	if s.mtu.outstanding != nil {
		return
	}
	if !s.mtuDiscoveryEnabled() {
		s.mtu.phase = mtuDisabled
		return
	}
	if s.mtu.phase == mtuDisabled {
		s.restartMTUConfirm()
	}
	if !s.mtu.nextProbe.IsZero() && now.Before(s.mtu.nextProbe) {
		return
	}
	switch s.mtu.phase {
	case mtuConfirm:
		s.sendDiscoveryProbe(s.effectiveMTU(), now, probeConfirm)
	case mtuSearch:
		size := s.mtu.finder.nextSize()
		if size == 0 {
			s.scheduleMTUWatch(now)
			return
		}
		s.sendDiscoveryProbe(size, now, probeSearch)
	case mtuWatch:
		if !s.mtu.appSinceProbe {
			return
		}
		if !s.mtu.raiseAt.IsZero() && !now.Before(s.mtu.raiseAt) {
			s.mtu.appSinceProbe = false
			s.beginMTUSearch(now)
			if s.mtu.phase == mtuSearch {
				size := s.mtu.finder.nextSize()
				if size == 0 {
					s.scheduleMTUWatch(now)
					return
				}
				s.sendDiscoveryProbe(size, now, probeSearch)
			}
			return
		}
		if !s.mtu.confirmAt.IsZero() && !now.Before(s.mtu.confirmAt) {
			s.mtu.appSinceProbe = false
			s.mtu.phase = mtuConfirm
			s.mtu.searchAfterConfirm = false
			s.mtu.confirmFails = 0
			s.sendDiscoveryProbe(s.effectiveMTU(), now, probeConfirm)
		}
	}
}

func (s *session) sendDiscoveryProbe(size int, now time.Time, kind mtuProbeKind) {
	minSize := s.mtuProbeMin()
	ceiling := s.mtuProbeCeiling()
	if size < minSize {
		size = minSize
	}
	if size > ceiling {
		s.scheduleMTUWatch(now)
		return
	}
	if kind == probeSearch && size <= s.mtu.finder.min {
		s.scheduleMTUWatch(now)
		return
	}
	err := s.sendMTUProbe(size, now, kind)
	if err == nil {
		if kind == probeSearch {
			s.mtu.finder.inFlight = size
			s.mtu.finder.probes++
		}
		s.mtu.appSinceProbe = false
		return
	}
	if kind == probeSearch && (isMessageTooLong(err) || errors.Is(err, errProbeTooBig)) {
		s.mtu.finder.rejectHard(size)
		s.mtu.nextProbe = now.Add(probePace)
		if s.mtu.finder.done() {
			s.scheduleMTUWatch(now)
		}
		return
	}
	if kind == probeConfirm && (errors.Is(err, errProbeTooBig) || isMessageTooLong(err)) {
		s.onMTUProbeLost(&mtuProbe{size: size, kind: probeConfirm}, now, true)
		return
	}
	if errors.Is(err, errProbeSize) || errors.Is(err, errRecordOverflow) {
		s.scheduleMTUWatch(now)
		return
	}
	s.mtu.nextProbe = now.Add(probePace)
}

func (s *session) mtuDeadline() time.Time {
	if s.mtu.outstanding != nil {
		return s.mtu.outstanding.deadline
	}
	if s.mtu.phase == mtuDisabled || !s.mtuDiscoveryEnabled() {
		return time.Time{}
	}
	if s.mtu.phase == mtuWatch {
		if !s.mtu.appSinceProbe {
			return time.Time{}
		}
		return earlierDeadline(s.mtu.confirmAt, s.mtu.raiseAt)
	}
	return s.mtu.nextProbe
}
