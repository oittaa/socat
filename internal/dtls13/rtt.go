package dtls13

import "time"

func (s *session) retransmitTimer() time.Duration {
	if s.rtt <= 0 {
		return initialRetransmit
	}
	return clampDuration(s.rtt+s.rtt/2, minRetransmit, maximumRetransmit)
}

func (s *session) ackDelay() time.Duration {
	return s.retransmitTimer() / 4
}

// RFC 9853 §5.5: T = 3×RTT of the old path when known, otherwise 1s.
// Keep a 100ms minimum for the old-path check.
func (s *session) pathChallengeTimer() time.Duration {
	if s == nil || s.rtt <= 0 {
		return time.Second
	}
	return max(3*s.rtt, minRetransmit)
}

func (s *session) noteRTT(sample time.Duration, f *flight) {
	if sample <= 0 {
		return
	}
	s.rtt = sample
	if f != nil && !f.resent {
		f.interval = s.retransmitTimer()
	}
}

func (s *session) noteFlightRTT(f *flight, now time.Time) {
	if f == nil || f.complete || f.resent || f.burstWait || f.firstSent.IsZero() || !now.After(f.firstSent) {
		return
	}
	s.noteRTT(now.Sub(f.firstSent), nil)
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}
