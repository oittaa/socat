package dtls13

const (
	minPathMTU       = 256
	maxMTUReductions = 8
)

func (s *session) effectiveMTU() int {
	if s.pathMTU > 0 {
		return min(s.pathMTU, s.handshake.config.MTU)
	}
	return s.handshake.config.MTU
}

func (s *session) reduceHandshakeMTU(tooBig int) bool {
	current := s.effectiveMTU()
	if current <= minPathMTU || s.mtuReductions >= maxMTUReductions {
		return false
	}
	next := current / 2
	if tooBig > minPathMTU {
		if capped := tooBig - 1; capped < next {
			next = capped
		}
	}
	if next < minPathMTU {
		next = minPathMTU
	}
	if next >= current {
		return false
	}
	s.pathMTU = next
	s.mtuReductions++
	return true
}
