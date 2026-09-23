package dtls13

// Interval search and loss tolerance follow quic-go mtu_discoverer.go.
// QUIC ACK timing is not used. See NOTICE.md for the upstream commit.

type mtuFinder struct {
	floor            int
	lost             [maxLostMTUProbes]int
	lastProbeWasLost bool
	inFlight         int
	probes           int
}

func (f *mtuFinder) init(start, ceiling int) {
	if start < 1 {
		start = 1
	}
	if ceiling < start {
		ceiling = start
	}
	f.floor = start
	f.lost[0] = ceiling
	for i := 1; i < len(f.lost); i++ {
		f.lost[i] = invalidProbeSize
	}
	f.lastProbeWasLost = false
	f.inFlight = 0
	f.probes = 0
}

func (f *mtuFinder) ceiling() int {
	for i, v := range f.lost {
		if v == invalidProbeSize {
			if i == 0 {
				return f.floor
			}
			return f.lost[i-1]
		}
	}
	return f.lost[len(f.lost)-1]
}

func (f *mtuFinder) done() bool {
	return f.ceiling()-f.floor <= maxMTUDiff+1 || f.probes >= maxSearchProbes
}

func (f *mtuFinder) nextSize() int {
	if f.done() {
		return 0
	}
	var size int
	if f.lastProbeWasLost {
		size = (f.floor + f.lost[0]) / 2
	} else {
		size = (f.floor + f.ceiling()) / 2
	}
	if size <= f.floor {
		size = f.floor + 1
	}
	if hi := f.ceiling(); size >= hi && hi > f.floor {
		size = hi - 1
	}
	if size <= f.floor || size > f.ceiling() {
		return 0
	}
	return size
}

func (f *mtuFinder) onAcked(size int) {
	f.inFlight = 0
	if size > f.floor {
		f.floor = size
	}
	f.lastProbeWasLost = false
	var j int
	for i, v := range f.lost {
		if size < v {
			j = i
			break
		}
	}
	if j > 0 {
		for i := range f.lost {
			if i+j < len(f.lost) {
				f.lost[i] = f.lost[i+j]
			} else {
				f.lost[i] = invalidProbeSize
			}
		}
	}
}

func (f *mtuFinder) onLost(size int) {
	f.lastProbeWasLost = true
	f.inFlight = 0
	for i, v := range f.lost {
		if size < v {
			copy(f.lost[i+1:], f.lost[i:])
			f.lost[i] = size
			return
		}
	}
}

func (f *mtuFinder) rejectHard(size int) {
	for range maxLostMTUProbes {
		f.onLost(size)
	}
}
