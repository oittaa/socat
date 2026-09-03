package relay

import (
	"sync"
	"sync/atomic"
)

// Tracker holds live transfer counters (WITH_STATS).
type Tracker struct {
	BytesLR, BytesRL   atomic.Uint64
	BlocksLR, BlocksRL atomic.Uint64
	LeftToRight        bool
	RightToLeft        bool
}

// Snapshot returns a copy of the counters for logging.
func (t *Tracker) Snapshot() Stats {
	if t == nil {
		return Stats{}
	}
	return Stats{
		BytesLR:  t.BytesLR.Load(),
		BytesRL:  t.BytesRL.Load(),
		BlocksLR: t.BlocksLR.Load(),
		BlocksRL: t.BlocksRL.Load(),
	}
}

var (
	statsMu sync.Mutex
	live    []*Tracker
	last    *Tracker
)

// RegisterTracker records a live transfer for SIGUSR1 / --statistics.
func RegisterTracker(t *Tracker) {
	if t == nil {
		return
	}
	statsMu.Lock()
	live = append(live, t)
	last = t
	statsMu.Unlock()
}

// UnregisterTracker removes a finished transfer; LastTracker stays set.
func UnregisterTracker(t *Tracker) {
	if t == nil {
		return
	}
	statsMu.Lock()
	out := live[:0]
	for _, x := range live {
		if x != t {
			out = append(out, x)
		}
	}
	clear(live[len(out):])
	live = out
	statsMu.Unlock()
}

// LiveTrackers returns currently running transfers.
func LiveTrackers() []*Tracker {
	statsMu.Lock()
	defer statsMu.Unlock()
	out := make([]*Tracker, len(live))
	copy(out, live)
	return out
}

// LastTracker is the most recently registered transfer (may already have ended).
func LastTracker() *Tracker {
	statsMu.Lock()
	defer statsMu.Unlock()
	return last
}
