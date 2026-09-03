package relay

import "testing"

func isolateTrackers(t *testing.T) {
	t.Helper()
	statsMu.Lock()
	oldLive, oldLast := live, last
	live, last = nil, nil
	statsMu.Unlock()
	t.Cleanup(func() {
		statsMu.Lock()
		live, last = oldLive, oldLast
		statsMu.Unlock()
	})
}

func liveBacking(t *testing.T) (active, tail []*Tracker) {
	t.Helper()
	statsMu.Lock()
	defer statsMu.Unlock()
	active = append([]*Tracker(nil), live...)
	full := live[:cap(live)]
	return active, full[len(live):]
}

func TestUnregisterTrackerClearsTailAndPreservesOrder(t *testing.T) {
	isolateTrackers(t)
	a, b, c := &Tracker{}, &Tracker{}, &Tracker{}
	RegisterTracker(a)
	RegisterTracker(b)
	RegisterTracker(c)
	if LastTracker() != c {
		t.Fatal("LastTracker should be the most recently registered")
	}

	UnregisterTracker(b)
	active, tail := liveBacking(t)
	if len(active) != 2 || active[0] != a || active[1] != c {
		t.Fatalf("active=%v want [a,c]", active)
	}
	for i, p := range tail {
		if p != nil {
			t.Fatalf("stale tail[%d]=%p", i, p)
		}
	}
	if LastTracker() != c {
		t.Fatal("LastTracker must stay set after unregister")
	}

	UnregisterTracker(a)
	active, tail = liveBacking(t)
	if len(active) != 1 || active[0] != c {
		t.Fatalf("active=%v want [c]", active)
	}
	for i, p := range tail {
		if p != nil {
			t.Fatalf("stale tail[%d]=%p after removing head", i, p)
		}
	}

	UnregisterTracker(c)
	active, tail = liveBacking(t)
	if len(active) != 0 {
		t.Fatalf("active=%v want empty", active)
	}
	for i, p := range tail {
		if p != nil {
			t.Fatalf("stale tail[%d]=%p after clearing last", i, p)
		}
	}
	if LastTracker() != c {
		t.Fatal("LastTracker must remain after the last unregister")
	}
}

func TestUnregisterTrackerNilAndRepeat(t *testing.T) {
	isolateTrackers(t)
	a, b := &Tracker{}, &Tracker{}
	RegisterTracker(a)
	RegisterTracker(b)
	UnregisterTracker(nil)
	UnregisterTracker(a)
	UnregisterTracker(a)
	active, tail := liveBacking(t)
	if len(active) != 1 || active[0] != b {
		t.Fatalf("active=%v want [b]", active)
	}
	for i, p := range tail {
		if p != nil {
			t.Fatalf("stale tail[%d]=%p", i, p)
		}
	}
	if LastTracker() != b {
		t.Fatal("LastTracker should still be b")
	}
}
