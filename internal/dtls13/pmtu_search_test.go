package dtls13

import "testing"

func TestMTUFinderInitClampsRange(t *testing.T) {
	var f mtuFinder
	f.init(0, 100)
	if f.floor != 1 || f.ceiling() != 100 {
		t.Fatalf("zero start min=%d max=%d", f.floor, f.ceiling())
	}
	f.init(80, 40)
	if f.floor != 80 || f.ceiling() != 80 || !f.done() {
		t.Fatalf("inverted range min=%d max=%d done=%t", f.floor, f.ceiling(), f.done())
	}
}

func TestMTUFinderIsolatedLossKeepsCeiling(t *testing.T) {
	var f mtuFinder
	f.init(400, 1200)
	f.onLost(800)
	if f.ceiling() != 1200 {
		t.Fatalf("one loss dropped max to %d", f.ceiling())
	}
	if f.floor != 400 {
		t.Fatalf("loss changed working min to %d", f.floor)
	}
	next := f.nextSize()
	if next == 0 || next >= 800 {
		t.Fatalf("after loss next=%d, want below the lost size", next)
	}
}

func TestMTUFinderThreeLossesLowerMax(t *testing.T) {
	var f mtuFinder
	f.init(400, 1200)
	f.onLost(700)
	f.onLost(800)
	if f.ceiling() != 1200 {
		t.Fatalf("two losses dropped max to %d", f.ceiling())
	}
	f.onLost(900)
	if f.ceiling() != 900 {
		t.Fatalf("three losses max=%d want 900", f.ceiling())
	}
	if f.floor != 400 {
		t.Fatalf("losses changed working min to %d", f.floor)
	}
}

func TestMTUFinderRejectHardDropsCeiling(t *testing.T) {
	var f mtuFinder
	f.init(400, 1200)
	f.rejectHard(800)
	if f.ceiling() != 800 {
		t.Fatalf("EMSGSIZE max=%d want 800", f.ceiling())
	}
	if f.floor != 400 {
		t.Fatal("hard reject lowered the working min")
	}
	next := f.nextSize()
	if next == 0 || next >= 800 {
		t.Fatalf("after hard reject next=%d", next)
	}
}

func TestMTUFinderDoneWhenRangeTight(t *testing.T) {
	var f mtuFinder
	f.init(1180, 1200)
	if !f.done() {
		t.Fatal("tight range should stop searching")
	}
	if f.nextSize() != 0 {
		t.Fatal("done finder still offered a probe")
	}
}

func TestMTUFinderProbeCapStopsSearch(t *testing.T) {
	var f mtuFinder
	f.init(256, 1200)
	f.probes = maxSearchProbes
	if !f.done() {
		t.Fatal("probe cap did not stop the search")
	}
}

func TestMTUFinderAckClearsSmallerLosses(t *testing.T) {
	var f mtuFinder
	f.init(400, 1200)
	f.onLost(700)
	f.onAcked(900)
	if f.floor != 900 {
		t.Fatalf("min %d", f.floor)
	}
	if f.ceiling() != 1200 {
		t.Fatalf("max %d after larger ack", f.ceiling())
	}
}
