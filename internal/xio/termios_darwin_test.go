//go:build darwin

package xio

import (
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinTABDLYEncoding(t *testing.T) {
	if termiosBits(unix.TAB3) != termiosBits(unix.OXTABS) {
		t.Fatalf("TAB3=%#x OXTABS=%#x; tab3 must set OXTABS", unix.TAB3, unix.OXTABS)
	}
	want := termiosBits(unix.TAB1) | termiosBits(unix.TAB2) | termiosBits(unix.TAB3)
	if termiosTABDLY != want {
		t.Fatalf("TABDLY=%#x want TAB1|TAB2|TAB3=%#x", termiosTABDLY, want)
	}
	if _, ok := termiosTwoBitShift(termiosTABDLY); ok {
		t.Fatal("Darwin TABDLY mixes OXTABS with TAB1/TAB2; it is not a 2-bit field")
	}
}

func TestDarwinOmitsTabdlyAndXTABS(t *testing.T) {
	names := TermiosHelpNames()
	for _, n := range []string{"tabdly", "xtabs"} {
		if slices.Contains(names, n) {
			t.Errorf("Darwin -hhh must not list %q", n)
		}
	}
	for _, n := range []string{"nldly", "bsdly", "vtdly", "ffdly", "crdly", "csize"} {
		if !slices.Contains(names, n) {
			t.Errorf("Darwin TermiosHelpNames missing %q", n)
		}
	}
}
