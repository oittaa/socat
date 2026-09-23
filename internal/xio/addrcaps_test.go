package xio

import (
	"testing"
)

func TestOptionCapsAllowed(t *testing.T) {
	if !optionCapsAllowed([]string{optCapListen}, []string{optCapListen}) {
		t.Fatal("listen address should allow listen option")
	}
	if optionCapsAllowed(nil, []string{optCapListen}) {
		t.Fatal("address without listen cap must reject listen options")
	}
	if !optionCapsAllowed([]string{optCapListen}, nil) {
		t.Fatal("unrestricted option must be allowed")
	}
}
