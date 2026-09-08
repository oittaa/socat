package xio

import (
	"testing"
)

func TestOptionCapsAllowed(t *testing.T) {
	if !OptionCapsAllowed([]string{OptCapListen}, []string{OptCapListen}) {
		t.Fatal("listen address should allow listen option")
	}
	if OptionCapsAllowed(nil, []string{OptCapListen}) {
		t.Fatal("address without listen cap must reject listen options")
	}
	if !OptionCapsAllowed([]string{OptCapListen}, nil) {
		t.Fatal("unrestricted option must be allowed")
	}
}
