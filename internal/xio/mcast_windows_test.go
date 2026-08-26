//go:build windows

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyMembershipJoinsUnsupportedOnWindows(t *testing.T) {
	none, err := parse.ParseSpec("UDP6:[::1]:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyMembershipJoins(0, none); err != nil {
		t.Fatalf("no membership options: %v", err)
	}

	spec, err := parse.ParseSpec("UDP6:[::1]:9,ipv6-join-group=[ff02::2]:lo")
	if err != nil {
		t.Fatal(err)
	}
	err = ApplyMembershipJoins(0, spec)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("error=%v want explicit Windows unsupported error", err)
	}
}
