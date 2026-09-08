//go:build linux

package xio

import (
	"slices"
	"testing"
)

func TestLinuxHelpIncludesHighestNamedBaud(t *testing.T) {
	if !slices.Contains(TermiosHelpNames(), "b4000000") {
		t.Fatal("TermiosHelpNames does not include b4000000")
	}
}
