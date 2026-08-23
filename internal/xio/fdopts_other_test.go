//go:build !linux

package xio

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyFDOptionsOtherRejectsOnlyEnabledLinuxOptions(t *testing.T) {
	disabled := parse.Spec{Options: []parse.Option{{Name: "o-noatime", Value: "0", Has: true}}}
	if err := ApplyFDOptions(nil, disabled); err != nil {
		t.Fatalf("disabled o-noatime: %v", err)
	}
	enabled := parse.Spec{Options: []parse.Option{{Name: "o-noatime"}}}
	if err := ApplyFDOptions(nil, enabled); err == nil {
		t.Fatal("enabled o-noatime was accepted")
	}
}
