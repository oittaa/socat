//go:build darwin || windows

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyFDOptionsUnsupportedRejectsEnabledLinuxOptions(t *testing.T) {
	disabled := parse.Spec{Options: []parse.Option{{Name: "o-noatime", Value: "0", Has: true}}}
	if err := ApplyFDOptions(nil, disabled); err != nil {
		t.Fatalf("disabled o-noatime: %v", err)
	}
	enabled := parse.Spec{Options: []parse.Option{{Name: "o-noatime"}}}
	if err := ApplyFDOptions(nil, enabled); err == nil {
		t.Fatal("enabled o-noatime was accepted")
	}
	for _, name := range []string{
		"fs-noatime", "fs-append", "fs-nodump", "fs-immutable", "fs-notail",
	} {
		disabledFS := parse.Spec{Options: []parse.Option{{Name: name, Value: "0", Has: true}}}
		if err := ApplyFDOptions(nil, disabledFS); err != nil {
			t.Fatalf("disabled %s: %v", name, err)
		}
		enabledFS := parse.Spec{Options: []parse.Option{{Name: name}}}
		err := ApplyFDOptions(nil, enabledFS)
		if err == nil {
			t.Fatalf("enabled %s was accepted", name)
		}
		if !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Fatalf("%s error=%v", name, err)
		}
	}
}
