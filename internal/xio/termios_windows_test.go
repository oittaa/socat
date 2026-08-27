//go:build windows

package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestWindowsRejectsTermiosOptions(t *testing.T) {
	for _, spec := range []string{
		"STDIO,echo",
		"STDIN,vintr=3",
		"FD:3,cfmakeraw",
		"STDIO,sane",
		"STDIO,icanon=0",
	} {
		s, err := parse.ParseSpec(spec)
		if err != nil {
			t.Fatal(err)
		}
		err = RejectUnsupportedTermios(s)
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Errorf("%s: err=%v want not supported on this platform", spec, err)
		}
		if err := ApplyTermios(0, s); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Errorf("ApplyTermios(%s): err=%v", spec, err)
		}
	}
	s, err := parse.ParseSpec("STDIO")
	if err != nil {
		t.Fatal(err)
	}
	if err := RejectUnsupportedTermios(s); err != nil {
		t.Fatalf("STDIO without termios options: %v", err)
	}
}
