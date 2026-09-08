package xio

import (
	"testing"
)

func TestTermiosOptionNames(t *testing.T) {
	names := TermiosOptionNames()
	have := make(map[string]bool, len(names))
	for _, name := range names {
		have[name] = true
	}
	for _, name := range []string{"vintr", "intr", "ispeed", "ospeed", "icanon", "echo", "sane", "b115200"} {
		if !have[name] {
			t.Errorf("TermiosOptionNames missing %q", name)
		}
	}
	for _, name := range []string{"dsusp", "vdsusp", "b900", "b3600", "ccid", "udplite-send-cscov", "ptmx", "openpty", "pty-wait-slave"} {
		if have[name] {
			t.Errorf("TermiosOptionNames must not include %q", name)
		}
	}
	if len(names) < 50 {
		t.Fatalf("TermiosOptionNames returned %d names, want a full termios set", len(names))
	}
}
