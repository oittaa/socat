//go:build windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsHelpListsOnlyHonoredOptions(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 2); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"reuseport", "ip-add-membership", "so-timestamp", "ip-ttl",
		"nonblock", "umask", "user", "group", "perm-early", "user-early", "group-early",
		"setsid", "pty", "setlk",
	} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("unsupported option %q is listed", name)
		}
	}
	for _, name := range []string{
		"reuseaddr", "broadcast", "setsockopt", "setsockopt-listen",
		"rcvtimeo", "sndtimeo", "ciphers", "chdir", "end-close",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("supported option %q is missing", name)
		}
	}
}
