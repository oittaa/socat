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
		"reuseport", "ip-add-membership", "so-timestamp",
		"nonblock", "umask", "user", "group", "uid", "owner", "gid",
		"perm-early", "user-early", "group-early",
		"setsid", "pty", "setlk",
		"bindtodevice",
		"ip-pktinfo", "ip-options", "ipv6-tclass", "ipv6-unicast-hops",
	} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("unsupported option %q is listed", name)
		}
	}
	for _, name := range []string{
		"reuseaddr", "broadcast", "setsockopt", "setsockopt-listen",
		"setsockopt-int", "setsockopt-bin", "setsockopt-string",
		"setsockopt-socket", "setsockopt-connected",
		"rcvtimeo", "sndtimeo", "sndbuf", "rcvbuf", "sndbuf-late", "rcvbuf-late",
		"ciphers", "chdir", "end-close",
		"ip-ttl", "ip-tos",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("supported option %q is missing", name)
		}
	}
}

func TestWindowsHelpOmitsTermiosSpellings(t *testing.T) {
	for _, level := range []int{2, 3} {
		var b bytes.Buffer
		if err := printHelp(&b, level); err != nil {
			t.Fatal(err)
		}
		help := b.String()
		for _, name := range []string{
			"vintr", "intr", "icanon", "ispeed", "ospeed", "sane", "echo",
			"cfmakeraw", "b115200", "tiocswinsz",
		} {
			if strings.Contains(help, "    "+name+" ") {
				t.Errorf("level %d lists unsupported termios option %q", level, name)
			}
		}
	}
}

func TestWindowsHelpHHHOmitsMembershipSpellings(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"ip-add-membership", "add-membership", "ip-membership", "membership",
		"ipv6-join-group", "ipv6-add-membership", "join-group",
	} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("unsupported membership spelling %q is listed in -hhh", name)
		}
	}
}
