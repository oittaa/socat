//go:build windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestWindowsHelpOmitsAcceptFD(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 1); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, addr := range []string{"ACCEPT-FD:<fdnum>", "ACCEPT:<fdnum>"} {
		if strings.Contains(help, addr) {
			t.Errorf("Windows help lists %q", addr)
		}
	}
}

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
		"o-sync", "async", "flock", "perm-late", "user-late",
		"setsid", "pty", "setlk",
		"dash", "setpgid",
		"bindtodevice",
		"ip-pktinfo", "ip-options", "ipv6-tclass", "ipv6-unicast-hops",
		"tcp-cork", "tcp-maxseg", "tcp-maxseg-late",
		"sctp-nodelay", "sctp-maxseg",
		"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string",
		"fs-append", "fs-nodump", "fs-notail", "nodump", "notail",
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
		"lockfile", "waitlock",
		"ip-ttl", "ip-tos",
		"so-debug", "so-dontroute", "so-oobinline",
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
		"ip-multicast-if", "ip-multicast-loop", "ip-multicast-ttl",
		"ipmulticastloop", "multicastloop", "ipmulticastttl", "multicastttl",
		"ipv6-multicast-loop", "ip-add-source-membership", "ipv6-join-source-group",
		"ip-freebind", "ip-transparent",
		"ip-mtu-discover", "mtudiscover", "ipmtudiscover",
		"ipv6-mtu-discover", "mtudiscover6",
	} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("unsupported membership spelling %q is listed in -hhh", name)
		}
	}
}
