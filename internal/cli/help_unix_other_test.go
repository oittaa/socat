//go:build !linux && !windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestUnixOtherHelpListsAcceptFD(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 1); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, addr := range []string{"ACCEPT-FD:<fdnum>", "ACCEPT:<fdnum>"} {
		if !strings.Contains(help, addr) {
			t.Errorf("help missing %q", addr)
		}
	}
}

func TestUnixOtherHelpHidesLinuxSCTP(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{"sctp-nodelay", "sctp-maxseg"} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("unsupported option %q is listed", name)
		}
	}
	for _, name := range []string{
		"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string",
		"cloexec",
		"ip-recvdstaddr", "ip-recvif",
		"nopush", "noopt",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
}
