//go:build !linux && !windows

package cli

import (
	"bytes"
	"runtime"
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
		"ip-retopts", "retopts", "ipretopts",
		"ip-router-alert", "iprouteralert", "routeralert",
		"ip-freebind", "ip-mtu-discover",
	} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("Linux-only option %q must not be advertised on %s", name, runtime.GOOS)
		}
	}
	honored := []string{
		"ioctl", "ioctl-void", "ioctl-int", "ioctl-intp", "ioctl-bin", "ioctl-string",
		"cloexec",
		"nopush", "noopt",
		"so-rcvlowat", "rcvlowat", "so-sndlowat", "sndlowat",
		"ip-hdrincl", "hdrincl", "iphdrincl",
	}
	if runtime.GOOS == "darwin" {
		honored = append(honored, "ip-recvdstaddr", "ip-recvif")
	}
	for _, name := range honored {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
	if runtime.GOOS != "darwin" {
		for _, name := range []string{"ip-recvdstaddr", "ip-recvif", "recvdstaddr", "iprecvdstaddr", "recvif"} {
			if strings.Contains(help, "    "+name+" ") {
				t.Errorf("Darwin-only option %q must not be advertised on %s", name, runtime.GOOS)
			}
		}
	}
}
