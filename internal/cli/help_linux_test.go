//go:build linux

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestLinuxHelpListsSocketBufferAndBindToDevice(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"sndbuf", "rcvbuf", "sndbuf-late", "rcvbuf-late", "bindtodevice",
		"so-sndbuf", "so-rcvbuf", "so-sndbuf-late", "so-rcvbuf-late",
		"so-bindtodevice", "if", "interface",
		"so-protocol", "so-prototype", "prototype", "protocol-family", "type",
		"ip-add-membership", "add-membership", "ip-membership", "membership",
		"ipv6-join-group", "ipv6-add-membership", "join-group",
		"setsockopt", "setsockopt-int", "setsockopt-bin", "setsockopt-string",
		"setsockopt-listen", "setsockopt-socket", "setsockopt-connected",
		"sockopt", "sockopt-int", "sockopt-bin", "sockopt-string",
		"sockopt-listen", "sockopt-sock", "sockopt-conn",
		"broadcast", "so-broadcast",
		"so-debug", "debug", "so-dontroute", "dontroute", "so-oobinline", "oobinline",
		"tcp-cork", "cork", "tcp-defer-accept", "defer-accept",
		"tcp-linger2", "linger2", "tcp-maxseg", "maxseg", "mss",
		"tcp-maxseg-late", "maxseg-late", "mss-late",
		"tcp-quickack", "quickack", "tcp-syncnt", "syncnt",
		"tcp-window-clamp", "window-clamp",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
	for _, addr := range []string{
		"VSOCK-CONNECT:<cid>:<port>",
		"VSOCK-LISTEN:<port>",
	} {
		if !strings.Contains(help, addr) {
			t.Errorf("help missing %q", addr)
		}
	}
}

func TestLinuxVersionDefinesVSOCK(t *testing.T) {
	var b bytes.Buffer
	if err := printVersion(&b); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "#define WITH_VSOCK 1") {
		t.Fatalf("missing WITH_VSOCK 1:\n%s", b.String())
	}
}
