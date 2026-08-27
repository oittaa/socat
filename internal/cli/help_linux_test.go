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
		"ip-multicast-if", "multicast-if",
		"ip-multicast-loop", "multicast-loop", "mcloop", "ipmulticastloop", "multicastloop",
		"ip-multicast-ttl", "multicast-ttl", "ipmulticastttl", "multicastttl",
		"ipv6-multicast-loop", "ipv6-mcloop", "mcloop6",
		"ip-add-source-membership", "add-source-membership", "source-membership",
		"ipv6-join-source-group", "ipv6-add-source-membership", "join-source-group",
		"ip-freebind", "freebind", "ipfreebind",
		"ip-transparent", "transparent",
		"setsockopt", "setsockopt-int", "setsockopt-bin", "setsockopt-string",
		"setsockopt-listen", "setsockopt-socket", "setsockopt-connected",
		"sockopt", "sockopt-int", "sockopt-bin", "sockopt-string",
		"sockopt-listen", "sockopt-sock", "sockopt-conn",
		"broadcast", "so-broadcast",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
	for _, name := range []string{"ip-recverr", "recverr", "iprecverr", "ipv6-recverr", "ipv6-multicast-hops"} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("rejected or unknown option %q must not be advertised in -hhh", name)
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
