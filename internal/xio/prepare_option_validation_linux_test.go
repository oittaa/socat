//go:build linux

package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareRejectsDarwinOnlyTCPOptions(t *testing.T) {
	for _, raw := range []string{
		"TCP4:127.0.0.1:9,nopush",
		"TCP4:127.0.0.1:9,tcp-nopush=1",
		"TCP4:127.0.0.1:9,noopt",
	} {
		_, err := xio.PrepareSpec(mustParseSpec(t, raw))
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestPrepareAcceptsFamiliesPassedToSocket(t *testing.T) {
	for _, raw := range []string{
		"TCP4:127.0.0.1:9,pf=0",
		"UDP4:127.0.0.1:9,pf=0",
		"SCTP4:127.0.0.1:9,pf=0",
		"IP4:127.0.0.1:255,pf=0",
		"UNIX-LISTEN:/tmp/socat-pf-unix,pf=1",
		"UNIX-CONNECT:/tmp/socat-pf-unix,pf=1",
		"ABSTRACT-LISTEN:socat-pf,pf=1",
		"EXEC:/bin/true,pf=1",
		"INTERFACE:lo,pf=17",
		"SOCKET-LISTEN:1:0:x00007f000001,pf=1",
		"INTERFACE:lo,so-type=3",
		"IP4:127.0.0.1:255,so-type=3",
	} {
		if _, err := xio.PrepareSpec(mustParseSpec(t, raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"UNIX-LISTEN:/tmp/socat-pf-unix,pf=2",
		"INTERFACE:lo,pf=2",
		"TCP4:127.0.0.1:9,pf=1",
		"INTERFACE:lo,so-type=99",
		"IP4:127.0.0.1:255,so-type=99",
	} {
		_, err := xio.PrepareSpec(mustParseSpec(t, raw))
		if err == nil {
			t.Fatalf("%s was accepted", raw)
		}
	}
}

func TestPrepareAcceptsLinuxTermiosNames(t *testing.T) {
	for _, raw := range []string{"iuclc", "olcuc", "xcase", "xtabs", "tabdly=0", "vswtc=0"} {
		if _, err := xio.PrepareSpec(mustParseSpec(t, "PTY,"+raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
