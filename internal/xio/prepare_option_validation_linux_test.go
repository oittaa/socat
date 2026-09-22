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

func TestPrepareAcceptsLinuxTermiosNames(t *testing.T) {
	for _, raw := range []string{"iuclc", "olcuc", "xcase", "xtabs", "tabdly=0", "vswtc=0"} {
		if _, err := xio.PrepareSpec(mustParseSpec(t, "PTY,"+raw)); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
