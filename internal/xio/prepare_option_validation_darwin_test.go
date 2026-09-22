//go:build darwin

package xio_test

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestPrepareRejectsLinuxOnlyTermios(t *testing.T) {
	for _, raw := range []string{"iuclc", "olcuc", "xcase", "xtabs", "tabdly=0", "vswtc=0"} {
		_, err := xio.PrepareSpec(mustParseSpec(t, "PTY,"+raw))
		if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}
