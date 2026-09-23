//go:build linux || darwin

package execopen

import (
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestExtraSources(t *testing.T) {
	in, out := extraSources(xio.ModeRDWR, true)
	if in != "3" || out != "3" {
		t.Fatalf("socket RDWR %s %s", in, out)
	}
	in, out = extraSources(xio.ModeRDWR, false)
	if in != "3" || out != "4" {
		t.Fatalf("pipes RDWR %s %s", in, out)
	}
	in, out = extraSources(xio.ModeRead, false)
	if in != "" || out != "3" {
		t.Fatalf("pipes read %s %s", in, out)
	}
	in, out = extraSources(xio.ModeWrite, true)
	if in != "3" || out != "" {
		t.Fatalf("socket write %s %s", in, out)
	}
}
