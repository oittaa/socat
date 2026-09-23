//go:build linux || darwin

package xio

import (
	"testing"
)

func TestExtraSources(t *testing.T) {
	in, out := extraSources(ModeRDWR, true)
	if in != "3" || out != "3" {
		t.Fatalf("socket RDWR %s %s", in, out)
	}
	in, out = extraSources(ModeRDWR, false)
	if in != "3" || out != "4" {
		t.Fatalf("pipes RDWR %s %s", in, out)
	}
	in, out = extraSources(ModeRead, false)
	if in != "" || out != "3" {
		t.Fatalf("pipes read %s %s", in, out)
	}
	in, out = extraSources(ModeWrite, true)
	if in != "3" || out != "" {
		t.Fatalf("socket write %s %s", in, out)
	}
}
