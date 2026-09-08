//go:build linux

package fileopen

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenLargefileAccepted(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-largefile,largefile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFlags(spec, xio.ModeRead); err != nil {
		t.Fatal(err)
	}
}
