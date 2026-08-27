//go:build windows

package fileopen

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenFlagsRejectsUnixOpenFlagsOnWindows(t *testing.T) {
	for _, raw := range []string{
		"OPEN:x,o-sync",
		"OPEN:x,o-dsync",
		"OPEN:x,o-rsync",
		"OPEN:x,o-noctty",
		"OPEN:x,o-nofollow",
		"OPEN:x,o-directory",
		"OPEN:x,o-largefile",
		"OPEN:x,async",
	} {
		spec, err := parse.ParseSpec(raw)
		if err != nil {
			t.Fatal(err)
		}
		_, err = OpenFlags(spec, xio.ModeRead)
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("%s: error=%v want not supported", raw, err)
		}
	}
}
