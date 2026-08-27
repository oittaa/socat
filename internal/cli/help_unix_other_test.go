//go:build !linux && !windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

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
}
