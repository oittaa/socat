//go:build !windows

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestNonWindowsHelpOmitsWindowsDescriptorModes(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{"bin", "binary", "o-binary", "text", "o-text", "noinherit", "o-noinherit"} {
		if strings.Contains(help, "    "+name+" ") {
			t.Errorf("non-Windows help lists %q", name)
		}
	}
}
