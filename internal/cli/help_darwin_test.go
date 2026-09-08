//go:build darwin

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestDarwinHelpListsAcceptFD(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 1); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, addr := range []string{"ACCEPT-FD:<fdnum>", "ACCEPT:<fdnum>"} {
		if !strings.Contains(help, addr) {
			t.Errorf("help missing %q", addr)
		}
	}
}
