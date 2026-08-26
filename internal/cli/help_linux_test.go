//go:build linux

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestLinuxHelpListsSocketBufferAndBindToDevice(t *testing.T) {
	var b bytes.Buffer
	if err := printHelp(&b, 3); err != nil {
		t.Fatal(err)
	}
	help := b.String()
	for _, name := range []string{
		"sndbuf", "rcvbuf", "sndbuf-late", "rcvbuf-late", "bindtodevice",
		"so-sndbuf", "so-rcvbuf", "so-sndbuf-late", "so-rcvbuf-late",
		"so-bindtodevice", "if", "interface",
	} {
		if !strings.Contains(help, "    "+name+" ") {
			t.Errorf("honored option %q is missing from -hhh", name)
		}
	}
}
