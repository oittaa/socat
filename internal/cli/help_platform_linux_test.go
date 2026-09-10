//go:build linux

package cli

import (
	"bytes"
	"testing"
)

func TestHelpPlatformVisibility(t *testing.T) {
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	listed := helpLineNames(output.String())
	for name, want := range map[string]bool{
		"ip-recverr": true, "recverr": true, "so-timestamp": true,
		"ip-recvdstaddr": false, "binary": false,
	} {
		if listed[name] != want {
			t.Errorf("%s: advertised=%v, want %v", name, listed[name], want)
		}
	}
}
