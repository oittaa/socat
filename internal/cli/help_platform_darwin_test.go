//go:build darwin

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
		"ip-recverr": false, "recverr": false, "binary": false,
		"ip-recvdstaddr": true, "so-timestamp": true,
	} {
		if listed[name] != want {
			t.Errorf("%s: advertised=%v, want %v", name, listed[name], want)
		}
	}
}
