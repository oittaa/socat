package cli

import (
	"bytes"
	"testing"
)

func checkPlatformHelp(t *testing.T, shown, hidden []string) {
	t.Helper()
	var output bytes.Buffer
	if err := printHelp(&output, 3); err != nil {
		t.Fatal(err)
	}
	listed := helpLineNames(output.String())
	for _, name := range shown {
		if !listed[name] {
			t.Errorf("-hhh missing %s", name)
		}
	}
	for _, name := range hidden {
		if listed[name] {
			t.Errorf("-hhh advertises unsupported %s", name)
		}
	}
}
