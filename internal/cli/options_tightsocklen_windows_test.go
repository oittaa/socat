//go:build windows

package cli

import (
	"strings"
	"testing"
)

func TestUnixTightSocklenRejectedOnWindows(t *testing.T) {
	err := validateParsed(t, "UNIX:foo,unix-tightsocklen=0")
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("error=%v want unix-tightsocklen platform rejection", err)
	}
}
