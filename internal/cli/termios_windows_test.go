//go:build windows

package cli

import (
	"strings"
	"testing"
)

func TestOPENNULB0Rejected(t *testing.T) {
	err := validateParsed(t, "OPEN:NUL,b0")
	if err == nil || !strings.Contains(err.Error(), "b0") || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("OPEN:NUL,b0: %v", err)
	}
}
