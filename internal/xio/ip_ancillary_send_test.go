package xio

import (
	"strings"
	"testing"
)

func TestParseHexOptRejectsMalformedAndOversizedValues(t *testing.T) {
	for _, value := range []string{"x0", "x" + strings.Repeat("00", maxIPOptions+1)} {
		if _, err := ParseHexOpt(value); err == nil {
			t.Fatalf("ParseHexOpt(%q) unexpectedly succeeded", value)
		}
	}
}
