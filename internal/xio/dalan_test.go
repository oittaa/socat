package xio

import (
	"strings"
	"testing"
)

func TestParseDalanRejectsLeftoverAndEmptyNumeric(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"512junk", "not-a-dalan-path", "i", "x0", "'ab'", `"unterminated`, "X0102"} {
		if _, _, err := ParseDalan(s, 'i'); err == nil {
			t.Errorf("ParseDalan(%q) succeeded", s)
		} else if !strings.Contains(err.Error(), "syntax error") {
			t.Errorf("ParseDalan(%q): %v want syntax error", s, err)
		}
	}
}

func TestParseSockoptBinRejectsSocatDataPath(t *testing.T) {
	t.Parallel()
	if _, _, _, err := parseSockoptBin("not-a-dalan-path"); err == nil {
		t.Fatal("ASCII path fallback must not be used for setsockopt-bin")
	}
	if _, _, _, err := parseSockoptBin(""); err == nil {
		t.Fatal("empty dalan must fail")
	}
}
