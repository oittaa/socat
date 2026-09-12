package xio

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
)

func TestParseDalanRejectsLeftoverAndEmptyNumeric(t *testing.T) {
	t.Parallel()
	for _, s := range []string{"512junk", "not-a-dalan-path", "i", "x0", "'ab'", `"unterminated`, "X0102"} {
		if _, _, err := addrconfig.ParseDalan(s, 'i'); err == nil {
			t.Errorf("ParseDalan(%q) succeeded", s)
		} else if !strings.Contains(err.Error(), "syntax error") {
			t.Errorf("ParseDalan(%q): %v want syntax error", s, err)
		}
	}
}

func TestParseDalanRejectsSocatDataPath(t *testing.T) {
	t.Parallel()
	if _, _, err := addrconfig.ParseDalan("not-a-dalan-path", 'i'); err == nil {
		t.Fatal("ASCII path fallback must not be used for setsockopt-bin")
	}
	data, singleInt, err := addrconfig.ParseDalan("", 'i')
	if err != nil || singleInt || len(data) != 0 {
		t.Fatalf("empty dalan: data=%q singleInt=%v err=%v", data, singleInt, err)
	}
}
