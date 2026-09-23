//go:build windows

package xio

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestOPENNULRejectsB0(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:NUL,b0")
	if err != nil {
		t.Fatal(err)
	}
	config, err := decodeAddress(spec)
	if err != nil {
		t.Fatal(err)
	}
	err = rejectUnsupportedTermios(config)
	if err == nil || !strings.Contains(err.Error(), "b0") || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("OPEN:NUL,b0: %v", err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "b0") || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("OpenSpec OPEN:NUL,b0: %v", err)
	}
}
