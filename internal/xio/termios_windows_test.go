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
	err = RejectUnsupportedTermios(config)
	if err == nil || !strings.Contains(err.Error(), "b0") || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("OPEN:NUL,b0: %v", err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "b0") || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("OpenSpec OPEN:NUL,b0: %v", err)
	}
}

func TestRunOpenedClosesOPENNULWhenRightPrepareFails(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:NUL")
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(context.Background(), spec, ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	o.AddCleanup(func() { closed = true })
	ch, err := parse.ParseChannel("NOSUCH:x")
	if err != nil {
		t.Fatal(err)
	}
	err = RunOpened(context.Background(), o, ch, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown device/address") {
		t.Fatalf("error=%v", err)
	}
	if !closed {
		t.Fatal("left OPEN:NUL was not closed")
	}
}
