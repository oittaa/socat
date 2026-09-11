//go:build windows

package fileopen

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestSTALLRejectedOnWindows(t *testing.T) {
	_, err := openSTALL(context.Background(), parse.Spec{Type: "STALL"}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("got %v", err)
	}
}

func TestPTYRejectedOnWindows(t *testing.T) {
	prepared, err := xio.PrepareSpec(parse.Spec{Type: "PTY"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.OpenPreparedSpec(context.Background(), prepared, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("got %v", err)
	}
}
