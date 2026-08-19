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
	_, err := openPTY(context.Background(), parse.Spec{Type: "PTY"}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("got %v", err)
	}
}
