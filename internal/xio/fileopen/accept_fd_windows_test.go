//go:build windows

package fileopen

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestAcceptFDRejectedOnWindows(t *testing.T) {
	_, err := openAcceptFD(context.Background(), parse.Spec{Type: "ACCEPT-FD", Params: []string{"3"}}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported on windows") {
		t.Fatalf("got %v", err)
	}
}
