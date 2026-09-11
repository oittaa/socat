//go:build windows

package fileopen

import (
	"context"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/xio"
)

func TestAcceptFDRejectedOnWindows(t *testing.T) {
	_, err := openAcceptFD(context.Background(), addrconfig.Address{Type: "ACCEPT-FD", File: addrconfig.File{FD: 3, FDSet: true}}, xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported on windows") {
		t.Fatalf("got %v", err)
	}
}
