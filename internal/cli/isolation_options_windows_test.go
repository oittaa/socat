//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestFileOwnerUserRejectedOnWindows(t *testing.T) {
	ch, err := parse.ParseChannel("CREATE:file,user=65534")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareChannel(ch)
	if err == nil || !strings.Contains(err.Error(), "not supported on this platform") {
		t.Fatalf("user= error=%v", err)
	}
}
