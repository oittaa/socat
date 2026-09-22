//go:build linux || darwin

package cli

import (
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestFileOwnerUserIsNotIsolationOption(t *testing.T) {
	ch, err := parse.ParseChannel("CREATE:file,user=65534")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareChannel(ch)
	if err != nil {
		t.Fatalf("user= is file owner, got %v", err)
	}
}
