//go:build linux || darwin

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestPTYLinkStillCreatesSymlink(t *testing.T) {
	link := filepath.Join(t.TempDir(), "pty-addr")
	ch, err := parse.ParseChannel("PTY,echo=0,link=" + link)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := xio.PrepareChannel(ch)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenPreparedChannel(context.Background(), prepared, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("PTY link missing: %v", err)
	}
}
