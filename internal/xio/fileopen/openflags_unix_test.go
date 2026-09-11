//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenDirectoryRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-directory")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("o-directory on a regular file succeeded")
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("o-directory: %v want ENOTDIR", err)
	}
}

func TestUnnamedPIPERejectsOSync(t *testing.T) {
	spec, err := parse.ParseSpec("PIPE,o-sync")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("unnamed PIPE,o-sync was accepted")
	}
	if !strings.Contains(err.Error(), "unnamed PIPE") {
		t.Fatalf("unnamed PIPE o-sync: %v", err)
	}
}
