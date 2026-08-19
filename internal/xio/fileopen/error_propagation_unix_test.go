//go:build unix

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestNamedPipeOwnershipFailureCleansCreatedFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	s, err := parse.ParseSpec("PIPE:" + path + ",user=socat-user-that-must-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPIPE(context.Background(), s, xio.ModeRDWR, nil); err == nil {
		t.Fatal("openPIPE unexpectedly ignored ownership failure")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("failed PIPE left filesystem entry behind: %v", err)
	}
}
