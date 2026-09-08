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

func TestOPENLockFailurePrecedesLateFtruncate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phase-lock-before-late")
	if err := os.WriteFile(path, []byte("abcdefghij"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",setlk-rd,ftruncate=3")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openOPEN(context.Background(), spec, xio.ModeWrite, nil); err == nil {
		t.Fatal("write-only OPEN unexpectedly acquired a read lock")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 10 {
		t.Fatalf("size=%d want 10: PH_LATE ftruncate ran before PH_FD lock failure", st.Size())
	}
}
