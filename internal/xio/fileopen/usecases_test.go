package fileopen

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func openUse(t *testing.T, spec string, mode xio.Mode) *xio.Opened {
	t.Helper()
	ch, err := parse.ParseChannel(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(context.Background(), ch, mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestCREATEAppendStillTruncatesExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create-append.bin")
	if err := os.WriteFile(path, []byte("stale-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := openUse(t, "CREATE:"+path+",append", xio.ModeWrite)
	if _, err := io.WriteString(w.Stream, "new"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("CREATE,append preserved stale contents: got %q", got)
	}
}

func TestOPENRepeatedFtruncateAppliesEachOccurrence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ops []string
	restore := xio.InstallLifecycleSyscallHook(func(op string) { ops = append(ops, op) })
	t.Cleanup(restore)
	_ = openUse(t, "OPEN:"+path+",ftruncate=8,ftruncate=3", xio.ModeWrite)
	n := 0
	for _, op := range ops {
		if op == "ftruncate" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("ftruncate count=%d want 2 (ops=%v)", n, ops)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("size=%d want 3", st.Size())
	}
}
