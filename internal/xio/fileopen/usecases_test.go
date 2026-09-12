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
	if _, err := io.WriteString(w.Stream(), "new"); err != nil {
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
