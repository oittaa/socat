//go:build linux || darwin

package xio_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestOPENFtruncateStillShortensNamedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenChannel(testCtx(t), mustParse(t, "OPEN:"+path+",ftruncate=3"), xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 3 {
		t.Fatalf("named OPEN ftruncate size=%d want 3", st.Size())
	}
}

func TestEXECAppendDoesNotError(t *testing.T) {
	truePath := lookPath(t, "true")
	o, err := xio.OpenChannel(testCtx(t), mustParse(t, "EXEC:"+truePath+",append"), xio.ModeRead, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
}
