//go:build linux

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestNamedPipeUnlinkLateRemovesNameOnFDOptionFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("PIPE:" + path + ",unlink-late,f-setpipe-sz=4096")
	if err != nil {
		t.Fatal(err)
	}
	o, err := xio.OpenSpec(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("f-setpipe-sz on a regular file succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("PIPE unlink-late left the name after setup failure: %v", err)
	}
}
