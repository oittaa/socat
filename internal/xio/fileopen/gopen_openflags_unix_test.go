//go:build unix

package fileopen

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestGOPENSocketRejectsOpenOnlyFlag(t *testing.T) {
	// Darwin's sockaddr_un.sun_path is only 104 bytes. t.TempDir includes the
	// full test name on macOS CI, so use a deliberately short /tmp path.
	dir, err := os.MkdirTemp("/tmp", "socat-gopen-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "listener.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	spec, err := parse.ParseSpec("GOPEN:" + path + ",o-sync")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openGOPEN(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("GOPEN socket silently accepted o-sync")
	}
	if !strings.Contains(err.Error(), "GOPEN resolves to a socket") {
		t.Fatalf("error=%v want explicit socket-dispatch rejection", err)
	}
}
