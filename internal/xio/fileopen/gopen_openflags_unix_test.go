//go:build unix

package fileopen

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestGOPENSocketRejectsOpenOnlyFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "listener.sock")
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
