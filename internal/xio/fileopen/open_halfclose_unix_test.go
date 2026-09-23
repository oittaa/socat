//go:build linux || darwin

package fileopen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/xio"
)

func TestOpenFIFOStaysOpenAfterHalfClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	peer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	opened := openUse(t, "OPEN:"+path, xio.ModeRDWR)
	if err := opened.Stream().ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	var buf [1]byte
	if n, err := opened.Stream().Read(buf[:]); n != 1 || err != nil || buf[0] != 'x' {
		t.Fatalf("n=%d buf=%q err=%v", n, buf[:n], err)
	}
}
