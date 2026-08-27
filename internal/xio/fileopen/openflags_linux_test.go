//go:build linux

package fileopen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenORsyncAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rsync.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-rsync")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_RSYNC == 0 {
		t.Fatalf("flags=%#x do not contain O_RSYNC", flags)
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.O_RSYNC == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_RSYNC", got)
	}
}

func TestOpenLargefileAccepted(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-largefile,largefile")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFlags(spec, xio.ModeRead); err != nil {
		t.Fatal(err)
	}
}
