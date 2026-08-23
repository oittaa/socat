//go:build linux

package xio

import (
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyFDOptionsNoatime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "noatime")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec, err := parse.ParseSpec("FD:3,o-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NOATIME == 0 {
		t.Fatalf("flags=%#x do not contain O_NOATIME", flags)
	}
}

func TestApplyFDOptionsPipeSize(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	spec, err := parse.ParseSpec("FD:3,pipesz=4096")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(r, spec); err != nil {
		t.Fatal(err)
	}
	size, err := unix.FcntlInt(r.Fd(), unix.F_GETPIPE_SZ, 0)
	if err != nil {
		t.Fatal(err)
	}
	if size != 4096 {
		t.Fatalf("pipe size=%d want 4096", size)
	}
}
