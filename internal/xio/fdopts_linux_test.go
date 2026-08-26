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

func TestApplyFDOptionsFSNoatime(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fs-noatime")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS); err != nil {
		t.Skipf("FS_IOC_GETFLAGS: %v", err)
	}

	spec, err := parse.ParseSpec("FD:3,fs-noatime")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, spec); err != nil {
		t.Skipf("fs-noatime: %v", err)
	}
	flags, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Fatal(err)
	}
	if flags&fsNoatimeFL == 0 {
		t.Fatalf("inode flags=%#x do not contain FS_NOATIME_FL", flags)
	}
	fcntlFlags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fcntlFlags&unix.O_NOATIME != 0 {
		t.Fatalf("fs-noatime must not set O_NOATIME (fcntl flags=%#x)", fcntlFlags)
	}

	clear, err := parse.ParseSpec("FD:3,fs-noatime=0")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, clear); err != nil {
		t.Fatal(err)
	}
	flags, err = unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		t.Fatal(err)
	}
	if flags&fsNoatimeFL != 0 {
		t.Fatalf("fs-noatime=0 left FS_NOATIME_FL set (flags=%#x)", flags)
	}
}

func TestApplyFDOptionsDoesNotSetODirect(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "odirect")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec, err := parse.ParseSpec("FD:3,o-direct")
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
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("ApplyFDOptions must not set O_DIRECT (flags=%#x)", flags)
	}
}
