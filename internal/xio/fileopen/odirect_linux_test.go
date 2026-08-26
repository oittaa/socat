//go:build linux

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenFlagsSetsODirect(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT == 0 {
		t.Fatalf("flags=%#x do not contain O_DIRECT", flags)
	}

	off, err := parse.ParseSpec("OPEN:x,o-direct=0")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(off, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT != 0 {
		t.Fatalf("o-direct=0 set O_DIRECT (flags=%#x)", flags)
	}

	alias, err := parse.ParseSpec("OPEN:x,direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(alias, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECT == 0 {
		t.Fatalf("direct alias flags=%#x do not contain O_DIRECT", flags)
	}
}

func TestOpenODirectAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "odirect.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-direct")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		t.Skipf("O_DIRECT open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.O_DIRECT == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_DIRECT", got)
	}
}

func TestCreateAppliesODirect(t *testing.T) {
	path := filepath.Join(t.TempDir(), "create.bin")
	spec, err := parse.ParseSpec("CREATE:" + path + ",o-direct")
	if err != nil {
		t.Fatal(err)
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	flags, err = applyODirectFlag(spec, flags)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		t.Skipf("CREATE O_DIRECT open: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	got, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got&unix.O_DIRECT == 0 {
		t.Fatalf("CREATE F_GETFL=%#x does not contain O_DIRECT", got)
	}

	o, err := openCREATE(context.Background(), spec, xio.ModeWrite, nil)
	if err != nil {
		t.Skipf("openCREATE o-direct: %v", err)
	}
	t.Cleanup(func() { _ = o.Close() })
}
