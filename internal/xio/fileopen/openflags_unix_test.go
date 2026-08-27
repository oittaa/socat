//go:build unix

package fileopen

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenFlagsSetsOSYNCAndOASYNC(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-sync,async")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_SYNC == 0 {
		t.Fatalf("flags=%#x do not contain O_SYNC", flags)
	}
	if flags&unix.O_ASYNC == 0 {
		t.Fatalf("flags=%#x do not contain O_ASYNC", flags)
	}

	off, err := parse.ParseSpec("OPEN:x,o-sync=0,async=0")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(off, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_SYNC != 0 || flags&unix.O_ASYNC != 0 {
		t.Fatalf("disabled flags=%#x still set O_SYNC or O_ASYNC", flags)
	}
}

func TestOpenFlagsNocttyNofollowDirectory(t *testing.T) {
	spec, err := parse.ParseSpec("OPEN:x,o-noctty,o-nofollow")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NOCTTY == 0 {
		t.Fatalf("flags=%#x do not contain O_NOCTTY", flags)
	}
	if flags&unix.O_NOFOLLOW == 0 {
		t.Fatalf("flags=%#x do not contain O_NOFOLLOW", flags)
	}

	dir, err := parse.ParseSpec("OPEN:x,o-directory")
	if err != nil {
		t.Fatal(err)
	}
	flags, err = OpenFlags(dir, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_DIRECTORY == 0 {
		t.Fatalf("flags=%#x do not contain O_DIRECTORY", flags)
	}
}

func TestOpenOSyncAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sync.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-sync")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
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
	if got&unix.O_SYNC == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_SYNC", got)
	}
}

func TestOpenAsyncAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "async.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",async")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
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
	if got&unix.O_ASYNC == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_ASYNC after open(2)", got)
	}
}

func TestOpenODsyncAppearsInFcntl(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dsync.bin")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",dsync")
	if err != nil {
		t.Fatal(err)
	}
	flags, err := OpenFlags(spec, xio.ModeRead)
	if err != nil {
		t.Fatal(err)
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
	if got&unix.O_DSYNC == 0 {
		t.Fatalf("F_GETFL=%#x does not contain O_DSYNC", got)
	}
}

func TestOpenNofollowRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + link + ",o-nofollow")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("o-nofollow on a symlink succeeded")
	}
	if !errors.Is(err, unix.ELOOP) && !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("o-nofollow: %v want ELOOP", err)
	}
}

func TestOpenDirectoryRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("OPEN:" + path + ",o-directory")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openOPEN(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("o-directory on a regular file succeeded")
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, syscall.ENOTDIR) {
		t.Fatalf("o-directory: %v want ENOTDIR", err)
	}
}

func TestUnnamedPIPERejectsOSync(t *testing.T) {
	spec, err := parse.ParseSpec("PIPE,o-sync")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openPIPE(context.Background(), spec, xio.ModeRDWR, nil)
	if err == nil {
		_ = o.Close()
		t.Fatal("unnamed PIPE,o-sync was accepted")
	}
	if !strings.Contains(err.Error(), "unnamed PIPE") {
		t.Fatalf("unnamed PIPE o-sync: %v", err)
	}
}
