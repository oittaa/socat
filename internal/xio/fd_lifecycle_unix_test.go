//go:build linux || darwin

package xio_test

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestFD3AppendFtruncatePerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fd3")
	orig, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orig.Close() })
	if _, err := orig.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}

	nfd, err := unix.Dup(int(orig.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(nfd) })

	ctx, g := testCtx(t), testGlobal()
	o, err := xio.OpenChannel(ctx, mustParse(t, fmt.Sprintf("FD:%d,append,ftruncate=6,perm=0600", nfd)), xio.ModeWrite, g)
	if err != nil {
		if os.IsPermission(err) {
			t.Skipf("FD lifecycle not permitted: %v", err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	flags, err := unix.FcntlInt(orig.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_APPEND == 0 {
		t.Fatalf("FD append flags=%#x missing O_APPEND", flags)
	}

	st, err := orig.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 6 {
		t.Fatalf("size=%d want 6 after ftruncate", st.Size())
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("perm=%#o want 0600", st.Mode().Perm())
	}

	if _, err := orig.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Stream.Write([]byte("XY")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdefXY" {
		t.Fatalf("append write got %q want abcdefXY", got)
	}
}

func TestFDAppendZeroClearsInheritedOAPPEND(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fd-append0")
	orig, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = orig.Close() })
	nfd, err := unix.Dup(int(orig.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(nfd) })

	o, err := xio.OpenChannel(testCtx(t), mustParse(t, fmt.Sprintf("FD:%d,append=0", nfd)), xio.ModeWrite, testGlobal())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })

	flags, err := unix.FcntlInt(orig.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_APPEND != 0 {
		t.Fatal("append=0 left O_APPEND set on inherited fd")
	}
}

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
