//go:build linux || darwin

package fileopen

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func dupPipeFD(t *testing.T) (nfd int, w *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	nfd, err = unix.Dup(int(r.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	return nfd, w
}

func openInheritedFD(t *testing.T, spec string, nfd int) *xio.Opened {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		_ = unix.Close(nfd)
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		_ = unix.Close(nfd)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestFDSetsCLOEXECByDefaultUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	if _, err := unix.FcntlInt(uintptr(nfd), unix.F_SETFD, 0); err != nil {
		_ = unix.Close(nfd)
		t.Fatal(err)
	}
	_ = openInheritedFD(t, "FD:"+strconv.Itoa(nfd), nfd)

	flags, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("FD did not set FD_CLOEXEC")
	}
}

func TestFDCloexecZeroClearsInheritedCLOEXECUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	_ = openInheritedFD(t, "FD:"+strconv.Itoa(nfd)+",cloexec=0", nfd)

	flags, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC != 0 {
		t.Fatal("cloexec=0 left FD_CLOEXEC set")
	}
}

func TestFDCloseLeavesInheritedDescriptorOpenUnix(t *testing.T) {
	nfd, w := dupPipeFD(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd))
	if err != nil {
		_ = unix.Close(nfd)
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		_ = unix.Close(nfd)
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, err := unix.Read(nfd, buf)
	if err != nil {
		t.Fatalf("inherited fd was closed: %v", err)
	}
	if n != 2 || string(buf) != "ok" {
		t.Fatalf("read %q want ok", buf[:n])
	}
}

func TestFDOpensBase0NumberUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	o := openInheritedFD(t, "FD:0x"+strconv.FormatInt(int64(nfd), 16), nfd)
	if o.Label != "FD:"+strconv.Itoa(nfd) {
		t.Fatalf("label=%q", o.Label)
	}
}
