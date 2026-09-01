//go:build linux || darwin

package fileopen

import (
	"context"
	"errors"
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
	t.Cleanup(func() { _ = unix.Close(nfd) })
	return nfd, w
}

func openInheritedFD(t *testing.T, spec string, nfd int) *xio.Opened {
	t.Helper()
	parsed, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	return o
}

func TestFDSetsCLOEXECByDefaultUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	if _, err := unix.FcntlInt(uintptr(nfd), unix.F_SETFD, 0); err != nil {
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
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
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

func TestFDEndCloseClosesInheritedDescriptorUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",end-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err = unix.Read(nfd, buf)
	if err == nil {
		t.Fatal("end-close left inherited fd open")
	}
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("read error=%v want EBADF", err)
	}
}

func TestFDCloseAliasClosesInheritedDescriptorUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, err = unix.Read(nfd, buf)
	if err == nil {
		t.Fatal("close left inherited fd open")
	}
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("read error=%v want EBADF", err)
	}
}

func TestFDOpensBase0NumberUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	o := openInheritedFD(t, "FD:0x"+strconv.FormatInt(int64(nfd), 16), nfd)
	if o.Label != "FD:"+strconv.Itoa(nfd) {
		t.Fatalf("label=%q", o.Label)
	}
}

func TestFDRepeatedOpenReusesCallerDescriptorUnix(t *testing.T) {
	nfd, w := dupPipeFD(t)
	before := inheritedSessionLive.Load()
	spec, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd))
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 32
	for i := 0; i < rounds; i++ {
		o, err := openFD(context.Background(), spec, xio.ModeRead, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := inheritedSessionLive.Load(); got != before {
		t.Fatalf("live session wrappers=%d want %d after %d open/close cycles", got, before, rounds)
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

func TestFDFailedOpenDoesNotKeepSessionWrapperUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	before := inheritedSessionLive.Load()
	spec, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",ftruncate=0")
	if err != nil {
		t.Fatal(err)
	}
	const rounds = 32
	for i := 0; i < rounds; i++ {
		_, err := openFD(context.Background(), spec, xio.ModeRead, nil)
		if err == nil {
			t.Fatal("ftruncate on a pipe succeeded")
		}
	}
	if got := inheritedSessionLive.Load(); got != before {
		t.Fatalf("live session wrappers=%d want %d after failed opens", got, before)
	}
	if _, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("failed open closed inherited fd: %v", err)
	}
}

func TestFDForkChildEndCloseLeavesInheritedDescriptorOpenUnix(t *testing.T) {
	nfd, w := dupPipeFD(t)
	parsed, err := parse.ParseSpec("FD:" + strconv.Itoa(nfd) + ",end-close")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openFD(context.Background(), parsed, xio.ModeRead, &xio.Global{ForkChild: true})
	if err != nil {
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
		t.Fatalf("fork-child end-close closed inherited fd: %v", err)
	}
	if n != 2 || string(buf) != "ok" {
		t.Fatalf("read %q want ok", buf[:n])
	}
}

func TestDuplicateInheritedFDSetsCLOEXECUnix(t *testing.T) {
	nfd, _ := dupPipeFD(t)
	if _, err := unix.FcntlInt(uintptr(nfd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	dup, err := duplicateInheritedFD(nfd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(dup) })
	flags, err := unix.FcntlInt(uintptr(dup), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("F_DUPFD_CLOEXEC left the duplicate inheritable")
	}
	orig, err := unix.FcntlInt(uintptr(nfd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if orig&unix.FD_CLOEXEC != 0 {
		t.Fatal("duplication set FD_CLOEXEC on the original")
	}
}
