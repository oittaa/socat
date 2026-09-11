//go:build linux || darwin

package xio

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/addrconfig"
	"github.com/oittaa/socat/internal/parse"
	"golang.org/x/sys/unix"
)

func TestApplyFDOptionsIoctlIntpFIONREADPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if _, err := w.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	spec := mustSpec(t, "FD:3,ioctl-intp="+strconv.FormatUint(uint64(fionreadRequest()), 10)+":0")
	if err := ApplyFDOptions(r, spec); err != nil {
		t.Fatalf("ioctl-intp FIONREAD: %v", err)
	}
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil || n != 4 || string(buf) != "abcd" {
		t.Fatalf("pipe payload after FIONREAD: n=%d buf=%q err=%v", n, buf, err)
	}
}

func TestApplyFDOptionsIoctlIntpFIONREADSocket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("socketpair: %v", err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "ioctl-a"), os.NewFile(uintptr(fds[1]), "ioctl-b")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	if _, err := b.Write([]byte("xy")); err != nil {
		t.Fatal(err)
	}
	spec := mustSpec(t, "FD:3,ioctl-intp="+strconv.FormatUint(uint64(fionreadRequest()), 10)+":0")
	if err := ApplyFDOptions(a, spec); err != nil {
		t.Fatalf("ioctl-intp FIONREAD socket: %v", err)
	}
}

func TestApplyFDOptionsIoctlVoidTIOCEXCLPty(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	spec := mustSpec(t, "FD:3,ioctl-void="+strconv.FormatUint(uint64(unix.TIOCEXCL), 10))
	if err := ApplyFDOptions(slave, spec); err != nil {
		t.Fatalf("ioctl-void TIOCEXCL: %v", err)
	}
}

func TestApplyFDOptionsIoctlBinTIOCGWINSZPty(t *testing.T) {
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	if _, err := unix.IoctlGetWinsize(int(slave.Fd()), unix.TIOCGWINSZ); err != nil {
		t.Skipf("not a tty: %v", err)
	}
	// TIOCGWINSZ writes struct winsize (8 bytes). ioctl-bin is the matching
	// generic form; skip rather than pass an int pointer of the wrong size.
	spec := mustSpec(t, "FD:3,ioctl-bin="+strconv.FormatUint(uint64(unix.TIOCGWINSZ), 10)+":x0000000000000000")
	if err := ApplyFDOptions(slave, spec); err != nil {
		t.Fatalf("ioctl-bin TIOCGWINSZ: %v", err)
	}
}

func TestApplyFDOptionsIoctlIntApplyErrorWithoutSuccess(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "ioctl-int")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	spec := mustSpec(t, "FD:3,ioctl-int=0:0")
	err = ApplyFDOptions(f, spec)
	if err == nil {
		t.Fatal("ioctl-int=0:0 unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "ioctl-int") {
		t.Fatalf("error=%v want ioctl-int", err)
	}
}

func TestApplyFDOptionsIoctlAlias(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if parse.CanonicalOptionName(mustSpec(t, "FD:3,ioctl=1").Options[0].Name) != "ioctl-void" {
		t.Fatal("ioctl must fold to ioctl-void")
	}
	spec := mustSpec(t, "FD:3,ioctl="+strconv.FormatUint(uint64(unix.TIOCEXCL), 10))
	err = ApplyFDOptions(r, spec)
	if err == nil {
		t.Fatal("ioctl-void TIOCEXCL on a pipe unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "ioctl") {
		t.Fatalf("error=%v want ioctl", err)
	}
}

func TestApplyFDOptionsIoctlIntpAliasPath(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if parse.CanonicalOptionName("ioctl") != "ioctl-void" {
		t.Fatal("ioctl must fold to ioctl-void")
	}
	spec := mustSpec(t, "FD:3,ioctl-intp="+strconv.FormatUint(uint64(fionreadRequest()), 10)+":0")
	if err := ApplyFDOptions(r, spec); err != nil {
		t.Fatal(err)
	}
}

func TestApplyConfiguredFDOptionsIoctlIntpFIONREADPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	if _, err := w.Write([]byte("abcd")); err != nil {
		t.Fatal(err)
	}
	spec := mustSpec(t, "FD:3,ioctl-intp="+strconv.FormatUint(uint64(fionreadRequest()), 10)+":0")
	config, err := addrconfig.Decode(spec, addrconfig.Facts{Type: "FD"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyConfiguredFDOptions(r, config.File, FDSkip{}); err != nil {
		t.Fatalf("prepared ioctl-intp FIONREAD: %v", err)
	}
	buf := make([]byte, 4)
	n, err := r.Read(buf)
	if err != nil || n != 4 || string(buf) != "abcd" {
		t.Fatalf("pipe payload after prepared FIONREAD: n=%d buf=%q err=%v", n, buf, err)
	}
}
