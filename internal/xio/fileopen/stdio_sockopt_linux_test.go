//go:build linux

package fileopen

import (
	"context"
	"os"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestOpenSTDIOInheritedSocketAppliesSOPriorityLinux(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	stdinFile := os.NewFile(uintptr(fds[0]), "stdin-sock")
	if stdinFile == nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatal("NewFile failed")
	}
	old := os.Stdin
	os.Stdin = stdinFile
	t.Cleanup(func() {
		os.Stdin = old
		_ = stdinFile.Close()
		_ = unix.Close(fds[1])
	})
	spec, err := parse.ParseSpec("STDIO,so-priority=4")
	if err != nil {
		t.Fatal(err)
	}
	o, err := openSTDIO(context.Background(), spec, xio.ModeRead, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	got, err := unix.GetsockoptInt(int(os.Stdin.Fd()), unix.SOL_SOCKET, unix.SO_PRIORITY)
	if err != nil {
		t.Fatal(err)
	}
	if got != 4 {
		t.Fatalf("inherited STDIO SO_PRIORITY=%d want 4", got)
	}
}
