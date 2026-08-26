//go:build unix

package fileopen

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestFDSetsockoptOnPipeFailsUnix(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	spec, err := parse.ParseSpec(fmt.Sprintf("FD:0,setsockopt-int=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	spec.Params = []string{strconv.Itoa(int(r.Fd()))}
	_, err = openFD(context.Background(), spec, xio.ModeRead, nil)
	if err == nil {
		t.Fatal("FD pipe with setsockopt must fail, not ignore")
	}
}

func TestFDSetsockoptOnSocketUnix(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec(fmt.Sprintf("FD:0,setsockopt-int=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		t.Fatal(err)
	}
	spec.Params = []string{strconv.Itoa(fds[0])}
	o, err := openFD(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = o.Close()
		_ = syscall.Close(fds[1])
	})
	got, err := unix.GetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	if err != nil {
		t.Fatal(err)
	}
	if got == 0 {
		t.Fatalf("SO_KEEPALIVE=%d want enabled", got)
	}
}

func TestSocketpairSetsockoptOncePerFDUnix(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf("SOCKETPAIR,setsockopt-int=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	var n int
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.Opt == unix.SO_KEEPALIVE {
			n++
		}
	})
	defer restore()
	o, err := openSocketpair(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if n != 2 {
		t.Fatalf("SO_KEEPALIVE setsockopt count=%d want 2 (one per socketpair fd)", n)
	}
}
