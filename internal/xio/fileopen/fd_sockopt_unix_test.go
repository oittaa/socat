//go:build linux || darwin

package fileopen

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	if !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
		t.Fatalf("error=%v want explicit lifecycle rejection", err)
	}
}

func TestFDSetsockoptPastSocketOnSocketUnix(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec(fmt.Sprintf("FD:0,setsockopt-socket=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
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

func TestFDRejectsPrebindAndConnectedSetsockoptUnix(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	for _, option := range []string{"setsockopt-listen", "setsockopt-int"} {
		t.Run(option, func(t *testing.T) {
			spec, err := parse.ParseSpec(fmt.Sprintf("FD:0,%s=%d:%d:1", option, unix.SOL_SOCKET, unix.SO_KEEPALIVE))
			if err != nil {
				t.Fatal(err)
			}
			spec.Params = []string{strconv.Itoa(fds[0])}
			if _, err := openFD(context.Background(), spec, xio.ModeRDWR, nil); err == nil {
				t.Fatalf("FD accepted %s", option)
			} else if !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
				t.Fatalf("error=%v want explicit lifecycle rejection", err)
			}
		})
	}
}

func TestSocketpairSetsockoptAllPhasesOnceInOrderPerFDUnix(t *testing.T) {
	spec, err := parse.ParseSpec(fmt.Sprintf(
		"SOCKETPAIR,setsockopt-int=%d:%d:1,sockopt-sock=%d:%d:0,setsockopt-listen=%d:%d:1",
		unix.SOL_SOCKET, unix.SO_KEEPALIVE,
		unix.SOL_SOCKET, unix.SO_KEEPALIVE,
		unix.SOL_SOCKET, unix.SO_KEEPALIVE,
	))
	if err != nil {
		t.Fatal(err)
	}
	valuesByFD := make(map[int][]int)
	restore := xio.SetSockoptTestHook(func(c xio.SockoptCall) {
		if c.AsInt && c.Opt == unix.SO_KEEPALIVE {
			valuesByFD[c.FD] = append(valuesByFD[c.FD], c.IntValue)
		}
	})
	defer restore()
	o, err := openSocketpair(context.Background(), spec, xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = o.Close() })
	if len(valuesByFD) != 2 {
		t.Fatalf("setsockopt fds=%v want two socketpair descriptors", valuesByFD)
	}
	for fd, values := range valuesByFD {
		if len(values) != 3 || values[0] != 1 || values[1] != 0 || values[2] != 1 {
			t.Fatalf("fd %d values=%v want [1 0 1] in command-line order", fd, values)
		}
	}
}
