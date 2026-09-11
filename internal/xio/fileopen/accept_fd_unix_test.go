//go:build linux || darwin

package fileopen

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func dupOwnedFD(t *testing.T, fd int) int {
	t.Helper()
	nfd, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(nfd)
	return nfd
}

func tcp4ListenOwned(t *testing.T) (fd int, addr string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpln, ok := ln.(*net.TCPListener)
	if !ok {
		_ = ln.Close()
		t.Fatalf("listener %T", ln)
	}
	f, err := tcpln.File()
	if err != nil {
		_ = ln.Close()
		t.Fatal(err)
	}
	addr = ln.Addr().String()
	_ = ln.Close()
	fd = dupOwnedFD(t, int(f.Fd()))
	_ = f.Close()
	return fd, addr
}

func parseAcceptSpec(t *testing.T, spec string, fd int) parse.Spec {
	t.Helper()
	s, err := parse.ParseSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	s.Params = []string{strconv.Itoa(fd)}
	return s
}

const acceptFDDup2HelperEnv = "SOCAT_TEST_ACCEPT_FD_DUP2_HELPER"

// TestAcceptFDCloseDoesNotDoubleClose asserts that Opened.Close does not
// close a descriptor number that was reused after the original listen fd
// was handed to FileListener. Dup2 onto that recycled number races with
// Go coverage meta files in the parent test process, so the assertion
// runs in an isolated helper subprocess without GOCOVERDIR.
func TestAcceptFDCloseDoesNotDoubleClose(t *testing.T) {
	if os.Getenv(acceptFDDup2HelperEnv) == "1" {
		acceptFDCloseDoesNotDoubleClose(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAcceptFDCloseDoesNotDoubleClose$", "-test.v", "-test.count=1") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(withoutCoverEnv(os.Environ()), acceptFDDup2HelperEnv+"=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ACCEPT-FD dup2 helper failed: %v\n%s", err, output)
	}
}

func withoutCoverEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if strings.HasPrefix(e, "GOCOVERDIR=") {
			continue
		}
		out = append(out, e)
	}
	return out
}

func acceptFDCloseDoesNotDoubleClose(t *testing.T) {
	t.Helper()
	lowFD, _ := tcp4ListenOwned(t)
	// Move the listener away from the low descriptor range used by concurrent
	// runtime and test activity. Checking whether a low numeric fd is valid
	// after close is racy: an unrelated open can immediately reuse it.
	fd, err := unix.FcntlInt(uintptr(lowFD), unix.F_DUPFD, 128)
	if err != nil {
		_ = unix.Close(lowFD)
		t.Fatal(err)
	}
	unix.CloseOnExec(fd)
	_ = unix.Close(lowFD)
	t.Cleanup(func() { _ = unix.Close(fd) })
	// fork returns before accept so we can inspect the listen fd without an
	// accepted conn reusing the original number.
	o, err := openAcceptFD(context.Background(), mustAddr(t, parseAcceptSpec(t, "ACCEPT-FD:0,fork", fd)), xio.ModeRDWR, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		t.Fatal("original listen fd still open after FileListener wrap")
	}
	newfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if newfd != fd {
		if err := unix.Dup2(newfd, fd); err != nil {
			_ = unix.Close(newfd)
			t.Fatal(err)
		}
		_ = unix.Close(newfd)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("Opened.Close closed replacement descriptor %d: %v", fd, err)
	}
}

func TestAcceptConnProbeUnsupported(t *testing.T) {
	if !acceptConnProbeUnsupported(unix.ENOPROTOOPT) {
		t.Fatal("ENOPROTOOPT must be skipped (Darwin ExtraFiles listeners)")
	}
	if acceptConnProbeUnsupported(unix.EBADF) {
		t.Fatal("EBADF must still fail the probe")
	}
}

func TestAcceptFDRejectsListenSetsockopt(t *testing.T) {
	fd, _ := tcp4ListenOwned(t)
	s, err := parse.ParseSpec(fmt.Sprintf("ACCEPT-FD:0,setsockopt-listen=%d:%d:1", unix.SOL_SOCKET, unix.SO_KEEPALIVE))
	if err != nil {
		t.Fatal(err)
	}
	s.Params = []string{strconv.Itoa(fd)}
	_, err = openAcceptFD(context.Background(), mustAddr(t, s), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "not supported at this lifecycle phase") {
		t.Fatalf("err=%v want lifecycle rejection", err)
	}
	_ = unix.Close(fd)
}

func TestAcceptFDWrongParamCount(t *testing.T) {
	_, err := openAcceptFD(context.Background(), mustAddr(t, parse.Spec{Type: "ACCEPT-FD"}), xio.ModeRDWR, nil)
	if err == nil || !strings.Contains(err.Error(), "wrong number of parameters") {
		t.Fatalf("err=%v", err)
	}
}
