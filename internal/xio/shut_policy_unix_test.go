//go:build linux || darwin

package xio

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
)

func TestIsNotSockMatchesENOTSOCK(t *testing.T) {
	if !isNotSock(syscall.ENOTSOCK) {
		t.Fatal("syscall.ENOTSOCK must satisfy isNotSock")
	}
}

func TestIsNotSockDoesNotMatchENOTCONN(t *testing.T) {
	if isNotSock(syscall.ENOTCONN) {
		t.Fatal("ENOTCONN must not satisfy isNotSock")
	}
	if isNotSock(fmt.Errorf("shut-down: %w", syscall.ENOTCONN)) {
		t.Fatal("wrapped ENOTCONN must not satisfy isNotSock")
	}
}

func TestFileStreamHalfCloseClosesPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	stream := FileStream(w)
	if err := stream.ShutdownWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	n, err := r.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("pipe half-close: n=%d err=%v", n, err)
	}
}

func TestShutDownOnUnconnectedSocketReportsNotConnected(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = syscall.Close(fd) }()
	stream := wrapShutDown(t, fdSyscallStream{Stream: &recordingStream{}, fd: fd})
	err = stream.ShutdownWrite()
	if err == nil || isNotSock(err) {
		t.Fatalf("err=%v want ENOTCONN, not not-a-socket", err)
	}
	if !errors.Is(err, syscall.ENOTCONN) {
		t.Fatalf("err=%v want ENOTCONN", err)
	}
}
