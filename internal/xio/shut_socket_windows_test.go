//go:build windows

package xio

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsNotSockMatchesWSAENOTSOCK(t *testing.T) {
	if !isNotSock(windows.WSAENOTSOCK) {
		t.Fatal("windows.WSAENOTSOCK must satisfy isNotSock")
	}
	if !isNotSock(fmt.Errorf("shut-down: %w", windows.WSAENOTSOCK)) {
		t.Fatal("wrapped WSAENOTSOCK must satisfy isNotSock")
	}
}

func TestIsNotSockDoesNotMatchWSAENOTCONN(t *testing.T) {
	if isNotSock(windows.WSAENOTCONN) {
		t.Fatal("WSAENOTCONN must not satisfy isNotSock")
	}
	if isNotSock(fmt.Errorf("shut-down: %w", windows.WSAENOTCONN)) {
		t.Fatal("wrapped WSAENOTCONN must not satisfy isNotSock")
	}
}

func TestGetsockoptSOTypeOnPipeReportsWSAENOTSOCK(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	var optErr error
	sc, err := w.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Control(func(fd uintptr) {
		_, optErr = windows.GetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, soType)
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(optErr, windows.WSAENOTSOCK) {
		t.Fatalf("SO_TYPE on pipe: err=%v want WSAENOTSOCK", optErr)
	}
}

func TestShutdownWriteOnPipeReportsWSAENOTSOCK(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	var shutErr error
	sc, err := w.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.Control(func(fd uintptr) {
		shutErr = ShutdownWrite(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(shutErr, windows.WSAENOTSOCK) {
		t.Fatalf("err=%v want WSAENOTSOCK", shutErr)
	}
}

func TestShutdownWriteOnUnconnectedSocketReportsWSAENOTCONN(t *testing.T) {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.Closesocket(s) }()
	typ, err := windows.GetsockoptInt(s, windows.SOL_SOCKET, soType)
	if err != nil {
		t.Fatalf("SO_TYPE on unconnected socket: %v", err)
	}
	if typ != windows.SOCK_STREAM {
		t.Fatalf("SO_TYPE=%d want SOCK_STREAM", typ)
	}
	err = ShutdownWrite(int(s))
	if isNotSock(err) {
		t.Fatalf("unconnected socket classified as not-a-socket: %v", err)
	}
	if !errors.Is(err, windows.WSAENOTCONN) {
		t.Fatalf("err=%v want WSAENOTCONN", err)
	}
}

func TestShutDownOnUnconnectedSocketReportsNotConnected(t *testing.T) {
	s, err := windows.Socket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.Closesocket(s) }()
	stream := wrapShutDown(t, fdSyscallStream{Stream: &recordingStream{}, fd: int(s)})
	err = stream.ShutdownWrite()
	if err == nil || isNotSock(err) {
		t.Fatalf("err=%v want WSAENOTCONN, not not-a-socket", err)
	}
	if !errors.Is(err, windows.WSAENOTCONN) {
		t.Fatalf("err=%v want WSAENOTCONN", err)
	}
}
