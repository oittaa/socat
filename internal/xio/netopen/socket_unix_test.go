//go:build linux || darwin

package netopen

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func listenRawTCP4(t *testing.T) *rawListener {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	sa := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if err := unix.Bind(fd, sa); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	return &rawListener{fd: fd, domain: unix.AF_INET}
}

func tcpPort(t *testing.T, addr net.Addr) int {
	t.Helper()
	ta, ok := addr.(*net.TCPAddr)
	if !ok || ta.Port <= 0 {
		t.Fatalf("addr %T %v", addr, addr)
	}
	return ta.Port
}

func TestRawListenerAddrBeforeFileLn(t *testing.T) {
	l := listenRawTCP4(t)
	t.Cleanup(func() { _ = l.Close() })
	port := tcpPort(t, l.Addr())
	if _, err := l.fileLn(); err != nil {
		t.Fatal(err)
	}
	if got := tcpPort(t, l.Addr()); got != port {
		t.Fatalf("port after fileLn=%d want %d", got, port)
	}
}

func TestRawListenerAcceptTimeoutWithoutFileListener(t *testing.T) {
	l := listenRawTCP4(t)
	t.Cleanup(func() { _ = l.Close() })
	if err := l.forceRaw(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := l.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := l.Accept()
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept err=%v want os.ErrDeadlineExceeded", err)
	}
	if elapsed < 150*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("raw accept-timeout elapsed %s", elapsed)
	}
}

func (l *rawListener) forceRaw() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enterRawLocked()
}
