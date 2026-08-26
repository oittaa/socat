//go:build unix

package netopen

import (
	"net"
	"sync"
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

func TestRawListenerAddrConcurrentWithFileLn(t *testing.T) {
	// TestSCTP4ListenConnectUseCase hits this: RunOpened calls SetDeadline /
	// Accept (fileLn mutates ln and fd) while the test reads Addr() for the port.
	l := listenRawTCP4(t)
	t.Cleanup(func() { _ = l.Close() })
	before := tcpPort(t, l.Addr())

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 200 {
			_ = l.Addr()
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := l.fileLn(); err != nil {
			t.Error(err)
		}
		_ = l.SetDeadline(time.Now().Add(time.Second))
	}()
	wg.Wait()
	if got := tcpPort(t, l.Addr()); got != before {
		t.Fatalf("port after concurrent fileLn=%d want %d", got, before)
	}
}

func TestRawListenerFileListenerFailureKeepsFD(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	l := &rawListener{fd: fd, domain: unix.AF_INET}
	t.Cleanup(func() { _ = l.Close() })
	_, err = l.fileLn()
	if err == nil {
		t.Fatal("FileListener succeeded on a datagram socket")
	}
	if l.fd != fd {
		t.Fatalf("fd after FileListener failure=%d want %d", l.fd, fd)
	}
	if _, err := unix.FcntlInt(uintptr(l.fd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("FileListener failure left closed fd %d: %v", l.fd, err)
	}

	newfd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(newfd) })
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(newfd), unix.F_GETFD, 0); err != nil {
		t.Fatalf("Close closed recycled descriptor old=%d new=%d: %v", fd, newfd, err)
	}
}
