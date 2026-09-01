//go:build linux || darwin

package netopen

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
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
	if !l.raw {
		t.Fatal("FileListener failure must switch to raw accept")
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

func TestRawListenerCloseUnblocksAccept(t *testing.T) {
	l := listenRawTCP4(t)
	if err := l.forceRaw(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept succeeded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("raw Accept was not unblocked by Close")
	}
}

func TestRawListenerAcceptUsesConnFromFD(t *testing.T) {
	l := listenRawTCP4(t)
	t.Cleanup(func() { _ = l.Close() })
	if err := l.forceRaw(); err != nil {
		t.Fatal(err)
	}
	port := tcpPort(t, l.Addr())
	done := make(chan error, 1)
	go func() {
		c, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, 8)
		n, err := c.Read(buf)
		if err != nil && err != io.EOF {
			done <- err
			return
		}
		_, err = c.Write(buf[:n])
		done <- err
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q", buf[:n])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dial/echo timed out")
	}
}

func TestRawFileConnCloseWrite(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "raw-closewrite")
	if f == nil {
		t.Fatal("NewFile")
	}
	c := &rawFileConn{f: f, local: &net.UnixAddr{Net: "unix"}, remote: &net.UnixAddr{Net: "unix"}}
	t.Cleanup(func() { _ = c.Close() })
	peer := os.NewFile(uintptr(fds[1]), "raw-closewrite-peer")
	t.Cleanup(func() { _ = peer.Close() })
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	n, err := peer.Read(buf)
	if n != 0 || err != io.EOF {
		t.Fatalf("peer Read n=%d err=%v want EOF", n, err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("Write after CloseWrite succeeded")
	}
}

func TestConnFromFDUnknownFamilyDeadlines(t *testing.T) {
	fd := unsupportedFileConnFD(t)
	c, err := connFromFD(fd, "generic-socket")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	raw, ok := c.(*rawFileConn)
	if !ok {
		t.Fatalf("conn type %T want *rawFileConn", c)
	}
	if !fdIsNonblock(t, raw) {
		t.Fatal("rawFileConn fd is blocking; os.File is not in the poller")
	}
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read with expired deadline succeeded")
	}
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("Read returned %v; fd was not registered with the poller", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) && !os.IsTimeout(err) {
		t.Fatalf("Read err=%v want deadline exceeded", err)
	}
}

func (l *rawListener) forceRaw() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.enterRawLocked()
}

func unsupportedFileConnFD(t *testing.T) int {
	t.Helper()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Skipf("no AF_VSOCK: %v", err)
	}
	f := os.NewFile(uintptr(fd), "probe-fileconn")
	if f == nil {
		_ = unix.Close(fd)
		t.Fatal("NewFile")
	}
	c, err := net.FileConn(f)
	logx.CloseQuiet(f)
	if err == nil {
		_ = c.Close()
		t.Skip("net.FileConn accepts AF_VSOCK")
	}
	fd, err = unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	return fd
}

func fdIsNonblock(t *testing.T, sc syscall.Conn) bool {
	t.Helper()
	raw, err := sc.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var ferr error
	if err := raw.Control(func(fd uintptr) {
		flags, ferr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}); err != nil {
		t.Fatal(err)
	}
	if ferr != nil {
		t.Fatal(ferr)
	}
	return flags&unix.O_NONBLOCK != 0
}
