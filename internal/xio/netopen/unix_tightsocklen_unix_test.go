//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
	"unsafe"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestUnixTightSocklenListenConnect(t *testing.T) {
	for _, extra := range []string{"", ",unix-tightsocklen=1", ",tightsocklen=0"} {
		t.Run("opt"+extra, func(t *testing.T) {
			path := unixSocketTestPath(t, "tight.sock")
			lspec, err := parse.ParseSpec("UNIX-LISTEN:" + path + extra + ",fork")
			if err != nil {
				t.Fatal(err)
			}
			server, err := openUnixListen(context.Background(), lspec, xio.ModeRDWR, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = server.Close() })

			done := make(chan error, 1)
			go func() {
				c, err := server.Listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer func() { _ = c.Close() }()
				buf := make([]byte, 8)
				n, err := c.Read(buf)
				if err != nil {
					done <- err
					return
				}
				_, err = c.Write(buf[:n])
				done <- err
			}()

			cspec, err := parse.ParseSpec("UNIX-CONNECT:" + path + extra)
			if err != nil {
				t.Fatal(err)
			}
			client, err := openUnixConnect(context.Background(), cspec, xio.ModeRDWR, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if _, err := client.Stream.Write([]byte("hi")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8)
			n, err := client.Stream.Read(buf)
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
				t.Fatal("accept/echo timed out")
			}
		})
	}
}

func TestClassicUnixSockaddrLenMatchesThisPlatform(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sunPath := len(unix.RawSockaddrUnix{}.Path)
	if got := classicUnixSockaddrLen(5, sunPath, sizeofUn, false, false); got != sizeofUn {
		t.Fatalf("untight=%d want sizeof=%d", got, sizeofUn)
	}
}

func TestUnixRawSockaddrUsesClassicLen(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sunPath := len(unix.RawSockaddrUnix{}.Path)
	_, n, err := unixRawSockaddr("hello", true)
	if err != nil {
		t.Fatal(err)
	}
	want := classicUnixSockaddrLen(len("hello"), sunPath, sizeofUn, false, true)
	if n != want {
		t.Fatalf("pathname tight=%d want %d (Go net includes a terminator)", n, want)
	}
	_, n, err = unixRawSockaddr("hello", false)
	if err != nil {
		t.Fatal(err)
	}
	if n != sizeofUn {
		t.Fatalf("pathname untight=%d want %d", n, sizeofUn)
	}
	_, n, err = unixRawSockaddr("\x00abc", true)
	if err != nil {
		t.Fatal(err)
	}
	want = classicUnixSockaddrLen(3, sunPath, sizeofUn, true, true)
	if n != want {
		t.Fatalf("abstract tight=%d want %d", n, want)
	}
}

func TestUnixConnectHonorsCanceledContext(t *testing.T) {
	path := unixSocketTestPath(t, "cancel.sock")
	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := listenUnixNetwork(context.Background(), spec, "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	conn, err := dialUnixSocklen(ctx, spec, nil, "unix", path, "")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled", err)
	}
}

func TestUnixConnectTimeoutDoesNotHang(t *testing.T) {
	path, cleanup := listenUnixBacklog(t, 1)
	t.Cleanup(cleanup)
	fillers := occupyUnixListenQueue(t, path)
	t.Cleanup(func() {
		for _, fd := range fillers {
			_ = unix.Close(fd)
		}
	})
	if !unixListenQueueIsFull(t, path, &fillers) {
		t.Skip("kernel did not block extra AF_UNIX connects")
	}

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(cfd) })
	if sockCloexec == 0 {
		unix.CloseOnExec(cfd)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = unixConnectPath(ctx, cfd, path, true)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("connect-timeout hung for %s", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want context.DeadlineExceeded (elapsed %s)", err, elapsed)
	}

	spec, err := parse.ParseSpec("UNIX-CONNECT:" + path + ",connect-timeout=0.15")
	if err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	conn, err := dialUnixSocklen(context.Background(), spec, nil, "unix", path, "")
	elapsed = time.Since(start)
	if conn != nil {
		_ = conn.Close()
	}
	if elapsed > time.Second {
		t.Fatalf("dial connect-timeout hung for %s", elapsed)
	}
	if err == nil {
		t.Fatal("dial with full listen queue succeeded")
	}
}

func TestUnixConnectCancelDuringWait(t *testing.T) {
	path, cleanup := listenUnixBacklog(t, 1)
	t.Cleanup(cleanup)
	fillers := occupyUnixListenQueue(t, path)
	t.Cleanup(func() {
		for _, fd := range fillers {
			_ = unix.Close(fd)
		}
	})
	if !unixListenQueueIsFull(t, path, &fillers) {
		t.Skip("kernel did not block extra AF_UNIX connects")
	}

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(cfd) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err = unixConnectPath(ctx, cfd, path, true)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("canceled connect hung for %s", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled (elapsed %s)", err, elapsed)
	}
}

func TestUnixConnectCancelDuringWaitWithLongDeadline(t *testing.T) {
	path, cleanup := listenUnixBacklog(t, 1)
	t.Cleanup(cleanup)
	fillers := occupyUnixListenQueue(t, path)
	t.Cleanup(func() {
		for _, fd := range fillers {
			_ = unix.Close(fd)
		}
	})
	if !unixListenQueueIsFull(t, path, &fillers) {
		t.Skip("kernel did not block extra AF_UNIX connects")
	}

	cfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(cfd) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err = unixConnectPath(ctx, cfd, path, true)
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("canceled connect with 30s deadline hung for %s", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled (elapsed %s)", err, elapsed)
	}
}

func TestWaitUnixConnectCancelWithLongDeadline(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
	})
	if sockCloexec == 0 {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1024)
	filled := false
	for i := 0; i < 1<<20; i++ {
		_, err := unix.Write(fds[0], buf)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			filled = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !filled {
		t.Skip("could not fill socketpair send buffer")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	err = waitUnixConnect(ctx, fds[0])
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Fatalf("waitUnixConnect with 30s deadline ignored cancel for %s", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want context.Canceled (elapsed %s)", err, elapsed)
	}
}

func listenUnixBacklog(t *testing.T, backlog int) (path string, cleanup func()) {
	t.Helper()
	path = unixSocketTestPath(t, "backlog.sock")
	lfd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(lfd)
	}
	if err := unixBindPath(lfd, path, true); err != nil {
		_ = unix.Close(lfd)
		t.Fatal(err)
	}
	if err := unix.Listen(lfd, backlog); err != nil {
		_ = unix.Close(lfd)
		t.Fatal(err)
	}
	return path, func() { _ = unix.Close(lfd) }
}

func occupyUnixListenQueue(t *testing.T, path string) []int {
	t.Helper()
	var fds []int
	for i := 0; i < 32; i++ {
		fd, errno := unixConnectNonblock(t, path)
		fds = append(fds, fd)
		if unixConnectInProgress(errno) {
			return fds
		}
		if errno != 0 {
			return fds
		}
	}
	return fds
}

func unixListenQueueIsFull(t *testing.T, path string, fillers *[]int) bool {
	t.Helper()
	fd, errno := unixConnectNonblock(t, path)
	*fillers = append(*fillers, fd)
	return unixConnectInProgress(errno)
}

func unixConnectNonblock(t *testing.T, path string) (int, unix.Errno) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sockCloexec == 0 {
		unix.CloseOnExec(fd)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		t.Fatal(err)
	}
	return fd, unixConnectOnce(t, fd, path)
}

func unixConnectOnce(t *testing.T, fd int, path string) unix.Errno {
	t.Helper()
	sa, n, err := unixRawSockaddr(path, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), uintptr(n)) // #nosec G103 -- test uses the same socklen as unixConnectPath
	return errno
}

func unixConnectInProgress(errno unix.Errno) bool {
	return errno == unix.EINPROGRESS || errno == unix.EAGAIN || errno == unix.EWOULDBLOCK
}
