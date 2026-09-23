//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
	"github.com/oittaa/socat/internal/xio"
	"github.com/oittaa/socat/internal/xio/execopen"
	"golang.org/x/sys/unix"
)

func TestSignalExitRestoresTerminal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			assertSignalRestoresTerminal(t, sig)
		})
	}
}

func assertSignalRestoresTerminal(t *testing.T, sig syscall.Signal) {
	t.Helper()
	master, slave, err := execopen.OpenPTYPair()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	t.Cleanup(func() {
		_ = master.Close()
		_ = slave.Close()
	})
	fd := int(slave.Fd())
	orig, err := ptyTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if orig.Lflag&unix.ECHO == 0 || orig.Lflag&unix.ICANON == 0 {
		t.Fatalf("pty slave is not cooked: %s", formatPTYTermios(orig))
	}

	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stderr.Close() })

	cmd := exec.Command(os.Args[0], "-test.run=^$") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(os.Environ(),
		"SOCAT_TTY_RESTORE_HELPER=1",
		"SOCAT_TTY_RESTORE_LEFT=-,raw,echo=0",
		"SOCAT_TTY_RESTORE_RIGHT=PIPE",
	)
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-done
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = testutil.Until(ctx, func() (bool, error) {
		select {
		case <-done:
			return false, fmt.Errorf("socat exited before raw mode: %v stderr=%s", waitErr, readTestFile(t, stderr.Name()))
		default:
		}
		cur, err := ptyTermios(fd)
		if err != nil {
			return false, err
		}
		return cur.Lflag&unix.ECHO == 0 && cur.Lflag&unix.ICANON == 0, nil
	})
	if err != nil {
		t.Fatalf("waiting for raw mode: %v stderr=%s", err, readTestFile(t, stderr.Name()))
	}
	// A marker that comes back has been copied by the transfer loop, so both
	// stdio descriptors are open and their restore hooks are registered.
	// Poll first: a PTY master read is not deadline-capable, and an unbounded
	// Read would stick if the byte never arrives.
	if _, err := master.Write([]byte("m")); err != nil {
		t.Fatal(err)
	}
	marker, err := readPolledByte(master)
	if err != nil {
		t.Fatalf("marker: %v stderr=%s", err, readTestFile(t, stderr.Name()))
	}
	if marker != 'm' {
		t.Fatalf("marker=%q stderr=%s", marker, readTestFile(t, stderr.Name()))
	}
	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatal(err)
	}
	exitCtx, exitCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer exitCancel()
	select {
	case <-done:
	case <-exitCtx.Done():
		t.Fatalf("%s did not exit stderr=%s", sig, readTestFile(t, stderr.Name()))
	}
	want := 128 + int(sig)
	var exitErr *exec.ExitError
	if !errors.As(waitErr, &exitErr) || exitErr.ExitCode() != want {
		t.Fatalf("exit=%v want %d stderr=%s", waitErr, want, readTestFile(t, stderr.Name()))
	}
	got, err := ptyTermios(fd)
	if err != nil {
		t.Fatal(err)
	}
	if !ptyTermiosEqual(orig, got) {
		t.Fatalf("%s left the terminal changed\n orig %s\n got  %s\n stderr=%s", sig, formatPTYTermios(orig), formatPTYTermios(got), readTestFile(t, stderr.Name()))
	}
}

func TestExitHooksRunBeforeCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var mu sync.Mutex
	var order []string
	record := func(step string) {
		mu.Lock()
		order = append(order, step)
		mu.Unlock()
	}
	unregister := xio.RegisterExitHook(func() { record("hook") })
	t.Cleanup(unregister)
	sigCh := make(chan os.Signal, 1)
	stop := startSignalHandlers(ctx, func() {
		record("cancel")
		cancel()
	}, nil, 0, nil, sigCh, make(chan os.Signal), nil)
	t.Cleanup(stop)
	sigCh <- syscall.SIGTERM
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancel was not called")
	}
	mu.Lock()
	got := append([]string(nil), order...)
	mu.Unlock()
	if len(got) != 2 || got[0] != "hook" || got[1] != "cancel" {
		t.Fatalf("order=%v want hook then cancel", got)
	}
}

// readPolledByte waits until fd is readable, then reads one byte.
func readPolledByte(f *os.File) (byte, error) {
	fd := int(f.Fd())
	if fd < 0 || fd > 1<<30 {
		return 0, fmt.Errorf("fd %d", fd)
	}
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		n, err := unix.Poll(pfd, 5000)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			return 0, fmt.Errorf("poll timeout")
		}
		if pfd[0].Revents&unix.POLLIN == 0 {
			return 0, fmt.Errorf("poll revents=%#x", pfd[0].Revents)
		}
		var buf [1]byte
		if _, err := unix.Read(fd, buf[:]); err != nil {
			return 0, err
		}
		return buf[0], nil
	}
}

func ptyTermiosEqual(a, b *unix.Termios) bool {
	return a.Iflag == b.Iflag && a.Oflag == b.Oflag && a.Cflag == b.Cflag && a.Lflag == b.Lflag && a.Cc == b.Cc && a.Ispeed == b.Ispeed && a.Ospeed == b.Ospeed
}

func formatPTYTermios(t *unix.Termios) string {
	return fmt.Sprintf("iflag=%#x oflag=%#x cflag=%#x lflag=%#x", t.Iflag, t.Oflag, t.Cflag, t.Lflag)
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
