//go:build unix

package cli

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
)

// TestExitCodeOnSignal mimics classic test.sh EXITCODESIGTERM / EXITCODESIGILL:
// a caught termination signal must exit 128+signum, not the kernel default
// dump/abort status.
func TestExitCodeOnSignal(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGILL} {
		t.Run(sig.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			sigCh := make(chan os.Signal, 1)
			exitCode := make(chan int, 1)
			stop := startSignalHandlers(ctx, cancel, logx.New(), defaultSignalLogMask(), func(code int) {
				exitCode <- code
			}, sigCh, make(chan os.Signal), nil)
			t.Cleanup(stop)

			sigCh <- sig
			select {
			case code := <-exitCode:
				want := 128 + int(sig)
				if code != want {
					t.Fatalf("exit code=%d want %d", code, want)
				}
			case <-time.After(time.Second):
				t.Fatal("signal exit callback was not called")
			}
		})
	}
}

func TestSignalHandlersPassThroughKeepsRunning(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 2)
	exitCode := make(chan int, 1)
	passed := make(chan os.Signal, 1)
	stop := startSignalHandlers(ctx, cancel, logx.New(), defaultSignalLogMask(), func(code int) {
		exitCode <- code
	}, sigCh, make(chan os.Signal), func(sig os.Signal) bool {
		if sig == syscall.SIGHUP {
			passed <- sig
			return true
		}
		return false
	})
	t.Cleanup(stop)

	sigCh <- syscall.SIGHUP
	select {
	case <-passed:
	case <-time.After(time.Second):
		t.Fatal("SIGHUP was not forwarded")
	}
	select {
	case code := <-exitCode:
		t.Fatalf("pass-through SIGHUP exited %d", code)
	case <-ctx.Done():
		t.Fatal("pass-through SIGHUP cancelled the context")
	case <-time.After(50 * time.Millisecond):
	}

	sigCh <- syscall.SIGTERM
	select {
	case code := <-exitCode:
		if code != 128+int(syscall.SIGTERM) {
			t.Fatalf("exit code=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("SIGTERM did not exit after pass-through")
	}
}
