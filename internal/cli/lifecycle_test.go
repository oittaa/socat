package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
)

func TestSignalHandlersDeliverExitAndStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	usr1 := make(chan os.Signal, 1)
	exitCode := make(chan int, 1)
	stop := startSignalHandlers(ctx, cancel, logx.New(), 0, func(code int) {
		exitCode <- code
	}, sigCh, usr1)

	sigCh <- syscall.SIGTERM
	select {
	case code := <-exitCode:
		if code != 128+int(syscall.SIGTERM) {
			t.Fatalf("exit code=%d", code)
		}
	case <-time.After(time.Second):
		t.Fatal("signal exit callback was not called")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal did not cancel the context")
	}
	stop()
	stop() // cleanup is intentionally idempotent
}

func TestSignalLogMaskControlsExitMessage(t *testing.T) {
	for _, tc := range []struct {
		name string
		mask uint64
		want bool
	}{
		{name: "masked out", mask: 0, want: false},
		{name: "included", mask: uint64(1) << uint(syscall.SIGTERM), want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var output bytes.Buffer
			logger := logx.New()
			logger.SetOutput(&output)
			sigCh := make(chan os.Signal, 1)
			exited := make(chan struct{}, 1)
			stop := startSignalHandlers(ctx, cancel, logger, tc.mask, func(int) { exited <- struct{}{} }, sigCh, make(chan os.Signal))
			sigCh <- syscall.SIGTERM
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("signal handler did not run")
			}
			stop()
			got := strings.Contains(output.String(), "exiting on signal")
			if got != tc.want {
				t.Fatalf("logged=%v output=%q", got, output.String())
			}
		})
	}
}

func TestSignalHandlersStopWithoutSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := startSignalHandlers(ctx, cancel, logx.New(), defaultSignalLogMask(), nil, make(chan os.Signal), make(chan os.Signal))
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("signal handlers did not stop")
	}
}
