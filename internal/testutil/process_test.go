package testutil

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestWaitSuccess(t *testing.T) {
	done := make(chan struct{})
	close(done)
	err := Wait(context.Background(), done, func() {
		t.Fatal("stop called on success")
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWaitCancelBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	var stopped atomic.Bool
	err := Wait(ctx, done, func() {
		if stopped.CompareAndSwap(false, true) {
			close(done)
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v want canceled", err)
	}
	if !stopped.Load() {
		t.Fatal("stop/cleanup was not called")
	}
}

func TestWaitCancelAfterStartup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan struct{})
		finished := make(chan error, 1)
		go func() { finished <- Wait(ctx, done, func() { close(done) }) }()
		synctest.Wait()
		cancel()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatalf("Wait=%v", err)
		}
		select {
		case <-done:
		default:
			t.Fatal("child was not stopped")
		}
	})
}

func TestWaitCompletedChildWinsOverCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	close(done)
	err := Wait(ctx, done, func() {
		t.Fatal("stop called after child already exited")
	})
	if err != nil {
		t.Fatalf("completed child should win over cancel: %v", err)
	}
}

func TestStartOutputPipeCapturesAndPreservesStderr(t *testing.T) {
	cmd := exec.Command("unused")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	var buf bytes.Buffer
	pr, pw, copyDone, err := StartOutputPipe(cmd, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Stderr != &stderr {
		t.Fatal("StartOutputPipe replaced an existing stderr")
	}
	if _, err := io.WriteString(pw, "hello"); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := DrainPipe(copyDone, pr, time.Second); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello" {
		t.Fatalf("buf=%q", buf.String())
	}
}

func TestStartOutputPipeDefaultsStderrToPipe(t *testing.T) {
	cmd := exec.Command("unused")
	var buf bytes.Buffer
	pr, pw, copyDone, err := StartOutputPipe(cmd, &buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = pw.Close()
		_ = DrainPipe(copyDone, pr, time.Second)
	})
	if cmd.Stdout != pw || cmd.Stderr != pw {
		t.Fatal("expected stdout and stderr to share the pipe file")
	}
}

func TestDrainPipeUnblocksHungCopy(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pw.Close() })
	copyDone := make(chan error, 1)
	go func() {
		_, copyErr := io.Copy(io.Discard, pr)
		copyDone <- copyErr
	}()
	finished := make(chan error, 1)
	go func() {
		finished <- DrainPipe(copyDone, pr, 30*time.Millisecond)
	}()
	err = <-finished
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err=%v want deadline exceeded", err)
	}
}
