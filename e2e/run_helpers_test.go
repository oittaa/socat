//go:build e2e

package e2e_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

func e2eHelperCmd(ctx context.Context, helper string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "SOCAT_E2E_HELPER="+helper)
	return cmd
}

func e2eHelperHoldCmd(t *testing.T, ctx context.Context) (*exec.Cmd, func()) {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := e2eHelperCmd(ctx, "hold-stdio")
	cmd.Stdin = pr
	return cmd, func() {
		_ = pr.Close()
		_ = pw.Close()
	}
}

func TestRunTestCmdSuccess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "print-and-exit"))
	if err != nil {
		t.Fatalf("success path: %v out=%s", err, out)
	}
	if string(out) != "helper-ok" {
		t.Fatalf("out=%q", out)
	}
}

func TestRunTestCmdStartupFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	missing := filepath.Join(t.TempDir(), "missing-binary")
	out, err := runTestCmd(ctx, exec.CommandContext(ctx, missing))
	if err == nil {
		t.Fatalf("expected startup failure, out=%s", out)
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("startup failure looked like a timeout: %v", err)
	}
}

func TestRunTestCmdCancelBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out, err := runTestCmd(ctx, e2eHelperCmd(ctx, "hold-stdio"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v out=%s want canceled", err, out)
	}
	if strings.Contains(string(out), "helper") {
		t.Fatalf("cancelled command produced output: %s", out)
	}
}

func TestRunTestCmdCancelAfterStartupCleansUp(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd, releaseStdin := e2eHelperHoldCmd(t, ctx)
	t.Cleanup(releaseStdin)
	var buf lockedBuffer
	pr, pw, copyDone, err := testutil.StartOutputPipe(cmd, &buf)
	if err != nil {
		t.Fatal(err)
	}
	p, err := startTestProcess(cmd)
	_ = pw.Close()
	if err != nil {
		_ = pr.Close()
		t.Fatal(err)
	}
	if p.cmd.Process == nil {
		t.Fatal("expected a started process")
	}
	if _, exited := p.status(); exited {
		t.Fatalf("hold-stdio exited before cancel: %v", func() error { e, _ := p.status(); return e }())
	}
	cancel()
	waitErr := testutil.Wait(ctx, p.done, p.stop)
	_ = testutil.DrainPipe(copyDone, pr, testutil.OutputDrainBound)
	if !errors.Is(waitErr, context.Canceled) {
		t.Fatalf("err=%v want canceled", waitErr)
	}
	if _, exited := p.status(); !exited {
		t.Fatal("cancel left the child running")
	}
}

func TestStartTestProcessPreservesStderrFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	path := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(path) // #nosec G304 -- test temp stderr capture
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	cmd := e2eHelperCmd(ctx, "exit-error")
	cmd.Stderr = f
	p, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Stderr != f {
		t.Fatal("startTestProcess replaced file-backed stderr")
	}
	if waitErr := testutil.Wait(ctx, p.done, p.stop); waitErr != nil {
		t.Fatal(waitErr)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "helper-fail" {
		t.Fatalf("stderr file=%q", got)
	}
}
