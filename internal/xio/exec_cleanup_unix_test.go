//go:build linux || darwin

package xio

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func execHoldSpec(script, opts string) string {
	spec := `EXEC:"` + script + `"`
	if opts != "" {
		spec += "," + opts
	}
	return spec
}

func systemHoldSpec(pidPath, opts string) string {
	spec := "SYSTEM:echo $$ >" + pidPath + "; exec sleep 30"
	if opts != "" {
		spec += "," + opts
	}
	return spec
}

func writeHoldScript(t *testing.T) (script, pidPath string) {
	t.Helper()
	dir := t.TempDir()
	pidPath = filepath.Join(dir, "pid")
	script = filepath.Join(dir, "hold.sh")
	body := "#!/bin/sh\necho $$ >\"" + pidPath + "\"\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script, pidPath
}

func waitPIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err == nil && pid > 1 {
				return pid
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("child pid file %s not written", path)
	return 0
}

func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func forceKill(pid int) {
	if pid > 1 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func openExecCleanup(t *testing.T, specText string, mode Mode, linger time.Duration) *Opened {
	t.Helper()
	return openExecCleanupCtx(t, context.Background(), specText, mode, linger)
}

func openExecCleanupCtx(t *testing.T, ctx context.Context, specText string, mode Mode, linger time.Duration) *Opened {
	t.Helper()
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	spec, err := parse.ParseSpec(specText)
	if err != nil {
		t.Fatal(err)
	}
	o, err := OpenSpec(ctx, spec, mode, &Global{Log: logx.New(), Linger: linger})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestFinishExecShutNoneKillsLongLivedChild(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec func(script string) string
		mode Mode
	}{
		{name: "exec-socketpair", spec: func(s string) string { return execHoldSpec(s, "shut-none") }, mode: ModeRDWR},
		{name: "exec-pipes", spec: func(s string) string { return execHoldSpec(s, "pipes,shut-none") }, mode: ModeRDWR},
		{name: "exec-write-only", spec: func(s string) string { return execHoldSpec(s, "shut-none") }, mode: ModeWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, pidPath := writeHoldScript(t)
			o := openExecCleanup(t, tc.spec(script), tc.mode, 20*time.Millisecond)
			pid := waitPIDFile(t, pidPath)
			t.Cleanup(func() {
				_ = o.Close()
				forceKill(pid)
			})
			start := time.Now()
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			elapsed := time.Since(start)
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) && processAlive(pid) {
				time.Sleep(5 * time.Millisecond)
			}
			if processAlive(pid) {
				t.Fatal("shut-none left the EXEC child running")
			}
			if elapsed > 2*time.Second {
				t.Fatalf("cleanup took %s; shut-none must not wait for the child", elapsed)
			}
		})
	}

	t.Run("system", func(t *testing.T) {
		pidPath := filepath.Join(t.TempDir(), "pid")
		o := openExecCleanup(t, systemHoldSpec(pidPath, "shut-none"), ModeRDWR, 20*time.Millisecond)
		pid := waitPIDFile(t, pidPath)
		t.Cleanup(func() {
			_ = o.Close()
			forceKill(pid)
		})
		start := time.Now()
		if err := o.Close(); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && processAlive(pid) {
			time.Sleep(5 * time.Millisecond)
		}
		if processAlive(pid) {
			t.Fatal("shut-none left the SYSTEM child running")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("cleanup took %s; shut-none must not wait for the child", elapsed)
		}
	})
}

func TestFinishExecDefaultKillsLongLivedChild(t *testing.T) {
	script, pidPath := writeHoldScript(t)
	o := openExecCleanup(t, execHoldSpec(script, ""), ModeRDWR, 20*time.Millisecond)
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		_ = o.Close()
		forceKill(pid)
	})
	start := time.Now()
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("default cleanup took %s", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(pid) {
		time.Sleep(5 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("default EXEC close left the child running")
	}
}

func TestFinishExecEndCloseDoesNotKillChild(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts string
	}{
		{name: "end-close", opts: "end-close"},
		{name: "end-close-and-shut-none", opts: "end-close,shut-none"},
		{name: "end-close-eq-1", opts: "end-close=1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, pidPath := writeHoldScript(t)
			o := openExecCleanup(t, execHoldSpec(script, tc.opts), ModeRDWR, 20*time.Millisecond)
			pid := waitPIDFile(t, pidPath)
			t.Cleanup(func() {
				_ = o.Close()
				forceKill(pid)
			})
			start := time.Now()
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
				t.Fatalf("end-close cleanup took %s", elapsed)
			}
			time.Sleep(50 * time.Millisecond)
			if !processAlive(pid) {
				t.Fatal("end-close must not kill the EXEC child")
			}
		})
	}
}

func TestFinishExecEndCloseZeroKillsChild(t *testing.T) {
	script, pidPath := writeHoldScript(t)
	o := openExecCleanup(t, execHoldSpec(script, "end-close=0"), ModeRDWR, 20*time.Millisecond)
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		_ = o.Close()
		forceKill(pid)
	})
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(pid) {
		time.Sleep(5 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("end-close=0 should kill like a normal EXEC close")
	}
}

func TestFinishExecEndCloseSurvivesContextCancel(t *testing.T) {
	script, pidPath := writeHoldScript(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := openExecCleanupCtx(t, ctx, execHoldSpec(script, "end-close,shut-none"), ModeRDWR, 20*time.Millisecond)
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		_ = o.Close()
		forceKill(pid)
	})
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			t.Fatal("context cancel after end-close cleanup killed the child")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestFinishExecEndCloseCancelBeforeCloseKillsChild(t *testing.T) {
	script, pidPath := writeHoldScript(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o := openExecCleanupCtx(t, ctx, execHoldSpec(script, "end-close"), ModeRDWR, 20*time.Millisecond)
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		cancel()
		_ = o.Close()
		forceKill(pid)
	})
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(pid) {
		time.Sleep(5 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("cancel during EXEC execution must still kill the child")
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFinishExecNaturalExitKeepsOutput(t *testing.T) {
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	for _, specText := range []string{
		"EXEC:/bin/echo hello-out",
		"EXEC:/bin/echo hello-out,shut-none",
		"SYSTEM:/bin/echo hello-out",
	} {
		t.Run(specText, func(t *testing.T) {
			spec, err := parse.ParseSpec(specText)
			if err != nil {
				t.Fatal(err)
			}
			o, err := OpenSpec(context.Background(), spec, ModeRead, &Global{Log: logx.New(), Linger: 20 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = o.Close() })
			got, err := io.ReadAll(o.Stream)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(got), "hello-out") {
				t.Fatalf("output=%q", got)
			}
			start := time.Now()
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("natural-exit cleanup took %s", elapsed)
			}
		})
	}
}

func TestFinishExecCloseAfterCancel(t *testing.T) {
	script, pidPath := writeHoldScript(t)
	if !FeatureEXEC {
		t.Skip("EXEC not enabled")
	}
	spec, err := parse.ParseSpec(execHoldSpec(script, "shut-none"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	o, err := OpenSpec(ctx, spec, ModeRDWR, &Global{Log: logx.New(), Linger: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		cancel()
		_ = o.Close()
		forceKill(pid)
	})
	cancel()
	start := time.Now()
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("canceled cleanup took %s", elapsed)
	}
}

func TestFinishExecPTYShutNoneKillsChild(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not enabled")
	}
	script, pidPath := writeHoldScript(t)
	o := openExecCleanup(t, execHoldSpec(script, "pty,shut-none"), ModeRDWR, 20*time.Millisecond)
	pid := waitPIDFile(t, pidPath)
	t.Cleanup(func() {
		_ = o.Close()
		forceKill(pid)
	})
	start := time.Now()
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("pty shut-none cleanup took %s", elapsed)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && processAlive(pid) {
		time.Sleep(5 * time.Millisecond)
	}
	if processAlive(pid) {
		t.Fatal("pty shut-none left the EXEC child running")
	}
}
