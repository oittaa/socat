//go:build linux || darwin

package xio

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/testutil"
)

func execHoldSpec(script, opts string) string {
	spec := `EXEC:"` + script + `"`
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var pid int
	err := testutil.Until(ctx, func() (bool, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || n <= 1 {
			return false, nil
		}
		pid = n
		return true, nil
	})
	if err != nil {
		t.Fatalf("child pid file %s not written", path)
	}
	return pid
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
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := testutil.Until(ctx, func() (bool, error) {
		return !processAlive(pid), nil
	}); err != nil {
		t.Fatal("end-close=0 should kill like a normal EXEC close")
	}
}

func TestExecChildCancelRelease(t *testing.T) {
	run := func(canceled bool) (killed bool, err error) {
		ctx, cancel := context.WithCancel(context.Background())
		if canceled {
			cancel()
		} else {
			defer cancel()
		}
		c := &execChild{cmd: exec.Command("true")}
		c.cmd.Cancel = func() error {
			killed = true
			return nil
		}
		c.armCancel(ctx)
		c.releaseCancel()
		return killed, c.cmd.Cancel()
	}
	killed, err := run(false)
	if killed || err != os.ErrProcessDone {
		t.Fatalf("end-close: killed=%v err=%v", killed, err)
	}
	killed, err = run(true)
	if !killed || err != nil {
		t.Fatalf("in-flight: killed=%v err=%v", killed, err)
	}
}
