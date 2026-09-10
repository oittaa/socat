//go:build e2e && (linux || darwin)

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEXECParentSignalPassThrough(t *testing.T) {
	// dash defers traps until a foreground child (sleep) exits. `read` is a
	// builtin, so the trap runs while the shell is the EXEC child. Loop so an
	// interrupted read does not exit and tear down the socketpair.
	cases := []struct {
		opt  string
		sig  syscall.Signal
		trap string
	}{
		{"sighup", syscall.SIGHUP, "HUP"},
		{"sigint", syscall.SIGINT, "INT"},
		{"sigquit", syscall.SIGQUIT, "QUIT"},
	}
	for _, tc := range cases {
		t.Run(tc.opt, func(t *testing.T) {
			bin := socatBin(t)
			dir := t.TempDir()
			ready := filepath.Join(dir, "ready")
			got := filepath.Join(dir, "got")
			script := filepath.Join(dir, "child.sh")
			body := "#!/bin/sh\n" +
				"trap 'echo got >\"" + got + "\"' " + tc.trap + "\n" +
				"echo $$ >\"" + ready + "\"\n" +
				"while true; do read dummy; done\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			hold := filepath.Join(dir, "hold")
			cmd := exec.Command(bin, "EXEC:"+script+","+tc.opt, "PIPE:"+hold)
			stderrPath := attachStderrFile(t, cmd)
			proc, err := startTestProcess(cmd)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				proc.stop()
				killPIDFile(ready)
			})

			waitPath(t, ready, proc, stderrPath, 5*time.Second)
			if err := cmd.Process.Signal(tc.sig); err != nil {
				t.Fatal(err)
			}
			waitPath(t, got, proc, stderrPath, 5*time.Second)
			if err, exited := proc.status(); exited {
				t.Fatalf("socat exited after pass-through %s: %v stderr=%s", tc.opt, err, readFile(t, stderrPath))
			}
			if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case <-proc.done:
			case <-time.After(5 * time.Second):
				t.Fatalf("socat did not exit after SIGTERM stderr=%s", readFile(t, stderrPath))
			}
		})
	}
}

func TestEXECParentSignalAbsentStillExits(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	script := filepath.Join(dir, "child.sh")
	body := "#!/bin/sh\necho $$ >\"" + ready + "\"\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	hold := filepath.Join(dir, "hold")
	cmd := exec.Command(bin, "EXEC:"+script, "PIPE:"+hold)
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		proc.stop()
		killPIDFile(ready)
	})

	waitPath(t, ready, proc, stderrPath, 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after SIGHUP stderr=%s", readFile(t, stderrPath))
	}
	got := exitStatus(proc)
	want := 128 + int(syscall.SIGHUP)
	if got != want {
		t.Fatalf("exit=%d want %d stderr=%s", got, want, readFile(t, stderrPath))
	}
	if !strings.Contains(readFile(t, stderrPath), "exiting on signal 1") {
		t.Fatalf("missing exiting on signal 1 in stderr=%s", readFile(t, stderrPath))
	}
}

func TestEXECNoForkSIGHUPExitStatus(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	script := filepath.Join(dir, "child.sh")
	body := "#!/bin/sh\necho $$ >\"" + ready + "\"\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "PIPE", "EXEC:"+script+",nofork,sighup")
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		proc.stop()
		killPIDFile(ready)
	})

	waitPath(t, ready, proc, stderrPath, 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after nofork SIGHUP stderr=%s", readFile(t, stderrPath))
	}
	got := exitStatus(proc)
	want := 128 + int(syscall.SIGHUP)
	if got != want {
		t.Fatalf("exit=%d want %d stderr=%s", got, want, readFile(t, stderrPath))
	}
	if strings.Contains(readFile(t, stderrPath), "exiting on signal 1") {
		t.Fatalf("nofork,sighup must forward SIGHUP, not self-exit stderr=%s", readFile(t, stderrPath))
	}
}

func TestEXECFiveSIGHUPOccurrencesRejected(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "EXEC:true,sighup,sighup,sighup,sighup,sighup", "PIPE").CombinedOutput()
	if err == nil {
		t.Fatal("five sighup flags on one EXEC must fail")
	}
	if !strings.Contains(string(out), "too many sub processes registered for signal 1") {
		t.Fatalf("output=%q want too many sub processes", out)
	}
}

func startEXECListenFork(t *testing.T, bin, execSpec string) (port int, proc *testProcess, stderrPath string) {
	t.Helper()
	var path string
	port, proc = startTCPTestServer(t, func(port int) *exec.Cmd {
		cmd := exec.Command(bin,
			fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			execSpec)
		path = attachStderrFile(t, cmd)
		return cmd
	})
	return port, proc, path
}

func TestEXECListenForkFiveSessionsSIGHUP(t *testing.T) {
	const n = 5
	bin := socatBin(t)
	dir := t.TempDir()
	pidsPath := filepath.Join(dir, "pids")
	readyPath := filepath.Join(dir, "ready")
	gotPath := filepath.Join(dir, "got")
	script := filepath.Join(dir, "child.sh")
	body := "#!/bin/sh\n" +
		"trap 'echo got >>\"" + gotPath + "\"' HUP\n" +
		"echo $$ >>\"" + pidsPath + "\"\n" +
		"read dummy && echo ready >>\"" + readyPath + "\"\n" +
		"while true; do read dummy || sleep 0.05; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	port, proc, stderrPath := startEXECListenFork(t, bin, "EXEC:"+script+",sighup")
	t.Cleanup(func() { killPIDFile(pidsPath) })

	conns := make([]net.Conn, 0, n)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v stderr=%s", i, err, readFile(t, stderrPath))
		}
		conns = append(conns, c)
	}
	waitFileLines(t, pidsPath, n, proc, stderrPath, 5*time.Second)
	for i, c := range conns {
		if _, err := io.WriteString(c, "ready\n"); err != nil {
			t.Fatalf("write readiness token %d: %v stderr=%s", i, err, readFile(t, stderrPath))
		}
	}
	// A child can write its PID immediately after cmd.Start, before the parent
	// registers that child for SIGHUP forwarding. Reading a token through the
	// relay proves openEXEC has returned and signal registration is complete.
	waitFileLines(t, readyPath, n, proc, stderrPath, 5*time.Second)
	if strings.Contains(readFile(t, stderrPath), "too many sub processes") {
		t.Fatalf("five LISTEN,fork sessions must each have four slots stderr=%s", readFile(t, stderrPath))
	}
	if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	waitFileLines(t, gotPath, n, proc, stderrPath, 5*time.Second)
	if err, exited := proc.status(); exited {
		t.Fatalf("listener exited during pass-through SIGHUP: %v stderr=%s", err, readFile(t, stderrPath))
	}
}

func TestEXECListenForkListenerSIGHUPScope(t *testing.T) {
	bin := socatBin(t)

	t.Run("before", func(t *testing.T) {
		dir := t.TempDir()
		script := filepath.Join(dir, "child.sh")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		_, proc, stderrPath := startEXECListenFork(t, bin, "EXEC:"+script+",sighup")
		if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case <-proc.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("listener did not exit on SIGHUP before sessions stderr=%s", readFile(t, stderrPath))
		}
		got := exitStatus(proc)
		want := 128 + int(syscall.SIGHUP)
		if got != want {
			t.Fatalf("exit=%d want %d stderr=%s", got, want, readFile(t, stderrPath))
		}
		if !strings.Contains(readFile(t, stderrPath), "exiting on signal 1") {
			t.Fatalf("missing exiting on signal 1 in stderr=%s", readFile(t, stderrPath))
		}
	})

	t.Run("during", func(t *testing.T) {
		dir := t.TempDir()
		ready := filepath.Join(dir, "ready")
		registered := filepath.Join(dir, "registered")
		got := filepath.Join(dir, "got")
		script := filepath.Join(dir, "child.sh")
		body := "#!/bin/sh\n" +
			"trap 'echo got >\"" + got + "\"' HUP\n" +
			"echo $$ >\"" + ready + "\"\n" +
			"read dummy && echo registered >\"" + registered + "\"\n" +
			"while true; do read dummy || sleep 0.05; done\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		port, proc, stderrPath := startEXECListenFork(t, bin, "EXEC:"+script+",sighup")
		t.Cleanup(func() { killPIDFile(ready) })
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		waitPath(t, ready, proc, stderrPath, 5*time.Second)
		if _, err := io.WriteString(c, "ready\n"); err != nil {
			t.Fatalf("write readiness token: %v stderr=%s", err, readFile(t, stderrPath))
		}
		// A child can write its PID immediately after cmd.Start, before the parent
		// registers that child for SIGHUP forwarding. Reading a token through the
		// relay proves openEXEC has returned and signal registration is complete.
		waitPath(t, registered, proc, stderrPath, 5*time.Second)
		if err := proc.cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitPath(t, got, proc, stderrPath, 5*time.Second)
		if err, exited := proc.status(); exited {
			t.Fatalf("listener exited during session SIGHUP: %v stderr=%s", err, readFile(t, stderrPath))
		}
	})

	t.Run("after", func(t *testing.T) {
		dir := t.TempDir()
		ready := filepath.Join(dir, "ready")
		done := filepath.Join(dir, "done")
		script := filepath.Join(dir, "child.sh")
		body := "#!/bin/sh\n" +
			"echo $$ >\"" + ready + "\"\n" +
			"cat\n" +
			"echo done >\"" + done + "\"\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		port, proc, stderrPath := startEXECListenFork(t, bin, "EXEC:"+script+",sighup")
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		waitPath(t, ready, proc, stderrPath, 5*time.Second)
		_ = c.Close()
		waitPath(t, done, proc, stderrPath, 5*time.Second)
		// `done` is written before the shell exits. SIGHUP is forwarded until
		// Wait reaps the child and unregisters it; retry until the listener
		// exits on the unregistered path.
		sighupUntilExit(t, proc, stderrPath, 5*time.Second)
		got := exitStatus(proc)
		want := 128 + int(syscall.SIGHUP)
		if got != want {
			t.Fatalf("exit=%d want %d stderr=%s", got, want, readFile(t, stderrPath))
		}
		if !strings.Contains(readFile(t, stderrPath), "exiting on signal 1") {
			t.Fatalf("missing exiting on signal 1 in stderr=%s", readFile(t, stderrPath))
		}
	})
}

func sighupUntilExit(t *testing.T, proc *testProcess, stderrPath string, timeout time.Duration) {
	t.Helper()
	if err := waitSIGHUPExit(proc.done, timeout, func() error {
		return proc.cmd.Process.Signal(syscall.SIGHUP)
	}, nil); err != nil {
		t.Fatalf("%v stderr=%s", err, readFile(t, stderrPath))
	}
}

func waitSIGHUPExit(done <-chan struct{}, timeout time.Duration, signal func() error, onWait func()) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ticker := time.NewTicker(listenProbeInterval)
	defer ticker.Stop()

	waitDone := func() error {
		if onWait != nil {
			onWait()
		}
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			select {
			case <-done:
				return nil
			default:
				return fmt.Errorf("listener did not exit on SIGHUP after sessions")
			}
		}
	}

	send := func() (exited bool, err error) {
		if err := signal(); err != nil {
			if errors.Is(err, os.ErrProcessDone) {
				return true, waitDone()
			}
			return false, fmt.Errorf("SIGHUP: %w", err)
		}
		return false, nil
	}

	if exited, err := send(); err != nil {
		return err
	} else if exited {
		return nil
	}
	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			select {
			case <-done:
				return nil
			default:
				return fmt.Errorf("listener did not exit on SIGHUP after sessions")
			}
		case <-ticker.C:
			exited, err := send()
			if err != nil {
				return err
			}
			if exited {
				return nil
			}
		}
	}
}

func TestWaitSIGHUPExitDelayedDone(t *testing.T) {
	done := make(chan struct{})
	waiting := make(chan struct{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- waitSIGHUPExit(done, 5*time.Second, func() error {
			return os.ErrProcessDone
		}, func() { close(waiting) })
	}()

	select {
	case <-waiting:
	case err := <-errCh:
		t.Fatalf("returned before done was published: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ErrProcessDone wait")
	}
	select {
	case err := <-errCh:
		t.Fatalf("returned before done was published: %v", err)
	default:
	}
	close(done)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("after done published: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not return after done was published")
	}
}

func waitFileLines(t *testing.T, path string, want int, proc *testProcess, stderrPath string, timeout time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	err := waitUntil(ctx, proc, func() (bool, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		n := 0
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line != "" {
				n++
			}
		}
		return n >= want, nil
	})
	if err != nil {
		contents := ""
		if b, readErr := os.ReadFile(path); readErr == nil {
			contents = string(b)
		}
		t.Fatalf("waiting for %d lines in %s: %v got %q stderr=%s", want, path, err, contents, readFile(t, stderrPath))
	}
}
