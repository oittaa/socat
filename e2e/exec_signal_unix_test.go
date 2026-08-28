//go:build e2e && unix

package e2e_test

import (
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
	bin := socatBin(t)
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready")
	got := filepath.Join(dir, "got")
	script := filepath.Join(dir, "child.sh")
	// dash defers traps until a foreground child (sleep) exits. `read` is a
	// builtin, so SIGHUP runs the trap while the shell is the EXEC child.
	// Loop so an interrupted read does not exit and tear down the socketpair.
	body := "#!/bin/sh\n" +
		"trap 'echo got >\"" + got + "\"' HUP INT QUIT\n" +
		"echo $$ >\"" + ready + "\"\n" +
		"while true; do read dummy; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	hold := filepath.Join(dir, "hold")
	cmd := exec.Command(bin, "EXEC:"+script+",sighup,sigint,sigquit", "PIPE:"+hold)
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
	waitPath(t, got, proc, stderrPath, 5*time.Second)
	if err, exited := proc.status(); exited {
		t.Fatalf("socat exited after pass-through SIGHUP: %v stderr=%s", err, readFile(t, stderrPath))
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after SIGTERM stderr=%s", readFile(t, stderrPath))
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

func TestEXECListenForkFiveSessionsSIGHUP(t *testing.T) {
	const n = 5
	bin := socatBin(t)
	port := freePort(t)
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
	cmd := exec.Command(bin,
		fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
		"EXEC:"+script+",sighup")
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)
	waitTCPListen(t, port, 5*time.Second)

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
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
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
		port := freePort(t)
		dir := t.TempDir()
		script := filepath.Join(dir, "child.sh")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin,
			fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			"EXEC:"+script+",sighup")
		stderrPath := attachStderrFile(t, cmd)
		proc, err := startTestProcess(cmd)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(proc.stop)
		waitTCPListen(t, port, 5*time.Second)
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
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
		port := freePort(t)
		dir := t.TempDir()
		ready := filepath.Join(dir, "ready")
		got := filepath.Join(dir, "got")
		script := filepath.Join(dir, "child.sh")
		body := "#!/bin/sh\n" +
			"trap 'echo got >\"" + got + "\"' HUP\n" +
			"echo $$ >\"" + ready + "\"\n" +
			"while true; do read dummy || sleep 0.05; done\n"
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin,
			fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			"EXEC:"+script+",sighup")
		stderrPath := attachStderrFile(t, cmd)
		proc, err := startTestProcess(cmd)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(proc.stop)
		waitTCPListen(t, port, 5*time.Second)
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		waitPath(t, ready, proc, stderrPath, 5*time.Second)
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		waitPath(t, got, proc, stderrPath, 5*time.Second)
		if err, exited := proc.status(); exited {
			t.Fatalf("listener exited during session SIGHUP: %v stderr=%s", err, readFile(t, stderrPath))
		}
	})

	t.Run("after", func(t *testing.T) {
		port := freePort(t)
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
		cmd := exec.Command(bin,
			fmt.Sprintf("TCP4-LISTEN:%d,reuseaddr,bind=127.0.0.1,fork", port),
			"EXEC:"+script+",sighup")
		stderrPath := attachStderrFile(t, cmd)
		proc, err := startTestProcess(cmd)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(proc.stop)
		waitTCPListen(t, port, 5*time.Second)
		c, err := net.DialTimeout("tcp4", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		waitPath(t, ready, proc, stderrPath, 5*time.Second)
		_ = c.Close()
		waitPath(t, done, proc, stderrPath, 5*time.Second)
		// Wait for Wait() to unregister the pid after cat exits.
		time.Sleep(50 * time.Millisecond)
		if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
		select {
		case <-proc.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("listener did not exit on SIGHUP after sessions stderr=%s", readFile(t, stderrPath))
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
}

func waitFileLines(t *testing.T, path string, want int, proc *testProcess, stderrPath string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, exited := proc.status(); exited {
			t.Fatalf("socat exited while waiting for %d lines in %s: %v stderr=%s", want, path, err, readFile(t, stderrPath))
		}
		b, err := os.ReadFile(path)
		if err == nil {
			n := 0
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if line != "" {
					n++
				}
			}
			if n >= want {
				return
			}
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	contents := ""
	if b, err := os.ReadFile(path); err == nil {
		contents = string(b)
	}
	t.Fatalf("timed out waiting for %d lines in %s got %q stderr=%s", want, path, contents, readFile(t, stderrPath))
}
