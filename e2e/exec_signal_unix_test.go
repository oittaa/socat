//go:build e2e && unix

package e2e_test

import (
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
