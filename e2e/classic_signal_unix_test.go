//go:build e2e && unix

package e2e_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/testutil"
)

// TestPIPERemove mimics classic test.sh PIPE_REMOVE (tag-1.8.1.3 test.sh):
// start `socat -u PIPE:<path> FILE:/dev/null` with no writer, wait until the
// FIFO exists, SIGTERM, and require the filesystem entry to be gone.
func TestPIPERemove(t *testing.T) {
	bin := socatBin(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "pipe")
	cmd := exec.Command(bin, "-u", "PIPE:"+path, "FILE:"+os.DevNull)
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)

	waitPath(t, path, proc, stderrPath, 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after SIGTERM stderr=%s", readFile(t, stderrPath))
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("FIFO still exists after SIGTERM (PIPE_REMOVE) stderr=%s", readFile(t, stderrPath))
	}
	if !strings.Contains(readFile(t, stderrPath), "exiting on signal") {
		t.Fatalf("missing signal log, stderr=%s", readFile(t, stderrPath))
	}
}

func TestUNIXSendtoBindRemove(t *testing.T) {
	bin := socatBin(t)
	remote := testutil.UnixSocketPath(t, "remote")
	local := testutil.UnixSocketPath(t, "local")
	hold := filepath.Join(filepath.Dir(local), "hold")
	// Open SENDTO first so bind= creates local, then block in PIPE open(O_RDONLY)
	// the same way PIPE_REMOVE stays alive. FILE:/dev/null as the peer starts
	// the transfer loop; Darwin poll on an unconnected unix datagram then
	// fails with "read/write on closed pipe" before waitPath sees the socket.
	cmd := exec.Command(bin, "-U", "UNIX-SENDTO:"+remote+",bind="+local, "PIPE:"+hold)
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)

	waitPath(t, local, proc, stderrPath, 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after SIGTERM stderr=%s", readFile(t, stderrPath))
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		t.Fatalf("SENDTO bind path still exists after SIGTERM stderr=%s", readFile(t, stderrPath))
	}
}

func TestUNIXConnectBindRemove(t *testing.T) {
	bin := socatBin(t)
	listen := testutil.UnixSocketPath(t, "listen")
	local := testutil.UnixSocketPath(t, "local")
	hold := filepath.Join(filepath.Dir(local), "hold")

	srv := exec.Command(bin, "-u", "UNIX-LISTEN:"+listen+",unlink-early", "FILE:"+os.DevNull)
	srvStderr := attachStderrFile(t, srv)
	srvProc, err := startTestProcess(srv)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srvProc.stop)
	waitPath(t, listen, srvProc, srvStderr, 5*time.Second)

	cmd := exec.Command(bin, "-U", "UNIX-CONNECT:"+listen+",bind="+local, "PIPE:"+hold)
	stderrPath := attachStderrFile(t, cmd)
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(proc.stop)

	waitPath(t, local, proc, stderrPath, 5*time.Second)
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("socat did not exit after SIGTERM stderr=%s", readFile(t, stderrPath))
	}
	if _, err := os.Lstat(local); !os.IsNotExist(err) {
		t.Fatalf("CONNECT bind path still exists after SIGTERM stderr=%s", readFile(t, stderrPath))
	}
}

// TestExitCodeOnSignal mimics classic test.sh EXITCODESIGTERM / EXITCODESIGILL:
// SYSTEM,nofork blocks in Wait(); a caught signal must yield 128+signum and
// log "exiting on signal" (handler ran, not a pre-Notify default dump).
func TestExitCodeOnSignal(t *testing.T) {
	bin := socatBin(t)
	for _, tc := range []struct {
		name   string
		sig    syscall.Signal
		logged string
	}{
		{name: "TERM", sig: syscall.SIGTERM, logged: "exiting on signal 15"},
		{name: "ILL", sig: syscall.SIGILL, logged: "exiting on signal 4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sig == syscall.SIGILL && runtime.GOOS == "darwin" {
				t.Skip("Go runtime on Darwin treats SIGILL as a crash dump; Notify cannot intercept it")
			}
			dir := t.TempDir()
			ready := filepath.Join(dir, "ready")
			script := filepath.Join(dir, "child.sh")
			body := "#!/bin/sh\necho $$ >\"" + ready + "\"\nexec sleep 30\n"
			if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(bin, "PIPE", "SYSTEM:exec "+script+",nofork")
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
			select {
			case <-proc.done:
			case <-time.After(5 * time.Second):
				t.Fatalf("socat did not exit after %s stderr=%s", tc.sig, readFile(t, stderrPath))
			}
			got := exitStatus(proc)
			want := 128 + int(tc.sig)
			if got != want {
				t.Fatalf("exit=%d want %d stderr=%s", got, want, readFile(t, stderrPath))
			}
			if !strings.Contains(readFile(t, stderrPath), tc.logged) {
				t.Fatalf("missing %q in stderr=%s", tc.logged, readFile(t, stderrPath))
			}
		})
	}
}

func attachStderrFile(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(path) // #nosec G304 -- test temp stderr capture
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	cmd.Stderr = f
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func waitPath(t *testing.T, path string, proc *testProcess, stderrPath string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err, exited := proc.status(); exited {
			t.Fatalf("socat exited while waiting for %s: %v stderr=%s", path, err, readFile(t, stderrPath))
		}
		if _, err := os.Lstat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s stderr=%s", path, readFile(t, stderrPath))
}

func exitStatus(p *testProcess) int {
	err, _ := p.status()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func killPIDFile(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 1 {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
