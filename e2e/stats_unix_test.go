//go:build e2e && unix

package e2e_test

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSIGUSR1Statistics(t *testing.T) {
	bin := socatBin(t)
	stdinR, stdinW := io.Pipe()
	cmd := exec.Command(bin, "STDIO", "PIPE")
	cmd.Stdin = stdinR
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	proc, err := startTestProcess(cmd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdinW.Close()
		proc.stop()
	})

	// Wait until the transfer loop has echoed bytes. SIGUSR1 before the
	// handler is installed kills the process (default action); SIGUSR1
	// before Transfer registers a tracker logs "not yet started" with no
	// STATISTICS lines. A 50ms sleep was too short for coverage-instrumented
	// linux-amd64 binaries.
	const payload = "ping\n"
	if _, err := io.WriteString(stdinW, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readWhileRunning(t, stdout, len(payload), proc, 5*time.Second)
	if err != nil {
		t.Fatalf("waiting for transfer echo: %v stderr=%s", err, proc.stderr.String())
	}
	if string(got) != payload {
		t.Fatalf("echo %q want %q", got, payload)
	}

	if err := signalUSR1(cmd.Process); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err, exited := proc.status(); exited {
			t.Fatalf("socat exited after SIGUSR1: %v stderr=%s", err, proc.stderr.String())
		}
		if strings.Count(proc.stderr.String(), "STATISTICS") >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no STATISTICS after SIGUSR1:\n%s", proc.stderr.String())
}

func readWhileRunning(t *testing.T, r io.Reader, n int, proc *testProcess, timeout time.Duration) ([]byte, error) {
	t.Helper()
	buf := make([]byte, n)
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(r, buf)
		done <- err
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				return nil, err
			}
			return buf, nil
		case <-proc.done:
			err, _ := proc.status()
			return nil, fmt.Errorf("socat exited: %v", err)
		case <-timer.C:
			return nil, fmt.Errorf("timed out")
		}
	}
}
