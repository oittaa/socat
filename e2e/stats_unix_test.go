//go:build e2e && unix

package e2e_test

import (
	"bytes"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSIGUSR1Statistics(t *testing.T) {
	bin := socatBin(t)
	pr, pw := io.Pipe()
	cmd := exec.Command(bin, "STDIO", "PIPE")
	cmd.Stdin = pr
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = pw.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if _, err := pw.Write([]byte("ping\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := signalUSR1(cmd.Process); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Count(stderr.String(), "STATISTICS") >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no STATISTICS after SIGUSR1:\n%s", stderr.String())
}
