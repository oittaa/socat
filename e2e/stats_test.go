//go:build e2e

package e2e_test

import (
	"bytes"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOptionStatistics(t *testing.T) {
	bin := socatBin(t)
	cmd := exec.Command(bin, "--statistics", "STDIO", "PIPE")
	cmd.Stdin = strings.NewReader("hello stats\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("socat: %v stderr=%s", err, stderr.String())
	}
	if !bytes.Contains(out, []byte("hello stats")) {
		t.Fatalf("stdout %q", out)
	}
	errS := stderr.String()
	if n := strings.Count(errS, "STATISTICS"); n != 2 {
		t.Fatalf("want 2 STATISTICS lines, got %d:\n%s", n, errS)
	}
}

func TestVersionHasSTATS(t *testing.T) {
	bin := socatBin(t)
	out, err := exec.Command(bin, "-V").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("#define WITH_STATS 1")) {
		t.Fatalf("missing WITH_STATS 1:\n%s", out)
	}
}

func TestSIGUSR1Statistics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGUSR1 on Windows")
	}
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
