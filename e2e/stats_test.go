//go:build e2e

package e2e_test

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
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
