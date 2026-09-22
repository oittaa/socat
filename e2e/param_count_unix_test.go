//go:build e2e && (linux || darwin)

package e2e_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBadParamCountDoesNotCreateUnixSocket(t *testing.T) {
	bin := socatBin(t)
	path := filepath.Join(t.TempDir(), "sock")
	out, err := exec.Command(bin, "UNIX-LISTEN:"+path, "TCP:127.0.0.1:1:extra").CombinedOutput()
	if err == nil {
		t.Fatal("expected a parameter-count error")
	}
	if !strings.Contains(string(out), "wrong number of parameters") {
		t.Fatalf("output=%s", out)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("listen socket created: %v", statErr)
	}
}
