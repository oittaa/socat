//go:build e2e && (linux || darwin)

package e2e_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBadParamCountDoesNotCreateUnixSocket(t *testing.T) {
	bin := socatBin(t)
	path := filepath.Join(t.TempDir(), "sock")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "UNIX-LISTEN:"+path, "TCP:127.0.0.1:1:extra").CombinedOutput()
	if err == nil {
		t.Fatal("expected a parameter-count error")
	}
	if ctx.Err() != nil {
		t.Fatalf("parameter-count error did not return before timeout: %v output=%s", ctx.Err(), out)
	}
	if !strings.Contains(string(out), "wrong number of parameters") {
		t.Fatalf("output=%s", out)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("listen socket created: %v", statErr)
	}
}
