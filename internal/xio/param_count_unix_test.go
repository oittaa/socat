//go:build linux || darwin

package xio_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
	_ "github.com/oittaa/socat/internal/xio/all"
)

func TestExtraUNIXListenParamDoesNotCreateSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock")
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ":extra")
	if err != nil {
		t.Fatal(err)
	}
	_, err = xio.PrepareSpec(spec)
	const want = "UNIX-LISTEN: wrong number of parameters (2 instead of 1)"
	if err == nil || err.Error() != want {
		t.Fatalf("err=%v want %q", err, want)
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("listen socket created before parameter check: %v", statErr)
	}
}
