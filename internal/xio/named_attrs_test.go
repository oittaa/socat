package xio

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestApplyNamedAttrsSetsPerm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	spec, err := parse.ParseSpec("UNIX-LISTEN:" + path + ",perm=0600")
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyNamedAttrs(path, spec, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("perm=%#o want 0600", got)
	}
}
