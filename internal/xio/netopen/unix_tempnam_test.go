package netopen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnixTempnamReplacesXXXXXX(t *testing.T) {
	dir := t.TempDir()
	// Literal XXXXXX file must not be chosen (classic BIND_TEMPNAME test).
	lit := filepath.Join(dir, "pre.XXXXXX")
	if err := os.WriteFile(lit, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := unixTempnam(filepath.Join(dir, "pre.XXXXXX"))
	if err != nil {
		t.Fatal(err)
	}
	if got == lit {
		t.Fatal("picked the literal XXXXXX path")
	}
	if !strings.HasPrefix(got, filepath.Join(dir, "pre.")) {
		t.Fatalf("prefix %q", got)
	}
	if strings.HasSuffix(got, "XXXXXX") || strings.Contains(filepath.Base(got), "XXXXXX") {
		t.Fatalf("XXXXXX not replaced in basename: %q", got)
	}
}
