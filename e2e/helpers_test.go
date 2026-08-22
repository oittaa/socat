//go:build e2e

// Shared helpers for the e2e suite. Keep only helpers with more than one
// consumer here; single-test helpers stay next to their tests.
package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oittaa/socat/internal/testcert"
)

func listenCert(t *testing.T) string {
	t.Helper()
	p, err := testcert.WriteTempListenCert(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func socatBin(t *testing.T) string {
	t.Helper()
	// Prefer ./socat from repo root or SOCAT env
	if p := os.Getenv("SOCAT"); p != "" {
		return p
	}
	candidates := []string{"../socat", "./socat", "socat", "../socat.exe", "./socat.exe", "socat.exe"}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("socat binary not found; run make build and set SOCAT= or run from repo root")
	return ""
}
