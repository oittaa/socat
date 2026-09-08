package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGo(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestScanSkipsTestdata(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "ok.go", "package p\n")
	writeGo(t, dir, "testdata/unix.go", "//go:build unix\n\npackage p\n")
	writeGo(t, dir, "vendor/unix.go", "//go:build unix\n\npackage p\n")

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unexpected findings:\n%s", joinFindings(hits))
	}
}

func TestScanSkipsDotAndUnderscoreDirs(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "ok.go", "package p\n")
	forbidden := "//go:build unix\n\npackage p\n"
	writeGo(t, dir, ".codex-review/example.go", forbidden)
	writeGo(t, dir, "_scratch/example.go", forbidden)
	writeGo(t, dir, ".codex-review-old/unix.go", forbidden)

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unexpected findings:\n%s", joinFindings(hits))
	}
}

func TestRepoHasNoUnsupportedConstraints(t *testing.T) {
	root, err := findModuleRoot(".")
	if err != nil {
		t.Fatal(err)
	}
	hits, err := scanTree(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("tracked Go files still have unsupported GOOS constraints:\n%s", joinFindings(hits))
	}
}

func joinFindings(hits []finding) string {
	var b strings.Builder
	for _, f := range hits {
		b.WriteString(f.String())
		b.WriteByte('\n')
	}
	return b.String()
}
