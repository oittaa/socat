package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanRejectsUnixTagAndUnsupportedFilename(t *testing.T) {
	dir := t.TempDir()
	unixSrc := filepath.Join(dir, "tag.go")
	if err := os.WriteFile(unixSrc, []byte("//go:build unix\n\npackage p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	freebsdSrc := filepath.Join(dir, "stub_freebsd.go")
	if err := os.WriteFile(freebsdSrc, []byte("package p\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "ok.go")
	if err := os.WriteFile(allowed, []byte("//go:build linux || darwin\n\npackage p\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	var unixTag, freebsdFile, allowedHit bool
	for _, f := range findings {
		switch {
		case strings.Contains(f.Msg, "build constraint uses unix"):
			unixTag = true
		case strings.Contains(f.Msg, "filename suffix implies unsupported GOOS freebsd"):
			freebsdFile = true
		case strings.Contains(f.Path, "ok.go"):
			allowedHit = true
		}
	}
	if !unixTag {
		t.Fatalf("missing unix tag finding: %v", findings)
	}
	if !freebsdFile {
		t.Fatalf("missing freebsd filename finding: %v", findings)
	}
	if allowedHit {
		t.Fatalf("linux || darwin file was rejected: %v", findings)
	}
}
