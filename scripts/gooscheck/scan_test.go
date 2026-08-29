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

func TestScanAllowsSupportedConstraints(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "linux.go", "//go:build linux\n\npackage p\n")
	writeGo(t, dir, "unix_named.go", "//go:build linux || darwin\n\npackage p\n")
	writeGo(t, dir, "stub.go", "//go:build darwin || windows\n\npackage p\n")
	writeGo(t, dir, "reuse.go", "//go:build linux || windows\n\npackage p\n")
	writeGo(t, dir, "all.go", "//go:build linux || darwin || windows\n\npackage p\n")
	writeGo(t, dir, "arch.go", "//go:build linux && !mips && !mipsle && !mips64 && !mips64le\n\npackage p\n")
	writeGo(t, dir, "e2e.go", "//go:build e2e && (linux || darwin)\n\npackage p\n")
	writeGo(t, dir, "plain.go", "package p\n")
	writeGo(t, dir, "sys_unix.go", "//go:build linux || darwin\n\npackage p\nimport _ \"golang.org/x/sys/unix\"\n")
	writeGo(t, dir, "foo_unix.go", "package p\n") // *_unix.go is not an implicit unix tag
	writeGo(t, dir, "foo_linux.go", "package p\n")
	writeGo(t, dir, "foo_linux_amd64.go", "package p\n")
	writeGo(t, dir, "termios.go", "package p\nconst bsdly = 1\n") // POSIX BSDLY, not a GOOS

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unexpected findings:\n%s", joinFindings(hits))
	}
}

func TestScanRejectsUnixTagAndUnsupportedOS(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "broad.go", "//go:build unix\n\npackage p\n")
	writeGo(t, dir, "bsd.go", "//go:build linux || freebsd\n\npackage p\n")
	writeGo(t, dir, "neg.go", "//go:build !windows\n\npackage p\n")
	writeGo(t, dir, "notunix.go", "//go:build !unix\n\npackage p\n")
	writeGo(t, dir, "notlinux.go", "//go:build !linux\n\npackage p\n")
	writeGo(t, dir, "old.go", "// +build solaris\n\npackage p\n")
	writeGo(t, dir, "foo_freebsd.go", "package p\n")
	writeGo(t, dir, "bar_openbsd_amd64.go", "package p\n")

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := joinFindings(hits)
	for _, want := range []string{
		"broad.go:1: build constraint uses unix",
		"bsd.go:1: build constraint uses freebsd",
		"neg.go:1: build constraint uses !windows",
		"notunix.go:1: build constraint uses !unix",
		"notlinux.go:1: build constraint uses !linux",
		"old.go:1: build constraint uses solaris",
		"foo_freebsd.go: filename suffix implies unsupported GOOS freebsd",
		"bar_openbsd_amd64.go: filename suffix implies unsupported GOOS openbsd",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
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
		t.Fatalf("testdata/vendor must be skipped: %s", joinFindings(hits))
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
		t.Fatalf(". and _ directories must be skipped: %s", joinFindings(hits))
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
