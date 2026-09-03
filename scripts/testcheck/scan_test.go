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

func joinFindings(hits []finding) string {
	var lines []string
	for _, h := range hits {
		lines = append(lines, h.String())
	}
	return strings.Join(lines, "\n")
}

func TestScanAllowsCompliantTests(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "plain_test.go", `package p
import "testing"
func TestOK(t *testing.T) {
	if false {
		t.Skip("explicit reason provided")
	}
}
`)
	writeGo(t, dir, "foo_windows_test.go", `package p
import (
	"runtime"
	"testing"
)
func TestWin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows-specific file allows runtime check")
	}
}
`)
	writeGo(t, dir, "bar_unix_test.go", `//go:build linux || darwin

package p
import (
	"runtime"
	"testing"
)
func TestUnix(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("unix-specific file allows runtime check")
	}
}
`)

	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("unexpected findings:\n%s", joinFindings(hits))
	}
}

func TestScanRejectsBareSkip(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "bare_test.go", `package p
import "testing"
func TestBare(t *testing.T) {
	t.Skip()
}
`)
	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || !strings.Contains(hits[0].Msg, "bare t.Skip() prohibited") {
		t.Fatalf("want bare t.Skip finding, got: %v", hits)
	}
}

func TestScanRejectsRuntimeGOOSSkipInCrossPlatform(t *testing.T) {
	dir := t.TempDir()
	writeGo(t, dir, "cross_test.go", `package p
import (
	"runtime"
	"testing"
)
func TestCross(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}
}
`)
	hits, err := scanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || !strings.Contains(hits[0].Msg, "runtime GOOS skip prohibited") {
		t.Fatalf("want runtime GOOS skip finding, got: %v", hits)
	}
}
