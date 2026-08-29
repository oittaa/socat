//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHelpAndInvalidOption(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage: filan") || stderr.Len() != 0 {
		t.Fatalf("help stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	if code := runWithIO([]string{"--invalid"}, &stdout, &stderr); code == 0 {
		t.Fatal("invalid option succeeded")
	}
	if !strings.Contains(stderr.String(), "unknown option") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunAnalyzesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-f", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "file") || !strings.Contains(stdout.String(), "0600") {
		t.Fatalf("filan output=%q", stdout.String())
	}
}

func TestRunNZeroAnalyzesStdin(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-n", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0:") {
		t.Fatalf("filan -n 0 did not report fd 0: %q", stdout.String())
	}
}
