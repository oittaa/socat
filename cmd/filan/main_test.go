//go:build linux || darwin

package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

func TestRunBase0FDNumbers(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-i", "0x0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0:") {
		t.Fatalf("-i 0x0 output=%q", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runWithIO([]string{"-n", "0x1"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "0:") {
		t.Fatalf("-n 0x1 output=%q", stdout.String())
	}
}

func TestRunDebugIncreasesVerbosity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-d", "-d", "-d", "-i", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "checking file descriptor 0") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestRunSimpleAndLongSocketStyle(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcp, ok := ln.(*net.TCPListener)
	if !ok {
		t.Fatal("tcp listener")
	}
	c, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := c.Control(func(h uintptr) { fd = int(h) }); err != nil {
		t.Fatal(err)
	}
	arg := strconv.Itoa(fd)

	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-s", "-i", arg}, &stdout, &stderr); code != 0 {
		t.Fatalf("-s exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "tcp") {
		t.Fatalf("-s output=%q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runWithIO([]string{"-S", "-i", arg}, &stdout, &stderr); code != 0 {
		t.Fatalf("-S exit=%d stderr=%s", code, stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "tcp") || !strings.Contains(got, "(stream)") || !strings.Contains(got, "-") {
		t.Fatalf("-S output=%q", got)
	}
}

func TestRunWinchReprints(t *testing.T) {
	ch := make(chan struct{}, 1)
	ch <- struct{}{}
	close(ch)
	winchTestHook = ch
	t.Cleanup(func() { winchTestHook = nil })

	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-W", "-s", "-i", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	if strings.Count(stdout.String(), "0 ") < 2 && strings.Count(stdout.String(), "    0") < 2 {
		t.Fatalf("expected two reports, got %q", stdout.String())
	}
}

func TestRunHelpListsNewFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatal(code)
	}
	help := stdout.String()
	for _, flag := range []string{"-S", "-W", "-d"} {
		if !strings.Contains(help, flag) {
			t.Fatalf("help missing %s: %q", flag, help)
		}
	}
}
