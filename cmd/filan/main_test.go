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

func TestRunSimpleAndLongFileStyle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.txt")
	if err := os.WriteFile(path, []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "file " + path
	for _, style := range []string{"-s", "-S"} {
		var stdout, stderr bytes.Buffer
		if code := runWithIO([]string{style, "-f", path}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s -f exit=%d stderr=%s", style, code, stderr.String())
		}
		got := strings.TrimSpace(stdout.String())
		if got != want {
			t.Fatalf("%s -f output=%q want %q", style, got, want)
		}
	}

	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-S", "-f", dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("-S -f dir exit=%d stderr=%s", code, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "dir "+dir {
		t.Fatalf("-S -f dir output=%q", stdout.String())
	}
}

func TestRunIThenNReplacesUpperBound(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-i", "0", "-n", "2"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	got := reportedFDNums(stdout.String())
	if !fdListEq(got, []int{0, 1}) {
		t.Fatalf("-i0 -n2 want fds 0,1 got %v\n%s", got, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runWithIO([]string{"-i", "1"}, &stdout, &stderr); code != 0 {
		t.Fatalf("-i1 exit=%d stderr=%s", code, stderr.String())
	}
	got = reportedFDNums(stdout.String())
	if !fdListEq(got, []int{1}) {
		t.Fatalf("-i1 want fd 1 got %v\n%s", got, stdout.String())
	}
}

func reportedFDNums(out string) []int {
	var fds []int
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
		if err != nil {
			continue
		}
		fds = append(fds, n)
	}
	return fds
}

func fdListEq(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestRunSimpleRangeNumbersFDs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-s", "-i", "0", "-n", "2"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr.String())
	}
	for _, wantFD := range []string{"0", "1"} {
		found := false
		for _, line := range strings.Split(stdout.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == wantFD {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("-s -i0 -n2 want numbered fd %s in output:\n%s", wantFD, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if code := runWithIO([]string{"-s", "-i", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("-s -i0 exit=%d stderr=%s", code, stderr.String())
	}
	line := strings.TrimSpace(stdout.String())
	fields := strings.Fields(line)
	if len(fields) > 0 {
		if _, err := strconv.Atoi(fields[0]); err == nil {
			t.Fatalf("-s -i0 single-fd should not have leading fd number, got: %q", line)
		}
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

func TestRunBadOutputFDHasSinglePrefix(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-o", "+bad"}, &stdout, &stderr); code == 0 {
		t.Fatal("expected invalid output fd to fail")
	}
	if got := stderr.String(); strings.Count(got, "filan:") != 1 || !strings.Contains(got, `bad -o "bad"`) {
		t.Fatalf("stderr=%q", got)
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

func TestRunClusteredDebugCountsAsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-dd", "-d", "-i", "0"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "checking file descriptor 0") {
		t.Fatalf("-dd increased verbosity more than once: %q", stderr.String())
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
	if got := stdout.String(); !strings.Contains(got, "tcp") {
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

func TestRunSimpleIPv6SocketStyle(t *testing.T) {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	tcp := ln.(*net.TCPListener)
	c, err := tcp.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	if err := c.Control(func(h uintptr) { fd = int(h) }); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-s", "-i", strconv.Itoa(fd)}, &stdout, &stderr); code != 0 {
		t.Fatalf("-s exit=%d stderr=%s", code, stderr.String())
	}
	if got := stdout.String(); !strings.HasPrefix(strings.TrimSpace(got), "tcp6") {
		t.Fatalf("-s IPv6 output=%q", got)
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
	n := 0
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	if n < 2 {
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
