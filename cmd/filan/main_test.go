//go:build linux || darwin

package main

import (
	"bytes"
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
