//go:build linux || darwin

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunHelpAndInvalidOption(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage: procan") || stderr.Len() != 0 {
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

func TestRunCompileDefinitions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-c"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"#define PF_INET ", "#define SOCK_DGRAM ", "#define SO_REUSEADDR "} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("procan -c missing %q", want)
		}
	}
}

func TestRunProcessReport(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runWithIO(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code=%d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"process id = ", "RESOURCE LIMITS", "sizeof(size_t)"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("process report missing %q", want)
		}
	}
}
