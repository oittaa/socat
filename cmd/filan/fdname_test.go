//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
)

func TestMain(m *testing.M) {
	switch os.Getenv("SOCAT_FILAN_HELPER") {
	case "dev-tty":
		os.Exit(runDevTTYHelper())
	}
	os.Exit(m.Run())
}

func runDevTTYHelper() int {
	style := os.Getenv("SOCAT_FILAN_STYLE")
	if style != "-s" && style != "-S" {
		_, _ = os.Stderr.WriteString("bad SOCAT_FILAN_STYLE\n")
		return 2
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		_, _ = os.Stderr.WriteString("open /dev/tty: " + err.Error() + "\n")
		return 1
	}
	defer func() { _ = f.Close() }()
	return run([]string{style, "-i", strconv.Itoa(int(f.Fd()))})
}

func parseSimpleName(t *testing.T, out string) (typ, path string) {
	t.Helper()
	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatal("empty output")
	}
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	typ, path, ok := strings.Cut(line, " ")
	if !ok {
		t.Fatalf("output %q", out)
	}
	return typ, strings.TrimSpace(path)
}

func runSimpleOnFD(t *testing.T, style string, fd int) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{style, "-i", strconv.Itoa(fd)}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	return stdout.String()
}

func TestFdnameLabelsPTYAsTTY(t *testing.T) {
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	fd := int(slave.Fd())
	for _, style := range []string{"-s", "-S"} {
		t.Run(style, func(t *testing.T) {
			got := runSimpleOnFD(t, style, fd)
			typ, path := parseSimpleName(t, got)
			if typ != "tty" {
				t.Fatalf("type=%q want tty (output %q)", typ, got)
			}
			if path == "" {
				t.Fatalf("missing path in %q", got)
			}
		})
	}
}

func TestFdnameDetailedPTYStaysChrdev(t *testing.T) {
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	var stdout, stderr bytes.Buffer
	if code := runWithIO([]string{"-i", strconv.Itoa(int(slave.Fd()))}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	got := stdout.String()
	if !strings.Contains(got, "chrdev") {
		t.Fatalf("detailed report missing chrdev: %q", got)
	}
	if strings.Contains(got, ": tty\t") {
		t.Fatalf("detailed report used tty type: %q", got)
	}
}

func TestFdnameDevNullStaysChrdev(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	fd := int(f.Fd())
	for _, style := range []string{"-s", "-S"} {
		t.Run(style, func(t *testing.T) {
			got := runSimpleOnFD(t, style, fd)
			typ, path := parseSimpleName(t, got)
			if typ != "chrdev" {
				t.Fatalf("type=%q want chrdev (output %q)", typ, got)
			}
			if !strings.Contains(path, "null") {
				t.Fatalf("path=%q", path)
			}
		})
	}
}

func TestFdnameDevTTYInSession(t *testing.T) {
	for _, style := range []string{"-s", "-S"} {
		t.Run(style, func(t *testing.T) {
			master, slave, err := xio.OpenPTYPair()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = master.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$") // #nosec G204 -- re-exec this test binary without a shell
			cmd.Env = append(os.Environ(),
				"SOCAT_FILAN_HELPER=dev-tty",
				"SOCAT_FILAN_STYLE="+style,
			)
			cmd.Stdin = slave
			cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				_ = slave.Close()
				t.Fatal(err)
			}
			if err := slave.Close(); err != nil {
				t.Fatal(err)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatalf("helper: %v stderr=%q stdout=%q", err, stderr.String(), stdout.String())
			}
			got := stdout.String()
			typ, path := parseSimpleName(t, got)
			if typ != "tty" {
				t.Fatalf("type=%q want tty (output %q)", typ, got)
			}
			if path == "" {
				t.Fatalf("missing path in %q", got)
			}
		})
	}
}
