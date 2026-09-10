//go:build darwin

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/xio"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	switch os.Getenv("SOCAT_PROCAN_HELPER") {
	case "pgrp-stdin":
		os.Exit(runPgrpStdinHelper())
	case "report":
		os.Exit(run(nil))
	}
	os.Exit(m.Run())
}

func runPgrpStdinHelper() int {
	pg, err := foregroundProcessGroup(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "foregroundProcessGroup: %v\n", err)
		return 1
	}
	fmt.Printf("%d %d\n", pg, unix.Getpgrp())
	return 0
}

func TestForegroundProcessGroupPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	for _, tc := range []struct {
		name string
		f    *os.File
	}{
		{"read", r},
		{"write", w},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fd := int(tc.f.Fd())
			n, rawErr := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
			if rawErr != nil {
				t.Fatalf("TIOCGPGRP on pipe: %v", rawErr)
			}
			if _, err := foregroundProcessGroup(fd); err == nil {
				t.Fatalf("foregroundProcessGroup succeeded on a pipe (raw TIOCGPGRP=%d)", n)
			}
		})
	}
}

func TestForegroundProcessGroupDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := foregroundProcessGroup(int(f.Fd())); err == nil {
		t.Fatal("foregroundProcessGroup succeeded on /dev/null")
	}
}

func TestForegroundProcessGroupBadFD(t *testing.T) {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	_, err = foregroundProcessGroup(fd)
	if err == nil {
		t.Fatal("foregroundProcessGroup succeeded on a closed descriptor")
	}
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("err=%v want EBADF", err)
	}
}

func TestForegroundProcessGroupControllingPTY(t *testing.T) {
	master, slave, err := xio.OpenPTYPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = master.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(os.Environ(), "SOCAT_PROCAN_HELPER=pgrp-stdin")
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
	fields := strings.Fields(stdout.String())
	if len(fields) != 2 {
		t.Fatalf("helper output %q", stdout.String())
	}
	pg, err := strconv.Atoi(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	pgrp, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatal(err)
	}
	if pg != pgrp {
		t.Fatalf("foreground pgrp %d != process group %d", pg, pgrp)
	}
	if pg != cmd.Process.Pid {
		t.Fatalf("foreground pgrp %d != child pid %d", pg, cmd.Process.Pid)
	}
}

func TestProcanRedirectedStdioForegroundGroup(t *testing.T) {
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = null.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$") // #nosec G204 -- re-exec this test binary without a shell
	cmd.Env = append(os.Environ(), "SOCAT_PROCAN_HELPER=report")
	cmd.Stdin = null
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v stderr=%q", err, stderr.String())
	}
	got := stdout.String()
	for _, want := range []string{
		"process group id if fg process / stdin = -1",
		"process group id if fg process / stdout = -1",
		"process group id if fg process / stderr = -1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in:\n%s", want, got)
		}
	}
}
