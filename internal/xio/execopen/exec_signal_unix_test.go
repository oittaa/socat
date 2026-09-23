//go:build linux || darwin

package execopen

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestOpenEXECParentSignalAssignmentRejected(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,sighup=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, xio.ModeRDWR, &xio.Global{Log: logx.New()})
	if err == nil || !strings.Contains(err.Error(), "no value permitted") {
		t.Fatalf("error=%v want no value permitted", err)
	}
}

func TestChildWaitExitCodeNormal(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 7")
	err := cmd.Run()
	code, ok := childWaitExitCode(err)
	if !ok || code != 7 {
		t.Fatalf("childWaitExitCode=%d ok=%v err=%v want 7", code, ok, err)
	}
	code, ok = childWaitExitCode(nil)
	if !ok || code != 0 {
		t.Fatalf("nil wait code=%d ok=%v want 0", code, ok)
	}
}

func TestChildWaitExitCodeSignaled(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	want := 128 + int(syscall.SIGHUP)
	code, ok := childWaitExitCode(err)
	if !ok || code != want {
		t.Fatalf("childWaitExitCode=%d ok=%v err=%v want %d", code, ok, err, want)
	}
	wrapped, ok := childWaitExitCode(fmt.Errorf("wait: %w", err))
	if !ok || wrapped != want {
		t.Fatalf("wrapped childWaitExitCode=%d ok=%v want %d", wrapped, ok, want)
	}
	g := &xio.Global{}
	(&execWaitState{exitCode: code, waitErr: err}).recordExit(g)
	if g.Child.ExitCode != 0 || g.Child.Err != nil {
		t.Fatalf("fork close recorded signaled status %+v", g.Child)
	}
}
