//go:build linux || darwin

package xio

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func TestOpenEXECParentSignalAssignmentRejected(t *testing.T) {
	spec, err := parse.ParseSpec("EXEC:true,sighup=0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, &Global{Log: logx.New()})
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

func TestOpenEXECPtyOptionFailureUnregistersSignals(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	spec, err := parse.ParseSpec("EXEC:sleep 30,pty,sighup,ioctl-int=0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, NewSession(Options{Linger: time.Second}, logx.New()))
	if err == nil || !strings.Contains(err.Error(), "ioctl-int") {
		t.Fatalf("error=%v want ioctl-int PTY master failure after Start", err)
	}
	enabled, n, pids := childSignalPassStateForTest(syscall.SIGHUP)
	if n != 0 {
		t.Fatalf("stale registered pids after PTY failure: n=%d pids=%v enabled=%v", n, pids, enabled)
	}
}

func TestOpenEXECFiveSIGHUPOccurrencesRejected(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	spec, err := parse.ParseSpec("EXEC:true,sighup,sighup,sighup,sighup,sighup")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, NewSession(Options{Linger: time.Second}, logx.New()))
	if err == nil || !strings.Contains(err.Error(), "too many sub processes registered for signal 1") {
		t.Fatalf("error=%v want too many", err)
	}
}
