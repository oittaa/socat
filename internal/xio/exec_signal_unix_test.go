//go:build unix

package xio

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/logx"
	"github.com/oittaa/socat/internal/parse"
)

func TestOpenEXECRegistersParentSignals(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	script := filepath.Join(t.TempDir(), "hold.sh")
	body := "#!/bin/sh\nexec sleep 30\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	o := openEXECSpec(t, "EXEC:"+script+",sighup,sigint", ModeRDWR)
	enabled, n, pids := childSignalPassStateForTest(syscall.SIGHUP)
	if !enabled || n != 1 || len(pids) != 1 || pids[0] <= 1 {
		t.Fatalf("sighup state enabled=%v n=%d pids=%v", enabled, n, pids)
	}
	enabledINT, nINT, _ := childSignalPassStateForTest(syscall.SIGINT)
	if !enabledINT || nINT != 1 {
		t.Fatalf("sigint enabled=%v n=%d", enabledINT, nINT)
	}
	_ = o.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, n, _ = childSignalPassStateForTest(syscall.SIGHUP)
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	enabled, n, _ = childSignalPassStateForTest(syscall.SIGHUP)
	if enabled || n != 0 {
		t.Fatalf("after close enabled=%v n=%d want empty table", enabled, n)
	}
}

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

func TestOpenEXECPipesAndPtyAcceptSIGHUP(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	for _, specText := range []string{
		"EXEC:true,pipes,sighup",
		"EXEC:true,pty,sighup",
		"SYSTEM:true,sigquit",
		"SHELL:true,sigint",
	} {
		t.Run(specText, func(t *testing.T) {
			if strings.Contains(specText, "pty") && !FeaturePTY {
				t.Skip("PTY not enabled")
			}
			spec, err := parse.ParseSpec(specText)
			if err != nil {
				t.Fatal(err)
			}
			o, err := OpenSpec(context.Background(), spec, ModeRDWR, &Global{Log: logx.New(), Linger: time.Second})
			if err != nil {
				t.Fatalf("OpenSpec: %v", err)
			}
			_ = o.Close()
		})
	}
}

func TestRegisterExecParentSignalsTooManyKillsChild(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	for i := 0; i < socatMaxPids; i++ {
		if err := registerChildSignal(8000+i, syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	spec, err := parse.ParseSpec("EXEC:sleep 30,sighup")
	if err != nil {
		t.Fatal(err)
	}
	err = registerExecParentSignals(spec, cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "too many sub processes") {
		t.Fatalf("error=%v want too many", err)
	}
}

func TestRegisterExecParentSignalsForkSessionIndependent(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	for i := 0; i < socatMaxPids; i++ {
		if err := registerChildSignal(8000+i, syscall.SIGHUP); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})
	spec, err := parse.ParseSpec("EXEC:sleep 30,sighup")
	if err != nil {
		t.Fatal(err)
	}
	g := (&Global{}).forkSession()
	if err := registerExecParentSignals(spec, cmd, g); err != nil {
		t.Fatalf("fork session must have its own four slots: %v", err)
	}
	_, n, _ := childSignalPassStateForTest(syscall.SIGHUP)
	if n != socatMaxPids+1 {
		t.Fatalf("n=%d want %d (4 process + 1 session)", n, socatMaxPids+1)
	}
}

func TestChildWaitExitCodeSignaled(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	ee, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("Wait err=%v want ExitError", err)
	}
	if ee.ExitCode() != -1 {
		t.Fatalf("Go ExitCode()=%d want -1 for a signaled child", ee.ExitCode())
	}
	code, ok := childWaitExitCode(err)
	if !ok || code != 128+int(syscall.SIGHUP) {
		t.Fatalf("childWaitExitCode=%d ok=%v want 129", code, ok)
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
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, &Global{Log: logx.New(), Linger: time.Second})
	if err == nil || !strings.Contains(err.Error(), "ioctl-int") {
		t.Fatalf("error=%v want ioctl-int PTY master failure after Start", err)
	}
	enabled, n, pids := childSignalPassStateForTest(syscall.SIGHUP)
	if n != 0 {
		t.Fatalf("stale registered pids after PTY failure: n=%d pids=%v enabled=%v", n, pids, enabled)
	}
}

func TestOpenEXECFiveForkSessionsRegisterSIGHUP(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	script := filepath.Join(t.TempDir(), "hold.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	parent := &Global{Log: logx.New(), Linger: 20 * time.Millisecond}
	var opened []*Opened
	t.Cleanup(func() {
		for _, o := range opened {
			_ = o.Close()
		}
	})
	for i := 0; i < 5; i++ {
		g := parent.forkSession()
		spec, err := parse.ParseSpec("EXEC:" + script + ",sighup")
		if err != nil {
			t.Fatal(err)
		}
		o, err := OpenSpec(context.Background(), spec, ModeRDWR, g)
		if err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
		opened = append(opened, o)
	}
	_, n, _ := childSignalPassStateForTest(syscall.SIGHUP)
	if n != 5 {
		t.Fatalf("n=%d want 5 concurrent fork sessions", n)
	}
}

func TestOpenEXECFiveSIGHUPOccurrencesRejected(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)
	spec, err := parse.ParseSpec("EXEC:true,sighup,sighup,sighup,sighup,sighup")
	if err != nil {
		t.Fatal(err)
	}
	_, err = OpenSpec(context.Background(), spec, ModeRDWR, &Global{Log: logx.New(), Linger: time.Second})
	if err == nil || !strings.Contains(err.Error(), "too many sub processes registered for signal 1") {
		t.Fatalf("error=%v want too many", err)
	}
}
