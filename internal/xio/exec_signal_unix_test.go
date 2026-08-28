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
	if !enabled || n != 0 {
		t.Fatalf("after close enabled=%v n=%d want enabled with empty list", enabled, n)
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
		"SYSTEM:true,sigquit",
		"SHELL:true,sigint",
	} {
		t.Run(specText, func(t *testing.T) {
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
	err = registerExecParentSignals(spec, cmd)
	if err == nil || !strings.Contains(err.Error(), "too many sub processes") {
		t.Fatalf("error=%v want too many", err)
	}
}
