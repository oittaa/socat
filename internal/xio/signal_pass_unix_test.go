//go:build linux || darwin

package xio

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/oittaa/socat/internal/parse"
)

func TestRegisterChildSignalMaxFour(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	for i := 1; i <= socatMaxPids; i++ {
		if err := registerChildSignal(1000+i, syscall.SIGHUP); err != nil {
			t.Fatalf("pid %d: %v", i, err)
		}
	}
	err := registerChildSignal(2000, syscall.SIGHUP)
	if err == nil || !strings.Contains(err.Error(), "too many sub processes registered for signal 1") {
		t.Fatalf("error=%v want too many sub processes", err)
	}
	if err := registerChildSignal(3000, syscall.SIGINT); err != nil {
		t.Fatalf("sigint should have its own four slots: %v", err)
	}
}

func TestForwardRegisteredChildSignalKillsAndDoesNotClearMode(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	var got []struct {
		pid int
		sig syscall.Signal
	}
	oldKill := killRegisteredChild
	killRegisteredChild = func(pid int, sig syscall.Signal) error {
		got = append(got, struct {
			pid int
			sig syscall.Signal
		}{pid, sig})
		return nil
	}
	t.Cleanup(func() { killRegisteredChild = oldKill })

	if ForwardRegisteredChildSignal(syscall.SIGHUP) {
		t.Fatal("unregistered SIGHUP must not enter pass-through")
	}
	if err := registerChildSignal(4242, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	if !ForwardRegisteredChildSignal(syscall.SIGHUP) {
		t.Fatal("registered SIGHUP must stay in pass-through")
	}
	if len(got) != 1 || got[0].pid != 4242 || got[0].sig != syscall.SIGHUP {
		t.Fatalf("kills=%v want pid 4242 SIGHUP", got)
	}
	unregisterChildSignals(4242)
	enabled, n, _ := childSignalPassStateForTest(syscall.SIGHUP)
	if enabled || n != 0 {
		t.Fatalf("enabled=%v n=%d want empty table after unregister", enabled, n)
	}
	got = nil
	if ForwardRegisteredChildSignal(syscall.SIGHUP) {
		t.Fatal("empty table must restore terminate-on-SIGHUP (classic listener parent)")
	}
	if len(got) != 0 {
		t.Fatalf("dead pid must not be killed again: %v", got)
	}
	if ForwardRegisteredChildSignal(syscall.SIGTERM) {
		t.Fatal("SIGTERM is not OFUNC_SIGNAL")
	}
}

func TestRegisterChildSignalPerSessionLimit(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	parent := &Global{}
	for i := 0; i < 5; i++ {
		g := parent.forkSession()
		if err := registerChildSignalOn(g, 2000+i, syscall.SIGHUP); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}
	enabled, n, pids := childSignalPassStateForTest(syscall.SIGHUP)
	if !enabled || n != 5 {
		t.Fatalf("enabled=%v n=%d pids=%v want 5 concurrent sessions", enabled, n, pids)
	}

	one := &Global{}
	for i := 0; i < socatMaxPids; i++ {
		if err := registerChildSignalOn(one, 77, syscall.SIGHUP); err != nil {
			t.Fatalf("occurrence %d: %v", i, err)
		}
	}
	err := registerChildSignalOn(one, 77, syscall.SIGHUP)
	if err == nil || !strings.Contains(err.Error(), "too many sub processes registered for signal 1") {
		t.Fatalf("error=%v want too many on a fifth occurrence in one session", err)
	}
}

func TestValidateExecParentSignalsTypeConst(t *testing.T) {
	ok, err := parse.ParseSpec("EXEC:true,sighup")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateExecParentSignals(ok); err != nil {
		t.Fatal(err)
	}
	bad, err := parse.ParseSpec("EXEC:true,sighup=0")
	if err != nil {
		t.Fatal(err)
	}
	err = validateExecParentSignals(bad)
	if err == nil || !strings.Contains(err.Error(), "no value permitted") {
		t.Fatalf("error=%v want no value permitted", err)
	}
}

func TestRegisterExecParentSignalsCountsOccurrences(t *testing.T) {
	resetChildSignalPassForTest()
	t.Cleanup(resetChildSignalPassForTest)

	spec, err := parse.ParseSpec("EXEC:true,sighup,sighup,sigint")
	if err != nil {
		t.Fatal(err)
	}
	cmd := &exec.Cmd{Process: &os.Process{Pid: 77}}
	if err := registerExecParentSignals(spec, cmd, nil); err != nil {
		t.Fatal(err)
	}
	_, nHUP, pids := childSignalPassStateForTest(syscall.SIGHUP)
	if nHUP != 2 || len(pids) != 2 || pids[0] != 77 || pids[1] != 77 {
		t.Fatalf("sighup slots=%d pids=%v want two copies of 77", nHUP, pids)
	}
	_, nINT, _ := childSignalPassStateForTest(syscall.SIGINT)
	if nINT != 1 {
		t.Fatalf("sigint n=%d want 1", nINT)
	}
}
