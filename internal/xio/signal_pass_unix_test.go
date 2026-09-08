//go:build linux || darwin

package xio

import (
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
