//go:build linux

package xio

import (
	"errors"
	"strings"
	"testing"
)

func TestRunAndRestoreNetNSReturnsRestoreFailure(t *testing.T) {
	want := errors.New("restore failed")
	original := setnsFunc
	setnsFunc = func(int, int) error { return want }
	t.Cleanup(func() { setnsFunc = original })

	safe := false
	err := runAndRestoreNetNS(42, &safe, func() error { return nil })
	if err == nil || !errors.Is(err, want) || !strings.Contains(err.Error(), "setns(42") {
		t.Fatalf("error=%v", err)
	}
	if safe {
		t.Fatal("thread marked reusable after namespace restore failure")
	}
}

func TestRunAndRestoreNetNSJoinsOperationAndRestoreFailures(t *testing.T) {
	operationErr := errors.New("operation failed")
	restoreErr := errors.New("restore failed")
	original := setnsFunc
	setnsFunc = func(int, int) error { return restoreErr }
	t.Cleanup(func() { setnsFunc = original })

	safe := false
	err := runAndRestoreNetNS(7, &safe, func() error { return operationErr })
	if !errors.Is(err, operationErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("error=%v", err)
	}
}
