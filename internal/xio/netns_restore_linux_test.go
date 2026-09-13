//go:build linux

package xio

import (
	"errors"
	"strings"
	"testing"
)

func TestRunAndRestoreNetNSReturnsRestoreFailure(t *testing.T) {
	safe := false
	err := runAndRestoreNetNS(-1, &safe, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "setns(-1") {
		t.Fatalf("error=%v", err)
	}
	if safe {
		t.Fatal("thread marked reusable after namespace restore failure")
	}
}

func TestRunAndRestoreNetNSJoinsOperationAndRestoreFailures(t *testing.T) {
	operationErr := errors.New("operation failed")

	safe := false
	err := runAndRestoreNetNS(-1, &safe, func() error { return operationErr })
	if !errors.Is(err, operationErr) || !strings.Contains(err.Error(), "setns(-1") {
		t.Fatalf("error=%v", err)
	}
}
