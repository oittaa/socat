//go:build linux

package xio

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRunAndRestoreNetNSReturnsRestoreFailure(t *testing.T) {
	safe := false
	err := runAndRestoreNetNS(-1, &safe, func() error { return nil })
	if !errors.Is(err, unix.EBADF) {
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
	if !errors.Is(err, operationErr) || !errors.Is(err, unix.EBADF) {
		t.Fatalf("error=%v", err)
	}
}
