//go:build linux || darwin

package netopen

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestClassicUnixSockaddrLenMatchesThisPlatform(t *testing.T) {
	sizeofUn := unix.SizeofSockaddrUnix
	sunPath := len(unix.RawSockaddrUnix{}.Path)
	if got := classicUnixSockaddrLen(5, sunPath, sizeofUn, false, false); got != sizeofUn {
		t.Fatalf("untight=%d want sizeof=%d", got, sizeofUn)
	}
}

type pastDeadlineCtx struct{}

func (pastDeadlineCtx) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Millisecond), true
}
func (pastDeadlineCtx) Done() <-chan struct{} { return make(chan struct{}) }
func (pastDeadlineCtx) Err() error            { return nil }
func (pastDeadlineCtx) Value(any) any         { return nil }

func TestWaitUnixConnectPastDeadlineIsNotSuccess(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|sockCloexec, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	err = waitUnixConnect(pastDeadlineCtx{}, fd)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitUnixConnect err=%v want context.DeadlineExceeded", err)
	}
	err = waitUnixConnectRetry(pastDeadlineCtx{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waitUnixConnectRetry err=%v want context.DeadlineExceeded", err)
	}
}
