//go:build windows

package relay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type pipeErrorWriter struct {
	err error
}

func (w pipeErrorWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestIsBenignCloseRejectsUnrelatedWindowsErrors(t *testing.T) {
	unrelatedErrors := []error{
		windows.WSAECONNABORTED,
		windows.WSAECONNRESET,
		windows.WSAETIMEDOUT,
		windows.WSAECONNREFUSED,
		windows.WSAENETUNREACH,
		windows.ERROR_ACCESS_DENIED,
		context.DeadlineExceeded,
		errors.New("unrelated custom error"),
	}
	for _, err := range unrelatedErrors {
		if isBenignClose(err) {
			t.Errorf("isBenignClose(%v) = true, want false", err)
		}
	}
}

func TestTransferUnrelatedErrorFails(t *testing.T) {
	left := FDStream{
		R: bytes.NewReader([]byte("test")),
		W: io.Discard,
		C: nopCloser{},
	}
	failWriter := pipeErrorWriter{err: windows.WSAECONNRESET}
	right := FDStream{
		R: bytes.NewReader(nil),
		W: failWriter,
		C: nopCloser{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := Transfer(ctx, left, right, Config{LeftToRight: true})
	if !errors.Is(err, windows.WSAECONNRESET) {
		t.Fatalf("Transfer returned %v, want windows.WSAECONNRESET", err)
	}
}
