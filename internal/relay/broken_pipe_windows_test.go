//go:build windows

package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

func TestTransferWindowsBrokenPipeCleanTermination(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Close() }()

	// Close read end before relay transfers payload into the writer.
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	left := FDStream{
		R: bytes.NewReader([]byte("payload for closed pipe")),
		W: io.Discard,
		C: nopCloser{},
	}
	right := FDStream{
		R: bytes.NewReader(nil),
		W: w,
		C: nopCloser{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = Transfer(ctx, left, right, Config{
		LeftToRight: true,
	})
	if err != nil {
		t.Fatalf("Transfer into closed pipe returned error: %v, want nil", err)
	}
}

func TestIsBenignCloseWindowsBrokenPipe(t *testing.T) {
	// Directly on ERROR_BROKEN_PIPE
	if !isBenignClose(windows.ERROR_BROKEN_PIPE) {
		t.Error("isBenignClose(windows.ERROR_BROKEN_PIPE) = false, want true")
	}
	// Directly on ERROR_NO_DATA
	if !isBenignClose(windows.ERROR_NO_DATA) {
		t.Error("isBenignClose(windows.ERROR_NO_DATA) = false, want true")
	}
	// Wrapped inside os.PathError
	pathErrBrokenPipe := &os.PathError{Op: "write", Path: "|1", Err: windows.ERROR_BROKEN_PIPE}
	if !isBenignClose(pathErrBrokenPipe) {
		t.Error("isBenignClose(pathErrBrokenPipe) = false, want true")
	}
	pathErrNoData := &os.PathError{Op: "write", Path: "|1", Err: windows.ERROR_NO_DATA}
	if !isBenignClose(pathErrNoData) {
		t.Error("isBenignClose(pathErrNoData) = false, want true")
	}
	// Custom wrapped error
	customWrapped := fmt.Errorf("write pipe failed: %w", windows.ERROR_BROKEN_PIPE)
	if !isBenignClose(customWrapped) {
		t.Error("isBenignClose(customWrapped) = false, want true")
	}
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
