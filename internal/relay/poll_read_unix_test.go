//go:build linux || darwin

package relay

import (
	"io"
	"os"
	"testing"
	"time"
)

func TestWaitPollReadPipeHangupIsEOF(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for pipe hangup")
		}
		err := waitPollRead(int(r.Fd()), 50)
		if err == errPollIdle {
			continue
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("pipe hangup err=%v", err)
		}
		// Darwin reports POLLIN together with hangup; Read still returns EOF.
		n, readErr := r.Read(make([]byte, 1))
		if n != 0 || readErr != io.EOF {
			t.Fatalf("pipe hangup read n=%d err=%v want EOF", n, readErr)
		}
		return
	}
}
