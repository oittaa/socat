//go:build windows

package xio

import (
	"os"
	"testing"
	"time"
)

func TestFileStreamShutdownWriteKeepsDeadlines(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pr.Close() }()
	defer func() { _ = pw.Close() }()

	if err := FileStream(pr).ShutdownWrite(); err != nil {
		t.Fatalf("ShutdownWrite: %v", err)
	}
	if err := pr.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline after ShutdownWrite: %v", err)
	}
	buf := make([]byte, 1)
	_, err = pr.Read(buf)
	if !os.IsTimeout(err) {
		t.Fatalf("Read: want timeout, got %v", err)
	}
}
