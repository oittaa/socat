//go:build windows

package xio

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestFileStreamShutdownWriteKeepsDeadlines(t *testing.T) {
	// os.Pipe is not pollable on Windows, so SetDeadline is unsupported even
	// before ShutdownWrite. Open with FILE_FLAG_OVERLAPPED so the runtime
	// keeps the handle on IOCP; File.Fd() would detach it.
	path := filepath.Join(t.TempDir(), "f")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|windows.O_FILE_FLAG_OVERLAPPED, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	if err := f.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline before ShutdownWrite: %v", err)
	}
	if err := f.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	if err := FileStream(f).ShutdownWrite(); err != nil {
		t.Fatalf("ShutdownWrite: %v", err)
	}
	if err := f.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline after ShutdownWrite: %v", err)
	}
}
