//go:build linux

package filan

import (
	"io"
	"os"
	"testing"
)

func TestFIONREADNegativeOffsetLinux(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "fionread-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tmp.Close() })

	if _, err := tmp.Seek(100, io.SeekStart); err != nil {
		t.Fatal(err)
	}

	n, err := fionread(int(tmp.Fd()))
	if err != nil {
		t.Fatalf("fionread error: %v", err)
	}
	if n != -100 {
		t.Fatalf("fionread on empty file at offset 100: got %d, want -100", n)
	}
}
