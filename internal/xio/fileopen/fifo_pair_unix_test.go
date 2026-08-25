//go:build unix

package fileopen

import (
	"path/filepath"
	"testing"
)

func TestOpenFIFOPairReaderThenWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := mkfifo(path, 0o666); err != nil {
		t.Fatal(err)
	}
	r, w, err := openFIFOPair(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	n, err := r.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestOpenFIFOPairMissingPath(t *testing.T) {
	r, w, err := openFIFOPair(filepath.Join(t.TempDir(), "missing"))
	if err == nil {
		_ = r.Close()
		_ = w.Close()
		t.Fatal("expected missing FIFO to fail")
	}
	if r != nil || w != nil {
		t.Fatalf("r=%v w=%v want nil", r, w)
	}
}

func TestOpenFIFOPairWriterFailureClosesReader(t *testing.T) {
	dir := t.TempDir()
	r, w, err := openFIFOPair(dir)
	if err == nil {
		_ = r.Close()
		_ = w.Close()
		t.Fatal("expected write-open failure on a directory")
	}
	if r != nil || w != nil {
		t.Fatalf("r=%v w=%v want nil after rollback", r, w)
	}
}
