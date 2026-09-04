package xio

import (
	"io"
	"os"
	"testing"
)

func TestWrapStreamLeavesDescriptorSetupToOwner(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stream")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := io.WriteString(f, "payload"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	stream, err := WrapStream(mustSpec(t, "FD:3,ftruncate=2,readbytes=4"), FileStream(f), StreamSocketTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payl" {
		t.Fatalf("read = %q, want byte limit without truncating the file", got)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 7 {
		t.Fatalf("stream wrapping changed file size to %d", info.Size())
	}
}
