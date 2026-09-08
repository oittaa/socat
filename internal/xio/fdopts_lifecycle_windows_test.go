//go:build windows

package xio

import (
	"os"
	"testing"
)

func TestApplyFDOptionsWindowsFtruncateShortensFile(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fd-trunc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if _, err := f.Write([]byte("abcdefghij")); err != nil {
		t.Fatal(err)
	}
	if err := ApplyFDOptions(f, mustSpec(t, "FD:3,ftruncate=4")); err != nil {
		t.Fatal(err)
	}
	st, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() != 4 {
		t.Fatalf("size=%d want 4", st.Size())
	}
}
