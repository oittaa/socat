//go:build unix

package xio

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
)

func TestSitoutEIOMasterReadAfterSlaveClose(t *testing.T) {
	if !FeaturePTY {
		t.Skip("PTY not available")
	}
	master, slave, err := OpenPTYPair()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close() })
	if err := slave.Close(); err != nil {
		t.Fatal(err)
	}

	spec, err := parse.ParseSpec("PTY")
	if err != nil {
		t.Fatal(err)
	}
	r, err := ptyMasterReader(master, spec)
	if err != nil {
		t.Fatal(err)
	}
	_ = master.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := r.Read(make([]byte, 8))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("default sitout n=%d err=%v want EOF", n, err)
	}
}
