//go:build linux

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/oittaa/socat/internal/outbuf"
)

func TestFilanFDReportsPipeSize(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	var report outbuf.Buf
	(&filanConfig{}).filanFD(int(r.Fd()), &report)
	var output bytes.Buffer
	if err := report.Flush(&output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "F_GETPIPE_SZ=") {
		t.Fatalf("pipe report=%q", output.String())
	}
}
