//go:build linux || darwin

package filan

import (
	"os"
	"testing"
)

func TestIsTerminalPTYAndNonTerminals(t *testing.T) {
	master, slave, err := openTestPTY()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
	})
	if !IsTerminal(int(slave.Fd())) {
		t.Fatal("PTY slave is not a terminal")
	}

	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = null.Close() })
	if IsTerminal(int(null.Fd())) {
		t.Fatal("/dev/null classified as a terminal")
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})
	if IsTerminal(int(r.Fd())) || IsTerminal(int(w.Fd())) {
		t.Fatal("pipe classified as a terminal")
	}
}
