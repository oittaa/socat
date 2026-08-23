//go:build unix

package fileopen

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/xio"
)

func TestNamedPipeOwnershipFailureCleansCreatedFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	s, err := parse.ParseSpec("PIPE:" + path + ",user=socat-user-that-must-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openPIPE(context.Background(), s, xio.ModeRDWR, nil); err == nil {
		t.Fatal("openPIPE unexpectedly ignored ownership failure")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("failed PIPE left filesystem entry behind: %v", err)
	}
}

func TestNamedPipeReadOpenDoesNotBlockForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	s, err := parse.ParseSpec("PIPE:" + path + ",nonblock")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		o, err := openPIPE(context.Background(), s, xio.ModeRead, nil)
		if err != nil {
			done <- err
			return
		}
		done <- o.Close()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PIPE ModeRead open blocked waiting for a writer")
	}
}
