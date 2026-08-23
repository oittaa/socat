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

func TestNamedPipeNonblockReadOpenDoesNotWaitForWriter(t *testing.T) {
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

func TestNamedPipeBlockingReadOpenWaitsForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	s, err := parse.ParseSpec("PIPE:" + path + ",unlink-close=0")
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		o   *xio.Opened
		err error
	}
	opened := make(chan result, 1)
	go func() {
		o, err := openPIPE(context.Background(), s, xio.ModeRead, nil)
		opened <- result{o: o, err: err}
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("PIPE did not create its FIFO")
		}
		time.Sleep(10 * time.Millisecond)
	}

	select {
	case r := <-opened:
		if r.o != nil {
			_ = r.o.Close()
		}
		t.Fatalf("PIPE ModeRead open returned before a writer: %v", r.err)
	case <-time.After(100 * time.Millisecond):
	}

	type fileResult struct {
		f   *os.File
		err error
	}
	writerOpened := make(chan fileResult, 1)
	go func() {
		f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- test-created FIFO path
		writerOpened <- fileResult{f: f, err: err}
	}()
	var writer *os.File
	select {
	case r := <-writerOpened:
		if r.err != nil {
			t.Fatal(r.err)
		}
		writer = r.f
		defer func() { _ = writer.Close() }()
	case <-time.After(2 * time.Second):
		t.Fatal("PIPE writer blocked despite a waiting reader")
	}

	select {
	case r := <-opened:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if err := r.o.Close(); err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PIPE ModeRead open did not resume after a writer opened")
	}
}
