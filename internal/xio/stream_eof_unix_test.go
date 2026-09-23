//go:build linux || darwin

package xio

import (
	"bytes"
	"context"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/oittaa/socat/internal/parse"
	"github.com/oittaa/socat/internal/relay"
)

func TestReadbytesEscapeUnblocksWhenPeerEOFs(t *testing.T) {
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	dst, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dst.Close() })
	spec, err := parse.ParseSpec("STDIO,readbytes=4,escape=27")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	left, err := WrapStream(prepared.Config, relay.FDStream{R: pr, W: io.Discard, C: NopCloser{}}, StreamSocketTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	right := relay.FDStream{R: readAfter(release), W: dst, C: NopCloser{}}
	done := make(chan error, 1)
	go func() {
		done <- relay.Transfer(context.Background(), left, right, relay.Config{Linger: 0})
	}()
	// Release the peer only after the filtered read is blocked.
	if !waitUntil(transferReadBlocked) {
		t.Fatal("read never blocked")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hung after peer EOF")
	}
}

func waitUntil(ready func() bool) bool {
	deadline := time.Now().Add(time.Second)
	for !ready() {
		if time.Now().After(deadline) {
			return false
		}
		runtime.Gosched()
	}
	return true
}

type readAfter <-chan struct{}

func (c readAfter) Read([]byte) (int, error) {
	<-c
	return 0, io.EOF
}

func transferReadBlocked() bool {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	stack := buf[:n]
	return bytes.Contains(stack, []byte("(*escapeReader).Read")) ||
		bytes.Contains(stack, []byte("waitReadableAndWritable"))
}
