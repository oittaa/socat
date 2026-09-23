//go:build linux || darwin

package xio

import (
	"context"
	"io"
	"os"
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
	entered := make(chan struct{})
	spec, err := parse.ParseSpec("STDIO,readbytes=4,escape=27")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	left, err := WrapStream(prepared.Config, relay.FDStream{
		R: &enteredReader{r: pr, entered: entered},
		W: io.Discard,
		C: NopCloser{},
	}, StreamSocketTimeouts)
	if err != nil {
		t.Fatal(err)
	}
	peerR, peerW := io.Pipe()
	t.Cleanup(func() { _ = peerR.Close(); _ = peerW.Close() })
	done := make(chan error, 1)
	go func() {
		done <- relay.Transfer(context.Background(), left, relay.FDStream{
			R: peerR, W: io.Discard, C: NopCloser{},
		}, relay.Config{Linger: 0})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("read never entered")
	}
	if err := peerW.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("hung after peer EOF")
	}
}

// enteredReader closes entered the first time Read is called, then reads r.
type enteredReader struct {
	r       io.Reader
	entered chan struct{}
}

func (e *enteredReader) UnwrapReader() io.Reader { return e.r }

func (e *enteredReader) Read(p []byte) (int, error) {
	if e.entered != nil {
		close(e.entered)
		e.entered = nil
	}
	return e.r.Read(p)
}
