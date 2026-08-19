package xio

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

type countingCloseStream struct {
	closes atomic.Int32
	err    error
}

func (*countingCloseStream) Read([]byte) (int, error)    { return 0, io.EOF }
func (*countingCloseStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *countingCloseStream) Close() error {
	s.closes.Add(1)
	return s.err
}
func (*countingCloseStream) ShutdownWrite() error { return nil }

func TestOpenedCloseIsConcurrentAndIdempotent(t *testing.T) {
	wantErr := errors.New("close failure")
	stream := &countingCloseStream{err: wantErr}
	o := &Opened{Stream: stream}

	const callers = 32
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- o.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, wantErr) {
			t.Errorf("Close error=%v want %v", err, wantErr)
		}
	}
	if got := stream.closes.Load(); got != 1 {
		t.Fatalf("stream closed %d times, want 1", got)
	}
	if got := o.EffectiveStream(); got != stream {
		t.Fatalf("close mutated exported stream: got %T", got)
	}
}
