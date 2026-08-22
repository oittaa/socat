package relay

import (
	"bytes"
	"context"
	"io"
	"sync/atomic"
	"testing"
)

type testRetryError struct{}

func (testRetryError) Error() string   { return "retry" }
func (testRetryError) Retryable() bool { return true }

type partialRetryStream struct {
	bytes.Buffer
	calls int
}

func (s *partialRetryStream) Read([]byte) (int, error) { return 0, io.EOF }
func (s *partialRetryStream) Close() error             { return nil }
func (s *partialRetryStream) ShutdownWrite() error     { return nil }

func (s *partialRetryStream) Write(p []byte) (int, error) {
	s.calls++
	if s.calls == 1 {
		n := min(3, len(p))
		_, _ = s.Buffer.Write(p[:n])
		return n, testRetryError{}
	}
	return s.Buffer.Write(p)
}

func TestWriteBlockPreservesPartialProgressAcrossRetry(t *testing.T) {
	dst := &partialRetryStream{}
	payload := []byte("partial-timeout-write")
	var byteCount atomic.Uint64

	wroteBlock, err := writeBlock(context.Background(), dst, -1, payload, &byteCount)
	if err != nil {
		t.Fatalf("writeBlock: %v", err)
	}
	if !wroteBlock {
		t.Fatal("writeBlock reported no progress")
	}
	if !bytes.Equal(dst.Bytes(), payload) {
		t.Fatalf("written %q, want %q", dst.Bytes(), payload)
	}
	if got := byteCount.Load(); got != uint64(len(payload)) {
		t.Fatalf("byte count = %d, want %d", got, len(payload))
	}
	if dst.calls != 2 {
		t.Fatalf("Write calls = %d, want 2", dst.calls)
	}
}
