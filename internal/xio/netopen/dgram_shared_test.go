package netopen

import (
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestCopyOneshotFirst(t *testing.T) {
	t.Parallel()
	n, err := copyOneshotFirst(make([]byte, 8), nil)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("empty first n=%d err=%v want EOF", n, err)
	}
	buf := make([]byte, 8)
	n, err = copyOneshotFirst(buf, []byte("hi"))
	if err != nil || string(buf[:n]) != "hi" {
		t.Fatalf("payload n=%d err=%v data=%q", n, err, buf[:n])
	}
}

func TestWriteSharedPacketScopesDeadlineToWrite(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	var mu sync.Mutex
	var calls []time.Time
	n, err := writeSharedPacket(&mu, deadline, func(got time.Time) error {
		calls = append(calls, got)
		return nil
	}, func() (int, error) {
		if len(calls) != 1 || !calls[0].Equal(deadline) {
			t.Fatalf("write saw deadlines %v, want %v", calls, deadline)
		}
		return 7, nil
	})
	if err != nil || n != 7 {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if len(calls) != 2 || !calls[1].IsZero() {
		t.Fatalf("deadline calls=%v, want deadline then clear", calls)
	}
}

func TestWriteSharedPacketClearsDeadlineAfterWriteError(t *testing.T) {
	wantErr := errors.New("write failed")
	clearErr := errors.New("clear failed")
	sets := 0
	n, err := writeSharedPacket(nil, time.Now().Add(time.Second), func(got time.Time) error {
		sets++
		if got.IsZero() {
			return clearErr
		}
		return nil
	}, func() (int, error) { return 3, wantErr })
	if n != 3 || !errors.Is(err, wantErr) || !errors.Is(err, clearErr) {
		t.Fatalf("write n=%d err=%v", n, err)
	}
	if sets != 2 {
		t.Fatalf("SetWriteDeadline called %d times, want 2", sets)
	}
}
